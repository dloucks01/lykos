"""Phase 6 — the `build_poc` stage: verify a crashing input in a clean sandbox, assemble a
self-contained PoC bundle, and (on success) promote the finding to POC-BACKED (L1)."""
from __future__ import annotations

import os

from ...db.dao import DynResultDAO, FindingDAO, PocDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import crash_dedup_key, crash_finding_candidate, crash_hijack
from ..fuzz.runner import place
from . import bundle
from .capture import MODES, how_to_feed

BUILD_POC_STAGE = "build_poc"
TOOL = "poc"
TOOL_VERSION = "poc-1"


def build_poc_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("build_poc requires a target_id")
    p = ctx.params or {}
    input_sha = p.get("input_sha")
    if not input_sha:
        raise ValueError("build_poc requires params.input_sha (a crashing input)")
    timeout = float(p.get("timeout", 10))
    mode, argv, mode_why = how_to_feed(ctx.conn, target, input_sha, p)

    input_bytes = ctx.content.get_bytes(input_sha)
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / "target.bin"
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)

    def _delivery(m):
        """(argv, stdin) for one delivery channel."""
        if m == "stdin":
            return place(argv, "/dev/stdin") if "@@" in [
                str(a) for a in argv] else list(argv), input_bytes
        if m == "arg":
            # truncate: execve cuts the argument at the first NUL anyway, so this is what the
            # program would actually receive -- refusing outright discarded payloads whose
            # control slot sits safely before it (see sandbox.argv_arg).
            return place(argv, sandbox.argv_arg(input_bytes, truncate=True)), b""
        wf = ctx.scratch() / "input.bin"
        wf.write_bytes(input_bytes)
        return place(argv, str(wf)), b""

    ctx.progress(msg="verifying PoC in a clean sandbox")
    # endianness/bits are load-bearing, not decoration: _qemu_for routes ppc64->ppc64le,
    # mips->mipsel and riscv->riscv32/64 on them. Omitting them hands a little-endian target
    # to the big-endian emulator, which cannot run it -- so the PoC "fails to reproduce" and
    # is filed as an unverified L0 rather than a verified L1.
    # Try the mode we believe in, then the others. A crashing input fed the wrong way does
    # not crash, and filing that as an unverified L0 turns a wrong setup into what reads as
    # "the input does not reproduce".
    # The options the crash was found under come first, because a crash found under an option
    # may need it -- but then WITHOUT them, for two reasons: a simpler reproducer is a better
    # PoC, and a mined flag that consumes the next argument (`-cmd`, `-o`) swallows the file
    # path, so replaying faithfully is the one thing that cannot work.
    prefixes = [list(argv)] + ([[]] if argv else [])
    tried, res = [], None
    for pre in prefixes:
        argv = pre
        for m in [mode] + [x for x in MODES if x != mode]:
            run_argv, stdin = _delivery(m)
            res = sandbox.run(exe, argv=run_argv, stdin=stdin, timeout=timeout,
                              arch=target.arch, endianness=target.endianness, bits=target.bits)
            tried.append(m if not pre else f"{m}+{' '.join(pre)}")
            if res.crashed:
                if m != mode:
                    mode_why = f"{mode_why}, but it only crashed via {m}"
                mode = m
                break
        if res is not None and res.crashed:
            if not pre and prefixes[0]:
                mode_why = f"{mode_why}; reproduces without {' '.join(prefixes[0])}"
            break
    run_argv, stdin = _delivery(mode)
    verified = res.crashed
    level = "L1" if verified else "L0"

    # Did we reproduce the crash we were ASKED to package, or a different one?
    # This is not pedantry: a broken replay argv made the target throw NoSuchFileException
    # instead of the ArrayIndexOutOfBoundsException the campaign found, and the stage filed a
    # verified L1 whose expected_signal was the wrong fault entirely. A PoC that reproduces
    # something else is still evidence, but it is not evidence of THIS finding, and the bundle
    # has to say which it is.
    wanted = next((r.signal_name for r in DynResultDAO(ctx.conn).list_by_target(target.id)
                   if r.input_sha == input_sha and r.crashed and r.signal_name), None)
    mismatch = bool(verified and wanted and res.signal_name and res.signal_name != wanted)
    if mismatch:
        mode_why = (f"{mode_why}; NOTE the replay produced {res.signal_name} where the "
                    f"campaign recorded {wanted}")

    meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
            "argv": argv, "expected_signal": res.signal_name, "isolation": res.isolation,
            "verified": verified, "tool_version": TOOL_VERSION,
            "recorded_signal": wanted, "signal_matches_finding": not mismatch}
    runtime = {"jar": "jar", "class": "class"}.get((target.file_type or "").lower(), "native")
    main_class = None
    if runtime == "class":
        # The class name comes from the file, not the target row: the JVM resolves a class by
        # its declared name and the bundle stores the bytes as `target.bin`.
        from .. import jvm as jvmmod
        info = jvmmod.parse(target_bytes)
        main_class = (info.classes or [None])[0]
    # The PREFIX, with `@@` intact -- not the argv we just ran. `run_argv` has the placeholder
    # already replaced by a scratch path that will not exist on the machine replaying this, so
    # baking it in produced `-c /tmp/lykos-<gone>/input.bin ... ./input.bin`: the reproducer
    # opens a missing file, throws NoSuchFileException, and demonstrates nothing. The bundle
    # places `./input.bin` itself.
    data = bundle.build(target_bytes, input_bytes, meta, res.stderr, mode, argv,
                        res.signal_name or "unknown", runtime=runtime,
                        main_class=main_class)
    bundle_sha = ctx.put_artifact("poc-bundle", data=data,
                                  meta={"verified": verified, "level": level})

    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level=level,
                                     verified=verified, signal_name=res.signal_name,
                                     input_sha=input_sha, bundle_sha=bundle_sha)

    if verified:
        fd = FindingDAO(ctx.conn)
        # the SAME key the run that found this input filed it under, or a verified PoC opens a
        # second finding beside the crash it just proved instead of promoting it
        fault_pc = DynResultDAO(ctx.conn).fault_pc_for(target.id, input_sha)
        hj = crash_hijack(ctx.conn, target.id, fault_pc)
        fd.upsert(target.id, target.case_id, crash_finding_candidate(
            res.signal_name, input_sha, res.isolation, "poc", "(PoC verified)",
            state="poc-backed", confidence=0.95, bundle_sha=bundle_sha,
            fault_pc=fault_pc, hijack=hj))
        fid = fd.id_for_dedup(
            target.id, crash_dedup_key(res.signal_name, fault_pc, hijack=hj))
        if fid:
            PocDAO(ctx.conn).set_finding(poc_id, fid)

    ctx.emit("poc.done", payload={"verified": verified, "level": level,
                                  "signal": res.signal_name, "bundle": bundle_sha,
                                  "recorded_signal": wanted,
                                  "signal_matches_finding": not mismatch,
                                  "input_mode": mode, "input_mode_why": mode_why,
                                  "input_modes_tried": tried})
    ctx.progress(pct=100, msg=("PoC verified (%s)" % level) if verified
                 else "PoC not reproduced (input did not crash)")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle"}


def register() -> None:
    register_stage(BUILD_POC_STAGE, build_poc_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_build_poc(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, BUILD_POC_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
