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
from .capture import MODES, env_var_from_argv, how_to_feed

BUILD_POC_STAGE = "build_poc"
TOOL = "poc"
TOOL_VERSION = "poc-1"



class _SanitizerReplay:
    """A verdict for a fault the SANITIZER reported rather than the kernel.

    `signal_name` carries the sanitizer class, not a signal name, because that is what happened:
    writing "SIGSEGV" for a `heap-buffer-overflow` ASan caught and reported cleanly would be a
    plausible-looking lie in the one field a reader trusts. Downstream only reads these fields.
    """

    def __init__(self, cls: dict, isolation, stderr):
        self.crashed = True
        self.signal_name = str(cls.get("class") or "sanitizer-error")
        self.isolation = isolation
        self.stderr = stderr or b""


class _SocketReplay:
    """sandbox.RunResult-shaped verdict for a socket replay (only these fields are read downstream)."""

    def __init__(self, crashed, signal_name, isolation):
        self.crashed, self.signal_name, self.isolation = bool(crashed), signal_name, isolation
        self.stderr = b""


def _dyn_isolation(conn, target, input_sha):
    """The isolation tag the run that found this input recorded ("net-tcp"/"net-udp"), or None."""
    from ...db.dao import DynResultDAO
    for r in DynResultDAO(conn).list_by_target(target.id):
        if r.input_sha == input_sha and r.isolation:
            return r.isolation
    return None


def _harness_sha(ctx, target, prefix: str):
    """The stored libFuzzer harness whose sha starts with `prefix` (or any, for this target)."""
    from ...db.dao import ArtifactDAO
    arts = [a for a in ArtifactDAO(ctx.conn).list_by_case(target.case_id)
            if a.kind == "libfuzzer-harness"]
    for a in arts:
        if prefix and a.sha256.startswith(prefix):
            return a.sha256
    return arts[-1].sha256 if arts and not prefix else None


def build_poc_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("build_poc requires a target_id")
    p = ctx.params or {}
    input_sha = p.get("input_sha")
    if not input_sha:
        raise ValueError("build_poc requires params.input_sha (a crashing input)")
    timeout = float(p.get("timeout", 10))
    mode, argv, mode_why = how_to_feed(ctx.conn, target, input_sha, p, content=ctx.content)

    input_bytes = ctx.content.get_bytes(input_sha)
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / "target.bin"
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)

    # A libFuzzer crash is a crash of the HARNESS, which is a different binary from the one that
    # was ingested. Replaying the input against the ingested binary is not a weaker test, it is
    # the wrong one: a heap overflow reached through `TIFFReadRGBAImage` does not reproduce under
    # a tool that never calls it, so a genuine memory-corruption finding would be filed as an
    # unverified L0 -- the same mistake prompted delivery made, in a new place. The run that found
    # it recorded the harness in its isolation tag, so this reads the record.
    _iso = _dyn_isolation(ctx.conn, target, input_sha) or ""
    if _iso.startswith("libfuzzer"):
        h_sha = _iso.split("/", 1)[1] if "/" in _iso else ""
        h_full = _harness_sha(ctx, target, h_sha)
        if h_full:
            exe = ctx.scratch() / "harness.bin"
            exe.write_bytes(ctx.content.get_bytes(h_full))
            os.chmod(exe, 0o755)
            target_bytes = exe.read_bytes()              # the bundle must ship the HARNESS
            mode, argv = "file", ["@@"]
            mode_why = ("replayed against the libFuzzer harness the crash was found in "
                        "(the ingested binary need not call the vulnerable path)")

    def _delivery(m):
        """(argv, stdin, env_overrides) for one delivery channel."""
        if m == "stdin":
            return (place(argv, "/dev/stdin") if "@@" in [
                str(a) for a in argv] else list(argv)), input_bytes, None
        if m == "arg":
            # truncate: execve cuts the argument at the first NUL anyway, so this is what the
            # program would actually receive -- refusing outright discarded payloads whose
            # control slot sits safely before it (see sandbox.argv_arg).
            return place(argv, sandbox.argv_arg(input_bytes, truncate=True)), b"", None
        if m == "env":
            # The input is a variable's VALUE; its NAME rides along as a "NAME=@@" argv prefix
            # element, which env_fuzz recorded on the crash. Without this an env-delivered crash
            # fell through to the file channel, never reproduced, and was filed as an unverified
            # L0 -- a crash the pipeline had genuinely found but could not prove.
            var, rest = env_var_from_argv(argv)
            if not var:
                return list(argv), b"", None
            return rest, b"", {var: input_bytes.decode("latin-1")}
        if m == "socket":
            return list(argv), b"", None                 # delivered over a socket, not at exec
        if m == "prompt":
            # Delivered one FIELD PER PROMPT, not at exec: the bytes are the same, the pacing is
            # what makes them land in the right field.
            return list(argv), input_bytes, None
        wf = ctx.scratch() / "input.bin"
        wf.write_bytes(input_bytes)
        return place(argv, str(wf)), b"", None

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
    # A crash found by PROMPTED delivery cannot be replayed in bulk, and sweeping the bulk
    # channels for it produces exactly the wrong answer: the input does not reproduce, so a
    # genuinely confirmed crash is filed as an unverified L0. `read` returns whatever is
    # available, so the whole blob lands in field one and field two reaches EOF -- measured on
    # the HTB target `replaceme`, whose SIGSEGV the campaign confirms and whose PoC stayed L0.
    # The run that found it recorded how (`bwrap+netns/prompted`), so this is reading the
    # record rather than guessing.
    if "prompted" in (_dyn_isolation(ctx.conn, target, input_sha) or ""):
        from ..fuzz.runner import run_input_prompted
        _, pres = run_input_prompted(exe, input_bytes, timeout=timeout)
        tried.append("stdin/prompted")
        if pres.crashed:
            res, mode = pres, "prompt"
            mode_why = f"{mode_why}; replayed one field per prompt, as the campaign delivered it"
    if mode == "socket":
        # A socket crash has NO exec-time carrier: the input only exists once the server is up and
        # listening, so none of the exec-time channels can deliver it and sweeping them is pointless.
        # Spawn the server and send it instead -- the same sequence net_fuzz used to find the crash.
        from ..fuzz import netfuzz
        proto = "udp" if "udp" in ((_dyn_isolation(ctx.conn, target, input_sha) or "")) else "tcp"
        crashed, sig_name, _signum, port = netfuzz.replay_once(
            str(exe), proto, input_bytes, argv=list(argv),
            listen_timeout=float(p.get("listen_timeout", 5.0)))
        res = _SocketReplay(crashed, sig_name, f"net-{proto}")
        tried = [f"socket/{proto}"]
        mode_why = (f"{mode_why}; replayed over a {proto.upper()} socket"
                    + (f" on port {port}" if port else ""))
    for pre in (prefixes if (mode not in ("socket", "prompt")
                            and not (res is not None and res.crashed)) else []):
        argv = pre
        for m in [mode] + [x for x in MODES if x != mode]:
            run_argv, stdin, run_env = _delivery(m)
            res = sandbox.run(exe, argv=run_argv, stdin=stdin, timeout=timeout,
                              arch=target.arch, endianness=target.endianness, bits=target.bits,
                              env_overrides=run_env)
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
    run_argv, stdin, _env = _delivery(mode)

    # A SANITIZER-DETECTED fault is not a signal. ASan/UBSan report the defect and the process
    # exits with a CODE (libFuzzer's harness exits 77), so `crashed` -- which asks "was it killed
    # by a signal" -- is False for a genuine heap-buffer-overflow. Measured on libtiff 4.0.3: the
    # replay printed `ERROR: AddressSanitizer: heap-buffer-overflow` and the PoC was filed as an
    # unverified L0 because nothing read it. This is the same shape the bundle README already
    # states for a JVM fault ("an uncaught exception and exit 1, not a signal"), applied to the
    # verification itself. `parse_asan_report` is used rather than a substring test because it
    # already separates a real report from a sanitizer SETUP failure, which is not a finding.
    if res is not None and not res.crashed and (res.stderr or b""):
        from ..debug.rootcause import parse_asan_report
        _san = parse_asan_report((res.stderr or b"").decode("utf-8", "replace"))
        if _san:
            res = _SanitizerReplay(_san, res.isolation, res.stderr)
            mode_why = (f"{mode_why}; the fault is a {_san.get('sanitizer', 'sanitizer')} report"
                        f" ({_san.get('class')}), not a signal")
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
            fault_pc=fault_pc, hijack=hj, file_type=target.file_type))
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
