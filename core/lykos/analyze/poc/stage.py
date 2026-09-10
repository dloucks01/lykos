"""Phase 6 — the `build_poc` stage: verify a crashing input in a clean sandbox, assemble a
self-contained PoC bundle, and (on success) promote the finding to POC-BACKED (L1)."""
from __future__ import annotations

import os

from ...db.dao import FindingDAO, PocDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import crash_finding_candidate
from . import bundle

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
    mode = p.get("input_mode", "stdin")
    argv = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 10))

    input_bytes = ctx.content.get_bytes(input_sha)
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(target_bytes)
    os.chmod(exe, 0o755)

    run_argv, stdin = [], b""
    if mode == "stdin":
        stdin = input_bytes
    elif mode == "arg":
        run_argv = [input_bytes.decode("latin-1")]
    elif mode == "file":
        wf = ctx.scratch() / "input.bin"
        wf.write_bytes(input_bytes)
        run_argv = [str(wf)]

    ctx.progress(msg="verifying PoC in a clean sandbox")
    # endianness/bits are load-bearing, not decoration: _qemu_for routes ppc64->ppc64le,
    # mips->mipsel and riscv->riscv32/64 on them. Omitting them hands a little-endian target
    # to the big-endian emulator, which cannot run it -- so the PoC "fails to reproduce" and
    # is filed as an unverified L0 rather than a verified L1.
    res = sandbox.run(exe, argv=run_argv, stdin=stdin, timeout=timeout, arch=target.arch,
                      endianness=target.endianness, bits=target.bits)
    verified = res.crashed
    level = "L1" if verified else "L0"

    meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
            "argv": argv, "expected_signal": res.signal_name, "isolation": res.isolation,
            "verified": verified, "tool_version": TOOL_VERSION}
    data = bundle.build(target_bytes, input_bytes, meta, res.stderr, mode, run_argv,
                        res.signal_name or "unknown")
    bundle_sha = ctx.put_artifact("poc-bundle", data=data,
                                  meta={"verified": verified, "level": level})

    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level=level,
                                     verified=verified, signal_name=res.signal_name,
                                     input_sha=input_sha, bundle_sha=bundle_sha)

    if verified:
        fd = FindingDAO(ctx.conn)
        fd.upsert(target.id, target.case_id, crash_finding_candidate(
            res.signal_name, input_sha, res.isolation, "poc", "(PoC verified)",
            state="poc-backed", confidence=0.95, bundle_sha=bundle_sha))
        fid = fd.id_for_dedup(target.id, f"dynamic-crash:{res.signal_name}")
        if fid:
            PocDAO(ctx.conn).set_finding(poc_id, fid)

    ctx.emit("poc.done", payload={"verified": verified, "level": level,
                                  "signal": res.signal_name, "bundle": bundle_sha})
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
