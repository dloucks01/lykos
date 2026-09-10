"""Phase 6 — the `synthesize_injection` stage: turn static injection candidates into confirmed
PoCs without fuzzing. For each injection class whose sink the binary imports (system/popen ->
command injection, printf-family -> format string, fopen/open -> path traversal), synthesize
marked payloads, deliver them over the input channel, detonate in the sandbox, and confirm by
effect (marker in output / leaked pointers / /etc/passwd content). A confirmed probe yields a
poc-backed finding carrying the exact demonstrating input.
"""
from __future__ import annotations

import os

from ...db.dao import CallEdgeDAO, FindingDAO, PocDAO, TargetDAO
from ...jobs.registry import register_stage
from ..detect.catalog import normalize
from ..dynamic import sandbox
from . import bundle, injection

INJECT_STAGE = "synthesize_injection"
TOOL = "inject"
TOOL_VERSION = "inject-1"


def _marker():
    return "LYK" + os.urandom(5).hex().upper()       # unique per run, avoids stale-output hits


def _channels(call_edges, given):
    if given:
        return [given]
    names = {normalize(e.dst_name) for e in call_edges if e.dst_name}
    order = []
    if names & {"fopen", "fopen64", "open", "open64", "freopen"}:
        order.append("file")
    if names & {"read", "fgets", "gets", "scanf", "__isoc99_scanf", "fread", "getline"}:
        order.append("stdin")
    order.append("arg")
    for m in ("stdin", "arg", "file"):
        if m not in order:
            order.append(m)
    return order


def _deliver(mode, payload, argv_base, ctx):
    if isinstance(payload, str):
        payload = payload.encode()
    if mode == "stdin":
        return list(argv_base), payload
    if mode == "arg":
        return argv_base + [payload.decode("latin-1")], b""
    wf = ctx.scratch() / "input.bin"
    wf.write_bytes(payload)
    return argv_base + [str(wf)], b""


def synthesize_injection_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("synthesize_injection requires a target_id")
    p = ctx.params or {}
    call_edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    names = {normalize(e.dst_name) for e in call_edges if e.dst_name}
    applicable = {k: v for k, v in injection.PROBES.items() if names & v["sinks"]}
    if not applicable:
        ctx.emit("inject.done", payload={"ok": True, "confirmed": 0,
                 "note": "the binary imports no command/format/file sinks to probe"})
        ctx.progress(pct=100, msg="no injection sinks present")
        return {}

    channels = _channels(call_edges, p.get("input_mode"))
    argv_base = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 8))
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(target_bytes)
    os.chmod(exe, 0o755)

    ctx.emit("inject.start", payload={"probes": sorted(applicable), "channels": channels})
    confirmed = []
    for name, spec in applicable.items():
        marker = _marker()
        payloads = spec["payloads"](marker)
        hit = None
        for payload in payloads:
            for mode in channels:
                run_argv, stdin = _deliver(mode, payload, argv_base, ctx)
                ctx.progress(msg=f"probing {name} ({mode})")
                res = sandbox.run(exe, argv=run_argv, stdin=stdin, timeout=timeout,
                                  arch=target.arch, endianness=target.endianness, bits=target.bits)
                out = (res.stdout or b"") + b"\n" + (res.stderr or b"")
                if spec["confirm"](out, payload, marker):
                    hit = {"payload": payload, "mode": mode, "signal": res.signal_name}
                    break
            if hit:
                break
        if hit:
            confirmed.append({"probe": name, **_finalize(ctx, target, target_bytes, spec, hit)})

    ctx.emit("inject.done", payload={"ok": True, "confirmed": len(confirmed),
             "results": [{"probe": c["probe"], "cwe": c["cwe"], "mode": c["mode"]}
                         for c in confirmed],
             "note": None if confirmed else "no injection confirmed on the entry channel "
                     "(sink may need navigation to reach; try the interactive console)"})
    ctx.progress(pct=100, msg=f"{len(confirmed)} injection PoC(s) confirmed")
    return {}


def _finalize(ctx, target, target_bytes, spec, hit):
    payload = hit["payload"]
    pb = payload if isinstance(payload, bytes) else payload.encode()
    mode = hit["mode"]
    input_sha = ctx.put_artifact("inject-input", data=pb)
    run_argv = [pb.decode("latin-1")] if mode == "arg" else []
    shown = pb.decode("latin-1")[:80]
    detail = (f"{spec['title']} confirmed at runtime via {mode}: payload {shown!r} produced the "
              f"expected effect (no fuzzing)")
    meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
            "argv": run_argv, "level": "L1", "cwe": spec["cwe"], "injection": spec["title"],
            "tool_version": TOOL_VERSION}
    data = bundle.build(target_bytes, pb, meta, b"", mode, run_argv, "none")
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"verified": True, "level": "L1"})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L1", verified=True,
                                     signal_name=None, input_sha=input_sha, bundle_sha=bundle_sha)
    fd = FindingDAO(ctx.conn)
    fd.upsert(target.id, target.case_id, {
        "cwe": spec["cwe"], "severity": spec["severity"], "detector": "inject_synth",
        "title": f"{spec['title']} (confirmed PoC)",
        "evidence": [{"channel": "injection", "detail": detail},
                     {"channel": "poc", "detail": f"verified PoC bundle {bundle_sha[:12]}"}],
        "function_addr": None, "site_addr": None,
        "dedup_key": f"{spec['cwe']}:inject:{mode}", "state": "poc-backed", "confidence": 0.97})
    fid = fd.id_for_dedup(target.id, f"{spec['cwe']}:inject:{mode}")
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    return {"cwe": spec["cwe"], "mode": mode, "bundle": bundle_sha, "input_sha": input_sha}


def register() -> None:
    register_stage(INJECT_STAGE, synthesize_injection_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=180)


def enqueue_inject(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, INJECT_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
