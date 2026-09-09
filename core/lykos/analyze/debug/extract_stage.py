"""Phase 6 — the `extract_secrets` stage: recover the constants a program checks input against.

Runs the target under GDB with breakpoints on the comparison functions it imports, feeding a
distinctive probe input. At each comparison both operands are captured; the operand that is not
our probe is the *expected* value -- a password, magic bytes, an expected token, a menu command.
These are auto-recovered offensive-RE facts (a gate on our input becomes a hard-coded-value
finding), deterministic and needing no crash. Native-arch only (host GDB).
"""
from __future__ import annotations

import re

from ...db.dao import CallEdgeDAO, FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..detect.catalog import normalize
from ..dynamic import sandbox
from . import secrets

EXTRACT_STAGE = "extract_secrets"
TOOL = "secrets"
TOOL_VERSION = "secrets-1"
_PROBE = b"LYKOSprobe0123456789ABCDEF"     # distinctive marker: our operand contains "LYKOSprobe"
_MARK = "LYKOSprobe"
_SECRET_KW = re.compile(r"(pass|pwd|secret|key|token|auth|admin|login|licen[sc]e|flag)", re.I)


def _printable(s):
    return bool(s) and all(32 <= ord(c) < 127 or c in "\t" for c in s)


def _ours(v):
    """Is this operand (a slice of) our probe input?"""
    return bool(v) and (_MARK in v or v in _PROBE.decode("latin-1") or
                        _PROBE.decode("latin-1").startswith(v[:8]))


def extract_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("extract_secrets requires a target_id")
    p = ctx.params or {}
    host = sandbox.host_arch()
    if (target.arch and target.arch != host) or not secrets.supported(target.arch or host):
        ctx.emit("secrets.done", payload={"ok": False, "supported": False,
                 "note": f"secret extraction is native-arch only (target {target.arch}, "
                         f"host {host}); cross-arch via qemu-gdbstub is future work"})
        ctx.progress(pct=100, msg="secret extraction not supported for this target")
        return {}

    names = {normalize(e.dst_name) for e in CallEdgeDAO(ctx.conn).list_by_target(target.id)
             if e.dst_name}
    funcs = sorted(names & set(secrets.CMP))
    if not funcs:
        ctx.emit("secrets.done", payload={"ok": True, "hits": 0, "findings": 0,
                 "note": "the binary imports no comparison functions to probe"})
        ctx.progress(pct=100, msg="no comparison sinks to probe")
        return {}

    mode = p.get("input_mode", "stdin")
    argv = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 20))
    data = ctx.content.get_bytes(p["input_sha"]) if p.get("input_sha") else _PROBE
    run_argv = argv + [data.decode("latin-1")] if (mode == "arg" and data) else argv
    stdin = data if mode == "stdin" else b""

    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
    import os
    os.chmod(exe, 0o755)

    ctx.progress(msg=f"probing {len(funcs)} comparison(s) under GDB: {', '.join(funcs)}")
    res = secrets.run_extract(exe, funcs, target.arch or host, argv=run_argv, stdin=stdin,
                              timeout=timeout)
    if not res.get("ok"):
        ctx.emit("secrets.done", payload={"ok": False, "note": res.get("note")})
        ctx.progress(pct=100, msg="extraction could not run: " + str(res.get("note")))
        return {}

    hits = res.get("hits", [])
    fd = FindingDAO(ctx.conn)
    recovered, seen, findings = [], set(), 0
    for h in hits:
        a0, a1 = h.get("a0"), h.get("a1")
        ours0, ours1 = _ours(a0), _ours(a1)
        # the expected constant is the operand that is not our probe
        cands = []
        if ours0 and not ours1:
            cands = [(a1, True)]
        elif ours1 and not ours0:
            cands = [(a0, True)]
        else:                                   # neither is ours: still report constants seen
            cands = [(a0, False), (a1, False)]
        for val, is_gate in cands:
            if not _printable(val) or not (1 <= len(val) <= 128):
                continue
            if val in seen:
                continue
            seen.add(val)
            recovered.append({"value": val, "gate": is_gate, "via": h.get("func"),
                              "func": h.get("caller")})
            secretish = is_gate or bool(_SECRET_KW.search(val)) or \
                bool(_SECRET_KW.search(h.get("caller") or ""))
            cwe = "CWE-798" if secretish else "CWE-547"
            sev = "medium" if secretish else "low"
            title = (f"Input compared against hard-coded value '{val}'" if is_gate
                     else f"Hard-coded comparison constant '{val}'")
            fd.upsert(target.id, target.case_id, {
                "cwe": cwe, "title": title[:200], "severity": sev, "detector": "secret_probe",
                "evidence": [{"channel": "compare-probe",
                              "detail": f"{h.get('func')}() compared our input against '{val}'"
                              + (f" in {h['caller']}()" if h.get("caller") else "")
                              + " (recovered at runtime)"}],
                "function_addr": None, "site_addr": None,
                "dedup_key": f"{cwe}:secret:{val}", "state": "corroborated", "confidence": 0.85})
            findings += 1

    ctx.emit("secrets.done", payload={"ok": True, "hits": len(hits), "findings": findings,
             "recovered": recovered[:40],
             "note": None if hits else "no comparisons observed on this input"})
    ctx.progress(pct=100, msg=f"{len(hits)} comparison(s), {findings} value(s) recovered")
    return {}


def register() -> None:
    register_stage(EXTRACT_STAGE, extract_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_extract(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, EXTRACT_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
