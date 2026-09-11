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
from ..poc.capture import how_to_feed
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


def worth_filing(value: str, is_gate: bool, caller: str | None) -> bool:
    """Is this recovered constant a FINDING, or just reverse-engineering inventory?

    A comparison is evidence about the program's handling of input only when our input was one
    of the operands (`is_gate`). Everything else is a constant the process happened to compare
    while we watched -- and the probe sees the dynamic loader's own strcmp calls, which is most
    of them. ncompress filed 56 corroborated findings that way, every one a loader path like
    '/lib64/ld-linux-x86-64.so.2'.

    A value or caller that NAMES a secret is kept even ungated: `strcmp(x, "api_key")` is worth
    surfacing however it was reached.
    """
    return bool(is_gate or _SECRET_KW.search(value or "")
                or _SECRET_KW.search(caller or ""))


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

    edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    names = {normalize(e.dst_name) for e in edges if e.dst_name}
    funcs = sorted(names & set(secrets.CMP))
    if not funcs:
        # Distinguish "nothing to probe" from "we have not looked yet". The call graph only
        # exists after disassembly, and reporting an un-disassembled target as having no
        # comparison functions is the same clean-looking wrong answer as "no fault reproduced"
        # was for an input fed the wrong way.
        note = ("the binary imports no comparison functions to probe" if edges else
                "no call graph for this target yet -- run disassemble before extract_secrets")
        ctx.emit("secrets.done", payload={"ok": bool(edges), "hits": 0, "findings": 0,
                 "note": note})
        ctx.progress(pct=100, msg="no comparison sinks to probe")
        return {}

    mode = how_to_feed(ctx.conn, target, p.get("input_sha"), p)[0]
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
            secretish = worth_filing(val, is_gate, h.get("caller"))
            if not secretish:
                # Neither operand was our input, so this comparison says nothing about how the
                # program handles input -- and the probe sees the dynamic loader's own strcmp
                # calls, which is most of them. ncompress filed 56 corroborated findings this
                # way, every one of them a loader path like '/lib64/ld-linux-x86-64.so.2'.
                # It stays in `recovered` as RE inventory; it is not a finding.
                continue
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
