"""Phase 6 — the `behavior_trace` stage: run the target and inventory the security-relevant
syscalls it makes (process exec, network, file writes/deletes, permission changes, anti-debug,
W^X). A behavioral capability report -- what the binary *does* -- plus findings for the
high-signal behaviors (outbound network, anti-debugging, self-modifying code, process exec).
Deterministic; native x86-64 (child processes across fork are not followed in v1).
"""
from __future__ import annotations

import json
import os

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from . import syscalls

TRACE_STAGE = "behavior_trace"
TOOL = "behavior"
TOOL_VERSION = "behavior-1"


def _private(ip: str) -> bool:
    return (ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.")
            or ip == "0.0.0.0" or any(ip.startswith(f"172.{i}.") for i in range(16, 32)))


def _finding(fd, target, cwe, sev, title, detail, key):
    fd.upsert(target.id, target.case_id, {
        "cwe": cwe, "severity": sev, "detector": "behavior", "title": title[:200],
        "evidence": [{"channel": "behavior", "detail": detail}],
        "function_addr": None, "site_addr": None, "dedup_key": key,
        "state": "corroborated", "confidence": 0.8})


def behavior_trace_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("behavior_trace requires a target_id")
    p = ctx.params or {}
    host = sandbox.host_arch()
    if (target.arch and target.arch != host) or not syscalls.supported(target.arch or host):
        ctx.emit("behavior.done", payload={"ok": False, "supported": False,
                 "note": f"behavior trace is x86-64-only for now (target {target.arch})"})
        ctx.progress(pct=100, msg="behavior trace not supported for this target")
        return {}

    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
    os.chmod(exe, 0o755)
    mode = p.get("input_mode", "stdin")
    argv = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 25))
    data = ctx.content.get_bytes(p["input_sha"]) if p.get("input_sha") else b"A" * 64
    run_argv = argv + [data.decode("latin-1")] if (mode == "arg" and data) else argv
    stdin = data if mode == "stdin" else b""

    ctx.progress(msg="tracing syscalls under GDB")
    res = syscalls.trace(exe, target.arch or host, argv=run_argv, stdin=stdin, timeout=timeout)
    if not res.get("ok"):
        ctx.emit("behavior.done", payload={"ok": False, "note": res.get("note")})
        ctx.progress(pct=100, msg="trace could not run: " + str(res.get("note")))
        return {}

    ev = res.get("events", [])
    inv = {"exec": [], "network": [], "files_written": [], "deleted": [], "chmod": [],
           "sockets": [], "anti_debug": False, "wx": False, "priv": [], "spawned": 0}
    for e in ev:
        s = e.get("syscall")
        if s in ("execve", "execveat") and e.get("path"):
            inv["exec"].append(e["path"])
        elif s in ("connect", "sendto") and e.get("dest", {}).get("family") == "inet":
            inv["network"].append(f"{e['dest'].get('addr')}:{e['dest'].get('port')}")
        elif s == "socket":
            inv["sockets"].append(e.get("family"))
        elif s in ("open", "openat") and e.get("write") and e.get("path"):
            inv["files_written"].append(e["path"])
        elif s in ("unlink", "unlinkat") and e.get("path"):
            inv["deleted"].append(e["path"])
        elif s in ("chmod", "fchmodat") and e.get("path"):
            inv["chmod"].append(e["path"])
        elif s == "ptrace" and e.get("request") == 0:
            inv["anti_debug"] = True
        elif s == "mprotect" and e.get("exec"):
            inv["wx"] = True
        elif s in ("setuid", "setgid"):
            inv["priv"].append(f"{s}({e.get('id')})")
        elif s in ("clone", "fork", "vfork"):
            inv["spawned"] += 1
    for k in ("exec", "network", "files_written", "deleted", "chmod", "sockets", "priv"):
        inv[k] = sorted(set(inv[k]))

    report_sha = ctx.put_artifact("behavior-trace",
                                  data=json.dumps({"events": ev, "inventory": inv},
                                                  indent=2, default=str).encode())

    fd = FindingDAO(ctx.conn)
    findings = 0
    for dest in inv["network"]:
        ip = dest.rsplit(":", 1)[0]
        ext = not _private(ip)
        _finding(fd, target, "BEHAVIOR", "medium" if ext else "low",
                 f"Outbound network connection to {dest}"
                 + (" (external -- possible C2/exfil)" if ext else " (local)"),
                 f"the binary called connect() to {dest} at runtime", f"BEHAVIOR:net:{dest}")
        findings += 1
    for path in inv["exec"]:
        _finding(fd, target, "BEHAVIOR", "medium", f"Process execution: {path}",
                 f"the binary exec'd {path!r} at runtime", f"BEHAVIOR:exec:{path}")
        findings += 1
    if inv["anti_debug"]:
        _finding(fd, target, "BEHAVIOR", "low", "Anti-debugging (ptrace PTRACE_TRACEME)",
                 "the binary called ptrace(PTRACE_TRACEME) -- a debugger-evasion check",
                 "BEHAVIOR:antidebug")
        findings += 1
    if inv["wx"]:
        _finding(fd, target, "BEHAVIOR", "low",
                 "Writable+executable memory (self-modifying / shellcode surface)",
                 "the binary made memory executable via mprotect(PROT_EXEC)", "BEHAVIOR:wx")
        findings += 1

    ctx.emit("behavior.done", payload={"ok": True, "syscalls": len(ev), "inventory": inv,
             "findings": findings, "report": report_sha,
             "note": None if ev else "no monitored syscalls observed on this input"})
    ctx.progress(pct=100, msg=f"{len(ev)} syscall(s); "
                 f"exec={len(inv['exec'])} net={len(inv['network'])} "
                 f"antidebug={inv['anti_debug']} wx={inv['wx']}")
    return {"output_shas": [report_sha], "output_kind": "behavior-trace"}


def register() -> None:
    register_stage(TRACE_STAGE, behavior_trace_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_behavior_trace(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, TRACE_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
