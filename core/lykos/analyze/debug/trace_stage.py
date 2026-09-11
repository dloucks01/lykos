"""Phase 6 — the `behavior_trace` stage: run the target and inventory the security-relevant
syscalls it makes (process exec, network, file writes/deletes, permission changes, anti-debug,
W^X). A behavioral capability report -- what the binary *does* -- plus findings for the
high-signal behaviors (outbound network, anti-debugging, self-modifying code, process exec).
Deterministic. Three backends behind one stage: native x86-64 ELF under GDB `catch syscall`;
cross-arch ELF under qemu-user's `-strace` (ABI-aware for any arch qemu supports); and Windows
PE under Wine's `+relay` API trace (`winapi`, the Windows analog -- process exec, network egress,
registry autostart persistence, file writes/deletes, W^X, self-injection, anti-debug). Child
processes across fork aren't followed in v1; the qemu backend can't decode the connect() sockaddr;
the PE backend attributes calls to the target by thread(s) + return address into the exe's mapped
range(s), and reports only full-path autostart-persistence keys (Wine's in-process session init
touches the registry too, so the raw key list stays in the events artifact, not the inventory).
"""
from __future__ import annotations

import json
import os

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..poc.capture import how_to_feed
from . import syscalls, winapi

TRACE_STAGE = "behavior_trace"
TOOL = "behavior"
TOOL_VERSION = "behavior-5"        # Windows PE Win32-API trace (exec/net/wx/inject/antidbg)


# Registry key paths that grant code execution at logon/boot -- the classic persistence locations,
# as the *full* path form (root + subkey). Wine's own session init creates/opens some autostart
# containers too, but with bare relative subkeys or under CurrentControlSet\Services (which it
# always enumerates), so those are deliberately NOT here -- only the full CurrentVersion\Run(Once),
# Winlogon, IFEO, AppInit_DLLs forms the target writes, which Wine boot does not.
_WIN_PERSIST = ("currentversion\\run", "currentversion\\runonce", "currentversion\\policies\\run",
                "winlogon\\userinit", "winlogon\\shell", "image file execution options",
                "appinit_dlls")


def _private(ip: str) -> bool:
    return (ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.")
            or ip == "0.0.0.0" or any(ip.startswith(f"172.{i}.") for i in range(16, 32)))


def _finding(fd, target, cwe, sev, title, detail, key):
    fd.upsert(target.id, target.case_id, {
        "cwe": cwe, "severity": sev, "detector": "behavior", "title": title[:200],
        "evidence": [{"channel": "behavior", "detail": detail}],
        "function_addr": None, "site_addr": None, "dedup_key": key,
        "state": "corroborated", "confidence": 0.8})


def _win_behavior_trace(ctx, target, p) -> dict:
    """Windows PE branch: trace the target's own Win32 API calls under Wine (+relay) and turn the
    high-signal ones (exec, network, registry persistence, W^X/injection, anti-debug) into
    findings -- the Windows analog of the syscall inventory."""
    if not winapi.supported():
        ctx.emit("behavior.done", payload={"ok": False, "supported": False,
                 "note": "wine not installed; cannot trace a Windows PE's API calls here"})
        ctx.progress(pct=100, msg="behavior trace needs wine for PE targets")
        return {}
    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
    os.chmod(exe, 0o755)
    mode = how_to_feed(ctx.conn, target, p.get("input_sha"), p)[0]
    argv = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 45))
    data = ctx.content.get_bytes(p["input_sha"]) if p.get("input_sha") else b""
    run_argv = argv + [data.decode("latin-1")] if (mode == "arg" and data) else argv
    stdin = data if mode == "stdin" else b""

    ctx.progress(msg="tracing Win32 API calls under Wine (+relay)")
    res = winapi.trace(exe, argv=run_argv, stdin=stdin, timeout=timeout)
    if not res.get("ok"):
        ctx.emit("behavior.done", payload={"ok": False, "note": res.get("note")})
        ctx.progress(pct=100, msg="win32 trace could not run: " + str(res.get("note")))
        return {}

    ev = res.get("events", [])
    # persistence is the clean registry signal: a write under a full-path autostart key. The raw
    # registry activity is polluted by Wine's in-process session init (BIOS/CPU/service
    # enumeration), so we report `persistence` rather than the whole key list (the full activity
    # stays in the events artifact). File writes/deletes are clean (Wine's own reads are write=0).
    inv = {"exec": [], "network": [], "persistence": [], "files_written": [],
           "deleted": [], "wx": False, "inject": False, "anti_debug": False}
    for e in ev:
        c, d = e.get("category"), e.get("detail")
        if c == "exec":
            inv["exec"].append(d or e["api"])
        elif c == "network":
            inv["network"].append(d or e["api"])
        elif c == "regkey" and d and any(pat in d.lower() for pat in _WIN_PERSIST):
            inv["persistence"].append(d)
        elif c == "file" and e.get("write") and d:
            inv["files_written"].append(d)
        elif c == "delete" and d:
            inv["deleted"].append(d)
        elif c == "wx":
            inv["wx"] = True
        elif c == "inject":
            inv["inject"] = True
        elif c == "antidebug":
            inv["anti_debug"] = True
    for k in ("exec", "network", "persistence", "files_written", "deleted"):
        inv[k] = sorted(set(inv[k]))
    persist = inv["persistence"]

    report_sha = ctx.put_artifact("behavior-trace",
                                  data=json.dumps({"events": ev, "inventory": inv,
                                                   "platform": "windows"},
                                                  indent=2, default=str).encode())
    fd = FindingDAO(ctx.conn)
    findings = 0
    for cmd in inv["exec"]:
        _finding(fd, target, "BEHAVIOR", "medium", f"Process execution: {cmd[:120]}",
                 f"the PE launched a process via a Win32 exec API: {cmd!r}",
                 f"BEHAVIOR:win:exec:{cmd[:60]}")
        findings += 1
    if inv["network"]:
        _finding(fd, target, "BEHAVIOR", "medium",
                 "Outbound network activity (Win32 sockets/WinINet)",
                 "the PE called a Win32 network API (connect/WSAConnect/InternetConnect/…): "
                 + ", ".join(inv["network"][:5]), "BEHAVIOR:win:net")
        findings += 1
    if inv["inject"]:
        _finding(fd, target, "BEHAVIOR", "high", "Process injection primitive",
                 "the PE used WriteProcessMemory/CreateRemoteThread/VirtualAllocEx (code "
                 "injection into another process)", "BEHAVIOR:win:inject")
        findings += 1
    if inv["wx"]:
        _finding(fd, target, "BEHAVIOR", "low",
                 "Writable+executable memory (self-modifying / shellcode surface)",
                 "the PE made memory executable via VirtualProtect(PAGE_EXECUTE_*)",
                 "BEHAVIOR:win:wx")
        findings += 1
    if inv["anti_debug"]:
        _finding(fd, target, "BEHAVIOR", "low", "Anti-debugging check",
                 "the PE called an anti-debug API (IsDebuggerPresent/CheckRemoteDebuggerPresent/"
                 "NtQueryInformationProcess)", "BEHAVIOR:win:antidebug")
        findings += 1
    for key in persist:
        _finding(fd, target, "BEHAVIOR", "high",
                 f"Registry autostart persistence: {key[:110]}",
                 f"the PE created/opened a known autostart persistence key ({key!r}) and wrote to "
                 "the registry at runtime", f"BEHAVIOR:win:persist:{key[:70]}")
        findings += 1
    for path in inv["files_written"]:
        _finding(fd, target, "BEHAVIOR", "low", f"File write: {path[:110]}",
                 f"the PE opened a file for writing: {path!r}", f"BEHAVIOR:win:file:{path[:70]}")
        findings += 1
    for path in inv["deleted"]:
        _finding(fd, target, "BEHAVIOR", "low", f"File deletion: {path[:110]}",
                 f"the PE deleted a file: {path!r}", f"BEHAVIOR:win:del:{path[:70]}")
        findings += 1

    ctx.emit("behavior.done", payload={"ok": True, "platform": "windows", "calls": len(ev),
             "inventory": inv, "findings": findings, "report": report_sha,
             "note": None if ev else "no monitored Win32 API calls observed on this input"})
    ctx.progress(pct=100, msg=f"{len(ev)} Win32 call(s); exec={len(inv['exec'])} "
                 f"net={bool(inv['network'])} persist={len(persist)} "
                 f"files={len(inv['files_written'])} del={len(inv['deleted'])}")
    return {"output_shas": [report_sha], "output_kind": "behavior-trace"}


def behavior_trace_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("behavior_trace requires a target_id")
    p = ctx.params or {}
    host = sandbox.host_arch()
    fmt = (target.file_type or "").lower()
    # Windows PE -> the Win32 API tracer (Wine +relay); ELF -> the syscall tracer below.
    if fmt == "pe":
        return _win_behavior_trace(ctx, target, p)
    if fmt and fmt != "elf":                              # Mach-O etc.: no substrate here
        ctx.emit("behavior.done", payload={"ok": False, "supported": False,
                 "note": f"behavior trace runs Linux ELF or Windows PE (via Wine); this target "
                         f"is {fmt.upper()} (macOS needs a full-system VM)."})
        ctx.progress(pct=100, msg=f"behavior trace does not support {fmt.upper()} targets")
        return {}
    emulated = bool(target.arch and target.arch != host)
    # backend: auto (native->gdb, cross->qemu), or forced. The gdb backend decodes the connect()
    # sockaddr (ip:port) but can't follow a forked child's exec (system/popen via clone3); the
    # qemu backend follows children (captures that exec) but leaves the connect dest undecoded.
    backend = (ctx.params or {}).get("backend", "auto").lower()
    use_qemu = backend == "qemu" or (backend == "auto" and emulated)
    if use_qemu and not sandbox._qemu_for(target.arch or host, target.endianness, target.bits):
        ctx.emit("behavior.done", payload={"ok": False, "supported": False,
                 "note": f"no qemu-user for {target.arch or host} (qemu behavior trace needs it)"})
        ctx.progress(pct=100, msg="behavior trace not supported (no qemu-user)")
        return {}
    if not use_qemu and emulated:
        ctx.emit("behavior.done", payload={"ok": False, "supported": False,
                 "note": f"the gdb behavior backend is native-only (target {target.arch}); "
                         f"use backend=qemu for cross-arch"})
        ctx.progress(pct=100, msg="gdb backend can't trace this cross-arch target")
        return {}
    if not use_qemu and not syscalls.supported(host):
        ctx.emit("behavior.done", payload={"ok": False, "supported": False,
                 "note": f"native gdb behavior trace has no syscall map for {host}"})
        ctx.progress(pct=100, msg="behavior trace not supported for this target")
        return {}

    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
    os.chmod(exe, 0o755)
    mode = how_to_feed(ctx.conn, target, p.get("input_sha"), p)[0]
    argv = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 25))
    data = ctx.content.get_bytes(p["input_sha"]) if p.get("input_sha") else b"A" * 64
    run_argv = argv + [data.decode("latin-1")] if (mode == "arg" and data) else argv
    stdin = data if mode == "stdin" else b""

    if use_qemu:
        arch = target.arch or host
        ctx.progress(msg=f"tracing syscalls under qemu-{arch} (-strace)")
        res = syscalls.trace_qemu(exe, arch, endianness=target.endianness,
                                  bits=target.bits, argv=run_argv, stdin=stdin, timeout=timeout)
    else:
        ctx.progress(msg="tracing syscalls under GDB")
        res = syscalls.trace(exe, host, argv=run_argv, stdin=stdin, timeout=timeout)
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
            d = e["dest"]
            # native decodes ip:port; the qemu backend can't decode the sockaddr -> mark undecoded
            inv["network"].append(f"{d['addr']}:{d['port']}" if d.get("addr")
                                  else "inet (destination not decoded under qemu-strace)")
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
        elif s in ("clone", "clone3", "fork", "vfork"):
            inv["spawned"] += 1
    for k in ("exec", "network", "files_written", "deleted", "chmod", "sockets", "priv"):
        inv[k] = sorted(set(inv[k]))

    report_sha = ctx.put_artifact("behavior-trace",
                                  data=json.dumps({"events": ev, "inventory": inv},
                                                  indent=2, default=str).encode())

    fd = FindingDAO(ctx.conn)
    findings = 0
    for dest in inv["network"]:
        if dest.startswith("inet ("):                 # qemu: connection made, destination unknown
            _finding(fd, target, "BEHAVIOR", "medium",
                     "Outbound network connection attempt (destination not decoded)",
                     "the binary called connect() on an AF_INET socket at runtime; qemu-strace "
                     "does not decode the sockaddr, so the destination is unknown",
                     "BEHAVIOR:net:undecoded")
            findings += 1
            continue
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
