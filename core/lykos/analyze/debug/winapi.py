"""Win32 API behavior trace via Wine's +relay logging -- the Windows analog of the syscall tracer.

`catch syscall` / qemu-strace see only the *Linux* syscalls Wine makes translating Win32 calls,
which is meaningless for Windows behavior. Instead we run the PE under `WINEDEBUG=+relay,+module`
(Wine logs every inter-DLL call) and keep only the calls the TARGET makes *directly*.

Attribution is the crux, because Wine's own service processes (services/plugplay/explorer/...) are
PE32+ images at the *same* ImageBase (0x140000000) as the target, so a return-address range check
alone can't separate them. Two conditions isolate the target: (a) the call is on the target's own
thread -- the thread that emits +module's `map_image_into_view` line for the exe (which also gives
the ASLR-robust runtime range); and (b) its caller return address is inside the exe's range (drops
the target's own DLLs' internal calls, e.g. system()'s inner CreateProcessW). A curated set of
dangerous Win32 APIs then maps to behavior findings.

Scope: process execution, network egress, W^X, self-injection, anti-debug. Registry writes and
file I/O are deliberately omitted -- Wine's own session/CRT init populates the hardware/environment
registry (and reads sysfs) unpredictably, and relay yields only the value name, not the full key
path, so they can't yet be told apart from a target's real persistence write.
"""
from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess

# api name -> behavior category. v1 traces the categories that attribute *cleanly* to the target
# under Wine (TID + ret-range). Registry writes and file I/O are deliberately NOT here: Wine's
# own session/CRT init populates the hardware/environment registry and reads sysfs paths
# unpredictably (sometimes in the target process), and relay gives only the value name (not the
# full key path), so they can't be told apart from a target's real persistence write yet --
# tracked as future work. Name-resolution APIs (getaddrinfo/gethostbyname) are excluded for the
# same reason (the CRT resolves the local hostname at startup); only actual egress is kept.
_EXEC = {"system", "_wsystem", "WinExec", "CreateProcessA", "CreateProcessW",
         "CreateProcessAsUserW", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExW"}
_NET = {"connect", "WSAConnect", "send", "sendto", "InternetConnectA", "InternetConnectW",
        "InternetOpenUrlA", "InternetOpenUrlW", "URLDownloadToFileA", "URLDownloadToFileW",
        "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW"}
_WX = {"VirtualProtect", "VirtualProtectEx"}
_INJECT = {"WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx", "QueueUserAPC",
           "SetThreadContext", "NtMapViewOfSection", "NtUnmapViewOfSection"}
_ANTIDBG = {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "NtSetInformationThread"}
_DANGER = _EXEC | _NET | _WX | _INJECT | _ANTIDBG

_CALL = re.compile(r'^\s*([0-9a-fA-F]+):Call\s+[A-Za-z0-9_]+\.([A-Za-z0-9_]+)\((.*)\)\s+'
                   r'ret=([0-9a-fA-F]+)\s*$')
_STR = re.compile(r'(?:L)?"((?:[^"\\]|\\.)*)"')
# +module logs the runtime map range of every image with the mapping thread's id as the line
# prefix; we want the main exe's -- both its address range AND the thread (=the target process).
_MAP = re.compile(r'^\s*([0-9a-fA-F]+):.*map_image_into_view mapping PE file .*?'
                  r'([^\\/"]+?)"? at 0x([0-9a-fA-F]+)-0x([0-9a-fA-F]+)')
# Wine's own session/service helpers -- never the target's behavior; drop if one slips into a
# trace (belt-and-suspenders behind the warm-up, which normally keeps them out entirely).
_WINE_EXES = ("services.exe", "plugplay.exe", "rpcss.exe", "svchost.exe", "winedevice.exe",
              "winemenubuilder.exe", "explorer.exe", "conhost.exe", "start.exe", "wineboot",
              "rundll32.exe")


def _is_wine_helper(detail) -> bool:
    d = (detail or "").lower()
    return any(h in d for h in _WINE_EXES)


def supported() -> bool:
    return _wine() is not None


def _wine():
    return shutil.which("wine") or shutil.which("wine64")


def _pe_image_range(exe):
    """Static (ImageBase, end) from the PE headers -- the fallback when +module didn't log a
    runtime range (e.g. no relocation, base honoured)."""
    try:
        d = open(exe, "rb").read(4096)
        e = struct.unpack_from("<I", d, 0x3C)[0]
        if d[e:e + 4] != b"PE\x00\x00":
            return None
        opt = e + 24
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic == 0x20B:                                  # PE32+
            base = struct.unpack_from("<Q", d, opt + 24)[0]
        else:                                               # PE32
            base = struct.unpack_from("<I", d, opt + 28)[0]
        size = struct.unpack_from("<I", d, opt + 56)[0]
        return base, base + size
    except Exception:
        return None


def _first_str(args):
    m = _STR.search(args)
    return m.group(1) if m else None


def _target_map(text, exe):
    """(thread-id, lo, hi) of the target exe's own image from +module's map_image line. The
    thread-id identifies the target PROCESS (Wine's service processes -- services/explorer/... --
    run on other threads, and share the same numeric ImageBase, so a range check alone can't
    separate them; the thread does)."""
    base = os.path.basename(str(exe)).lower()
    for m in _MAP.finditer(text):
        if m.group(2).lower() == base:
            return m.group(1), int(m.group(3), 16), int(m.group(4), 16)
    return None


def parse(text, tid, lo, hi):
    """Relay lines that are (a) on the target's own thread `tid` (excludes Wine's service
    processes) and (b) a dangerous API called *directly* by the target -- caller ret inside the
    exe's [lo,hi) range (excludes the target's own DLLs' internal calls, e.g. system()'s inner
    CreateProcessW, on the same thread but returning into msvcrt). Returns behavior events."""
    ev = []
    for line in text.splitlines():
        m = _CALL.match(line)
        if not m:
            continue
        ltid, fn, args, ret = m.group(1), m.group(2), m.group(3), int(m.group(4), 16)
        if fn not in _DANGER or (tid is not None and ltid != tid) or not (lo <= ret < hi):
            continue
        s = _first_str(args)
        if fn in _EXEC:
            if _is_wine_helper(s):
                continue                                 # Wine's own service startup, not target
            ev.append({"api": fn, "category": "exec", "detail": s})
        elif fn in _NET:
            ev.append({"api": fn, "category": "network", "detail": s})
        elif fn in _WX:
            ev.append({"api": fn, "category": "wx", "detail": None})
        elif fn in _INJECT:
            ev.append({"api": fn, "category": "inject", "detail": None})
        elif fn in _ANTIDBG:
            ev.append({"api": fn, "category": "antidebug", "detail": None})
        if len(ev) >= 2000:
            break
    return ev


def _relay(exe, *, argv, stdin, timeout, wineprefix) -> dict:
    """Run the PE under Wine `+relay,+module`, and resolve the target's own thread + module range
    (the attribution key). Returns {ok, text, tid, lo, hi} or {ok: False, note}. Shared by the
    behavior tracer and the dangerous-call monitor."""
    wine = _wine()
    if not wine:
        return {"ok": False, "note": "wine not installed; cannot run a Windows PE here"}
    from ..dynamic import sandbox
    prefix = wineprefix or sandbox._default_wineprefix()   # user-owned, WoW64-capable prefix
    os.makedirs(prefix, exist_ok=True)
    env = {**os.environ, "WINEPREFIX": prefix, "DISPLAY": ""}
    cmd = [wine, str(exe)] + [str(a) for a in argv]
    sandbox._ensure_wineprefix(wine, prefix)            # boot once (only if the prefix is cold)
    env["WINEDEBUG"] = "+relay,+module"
    try:
        proc = subprocess.run(cmd, input=stdin, capture_output=True, timeout=timeout, env=env)
        text = proc.stderr.decode("latin-1", "ignore")
    except subprocess.TimeoutExpired as e:
        text = (e.stderr or b"").decode("latin-1", "ignore")
    tm = _target_map(text, exe)
    if tm:                                              # ASLR-robust: thread + runtime range
        return {"ok": True, "text": text, "tid": tm[0], "lo": tm[1], "hi": tm[2]}
    if "wine: failed to load" in text.lower():
        # The loader could not start the image -- it never ran. Common cause: a 32-bit PE with no
        # i386 WoW64 runtime (wine: failed to load ...\syswow64\ntdll.dll). Report it honestly
        # rather than as "no behavior". (A benign `LdrGetDllHandleEx retval=c0000135` is NOT this
        # -- a normal DLL-probe miss -- so we key only on the loader's message.)
        low = text.lower()
        note = "wine could not launch this PE"
        if "syswow64" in low or "wine32" in low:
            note += (" -- it is 32-bit and the i386 WoW64 runtime is missing (install wine32: "
                     "dpkg --add-architecture i386 && apt-get install wine32:i386)")
        return {"ok": False, "note": note + "."}
    rng = _pe_image_range(exe)                           # fallback: static ImageBase, no thread
    if not rng:
        return {"ok": False, "note": "could not determine the target's module range"}
    return {"ok": True, "text": text, "tid": None, "lo": rng[0], "hi": rng[1]}


def trace(exe, *, argv=(), stdin: bytes = b"", timeout: float = 40.0, wineprefix=None) -> dict:
    r = _relay(exe, argv=argv, stdin=stdin, timeout=timeout, wineprefix=wineprefix)
    if not r.get("ok"):
        return r
    return {"ok": True, "events": parse(r["text"], r["tid"], r["lo"], r["hi"])}
