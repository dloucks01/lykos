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
import tempfile

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
# registry + file: now attributable (target mapping threads exclude Wine's session-init writes),
# and the full key path is recovered from the subkey arg of RegCreateKey/RegOpenKey + its HKEY
# root. Persistence is flagged from the key path; RegSetValueEx is a registry write.
_REG_OPEN = {"RegCreateKeyExW", "RegCreateKeyExA", "RegCreateKeyW", "RegCreateKeyA",
             "RegOpenKeyExW", "RegOpenKeyExA"}
_REG_SET = {"RegSetValueExW", "RegSetValueExA", "RegSetValueW", "RegSetValueA"}
_FILE_W = {"CreateFileW", "CreateFileA"}
_FILE_DEL = {"DeleteFileW", "DeleteFileA"}
# The C runtime is how a large class of Windows binaries actually does I/O, and the Win32 call
# underneath happens inside msvcrt -- which is NOT the target's image, so it is correctly not
# attributed to it. Watching only the Win32 names meant a mingw-built jhead, which opens and
# reads the file it is given, reported "calls: 0, ok: true" out of 368 attributed calls: a
# behaviour inventory that says a file parser touches no files.
_CRT_FILE = {"fopen", "_wfopen", "fopen_s", "freopen", "_open", "_wopen", "_sopen",
             "fread", "fwrite", "fputc", "fgetc", "fgets", "fputs"}
_CRT_FILE_W = {"remove", "_unlink", "_wunlink", "rename", "_wrename"}
_CRT_EXEC = {"_popen", "_wpopen", "_spawnl", "_spawnv", "_spawnve", "_execv", "_execve"}
_EXEC = _EXEC | _CRT_EXEC
_DANGER = (_EXEC | _NET | _WX | _INJECT | _ANTIDBG | _REG_OPEN | _REG_SET | _FILE_W
           | _FILE_DEL | _CRT_FILE | _CRT_FILE_W)

_REG_ROOTS = {"80000000": "HKCR", "80000001": "HKCU", "80000002": "HKLM",
              "80000003": "HKU", "80000005": "HKCC"}
_FILE_WRITE_ACCESS = ("40000000", "10000000", "c0000000")  # GENERIC_WRITE / ALL / READ|WRITE


def _reg_root(args):
    tok = args.split(",", 1)[0].strip().lower()[-8:]
    return _REG_ROOTS.get(tok, "")

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


def _winpath(s):
    """Wine relay prints wide-string backslashes escaped (`Software\\\\Microsoft`); collapse the
    doubled backslashes so a captured registry key / file path matches on real path substrings."""
    return s.replace("\\\\", "\\") if s else s


def _target_maps(text, exe):
    """All (thread-id, lo, hi) mappings of the target exe from +module's map_image lines. New-Wine
    (WoW64) maps a DYNAMICBASE exe TWICE -- a transient loader inspection at a low base, then the
    real run at 0x140000000 (a different thread) -- so we must attribute against every mapping,
    not just the first. The thread-id identifies the target PROCESS (Wine's service processes run
    on other threads and share the numeric ImageBase, so a range check alone can't separate them);
    a tid of None (static-range fallback) matches any thread."""
    base = os.path.basename(str(exe)).lower()
    out = []
    for line in text.splitlines():                      # _MAP is ^-anchored: match per line
        m = _MAP.match(line)
        if m and m.group(2).lower() == base:
            out.append((m.group(1), int(m.group(3), 16), int(m.group(4), 16)))
    return out


def _in_target(maps, ltid, ret):
    return any((tid is None or ltid == tid) and lo <= ret < hi for tid, lo, hi in maps)


def parse(text, maps):
    """Relay lines that are (a) on one of the target's own mapping threads (excludes Wine's
    service processes) and (b) a dangerous API called *directly* by the target -- caller ret
    inside that mapping's range (excludes the target's own DLLs' internal calls, e.g. system()'s
    inner CreateProcessW, returning into msvcrt). Returns behavior events."""
    ev = []
    for line in text.splitlines():
        m = _CALL.match(line)
        if not m:
            continue
        ltid, fn, args, ret = m.group(1), m.group(2), m.group(3), int(m.group(4), 16)
        if fn not in _DANGER or not _in_target(maps, ltid, ret):
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
        elif fn in _REG_OPEN:
            root, sub = _reg_root(args), _winpath(s)
            key = (root + "\\" + sub) if (root and sub) else (sub or root)
            if key:
                ev.append({"api": fn, "category": "regkey", "detail": key})
        elif fn in _REG_SET:
            ev.append({"api": fn, "category": "regvalue", "detail": s})
        elif fn in _FILE_W:
            write = any(a in args.lower() for a in _FILE_WRITE_ACCESS)
            ev.append({"api": fn, "category": "file", "detail": _winpath(s), "write": write})
        elif fn in _FILE_DEL:
            ev.append({"api": fn, "category": "delete", "detail": _winpath(s)})
        elif fn in _CRT_FILE:
            # A CRT call carries a path only when it opens; fread/fputc name a FILE* the trace
            # cannot resolve to a name, so those are recorded as file activity without one
            # rather than dropped -- "this program reads files" is the inventory's job.
            write = fn in ("fwrite", "fputs", "fputc") or '"w' in args or '"a' in args
            ev.append({"api": fn, "category": "file", "detail": _winpath(s) or None,
                       "write": write})
        elif fn in _CRT_FILE_W:
            ev.append({"api": fn, "category": "delete", "detail": _winpath(s)})
        if len(ev) >= 2000:
            break
    return ev


_RELAY_CAP = 32 << 20          # bytes of +relay trace to keep; the rest is not worth the RAM


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
    # +relay logs EVERY Win32 call: one second of jhead produces 24 MB on a warm prefix, and
    # several times that while Wine boots a cold one. Buffering it in the parent held it as
    # bytes and then again as a str. Spill it to a file and read back a bounded prefix, so a
    # long-running or chatty target cannot take the server down -- and say when it was cut,
    # because a trace that was cut means a partial inventory.
    truncated = timed_out = False
    with tempfile.TemporaryFile() as errf:
        try:
            subprocess.run(cmd, input=stdin, stdout=subprocess.DEVNULL, stderr=errf,
                           timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            # We stopped watching; the program did not stop running. Swallowed silently, this
            # is indistinguishable from a program that ran to completion and did nothing --
            # so a PE killed mid-run reported "no persistence, no network, no exec" and the
            # inventory read as a clean bill of health. Record it and let the caller say so.
            timed_out = True
        # the CHILD wrote to this fd, so the parent's own file position never moved --
        # tell() returns 0 and the truncation flag could never fire
        size = os.fstat(errf.fileno()).st_size
        errf.seek(0)
        raw = errf.read(_RELAY_CAP)
        truncated = size > _RELAY_CAP
    text = raw.decode("latin-1", "ignore")
    maps = _target_maps(text, exe)
    if maps:                                            # ASLR-robust: thread(s) + runtime range(s)
        return {"ok": True, "text": text, "maps": maps, "truncated": truncated,
                "timed_out": timed_out}
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
    rng = _pe_image_range(exe)                           # fallback: static ImageBase, any thread
    if not rng:
        return {"ok": False, "note": "could not determine the target's module range"}
    return {"ok": True, "text": text, "maps": [(None, rng[0], rng[1])],
            "truncated": truncated, "timed_out": timed_out}


def trace(exe, *, argv=(), stdin: bytes = b"", timeout: float = 40.0, wineprefix=None) -> dict:
    r = _relay(exe, argv=argv, stdin=stdin, timeout=timeout, wineprefix=wineprefix)
    if not r.get("ok"):
        return r
    return {"ok": True, "events": parse(r["text"], r["maps"]),
            "truncated": bool(r.get("truncated")), "timed_out": bool(r.get("timed_out"))}
