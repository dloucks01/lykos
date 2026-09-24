"""Win32 dangerous-call monitor -- the Windows analog of `debug_monitor`.

Runs the PE under Wine `+relay` (via `winapi._relay`) and captures the CONCRETE ARGUMENTS the
target passes to dangerous Win32 sinks: the command line to CreateProcess/WinExec/ShellExecute/
system, the URL to URLDownloadToFile, the format string to wsprintf, the source of a string copy,
and the module name to LoadLibrary. Sound signals become findings -- an executed command
(CWE-78), a `%n`/`%s` format string on attacker data (CWE-134), a remote-file download (CWE-494);
the rest is a runtime call log (evidence). Attribution is the same as the behavior tracer: keep
only calls on the target's own thread whose caller return address is inside the exe's mapped
range (so Wine's service processes and the target's own DLL internals are excluded).

This is the *monitor* lens (the exact arguments at a sink, as evidence), distinct from
behavior_trace's inventory. Overflow verdicts on copies need the caller's stack-buffer size,
which we don't recover for PE yet -- copies are captured as evidence only (no overflow claim).
"""
from __future__ import annotations

from . import winapi

_EXEC = {"system", "_wsystem", "WinExec", "CreateProcessA", "CreateProcessW",
         "CreateProcessAsUserW", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExW"}
_FMT = {"wsprintfA", "wsprintfW", "swprintf", "sprintf", "vsprintf", "_snprintf", "_snwprintf"}
_DL = {"URLDownloadToFileA", "URLDownloadToFileW"}
# lstrcpy/strcpy/strcat etc.: the target's own string copies -- captured as evidence (with the
# source length). Overflow verdicts need the caller's buffer size (not recovered for PE yet).
_COPY = {"lstrcpyA", "lstrcpyW", "lstrcatA", "lstrcatW", "StrCpyA", "StrCpyW", "StrCatW",
         "strcpy", "strcat", "wcscpy", "wcscat"}
# LoadLibrary is deliberately omitted: under Wine the load list is dominated by Wine's own display
# drivers (winemac/winex11/winewayland.drv) and every PE loads many system DLLs -- low signal.
_CAT = {**{a: "exec" for a in _EXEC}, **{a: "format" for a in _FMT},
        **{a: "download" for a in _DL}, **{a: "copy" for a in _COPY}}


def supported() -> bool:
    return winapi.supported()


def parse(text, maps):
    """Dangerous-sink calls the target makes directly (on one of its mapping threads, ret in that
    mapping's range), with the concrete argument captured -- the first decoded string (command /
    URL / format / src)."""
    hits = []
    for line in text.splitlines():
        m = winapi._CALL.match(line)
        if not m:
            continue
        ltid, fn, args, ret = m.group(1), m.group(2), m.group(3), int(m.group(4), 16)
        cat = _CAT.get(fn)
        if not cat or not winapi._in_target(maps, ltid, ret):
            continue
        if cat == "exec" and winapi._is_wine_helper(winapi._first_str(args)):
            continue                                     # Wine's own service startup, not target
        val = winapi._first_str(args)
        rec = {"api": fn, "kind": cat, "value": val}
        if cat == "copy" and val is not None:
            rec["length"] = len(val)
        hits.append(rec)
        if len(hits) >= 2000:
            break
    return hits


def monitor(exe, *, argv=(), stdin: bytes = b"", timeout: float = 40.0, wineprefix=None) -> dict:
    r = winapi._relay(exe, argv=argv, stdin=stdin, timeout=timeout, wineprefix=wineprefix)
    if not r.get("ok"):
        return r
    # Same bargain as winapi.trace: a run we cut short yields a partial call list, and an
    # empty partial list is not the same claim as "this PE calls no dangerous sink".
    return {"ok": True, "hits": parse(r["text"], r["maps"]),
            "truncated": bool(r.get("truncated")), "timed_out": bool(r.get("timed_out"))}
