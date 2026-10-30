"""Validate a solved hypothesis by REPLAYING its input -- the only path to `confirmed`.

The solver's models can be unsound, so its claim is never the finding. Each input is run for
real, inside lykos' process sandbox, and an oracle must fire AT THE HYPOTHESIS SITE:

  asan          a sanitizer build is available (source targets): the first in-program frame of
                the ASan/UBSan report is the site's source line. An allocation-size wrap
                (int-overflow-alloc) overflows downstream, so its match is the report's
                "allocated by" frame instead.
  exec-marker   command injection: the injected `id>&2` ran -- its `uid=N(` output appears in
                what the program printed (stderr is not swallowed by a popen() pipe).
  native-crash  binary only, no sanitizer build: the input crashes the analysed binary with a
                fatal signal on every one of REPLAYS runs, and the faulting PC lies inside the
                site's function. A crash elsewhere (inside libc, at a smashed return address) is
                reported, not confirmed: attributing it needs a backtrace (see improvements).

A report that lands somewhere else is still real evidence: it comes back as `incidental` so the
loop can file it against the line it actually hit instead of dropping it.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .model import Hypothesis, Verdict

REPLAYS = 3
SAN_ENV = {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1",
           "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1:abort_on_error=1"}
FATAL = {"SIGSEGV", "SIGBUS", "SIGILL", "SIGFPE", "SIGABRT", "SIGTRAP"}
_ID_MARK = re.compile(rb"uid=\d+\(")

_ASAN_ERR = re.compile(r"ERROR: AddressSanitizer: (.+?)(?: on (?:unknown )?address| on 0x|:? \(|$)", re.M)
_UBSAN_ERR = re.compile(r"(\S+?):(\d+):\d+: runtime error: (.*)$", re.M)
_FRAME = re.compile(r"^\s*#\d+ 0x[0-9a-f]+ in (\S+) (\S+?):(\d+)", re.M)
_ALLOC = re.compile(r"allocated by thread.*?\n((?:\s*#\d+ .*\n)+)", re.S)
# frames that belong to the sanitizer runtime or libc, never "the program". Specific path pieces
# only: a loose "asan" match also swallowed a PROGRAM built under a directory named asan/.
_RUNTIME = re.compile(r"libsanitizer/|sanitizer_common|compiler-rt/|/asan/asan_|/ubsan/ubsan_|"
                      r"(^|/)csu/|libc-start\.c|libc_start_call_main|(^|/)sysdeps/|"
                      r"(^|/)(stdio-common|libio|string|stdlib|malloc|nptl|posix)/[^/]+\.c$|"
                      r"^/usr/(lib|include)/")


@dataclass
class Target:
    """How to run the program under test. `exe` is the analysed (plain) build; `asan_exe`, when
    present, is the sanitizer build of the SAME source, used as the oracle."""
    exe: Path
    argv: list = field(default_factory=lambda: ["@@"])   # "@@" = where the input goes
    mode: str = "file"                                    # file | stdin | arg
    asan_exe: Optional[Path] = None
    arch: Optional[str] = None
    endianness: Optional[str] = None
    bits: Optional[int] = None
    source_root: Optional[Path] = None                    # the tree the analysed build came from
    display_root: Optional[Path] = None                   # the operator's own source tree


@dataclass
class Replay:
    crashed: bool
    signal: Optional[str]
    stdout: bytes
    stderr: bytes
    fault_pc: Optional[int] = None
    note: str = ""


def _program_frame(text: str, start: int, source_root: Optional[Path]):
    """First frame after `start` that is the program's own code: (func, file, line)."""
    for m in _FRAME.finditer(text, start):
        fn, path, line = m.group(1), m.group(2), int(m.group(3))
        if _RUNTIME.search(path):
            continue
        return fn, path, line
    return None


def parse_sanitizer(stderr: str, source_root: Optional[Path] = None):
    """(kind, func, file, line, alloc_line) of the first sanitizer report, or None."""
    a = _ASAN_ERR.search(stderr)
    u = _UBSAN_ERR.search(stderr)
    if u and not _RUNTIME.search(u.group(1)) and (not a or u.start() < a.start()):
        fr = _program_frame(stderr, u.end(), source_root)
        return ("ubsan:" + u.group(3).split(" ")[0], fr[0] if fr else None, u.group(1),
                int(u.group(2)), None)
    if a:
        fr = _program_frame(stderr, a.end(), source_root)
        al = None
        m = _ALLOC.search(stderr, a.end())
        if m:
            af = _program_frame(m.group(1), 0, source_root)
            al = af[2] if af else None
        if fr:
            return a.group(1).strip(), fr[0], fr[1], fr[2], al
        return a.group(1).strip(), None, None, None, al
    return None


def _same_file(report_path: Optional[str], location: Optional[str]) -> bool:
    if not report_path or not location:
        return True                        # nothing to disagree on; the line decides
    a = os.path.basename(report_path)
    b = os.path.basename(location.rsplit(":", 1)[0])
    return a == b


def replay(target: Target, exe: Path, data: bytes, *, timeout: float = 10.0,
           env: Optional[dict] = None) -> Replay:
    """One sandboxed run of `exe` with `data` delivered per the target's invocation."""
    from ..analyze.dynamic import sandbox
    argv, stdin, tmp, binds = list(target.argv), b"", None, ()
    try:
        if target.mode == "stdin":
            stdin = data
        elif target.mode == "arg":
            arg = data.split(b"\0", 1)[0].decode("latin-1")
            argv = [arg if a == "@@" else a for a in argv] if "@@" in argv else argv + [arg]
        else:
            tmp = tempfile.mkdtemp(prefix="lykos-replay-")
            path = os.path.join(tmp, "input")
            with open(path, "wb") as fh:
                fh.write(data)
            argv = [path if a == "@@" else a for a in argv] if "@@" in argv else argv + [path]
            binds = (tmp,)
        r = sandbox.run(str(exe), argv=argv, stdin=stdin, timeout=timeout, arch=target.arch,
                        endianness=target.endianness, bits=target.bits, ro_binds=binds,
                        env_overrides=env, capture=1 << 20)
        return Replay(bool(r.crashed), r.signal_name, r.stdout or b"", r.stderr or b"",
                      r.fault_pc, r.note or "")
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def _native_runs(target: Target, data: bytes, n: int) -> list:
    """`n` traced runs of the plain build (fault PCs as file addresses), or plain runs."""
    from ..analyze.dynamic import sandbox
    base = list(target.argv)
    payload = data.split(b"\0", 1)[0] if target.mode == "arg" else data
    res = sandbox.run_batch(str(target.exe), [payload] * n, mode=target.mode, base_argv=base,
                            timeout=10.0, arch=target.arch, endianness=target.endianness,
                            bits=target.bits)
    if res:
        return [Replay(bool(r.crashed), r.signal_name, r.stdout or b"", r.stderr or b"",
                       r.fault_pc, r.note or "") for r in res]
    return [replay(target, target.exe, data) for _ in range(n)]


def validate(target: Target, hyp: Hypothesis, data: bytes):
    """-> (Verdict, incidental) where incidental is (kind, file, line, func) for a sanitizer
    report that fired somewhere other than this site, else None."""
    if hyp.kind == "cmd-injection":
        r = replay(target, target.exe, data)
        hit = _ID_MARK.search(r.stdout) or _ID_MARK.search(r.stderr)
        if hit:
            return Verdict(True, "exec-marker", "the injected `id` executed: "
                           + (r.stderr + r.stdout)[hit.start():hit.start() + 60]
                           .decode("latin-1", "replace").split("\n")[0], hyp.line), None
        return Verdict(False, "exec-marker", "the injected command did not run"), None

    if target.asan_exe is not None:
        agree, last, incidental = 0, None, None
        for _ in range(REPLAYS):
            r = replay(target, target.asan_exe, data, env=SAN_ENV)
            rep = parse_sanitizer(r.stderr.decode("utf-8", "replace"), target.source_root)
            if not rep:
                last = f"no sanitizer report ({r.signal or 'clean exit'})"
                break
            kind, func, path, line, alloc_line = rep
            if hyp.kind == "int-overflow-alloc":
                ok = (hyp.line is not None and alloc_line == hyp.line
                      and "heap-buffer-overflow" in kind)
                last = f"{kind} at line {line}, allocated at line {alloc_line}; site line {hyp.line}"
            else:
                ok = hyp.line is not None and line == hyp.line and _same_file(path, hyp.location)
                last = f"{kind} in {func} at {os.path.basename(path or '?')}:{line}; site line {hyp.line}"
            if not ok:
                if line is not None:
                    incidental = (kind, path, line, func)
                break
            agree += 1
        if agree == REPLAYS:
            return Verdict(True, "asan", last, hyp.line, agree), None
        return Verdict(False, "asan", last or "", None, agree), incidental

    runs = _native_runs(target, data, REPLAYS)
    sigs = [r.signal for r in runs]
    if not all(r.crashed and r.signal in FATAL for r in runs):
        return Verdict(False, "native-crash",
                       f"did not crash on every replay ({', '.join(str(s) for s in sigs)})"), None
    pcs = {r.fault_pc for r in runs}
    lo = hyp.func_addr
    hi = lo + hyp.func_size if (lo is not None and hyp.func_size) else None
    inside = [p for p in pcs if p is not None and lo is not None and hi is not None and lo <= p < hi]
    if inside and len(pcs) == 1:
        return Verdict(True, "native-crash",
                       f"{sigs[0]} at {inside[0]:#x} inside {hyp.func or 'the site function'} on "
                       f"{REPLAYS}/{REPLAYS} replays", hyp.line, REPLAYS), None
    where = ", ".join(f"{p:#x}" for p in pcs if p is not None) or "an unknown address"
    return Verdict(False, "native-crash", crashes=True, detail=
                   f"{sigs[0]} on every replay, but at {where}, outside "
                   f"{hyp.func or 'the site function'}: not attributable to this site "
                   f"without a backtrace"), None
