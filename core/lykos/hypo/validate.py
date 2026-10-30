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
RESOURCE_TIMEOUT = 6.0        # a correctly-bounded program finishes well under this
AUTH_MARKER_ENV = b"LYKOS_AUTH_OK"    # the privileged-path marker the auth-bypass oracle looks for
SAN_ENV = {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1",
           "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1:abort_on_error=1"}
MSAN_ENV = {"MSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:print_stats=0:exitcode=99"}
LSAN_ENV = {"ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1:symbolize=1:allocator_may_return_null=1",
            "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1:abort_on_error=1"}
FATAL = {"SIGSEGV", "SIGBUS", "SIGILL", "SIGFPE", "SIGABRT", "SIGTRAP"}
_ID_MARK = re.compile(rb"uid=\d+\(")
_SHELLS = {"sh", "bash", "dash", "zsh"}
_EXECVE = re.compile(r'execve\("([^"]*)"(?:,.*)?\)\s*=\s*0')
_MARKER_EXE = "id"           # the program the solver pins an injectable exec/path to
# an open-family syscall's path argument (the first quoted string; for openat the dirfd is not
# quoted, so the first quoted token is still the path).
_OPENPATH = re.compile(r'\bopen(?:at|64|at64)?\([^"]*"((?:[^"\\]|\\.)*)"')
_TRAVERSAL_TAIL = "etc/passwd"   # driver pins the traversal to `../`*N + this tail

_MSAN_ERR = re.compile(r"(?:WARNING|ERROR): MemorySanitizer: (use-of-uninitialized-value)", re.M)
_LSAN_ERR = re.compile(r"LeakSanitizer: detected memory leaks", re.M)
_LEAK_BLOCK = re.compile(r"(?:Direct|Indirect) leak of .*? allocated from:\n((?:\s*#\d+ .*\n)+)", re.S)
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
    msan_exe: Optional[Path] = None                       # clang MemorySanitizer build (uninit)
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
    timed_out: bool = False


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


def parse_msan(stderr: str, source_root: Optional[Path] = None):
    """(func, file, line) of the first MemorySanitizer use-of-uninitialized-value report's first
    in-program frame, or None. MSan reports the frame where the uninitialised value is USED."""
    m = _MSAN_ERR.search(stderr)
    if not m:
        return None
    return _program_frame(stderr, m.end(), source_root)


def parse_lsan(stderr: str, source_root: Optional[Path] = None):
    """(func, file, line) for each leaked allocation's first in-program frame (the allocation
    site LeakSanitizer reports), or [] when no leak was detected."""
    if not _LSAN_ERR.search(stderr):
        return []
    out = []
    for m in _LEAK_BLOCK.finditer(stderr):
        fr = _program_frame(m.group(1), 0, source_root)
        if fr:
            out.append(fr)
    return out


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
                      r.fault_pc, r.note or "", bool(getattr(r, "timed_out", False)))
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


def _strace_log(target: Target, data: bytes, trace: str) -> Optional[str]:
    """Run the target once under `strace -e trace=<trace>` inside bwrap and return the trace text,
    or None if strace is absent or the trace could not be produced. The syscall-effect oracle."""
    strace = shutil.which("strace")
    if not strace:
        return None
    from ..analyze.dynamic import sandbox
    tmp = tempfile.mkdtemp(prefix="lykos-strace-")
    try:
        log = os.path.join(tmp, "trace")
        argv, stdin_bytes = list(target.argv), b""
        inp = os.path.join(tmp, "input")
        with open(inp, "wb") as fh:
            fh.write(data if target.mode != "arg" else data.split(b"\0", 1)[0])
        if target.mode == "stdin":
            stdin_bytes = data
        elif target.mode == "arg":
            a = data.split(b"\0", 1)[0].decode("latin-1")
            argv = [a if x == "@@" else x for x in argv] if "@@" in argv else argv + [a]
        else:
            argv = [inp if x == "@@" else x for x in argv] if "@@" in argv else argv + [inp]
        inner = [strace, "-f", "-qq", "-e", f"trace={trace}", "-o", log, "--", str(target.exe), *argv]
        prefix = sandbox.isolate_prefix(str(Path(target.exe).parent), net=False,
                                        ro_binds=[tmp], rw_binds=[tmp])
        try:
            sandbox.run_reaped(prefix + inner, input=stdin_bytes, timeout=10.0,
                               capture_output=True)
        except Exception:        # noqa: BLE001 - a trace failure is "no evidence", not a crash
            return None
        try:
            with open(log, errors="replace") as fh:
                return fh.read()
        except OSError:
            return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


_TOCTOU_MARK = b"LYKOS_TOCTOU_WIN"
TOCTOU_TRIES = 200


def _toctou_run(target: Target, link: str, cwd: str) -> bytes:
    """Run the program with its path input pointing at `link`; return stdout+stderr. Runs
    directly (not under bwrap): the exploit is a host-side symlink race on our own temp dir."""
    import subprocess
    if target.mode == "stdin":
        argv = [str(target.exe)] + [a for a in target.argv if a != "@@"]
        stdin = (link + "\n").encode()
    else:   # arg
        argv = [str(target.exe)] + [link if a == "@@" else a for a in target.argv]
        stdin = b""
    try:
        p = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           cwd=cwd, timeout=5)
        return (p.stdout or b"") + (p.stderr or b"")
    except (subprocess.TimeoutExpired, OSError):
        return b""


def _relink(link: str, dest: str):
    if os.path.lexists(link):
        os.unlink(link)
    os.symlink(dest, link)


def _toctou_win(target: Target, tries: int = TOCTOU_TRIES):
    """Win a symlink-swap race between the program's filename check and its open. Returns
    (won, reason). SOUND: the target file is built to FAIL the program's check (its marker never
    surfaces in a steady-target run), so the marker appearing during racing proves the check
    passed on the benign file while the open resolved to the target -- a real TOCTOU."""
    tmp = tempfile.mkdtemp(prefix="lykos-toctou-")
    try:
        benign, tgt, link = (os.path.join(tmp, n) for n in ("benign", "target", "link"))
        with open(benign, "wb") as f:
            f.write(b"BENIGN\n")
        with open(tgt, "wb") as f:                 # large + marked: the size check rejects it
            f.write((_TOCTOU_MARK + b"\n") * 600)
        _relink(link, benign)
        if _TOCTOU_MARK in _toctou_run(target, link, tmp):
            return False, "benign run already shows the marker (misconfigured)"
        _relink(link, tgt)
        if _TOCTOU_MARK in _toctou_run(target, link, tmp):
            return False, "no effective check: the program serves the target steadily (not a TOCTOU)"
        import threading
        for _ in range(tries):
            _relink(link, benign)
            stop = threading.Event()

            def swapper():
                while not stop.is_set():
                    try:
                        _relink(link, tgt)
                        _relink(link, benign)
                    except OSError:
                        pass
            th = threading.Thread(target=swapper, daemon=True)
            th.start()
            out = _toctou_run(target, link, tmp)
            stop.set()
            th.join(timeout=2)
            if _TOCTOU_MARK in out:
                return True, f"served the swapped-in target after the check passed on the benign file"
        return False, f"race not won in {tries} attempts"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _exec_markers(target: Target, data: bytes) -> set:
    """Basenames of the programs the target successfully execve'd on this input."""
    log = _strace_log(target, data, "execve")
    if not log:
        return set()
    return {os.path.basename(m.group(1)) for m in _EXECVE.finditer(log)}


def _traversal_opens(target: Target, data: bytes) -> list:
    """Open-family syscall paths that escaped a base directory on this input: a `../` sequence
    AND the pinned sentinel tail. Such a path cannot be formed without the attacker's bytes."""
    log = _strace_log(target, data, "open,openat,creat")
    if not log:
        return []
    hits = []
    for m in _OPENPATH.finditer(log):
        p = m.group(1)
        if "../" in p and _TRAVERSAL_TAIL in p:
            hits.append(p)
    return hits


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
        # output can be swallowed (a popen pipe the program reads) or absent (`id <bad-user>`
        # errors): the syscall oracle proves the exec itself. The solver pins an injectable sink
        # to `id`, so an execve of `id` that the program would never make on its own is the proof.
        execs = _exec_markers(target, data)
        if _MARKER_EXE in execs:
            return Verdict(True, "exec-syscall",
                           f"strace observed execve of the injected program ({_MARKER_EXE})",
                           hyp.line), None
        return Verdict(False, "exec-marker",
                       f"the injected command did not run (execs seen: {sorted(execs) or 'none'})"), None

    if hyp.kind == "path-traversal":
        # no sanitizer catches a traversal: the proof is the syscall itself -- the process issued
        # an open() for a path carrying `../` out of its base to the pinned sentinel, which it
        # could not have built without the attacker's bytes.
        hits = _traversal_opens(target, data)
        if hits:
            return Verdict(True, "openat", f"the process opened a path outside its base: {hits[0]}",
                           hyp.line), None
        if shutil.which("strace") is None:
            return Verdict(False, "openat", "strace unavailable: cannot observe the open syscall"), None
        return Verdict(False, "openat", "no out-of-base open() observed on replay"), None

    if hyp.kind == "uninit-read":
        # no condition is "satisfiable at the site": the proof is MSan reporting the use of an
        # uninitialised value at this source line, on every replay. Needs the clang MSan build.
        if target.msan_exe is None:
            return Verdict(False, "msan", "no MemorySanitizer build available (clang required)"), None
        agree, last, incidental = 0, None, None
        for _ in range(REPLAYS):
            r = replay(target, target.msan_exe, data, env=MSAN_ENV)
            rep = parse_msan(r.stderr.decode("utf-8", "replace"), target.source_root)
            if not rep:
                last = f"no MemorySanitizer report ({r.signal or 'clean exit'})"
                break
            func, path, line = rep
            ok = hyp.line is not None and line == hyp.line and _same_file(path, hyp.location)
            last = f"use-of-uninitialized-value in {func} at {os.path.basename(path or '?')}:{line}; site line {hyp.line}"
            if not ok:
                incidental = ("use-of-uninitialized-value", path, line, func)
                break
            agree += 1
        if agree == REPLAYS:
            return Verdict(True, "msan", last, hyp.line, agree), None
        return Verdict(False, "msan", last or "", None, agree), incidental

    if hyp.kind == "auth-bypass":
        # secret-swap oracle: re-run with a freshly randomised secret the solver never saw. A
        # legitimate credential could not grant under it, so the authenticated marker appearing
        # proves the grant does not depend on knowing the secret -- a real bypass (CWE-287/863).
        import secrets
        s2 = secrets.token_hex(24)
        marker = (AUTH_MARKER_ENV or b"LYKOS_AUTH_OK")
        granted = control = 0
        for _ in range(REPLAYS):
            r = replay(target, target.exe, data, env={"LYKOS_SECRET": s2})
            if marker in r.stdout or marker in r.stderr:
                granted += 1
        # a wrong credential must NOT grant, or the marker is meaningless on this target
        for _ in range(REPLAYS):
            rc = replay(target, target.exe, b"lykos-wrong-" + s2.encode()[:8] + b"\n",
                        env={"LYKOS_SECRET": s2})
            if marker in rc.stdout or marker in rc.stderr:
                control += 1
        if granted == REPLAYS and control == 0:
            return Verdict(True, "auth-secret-swap", "granted access under a freshly randomised "
                           "secret the input cannot match (a legitimate credential could not)",
                           hyp.line), None
        if control == REPLAYS:
            return Verdict(False, "auth-secret-swap",
                           "the marker also appears for a wrong credential: not a usable oracle"), None
        return Verdict(False, "auth-secret-swap", f"did not grant under a randomised secret "
                       f"({granted}/{REPLAYS}): legitimate-credential path"), None

    if hyp.kind == "type-confusion":
        # UBSan's vptr check (in the address,undefined build) reports a bad downcast exactly where
        # it happens. The driver's site is the vtable call; the FINDING is attributed to UBSan's
        # line (precise), on 3/3 replays.
        if target.asan_exe is None:
            return Verdict(False, "ubsan-vptr", "no sanitizer build for the vptr check"), None
        agree, last, line, func = 0, None, None, None
        for _ in range(REPLAYS):
            r = replay(target, target.asan_exe, data, env=SAN_ENV)
            rep = parse_sanitizer(r.stderr.decode("utf-8", "replace"), target.source_root)
            if not rep or "downcast" not in (rep[0] or ""):
                last = f"no bad-downcast report ({r.signal or 'clean exit'})"
                break
            _kind, func, path, line, _al = rep
            last = f"{_kind} in {func} at {os.path.basename(path or '?')}:{line}"
            agree += 1
        if agree == REPLAYS:
            return Verdict(True, "ubsan-vptr", last, line, agree), None
        return Verdict(False, "ubsan-vptr", last or "", None, agree), None

    if hyp.kind == "toctou":
        if target.mode not in ("arg", "stdin"):
            return Verdict(False, "toctou-race",
                           "TOCTOU replay needs a path supplied as an argument or on stdin"), None
        won, why = _toctou_win(target)
        if won:
            return Verdict(True, "toctou-race",
                           f"won a check-to-use race: {why}", hyp.line), None
        return Verdict(False, "toctou-race", why), None

    if hyp.kind == "resource-exhaustion":
        # the proof is non-termination: the plain build, given this input, does not finish within
        # a generous limit on every replay. A correctly-bounded loop returns well under it, so a
        # 3/3 timeout is a real denial-of-service symptom at the input-controlled loop.
        hangs = 0
        for _ in range(REPLAYS):
            if replay(target, target.exe, data, timeout=RESOURCE_TIMEOUT).timed_out:
                hangs += 1
        if hangs == REPLAYS:
            return Verdict(True, "timeout", f"did not terminate within {RESOURCE_TIMEOUT:.0f}s on "
                           f"{REPLAYS}/{REPLAYS} replays (input-controlled loop)", hyp.line, hangs), None
        return Verdict(False, "timeout", f"terminated within the limit ({hangs}/{REPLAYS} hung)"), None

    if hyp.kind == "mem-leak":
        # LeakSanitizer rides on the ASan build (detect_leaks=1). Confirm only when a leaked block
        # was allocated at this site line, on every replay; a leak elsewhere is incidental.
        if target.asan_exe is None:
            return Verdict(False, "lsan", "no sanitizer build for leak detection"), None
        agree, last, incidental = 0, None, None
        for _ in range(REPLAYS):
            r = replay(target, target.asan_exe, data, env=LSAN_ENV)
            leaks = parse_lsan(r.stderr.decode("utf-8", "replace"), target.source_root)
            if not leaks:
                last = f"no leak reported ({r.signal or 'clean exit'})"
                break
            lines = sorted({ln for _f, _p, ln in leaks})
            last = f"block(s) leaked, allocated at line(s) {lines}; site line {hyp.line}"
            if hyp.line not in lines:
                f0 = leaks[0]
                incidental = ("memory-leak", f0[1], f0[2], f0[0])
                break
            agree += 1
        if agree == REPLAYS:
            return Verdict(True, "lsan", last, hyp.line, agree), None
        return Verdict(False, "lsan", last or "", None, agree), incidental

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
