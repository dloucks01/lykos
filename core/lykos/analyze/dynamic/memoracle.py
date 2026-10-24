"""Binary-only memory-safety oracles: catch heap corruption in targets with NO source ASan.

lykos gets precise memory-safety detection on a SOURCE build (ASan/UBSan/MSan name the exact
defect with a file:line). A stripped, third-party or cross-arch binary has none of that -- a heap
out-of-bounds or use-after-free there merely *sometimes* faults, and often runs on silently. This
module adds the two classic non-instrumentation oracles that turn that silent corruption into a
signal, on any binary, offline and with :

  * **libdislocator** (AFL++'s guard-page allocator, `LD_PRELOAD`ed): every allocation is placed at
    the END of its own page with an unmapped page just past it, so a one-byte heap overflow faults
    *immediately* (SIGSEGV) instead of corrupting the next chunk and maybe never crashing. Freed
    pages are unmapped, so a use-after-free faults too. Arch-agnostic for a host-architecture ELF;
    zero shadow memory. This is a *fuzzing* oracle -- it makes the fork-server catch heap bugs it
    was blind to.

  * **Valgrind memcheck** (re-run one interesting input): a DBT shadow-memory checker that names the
    exact class -- heap OOB read/write, use-after-free, double-free, invalid free, uninitialised
    read, leak -- with the sizes involved. Too slow for the hot loop (~10-30x), so it is a *triage*
    oracle: run it on a crash (or a coverage-interesting survivor) to CLASSIFY the memory error into
    a CWE, giving a stripped binary the same defect-naming a source ASan build gets for free.

`libqasan` (QEMU-mode ASan, `AFL_USE_QASAN=1`) is the third lane -- deeper heap shadowing than
dislocator -- but it must be built from AFL++ `qemu_mode/libqasan`; we detect it and use it when
present. All three are complementary: dislocator for speed on any arch, qasan for depth on ELF
under qemu, valgrind for the authoritative post-hoc classification.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------- tool discovery

_DISLOCATOR_NAMES = ("libdislocator.so",)
_DISLOCATOR_DIRS = ("/usr/lib/afl", "/usr/local/lib/afl", "/usr/lib/x86_64-linux-gnu")


def _afl_search_dirs():
    afl = os.environ.get("AFL_PATH")
    return _DISLOCATOR_DIRS + ((afl,) if afl else ())


def dislocator_lib() -> Optional[Path]:
    """Path to libdislocator.so (AFL++), or None. Honours LYKOS_DISLOCATOR then AFL_PATH."""
    env = os.environ.get("LYKOS_DISLOCATOR")
    if env and Path(env).exists():
        return Path(env)
    dirs = list(_DISLOCATOR_DIRS)
    afl = os.environ.get("AFL_PATH")
    if afl:
        dirs.insert(0, afl)
    for d in dirs:
        for n in _DISLOCATOR_NAMES:
            p = Path(d) / n
            if p.exists():
                return p
    which = shutil.which("libdislocator.so")
    return Path(which) if which else None


def tokencap_lib() -> Optional[Path]:
    """Path to libtokencap.so (AFL++): captures the string/memcmp tokens a target compares its
    input against AT RUNTIME, complementing the static cmpdict extractor. None if absent."""
    env = os.environ.get("LYKOS_TOKENCAP")
    if env and Path(env).exists():
        return Path(env)
    for d in _afl_search_dirs():
        p = Path(d) / "libtokencap.so"
        if p.exists():
            return p
    return None


def libqasan_lib() -> Optional[Path]:
    """Path to libqasan.so (AFL++ QEMU-mode ASan), or None -- it ships only when AFL++'s qemu_mode
    was built, so on many hosts it is absent and the dislocator/valgrind lanes carry the load."""
    env = os.environ.get("LYKOS_QASAN")
    if env and Path(env).exists():
        return Path(env)
    for d in _afl_search_dirs():
        p = Path(d) / "libqasan.so"
        if p.exists():
            return p
    return None


def valgrind_bin() -> Optional[str]:
    return os.environ.get("LYKOS_VALGRIND") or shutil.which("valgrind")


# ---------------------------------------------------------------- dislocator preload

def dislocator_preload(base_env: Optional[dict], *, host_arch: str, target_arch: Optional[str]):
    """Return an env dict with libdislocator LD_PRELOADed, or None when it cannot apply.

    LD_PRELOAD injects into the DYNAMIC LINKER of a process of the SAME architecture as the lib, so
    it works for a host-architecture ELF run natively (or batched under ptrace). A cross-arch guest
    under qemu-user would need a guest-built libdislocator we do not have, so we decline there
    rather than preload an incompatible object (which the guest loader would reject and abort). The
    caller treats None as "no dislocator oracle for this target" and runs unguarded.

    `AFL_ALIGNED_ALLOC=1` keeps allocations 16-byte aligned (some targets require it); we leave the
    default (end-of-page) placement, which is what catches the off-by-one write.
    """
    lib = dislocator_lib()
    if lib is None:
        return None
    if target_arch and host_arch and target_arch != host_arch:
        return None                                   # guest arch: no compatible preload object
    env = dict(base_env if base_env is not None else os.environ)
    prior = env.get("LD_PRELOAD", "")
    env["LD_PRELOAD"] = (str(lib) + (":" + prior if prior else ""))
    return env


# ---------------------------------------------------------------- confinement

def _confined(argv: list, exe, *, ro=(), rw=(), setenv: Optional[dict] = None) -> list:
    """`argv` wrapped in the platform's bwrap prefix (read-only root, secrets masked, no network,
    fresh /tmp, pid namespace) -- or `argv` unchanged when bwrap is unusable.

    Both lanes below EXECUTE the untrusted target (one under libtokencap, one under memcheck) and
    did so with a bare `subprocess.run`: full user privileges, network, the analyst's home
    writable, and on timeout only the direct child killed. `setenv` is passed through bwrap's own
    --setenv so a preload survives even a setuid bwrap (whose loader would strip LD_PRELOAD)."""
    try:
        from . import sandbox
        exedir = str(Path(exe).resolve().parent)
        pre = sandbox.isolate_prefix(exedir, net=False, ro_binds=[str(d) for d in ro],
                                     rw_binds=[str(d) for d in rw], chdir=exedir)
    except Exception:                                   # noqa: BLE001 -- containment best-effort
        pre = []
    if not pre:
        return list(argv)
    if setenv and "--" in pre:
        cut = pre.index("--")
        extra = []
        for k, v in setenv.items():
            extra += ["--setenv", k, v]
        pre = pre[:cut] + extra + pre[cut:]
    return pre + list(argv)


# ---------------------------------------------------------------- runtime comparison tokens

# libtokencap hooks the string/memory comparison functions and appends every constant a target
# compares its input AGAINST to AFL_TOKEN_FILE, in AFL dictionary form: one `"token"` per line.
_TOKEN_LINE = re.compile(rb'^\s*(?:[\w.]+\s*=\s*)?"((?:[^"\\]|\\.)*)"\s*$')
#: A token longer than this is almost certainly a whole buffer rather than a magic value, and a
#: dictionary entry that large only slows the mutator down.
_TOKEN_MAX = 64


def _unescape(tok: bytes) -> bytes:
    """AFL dictionary escaping: \\xNN byte escapes plus \\\\ and \\"."""
    out, i = bytearray(), 0
    while i < len(tok):
        c = tok[i]
        if c != 0x5C or i + 1 >= len(tok):           # not a backslash
            out.append(c)
            i += 1
            continue
        nxt = tok[i + 1]
        if nxt == 0x78 and i + 3 < len(tok):         # \xNN
            try:
                out.append(int(tok[i + 2:i + 4], 16))
                i += 4
                continue
            except ValueError:
                pass
        out.append(nxt)
        i += 2
    return bytes(out)


def parse_token_file(data: bytes) -> list:
    """The distinct tokens in an AFL-format dictionary, longest-first, unescaped."""
    toks, seen = [], set()
    for raw in (data or b"").splitlines():
        m = _TOKEN_LINE.match(raw.strip())
        if not m:
            continue
        tok = _unescape(m.group(1))
        if 2 <= len(tok) <= _TOKEN_MAX and tok not in seen:
            seen.add(tok)
            toks.append(tok)
    # Longest first: a mutator that inserts the whole magic value gets past the gate in one step,
    # where a prefix only gets past the first byte of the comparison.
    toks.sort(key=len, reverse=True)
    return toks


def runtime_tokens(exe, data: bytes, *, mode: str = "stdin", base_argv=(), timeout: float = 20.0,
                   host_arch: str = "", target_arch: Optional[str] = None) -> list:
    """Tokens the target actually COMPARED its input against, observed at runtime. [] if n/a.

    The static extractor (`fuzz.cmpdict`) reads comparisons out of the recovered IR, so it sees
    only the ones whose operand is a constant IN THE CODE. A magic value that is COMPUTED -- a
    decoded header, a checksum, a token read from a config or the environment -- exists only at
    runtime, and that is exactly the kind of gate a blind campaign never gets past. libtokencap
    hooks the comparison functions and reports those, which is why it was built; it was never
    called, so this half of the input-to-state dictionary did not exist.

    Same preload constraints as `dislocator_preload`: host-architecture ELF only, and a target
    that is dynamically linked (a static binary resolves no symbols through the loader).
    """
    lib = tokencap_lib()
    if lib is None:
        return []
    if target_arch and host_arch and target_arch != host_arch:
        return []
    import tempfile
    d = tempfile.mkdtemp(prefix="lykos-tokcap-")
    out = Path(d) / "tokens.dict"
    env = dict(os.environ)
    prior = env.get("LD_PRELOAD", "")
    env["LD_PRELOAD"] = str(lib) + (":" + prior if prior else "")
    env["AFL_TOKEN_FILE"] = str(out)
    argv = [str(exe), *[str(a) for a in base_argv]]
    tmp = None
    try:
        stdin_data = b""
        if mode == "stdin":
            stdin_data = data
        elif mode == "arg":
            argv = [str(exe), data.split(b"\x00", 1)[0].decode("latin-1"),
                    *[str(a) for a in base_argv]]
        elif mode == "file":
            # inside the token dir, which the sandbox binds -- its own /tmp is a fresh tmpfs
            fd, tmp = tempfile.mkstemp(prefix="lykos-tokcap-in-", dir=d)
            os.write(fd, data)
            os.close(fd)
            argv = [(tmp if a == "@@" else a) for a in argv] if "@@" in argv else argv + [tmp]
        cmd = _confined(argv, exe, rw=[d], setenv={"LD_PRELOAD": env["LD_PRELOAD"],
                                                   "AFL_TOKEN_FILE": str(out)})
        try:
            subprocess.run(cmd, input=stdin_data, capture_output=True, timeout=timeout, env=env)
        except (OSError, subprocess.SubprocessError):
            return []
        try:
            return parse_token_file(out.read_bytes())
        except OSError:
            return []
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------- valgrind triage

# memcheck error class -> (CWE, severity). Aligned with rootcause._ASAN_CWE so a valgrind-classified
# crash and a sanitizer-classified crash land on comparable CWEs.
_VALGRIND_CWE = {
    "heap-oob-write": ("CWE-122", "critical"),
    "heap-oob-read": ("CWE-125", "high"),
    "use-after-free": ("CWE-416", "critical"),
    "double-free": ("CWE-415", "critical"),
    "invalid-free": ("CWE-590", "high"),
    "uninitialised": ("CWE-457", "medium"),
    # Uninitialised bytes handed to a WRITE syscall have LEFT THE PROCESS. memcheck reports that
    # distinctly ("Syscall param write(buf) points to uninitialised byte(s)"), and the difference
    # matters: a conditional jump on an uninitialised value is an internal error with no effect a
    # report can demonstrate, while this one IS the effect -- stack or heap residue disclosed to
    # whoever reads the output. Ranked above plain `uninitialised` for that reason.
    "uninit-disclosure": ("CWE-200", "high"),
    "leak": ("CWE-401", "low"),
}

# "Syscall param write(buf) points to uninitialised byte(s)" -- also sendto/send/pwrite/writev.
_VG_DISCLOSE = re.compile(
    r"^syscall param (write|pwrite\d*|writev|send|sendto|sendmsg)\b.*points to uninitialised")
# "Uninitialised value was created by a stack allocation" / "by a heap allocation"
_VG_ORIGIN = re.compile(r"uninitialised value was created by an? (\w+) allocation")

_VG_LINE = re.compile(rb"^==\d+==\s?(.*)$")


def parse_memcheck(stderr: bytes) -> Optional[dict]:
    """Classify a Valgrind memcheck run's stderr into the WORST memory error it reported.

    memcheck prints, per error, a header line (``Invalid write of size 4``) then an ``Address ...``
    context line that disambiguates the class: ``after a block`` / ``before a block`` = an
    out-of-bounds access; ``inside a block ... free'd`` = a use-after-free; an ``Invalid free()``
    whose address is a freed block = a double free. We scan every error and return the most severe.
    Returns ``{kind, cwe, severity, size, detail}`` or None when memcheck found nothing.
    """
    # Flatten the ==PID== prefix so the header and its following Address line are adjacent.
    lines = []
    for raw in stderr.splitlines():
        m = _VG_LINE.match(raw)
        if m:
            lines.append(m.group(1).decode("latin-1", "replace").strip())
    text = "\n".join(lines)

    findings = []

    def _size(hdr: str):
        m = re.search(r"of size (\d+)", hdr)
        return int(m.group(1)) if m else None

    for i, ln in enumerate(lines):
        low = ln.lower()
        ctx = " ".join(lines[i + 1:i + 4]).lower()   # the Address/context lines that follow
        # memcheck names a real heap region only for a genuine heap error: "... a block of
        # size N alloc'd/free'd". A wild or NULL pointer instead reads "not stack'd, malloc'd
        # or (recently) free'd" -- note that NEGATION also contains the substring "free'd", so
        # keying on "free'd" alone misreads a NULL deref as a use-after-free. Gate on the
        # affirmative block marker, and treat an invalid read/write with no heap block as NOT a
        # heap defect (a wild/NULL/stack pointer) -- left to the signal-based classifier.
        heap = "block of size" in ctx
        freed = heap and "free'd" in ctx
        kind = None
        if low.startswith("invalid write"):
            kind = "use-after-free" if freed else ("heap-oob-write" if heap else None)
        elif low.startswith("invalid read"):
            kind = "use-after-free" if freed else ("heap-oob-read" if heap else None)
        elif "invalid free" in low or "invalid delete" in low:
            # a free of an already-freed block is a double free; otherwise a free of a bad pointer.
            kind = "double-free" if freed else "invalid-free"
        elif _VG_DISCLOSE.match(low):
            kind = "uninit-disclosure"
        elif low.startswith("use of uninitialised") or "uninitialised value" in low:
            kind = "uninitialised"
        elif "conditional jump or move depends on uninitialised" in low:
            kind = "uninitialised"
        if kind:
            cwe, sev = _VALGRIND_CWE[kind]
            f = {"kind": kind, "cwe": cwe, "severity": sev, "size": _size(ln), "detail": ln}
            if kind.startswith("uninit"):
                # memcheck with --track-origins names WHERE the uninitialised value came from
                # ("created by a stack allocation"), which is the difference between "something
                # was uninitialised" and a root cause a reader can act on.
                # The origin sits AFTER the error's whole stack trace, which can be a dozen
                # frames deep, so a short window misses it. Prefer the nearest, then fall back
                # to the run as a whole -- with several uninit errors the origins are all of the
                # same shape, and this is evidence rather than the verdict.
                om = (_VG_ORIGIN.search(" ".join(lines[i + 1:i + 40]).lower())
                      or _VG_ORIGIN.search(text.lower()))
                if om:
                    f["origin"] = om.group(1)          # "stack" | "heap" | "client"
            findings.append(f)

    if not findings:
        # A leak-only run: "definitely lost: N bytes in M blocks".
        m = re.search(r"definitely lost:\s*([\d,]+) bytes", text)
        if m and int(m.group(1).replace(",", "")) > 0:
            cwe, sev = _VALGRIND_CWE["leak"]
            return {"kind": "leak", "cwe": cwe, "severity": sev, "size": None,
                    "detail": f"definitely lost {m.group(1)} bytes"}
        return None

    order = ["double-free", "use-after-free", "heap-oob-write", "invalid-free",
             "heap-oob-read", "uninit-disclosure", "uninitialised", "leak"]
    findings.sort(key=lambda f: order.index(f["kind"]))
    return findings[0]


def valgrind_triage(exe, data: bytes, *, mode: str = "stdin", base_argv=(),
                    timeout: float = 60.0, input_path: Optional[str] = None,
                    ctx=None) -> Optional[dict]:
    """Run one input under Valgrind memcheck and classify the memory error, or None.

    `mode` mirrors the sandbox: ``stdin`` feeds ``data`` on stdin; ``file`` writes it to a temp file
    and passes the path (``@@`` in base_argv, else appended); ``arg`` passes it as the first argv.
    Returns ``parse_memcheck``'s dict plus ``{via: "valgrind"}``, or None when valgrind is absent,
    the run did not finish, or memcheck reported nothing. This is a TRIAGE lane: callers invoke it
    on a crash / interesting input, not in the fuzz loop.
    """
    vg = valgrind_bin()
    if vg is None:
        return None
    exe = str(exe)
    import tempfile
    tmp = None
    tmpdir = None
    ro_dirs: list = []
    argv = [exe, *[str(a) for a in base_argv]]
    stdin_data = b""
    try:
        if mode == "stdin":
            stdin_data = data
        elif mode == "arg":
            argv = [exe, data.split(b"\x00", 1)[0].decode("latin-1")] + [str(a) for a in base_argv]
        elif mode == "file":
            if input_path is None:
                tmpdir = tempfile.mkdtemp(prefix="lykos-vg-")
                fd, tmp = tempfile.mkstemp(prefix="lykos-vg-", dir=tmpdir)
                os.write(fd, data)
                os.close(fd)
                input_path = tmp
            ro_dirs.append(str(Path(input_path).resolve().parent))
            if "@@" in argv:
                argv = [input_path if a == "@@" else a for a in argv]
            else:
                argv = argv + [input_path]
        # --track-origins names WHERE an undefined value came from ("created by a stack
        # allocation"), which is the difference between "something was uninitialised" and a root
        # cause a reader can act on. It costs extra shadow state, which this triage lane can
        # afford; the fuzz loop never comes here.
        cmd = _confined([vg, "--error-exitcode=0", "--exit-on-first-error=no",
                         "--leak-check=summary", "--errors-for-leak-kinds=definite",
                         "--track-origins=yes", "-q", *argv], exe, ro=ro_dirs)
        _t0 = time.time()
        try:
            r = subprocess.run(cmd, input=stdin_data, capture_output=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            return None
        # Surface the valgrind command + its memcheck summary in the live tool-command console
        # (valgrind feeds the target's stdin, so it runs its own subprocess, not ctx.run_subprocess).
        if ctx is not None:
            try:
                ctx.record_exec(cmd, start=_t0, rc=r.returncode, out=r.stdout, err=r.stderr)
            except Exception:
                # Advisory console echo only: a record_exec failure must not sink the memcheck
                # verdict parsed below -- the analysis value is in r.stderr, not the live echo.
                pass
        verdict = parse_memcheck(r.stderr or b"")
        if verdict is not None:
            verdict["via"] = "valgrind"
        return verdict
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
