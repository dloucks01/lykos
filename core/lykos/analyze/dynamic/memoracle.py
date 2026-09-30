"""Binary-only memory-safety oracles: catch heap corruption in targets with NO source ASan.

lykos gets precise memory-safety detection on a SOURCE build (ASan/UBSan/MSan name the exact
defect with a file:line). A stripped, third-party or cross-arch binary has none of that -- a heap
out-of-bounds or use-after-free there merely *sometimes* faults, and often runs on silently. This
module adds the two classic non-instrumentation oracles that turn that silent corruption into a
signal, on any binary, offline and with no AI:

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
    "leak": ("CWE-401", "low"),
}

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
        elif low.startswith("use of uninitialised") or "uninitialised value" in low:
            kind = "uninitialised"
        elif "conditional jump or move depends on uninitialised" in low:
            kind = "uninitialised"
        if kind:
            cwe, sev = _VALGRIND_CWE[kind]
            findings.append({"kind": kind, "cwe": cwe, "severity": sev,
                             "size": _size(ln), "detail": ln})

    if not findings:
        # A leak-only run: "definitely lost: N bytes in M blocks".
        m = re.search(r"definitely lost:\s*([\d,]+) bytes", text)
        if m and int(m.group(1).replace(",", "")) > 0:
            cwe, sev = _VALGRIND_CWE["leak"]
            return {"kind": "leak", "cwe": cwe, "severity": sev, "size": None,
                    "detail": f"definitely lost {m.group(1)} bytes"}
        return None

    order = ["double-free", "use-after-free", "heap-oob-write", "invalid-free",
             "heap-oob-read", "uninitialised", "leak"]
    findings.sort(key=lambda f: order.index(f["kind"]))
    return findings[0]


def valgrind_triage(exe, data: bytes, *, mode: str = "stdin", base_argv=(),
                    timeout: float = 60.0, input_path: Optional[str] = None) -> Optional[dict]:
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
    argv = [exe, *[str(a) for a in base_argv]]
    stdin_data = b""
    try:
        if mode == "stdin":
            stdin_data = data
        elif mode == "arg":
            argv = [exe, data.split(b"\x00", 1)[0].decode("latin-1")] + [str(a) for a in base_argv]
        elif mode == "file":
            if input_path is None:
                fd, tmp = tempfile.mkstemp(prefix="lykos-vg-")
                os.write(fd, data)
                os.close(fd)
                input_path = tmp
            if "@@" in argv:
                argv = [input_path if a == "@@" else a for a in argv]
            else:
                argv = argv + [input_path]
        cmd = [vg, "--error-exitcode=0", "--exit-on-first-error=no",
               "--leak-check=summary", "--errors-for-leak-kinds=definite",
               "-q", *argv]
        try:
            r = subprocess.run(cmd, input=stdin_data, capture_output=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            return None
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
