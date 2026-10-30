"""One inventory of every external tool lykos can use, what it unlocks, and how to get it.

The platform's core is stdlib-based and runs with none of these; each stage locates its tool,
runs it, and declines with a reason when it is absent. That design only works if an operator
can find out WHICH tools this host has -- on an offline workstation there is no package
manager to ask, and "the stage declined" is a poor way to discover that Ghidra was never
installed.

This module is the single place that answers it. `lykos doctor` prints it, the offline
bundle script reads it to know what to collect, and doc 23 is generated from the same table --
so a tool cannot be added to one and forgotten in the others. Every probe delegates to the
locator the stage itself uses, rather than re-implementing the search: a doctor that looks in
different places from the code is worse than no doctor, because it reports a capability the
platform will then decline to run.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import observe

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Tool:
    key: str
    title: str
    unlocks: str                 # what having it buys
    without: str                 # what you lose without it
    install: str                 # how to get it (apt line, build script, or venv)
    probe: Callable[[], Optional[str]]   # -> version/path string, or None
    tier: str = "optional"       # "required" | "recommended" | "optional"
    apt: tuple = field(default_factory=tuple)   # debs the collector should pull
    # Tools that are NOT apt-installable everywhere (Ghidra is a package on Kali and a
    # tarball on Ubuntu; SymQEMU is built from source) are carried as a directory copy
    # instead. Returns the paths to bundle, or [] when the tool is not installed here.
    bundle: Optional[Callable[[], list]] = None


def _v(cmd, *args, timeout=5, env=None):
    """First line of a tool's own version output -- proof it RUNS, not just that it exists.

    A tool that is present but broken or ABI-incompatible typically exits non-zero and prints
    nothing usable; reporting its path as "ok" would tell an operator a capability is available
    that the platform will then decline. So: return the first output line only when the tool
    actually produced one; if it exits non-zero with no output, report it as absent (None)
    rather than falling back to the exe path.
    """
    exe = shutil.which(cmd) if isinstance(cmd, str) else str(cmd)
    if not exe:
        return None
    try:
        r = subprocess.run([exe, *args], capture_output=True, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError):
        return None
    out = (r.stdout or b"") + (r.stderr or b"")
    text = out.decode("utf-8", "replace")
    if _did_not_run(r.returncode, text):
        # The loader/kernel refused it (missing .so, bad interpreter, corrupt ELF) or it died on
        # a signal. Its first stderr line is the loader's complaint, NOT a version banner --
        # returning it would print a broken engine as "[ok]" in doctor.
        return None
    line = text.strip().splitlines()
    if line:
        return line[0][:90]
    # No output: only trust it if it exited cleanly (some tools print nothing on --version but
    # a non-zero exit with no output means it did not really run).
    return exe if r.returncode == 0 else None


# Text the dynamic loader / kernel / shell prints when a binary could not even START. A tool whose
# probe output contains one of these did not run, whatever it printed after.
_LOADER_FAILURES = (
    "error while loading shared libraries",
    "cannot open shared object file",
    "cannot execute binary file",
    "exec format error",
    "no such file or directory",           # e.g. a missing PT_INTERP: `bad ELF interpreter`
    "bad elf interpreter",
    "symbol lookup error",
    "version `glibc_",                     # "version `GLIBC_2.38' not found"
    "segmentation fault",
    "illegal instruction",
    "cannot be preloaded",                 # ld.so rejected an LD_PRELOAD object (rc stays 0!)
)


def _did_not_run(rc, text: str) -> bool:
    """True when a probe's exit status / output proves the tool never really ran.

    126/127 are the exec-failure statuses (ld.so exits 127 on a missing library); a negative rc is
    death by signal (a relink-corrupted binary SIGSEGVs before printing anything). A clean, non-zero
    exit with a banner (`afl-fuzz -h` exits 1) is NOT a failure -- only the loader's own wording is.
    """
    if rc is None or rc < 0 or rc in (126, 127):
        return True
    low = (text or "").lower()
    return any(m in low for m in _LOADER_FAILURES)


def _probe_python():
    import sys
    return f"{sys.executable} ({sys.version.split()[0]})"


def _probe_bwrap():
    from .analyze.dynamic import sandbox
    if not sandbox._bwrap_usable():
        return None
    return _v("bwrap", "--version") or "bwrap"


def _probe_ghidra():
    from .analyze.ghidra import locate_ghidra
    p = locate_ghidra()
    return str(p) if p else None


def _probe_rizin():
    """The native RE backend CLI (rizin, else radare2). This is the default decompiler now.

    Capture its version banner too (via `-v`), not just the path: doctor could not tell an
    operator their rizin was too old/incompatible -- an old bundled rizin or a fallback to an old
    host r2 recovers nothing and silently starves every function-keyed detector. `_v` returns the
    first `-v` line; fall back to the bare path if the banner cannot be read so a present-but-quiet
    tool still reports as installed."""
    from .analyze.native_re import locate_native
    p = locate_native()
    if p is None:
        return None
    ver = _v(p, "-v")                              # first line of `rizin -v` / `r2 -v`
    return f"{ver} ({p})" if ver else str(p)


def _probe_pypcode():
    """pypcode = Ghidra's SLEIGH lifter as a Python module (no JVM). Emits the P-Code IR the
    memory-safety detectors parse. Bundled under vendor/pysite and put on sys.path by
    vendorenv, so `import pypcode` resolves in-place on the offline host."""
    try:
        import pypcode
        return f"pypcode {getattr(pypcode, '__version__', '?')}"
    except Exception:
        observe.absorbed(_log, "answering None")
        return None


def _bundle_symqemu():
    """The vendored emulator and the SymCC runtime it loads beside it."""
    from pathlib import Path

    from .analyze.symbolic.symqemu import locate_symqemu
    p = locate_symqemu()
    if not p:
        return []
    p = Path(p)
    out = [p]
    for lib in p.parent.glob("libSymCCRt*.so"):
        out.append(lib)
    return out


def _probe_gdb():
    from .analyze.debug.gdb import locate_gdb
    p = locate_gdb()
    return _v(p, "--version") if p else None


def _probe_afl():
    # `afl-fuzz -h` exits 1 with its usage text when it runs; a loader failure (missing .so after a
    # bad relink) is caught by _v, so a present-but-broken afl-fuzz is no longer reported "ok".
    from .analyze.fuzz.aflpp import locate_afl
    p = locate_afl()
    if not p:
        return None
    return str(p) if _v(p, "-h") else None


def _probe_clang():
    # clang drives the libFuzzer source-coverage lane (-fsanitize=fuzzer) and afl-clang-fast. The
    # bundle historically omitted it, so that lane silently vanished on the air-gapped laptop.
    return _v("clang", "--version")


def _probe_afl_qemu():
    """Which GUESTS the available afl-qemu-trace binaries emulate.

    `file` cannot answer this: the emulator is always built for the host and the guest is
    fixed at build time, so the version banner is the only truth. Reporting the file's
    architecture here would tell an operator the opposite of what is true.
    """
    from pathlib import Path

    from .analyze.fuzz.aflpp import locate_afl, qemu_trace_arch
    seen = {}
    cands = []
    afl = locate_afl()
    if afl:
        cands += list(Path(afl).parent.glob("afl-qemu-trace*"))
    for d in ("/usr/local/bin", "/usr/bin"):
        cands += list(Path(d).glob("afl-qemu-trace*"))
    for c in cands:
        try:
            arch = qemu_trace_arch(c)
        except Exception:
            observe.absorbed(_log, "keeping the default")
            arch = None
        if arch and arch not in seen:
            seen[arch] = str(c)
    return ", ".join(f"{a} ({seen[a]})" for a in sorted(seen)) or None


def _qemu_suffixes() -> tuple:
    """The qemu-user emulator names the sandbox can actually select: its base arch table plus
    the endianness/word-size variants _qemu_for routes to. Derived from the sandbox so doctor
    cannot drift from the code that runs the emulator (a hand-written list here had already
    dropped mips64/mips64el/sparc that sandbox._qemu_for selects)."""
    from .analyze.dynamic import sandbox
    suf = set(sandbox._QEMU.values())
    suf |= {"mipsel", "mips64el", "ppc64le", "riscv32", "riscv64", "sparc64"}
    return tuple(sorted(suf))


def _probe_qemu():
    # Each emulator must print its own `qemu-<arch> version` banner: a relink once corrupted the
    # static-PIE qemu-user binaries, which still existed on PATH but SIGSEGV'd on start.
    suffixes = _qemu_suffixes()
    found = [a for a in suffixes if shutil.which(f"qemu-{a}")
             and "version" in (_v(f"qemu-{a}", "--version") or "").lower()]
    return f"{len(found)}/{len(suffixes)}: {' '.join(found)}" if found else None


def _probe_java():
    from .analyze.dynamic import sandbox
    j = sandbox._java()
    return _v(j, "-version") if j else None


def _probe_jdk():
    # Report "ok" only for the tools the gate this unlocks actually requires. realgate._JDK is
    # ("javac","jar","java"); reporting ok on a host missing `java` would promise a JVM gate
    # that then skips -- doctor must not claim a capability the platform declines to use.
    from .eval.realgate import _JDK
    if not all(shutil.which(t) for t in _JDK):
        return None
    return _v("javac", "-version")


def _probe_wine():
    from .analyze.dynamic import sandbox
    w = sandbox._wine()
    return _v(w, "--version") if w else None


def _probe_angr():
    from .analyze.symbolic.concolic import locate_angr_python
    p = locate_angr_python()
    return str(p) if p else None


def _probe_unicorn():
    from .analyze.firmware.rehost import locate_unicorn_python
    p = locate_unicorn_python()
    return str(p) if p else None


def _probe_symqemu():
    """SymQEMU must RUN, not merely exist: the bundle once shipped a symqemu whose vendored SymCC
    runtime / libglib could not be loaded, and an existence-only probe printed it "[ok]" while the
    concolic stage then failed on every seed. Two bounded checks, both with the SAME environment
    `symqemu.run_once` gives it (the runtime dir on LD_LIBRARY_PATH):

      1. `--version` -- the loader resolves libSymCCRtShared + libglib and qemu prints its banner;
      2. for a host-arch emulator, run the host's own `true` under it with a scratch
         SYMCC_OUTPUT_DIR -- proves the SymCC runtime initialises and the guest runs to exit 0.
    """
    import os
    import platform
    import tempfile
    from pathlib import Path

    from .analyze.symbolic.symqemu import locate_symqemu
    p = locate_symqemu()
    if not p:
        return None
    p = Path(p)
    env = dict(os.environ)
    libdir = str(p.resolve().parent)
    env["LD_LIBRARY_PATH"] = libdir + (":" + env["LD_LIBRARY_PATH"]
                                       if env.get("LD_LIBRARY_PATH") else "")
    banner = _v(p, "--version", timeout=10, env=env)
    if not banner or "version" not in banner.lower():
        return None
    host = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64",
            "arm64": "aarch64"}.get(platform.machine().lower())
    true = shutil.which("true")
    if host and true and p.name == f"symqemu-{host}":
        with tempfile.TemporaryDirectory(prefix="lykos-symqemu-probe-") as out:
            env["SYMCC_OUTPUT_DIR"] = out
            try:
                r = subprocess.run([str(p), true], capture_output=True, timeout=20, env=env,
                                   stdin=subprocess.DEVNULL)
            except (OSError, subprocess.SubprocessError):
                return None
            text = ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "replace")
            if r.returncode != 0 or _did_not_run(r.returncode, text):
                return None
    return f"{banner} ({p})"


def _probe_cc():
    for c in ("gcc", "cc", "clang"):
        if shutil.which(c):
            return _v(c, "--version")
    return None


def cross_compilers() -> list:
    """The cross compilers the architecture gate actually invokes, read from its own matrix.

    Hand-maintaining this list got it wrong in both directions: it named a MIPS compiler that
    exists in no current Debian or Kali repo, and omitted loongarch64, m68k, sh4, sparc64,
    s390x and two of the three PowerPC variants that the gate really does build. The matrix is
    the only thing that knows.
    """
    from .eval import archgate
    out = {c.cc for c in archgate.MATRIX if getattr(c, "cc", None) and c.cc != "gcc"}
    return sorted(out)


# Cross triple -> Debian multiarch name, for the `libc6-dev-<arch>-cross` dev package that carries
# that arch's static libc.a (FLIRT's reference for a stripped STATIC cross binary). The cross gcc
# only RECOMMENDS it, so --no-install-recommends drops it unless we name it explicitly. The collector
# skips any package not in the target distro (apt-cache guard), so naming an arch the distro lacks is
# harmless.
_CROSS_DEB_ARCH = {
    "aarch64-linux-gnu": "arm64", "arm-linux-gnueabihf": "armhf", "arm-linux-gnueabi": "armel",
    "riscv64-linux-gnu": "riscv64", "powerpc64le-linux-gnu": "ppc64el",
    "powerpc64-linux-gnu": "ppc64", "powerpc-linux-gnu": "powerpc",
    "mips64el-linux-gnu": "mips64el", "mipsel-linux-gnu": "mipsel", "mips-linux-gnu": "mips",
    "s390x-linux-gnu": "s390x", "sparc64-linux-gnu": "sparc64", "m68k-linux-gnu": "m68k",
    "sh4-linux-gnu": "sh4", "loongarch64-linux-gnu": "loong64",
}


def _cross_apt() -> tuple:
    """Debian package names for those compilers: <triple>-gcc ships in gcc-<triple>, and the cross
    static libc (FLIRT's reference for a stripped static cross binary) in libc6-dev-<arch>-cross."""
    pkgs = set()
    try:
        for cc in cross_compilers():
            if cc.endswith("-gcc"):
                triple = cc[:-4]
                pkgs.add("gcc-" + triple)
                deb = _CROSS_DEB_ARCH.get(triple)
                if deb:
                    pkgs.add("libc6-dev-%s-cross" % deb)   # the arch's libc.a for FLIRT
    except Exception:                                   # noqa: BLE001
        pass
    pkgs.add("gcc-mingw-w64-x86-64")                    # PE fixtures, not in the arch matrix
    return tuple(sorted(pkgs))


def _probe_cross_cc():
    try:
        want = cross_compilers() + ["x86_64-w64-mingw32-gcc"]
    except Exception:                                   # noqa: BLE001
        want = ["x86_64-w64-mingw32-gcc"]
    found = [t for t in want if shutil.which(t) and _v(t, "--version")]
    if not found:
        return None
    return f"{len(found)}/{len(want)}: " + " ".join(t.replace("-linux-gnu", "").replace(
        "-gcc", "") for t in found)


def _probe_objdump():
    return _v("objdump", "--version") if shutil.which("objdump") else None


def _probe_node():
    return _v("node", "--version") if shutil.which("node") else None


def _probe_valgrind():
    from .analyze.dynamic.memoracle import valgrind_bin
    vg = valgrind_bin()
    return _v(vg, "--version") if vg else None


def _preloads(lib) -> bool:
    """True when the host loader accepts `lib` as an LD_PRELOAD into the host's `true`. ld.so
    REJECTS a missing/corrupt/foreign-arch preload object with a warning but still exits 0 -- so
    the stderr text, not the rc, is the evidence. That is exactly how a broken libdislocator would
    otherwise run every 'guarded' execution unguarded while doctor said ok."""
    import os
    true = shutil.which("true")
    if not true:
        return True                                  # cannot test; do not invent a failure
    env = dict(os.environ)
    env["LD_PRELOAD"] = str(lib)
    try:
        r = subprocess.run([true], capture_output=True, timeout=5, env=env)
    except (OSError, subprocess.SubprocessError):
        return False
    text = ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "replace")
    return r.returncode == 0 and not _did_not_run(r.returncode, text)


def _probe_dislocator():
    from .analyze.dynamic.memoracle import dislocator_lib
    p = dislocator_lib()
    return str(p) if p and _preloads(p) else None


def _probe_qasan():
    from .analyze.dynamic.memoracle import libqasan_lib
    p = libqasan_lib()
    return str(p) if p else None


def _probe_strace():
    return _v("strace", "-V")


def _probe_honggfuzz():
    return _v("honggfuzz", "--version")


def _probe_infer():
    return _v("infer", "--version")


def _probe_ropper():
    return _v("ropper", "--version") or (shutil.which("ropper") and "installed")


def _probe_klee():
    # a container wrapper (vendor/tools/bin/klee): report presence, not a 30-second image start
    w = shutil.which("klee")
    return f"container wrapper ({w})" if w else None


def _probe_rr():
    return _v("rr", "--version")


def _probe_weggli():
    from .analyze.weggli import weggli_bin
    w = weggli_bin()
    if not w:
        return None
    ver = _v(w, "--version")
    return f"{ver} ({w})" if ver else None


# A broad base of C/C++ development libraries (-dev packages) to carry in the air-gap bundle, so
# that the common source project BUILDS offline instead of failing for a missing header. The build
# sandbox cannot fetch anything, so a dependency that is not on the box is a dependency the project
# cannot use -- and a failed build costs the entire binary/dynamic/symbolic capability for that
# target. This cannot cover every possible dependency (nothing offline can); it covers the
# libraries real targets -- network services, parsers, codecs, crypto, system daemons -- pull in
# most often. `lykos deps <dir>` reports what a SPECIFIC project still needs beyond this base so an
# operator stages it before going offline. Heavy desktop-GUI stacks (GTK/Qt/pango/cairo) are left
# out deliberately: they are rarely the target and multiply the bundle size.
#
# Debian/Kali names. The collector's apt-cache guard skips any package the target distro lacks, so
# a name missing on one distro is harmless rather than fatal.
_DEV_LIB_BASE: tuple = (
    # compression
    "zlib1g-dev", "libbz2-dev", "liblzma-dev", "libzstd-dev", "liblz4-dev", "libbrotli-dev",
    "libsnappy-dev",
    # crypto / TLS / auth
    "libssl-dev", "libgnutls28-dev", "libnettle-dev", "libgcrypt20-dev", "libsodium-dev",
    "libkrb5-dev", "libldap2-dev", "libsasl2-dev",
    # text / parsing / data formats
    "libxml2-dev", "libexpat1-dev", "libpcre2-dev", "libpcre3-dev", "libjansson-dev",
    "libjson-c-dev", "libyaml-dev", "libffi-dev", "libgmp-dev", "libmpfr-dev",
    # databases / transfer
    "libsqlite3-dev", "libcurl4-openssl-dev",
    # networking / capture
    "libpcap-dev", "libnl-3-dev", "libssh2-1-dev", "libssh-dev", "libusb-1.0-0-dev",
    "libevent-dev", "libuv1-dev",
    # system / security
    "libcap-dev", "libcap-ng-dev", "libseccomp-dev", "libselinux1-dev", "libdbus-1-dev",
    "libsystemd-dev", "libudev-dev", "uuid-dev", "libmnl-dev", "libmagic-dev", "libarchive-dev",
    # terminal / line editing
    "libncurses-dev", "libreadline-dev", "libedit-dev",
    # image / media codecs (common fuzz targets)
    "libpng-dev", "libjpeg-dev", "libtiff-dev", "libgif-dev", "libwebp-dev", "libfreetype-dev",
    "libfontconfig-dev", "libsndfile1-dev", "libogg-dev", "libvorbis-dev", "libflac-dev",
    "libasound2-dev",
    # base windowing header set a surprising number of libraries probe for (lightweight subset)
    "libx11-dev",
)

# A handful of representative headers from the base, to report presence without asking apt.
_DEV_LIB_PROBE_HEADERS = (
    "openssl/ssl.h", "zlib.h", "bzlib.h", "lzma.h", "zstd.h", "curl/curl.h", "libxml/parser.h",
    "sqlite3.h", "pcre2.h", "ncurses.h", "ffi.h", "expat.h", "gmp.h", "readline/readline.h",
)


def dev_dependency_base() -> tuple:
    """The broad C/C++ -dev library base the offline bundle carries so common source projects build
    without network. One place, so the collector and doctor cannot drift."""
    return _DEV_LIB_BASE


def _probe_devbase():
    """How much of the dev-library base is present on THIS host, by checking a representative set of
    headers with the same search a build uses. Not all-or-nothing: reports N/M so an operator sees
    partial coverage, and None only when none are present."""
    try:
        from .analyze.dep_preflight import _header_present
    except Exception:                                   # noqa: BLE001
        return None
    have = [h for h in _DEV_LIB_PROBE_HEADERS if _header_present(h)]
    if not have:
        return None
    return f"{len(have)}/{len(_DEV_LIB_PROBE_HEADERS)} common dev headers (e.g. " \
           + ", ".join(have[:4]) + ")"


TOOLS: tuple = (
    Tool("python", "Python 3", "the platform itself", "nothing runs",
         "already present (the runtime is stdlib-based; no pip packages)",
         _probe_python, tier="required"),
    Tool("bwrap", "bubblewrap", "the sandbox tier used for every execution",
         "execution drops to rlimits-only: no network namespace, no read-only root. It still "
         "RUNS, which is the problem -- this is the one degradation you do not want silent "
         "when the binary is hostile",
         "apt-get install bubblewrap", _probe_bwrap, tier="required", apt=("bubblewrap",)),
    Tool("rizin", "rizin + rz-ghidra (native RE)",
         "the DEFAULT disassemble/decompile backend: CFG, xrefs, decompiled C -- no JVM",
         "no native RE backend; disassembly falls back to Ghidra only if it is present",
         "apt-get install rizin rz-ghidra", _probe_rizin, tier="required",
         apt=("rizin", "rz-ghidra")),
    Tool("pypcode", "pypcode (Ghidra P-Code, no JVM)",
         "the Ghidra P-Code IR the taint/bounds/int-overflow detectors consume",
         "the native backend still decompiles, but P-Code-based memory-safety detection degrades",
         "vendored: pip install pypcode (bundled under vendor/pysite, added to sys.path)",
         _probe_pypcode, tier="required"),
    Tool("ghidra", "Ghidra (headless) -- optional, not bundled",
         "an alternative RE backend with stronger auto-analysis on some stripped/optimized "
         "binaries; rizin/rz-ghidra + pypcode is the bundled default and covers the common case",
         "nothing in the bundle: the native rizin backend is used. Install Ghidra separately "
         "only if a hard binary analyses poorly, then LYKOS_DECOMPILER=ghidra",
         "apt-get install ghidra (Kali), or unpack a release into /opt and set LYKOS_GHIDRA; "
         "then LYKOS_DECOMPILER=ghidra. Not shipped in the offline bundle (replaced by rizin)",
         _probe_ghidra, tier="optional"),
    Tool("qemu", "qemu-user", "executing any non-host-architecture binary",
         "cross-architecture targets cannot run at all -- static analysis only",
         "apt-get install qemu-user qemu-user-binfmt",
         _probe_qemu, tier="recommended", apt=("qemu-user", "qemu-user-binfmt")),
    Tool("gdb", "GDB", "root_cause detail, multi_debug, the runtime monitor, dynamic taint",
         "root_cause falls back to the stdlib ptrace helper; multi_debug and the monitor "
         "decline",
         "apt-get install gdb", _probe_gdb, tier="recommended", apt=("gdb",)),
    Tool("cc", "C compiler", "building the eval corpus and the real-gate fixtures",
         "make eval-gate / real-gate skip; analysis of supplied binaries is unaffected",
         "apt-get install build-essential", _probe_cc, tier="recommended",
         apt=("build-essential",)),
    Tool("clang", "clang + libFuzzer/ASan runtime",
         "coverage_fuzz of SOURCE via libFuzzer (-fsanitize=fuzzer) and afl-clang-fast instrumentation",
         "libFuzzer source-coverage is unavailable (afl qemu-mode for binaries + afl-gcc-fast for "
         "source remain); this gap shipped silently in earlier bundles",
         "apt-get install clang libclang-rt-dev", _probe_clang, tier="optional",
         apt=("clang", "libclang-rt-dev")),
    Tool("afl", "AFL++", "coverage_fuzz (fork-server, coverage-guided)",
         "black-box fuzz only -- measured ~40x slower on ARM",
         "apt-get install afl++", _probe_afl, tier="optional", apt=("afl++",)),
    Tool("afl-qemu", "afl-qemu-trace (per guest)",
         "coverage_fuzz against a non-host architecture",
         "coverage_fuzz declines for those guests and prints the build command",
         "examples/afl-qemu/build.sh <arch>  (one per guest architecture)",
         _probe_afl_qemu, tier="optional"),
    Tool("dislocator", "libdislocator (guard-page heap oracle)",
         "a binary-only heap oracle: LD_PRELOADed, a heap OOB / use-after-free in a target with no "
         "source ASan faults immediately instead of corrupting silently",
         "stripped binaries lose the guard-page heap oracle (valgrind triage still applies)",
         "apt-get install afl++  (ships libdislocator.so under /usr/lib/afl)",
         _probe_dislocator, tier="optional", apt=("afl++",)),
    Tool("valgrind", "Valgrind memcheck (memory-error triage)",
         "classifies a crash into an exact memory-error CWE (heap OOB read/write, "
         "use-after-free, double-free, uninitialised read) on a binary with no source ASan",
         "dynamic crashes on stripped binaries are not classified by defect class",
         "apt-get install valgrind",
         _probe_valgrind, tier="optional", apt=("valgrind",)),
    Tool("qasan", "libqasan (QEMU-mode ASan) -- optional, built from AFL++",
         "deeper heap shadowing than libdislocator for an ELF fuzzed under qemu",
         "the dislocator + valgrind lanes cover the common case; qasan adds shadow-memory depth",
         "build AFL++ qemu_mode with libqasan, then LYKOS_QASAN=/path/libqasan.so",
         _probe_qasan, tier="optional"),
    Tool("strace", "strace (syscall tracer)",
         "the syscall-effect oracle (exec/open arguments) for command injection, path traversal "
         "and TOCTOU validation on native targets",
         "those validators fall back to output markers; path traversal cannot be proven on a "
         "target that does not print what it opened",
         "apt-get install strace", _probe_strace, tier="recommended", apt=("strace",)),
    Tool("honggfuzz", "honggfuzz -- optional fallback fuzzer",
         "a second coverage-guided engine for the hypothesis loop's fuzz fallback (doc 52 step 5)",
         "AFL++ remains the fallback fuzzer",
         "build from source into vendor/tools/honggfuzz (docs/internal/53)",
         _probe_honggfuzz, tier="optional"),
    Tool("infer", "Infer (Meta, MIT) -- optional source analyzer",
         "an independent interprocedural proposer for source targets (null deref, leaks, races)",
         "proposals come from lykos' own checks only",
         "unpack the official release into vendor/tools/infer (docs/internal/53)",
         _probe_infer, tier="optional"),
    Tool("ropper", "ropper -- optional gadget finder",
         "a cross-check for lykos' own gadget search in the exploit ladder",
         "lykos' built-in gadget finder and ROP solver are used alone",
         "vendor/tools/ropper-venv (docs/internal/53)", _probe_ropper, tier="optional"),
    Tool("klee", "KLEE -- optional, dev-side container",
         "a second symbolic engine to cross-check the angr hypothesis driver on source targets",
         "angr is the only symbolic engine",
         "podman pull docker.io/klee/klee:3.3; wrapper vendor/tools/bin/klee (not air-gap bundled)",
         _probe_klee, tier="optional"),
    Tool("rr", "rr record/replay -- optional, needs root to set up",
         "deterministic replay of a validated PoC for root-cause and race analysis",
         "PoCs are replayed live (N-run agreement) instead of recorded",
         "sudo apt install rr && sudo sysctl kernel.perf_event_paranoid=1",
         _probe_rr, tier="optional", apt=("rr",)),
    Tool("weggli", "weggli (source variant analysis)",
         "AST pattern matching over C/C++ source: run the vuln-pattern pack and hunt variants of a "
         "known bug (lykos weggli-scan)",
         "the source variant-analysis pack is unavailable (binary variant-scan still applies)",
         "cargo install weggli  (or a release binary), then it is on PATH / set LYKOS_WEGGLI",
         _probe_weggli, tier="optional"),
    Tool("jdk", "JDK (javac + jar)", "building the JVM gate fixtures",
         "the real-gate JVM case skips",
         "apt-get install default-jdk", _probe_jdk, tier="optional", apt=("default-jdk",)),
    Tool("java", "Java runtime", "running JAR/class targets",
         "Java targets triage and analyse statically but cannot be executed",
         "apt-get install default-jre", _probe_java, tier="optional",
         apt=("default-jre",)),
    Tool("wine", "Wine", "Windows PE execution, behaviour trace and the Win32 monitor",
         "PE targets analyse statically; synthesize_poc still derives an overflow "
         "from the frame",
         "apt-get install wine wine64", _probe_wine, tier="optional",
         apt=("wine", "wine64")),
    Tool("cross-cc", "Cross compilers", "building the architecture-gate fixtures",
         "make arch-gate covers fewer architectures",
         "apt-get install " + " ".join(_cross_apt()),
         _probe_cross_cc, tier="optional", apt=_cross_apt()),
    Tool("angr", "angr (vendored venv)", "the concolic stage's default backend",
         "concolic declines unless symqemu is present",
         "python3 -m venv vendor/angr-venv && vendor/angr-venv/bin/pip install 'angr==9.3.4'",
         _probe_angr, tier="optional"),
    Tool("unicorn", "Unicorn (vendored venv)", "firmware_rehost (bare-metal Cortex-M)",
         "firmware_rehost declines; carving and headerless identification still work",
         "python3 -m venv vendor/unicorn-venv && "
         "vendor/unicorn-venv/bin/pip install unicorn keystone-engine",
         _probe_unicorn, tier="optional"),
    Tool("symqemu", "SymQEMU (vendored build)", "the concolic stage's symbolic-execution backend",
         "concolic uses angr, or declines if that is absent too",
         "packaging/build-symqemu.sh  (builds in a container, vendors the result)",
         _probe_symqemu, tier="optional", bundle=_bundle_symqemu),
    Tool("objdump", "binutils objdump", "a few disassembly cross-checks in the test suite",
         "those tests skip", "apt-get install binutils", _probe_objdump, tier="optional",
         apt=("binutils",)),
    Tool("node", "Node.js", "the GUI test harnesses (make gui)",
         "make gui fails; the UI itself is unaffected",
         "apt-get install nodejs", _probe_node, tier="optional", apt=("nodejs",)),
    Tool("devbase", "C/C++ dev-library base",
         "building the COMMON source project offline: the headers/libs (openssl, zlib, xml2, "
         "curl, sqlite, pcre, codecs, crypto, system daemons) real targets link against",
         "a source project needing one of these cannot build on the air-gapped box, which costs "
         "the whole binary/dynamic/symbolic capability for that target -- it degrades to "
         "static-source only. `lykos deps <dir>` reports what a SPECIFIC project still needs",
         "apt-get install " + " ".join(_DEV_LIB_BASE), _probe_devbase, tier="recommended",
         apt=_DEV_LIB_BASE),
)


def survey(progress=None) -> list:
    """[(Tool, found_str_or_None)] for this host, in declaration order. `progress(tool)`, when
    given, is called BEFORE each probe -- several probes spawn subprocesses with multi-second
    timeouts (rizin/gdb/clang/java/wine/qemu), so a caller can show which one is running instead of
    appearing to hang."""
    out = []
    for t in TOOLS:
        if progress is not None:
            try:
                progress(t)
            except Exception:                           # noqa: BLE001 -- progress must never fail a probe
                pass
        try:
            got = t.probe()
        except Exception as e:                          # noqa: BLE001
            got = None
            t = Tool(t.key, t.title, t.unlocks, f"probe failed: {e!r}", t.install, t.probe,
                     tier=t.tier, apt=t.apt)
        out.append((t, got))
    return out


def missing(tier: Optional[str] = None) -> list:
    """Tools not present, optionally filtered to one tier."""
    return [t for t, got in survey() if not got and (tier is None or t.tier == tier)]


def apt_packages() -> list:
    """Every deb the offline collector should pull, deduplicated and sorted. ONE build with all
    capabilities. rizin/rz-ghidra + pypcode replaced Ghidra as the RE backend (Ghidra carries no
    apt here), so it is the only thing not pulled; everything else the platform uses is."""
    out: set = set()
    for t in TOOLS:
        out.update(t.apt)
    return sorted(out)


def bundle_paths() -> list:
    """Non-apt tools to copy into the offline bundle, as ``[(key, [paths]), ...]``.

    Some engines are not apt packages on this host (SymQEMU is a source build, and anything else
    a Tool marks with a ``bundle`` callable). The collector pulls the deb-installable tools with
    ``apt_packages``; this covers the rest, driven by the SAME ``TOOLS`` table so the two cannot
    drift. A tool whose ``bundle`` callable returns nothing (not built/installed here) is skipped,
    and a callable that raises is skipped too -- a missing extra must not abort the whole collect.
    Returns only entries that actually have paths, in declaration order.
    """
    out: list = []
    for t in TOOLS:
        if not t.bundle:
            continue
        try:
            paths = t.bundle() or []
        except Exception as e:                          # noqa: BLE001
            # A probe/locator for an absent extra may raise; that just means "not here to bundle".
            observe.absorbed(_log, f"bundle_paths: {t.key} not bundled ({e!r})")
            continue
        if paths:
            out.append((t.key, list(paths)))
    return out


def report(*, verbose: bool = False, rows=None) -> str:
    """A human-readable capability report for this host. Pass `rows` from a prior `survey()` to
    format without re-probing (so a streaming caller probes once)."""
    rows = survey() if rows is None else rows
    width = max(len(t.title) for t, _ in rows)
    lines: list = []
    by_tier: dict = {"required": [], "recommended": [], "optional": []}
    for t, got in rows:
        by_tier.setdefault(t.tier, []).append((t, got))
    for tier in ("required", "recommended", "optional"):
        group = by_tier.get(tier) or []
        if not group:
            continue
        lines.append(f"\n{tier.upper()}")
        for t, got in group:
            mark = "ok  " if got else "MISS"
            lines.append(f"  [{mark}] {t.title:<{width}}  {got or '-- not found --'}")
            if not got or verbose:
                lines.append(f"         unlocks: {t.unlocks}")
            if not got:
                lines.append(f"         without: {t.without}")
                lines.append(f"         install: {t.install}")
    gone = [t for t, got in rows if not got]
    hard = [t for t in gone if t.tier == "required"]
    lines.append("")
    lines.append(f"{len(rows) - len(gone)}/{len(rows)} present."
                 + (f" {len(hard)} REQUIRED missing." if hard else ""))
    return "\n".join(lines)


def as_dict() -> dict:
    """The same survey as JSON-able data, for the API and for scripting."""
    return {"tools": [{"key": t.key, "title": t.title, "tier": t.tier, "found": got,
                       "present": bool(got), "unlocks": t.unlocks, "without": t.without,
                       "install": t.install} for t, got in survey()]}
