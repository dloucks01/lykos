"""One inventory of every external tool lykos can use, what it unlocks, and how to get it.

The platform's core is stdlib-only and runs with none of these; each stage locates its tool,
runs it, and declines with a reason when it is absent. That design only works if an operator
can find out WHICH tools this host has -- on an air-gapped workstation there is no package
manager to ask, and "the stage declined" is a poor way to discover that Ghidra was never
installed.

This module is the single place that answers it. `lykos doctor` prints it, the air-gap
bundle script reads it to know what to collect, and doc 23 is generated from the same table --
so a tool cannot be added to one and forgotten in the others. Every probe delegates to the
locator the stage itself uses, rather than re-implementing the search: a doctor that looks in
different places from the code is worse than no doctor, because it reports a capability the
platform will then decline to run.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional


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


def _v(cmd, *args, timeout=5):
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
        r = subprocess.run([exe, *args], capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    out = (r.stdout or b"") + (r.stderr or b"")
    line = out.decode("utf-8", "replace").strip().splitlines()
    if line:
        return line[0][:90]
    # No output: only trust it if it exited cleanly (some tools print nothing on --version but
    # a non-zero exit with no output means it did not really run).
    return exe if r.returncode == 0 else None


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


def _bundle_ghidra():
    """Ghidra's install root. `<root>/support/analyzeHeadless` is what the locator returns,
    and the locator already searches /opt/ghidra* and <repo>/vendor/ghidra -- so a copy placed
    at either is found with no configuration on the air-gapped side."""
    from .analyze.ghidra import locate_ghidra
    p = locate_ghidra()
    if not p:
        return []
    root = p.parent.parent if p.parent.name == "support" else p.parent
    return [root] if (root / "support").is_dir() else []


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
    from .analyze.fuzz.aflpp import locate_afl
    p = locate_afl()
    return str(p) if p else None


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
    suffixes = _qemu_suffixes()
    found = [a for a in suffixes if shutil.which(f"qemu-{a}")]
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
    from .analyze.symbolic.symqemu import locate_symqemu
    p = locate_symqemu()
    return str(p) if p else None


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


def _cross_apt() -> tuple:
    """Debian package names for those compilers: <triple>-gcc ships in gcc-<triple>."""
    pkgs = set()
    try:
        for cc in cross_compilers():
            if cc.endswith("-gcc"):
                pkgs.add("gcc-" + cc[:-4])
    except Exception:                                   # noqa: BLE001
        pass
    pkgs.add("gcc-mingw-w64-x86-64")                    # PE fixtures, not in the arch matrix
    return tuple(sorted(pkgs))


def _probe_cross_cc():
    try:
        want = cross_compilers() + ["x86_64-w64-mingw32-gcc"]
    except Exception:                                   # noqa: BLE001
        want = ["x86_64-w64-mingw32-gcc"]
    found = [t for t in want if shutil.which(t)]
    if not found:
        return None
    return f"{len(found)}/{len(want)}: " + " ".join(t.replace("-linux-gnu", "").replace(
        "-gcc", "") for t in found)


def _probe_objdump():
    return _v("objdump", "--version") if shutil.which("objdump") else None


def _probe_node():
    return _v("node", "--version") if shutil.which("node") else None


TOOLS: tuple = (
    Tool("python", "Python 3", "the platform itself", "nothing runs",
         "already present (the runtime is stdlib-only; no pip packages)",
         _probe_python, tier="required"),
    Tool("bwrap", "bubblewrap", "the sandbox tier used for every execution",
         "execution drops to rlimits-only: no network namespace, no read-only root. It still "
         "RUNS, which is the problem -- this is the one degradation you do not want silent "
         "when the binary is hostile",
         "apt-get install bubblewrap", _probe_bwrap, tier="required", apt=("bubblewrap",)),
    Tool("ghidra", "Ghidra (headless)",
         "disassemble, and everything downstream: detect_cwe, taint, bounds, directed fuzzing",
         "the whole static half. Fuzzing still finds crashes; nothing explains one",
         "apt-get install ghidra (Kali), or unpack a release into /opt and set LYKOS_GHIDRA",
         _probe_ghidra, tier="required", apt=("ghidra", "default-jdk"),
         bundle=_bundle_ghidra),
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
    Tool("afl", "AFL++", "coverage_fuzz (fork-server, coverage-guided)",
         "black-box fuzz only -- measured ~40x slower on ARM",
         "apt-get install afl++", _probe_afl, tier="optional", apt=("afl++",)),
    Tool("afl-qemu", "afl-qemu-trace (per guest)",
         "coverage_fuzz against a non-host architecture",
         "coverage_fuzz declines for those guests and prints the build command",
         "examples/afl-qemu/build.sh <arch>  (one per guest architecture)",
         _probe_afl_qemu, tier="optional"),
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
         "python3 -m venv vendor/angr-venv && vendor/angr-venv/bin/pip install angr",
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
)


def survey() -> list:
    """[(Tool, found_str_or_None)] for this host, in declaration order."""
    out = []
    for t in TOOLS:
        try:
            got = t.probe()
        except Exception as e:                          # noqa: BLE001
            got = None
            t = Tool(t.key, t.title, t.unlocks, f"probe failed: {e!r}", t.install, t.probe,
                     t.tier, t.apt)
        out.append((t, got))
    return out


def missing(tier: Optional[str] = None) -> list:
    """Tools not present, optionally filtered to one tier."""
    return [t for t, got in survey() if not got and (tier is None or t.tier == tier)]


def bundle_paths() -> list:
    """[(key, [paths])] for every tool that ships as a directory copy rather than a deb.

    Ghidra is the reason this exists: it is a REQUIRED tool and it is not apt-installable
    outside Kali, so a bundle built from the package list alone would arrive without the
    single most important engine and nothing would say so until the first disassemble.
    """
    out = []
    for t in TOOLS:
        if not t.bundle:
            continue
        try:
            paths = [p for p in t.bundle() if p]
        except Exception as e:                          # noqa: BLE001
            # Never silent: a bundle probe that raises would otherwise drop the tool from the
            # air-gap tarball with no trace -- the exact failure this module exists to prevent
            # (a REQUIRED engine like Ghidra arriving absent, found only at first disassemble).
            raise RuntimeError(
                f"bundle probe for {t.key!r} failed: {e!r}; refusing to build a bundle that "
                f"would silently omit it") from e
        if paths:
            out.append((t.key, paths))
    return out


def apt_packages() -> list:
    """Every deb the air-gap collector should pull, deduplicated and sorted."""
    out: set = set()
    for t in TOOLS:
        out.update(t.apt)
    return sorted(out)


def report(*, verbose: bool = False) -> str:
    """A human-readable capability report for this host."""
    rows = survey()
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
