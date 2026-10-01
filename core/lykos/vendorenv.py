"""Activate a run-in-place toolchain: no install, no root, and the laptop's libraries untouched.

The offline toolchain bundle does not install anything. It extracts to a relocatable prefix
under the repo's ``vendor/`` directory (``vendor/toolchain``), and the engines run straight
out of that tree. This module is what makes that work, and it does so through ``PATH`` **only**:
once, before any stage's locator runs, it prepends the prefix's binary directory to ``PATH``.

It deliberately does NOT touch ``LD_LIBRARY_PATH`` or any other library-search setting of this
process. Putting the bundle's shared libraries on the process-wide search path would make the
laptop's own binaries -- and every system subprocess lykos spawns -- prefer bundle libraries
over their own, which is how a mismatched library can crash system tooling. So the bundle's
libraries stay strictly private to the bundle's own tools: ``setup.sh`` writes a tiny wrapper
per vendored executable (under ``vendor/toolchain/.wrappers``) that sets ``LD_LIBRARY_PATH``
for that one process and execs the real binary. Only those wrappers go on ``PATH``. Nothing the
laptop already had is ever relinked, replaced, symlinked, or removed.

Every tool locator in the platform funnels through ``shutil.which`` (which reads ``PATH``) or a
``vendor/`` search of its own, so prepending the wrapper directory is the whole mechanism by
which a bundled ``bwrap``/``gdb``/``qemu-*``/``gcc``/``wine``/``java`` is found with nothing
installed. Ghidra, the angr and Unicorn venvs, and SymQEMU are located by their own code, which
already searches ``vendor/``; this module only points the config env vars they honour at the
vendored copies when those exist and the operator has not set them.

Activation is idempotent and a no-op when there is no vendored toolchain, so an ordinary host
is completely unaffected.
"""
from __future__ import annotations

import os
import sys
from glob import glob
from pathlib import Path
from typing import Optional

_ACTIVE_FLAG = "_LYKOS_VENDOR_ACTIVE"

# The scoped-wrapper directory setup.sh generates; preferred on PATH so a vendored tool runs
# with only the bundle's own libraries, never the laptop's search path.
_WRAPPER_SUBDIR = ".wrappers"
# Directories inside the extracted prefix that hold executables. Debian lays a package's files
# under usr/; the local/sbin variants catch afl-qemu-trace copies and the odd tool that lands
# in /bin or /sbin directly. NOTE: library directories are intentionally not listed here or put
# on any search path -- see the module docstring.
_BIN_SUBDIRS = ("usr/local/bin", "usr/bin", "usr/sbin", "bin", "sbin", "usr/games")


def repo_root() -> Optional[Path]:
    """The source checkout root (the dir that holds ``core/lykos``), or None.

    Under a zipapp (.pyz) ``__file__`` lives inside the archive and this path is not a real
    directory; the ``is_dir`` guard makes that case a clean None rather than a bogus vendor
    search inside the zip.
    """
    root = Path(__file__).resolve().parents[2]
    return root if (root / "core" / "lykos").is_dir() else None


def vendor_dir() -> Optional[Path]:
    """The ``vendor/`` directory the bundle extracts into, or None if there is none.

    Order: ``LYKOS_VENDOR`` (explicit), then ``<repo>/vendor``, then ``./vendor`` under the
    current working directory (covers running from an extracted repo tarball).
    """
    env = os.environ.get("LYKOS_VENDOR")
    if env:
        p = Path(env)
        return p if p.is_dir() else None
    root = repo_root()
    if root and (root / "vendor").is_dir():
        return root / "vendor"
    cwd = Path.cwd() / "vendor"
    return cwd if cwd.is_dir() else None


def toolchain_prefix() -> Optional[Path]:
    """The extracted relocatable prefix the apt-sourced tools run from, or None.

    Order: ``LYKOS_TOOLCHAIN`` (explicit), then ``<vendor>/toolchain``.
    """
    env = os.environ.get("LYKOS_TOOLCHAIN")
    if env:
        p = Path(env)
        return p if p.is_dir() else None
    v = vendor_dir()
    if v and (v / "toolchain").is_dir():
        return v / "toolchain"
    return None


def _bin_dirs(prefix: Path) -> list:
    """The executable directories to put on PATH: the scoped-wrapper dir first (so a vendored
    tool runs with only the bundle's own libraries), then the raw bin dirs behind it as a
    fallback for any tool without a wrapper. Library directories are never returned -- the
    bundle's libraries never join a process-wide search path. See the module docstring."""
    out: list = []
    wrappers = prefix / _WRAPPER_SUBDIR
    if wrappers.is_dir():
        out.append(str(wrappers))
    for sub in _BIN_SUBDIRS:
        d = prefix / sub
        if d.is_dir():
            out.append(str(d))
    return out


def _find_ghidra(vendor: Optional[Path], prefix: Optional[Path]) -> Optional[Path]:
    """A Ghidra install root inside the vendored tree, or None.

    ``locate_ghidra`` already searches ``<repo>/vendor/ghidra`` and system paths, so a copy
    placed there needs nothing. But the container/apt path extracts Ghidra's deb *into the
    toolchain prefix* (``toolchain/usr/share/ghidra*``), which no locator and no PATH entry
    would find -- ``analyzeHeadless`` lives under ``support/``, not ``bin/``. Point the locator
    at it by finding the root whose ``support/analyzeHeadless`` exists.
    """
    if vendor and (vendor / "ghidra" / "support").is_dir():
        return vendor / "ghidra"
    if prefix:
        for pat in ("usr/share/ghidra*", "usr/lib/ghidra*", "opt/ghidra*", "ghidra*"):
            for hit in sorted(glob(str(prefix / pat)), reverse=True):
                if (Path(hit) / "support" / "analyzeHeadless").exists():
                    return Path(hit)
    return None


def _prepend_path(dirs: list) -> None:
    """Put ``dirs`` in front of ``os.environ['PATH']``, de-duplicated, dropping empties.

    Prepending (not replacing) keeps the host's own tools reachable: a vendored ``gdb`` wins,
    but anything the bundle does not carry still resolves against the system path behind it.
    PATH selects which *executable* a name resolves to; it does not change how any binary finds
    its shared libraries, so this cannot relink the laptop's own programs.
    """
    if not dirs:
        return
    existing = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    seen: set = set()
    ordered: list = []
    for p in [*dirs, *existing]:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    os.environ["PATH"] = os.pathsep.join(ordered)


def vendored_python(prefix: Optional[Path]) -> Optional[Path]:
    """The bundle's OWN interpreter (``usr/bin/python3.X``), or None if none was vendored.

    A bundle built by make-runnable ships a matching Python so the engine venvs and the pypcode
    wheel -- both ABI-locked to one Python minor -- do not depend on whatever python3 the laptop
    happens to have. Prefer the concrete versioned binary over the ``python3`` symlink.
    """
    if not prefix:
        return None
    for c in sorted(glob(str(prefix / "usr/bin/python3.[0-9]*")), reverse=True):
        p = Path(c)
        if p.is_file() and os.access(c, os.X_OK):
            return p
    p3 = prefix / "usr/bin/python3"
    return p3 if p3.exists() else None


def _repoint_venvs(vendor: Optional[Path], interp: Optional[Path]) -> list:
    """Point each vendored engine venv at the BUNDLE's interpreter.

    The venvs are built on the collect host with an absolute base-python path (``/usr/bin/...``)
    that does not exist on the laptop, and the extract location is unknown until the bundle is
    unzipped -- so the fix is done here, at activation, against the interpreter's now-known path.
    Rewrites ``pyvenv.cfg`` (home/executable) and the ``bin/python*`` symlinks. Idempotent, and a
    best-effort no-op if the tree is read-only.
    """
    if not vendor or not interp:
        return []
    import re
    interp = interp.resolve()
    homedir = str(interp.parent)
    fixed: list = []
    for cfg in sorted(glob(str(vendor / "*-venv" / "pyvenv.cfg"))):
        ven = Path(cfg).parent
        try:
            txt = Path(cfg).read_text()
            new = re.sub(r"(?m)^home\s*=.*$", f"home = {homedir}", txt)
            new = re.sub(r"(?m)^executable\s*=.*$", f"executable = {interp}", new)
            if new != txt:
                Path(cfg).write_text(new)
            bindir = ven / "bin"
            for name in {"python", "python3", interp.name}:
                link = bindir / name
                try:
                    if link.is_symlink() and os.path.realpath(link) == str(interp):
                        continue
                    if link.is_symlink() or link.exists():
                        link.unlink()
                    link.symlink_to(interp)
                except OSError:
                    pass
            fixed.append(str(ven))
        except OSError:
            continue
    return fixed


def activate(force: bool = False) -> dict:
    """Point this process's environment at the vendored, run-in-place toolchain.

    Idempotent: a flag in the environment means a second call (or a child that inherited the
    already-activated env) does nothing. Returns a small summary of what was wired up, for
    ``lykos doctor`` and for debugging; an empty ``bin`` summary means there was no vendored
    toolchain and the host's own tools are in use. It only ever prepends to PATH and sets a
    couple of config env vars -- it never modifies any library-search path.
    """
    if os.environ.get(_ACTIVE_FLAG) and not force:
        return {"already": True}

    summary: dict = {"vendor": None, "toolchain": None, "bin": [], "env": {}}
    vendor = vendor_dir()
    summary["vendor"] = str(vendor) if vendor else None

    prefix = toolchain_prefix()
    if prefix:
        summary["toolchain"] = str(prefix)
        bins = _bin_dirs(prefix)
        _prepend_path(bins)
        summary["bin"] = bins

    # Point the engine-specific locators at their vendored copies when the operator has not
    # already chosen one. These honour their own env vars first (see each locate_* function),
    # so an explicit choice is never overridden.
    env = summary["env"]
    ghidra = _find_ghidra(vendor, prefix)
    if ghidra:
        for var in ("LYKOS_GHIDRA", "GHIDRA_INSTALL_DIR"):
            if not os.environ.get(var):
                os.environ[var] = str(ghidra)
                env[var] = str(ghidra)
    # A JDK unpacked into the prefix (Ghidra needs one, and the apt ghidra pulls one in). Its
    # java/javac live under usr/lib/jvm/<vm>/bin, not usr/bin, so they are not on PATH and not
    # wrapped. Export JAVA_HOME (Ghidra's launcher honours it) AND put the JVM bin on PATH so
    # `java`/`javac` resolve -- otherwise a JDK that is present reports absent, and JAR targets
    # cannot run. java links the host's own libraries here (no vendored LD path), which on the
    # bundle's own distribution is exactly right.
    if prefix and not os.environ.get("JAVA_HOME"):
        for cand in sorted(glob(str(prefix / "usr/lib/jvm/*"))):
            jbin = Path(cand) / "bin"
            if (jbin / "java").is_file():
                os.environ["JAVA_HOME"] = cand
                env["JAVA_HOME"] = cand
                _prepend_path([str(jbin)])
                summary["bin"].append(str(jbin))
                break

    # A relocated GCC (and the cross-compilers) looks for system headers and startup files at
    # absolute /usr paths, which are empty on a minimal target -- so `#include <string.h>` and
    # linking fail even though the bundle carries them. Point the compilers at the vendored
    # sysroot via the standard env vars (GCC reads LIBRARY_PATH for both -l libs and the crt*.o
    # startfiles). Only when unset, so an operator's own choice wins. These affect compiler
    # invocations only; they never change how the analysis binaries link.
    if prefix:
        incdirs = [str(prefix / "usr/include")] if (prefix / "usr/include").is_dir() else []
        incdirs += sorted(glob(str(prefix / "usr/include/*-linux-gnu")))
        libdirs = [str(prefix / d) for d in ("usr/lib", "lib") if (prefix / d).is_dir()]
        libdirs += sorted(glob(str(prefix / "usr/lib/*-linux-gnu")))
        libdirs += sorted(glob(str(prefix / "lib/*-linux-gnu")))
        for var, dirs in (("C_INCLUDE_PATH", incdirs), ("CPLUS_INCLUDE_PATH", incdirs),
                          ("LIBRARY_PATH", libdirs)):
            if dirs and not os.environ.get(var):
                os.environ[var] = os.pathsep.join(dirs)
                env[var] = os.environ[var]

    # The vendored Python site (pypcode and any other bundled pure/py-ext package) goes on
    # sys.path so `import pypcode` resolves in-place -- it is a compiled wheel built against the
    # bundle's Python, so it is imported by the main interpreter, not run from a venv. Also add
    # it to PYTHONPATH so child processes inherit it. Absent => a no-op; the core stays
    # stdlib-based unless a bundle placed one here.
    site = pysite_dir(vendor)
    if site:
        s = str(site)
        if s not in sys.path:
            sys.path.insert(0, s)
        _prepend_env("PYTHONPATH", [s])
        summary["pysite"] = s

    # Repoint the engine venvs at the bundle's own interpreter, so angr/unicorn do not need the
    # laptop to have the exact python3 the venvs were built with. Only when an interpreter was
    # vendored; on an ordinary dev host (no vendored python) this is a no-op and the venvs keep
    # their original base.
    interp = vendored_python(prefix)
    if interp:
        summary["python"] = str(interp)
        fixed = _repoint_venvs(vendor, interp)
        if fixed:
            summary["venvs"] = fixed

    os.environ[_ACTIVE_FLAG] = "1"
    return summary


def pysite_dir(vendor: Optional[Path] = None) -> Optional[Path]:
    """The vendored Python site directory (a ``pip install --target`` tree, e.g. holding
    pypcode), or None. Order: ``LYKOS_PYSITE`` then ``<vendor>/pysite``."""
    env = os.environ.get("LYKOS_PYSITE")
    if env:
        p = Path(env)
        return p if p.is_dir() else None
    if vendor is None:
        vendor = vendor_dir()
    if vendor and (vendor / "pysite").is_dir():
        return vendor / "pysite"
    return None


def _prepend_env(var: str, dirs: list) -> None:
    """Prepend dirs to a colon-separated env var (PYTHONPATH), de-duplicated."""
    if not dirs:
        return
    existing = [p for p in os.environ.get(var, "").split(os.pathsep) if p]
    seen: set = set()
    ordered: list = []
    for p in [*dirs, *existing]:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    os.environ[var] = os.pathsep.join(ordered)


def status_line() -> str:
    """One line for ``lykos doctor``: where the run-in-place toolchain came from, if any."""
    prefix = toolchain_prefix()
    if prefix:
        return f"toolchain: run-in-place from {prefix} (nothing installed)"
    v = vendor_dir()
    if v:
        return f"toolchain: host PATH (vendor/ present at {v}, no toolchain/ tree)"
    return "toolchain: host PATH (no vendored toolchain)"
