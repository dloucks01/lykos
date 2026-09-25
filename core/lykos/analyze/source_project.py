"""Build a multi-file / build-system C/C++ SOURCE PROJECT into ASan+UBSan-instrumented binaries.

`ingest.compile_source` handles a single translation unit; real source is projects -- multiple
files, a Makefile, CMake, or autotools. This builds those the robust way: a compiler WRAPPER that
appends the sanitizer flags to whatever the project's own build invokes (like afl-cc), so
instrumentation lands no matter how the project sets CFLAGS. The produced executables then flow
through the normal pipeline exactly like a compiled single file -- every sanitizer catch is a
SIGABRT/trap the fuzzer confirms and root-causes to a source file:line, no CTF oracle needed.

Sanitizer abort is arranged at RUN time (the sandbox already sets ASAN_OPTIONS=abort_on_error=1)
and by `-fno-sanitize-recover=all` for UBSan, so no linked options TU is needed here.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

_C_EXT = {".c"}
_CXX_EXT = {".cc", ".cpp", ".cxx", ".c++", ".C"}
_SOURCE_EXT = _C_EXT | _CXX_EXT
_BUILD_FILES = ("compile_commands.json", "CMakeLists.txt", "configure", "configure.ac",
                "Makefile", "makefile", "GNUmakefile")

# The instrumentation the wrapper forces onto every compile/link. Mirrors ingest.compile_source:
# permissive (analyse, not ship), FORTIFY off so ASan reports with a file:line, frame pointers kept.
_SAN_FLAGS = ["-g", "-O1", "-fno-omit-frame-pointer", "-fsanitize=address,undefined",
              "-fno-sanitize-recover=all", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0",
              "-D_GNU_SOURCE", "-w", "-Wno-error=implicit-function-declaration",
              "-Wno-error=implicit-int", "-Wno-error=int-conversion"]


def is_source_project(root) -> bool:
    """True when a directory should be built from source rather than treated as a prebuilt-binary
    bundle: it carries a recognised build file, or holds C/C++ source and no obviously-prebuilt main
    ELF. (`ingest.gather_bundle` still handles the prebuilt-binary + loader/libc challenge case.)"""
    root = Path(root)
    if any((root / f).exists() for f in _BUILD_FILES):
        return True
    return any(p.suffix in _SOURCE_EXT for p in root.rglob("*") if p.is_file())


def _which_cc():
    return (shutil.which("gcc") or shutil.which("clang"),
            shutil.which("g++") or shutil.which("clang++"))


def _write_wrappers(bindir: Path):
    """A cc/c++ wrapper pair that appends `_SAN_FLAGS` to the real compiler. Putting them on PATH as
    `cc`/`gcc`/`clang` (and the C++ names) forces instrumentation through make/cmake/configure."""
    cc, cxx = _which_cc()
    if not cc or not cxx:
        return None
    flags = " ".join(_SAN_FLAGS)
    for names, real in ((("cc", "gcc", "clang"), cc), (("c++", "g++", "clang++"), cxx)):
        body = f'#!/bin/sh\nexec "{real}" {flags} "$@"\n'
        for n in names:
            w = bindir / n
            w.write_text(body)
            w.chmod(0o755)
    return cc, cxx


def _elf_executables(root: Path, since: float):
    """Newly-produced ELF executables under `root` (ET_EXEC, or ET_DYN with an interpreter -- a PIE
    program, not a plain shared library). Object files, archives and .so libraries are excluded."""
    out = []
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix in {".o", ".a", ".so", ".lo", ".la"} or ".so." in p.name:
            continue
        try:
            if p.stat().st_mtime < since - 1:
                continue
            with open(p, "rb") as f:
                head = f.read(20)
        except OSError:
            continue
        if head[:4] != b"\x7fELF" or len(head) < 18:
            continue
        e_type = int.from_bytes(head[16:18], "little" if head[5] == 1 else "big")
        if e_type == 2:                                   # ET_EXEC
            out.append(p)
        elif e_type == 3 and os.access(p, os.X_OK):       # ET_DYN + executable bit -> a PIE program
            out.append(p)
    return sorted(out, key=lambda p: p.stat().st_size, reverse=True)


def _elf_libraries(root: Path, since: float):
    """Newly-produced ELF shared objects (ET_DYN .so) -- the artifact a library-only source project
    (no main) links to. The sanitizer runtimes are excluded by name."""
    out = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        n = p.name
        if not (n.endswith(".so") or ".so." in n):
            continue
        if any(x in n for x in ("libasan", "libubsan", "liblsan", "libclang_rt")):
            continue
        try:
            if p.stat().st_mtime < since - 1:
                continue
            with open(p, "rb") as f:
                head = f.read(18)
        except OSError:
            continue
        if head[:4] == b"\x7fELF" and len(head) >= 18 and \
                int.from_bytes(head[16:18], "little" if head[5] == 1 else "big") == 3:
            out.append(p)
    return sorted(out, key=lambda p: p.stat().st_size, reverse=True)


def build_source_project(root, *, timeout: int = 300) -> dict:
    """Build the project rooted at `root` with sanitizers forced in. Returns
    {ok, system, binaries:[Path], primary:Path|None, compiler, log}. `binaries` is largest-first;
    `primary` is the biggest produced executable. `ok` is False (with the build log) when nothing
    executable came out."""
    root = Path(root).resolve()
    cc, cxx = _which_cc()
    if not cc:
        return {"ok": False, "system": None, "binaries": [], "primary": None,
                "compiler": None, "log": "no C/C++ compiler found (need gcc/clang)"}
    import tempfile
    import time
    wrapdir = Path(tempfile.mkdtemp(prefix="lykos-ccwrap-"))
    _write_wrappers(wrapdir)
    env = dict(os.environ)
    env["PATH"] = f"{wrapdir}:{env.get('PATH', '')}"
    env["CC"], env["CXX"] = "cc", "c++"                   # the wrappers, resolved via PATH
    flags = " ".join(_SAN_FLAGS)
    env["CFLAGS"] = (env.get("CFLAGS", "") + " " + flags).strip()
    env["CXXFLAGS"] = (env.get("CXXFLAGS", "") + " " + flags).strip()
    env["LDFLAGS"] = (env.get("LDFLAGS", "") + " -fsanitize=address,undefined").strip()
    start = time.time()

    def _run(argv, cwd=root):
        try:
            r = subprocess.run(argv, cwd=str(cwd), env=env, capture_output=True, text=True,
                               timeout=timeout)
            return r.returncode, (r.stdout or "") + (r.stderr or "")
        except (OSError, subprocess.SubprocessError) as e:
            return 1, f"{argv[0]}: {e}"

    log, system = "", None
    try:
        if (root / "compile_commands.json").exists() or (root / "CMakeLists.txt").exists():
            system = "cmake"
            bd = root / "_lykos_build"
            bd.mkdir(exist_ok=True)
            rc, o1 = _run(["cmake", "-S", str(root), "-B", str(bd),
                           f"-DCMAKE_C_COMPILER={wrapdir/'cc'}", f"-DCMAKE_CXX_COMPILER={wrapdir/'c++'}",
                           "-DCMAKE_BUILD_TYPE=Debug"], cwd=root)
            rc2, o2 = _run(["cmake", "--build", str(bd), "-j"], cwd=root)
            log = o1 + o2
        elif (root / "configure").exists():
            system = "autotools"
            rc, o1 = _run(["./configure"], cwd=root)
            rc2, o2 = _run(["make", "-j"], cwd=root)
            log = o1 + o2
        elif any((root / m).exists() for m in ("Makefile", "makefile", "GNUmakefile")):
            system = "make"
            # Pass the wrapped CC/flags as make VARIABLES too (override the Makefile's own).
            rc, log = _run(["make", "-j", f"CC={wrapdir/'cc'}", f"CXX={wrapdir/'c++'}",
                            f"CFLAGS={flags}", f"CXXFLAGS={flags}",
                            "LDFLAGS=-fsanitize=address,undefined"])
        else:
            system = "loose"
            srcs = sorted(str(p) for p in root.rglob("*") if p.suffix in _SOURCE_EXT)
            if not srcs:
                return {"ok": False, "system": "loose", "binaries": [], "primary": None,
                        "compiler": Path(cc).name, "log": "no C/C++ sources found"}
            driver = str(wrapdir / "c++") if any(Path(s).suffix in _CXX_EXT for s in srcs) \
                else str(wrapdir / "cc")
            out = root / "a.lykos.bin"
            rc, log = _run([driver] + srcs + ["-o", str(out)])
            if rc != 0 or not out.exists():
                # No main() (a LIBRARY) -> link a shared object instead, so a pure library still
                # ingests. Static detectors run on it and the libFuzzer stage builds a harness for
                # its exported functions from the retained source.
                so = root / "a.lykos.so"
                rc, log2 = _run([driver, "-shared", "-fPIC"] + srcs + ["-o", str(so)])
                log = log + "\n" + log2
                system = "loose-shared"
        bins = _elf_executables(root, start)
        kind = "executable"
        if not bins:                                     # a library build (shared object)
            bins = _elf_libraries(root, start)
            kind = "library"
        return {"ok": bool(bins), "system": system, "kind": kind, "binaries": bins,
                "primary": bins[0] if bins else None, "compiler": Path(cc).name, "log": log[-4000:]}
    finally:
        shutil.rmtree(wrapdir, ignore_errors=True)
