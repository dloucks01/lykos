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


def _project_root(root: Path) -> Path:
    """Descend through single wrapper directories before detecting the build system.

    A release tarball unpacks to one top dir (`jhead-3.04/`), so the Makefile/CMakeLists/configure
    lives one level down. Detecting the build system at the OUTER dir finds none of them and falls
    to the loose "compile every .c together" path, which fails for any real multi-file project --
    and ingest then reports "no analysable binary found in the bundle". Follow a chain of lone
    subdirectories (bounded) to the real root; stop as soon as a level has a build file or more than
    one meaningful entry."""
    cur = Path(root)
    for _ in range(8):                                    # bound against pathological nesting
        if any((cur / f).exists() for f in _BUILD_FILES):
            return cur
        entries = [p for p in cur.iterdir() if not p.name.startswith(".")]
        if len(entries) == 1 and entries[0].is_dir():
            cur = entries[0]
        else:
            return cur
    return cur


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


def _is_build_scaffold(p: Path) -> bool:
    """CMake writes compiler-probe binaries -- CMakeDetermineCompilerABI_C.bin, CompilerIdC/a.out --
    under `<build>/CMakeFiles/`, and they are LARGER than a tiny project binary, so picking the
    largest new executable selected CMake's own scaffolding instead of the target. Final targets
    never live under CMakeFiles/, so excluding that path component is safe."""
    return "CMakeFiles" in p.parts


def _elf_executables(root: Path, since: float):
    """Newly-produced ELF executables under `root` (ET_EXEC, or ET_DYN with an interpreter -- a PIE
    program, not a plain shared library). Object files, archives and .so libraries are excluded."""
    out = []
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix in {".o", ".a", ".so", ".lo", ".la"} or ".so." in p.name:
            continue
        if _is_build_scaffold(p):                         # skip CMake's compiler-probe binaries
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
        if not p.is_file() or _is_build_scaffold(p):
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


def _build_confinement(root: Path, wrapdir: Path) -> list:
    """bwrap prefix for running a project's build commands, or [] when bwrap is unusable (the
    build then runs unconfined, as before; the build log says so). Opt out with
    LYKOS_BUILD_UNCONFINED=1 for a project whose build legitimately needs to write elsewhere."""
    if os.environ.get("LYKOS_BUILD_UNCONFINED") == "1":
        return []
    try:
        from .dynamic import sandbox
        return sandbox.isolate_prefix(str(root), net=False, rw_binds=[str(root), str(wrapdir)],
                                      chdir=str(root))
    except Exception:                                     # noqa: BLE001 -- best-effort containment
        return []


def _run_group(argv, *, cwd, env, timeout: float):
    """(returncode, combined output) of one build command run in its OWN process group.

    `subprocess.run(timeout=)` kills only the direct child: a timed-out `make -j` left its cc1 /
    sub-make / configure-test grandchildren running, and anything a build script backgrounded
    kept the output pipe open so the call blocked until the timeout even after `make` exited.
    The whole group is killed on timeout AND after a normal exit (a build leaves no daemons)."""
    import signal
    try:
        proc = subprocess.Popen(argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                start_new_session=True)
    except OSError as e:
        return 1, f"{argv[0]}: {e}"

    def _killpg():
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    import time as _time
    timed_out = False
    out = b""
    deadline = _time.monotonic() + timeout
    exited_at = None
    try:
        while True:
            left = deadline - _time.monotonic()
            if left <= 0:
                timed_out = True
                break
            try:
                out, _ = proc.communicate(timeout=min(1.0, left))
                break
            except subprocess.TimeoutExpired:
                # the command itself finished but something it backgrounded still holds the
                # output pipe: give it a short grace, then reap the group instead of waiting out
                # the whole build budget on a daemon
                if proc.poll() is not None:
                    exited_at = exited_at or _time.monotonic()
                    if _time.monotonic() - exited_at > 2.0:
                        break
        if proc.stdout and not out:
            _killpg()
            try:
                out, _ = proc.communicate(timeout=10)
            except (subprocess.TimeoutExpired, ValueError):
                out = b""
    finally:
        _killpg()
        if proc.poll() is None:
            proc.kill()
        proc.wait()
    text = (out or b"").decode("utf-8", "replace")
    if timed_out:
        return 1, text + f"\n{argv[0]}: timed out after {timeout:.0f}s (process group killed)\n"
    return proc.returncode, text


def build_source_project(root, *, timeout: int = 300, total: int | None = None) -> dict:
    """Build the project rooted at `root` with sanitizers forced in. Returns
    {ok, system, binaries:[Path], primary:Path|None, compiler, log}. `binaries` is largest-first;
    `primary` is the biggest produced executable. `ok` is False (with the build log) when nothing
    executable came out."""
    root = _project_root(Path(root).resolve())            # descend a `project-1.2/` wrapper dir
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

    # A DEADLINE FOR THE WHOLE CHAIN, not just per command. `timeout` bounds one command, and the
    # chain is cmake -> autotools -> make -> loose with up to two commands each: a project that
    # ships several build systems can therefore spend 6 x 300s before the fallback, and that is
    # measured, not hypothetical. libsndfile 1.0.28 ships CMakeLists.txt AND configure AND a
    # Makefile; once the cmake policy retry made its cmake build start succeeding, the gate run
    # spent ~44 minutes inside ingest and printed no row at all for a 600-second case. The build
    # is not free time -- it comes out of the same budget the search needs.
    deadline = time.time() + float(total if total is not None else timeout * 3)

    def _left() -> float:
        return max(0.0, deadline - time.time())

    # A source project's Makefile / configure / CMakeLists is UNTRUSTED CODE that runs on this
    # host. Confine every build command when bwrap is usable: read-only root with the secret
    # dirs masked, no network, fresh /tmp, and only the project tree + the compiler-wrapper dir
    # writable -- so a hostile build can produce binaries in its own tree and nothing else.
    confine = _build_confinement(root, wrapdir)
    if confine:
        env["CCACHE_DISABLE"] = "1"      # a ccache'd compiler would fail writing ~/.ccache (ro)

    def _run(argv, cwd=root):
        slice_s = min(float(timeout), _left())
        if slice_s <= 1.0:
            return 1, f"{argv[0]}: skipped, the build budget is spent"
        return _run_group(confine + list(argv), cwd=cwd, env=env, timeout=slice_s)

    # STATIC libraries, for both builders. A shared build of a library project produces tools that
    # are unrunnable here for two independent reasons, measured on libtiff 4.0.3 and expat 2.1.0:
    #   * libtool puts the real ELF in `tools/.libs/` and leaves a SHELL WRAPPER at `tools/tiffcrop`
    #     that sets LD_LIBRARY_PATH. The pipeline analysed the wrapper (expat: 13,701 executions of
    #     a shell script, file_type "other", 0 findings);
    #   * the real ELF in `.libs/` has NO RPATH -- it NEEDS `libtiff.so.5` and nothing stages it, so
    #     the loader refuses it. The scorecard said `ran: false` and the orchestrator still spent
    #     34,059 executions on an image that never started.
    # Linking the tools statically against the project's own libs makes each tool one self-contained
    # instrumented ELF needing only host libraries (libasan/libz/libm), which is what the sanitizer
    # build is for. Verified on libtiff 4.0.3: `tools/tiffcrop` becomes a 7 MB ASan ELF that runs,
    # and so do tiffinfo/tiffcp/tiff2pdf/tiffdump/tiffmedian.
    # `-B` (always remake) on every make, because a source tree handed to us may ALREADY be
    # built -- which is the normal state of a tree someone has been working in. Without it:
    #
    #   * `make` has nothing to do, so it produces no file newer than the attempt, and
    #     `_elf_executables(root, since=start)` finds nothing. The builder is judged to have
    #     failed and the chain falls through to `loose`, which links every `main()` in the tree
    #     into one executable -- bzip2 ships four (bzip2.c, bzip2recover.c, spewG.c,
    #     unzcrash.c) -- and dies on "multiple definition of `main`". Measured on
    #     ~/Downloads/libs/bzip2-1.0.6: reported "source project did not build" for a project
    #     that builds in seconds.
    #
    #   * and the worse half: the existing binary was built with the PROJECT's flags, not ours.
    #     This whole path exists to force ASan+UBSan through the project's own build system, so
    #     reusing a stale artefact would quietly analyse an uninstrumented binary and report the
    #     absence of sanitizer findings as a result.
    #
    # The cost is a full rebuild of a tree that was already built, which is the right trade: the
    # instrumentation is the point.
    def _b_cmake():
        bd = root / "_lykos_build"
        bd.mkdir(exist_ok=True)
        conf = ["cmake", "-S", str(root), "-B", str(bd),
                f"-DCMAKE_C_COMPILER={wrapdir/'cc'}", f"-DCMAKE_CXX_COMPILER={wrapdir/'c++'}",
                "-DBUILD_SHARED_LIBS=OFF", "-DCMAKE_BUILD_TYPE=Debug"]
        rc, o1 = _run(conf, cwd=root)
        if rc != 0:
            # CMake 4 REMOVED compatibility with `cmake_minimum_required(VERSION <3.5)`, so every
            # pre-2016 project is refused outright on this host (cmake 4.3.4):
            #     Compatibility with CMake < 3.5 has been removed from CMake.
            #     Or, add -DCMAKE_POLICY_VERSION_MINIMUM=3.5 to try configuring anyway.
            # Measured on openjpeg 2.3.0, whose CMakeLists asks for 2.8: configure failed, the
            # builder fell through to `loose`, and that cannot link a tree full of cmake's own
            # feature-probe programs (each with its own main). Retried on the OUTCOME rather
            # than on the wording, the way the autotools builder retries `--disable-shared`.
            rc2, o_retry = _run(conf + ["-DCMAKE_POLICY_VERSION_MINIMUM=3.5"], cwd=root)
            o1 = o1 + "\n-- cmake refused the project's minimum version; retried with " \
                      "CMAKE_POLICY_VERSION_MINIMUM=3.5 --\n" + o_retry
            if rc2 != 0:
                return "cmake", o1
        _, o2 = _run(["cmake", "--build", str(bd), "-j", "--clean-first"], cwd=root)
        return "cmake", o1 + o2

    def _b_autotools():
        start_make = time.time()
        # `--disable-shared` is not a preference here, it is what makes the build RUNNABLE (above).
        # But `configure` is not always autoconf's: zlib's is hand-written and ABORTS on an option
        # it does not know ("unknown option: --disable-shared ... ./configure aborting"), leaving
        # no usable Makefile. The retry used to be gated on "command not found"/"No such file",
        # which that message does not contain, so the whole project fell through to the loose
        # builder and failed there -- zlib ingested as "source project did not build", a
        # regression introduced by adding the flag.
        #
        # So the retry is keyed on the OUTCOME, not on the wording of the complaint: if the first
        # configure did not succeed, run it with no options at all. Static linking is what we
        # want, not a requirement we can impose on every project's option vocabulary.
        rc, o1 = _run(["./configure", "--disable-shared"], cwd=root)
        if rc != 0:
            rc2, o_retry = _run(["./configure"], cwd=root)
            o1 = o1 + "\n-- configure rejected --disable-shared; retried without options --\n" \
                 + o_retry
            # zlib's own spelling for the same thing, tried only when the bare run also failed.
            if rc2 != 0:
                _, o3 = _run(["./configure", "--static"], cwd=root)
                o1 = o1 + "\n-- retried with --static --\n" + o3
        # `-B` FIRST, then a plain make as the retry -- in that order, because each fixes a
        # failure the other causes.
        #
        #   * `-B` is what makes an ALREADY-BUILT tree get rebuilt with our instrumentation.
        #     Without it make says "nothing to be done", the stale uninstrumented artifact is
        #     analysed, and nothing anywhere says so (test_a_prebuilt_tree_is_rebuilt_not_reused).
        #   * but `-B` also forces autotools' MAINTAINER rules, so a freshly unpacked release
        #     tarball tries to regenerate aclocal.m4 -> `aclocal` -> not installed here:
        #         make: *** [Makefile:484: aclocal.m4] Error 127
        #     and libsndfile 1.0.28 fell through to the `loose` builder, which cannot link a tree
        #     containing several programs with their own main(). It then ingested as a PREBUILT
        #     BINARY with no source, so its libFuzzer stage said "no source for this target" and
        #     the campaign ran at 359 exec/s instead of building in-process doors.
        #
        # So: force the rebuild, and if that leaves nothing, build the ordinary way. Measured
        # after the retry: libsndfile yields 10 entry points, primary `programs/sndfile-info`.
        rcm, o2 = _run(["make", "-B", "-j"], cwd=root)
        if rcm != 0 and not _elf_executables(root, start_make) \
                and not _elf_libraries(root, start_make):
            _, o2b = _run(["make", "-j"], cwd=root)
            o2 = o2 + "\n-- `make -B` failed and produced nothing (maintainer rules need tools "
            o2 = o2 + "this host lacks); retried without -B --\n" + o2b
        return "autotools", o1 + o2

    def _b_make():
        # Pass the wrapped CC/flags as make VARIABLES too (override the Makefile's own). Same
        # order as the autotools builder above and for the same measured reasons: `-B` forces
        # the rebuild that makes our instrumentation real, and a plain make is the retry for a
        # tree whose maintainer rules cannot run here.
        start_make = time.time()
        argv = ["make", "-j", f"CC={wrapdir/'cc'}", f"CXX={wrapdir/'c++'}",
                f"CFLAGS={flags}", f"CXXFLAGS={flags}",
                "LDFLAGS=-fsanitize=address,undefined"]
        rcm, o = _run(argv[:1] + ["-B"] + argv[1:])
        if rcm != 0 and not _elf_executables(root, start_make) \
                and not _elf_libraries(root, start_make):
            _, o2 = _run(argv)
            o = o + "\n-- `make -B` failed and produced nothing; retried without -B --\n" + o2
        return "make", o

    def _b_loose():
        srcs = sorted(str(p) for p in root.rglob("*") if p.suffix in _SOURCE_EXT)
        if not srcs:
            return "loose", "no C/C++ sources found"
        # Each file gets the driver for ITS OWN language. Picking one driver for the whole tree
        # meant a single stray C++ file sent every .c file through c++ -- and K&R parameter lists
        # (`void zcfree (opaque, ptr)`) are valid C89 and invalid C++, so zlib, whose tree carries
        # contrib/iostream*/zfstream.cc, failed to compile its own zutil.c:
        #     error: 'opaque' was not declared in this scope
        # That is this project's oldest build defect in a new place: the gate's header already
        # records "one .cxx file forcing a C project through clang++".
        cxx_present = any(Path(x).suffix in _CXX_EXT for x in srcs)
        objs, log = [], ""
        for src in srcs:
            drv = str(wrapdir / ("c++" if Path(src).suffix in _CXX_EXT else "cc"))
            obj = str(Path(src).with_suffix(".lykos.o"))
            # -fPIC always: the objects are compiled before we know whether this tree has a
            # main(), and a pure LIBRARY links as a shared object below. PIC costs nothing for
            # the executable link (PIE is the default anyway) and without it that fallback
            # failed -- which is how a library with no main stopped ingesting at all.
            rc, o = _run([drv, "-c", "-fPIC", src, "-o", obj])
            log += o
            if rc == 0 and Path(obj).exists():
                objs.append(obj)
        if not objs:
            return "loose", log or "no translation unit compiled"
        # Link with c++ when any C++ object is present, so libstdc++ comes along.
        driver = str(wrapdir / ("c++" if cxx_present else "cc"))
        srcs = objs                                      # the link steps below take the objects
        out = root / "a.lykos.bin"
        _, l2 = _run([driver] + srcs + ["-o", str(out)])
        log += l2
        if not out.exists():
            # No main() (a LIBRARY) -> link a shared object instead, so a pure library still
            # ingests. Static detectors run on it and the libFuzzer stage builds a harness for
            # its exported functions from the retained source.
            so = root / "a.lykos.so"
            _, log2 = _run([driver, "-shared", "-fPIC"] + srcs + ["-o", str(so)])
            log = log + "\n" + log2
        return "loose", log

    # Applicable builders in PREFERENCE order, each TRIED until one yields a binary -- a real
    # project often ships more than one (zlib carries CMakeLists.txt AND a configure/Makefile), and
    # the preferred one can fail for reasons unrelated to the code: modern CMake 4.x rejects an old
    # `cmake_minimum_required(VERSION <3.5)`, so committing to cmake alone gave up on a project that
    # builds fine via ./configure. `loose` (compile the sources directly) is always the last resort.
    builders = []
    if (root / "compile_commands.json").exists() or (root / "CMakeLists.txt").exists():
        builders.append(_b_cmake)
    if (root / "configure").exists():
        builders.append(_b_autotools)
    if any((root / m).exists() for m in ("Makefile", "makefile", "GNUmakefile")):
        builders.append(_b_make)
    builders.append(_b_loose)

    full_log, system = "", None
    try:
        for build in builders:
            if _left() <= 1.0:
                full_log += "\n== build budget spent; remaining builders not attempted ==\n"
                break
            start = time.time()                          # attribute binaries to THIS builder only
            system, log = build()
            full_log += f"\n== {system} ==\n{log}"
            bins = _elf_executables(root, start)
            kind = "executable"
            libs = []
            if not bins:                                 # a library build (shared object)
                bins = _elf_libraries(root, start)
                kind = "library"
            else:
                # A large project's real code often lives in its shared libraries, not only in the
                # thin executables and in-tree fuzz harnesses. Surface the built .so's ALONGSIDE the
                # executables: they are not runnable as programs, but
                # the binary static detectors, CVE fingerprinting and symbolic execution all read a
                # .so, so registering them widens coverage past the entry-point executables.
                libs = _elf_libraries(root, start)
            if bins:
                return {"ok": True, "system": system, "kind": kind, "binaries": bins,
                        "libraries": libs, "primary": bins[0], "compiler": Path(cc).name,
                        "log": full_log[-4000:]}
        if not confine:
            full_log += ("\n== note: build ran UNCONFINED (bwrap unavailable) -- the project's "
                         "build scripts executed with this user's full privileges ==\n")
        return {"ok": False, "system": system, "kind": "executable", "binaries": [],
                "primary": None, "compiler": Path(cc).name, "log": full_log[-4000:]}
    finally:
        shutil.rmtree(wrapdir, ignore_errors=True)
