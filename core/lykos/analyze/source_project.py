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


# The ANALYSIS build for the hypothesis loop (lykos hunt): what symbolic execution walks. No
# sanitizer (its instrumentation multiplies the paths angr must explore) and -O0 so DWARF maps every
# store to its line and every local to its stack slot; the sanitizer build above is its validator.
_PLAIN_FLAGS = ["-g", "-O0", "-fno-omit-frame-pointer", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0",
                "-D_GNU_SOURCE", "-w", "-Wno-error=implicit-function-declaration",
                "-Wno-error=implicit-int", "-Wno-error=int-conversion"]


def _which_cc():
    return (shutil.which("gcc") or shutil.which("clang"),
            shutil.which("g++") or shutil.which("clang++"))


def _defines_main(obj: str) -> bool:
    """True if the ELF object DEFINES `main` (a `T`/`t` text symbol, not an undefined `U`). Used to
    link a multi-program tree one executable per main() instead of colliding them all into one."""
    nm = shutil.which("nm")
    if not nm:
        return False
    try:
        out = subprocess.run([nm, obj], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in ("T", "t") and parts[2] == "main":
            return True
    return False


def _write_wrappers(bindir: Path, flag_list=None, trailing: str = ""):
    """A cc/c++ wrapper pair that appends `_SAN_FLAGS` to the real compiler. Putting them on PATH as
    `cc`/`gcc`/`clang` (and the C++ names) forces instrumentation through make/cmake/configure.

    `trailing` is appended AFTER the project's own arguments (`"$@"`), so a flag placed there WINS
    over whatever the project set -- used for the gnu89 retry wrapper, whose `-std=gnu89` must
    override a project `-std=` to clear the K&R conflicting-types hard errors that gcc 14+ makes
    fatal (`struct tm *gmtime(), *localtime();` vs. the modern prototypes -- Info-ZIP unzip 6.0)."""
    cc, cxx = _which_cc()
    if not cc or not cxx:
        return None
    flags = " ".join(_SAN_FLAGS if flag_list is None else flag_list)
    tail = (" " + trailing) if trailing else ""
    for names, real in ((("cc", "gcc", "clang"), cc), (("c++", "g++", "clang++"), cxx)):
        body = f'#!/bin/sh\nexec "{real}" {flags} "$@"{tail}\n'
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


_SALVAGE_MAX_OBJS = 4000              # bound the relocatable merge against a pathological tree


def _elf_objects(root: Path, since: float):
    """Newly-produced ELF RELOCATABLE objects (ET_REL `.o`) under `root` -- the instrumented output
    of every translation unit that COMPILED, even in a build that then failed at link. These are
    what partial-build salvage merges. CMake's compiler-probe objects (under CMakeFiles/) and
    autoconf's `conftest.o` are excluded -- they are build scaffolding, not the project's code."""
    out = []
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix not in (".o", ".obj") or _is_build_scaffold(p):
            continue
        if p.name.startswith("conftest"):
            continue
        try:
            if p.stat().st_mtime < since - 1:
                continue
            with open(p, "rb") as f:
                head = f.read(18)
        except OSError:
            continue
        if head[:4] == b"\x7fELF" and len(head) >= 18 and \
                int.from_bytes(head[16:18], "little" if head[5] == 1 else "big") == 1:  # ET_REL
            out.append(p)
    return sorted(out, key=lambda p: p.stat().st_size, reverse=True)


def _build_confinement(root: Path, *wrapdirs: Path) -> list:
    """bwrap prefix for running a project's build commands, or [] when bwrap is unusable (the
    build then runs unconfined, as before; the build log says so). Opt out with
    LYKOS_BUILD_UNCONFINED=1 for a project whose build legitimately needs to write elsewhere."""
    if os.environ.get("LYKOS_BUILD_UNCONFINED") == "1":
        return []
    try:
        from .dynamic import sandbox
        return sandbox.isolate_prefix(str(root), net=False,
                                      rw_binds=[str(root)] + [str(w) for w in wrapdirs],
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


def _defeat_maintainer_rules(root: Path) -> None:
    """Make an autotools tree's GENERATED files look newer than their sources, so `make` never
    tries to re-run aclocal / automake / autoconf -- none of which is installed on an air-gapped
    host. A released tarball ships `aclocal.m4`, `configure`, `config.h.in` and every `Makefile.in`
    pre-generated; whether `make` leaves them alone is purely an mtime question, and unpacking (or
    our own `git`/`cp` of the tree) does not preserve the shipped ordering. When a generated file
    looks older than a source it depends on, make fires the MAINTAINER rule to regenerate it and
    dies -- measured on libsndfile 1.0.28 AND giflib 5.1.4:

        make: *** [Makefile:587: aclocal.m4] Error 127   (aclocal-1.15: command not found)

    after which the project fell through to the loose builder and ingested wrong (libsndfile as a
    prebuilt binary with no source; giflib as a single library, so gif2rgb/giftool -- where its
    CVEs live -- were never analysed and recall collapsed 6 -> 0). Touching the generated files
    forward, in dependency order, is the standard "I have no maintainer tools" autotools
    workaround; it is a no-op on a tree that has none of these files (a plain Makefile / CMake
    project)."""
    import time as _time
    base = _time.time() + 1.0
    # oldest -> newest; each tier must end up newer than the tier(s) it is generated from.
    tiers = ({"aclocal.m4"},
             {"configure", "config.h.in"},
             {"Makefile.in"},
             {"config.status"},
             {"Makefile", "config.h", "stamp-h1"})
    for i, names in enumerate(tiers):
        ts = base + i
        for p in root.rglob("*"):
            if p.name in names and p.is_file():
                try:
                    os.utime(p, (ts, ts))
                except OSError:
                    pass


def build_source_project(root, *, timeout: int = 300, total: int | None = None,
                         sanitize: bool = True, opt: str | None = None) -> dict:
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
    flag_list = _SAN_FLAGS if sanitize else _PLAIN_FLAGS
    if opt:              # e.g. "-O0" for a validator build: -O1 can optimise the planted UB away
        flag_list = [opt if f.startswith("-O") else f for f in flag_list]
    san_ld = "-fsanitize=address,undefined" if sanitize else ""
    _write_wrappers(wrapdir, flag_list)
    # A second wrapper set whose `-std=gnu89` is appended AFTER the project's args, so it overrides
    # a project `-std=` and makes gcc accept pre-ANSI K&R code that gcc 14+ now rejects outright
    # (implicit int, implicit declarations, and the `struct tm *gmtime()` conflicting-types error in
    # Info-ZIP unzip 6.0's unxcfg.h). Used only as a LAST-RESORT retry when the normal build produced
    # no binary, so it can never regress a tree that already builds under the modern default.
    wrapdir89 = Path(tempfile.mkdtemp(prefix="lykos-ccwrap89-"))
    _write_wrappers(wrapdir89, flag_list, trailing="-std=gnu89")
    env = dict(os.environ)
    env["PATH"] = f"{wrapdir}:{env.get('PATH', '')}"
    env["CC"], env["CXX"] = "cc", "c++"                   # the wrappers, resolved via PATH
    flags = " ".join(flag_list)
    env["CFLAGS"] = (env.get("CFLAGS", "") + " " + flags).strip()
    env["CXXFLAGS"] = (env.get("CXXFLAGS", "") + " " + flags).strip()
    env["LDFLAGS"] = (env.get("LDFLAGS", "") + " " + san_ld).strip()
    # The gnu89 retry runs the wrapdir89 wrappers (PATH + explicit CC/CXX) and must NOT carry the
    # CFLAGS/CXXFLAGS overrides: those duplicate the sanitizer flags the wrappers already inject and,
    # more importantly, clobber a Makefile's own include/define flags (unzip's `-I.`).
    env89 = dict(env)
    env89["PATH"] = f"{wrapdir89}:{env.get('PATH', '')}"
    env89["CC"], env89["CXX"] = str(wrapdir89 / "cc"), str(wrapdir89 / "c++")
    env89.pop("CFLAGS", None)
    env89.pop("CXXFLAGS", None)

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
    confine = _build_confinement(root, wrapdir, wrapdir89)
    if confine:
        env["CCACHE_DISABLE"] = "1"      # a ccache'd compiler would fail writing ~/.ccache (ro)
        env89["CCACHE_DISABLE"] = "1"

    def _run(argv, cwd=root, run_env=None):
        slice_s = min(float(timeout), _left())
        if slice_s <= 1.0:
            return 1, f"{argv[0]}: skipped, the build budget is spent"
        return _run_group(confine + list(argv), cwd=cwd, env=run_env or env, timeout=slice_s)

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
        # Two failures have to be fixed AT ONCE here; `make -B` -- the old strategy -- could only
        # trade one for the other:
        #
        #   * an ALREADY-BUILT tree (a shipped tarball's binaries, or our own previous run's) must
        #     be REBUILT with our instrumentation, not reused. A plain `make` on it says "nothing
        #     to be done", the stale uninstrumented artifact is analysed, and nothing says so
        #     (test_a_prebuilt_tree_is_rebuilt_not_reused).
        #   * but `make -B` also forces autotools' MAINTAINER rules, so the tree tries to
        #     regenerate aclocal.m4 -> `aclocal` -> not installed here:
        #         make: *** [Makefile:587: aclocal.m4] Error 127
        #     measured on BOTH libsndfile 1.0.28 and giflib 5.1.4; each fell through to the loose
        #     builder and ingested wrong -- libsndfile as a prebuilt binary with no source (its
        #     libFuzzer stage said "no source" and ran at 359 exec/s), giflib as ONE library, so
        #     gif2rgb/giftool -- where its CVEs live -- were never analysed and recall went 6 -> 0.
        #
        # So fix both at the root: defeat the maintainer rules (make never reaches for aclocal),
        # `make clean` so the stale artifacts are gone, then a plain `make` that rebuilds every
        # program from source with our wrappers. Measured after this: giflib yields its 6 util
        # programs, libsndfile its 10 entry points -- deterministically, on a fresh OR an
        # already-built tree. `-B` stays only as a last-resort retry (a non-standard `clean`).
        _defeat_maintainer_rules(root)
        _run(["make", "clean"], cwd=root)              # best-effort; ignore a missing clean target
        rcm, o2 = _run(["make", "-j"], cwd=root)
        if rcm != 0 and not _elf_executables(root, start_make) \
                and not _elf_libraries(root, start_make):
            _, o2b = _run(["make", "-B", "-j"], cwd=root)
            o2 = o2 + "\n-- plain make produced nothing after clean; retried with -B --\n" + o2b
        return "autotools", o1 + o2

    def _b_make():
        # Drive the build through the PATH compiler-wrappers (they inject the sanitizer) and set
        # CC/CXX/LD as make variables so a Makefile that hard-codes a compiler path still goes
        # through the wrapper. Crucially, do NOT pass CFLAGS/CXXFLAGS as make overrides: a
        # command-line `CFLAGS=` wins over the Makefile's own, dropping the project's include/define
        # flags. unzip 6.0's `generic` target runs `configure` to write those flags (notably `-I.`),
        # and overriding CFLAGS produced `fatal error: unzip.h: No such file`. The sanitizer flags
        # the old override carried are already injected by the wrappers, so dropping it only helps.
        # `-B` forces the rebuild that makes our instrumentation real on an already-built tree.
        start_make = time.time()

        def _cc_vars(wd):
            return [f"CC={wd/'cc'}", f"CXX={wd/'c++'}", f"LD={wd/'cc'}"]

        def _made(since):
            # rc is NOT a reliable success signal: an old Makefile's default target is often a
            # help/usage message that succeeds (rc=0) while building nothing (unzip 6.0's first
            # rule is `help:`). Only a freshly-produced ELF counts.
            return _elf_executables(root, since) or _elf_libraries(root, since)

        # Each attempt is (label, extra-make-args, which-wrapper-env). `-B` forces the rebuild that
        # makes our instrumentation real on an already-built tree; a plain `make` is the retry for a
        # tree whose maintainer rules cannot run under `-B`. The default target may build nothing
        # (unzip's `help`), so the conventional aggregate targets `all`/`generic` are tried next
        # (`generic` is unzip's own autoconfigure-then-build). Finally, a pre-ANSI K&R tree gcc 14+
        # refuses outright (unzip's `gmtime` conflicting-types error) is retried through the gnu89
        # wrapper, whose `-std=gnu89` makes gcc accept the old declarations -- this is what builds
        # unzip 6.0 as an ASan binary so `zip_overflow` fires in-pipeline.
        # The make attempts carry NO CFLAGS/CXXFLAGS in the environment either: `make` imports
        # CFLAGS from the env, so an env `CFLAGS=<sanitizer flags>` clobbers a Makefile's own
        # include/define flags the same way a command-line override does (unzip's `-I.` -> "unzip.h:
        # No such file"). The wrappers inject the sanitizer, so the env flags are redundant here.
        env_mk = dict(env)
        env_mk.pop("CFLAGS", None)
        env_mk.pop("CXXFLAGS", None)
        modern = [("-B",      ["-B"],      env_mk),
                  ("plain",   [],          env_mk),
                  ("all",     ["all"],     env_mk),
                  ("generic", ["generic"], env_mk)]
        gnu89 = [("-B gnu89",      ["-B"],      env89),
                 ("all gnu89",     ["all"],     env89),
                 ("generic gnu89", ["generic"], env89)]

        def _try(attempts):
            nonlocal o
            for label, extra, e in attempts:
                s = time.time()
                wd = wrapdir89 if e is env89 else wrapdir
                _, ot = _run(["make", "-j"] + extra + _cc_vars(wd), run_env=e)
                o += f"\n-- make attempt [{label}] --\n" + ot
                if _made(s):
                    return "make", o
            return None

        o = ""
        done = _try(modern)
        if done:
            return done
        # Before the gnu89 retry, reset the autoconf-style state the modern attempts left behind.
        # unzip's `generic` writes a `flags` file from a `configure` PROBE; a probe run under the
        # modern compiler bakes in choices that defeat `-std=gnu89` (configure is not re-run while
        # `flags` is up to date), so the retry still hits the K&R error. Removing the probe outputs
        # (and the stale objects) makes `generic` re-probe under the gnu89 wrapper -- measured to
        # turn the retry from a 0.1s no-op back into unzip/unzipsfx/funzip.
        _run(["make", "clean"], run_env=env89)             # best-effort; may be a no-op echo
        for junk in ("flags", "config.cache", "config.status", "config.log"):
            try:
                (root / junk).unlink()
            except OSError:
                pass
        for obj in list(root.rglob("*.o")) + list(root.rglob("*.obj")):
            try:
                obj.unlink()
            except OSError:
                pass
        return _try(gnu89) or ("make", o)

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
        # Partition the objects by whether they DEFINE `main`. A tree with several programs ships
        # several main()s (Info-ZIP unzip: unzip/funzip/unzipsfx/unzipstb; bzip2: bzip2/
        # bzip2recover/spewG/unzcrash). Linking them all into one executable fails with "multiple
        # definition of `main`", which used to sink the whole tree to "did not build". Link each
        # main-object with all the NON-main objects into its OWN program instead, so every entry
        # point is produced and analysed.
        mains = [o for o in objs if _defines_main(o)]
        shared = [o for o in objs if o not in mains]
        made_any = False
        if len(mains) <= 1:
            out = root / "a.lykos.bin"
            _, l2 = _run([driver] + objs + ["-o", str(out)])
            log += l2
            made_any = out.exists()
        else:
            for m in mains:
                stem = Path(m).name.replace(".lykos.o", "") or "prog"
                out = root / f"a.lykos.{stem}.bin"
                _, l2 = _run([driver, m] + shared + ["-o", str(out)])
                log += l2
                made_any = made_any or out.exists()
            if made_any:
                log = f"-- linked {len(mains)} program(s) per-main (multiple main() in tree) --\n" + log
        if not made_any:
            # No main() (a LIBRARY) -> link a shared object instead, so a pure library still
            # ingests. Static detectors run on it and the libFuzzer stage builds a harness for
            # its exported functions from the retained source.
            so = root / "a.lykos.so"
            _, log2 = _run([driver, "-shared", "-fPIC"] + objs + ["-o", str(so)])
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

    def _b_salvage(since: float):
        """Last-resort PARTIAL-build salvage: a build can fail at LINK (a missing library) or on
        ONE translation unit while most of the tree compiled cleanly. Rather than discard all of
        that instrumented code, merge every ELF object that DID compile into one relocatable ELF
        with `ld -r` (via the real compiler driver). `-r` is an incremental link: it tolerates
        undefined symbols and non-PIC objects -- exactly the two things that make a normal
        `-shared`/executable link of a half-built tree fail -- so a tree that produced objects but
        no binary still yields a single analysable ELF. It is not runnable (ET_REL), so it is
        registered like a library: the binary static detectors, CVE fingerprinting and symbolic
        execution read it, reaching the code the failed link would have thrown away.

        Returns (path, n_objects) or None. Uses the REAL compiler (the objects are already
        instrumented; re-adding sanitizer flags at an `-r` merge only risks the merge)."""
        objs = _elf_objects(root, since)
        if not objs:
            return None
        objs = objs[:_SALVAGE_MAX_OBJS]
        out = root / "a.lykos-partial.o"
        rc, _ = _run([cc, "-r", "-nostdlib", "-o", str(out)] + [str(o) for o in objs])
        if rc == 0 and out.exists() and out.stat().st_size:
            return out, len(objs)
        return None

    overall_start = time.time()
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
        # No builder produced a binary. Before giving up to static-source only, salvage whatever
        # compiled: a single relocatable ELF of every object the failed build left behind, so the
        # binary/symbolic capability covers the compiled subset instead of nothing.
        salv = _b_salvage(overall_start) if _left() > 1.0 else None
        if salv:
            out, nobj = salv
            full_log += (f"\n== partial-build salvage: {system or 'build'} produced no binary; "
                         f"merged {nobj} compiled object(s) into {out.name} (ld -r) so binary and "
                         "symbolic analysis cover the compiled subset -- the rest is static-source "
                         "only ==\n")
            return {"ok": True, "system": "salvage", "kind": "library", "partial": True,
                    "salvaged_objects": nobj, "binaries": [out], "libraries": [out],
                    "primary": out, "compiler": Path(cc).name, "log": full_log[-4000:]}
        if not confine:
            full_log += ("\n== note: build ran UNCONFINED (bwrap unavailable) -- the project's "
                         "build scripts executed with this user's full privileges ==\n")
        return {"ok": False, "system": system, "kind": "executable", "binaries": [],
                "primary": None, "compiler": Path(cc).name, "log": full_log[-4000:]}
    finally:
        shutil.rmtree(wrapdir, ignore_errors=True)
        shutil.rmtree(wrapdir89, ignore_errors=True)
