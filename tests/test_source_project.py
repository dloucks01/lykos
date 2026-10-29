"""Multi-file / build-system source PROJECTS: lykos builds them with ASan+UBSan (via a compiler
wrapper that forces instrumentation through the project's own build) and analyses the produced
binary, so real source -- not just a single .c -- gets sanitizer-diagnosed findings with a source
file:line and no CTF oracle."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.analyze.source_project import build_source_project, is_source_project
from lykos.db.dao import ArtifactDAO, TargetDAO


@pytest.fixture
def gcc_or_skip():
    if not (sandbox.host_arch() == "x86-64"):
        pytest.skip("native x86-64 only")
    import shutil
    if not (shutil.which("gcc") or shutil.which("clang")):
        pytest.skip("no C compiler")


def _make_project(d):
    (d / "dup.c").write_text("#include <stdlib.h>\n#include <string.h>\n"
                             "char* dup_line(const char*s){char*b=malloc(8); strcpy(b,s); return b;}\n")
    (d / "main.c").write_text("#include <stdio.h>\nchar* dup_line(const char*);\n"
                              "int main(int c,char**v){ char*d=dup_line(c>1?v[1]:\"x\");"
                              " printf(\"%s\",d); return 0; }\n")
    (d / "Makefile").write_text("app: main.c dup.c\n\t$(CC) $(CFLAGS) main.c dup.c -o app $(LDFLAGS)\n")


def test_is_source_project(tmp_path):
    _make_project(tmp_path)
    assert is_source_project(tmp_path)
    empty = tmp_path / "sub"; empty.mkdir()
    assert not is_source_project(empty)                   # no build file, no sources


def test_build_make_project_is_instrumented(tmp_path, gcc_or_skip):
    _make_project(tmp_path)
    r = build_source_project(tmp_path)
    assert r["ok"] and r["system"] == "make" and r["primary"], r["log"][-400:]
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "abort_on_error=1:halt_on_error=1:detect_leaks=0"
    p = subprocess.run([str(r["primary"]), "A" * 64], capture_output=True, env=env, timeout=10)
    assert p.returncode == -6                              # SIGABRT from the sanitizer
    assert b"heap-buffer-overflow" in p.stderr             # ASan classified it


def _fake_elf_exec(path: Path, size: int):
    """Minimal ET_EXEC ELF header + padding, as a stand-in binary for selection-logic tests."""
    path.parent.mkdir(parents=True, exist_ok=True)
    hdr = b"\x7fELF" + b"\x02\x01" + bytes(10) + b"\x02\x00"   # 64-bit LE, e_type=ET_EXEC
    path.write_bytes(hdr + b"\x00" * max(0, size - len(hdr)))


def test_elf_executables_skips_cmake_scaffolding(tmp_path):
    # CMake drops compiler-probe binaries under <build>/CMakeFiles/ that are LARGER than a tiny
    # target, so "largest new executable" picked CMake's own scaffolding instead of the program.
    from lykos.analyze.source_project import _elf_executables
    bd = tmp_path / "_lykos_build"
    _fake_elf_exec(bd / "CMakeFiles" / "4.3.4" / "CMakeDetermineCompilerABI_C.bin", 40000)
    _fake_elf_exec(bd / "CMakeFiles" / "4.3.4" / "CompilerIdC" / "a.out", 38000)
    _fake_elf_exec(bd / "tokbuf", 30000)                      # the real, smaller target
    found = _elf_executables(tmp_path, since=0)
    assert [p.name for p in found] == ["tokbuf"], found


def test_build_cmake_project_selects_target_binary(tmp_path, gcc_or_skip):
    # End-to-end CMake build: the produced "primary" must be the project's target, not a CMake probe.
    import shutil
    if not shutil.which("cmake"):
        pytest.skip("cmake not installed")
    (tmp_path / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.5)\nproject(tokbuf C)\n"
        "add_executable(tokbuf main.c)\n")
    (tmp_path / "main.c").write_text("#include <string.h>\n"
                                     "int main(int c,char**v){char b[8];if(c>1)strcpy(b,v[1]);return b[0];}\n")
    r = build_source_project(tmp_path)
    assert r["ok"] and r["system"] == "cmake", r["log"][-400:]
    assert r["primary"].name == "tokbuf", f"selected {r['primary']} instead of the target"
    assert "CMakeFiles" not in r["primary"].parts


def test_build_falls_back_when_preferred_system_fails(tmp_path, gcc_or_skip):
    # A real project often ships several build systems (zlib: CMakeLists.txt AND configure/Makefile).
    # The preferred one can fail for reasons unrelated to the code -- modern CMake 4.x rejects an old
    # `cmake_minimum_required(VERSION <3.5)`. Committing to cmake alone then gave up on a project that
    # builds fine via make. The builder must fall through to the next system.
    import shutil
    if not shutil.which("cmake"):
        pytest.skip("cmake not installed")
    (tmp_path / "CMakeLists.txt").write_text(      # fails configure: demands an impossible version
        "cmake_minimum_required(VERSION 99.0)\nproject(app C)\nadd_executable(app m.c)\n")
    (tmp_path / "m.c").write_text("int main(){return 0;}\n")
    (tmp_path / "Makefile").write_text("app: m.c\n\t$(CC) $(CFLAGS) m.c -o app $(LDFLAGS)\n")
    r = build_source_project(tmp_path)
    assert r["ok"], r["log"][-500:]
    assert r["system"] == "make", f"did not fall back to make (system={r['system']})"
    assert r["primary"] and r["primary"].name == "app"


def test_build_descends_wrapper_dir(tmp_path, gcc_or_skip):
    # A release tarball unpacks to a single `project-1.2/` dir with the Makefile INSIDE it. The
    # build system was detected at the outer dir, found no Makefile, fell to the loose path and
    # failed -- so ingest reported "no analysable binary". Build must descend to the real root.
    from lykos.analyze.source_project import _project_root
    wrapper = tmp_path / "myproj-1.2"
    wrapper.mkdir()
    _make_project(wrapper)
    assert _project_root(tmp_path) == wrapper              # descended past the lone wrapper
    r = build_source_project(tmp_path)
    assert r["ok"] and r["system"] == "make" and r["primary"], r["log"][-400:]


def test_build_loose_multifile(tmp_path, gcc_or_skip):
    # no build file, two source files -> compiled together with sanitizers
    (tmp_path / "a.c").write_text("int helper(int x){ return x + 1; }\n")
    (tmp_path / "b.c").write_text("int helper(int); int main(){ return helper(0); }\n")
    r = build_source_project(tmp_path)
    assert r["ok"] and r["system"] == "loose" and r["primary"]


def test_ingest_source_project(store, case, gcc_or_skip):
    import tempfile
    from pathlib import Path
    d = Path(tempfile.mkdtemp())
    _make_project(d)
    register()
    t = ingest(store, case.id, d, filename="myproj")
    assert t and t.sha256
    got = TargetDAO(store.conn).get(t.id)
    assert got is not None
    arts = [a for a in ArtifactDAO(store.conn).list_by_case(case.id) if a.kind == "source-project"]
    assert arts, "the source tree should be archived for the code view + provenance"
    assert arts[0].meta.get("build_system") == "make"


def test_ingest_source_from_mismatched_ondisk_name(store, case, gcc_or_skip):
    """The HTTP upload path streams the body to a temp file named `body.bin` and carries the real
    name only in `filename`. gcc/clang pick how to treat an input file from its ON-DISK extension,
    so `body.bin` was handed to the linker ("file format not recognized; treating as linker
    script") and never compiled. Every prior source test passed a correctly-named `.c`/`.cpp` path,
    so none covered this. compile_source now pins the language with `-x`; this reproduces the upload
    path by giving ingest a wrong-extension file plus a source `filename`."""
    import tempfile
    from pathlib import Path

    from lykos.analyze.ingest import ingest
    blob = Path(tempfile.mkdtemp()) / "body.bin"            # the on-disk name the HTTP path uses
    blob.write_text("#include <string.h>\nint main(int c,char**v){char b[8];"
                    " if(c>1)strcpy(b,v[1]); return b[0]; }\n")
    t = ingest(store, case.id, blob, filename="overflow.c")  # real name says C
    assert t and t.sha256, "source with a non-source on-disk name failed to compile+ingest"
    arts = [a for a in ArtifactDAO(store.conn).list_by_case(case.id) if a.kind == "source-code"]
    assert arts and arts[0].meta.get("filename") == "overflow.c"


def test_failed_source_build_surfaces_reason_not_bundle_error(store, case, monkeypatch):
    """A source project that fails to build (e.g. cmake/make not installed) must report WHY. The
    code falls through to the prebuilt-binary bundle path, which found no ELF and raised the generic
    "no analysable binary found in the bundle" -- hiding the actual cause (a missing build tool).
    ingest now carries the build log into the error when the input was recognised as source."""
    import tempfile
    from pathlib import Path

    from lykos.analyze import source_project
    from lykos.analyze.ingest import (  # submodule attrs (package re-exports the func)
        NotAnalysable,
        ingest,
    )
    d = Path(tempfile.mkdtemp())
    (d / "proj").mkdir()
    (d / "proj" / "m.c").write_text("int main(){return 0;}\n")      # recognised as source, no ELF
    monkeypatch.setattr(source_project, "build_source_project",
                        lambda p, **k: {"ok": False, "system": "cmake", "primary": None,
                                        "binaries": [], "compiler": "gcc",
                                        "log": "cmake: No such file or directory"})
    with pytest.raises(NotAnalysable, match=r"(?s)did not build.*cmake"):
        ingest(store, case.id, d, filename="proj.tar.gz")


def test_static_detect_runs_on_instrumented_source_binary(store, case, gcc_or_skip):
    """A source file compiles to an ASan+UBSan (PIE) binary whose huge runtime used to make
    _program_only mis-attribute the base and drop the program's own code -- blinding every static
    detector (zero findings). The entry-point consistency guard now keeps analysis running, so a
    source target gets static SAST (here a corroborated CWE-22) in ADDITION to dynamic sanitizer
    findings."""
    import tempfile
    from pathlib import Path

    from lykos.analyze.detect import enqueue_detect
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    register()
    src = Path(tempfile.mkdtemp()) / "t.c"
    src.write_text("#include <stdio.h>\nint main(int c,char**v){ if(c<2)return 0;"
                   " FILE*f=fopen(v[1],\"r\"); if(f)fclose(f); return 0; }\n")
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, case.id, src, filename="t.c")   # source -> ASan-instrumented binary
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True); assert pool.wait_idle(40)
        enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
        enqueue_detect(q, t, force=True); assert pool.wait_idle(90)
        rows = store.conn.execute("SELECT cwe,state FROM finding WHERE target_id=?", (t.id,)).fetchall()
        assert rows, "instrumented source binary produced zero static findings (regression)"
        assert any(cwe == "CWE-22" and state == "corroborated" for cwe, state in rows), rows
    finally:
        pool.stop(grace=3.0)


def test_library_source_builds_shared_object(tmp_path, gcc_or_skip):
    # a pure library (no main) links to a shared object instead of failing, so it still ingests
    (tmp_path / "lib.c").write_text("#include <string.h>\n"
                                    "void parse_record(char*s){ char t[16]; strcpy(t,s); }\n")
    r = build_source_project(tmp_path)
    assert r["ok"] and r["kind"] == "library" and r["primary"].name.endswith(".so"), r["log"][-300:]


_KR_C = """#include <stdio.h>
int helper(int);
int kr_style(a, b)
    int a; int b;                 /* K&R parameter list: valid C89, rejected by C++ */
{ return a + b; }
int main(void){ printf("%d\\n", kr_style(2,3) + helper(1)); return 0; }
"""
_CXX_HELPER = 'extern "C" int helper(int x) { return x * 10; }\n'


def test_each_source_is_compiled_with_the_driver_for_its_own_language(tmp_path, gcc_or_skip):
    """The loose builder picked ONE driver for the whole tree -- c++ if any source had a C++
    extension -- so a single stray .cc file sent every .c file through c++. K&R parameter lists
    are valid C89 and invalid C++, and zlib's tree carries contrib/iostream*/zfstream.cc, so the
    build failed on zlib's own zutil.c:

        error: 'opaque' was not declared in this scope
          315 | void ZLIB_INTERNAL zcfree (opaque, ptr)

    The gate's header already records this defect class in another place: "one .cxx file forcing
    a C project through clang++"."""
    (tmp_path / "main.c").write_text(_KR_C)
    (tmp_path / "extra.cc").write_text(_CXX_HELPER)
    built = build_source_project(tmp_path)
    assert built.get("system") == "loose"
    exe = built["primary"]
    assert os.path.exists(exe)
    # and the LINK used c++, or the C++ translation unit's runtime would be missing
    r = subprocess.run([exe], capture_output=True, text=True, timeout=30)
    assert r.stdout.strip() == "15", (r.returncode, r.stdout, r.stderr[-200:])


def test_a_configure_that_rejects_our_option_is_retried_without_it(tmp_path, gcc_or_skip):
    """`configure` is not always autoconf's. zlib's is hand-written and ABORTS on an option it
    does not know -- "unknown option: --disable-shared ... ./configure aborting" -- leaving no
    usable Makefile, so the project fell through to the loose builder and failed there. zlib
    ingested as "source project did not build".

    The retry was gated on "command not found"/"No such file", which that message does not
    contain, so it never fired. Keying it on the OUTCOME instead works for any project's option
    vocabulary."""
    (tmp_path / "configure").write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do\n'
        '  case "$a" in --disable-shared)\n'
        '    echo "unknown option: $a"; echo "aborting"; exit 1;; esac\n'
        "done\n"
        "printf 'all:\\n\\t$(CC) main.c -o built.bin\\n' > Makefile\n")
    (tmp_path / "configure").chmod(0o755)
    (tmp_path / "main.c").write_text("int main(void){return 0;}\n")
    built = build_source_project(tmp_path)
    assert built.get("system") == "autotools", built.get("system")
    assert os.path.basename(built["primary"]) == "built.bin"
    log = built.get("log") or ""
    assert "retried without options" in log, "the retry is invisible in the build log"


# ---------------------------------------------------------------- an ALREADY-BUILT source tree
# The normal state of a tree someone has been working in, and it defeated the whole path. `make`
# had nothing to do, so no file was newer than the attempt, `_elf_executables(root, since=start)`
# found none, the builder was judged to have failed, and the chain fell through to `loose` --
# which links every `main()` in the tree into one executable. bzip2 ships four (bzip2.c,
# bzip2recover.c, spewG.c, unzcrash.c), so it died on "multiple definition of `main`" and the
# tool reported "source project did not build" for a project that builds in seconds.
#
# The worse half is quieter: had detection found the stale binary, it was built with the
# PROJECT's flags. This path exists to force ASan+UBSan through the project's own build system,
# so reusing that artefact would analyse an uninstrumented binary and report the absence of
# sanitizer findings as a result.


def test_every_builder_forces_a_rebuild():
    """`-B` / `--clean-first` on every builder. A source-level guard because reproducing this
    needs a tree that is already built, which a fixture would have to build first -- and the
    build is the slow part."""
    import inspect

    from lykos.analyze import source_project
    src = inspect.getsource(source_project.build_source_project)
    assert '["make", "-B", "-j"]' in src, "the autotools builder does not force a rebuild"
    # The make builder assembles its argv (it has a CC/CFLAGS override to pass) and inserts -B
    # ahead of it, so the forced rebuild is this splice rather than a literal command line. The
    # spelling changed when a plain-make RETRY was added for trees whose maintainer rules cannot
    # run here; the guarantee this test exists for did not.
    assert 'argv[:1] + ["-B"] + argv[1:]' in src, \
        "the make builder does not force a rebuild"
    assert 'f"CC={wrapdir' in src, "the make builder does not override the compiler"
    assert '"--clean-first"' in src, "the cmake builder does not force a rebuild"


def test_a_prebuilt_tree_is_rebuilt_not_reused(tmp_path, gcc_or_skip):
    """The behaviour, on a tiny project that mimics the shape: a Makefile, several `main`s, and
    an artefact already in place with a newer mtime than its sources."""
    import os
    import time

    from lykos.analyze.source_project import build_source_project
    root = tmp_path / "proj"
    root.mkdir()
    (root / "tool.c").write_text(
        "#include <stdio.h>\n#include <string.h>\n"
        "int main(int c, char**v){char b[8]; if(c>1) strcpy(b,v[1]);"
        " printf(\"%s\\n\", b); return 0;}\n")
    # a SECOND main, which is what makes the loose fallback impossible
    (root / "helper.c").write_text("int main(void){return 0;}\n")
    (root / "Makefile").write_text(
        "all: tool helper\ntool: tool.c\n\t$(CC) $(CFLAGS) tool.c -o tool\n"
        "helper: helper.c\n\t$(CC) $(CFLAGS) helper.c -o helper\n")
    # pre-build it with the PROJECT's flags (no sanitizer), and make the artefacts newest
    os.system(f"cd {root} && make >/dev/null 2>&1")
    assert (root / "tool").exists(), "the fixture did not pre-build"
    plain = (root / "tool").stat().st_size
    time.sleep(0.05)
    os.utime(root / "tool", None)
    os.utime(root / "helper", None)

    r = build_source_project(root) or {}
    assert r.get("ok"), f"an already-built tree did not build: {(r.get('log') or '')[-400:]}"
    assert r.get("system") == "make", \
        f"fell through to {r.get('system')!r} instead of using the project's Makefile"
    exe = Path(r["primary"])
    # the instrumented binary is substantially larger than the project's own
    assert exe.stat().st_size > plain, \
        "the artefact was reused rather than rebuilt with our instrumentation"
    out = subprocess.run(["nm", "-D", str(exe)], capture_output=True, text=True).stdout.lower()
    dyn = subprocess.run(["readelf", "-d", str(exe)], capture_output=True, text=True).stdout.lower()
    assert "asan" in out or "asan" in dyn, "the rebuilt binary carries no ASan"

# ----------------------------------------------- what stopped two real libraries from building
def test_a_plain_make_is_the_retry_when_B_cannot_run():
    """`-B` first (it is what makes an already-built tree rebuild with our instrumentation), and
    a plain make as the RETRY when it fails having produced nothing.

    Measured on libsndfile 1.0.28: `./configure` succeeded, then `make -B -j` forced autotools'
    maintainer rules and died with

        make: *** [Makefile:484: aclocal.m4] Error 127

    because `aclocal` is not installed here. The project fell through to the `loose` builder,
    which cannot link a tree containing several programs with their own main(), so libsndfile
    ingested as a PREBUILT BINARY with no source -- which is why its libFuzzer stage reported
    "no source for this target" and the campaign ran at 359 exec/s through the black-box path
    instead of building in-process doors. With the retry: 10 entry points, primary
    `programs/sndfile-info`, an 8 MB ASan ELF.

    The order matters in both directions, which is why both tests exist: reversing it (plain
    make first) makes `test_a_prebuilt_tree_is_rebuilt_not_reused` fail, because make then says
    "nothing to be done" and the stale uninstrumented artifact is analysed instead.
    """
    import inspect

    from lykos.analyze import source_project as sp
    src = inspect.getsource(sp.build_source_project)
    first = src.index('_run(["make", "-B", "-j"], cwd=root)')
    retry = src.index('_run(["make", "-j"], cwd=root)')
    assert first < retry, "-B has to be attempted first; a plain make is the fallback"
    assert 'if rcm != 0 and not _elf_executables(root, start_make)' in src, \
        "the retry must be gated on -B having FAILED and produced nothing"


def test_cmake_retries_past_a_removed_minimum_version():
    """CMake 4 removed compatibility with `cmake_minimum_required(VERSION <3.5)`.

    Measured on openjpeg 2.3.0 (asks for 2.8) with cmake 4.3.4:

        CMake Error: Compatibility with CMake < 3.5 has been removed from CMake.
        Or, add -DCMAKE_POLICY_VERSION_MINIMUM=3.5 to try configuring anyway.

    configure failed, the builder fell through to `loose`, and that cannot link a tree full of
    cmake's own feature-probe programs. With the retry: 3 entry points -- opj_compress,
    opj_dump, opj_decompress -- which is the whole reason this library is in the corpus. Every
    pre-2016 cmake project on a modern host hits this, so it is not one library's quirk.
    """
    import inspect

    from lykos.analyze import source_project as sp
    src = inspect.getsource(sp.build_source_project)
    assert "CMAKE_POLICY_VERSION_MINIMUM=3.5" in src
    # keyed on the OUTCOME, not on the wording of cmake's complaint
    assert "if rc != 0:" in src.split("def _b_cmake")[1].split("def _b_autotools")[0]


def test_the_builder_chain_has_a_deadline(tmp_path):
    """The build comes out of the same budget the search needs.

    `timeout` bounds ONE command, and the chain is cmake -> autotools -> make -> loose with up
    to two commands each: a project shipping several build systems can spend 6 x 300s before the
    fallback. Measured, not hypothetical -- libsndfile 1.0.28 ships CMakeLists.txt AND configure
    AND a Makefile, and once the cmake policy retry made its cmake build start succeeding, a
    600-second gate case spent ~44 minutes inside ingest and printed no row at all.
    """
    import time

    from lykos.analyze.source_project import build_source_project
    # a tree that looks like a project and cannot build: every builder is attempted
    (tmp_path / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 2.6)\n"
                                             "project(x C)\nadd_executable(x nope.c)\n")
    (tmp_path / "configure").write_text("#!/bin/sh\nexit 1\n")
    (tmp_path / "configure").chmod(0o755)
    (tmp_path / "Makefile").write_text("all:\n\t@false\n")
    (tmp_path / "a.c").write_text("int main(void){return 0;}\n")
    t0 = time.time()
    r = build_source_project(tmp_path, timeout=5, total=8)
    elapsed = time.time() - t0
    assert elapsed < 40, f"the chain ignored its deadline ({elapsed:.0f}s for an 8s budget)"
    # and it says so rather than reporting a plain failure
    if not r["ok"]:
        assert "budget" in (r.get("log") or "") or r["system"] is not None


def test_executable_build_also_surfaces_shared_libraries():
    """When a project build produces executables, the built shared libraries are surfaced TOO
    (a 'libraries' key), so the bulk of a project's code (its .so, not the thin executables) is
    reachable as targets -- not only the fallback library-only build."""
    import inspect

    from lykos.analyze import source_project
    src = inspect.getsource(source_project.build_source_project)
    assert "_elf_libraries(root, start)" in src and '"libraries"' in src


def test_ingest_registers_built_shared_libraries_as_targets(store, case, tmp_path):
    """_ingest_built_project registers the built .so libraries as case targets (deduped by sha),
    alongside the primary executable -- so a project's libraries (where the bulk of the code is)
    become analysable, not just the thin executables and harnesses."""
    from lykos.analyze.ingest import _ingest_built_project
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.c").write_text("int f(void){return 0;}\n")

    def _mk(name, kind_byte, filler):
        p = root / name
        p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + kind_byte + b"\x00" + filler)
        return p

    exe = _mk("app", b"\x02", b"X" * 300)             # ET_EXEC
    lib1 = _mk("libcore.so", b"\x03", b"Y" * 500)
    lib2 = _mk("libutil.so", b"\x03", b"Z" * 400)
    built = {"ok": True, "system": "cmake", "kind": "executable", "compiler": "clang",
             "primary": exe, "binaries": [exe], "libraries": [lib1, lib2], "lib_dirs": []}
    _ingest_built_project(store, case.id, root, built, "proj")
    names = {t.filename for t in store.targets.list_by_case(case.id)}
    assert "proj" in names                                   # the primary (named by the ingest name)
    assert "libcore.so" in names and "libutil.so" in names, names


def test_partial_build_salvages_compiled_objects(tmp_path, gcc_or_skip):
    """A build that COMPILES objects but then fails (a missing link library, or a unit that only
    the project's own build can compile) must not lose everything: the compiled objects are merged
    into one relocatable ELF so binary/symbolic analysis covers the compiled subset. The loose
    builder cannot recompile these raw (they need -DNEEDED), so salvage is what recovers them."""
    # foo.c compiles ONLY with -DNEEDED (which only the Makefile rule passes); the link then fails
    # on a library that does not exist -> objects exist, no binary, loose cannot rebuild them.
    (tmp_path / "foo.c").write_text(
        "#ifndef NEEDED\n#error needs NEEDED\n#endif\n"
        "int helper(int x){ return x + 1; }\n")
    (tmp_path / "Makefile").write_text(
        "all: prog\n"
        "foo.o: foo.c\n\t$(CC) -DNEEDED $(CFLAGS) -c foo.c -o foo.o\n"
        "prog: foo.o\n\t$(CC) foo.o -o prog $(LDFLAGS) -lxyz_definitely_missing_zzz\n")
    built = build_source_project(tmp_path, timeout=120, total=180)
    assert built["ok"] is True and built.get("partial") is True
    assert built["system"] == "salvage" and built["salvaged_objects"] >= 1
    prim = Path(built["primary"])
    assert prim.exists() and prim.stat().st_size > 0
    with open(prim, "rb") as f:
        head = f.read(18)
    assert head[:4] == b"\x7fELF"
    et = int.from_bytes(head[16:18], "little" if head[5] == 1 else "big")
    assert et == 1                                        # ET_REL -- a merged relocatable object
    assert "partial-build salvage" in built["log"]


def test_elf_objects_finds_relocatables_and_skips_scaffold(tmp_path, gcc_or_skip):
    import shutil
    import time as _t

    from lykos.analyze.source_project import _elf_objects
    cc = shutil.which("gcc") or shutil.which("clang")
    (tmp_path / "a.c").write_text("int f(void){return 3;}\n")
    since = _t.time()
    subprocess.run([cc, "-c", str(tmp_path / "a.c"), "-o", str(tmp_path / "a.o")], check=True)
    # autoconf scaffolding and CMake probe objects must NOT be salvaged
    (tmp_path / "conftest.o").write_bytes((tmp_path / "a.o").read_bytes())
    cmf = tmp_path / "CMakeFiles"; cmf.mkdir()
    (cmf / "probe.o").write_bytes((tmp_path / "a.o").read_bytes())
    found = {p.name for p in _elf_objects(tmp_path, since)}
    assert "a.o" in found
    assert "conftest.o" not in found and "probe.o" not in found
