"""Multi-file / build-system source PROJECTS: lykos builds them with ASan+UBSan (via a compiler
wrapper that forces instrumentation through the project's own build) and analyses the produced
binary, so real source -- not just a single .c -- gets sanitizer-diagnosed findings with a source
file:line and no CTF oracle."""
from __future__ import annotations

import os
import subprocess

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
    from lykos.analyze.ingest import NotAnalysable, ingest   # submodule attrs (package re-exports the func)
    from lykos.analyze import source_project
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
    from lykos.analyze.ingest import ingest, enqueue_triage
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.detect import enqueue_detect
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
