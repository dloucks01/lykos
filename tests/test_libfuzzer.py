"""Coverage-guided libFuzzer fuzzing of C/C++ source: build an LLVMFuzzerTestOneInput harness
(in-tree or synthesized for an entry function) with ASan+UBSan, let libFuzzer drive coverage, and
file each crash as a confirmed finding classified from the sanitizer report (bug class + source
file:line) -- no CTF oracle. This is the coverage-guided complement to the blind `fuzz` stage and
the only path that fuzzes LIBRARY source with no main()."""
from __future__ import annotations

import shutil

import pytest
from lykos.analyze import libfuzzer as LF
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox


def _clang_or_skip():
    if sandbox.host_arch() != "x86-64" or not shutil.which("clang"):
        pytest.skip("libFuzzer needs clang on x86-64")


def test_find_and_synth_harness(tmp_path):
    (tmp_path / "a.c").write_text("void parse(char* s){ (void)s; }\n")
    assert LF.find_harness(tmp_path) is None
    (tmp_path / "h.c").write_text("int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n)"
                                  "{return 0;}\n")
    assert LF.find_harness(tmp_path).name == "h.c"
    s = LF.synth_harness("parse", kind="cstring")
    assert "LLVMFuzzerTestOneInput" in s and "parse((char *)s)" in s
    assert "parse(data, size)" in LF.synth_harness("parse", kind="buflen")
    # C++ symbol: declared with its real signature + extern "C" for a C symbol from a C++ harness
    cpp = LF.synth_harness("load", kind="cstring", arg_type="const char *", cxx=True, c_linkage=False)
    assert "void load(const char *)" in cpp and 'extern "C" int LLVMFuzzerTestOneInput' in cpp


def test_build_and_run_intree_harness(tmp_path):
    _clang_or_skip()
    (tmp_path / "h.c").write_text(
        "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n#include <stdio.h>\n"
        "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){char b[8];memset(b,0,8);"
        " if(n>0)memcpy(b,d,n); if(b[0]==0x7f)printf(\" \"); return 0;}\n")
    out = tmp_path / "fuzz.bin"
    b = LF.build_libfuzzer(tmp_path, out)
    assert b["ok"] and "in-tree" in b["harness"], b["log"][-300:]
    r = LF.run_libfuzzer(out, tmp_path, seconds=15)
    assert r["crashes"] and b"AddressSanitizer" in (r["crashes"][0]["report"] or "").encode()


def test_synth_harness_for_library_function(tmp_path):
    _clang_or_skip()
    (tmp_path / "lib.c").write_text("#include <string.h>\n#include <stdio.h>\n"
                                    "void parse(char*s){char t[16];strcpy(t,s);"
                                    "if(t[0]==0x7f)printf(\" \");}\n")
    out = tmp_path / "fuzz.bin"
    b = LF.build_libfuzzer(tmp_path, out, harness_fn="parse")
    assert b["ok"] and "synthesized" in b["harness"], b["log"][-300:]
    r = LF.run_libfuzzer(out, tmp_path, seconds=15)
    assert r["crashes"]


@pytest.fixture
def pool(store):
    register()
    from lykos.jobs import JobConfig, WorkerPool
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_libfuzzer_stage_confirms_finding_with_source_line(store, case, pool):
    _clang_or_skip()
    if not shutil.which("gcc"):
        pytest.skip("no gcc to build the source project at ingest")
    import tempfile
    from pathlib import Path
    from lykos.analyze.ingest import ingest
    from lykos.analyze.libfuzzer_stage import enqueue_libfuzzer
    from lykos.db.dao import FindingDAO
    from lykos.jobs import JobQueue
    proj = Path(tempfile.mkdtemp())
    (proj / "parse.c").write_text("#include <string.h>\n#include <stdio.h>\n"
                                  "void parse(char*s){char t[16];strcpy(t,s);if(t[0]==0x7f)printf(\" \");}\n")
    (proj / "main.c").write_text("#include <stdio.h>\nvoid parse(char*);\n"
                                 "int main(){char b[256];if(fgets(b,256,stdin))parse(b);return 0;}\n")
    (proj / "Makefile").write_text("app: main.c parse.c\n\t$(CC) $(CFLAGS) main.c parse.c -o app $(LDFLAGS)\n")
    t = ingest(store, case.id, proj, filename="prog")
    run = enqueue_libfuzzer(JobQueue(store.conn), t, params={"harness_fn": "parse", "seconds": 15})
    assert pool.wait_idle(90) and store.runs.get(run.id).status == "done"
    lf = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "libfuzzer"]
    assert lf and lf[0].state == "confirmed"
    assert lf[0].cwe in ("CWE-121", "CWE-122", "CWE-787")
    assert any("parse.c:" in e.get("detail", "") for e in lf[0].evidence)   # precise source line


def test_pick_harness_fn():
    import tempfile
    from pathlib import Path
    from lykos.analyze.libfuzzer import pick_harness_fn
    d = Path(tempfile.mkdtemp())
    (d / "a.c").write_text("static void helper(char*x){(void)x;}\n"
                           "int parse(const char* s){ return s[0]; }\n")
    assert pick_harness_fn(d) == "parse"                  # non-static, char* first arg
    (d / "b.c").write_text("int add(int a,int b){return a+b;}\n")
    from pathlib import Path as P
    e = P(tempfile.mkdtemp()); (e / "b.c").write_text("int add(int a,int b){return a+b;}\n")
    assert pick_harness_fn(e) is None                     # no buffer-consuming function


def test_libfuzzer_on_pure_library_auto_harness(store, case, pool):
    _clang_or_skip()
    import shutil as _sh
    if not _sh.which("gcc"):
        pytest.skip("no gcc to build the library at ingest")
    import tempfile
    from pathlib import Path
    from lykos.analyze.ingest import ingest
    from lykos.analyze.libfuzzer_stage import enqueue_libfuzzer
    from lykos.db.dao import FindingDAO
    from lykos.jobs import JobQueue
    lib = Path(tempfile.mkdtemp())
    (lib / "parse.c").write_text("#include <string.h>\n"
                                 "#include <stdio.h>\nvoid parse_record(char*s){ char t[16]; strcpy(t,s);"
                                 " if(t[0]==0x7f)printf(\" \"); }\n")
    t = ingest(store, case.id, lib, filename="mylib")     # pure library -> ingests as .so
    run = enqueue_libfuzzer(JobQueue(store.conn), t, params={"seconds": 15})   # auto-harness
    assert pool.wait_idle(90) and store.runs.get(run.id).status == "done"
    lf = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "libfuzzer"]
    assert lf and lf[0].state == "confirmed" and lf[0].cwe in ("CWE-121", "CWE-122", "CWE-787")


def test_libfuzzer_cpp_project_name_mangling(store, case, pool):
    """A C++ source project: the synthesized harness must forward-declare the target with its real
    signature (const char*) so C++ name mangling matches at link time -- `extern void load()` would
    mangle differently and silently fail. Verifies C++ (not just C) source is fuzzable end-to-end."""
    _clang_or_skip()
    import shutil as _sh
    if not _sh.which("g++"):
        pytest.skip("no g++ to build the C++ project at ingest")
    import tempfile
    from pathlib import Path
    from lykos.analyze.ingest import ingest
    from lykos.analyze.libfuzzer_stage import enqueue_libfuzzer
    from lykos.db.dao import FindingDAO
    from lykos.jobs import JobQueue
    d = Path(tempfile.mkdtemp())
    (d / "parser.cpp").write_text("#include <cstring>\n#include <cstdio>\n"
                                  "void load(const char* in){ char n[16]; std::strcpy(n,in);"
                                  " if(n[0]) std::printf(\" \"); }\n")
    (d / "main.cpp").write_text("#include <cstdio>\nvoid load(const char*);\n"
                                "int main(){ char b[256]; if(std::fgets(b,256,stdin)) load(b); return 0; }\n")
    (d / "Makefile").write_text("app: main.cpp parser.cpp\n\t$(CXX) $(CXXFLAGS) main.cpp parser.cpp -o app $(LDFLAGS)\n")
    t = ingest(store, case.id, d, filename="cpproj")
    run = enqueue_libfuzzer(JobQueue(store.conn), t, params={"harness_fn": "load", "seconds": 15})
    assert pool.wait_idle(90) and store.runs.get(run.id).status == "done"
    lf = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "libfuzzer"]
    assert lf and lf[0].state == "confirmed" and lf[0].cwe in ("CWE-121", "CWE-122", "CWE-787")
