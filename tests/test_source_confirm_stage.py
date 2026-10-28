"""End-to-end: the source_confirm STAGE drives the non-fuzzing confirmation ladder from a source
target. A cmake project ships a parser with a stack overflow behind a 2-byte magic gate and an in-tree
libFuzzer harness. ingest() registers the harness as a target (+ archives the tree); source_confirm
materializes the tree, builds the clean + ASan static harnesses, runs the ladder (concolic rung solves
the gate), and files a CONFIRMED finding + a DynResult the exploit ladder can see -- a proven,
non-fuzzing PoC with a reproducing input."""
import shutil

import pytest

_CM = """
cmake_minimum_required(VERSION 3.13)
project(fz C)
option(BUILD_FUZZERS "" OFF)
option(WITH_SANITIZE_ADDRESS "" OFF)
if(WITH_SANITIZE_ADDRESS)
  add_compile_options(-fsanitize=address -g -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address)
endif()
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/gen.h.in ${CMAKE_CURRENT_BINARY_DIR}/gen.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_library(vuln vuln.c)
if(BUILD_FUZZERS)
  add_executable(TestFuzzGate TestFuzzGate.c)
  target_link_libraries(TestFuzzGate vuln)
  target_compile_options(TestFuzzGate PRIVATE -fsanitize=fuzzer-no-link)
  target_link_options(TestFuzzGate PRIVATE -fsanitize=fuzzer)
  add_custom_target(fuzzers DEPENDS TestFuzzGate)
endif()
"""
_VULN = ('#include <stdint.h>\n#include <string.h>\n#include "gen.h"\n'
         'void parse(const uint8_t *d, unsigned long n) {\n'
         '  char buf[16];\n'
         '  if (n >= 32 && d[0] == 0x42 && d[1] == 0x43) { memcpy(buf, d, 32);\n'
         '    __asm__ volatile("" :: "r"(buf) : "memory"); }\n}\n')
_HARNESS = ('#include <stdint.h>\n#include <stddef.h>\n'
            'void parse(const uint8_t *, unsigned long);\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { parse(data, size); return 0; }\n')


def _mk(d):
    d.mkdir(parents=True, exist_ok=True)
    (d / "CMakeLists.txt").write_text(_CM)
    (d / "gen.h.in").write_text("#define OK 1\n")
    (d / "vuln.c").write_text(_VULN)
    (d / "TestFuzzGate.c").write_text(_HARNESS)


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_source_confirm_stage_files_confirmed_poc(store, tmp_path):
    import subprocess
    from lykos.analyze import register
    from lykos.analyze.ingest import ingest
    from lykos.analyze.source_confirm_stage import enqueue_source_confirm
    from lykos.analyze.symbolic import concolic as C
    from lykos.db.dao import DynResultDAO, FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    if C.locate_angr_python() is None:
        pytest.skip("angr not available")
    if subprocess.run([shutil.which("clang"), "-fsanitize=fuzzer,address", "-xc", "-",
                       "-o", str(tmp_path / "p.bin")],
                      input=b"int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}",
                      capture_output=True).returncode:
        pytest.skip("this clang cannot link -fsanitize=fuzzer")

    proj = tmp_path / "proj"
    _mk(proj)
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("sc").id, proj, filename="proj")
        run = enqueue_source_confirm(JobQueue(store.conn), t, params={"max_seconds": 240,
                                                                      "input_size": 64})
        assert pool.wait_idle(600) and JobQueue(store.conn).runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)

    finds = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "source_confirm"]
    assert finds, "source_confirm filed no confirmed finding"
    assert any(f.state == "confirmed" for f in finds)
    assert any("overflow" in (f.title or "") for f in finds), f"titles={[f.title for f in finds]}"
    # a DynResult the exploit ladder can see, carrying the reproducing input
    drs = [d for d in DynResultDAO(store.conn).list_by_target(t.id)
           if (d.isolation or "").startswith("source_confirm")]
    assert drs and drs[0].crashed and drs[0].input_sha
