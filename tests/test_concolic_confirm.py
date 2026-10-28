"""The non-fuzzing confirmation rung: concolic input synthesis + ASan replay (directed_confirm).

The fixture's parser hides a stack overflow behind a 2-BYTE MAGIC GATE (0x42 0x43) -- blind fuzzing
would need ~1/65536 to stumble past it; concolic solves it deterministically. Once past the gate the
overflow is unconditional, so any gate-passing input faults under ASan. concolic_confirm explores the
clean (non-ASan) build to solve the gate and replays the solved input through the ASan build, returning
a CONFIRMED stack-buffer-overflow with a passing negative control -- a proven PoC with no fuzzing."""
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
         '  if (n >= 32 && d[0] == 0x42 && d[1] == 0x43) {    /* 2-byte magic gate */\n'
         '    memcpy(buf, d, 32);                              /* unconditional 32->16 overflow */\n'
         '    __asm__ volatile("" :: "r"(buf) : "memory");\n'
         '  }\n}\n')
_HARNESS = ('#include <stdint.h>\n#include <stddef.h>\n'
            'void parse(const uint8_t *, unsigned long);\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { parse(data, size); return 0; }\n')


def _mk(d):
    (d / "CMakeLists.txt").write_text(_CM)
    (d / "gen.h.in").write_text("#define OK 1\n")
    (d / "vuln.c").write_text(_VULN)
    (d / "TestFuzzGate.c").write_text(_HARNESS)


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_concolic_confirm_solves_gate_and_confirms(tmp_path):
    from lykos.analyze import libfuzzer as LF
    from lykos.analyze.symbolic import concolic as C
    from lykos.analyze.symbolic import directed_confirm as DC
    if C.locate_angr_python() is None:
        pytest.skip("angr not available")
    # libFuzzer runtime must link, and ASan must actually catch a small stack overflow here.
    probe = tmp_path / "p.c"
    probe.write_text("int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}\n")
    if subprocess_rc([shutil.which("clang"), "-fsanitize=fuzzer,address", str(probe),
                      "-o", str(tmp_path / "p.bin")]):
        pytest.skip("this clang cannot link -fsanitize=fuzzer")

    de = tmp_path / "explore"
    de.mkdir()
    _mk(de)
    dr = tmp_path / "replay"
    dr.mkdir()
    _mk(dr)
    eb = LF.cmake_build_harnesses(de, timeout=180, shared=False, sanitize=False)   # clean, for angr
    rb = LF.cmake_build_harnesses(dr, timeout=180, shared=False, sanitize=True)    # ASan, for replay
    assert eb["ok"] and rb["ok"], f"builds failed:\n{eb['log'][-600:]}\n{rb['log'][-600:]}"
    explore = eb["harnesses"][0]["binary"]
    replay = rb["harnesses"][0]["binary"]

    res = DC.concolic_confirm(explore, replay, harness_fn="LLVMFuzzerTestOneInput",
                              input_size=64, lib_dirs=rb["lib_dirs"], timeout=120)
    assert res["confirmed"], f"concolic did not confirm the gated overflow: {res['reason']}"
    assert res["input"] and res["input"][0] == 0x42 and res["input"][1] == 0x43, \
        "the confirming input did not carry the solved magic gate"
    assert "stack-buffer-overflow" in (res["report"] or ""), \
        f"expected a stack-buffer-overflow in the ASan report; class={res['class']}"
    assert res["rung"] == "concolic"


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_confirm_ladder_proves_via_concolic_rung(tmp_path):
    """The ladder orchestration: given the harness descriptors, confirm_ladder tries the rungs
    smartest-first (template -> concolic -> smart-fuzz) and returns the proven bug tagged with the
    rung that proved it. The template/smart-fuzz rungs are not implemented yet, so the gated overflow
    is proved by the concolic rung."""
    from lykos.analyze import libfuzzer as LF
    from lykos.analyze.symbolic import concolic as C
    from lykos.analyze.symbolic import directed_confirm as DC
    if C.locate_angr_python() is None:
        pytest.skip("angr not available")
    probe = tmp_path / "p.c"
    probe.write_text("int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}\n")
    if subprocess_rc([shutil.which("clang"), "-fsanitize=fuzzer,address", str(probe),
                      "-o", str(tmp_path / "p.bin")]):
        pytest.skip("this clang cannot link -fsanitize=fuzzer")
    de = tmp_path / "explore"
    de.mkdir()
    _mk(de)
    dr = tmp_path / "replay"
    dr.mkdir()
    _mk(dr)
    eb = LF.cmake_build_harnesses(de, timeout=180, shared=False, sanitize=False)
    rb = LF.cmake_build_harnesses(dr, timeout=180, shared=False, sanitize=True)
    assert eb["ok"] and rb["ok"]
    harnesses = [{"name": "TestFuzzGate", "explore_binary": eb["harnesses"][0]["binary"],
                  "replay_binary": rb["harnesses"][0]["binary"], "lib_dirs": rb["lib_dirs"],
                  "input_size": 64}]
    proven = DC.confirm_ladder(harnesses, timeout_per=120)
    assert len(proven) == 1, f"ladder did not prove the bug: {proven}"
    p = proven[0]
    assert p["harness"] == "TestFuzzGate" and p["rung"] == "concolic"
    assert "stack-buffer-overflow" in (p["report"] or "")


def subprocess_rc(argv):
    import subprocess
    return subprocess.run(argv, capture_output=True).returncode
