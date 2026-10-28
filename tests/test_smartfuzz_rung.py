"""The ladder's floor rung: directed/structure-seeded SMART fuzzing of a SHARED ASan harness
(directed_confirm.smartfuzz_confirm). This is the rung that works where the concolic rung cannot build
a static harness (FreeRDP's static-OpenSSL cascade) -- it runs on the shared build. The fixture bug is
NOT gated (so coverage-guided fuzzing reaches it quickly from the primed over-long seeds), proving the
rung confirms a real ASan fault with a negative control, and returns rung="smart-fuzz"."""
import shutil
import subprocess

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
add_library(vuln vuln.c)
if(BUILD_FUZZERS)
  add_executable(TestFuzzEasy TestFuzzEasy.c)
  target_link_libraries(TestFuzzEasy vuln)
  target_compile_options(TestFuzzEasy PRIVATE -fsanitize=fuzzer-no-link)
  target_link_options(TestFuzzEasy PRIVATE -fsanitize=fuzzer)
  add_custom_target(fuzzers DEPENDS TestFuzzEasy)
endif()
"""
# NOT gated -- any input of 20+ bytes overflows the 16-byte buffer, so coverage-guided fuzzing (primed
# with over-long seeds) hits it immediately. This is the rung for bugs the solver need not solve.
_VULN = ('#include <stdint.h>\n#include <string.h>\n'
         'void parse(const uint8_t *d, unsigned long n) {\n'
         '  char buf[16];\n'
         '  if (n >= 20) { memcpy(buf, d, n < 64 ? n : 64); __asm__ volatile("" :: "r"(buf) : "memory"); }\n}\n')
_HARNESS = ('#include <stdint.h>\n#include <stddef.h>\n'
            'void parse(const uint8_t *, unsigned long);\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { parse(data, size); return 0; }\n')


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_smartfuzz_rung_confirms_shared_harness(tmp_path):
    from lykos.analyze import libfuzzer as LF
    from lykos.analyze.symbolic import directed_confirm as DC
    if subprocess.run([shutil.which("clang"), "-fsanitize=fuzzer,address", "-xc", "-",
                       "-o", str(tmp_path / "p.bin")],
                      input=b"int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}",
                      capture_output=True).returncode:
        pytest.skip("this clang cannot link -fsanitize=fuzzer")
    d = tmp_path / "proj"
    d.mkdir()
    (d / "CMakeLists.txt").write_text(_CM)
    (d / "vuln.c").write_text(_VULN)
    (d / "TestFuzzEasy.c").write_text(_HARNESS)
    # SHARED ASan build -- what works on a project (e.g. FreeRDP) whose static link does not.
    b = LF.cmake_build_harnesses(d, timeout=180, shared=True, sanitize=True)
    assert b["ok"], f"shared ASan harness build failed:\n{b['log'][-800:]}"
    fuzz_binary = b["harnesses"][0]["binary"]

    res = DC.smartfuzz_confirm(fuzz_binary, lib_dirs=b["lib_dirs"], seeds=[b"Z" * 40],
                               input_size=4096, timeout=60)
    assert res["confirmed"], f"smart-fuzz did not confirm the overflow: {res['reason']}"
    assert res["rung"] == "smart-fuzz"
    assert "overflow" in (res["report"] or ""), f"class={res['class']}"
