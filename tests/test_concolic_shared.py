"""Concolic on a SHARED build (the FreeRDP-shaped case): when the static link is unavailable, the
parser lives in the project's .so, not the harness ELF. The concolic rung force-loads that .so into
angr (auto_load_libs stays off, so system libs stay stubbed) and still solves the parser's gate; the
solved input is replayed through the shared ASan build to confirm. This is the no-sudo unblock for
concolic-on-FreeRDP -- proven here on a fixture whose parser is in a shared library.
"""
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
  add_executable(TestFuzzGate TestFuzzGate.c)
  target_link_libraries(TestFuzzGate vuln)
  target_compile_options(TestFuzzGate PRIVATE -fsanitize=fuzzer-no-link)
  target_link_options(TestFuzzGate PRIVATE -fsanitize=fuzzer)
  add_custom_target(fuzzers DEPENDS TestFuzzGate)
endif()
"""
# parser behind a 2-byte magic gate -- lives in libvuln.so on a shared build
_VULN = ('#include <stdint.h>\n#include <string.h>\n'
         'void parse(const uint8_t *d, unsigned long n) {\n'
         '  char buf[16];\n'
         '  if (n >= 32 && d[0] == 0x42 && d[1] == 0x43) { memcpy(buf, d, 32);\n'
         '    __asm__ volatile("" :: "r"(buf) : "memory"); }\n}\n')
_HARNESS = ('#include <stdint.h>\n#include <stddef.h>\n'
            'void parse(const uint8_t *, unsigned long);\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { parse(data, size); return 0; }\n')


def _mk(d):
    d.mkdir()
    (d / "CMakeLists.txt").write_text(_CM)
    (d / "vuln.c").write_text(_VULN)
    (d / "TestFuzzGate.c").write_text(_HARNESS)


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_concolic_confirms_on_a_shared_build_via_forced_so(tmp_path):
    from lykos.analyze import libfuzzer as LF
    from lykos.analyze.source_confirm_stage import _project_libs
    from lykos.analyze.symbolic import concolic as C
    from lykos.analyze.symbolic import directed_confirm as DC
    if C.locate_angr_python() is None:
        pytest.skip("angr not available")
    if subprocess.run([shutil.which("clang"), "-fsanitize=fuzzer,address", "-xc", "-",
                       "-o", str(tmp_path / "p.bin")],
                      input=b"int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}",
                      capture_output=True).returncode:
        pytest.skip("this clang cannot link -fsanitize=fuzzer")
    de = tmp_path / "exp"
    _mk(de)
    dr = tmp_path / "rep"
    _mk(dr)
    # SHARED clean (for angr) + SHARED ASan (for replay) -- the parser is in libvuln.so in both.
    ec = LF.cmake_build_harnesses(de, timeout=180, shared=True, sanitize=False)
    rc = LF.cmake_build_harnesses(dr, timeout=180, shared=True, sanitize=True)
    assert ec["ok"] and rc["ok"], f"builds failed:\n{ec['log'][-500:]}\n{rc['log'][-500:]}"
    proj_libs = _project_libs(ec["lib_dirs"])
    assert any("vuln" in p for p in proj_libs), f"project .so not found in {proj_libs}"

    res = DC.concolic_confirm(ec["harnesses"][0]["binary"], rc["harnesses"][0]["binary"],
                              input_size=64, lib_dirs=rc["lib_dirs"], load_libs=proj_libs, timeout=150)
    assert res["confirmed"], f"shared-build concolic did not confirm: {res['reason']}"
    assert res["input"] and res["input"][0] == 0x42 and res["input"][1] == 0x43, \
        "the confirming input did not carry the solved magic gate -- the .so parser was not explored"
    assert "stack-buffer-overflow" in (res["report"] or ""), f"class={res['class']}"
