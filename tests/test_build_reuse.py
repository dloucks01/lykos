"""Build-cache sharing: a cmake harness build is keyed by its (shared, sanitize) config, so the SAME
config lands in the SAME build dir and is REUSED instead of rebuilt. This is what lets source_confirm
and libfuzzer_stage share the one shared-ASan harness build (each configure pass rmtrees its dir, so
before this a second caller with a different build_name did a full rebuild).
"""
import os
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
add_library(vuln vuln.c)
if(BUILD_FUZZERS)
  add_executable(TestFuzzA TestFuzzA.c)
  target_link_libraries(TestFuzzA vuln)
  target_compile_options(TestFuzzA PRIVATE -fsanitize=fuzzer-no-link)
  target_link_options(TestFuzzA PRIVATE -fsanitize=fuzzer)
  add_custom_target(fuzzers DEPENDS TestFuzzA)
endif()
"""
_VULN = "void parse(const unsigned char *d, unsigned long n){ (void)d; (void)n; }\n"
_HARNESS = ("#include <stddef.h>\n#include <stdint.h>\nvoid parse(const unsigned char*,unsigned long);\n"
            "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){ parse(d,s); return 0; }\n")


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_same_config_build_is_reused_not_rebuilt(tmp_path):
    from lykos.analyze import libfuzzer as LF
    d = tmp_path / "proj"
    d.mkdir()
    (d / "CMakeLists.txt").write_text(_CM)
    (d / "vuln.c").write_text(_VULN)
    (d / "TestFuzzA.c").write_text(_HARNESS)

    b1 = LF.cmake_build_harnesses(d, timeout=180, shared=True, sanitize=True)
    assert b1["ok"] and not b1.get("reused"), f"first build should build:\n{b1['log'][-500:]}"
    binary = b1["harnesses"][0]["binary"]
    assert "_lykos_cmake_sh_asan" in binary        # config-keyed dir, not a caller-specific name
    mtime1 = os.path.getmtime(binary)

    # Second call, SAME config -> reused, same binary, NOT rebuilt (mtime unchanged).
    b2 = LF.cmake_build_harnesses(d, timeout=180, shared=True, sanitize=True)
    assert b2["ok"] and b2.get("reused") is True
    assert b2["harnesses"][0]["binary"] == binary
    assert os.path.getmtime(binary) == mtime1, "reuse must not rebuild the harness"

    # A DIFFERENT config (no ASan) is a DIFFERENT dir -> a fresh build, not the reused one.
    b3 = LF.cmake_build_harnesses(d, timeout=180, shared=True, sanitize=False)
    assert b3["ok"] and not b3.get("reused")
    assert "_lykos_cmake_sh_clean" in b3["harnesses"][0]["binary"]
    assert b3["harnesses"][0]["binary"] != binary
