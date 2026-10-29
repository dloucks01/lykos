"""The template rung's LENGTH-PREFIX probes (format-aware): a parser that reads a leading size field
and trusts it is confirmed deterministically, even when the generic oversized-blob templates are
rejected. The fixture rejects an absurd length (so an all-'A' blob, whose first bytes decode to
~0x41414141, is dropped) but trusts a modest one -- so ONLY a length-prefix template trips it. No
solver, no fuzzing.
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
  add_executable(TestFuzzLen TestFuzzLen.c)
  target_link_libraries(TestFuzzLen vuln)
  target_compile_options(TestFuzzLen PRIVATE -fsanitize=fuzzer-no-link)
  target_link_options(TestFuzzLen PRIVATE -fsanitize=fuzzer)
  add_custom_target(fuzzers DEPENDS TestFuzzLen)
endif()
"""
# Reads a 4-byte little-endian length, REJECTS absurd lengths (so an all-'A' blob -> len ~0x41414141
# is dropped: generic blobs are safe here), but TRUSTS a modest length for the copy into buf[16].
_VULN = ('#include <stdint.h>\n#include <string.h>\n'
         'void parse(const uint8_t *d, unsigned long n) {\n'
         '  char buf[16];\n'
         '  if (n < 4) return;\n'
         '  uint32_t len = (uint32_t)d[0] | ((uint32_t)d[1]<<8) | ((uint32_t)d[2]<<16) | ((uint32_t)d[3]<<24);\n'
         '  if (len > (1u<<20)) return;              /* reject absurd -> all-A blobs are safe */\n'
         '  unsigned long avail = n - 4;\n'
         '  memcpy(buf, d + 4, len < avail ? len : avail);   /* trusts len -> overflow buf[16] */\n'
         '  __asm__ volatile("" :: "r"(buf) : "memory");\n}\n')
_HARNESS = ('#include <stdint.h>\n#include <stddef.h>\n'
            'void parse(const uint8_t *, unsigned long);\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { parse(data, size); return 0; }\n')


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_length_prefix_template_confirms_what_blobs_miss(tmp_path):
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
    (d / "TestFuzzLen.c").write_text(_HARNESS)
    b = LF.cmake_build_harnesses(d, timeout=180, shared=True, sanitize=True)
    assert b["ok"], f"build failed:\n{b['log'][-600:]}"

    res = DC.template_confirm(b["harnesses"][0]["binary"], lib_dirs=b["lib_dirs"], timeout=60)
    assert res["confirmed"], f"length-prefix template did not confirm: {res['reason']}"
    assert res["rung"] == "template"
    assert "overflow" in (res["report"] or ""), f"class={res['class']}"
    # the confirming input is a length-prefix shape, NOT an all-'A' blob (those are rejected here)
    assert set(res["input"]) != {ord("A")}, "an all-'A' blob should have been rejected by the guard"
    first4 = int.from_bytes(res["input"][:4], "little")
    assert 16 < first4 <= (1 << 20), f"the leading length field was {first4}, not a trusted-length shape"
