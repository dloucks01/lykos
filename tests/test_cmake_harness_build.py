"""CMake-aware build of a project's IN-TREE libFuzzer harness, the compile substrate the source
path needs for a large project (FreeRDP's generated `winpr/config.h` cannot be produced by a per-TU
compile -- only by the project's own cmake). libfuzzer.cmake_build_harnesses configures+builds the
project with clang + ASan + standalone libFuzzer and returns the harness ELF + its shared-lib dirs.

The fixture is a tiny cmake project shaped like the real case: a GENERATED header (configure_file),
a library with a bug behind a magic gate, and an in-tree LLVMFuzzerTestOneInput harness. The bug is
reachable only by a DIRECTED input (the gate byte 0x42), so a crafted input -- not fuzzing -- drives
ASan to fault at it, and a benign input does not. That is the non-fuzzing confirmation in miniature."""
import os
import subprocess

import pytest
from lykos.analyze import libfuzzer

_CMAKELISTS = """
cmake_minimum_required(VERSION 3.13)
project(fz C)
option(BUILD_FUZZERS "" OFF)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/gen_config.h.in ${CMAKE_CURRENT_BINARY_DIR}/gen_config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_library(vuln vuln.c)
if(BUILD_FUZZERS)
  add_compile_options(-fsanitize=fuzzer-no-link,address -fno-omit-frame-pointer -g)
  add_executable(TestFuzzVuln TestFuzzVuln.c)
  target_link_libraries(TestFuzzVuln vuln)
  target_link_options(TestFuzzVuln PRIVATE -fsanitize=fuzzer,address)
  add_custom_target(fuzzers DEPENDS TestFuzzVuln)
endif()
"""

_GEN_IN = "#define GEN_CONFIG_OK 1\n"

# The bug is behind a magic gate so a random single byte does NOT hit it -- a DIRECTED input must set
# d[0]==0x42, then d[1] is an attacker length copied into a 16-byte stack buffer (overflow when >16).
_VULN_C = """
#include <stdint.h>
#include <string.h>
#include "gen_config.h"
#if !GEN_CONFIG_OK
#error "generated header not seen -- cmake configure did not run"
#endif
void parse(const uint8_t *d, unsigned long n) {
    char buf[16];
    if (n >= 3 && d[0] == 0x42) {
        unsigned long len = d[1];          /* attacker-controlled length */
        memcpy(buf, d + 2, len);           /* stack overflow when len > 16 */
        __asm__ volatile("" :: "r"(buf) : "memory");
    }
}
"""

_HARNESS_C = """
#include <stdint.h>
#include <stddef.h>
void parse(const uint8_t *, unsigned long);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { parse(data, size); return 0; }
"""


def _have(*tools):
    import shutil
    return all(shutil.which(t) for t in tools)


@pytest.mark.skipif(not _have("cmake", "clang"), reason="needs cmake + clang")
def test_cmake_build_harness_and_directed_confirm(tmp_path):
    (tmp_path / "CMakeLists.txt").write_text(_CMAKELISTS)
    (tmp_path / "gen_config.h.in").write_text(_GEN_IN)
    (tmp_path / "vuln.c").write_text(_VULN_C)
    (tmp_path / "TestFuzzVuln.c").write_text(_HARNESS_C)

    # libFuzzer must actually be available with this clang (some clangs ship without the runtime).
    probe = tmp_path / "p.c"
    probe.write_text("int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}\n")
    import shutil as _sh
    if subprocess.run([_sh.which("clang"), "-fsanitize=fuzzer,address", str(probe),
                       "-o", str(tmp_path / "p.bin")], capture_output=True).returncode:
        pytest.skip("this clang cannot link -fsanitize=fuzzer (no libFuzzer runtime)")

    res = libfuzzer.cmake_build_harnesses(tmp_path, timeout=180)
    assert res["ok"], f"cmake harness build failed:\n{res['log'][-1500:]}"
    h = next((x for x in res["harnesses"] if x["name"] == "TestFuzzVuln"), None)
    assert h, f"TestFuzzVuln harness not produced: {res['harnesses']}"
    binary = h["binary"]
    assert libfuzzer._is_elf_exec(__import__("pathlib").Path(binary))

    env = dict(os.environ)
    if res["lib_dirs"]:
        env["LD_LIBRARY_PATH"] = os.pathsep.join(res["lib_dirs"] + [env.get("LD_LIBRARY_PATH", "")])
    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0"

    # DIRECTED crafting: the magic gate + an oversized length -> ASan must fault at the overflow.
    crash = tmp_path / "crash.bin"
    crash.write_bytes(b"\x42\xff" + b"A" * 64)
    r = subprocess.run([binary, str(crash)], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode != 0 and "AddressSanitizer" in (r.stdout + r.stderr), \
        f"directed input did not trip ASan (rc={r.returncode}):\n{(r.stdout + r.stderr)[-1500:]}"

    # NEGATIVE control: a benign input that misses the gate must NOT fault -- the crash is caused by
    # the crafted bytes, not by running the harness at all.
    benign = tmp_path / "ok.bin"
    benign.write_bytes(b"\x00\x01\x02\x03")
    r2 = subprocess.run([binary, str(benign)], capture_output=True, text=True, env=env, timeout=60)
    assert r2.returncode == 0 and "AddressSanitizer" not in (r2.stdout + r2.stderr), \
        f"benign input faulted (rc={r2.returncode}):\n{(r2.stdout + r2.stderr)[-800:]}"
