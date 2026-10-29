"""Frontier dump: on a CUT-OFF concolic search (a big target that does not drain in the budget --
FreeRDP's parsers), the deepest states sit in deferred/active/spilled, not deadended, so the rung used
to report 'generated no inputs (cutoff)'. Now the deepest frontier states are concretised too, each an
input that drove a long way into the parser; replayed under ASan with a negative control they can still
confirm a bug. The fixture forces cutoff (a long branchy loop -> state explosion, nothing deadends) with
an UNCONDITIONAL overflow, so a frontier input is the ONLY way to confirm it -- which it does."""
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
  add_executable(TestFuzzBig TestFuzzBig.c)
  target_link_libraries(TestFuzzBig vuln)
  target_compile_options(TestFuzzBig PRIVATE -fsanitize=fuzzer-no-link)
  target_link_options(TestFuzzBig PRIVATE -fsanitize=fuzzer)
  add_custom_target(fuzzers DEPENDS TestFuzzBig)
endif()
"""
# memcpy of 40 into buf[16] for any non-trivial input (so EMPTY input is safe -> the negative control
# passes) + a long branchy loop that explodes the state space so the search CUTS OFF without draining
# -> no deadended states, only a frontier.
_VULN = ('#include <stdint.h>\n#include <string.h>\n'
         'void parse(const uint8_t *d, unsigned long n) {\n'
         '  char buf[16];\n'
         '  if (n >= 20) { memcpy(buf, d, 40); __asm__ volatile("" :: "r"(buf) : "memory"); }\n'
         '  volatile unsigned long acc = 0;\n'
         '  for (unsigned i = 0; i < 100000u; i++) { if (i < n && (d[i % 32] & 1)) acc += i; }\n'
         '  (void)acc;\n}\n')
_HARNESS = ('#include <stdint.h>\n#include <stddef.h>\n'
            'void parse(const uint8_t *, unsigned long);\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { parse(data, size); return 0; }\n')


def _mk(d):
    d.mkdir()
    (d / "CMakeLists.txt").write_text(_CM)
    (d / "vuln.c").write_text(_VULN)
    (d / "TestFuzzBig.c").write_text(_HARNESS)


def _angr_clang(tmp_path):
    from lykos.analyze.symbolic import concolic as C
    if C.locate_angr_python() is None or not (shutil.which("cmake") and shutil.which("clang")):
        return None
    if subprocess.run([shutil.which("clang"), "-fsanitize=fuzzer,address", "-xc", "-",
                       "-o", str(tmp_path / "p.bin")],
                      input=b"int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}",
                      capture_output=True).returncode:
        return None
    return C.locate_angr_python()


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_cutoff_search_dumps_frontier_inputs(tmp_path):
    from lykos.analyze import libfuzzer as LF
    from lykos.analyze.symbolic import concolic as C
    py = _angr_clang(tmp_path)
    if py is None:
        pytest.skip("angr / clang -fsanitize=fuzzer unavailable")
    de = tmp_path / "exp"
    _mk(de)
    eb = LF.cmake_build_harnesses(de, timeout=180, shared=False, sanitize=False)
    assert eb["ok"], eb["log"][-500:]
    spec = {"binary": eb["harnesses"][0]["binary"], "input_mode": "harness",
            "harness_fn": "LLVMFuzzerTestOneInput", "input_size": 64, "max_seconds": 25, "num_find": 8}
    res = C.run_explore(py, spec, timeout=60)
    assert res.get("cutoff") is True, f"expected a cut-off search; stats={res.get('stats')}"
    assert res.get("generated"), "cutoff must still yield inputs (the frontier dump), not zero"
    assert any(g.get("reached") == "frontier" for g in res["generated"]), \
        f"expected frontier-dumped inputs; tags={[g.get('reached') for g in res['generated']]}"


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_frontier_input_confirms_the_overflow(tmp_path):
    from lykos.analyze import libfuzzer as LF
    from lykos.analyze.symbolic import directed_confirm as DC
    py = _angr_clang(tmp_path)
    if py is None:
        pytest.skip("angr / clang -fsanitize=fuzzer unavailable")
    de = tmp_path / "exp"
    _mk(de)
    dr = tmp_path / "rep"
    _mk(dr)
    eb = LF.cmake_build_harnesses(de, timeout=180, shared=False, sanitize=False)
    rb = LF.cmake_build_harnesses(dr, timeout=180, shared=False, sanitize=True)
    assert eb["ok"] and rb["ok"]
    res = DC.concolic_confirm(eb["harnesses"][0]["binary"], rb["harnesses"][0]["binary"],
                              input_size=64, lib_dirs=rb["lib_dirs"], timeout=40)
    assert res["confirmed"], f"frontier-dumped input did not confirm the overflow: {res['reason']}"
    assert "overflow" in (res["report"] or ""), f"class={res['class']}"
