"""The ladder's SMARTEST/first rung: deterministic TEMPLATE synthesis (directed_confirm.template_confirm).

No solver, no fuzzing -- just replay a small fixed set of known-bad shapes (oversized blobs, format
probes) under ASan. A directly-triggerable overflow is proven instantly by the minimal oversized blob,
with an empty-input negative control, and the ladder prefers this rung over concolic/smart-fuzz because
it runs first. Only cmake+clang are needed (no angr): the rung just replays."""
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
# NOT gated: any input of 20+ bytes overflows the 16-byte buffer, so a single oversized blob trips it.
_VULN = ('#include <stdint.h>\n#include <string.h>\n'
         'void parse(const uint8_t *d, unsigned long n) {\n'
         '  char buf[16];\n'
         '  if (n >= 20) { memcpy(buf, d, n < 64 ? n : 64); __asm__ volatile("" :: "r"(buf) : "memory"); }\n}\n')
_SAFE = ('#include <stdint.h>\n#include <stddef.h>\n'
         'void parse(const uint8_t *d, unsigned long n) { (void)d; (void)n; }\n')
_HARNESS = ('#include <stdint.h>\n#include <stddef.h>\n'
            'void parse(const uint8_t *, unsigned long);\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { parse(data, size); return 0; }\n')


def _build(tmp_path, vuln):
    from lykos.analyze import libfuzzer as LF
    d = tmp_path / "proj"
    d.mkdir()
    (d / "CMakeLists.txt").write_text(_CM)
    (d / "vuln.c").write_text(vuln)
    (d / "TestFuzzEasy.c").write_text(_HARNESS)
    b = LF.cmake_build_harnesses(d, timeout=180, shared=True, sanitize=True)
    assert b["ok"], f"shared ASan build failed:\n{b['log'][-600:]}"
    return b


def _clang_fuzzer_ok(tmp_path):
    return subprocess.run([shutil.which("clang"), "-fsanitize=fuzzer,address", "-xc", "-",
                           "-o", str(tmp_path / "p.bin")],
                          input=b"int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}",
                          capture_output=True).returncode == 0


def test_default_templates_are_small_and_deterministic():
    from lykos.analyze.symbolic import directed_confirm as DC
    t1 = DC._default_templates(4096)
    t2 = DC._default_templates(4096)
    assert t1 == t2 and 8 <= len(t1) <= 20          # a fixed handful, not a fuzzing loop
    assert t1[0] == b"A" * 32                        # smallest-first, so the minimal trigger wins
    assert any(b"%n" in x for x in t1)               # format-string probe present


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_template_rung_confirms_overflow_without_fuzzing(tmp_path):
    from lykos.analyze.symbolic import directed_confirm as DC
    if not _clang_fuzzer_ok(tmp_path):
        pytest.skip("this clang cannot link -fsanitize=fuzzer")
    b = _build(tmp_path, _VULN)
    res = DC.template_confirm(b["harnesses"][0]["binary"], lib_dirs=b["lib_dirs"], input_size=4096,
                              timeout=60)
    assert res["confirmed"], f"template rung did not confirm: {res['reason']}"
    assert res["rung"] == "template"
    assert res["input"] and len(res["input"]) >= 20 and set(res["input"]) == {ord("A")}
    assert "overflow" in (res["report"] or ""), f"class={res['class']}"


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_ladder_prefers_the_template_rung(tmp_path):
    """The template rung runs FIRST, so a directly-triggerable bug is proved by it, not smart-fuzz."""
    from lykos.analyze.symbolic import directed_confirm as DC
    if not _clang_fuzzer_ok(tmp_path):
        pytest.skip("this clang cannot link -fsanitize=fuzzer")
    b = _build(tmp_path, _VULN)
    attempts = []
    proven = DC.confirm_ladder([{"name": "TestFuzzEasy", "fuzz_binary": b["harnesses"][0]["binary"],
                                 "lib_dirs": b["lib_dirs"], "input_size": 4096}],
                               timeout_per=60, attempts_out=attempts)
    assert len(proven) == 1 and proven[0]["rung"] == "template"
    # template confirmed first; smart-fuzz was never reached for this harness
    outcomes = {(a["rung"], a["outcome"]) for a in attempts}
    assert ("template", "confirmed") in outcomes
    assert not any(a["rung"] == "smart-fuzz" for a in attempts)


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_template_rung_declines_on_a_safe_harness(tmp_path):
    from lykos.analyze.symbolic import directed_confirm as DC
    if not _clang_fuzzer_ok(tmp_path):
        pytest.skip("this clang cannot link -fsanitize=fuzzer")
    b = _build(tmp_path, _SAFE)
    res = DC.template_confirm(b["harnesses"][0]["binary"], lib_dirs=b["lib_dirs"], timeout=30)
    assert not res["confirmed"] and "no template input faulted" in res["reason"]
