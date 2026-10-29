"""Parser-entry seeding + relevant-.so loading: concolic enters angr directly at the parser the
harness drives (skipping the wrapper/context setup that eats the budget), and force-loads only the
.so that harness needs. Entering at the parser is SOUND only when the harness calls it with a clean
(data, size) -- a context-taking parser falls back to the libFuzzer wrapper. Proven on a fixture whose
parser lives in libvuln.so.
"""
import shutil
import subprocess

import pytest

from lykos.analyze import source_confirm_stage as SC


# ---- _parser_entry (pure) --------------------------------------------------------------------

def _entry(tmp_path, body):
    p = tmp_path / "h.c"
    p.write_text(body)
    return SC._parser_entry(str(p))


def test_clean_data_size_call_is_the_entry(tmp_path):
    assert _entry(tmp_path, "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)"
                            "{ return parse_pdu(data, size); }") == "parse_pdu"


def test_cast_on_data_still_detected(tmp_path):
    assert _entry(tmp_path, "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)"
                            "{ return asn_parse((const char*)data, size); }") == "asn_parse"


def test_context_taking_parser_falls_back(tmp_path):
    # parse(ctx, data, size, pw) -> cannot synthesize ctx -> None (concolic uses the wrapper)
    assert _entry(tmp_path, "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)"
                            "{ F *f = f_new(); freerdp_parse(f, data, size, 0); return 0; }") is None


def test_ambiguous_two_candidates_falls_back(tmp_path):
    assert _entry(tmp_path, "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)"
                            "{ a_parse(data, size); b_parse(data, size); return 0; }") is None


def test_memcpy_like_calls_are_not_entries(tmp_path):
    assert _entry(tmp_path, "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)"
                            "{ char b[8]; memcpy(data, size); return 0; }") is None


# ---- _relevant_libs (pure fallback) ----------------------------------------------------------

def test_relevant_libs_empty_and_fallback():
    assert SC._relevant_libs("/no/such/bin", []) == []
    # a binary whose NEEDED cannot be read (missing file) -> fall back to all project libs
    allp = ["/x/libfreerdp3.so", "/x/libwinpr3.so"]
    assert sorted(SC._relevant_libs("/no/such/bin", allp)) == sorted(allp)


# ---- functional: concolic enters at the parser in the .so ------------------------------------

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
def test_concolic_enters_at_the_parser_symbol(tmp_path):
    from lykos.analyze import libfuzzer as LF
    from lykos.analyze.symbolic import concolic as C
    from lykos.analyze.symbolic import directed_confirm as DC
    py = C.locate_angr_python()
    if py is None:
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
    ec = LF.cmake_build_harnesses(de, timeout=180, shared=True, sanitize=False)
    rc = LF.cmake_build_harnesses(dr, timeout=180, shared=True, sanitize=True)
    assert ec["ok"] and rc["ok"]
    libs = SC._project_libs(ec["lib_dirs"])
    entry = SC._parser_entry(ec["harnesses"][0]["source"])
    assert entry == "parse"

    # the driver enters at `parse` (reported) and confirms via the .so-resident parser
    spec = {"binary": ec["harnesses"][0]["binary"], "input_mode": "harness", "harness_fn": entry,
            "input_size": 64, "max_seconds": 90, "num_find": 8, "load_libs": libs}
    res = C.run_explore(py, spec, timeout=120)
    assert res.get("harness_entry") == "parse", f"entered at {res.get('harness_entry')}"

    conf = DC.concolic_confirm(ec["harnesses"][0]["binary"], rc["harnesses"][0]["binary"],
                               harness_fn=entry, input_size=64, lib_dirs=rc["lib_dirs"],
                               load_libs=libs, timeout=120)
    assert conf["confirmed"], f"parser-entry concolic did not confirm: {conf['reason']}"
    assert conf["input"] and conf["input"][0] == 0x42 and conf["input"][1] == 0x43


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_driver_falls_back_when_entry_symbol_absent(tmp_path):
    from lykos.analyze import libfuzzer as LF
    from lykos.analyze.symbolic import concolic as C
    py = C.locate_angr_python()
    if py is None:
        pytest.skip("angr not available")
    if subprocess.run([shutil.which("clang"), "-fsanitize=fuzzer,address", "-xc", "-",
                       "-o", str(tmp_path / "p.bin")],
                      input=b"int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}",
                      capture_output=True).returncode:
        pytest.skip("this clang cannot link -fsanitize=fuzzer")
    de = tmp_path / "exp"
    _mk(de)
    ec = LF.cmake_build_harnesses(de, timeout=180, shared=True, sanitize=False)
    assert ec["ok"]
    spec = {"binary": ec["harnesses"][0]["binary"], "input_mode": "harness",
            "harness_fn": "no_such_parser_fn", "input_size": 64, "max_seconds": 60, "num_find": 4,
            "load_libs": SC._project_libs(ec["lib_dirs"])}
    res = C.run_explore(py, spec, timeout=90)
    assert res.get("ok") is True and res.get("harness_entry") == "LLVMFuzzerTestOneInput"
