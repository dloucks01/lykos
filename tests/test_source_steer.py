"""Finding-directed steering: point the concolic rung at the statically-suspected bug LINES.

dwarfline.resolve_sites maps a file:line to a code address via the DWARF line table;
source_confirm._steer_sites collects the (basename, line) sites of the static candidates; the concolic
rung explores toward those addresses. Steering to the bug LINE (not the enclosing function entry) is
the correct granularity -- the line is only reachable once the guard it sits behind is solved, so a
site-steered input actually triggers the fault. The angr driver also accepts explicit function
`target_syms`. Steering only changes exploration efficiency; the ASan replay + negative control gate
every confirmation, so it can never cause a false positive -- these tests pin that confirmation holds.
"""
import shutil
import subprocess

import pytest

from lykos.analyze.symbolic import dwarfline
from lykos.db.dao import FindingDAO, TargetDAO


# ---- dwarfline.resolve_sites (needs a -g build) ----------------------------------------------

@pytest.mark.skipif(not (shutil.which("gcc") or shutil.which("cc")), reason="needs a C compiler")
@pytest.mark.skipif(not shutil.which("objdump"), reason="needs objdump")
def test_resolve_sites_maps_line_to_address(tmp_path):
    cc = shutil.which("gcc") or shutil.which("cc")
    src = tmp_path / "prog.c"
    src.write_text("#include <stdio.h>\n"
                   "int add(int a, int b)\n{\n    int s = a + b;\n    return s;\n}\n"
                   "int main(void)\n{\n    printf(\"%d\\n\", add(1, 2));\n    return 0;\n}\n")
    exe = tmp_path / "prog"
    assert subprocess.run([cc, "-g", "-O0", str(src), "-o", str(exe)],
                          capture_output=True).returncode == 0
    got = dwarfline.resolve_sites(exe, {("prog.c", 4)})          # the `int s = a + b;` line
    assert ("prog.c", 4) in got and isinstance(got[("prog.c", 4)], int) and got[("prog.c", 4)] > 0
    assert dwarfline.site_addrs(exe, {("prog.c", 4)}) == [got[("prog.c", 4)]]
    # a line with no code (and a missing file) resolve to nothing, never an error
    assert dwarfline.resolve_sites(exe, {("prog.c", 99999), ("absent.c", 1)}) == {}


def test_resolve_sites_empty_request_is_empty(tmp_path):
    assert dwarfline.resolve_sites(tmp_path / "nope", set()) == {}


# ---- _steer_sites (store) ---------------------------------------------------------------------

class _Ctx:
    def __init__(self, conn):
        self.conn = conn


def test_steer_sites_collects_basename_line(store, case):
    from lykos.analyze import source_confirm_stage as SC
    t = TargetDAO(store.conn).upsert(case.id, "t", "a" * 64, arch="source", bits=0)
    FindingDAO(store.conn).upsert(t.id, t.case_id, {
        "cwe": "CWE-190", "title": "ovf", "severity": "high", "detector": "int_overflow",
        "state": "candidate", "confidence": 0.5, "dedup_key": "io:1",
        "evidence": [{"channel": "source", "detail": "core/pdu.c:42: malloc(n * sz)"}]})
    FindingDAO(store.conn).upsert(t.id, t.case_id, {               # non-static detector -> ignored
        "cwe": "CWE-787", "title": "x", "severity": "high", "detector": "heap_trace",
        "state": "candidate", "confidence": 0.5, "dedup_key": "ht:1",
        "evidence": [{"channel": "source", "detail": "other.c:1: ..."}]})
    assert SC._steer_sites(_Ctx(store.conn), t) == [("pdu.c", 42)]


# ---- steering end-to-end ----------------------------------------------------------------------

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
# line 5 is the memcpy -- inside the magic-gated branch, so it is reachable ONLY after the gate solves
_VULN = ('#include <stdint.h>\n#include <string.h>\n'                      # 1,2
         'void parse(const uint8_t *d, unsigned long n) {\n'               # 3
         '  char buf[16];\n'                                               # 4
         '  if (n >= 32 && d[0] == 0x42 && d[1] == 0x43) { memcpy(buf, d, 32);\n'   # 5
         '    __asm__ volatile("" :: "r"(buf) : "memory"); }\n}\n')        # 6,7
_HARNESS = ('#include <stdint.h>\n#include <stddef.h>\n'
            'void parse(const uint8_t *, unsigned long);\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { parse(data, size); return 0; }\n')


def _mk(d):
    (d / "CMakeLists.txt").write_text(_CM)
    (d / "vuln.c").write_text(_VULN)
    (d / "TestFuzzGate.c").write_text(_HARNESS)


def _clang_ok(tmp_path):
    return shutil.which("cmake") and shutil.which("clang") and subprocess.run(
        [shutil.which("clang"), "-fsanitize=fuzzer,address", "-xc", "-", "-o", str(tmp_path / "p.bin")],
        input=b"int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}",
        capture_output=True).returncode == 0


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_driver_resolves_steer_symbols(tmp_path):
    """The driver's explicit function-name steering capability (resolved via the symbol table)."""
    from lykos.analyze import libfuzzer as LF
    from lykos.analyze.symbolic import concolic as C
    py = C.locate_angr_python()
    if py is None or not _clang_ok(tmp_path):
        pytest.skip("angr / clang -fsanitize=fuzzer unavailable")
    de = tmp_path / "explore"
    de.mkdir()
    _mk(de)
    eb = LF.cmake_build_harnesses(de, timeout=180, shared=False, sanitize=False)
    assert eb["ok"], eb["log"][-500:]
    spec = {"binary": str(eb["harnesses"][0]["binary"]), "input_mode": "harness",
            "harness_fn": "LLVMFuzzerTestOneInput", "input_size": 64, "max_seconds": 60,
            "num_find": 8, "target_syms": ["parse", "no_such_function"]}
    res = C.run_explore(py, spec, timeout=90)
    assert res.get("steered_syms") == ["parse"], res.get("steered_syms")


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_concolic_confirm_with_site_steering(tmp_path):
    """Steering to the bug LINE (not the function) still confirms: reaching the memcpy requires the
    gate to be solved, so the site-steered input faults under ASan."""
    from lykos.analyze import libfuzzer as LF
    from lykos.analyze.symbolic import concolic as C
    from lykos.analyze.symbolic import directed_confirm as DC
    if C.locate_angr_python() is None or not _clang_ok(tmp_path):
        pytest.skip("angr / clang -fsanitize=fuzzer unavailable")
    de = tmp_path / "explore"
    de.mkdir()
    _mk(de)
    dr = tmp_path / "replay"
    dr.mkdir()
    _mk(dr)
    eb = LF.cmake_build_harnesses(de, timeout=180, shared=False, sanitize=False)
    rb = LF.cmake_build_harnesses(dr, timeout=180, shared=False, sanitize=True)
    assert eb["ok"] and rb["ok"]
    addrs = dwarfline.site_addrs(eb["harnesses"][0]["binary"], {("vuln.c", 5)})
    assert addrs, "could not resolve the memcpy line to an address (no DWARF line info?)"
    res = DC.concolic_confirm(eb["harnesses"][0]["binary"], rb["harnesses"][0]["binary"],
                              input_size=64, lib_dirs=rb["lib_dirs"],
                              targets=[hex(a) for a in addrs], timeout=120)
    assert res["confirmed"], f"site-steered concolic did not confirm: {res['reason']}"
    assert res["input"] and res["input"][0] == 0x42 and res["input"][1] == 0x43
    assert "stack-buffer-overflow" in (res["report"] or "")
