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
  add_executable(TestFuzzVuln2 TestFuzzVuln2.c)
  target_link_libraries(TestFuzzVuln2 vuln)
  target_link_options(TestFuzzVuln2 PRIVATE -fsanitize=fuzzer,address)
  add_custom_target(fuzzers DEPENDS TestFuzzVuln TestFuzzVuln2)
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


def _write_fixture(d):
    (d / "CMakeLists.txt").write_text(_CMAKELISTS)
    (d / "gen_config.h.in").write_text(_GEN_IN)
    (d / "vuln.c").write_text(_VULN_C)
    (d / "TestFuzzVuln.c").write_text(_HARNESS_C)
    (d / "TestFuzzVuln2.c").write_text(_HARNESS_C)


def _libfuzzer_ok(d):
    """True when this clang can actually link -fsanitize=fuzzer (some ship without the runtime)."""
    import shutil as _sh
    probe = d / "p.c"
    probe.write_text("int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}\n")
    return subprocess.run([_sh.which("clang"), "-fsanitize=fuzzer,address", str(probe),
                           "-o", str(d / "p.bin")], capture_output=True).returncode == 0


@pytest.mark.skipif(not _have("cmake", "clang"), reason="needs cmake + clang")
def test_cmake_build_harness_and_directed_confirm(tmp_path):
    _write_fixture(tmp_path)
    if not _libfuzzer_ok(tmp_path):
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


@pytest.mark.skipif(not _have("cmake", "clang"), reason="needs cmake + clang")
def test_build_libfuzzer_cmake_fallback_and_run(tmp_path):
    """build_libfuzzer falls back to the project's cmake for a cmake project whose in-tree harness the
    per-TU compile cannot build (the generated header is missing), returns the harness binary + its
    shared-lib dirs, and run_libfuzzer loads those libs via LD_LIBRARY_PATH. Seeded with the DIRECTED
    crash input it reproduces the overflow (ASan report) -- the harness is usable by the pipeline."""
    from pathlib import Path as _P
    _write_fixture(tmp_path)
    if not _libfuzzer_ok(tmp_path):
        pytest.skip("this clang cannot link -fsanitize=fuzzer (no libFuzzer runtime)")
    spec = {"kind": "in-tree", "id": "tree-tfv", "entry": "TestFuzzVuln.c",
            "path": tmp_path / "TestFuzzVuln.c", "anchor": None}
    build = libfuzzer.build_libfuzzer(tmp_path, tmp_path / "out.bin", spec=spec, timeout=180)
    assert build["ok"], f"build_libfuzzer cmake fallback failed:\n{build['log'][-1500:]}"
    assert "cmake" in build["harness"], f"expected cmake-built harness, got {build['harness']!r}"
    assert build.get("lib_dirs"), "shared-lib dirs not reported (run would fail to load libvuln.so)"
    assert libfuzzer._is_elf_exec(_P(build["binary"]))
    # seed with the DIRECTED crash -> libFuzzer replays it immediately and ASan faults (deterministic,
    # not a fuzzing-luck dependency); lib_dirs must be honoured or the harness cannot even load.
    res = libfuzzer.run_libfuzzer(build["binary"], tmp_path / "run", seconds=8,
                                  corpus=[b"\x42\xff" + b"A" * 64], lib_dirs=build["lib_dirs"])
    assert res["crashes"], f"seeded directed crash not reproduced:\n{res['log'][-1500:]}"
    assert any("AddressSanitizer" in (c.get("report") or "") for c in res["crashes"])


@pytest.mark.skipif(not _have("cmake", "clang"), reason="needs cmake + clang")
def test_ingest_registers_cmake_harnesses(store, tmp_path):
    """ingest(folder) on a cmake project that ships in-tree harnesses but produces no runnable main
    binary registers the HARNESSES as the case's targets (not a junk gather_bundle pick), archives the
    source tree keyed to them, and records lib_dirs. This is the 'give it a folder' flow working."""
    from lykos.analyze.ingest import ingest
    from lykos.db.dao import ArtifactDAO
    src = tmp_path / "proj"
    src.mkdir()
    _write_fixture(src)
    if not _libfuzzer_ok(tmp_path):
        pytest.skip("this clang cannot link -fsanitize=fuzzer (no libFuzzer runtime)")

    case = store.cases.create("fdp-like")
    t = ingest(store, case.id, src, filename="proj")
    assert t is not None

    # the in-tree harnesses were built via the project's cmake and registered as the case's targets --
    # NOT a junk gather_bundle pick. The primary carries the `filename`; the extra harness is named by
    # its own name, so a harness name appears among the targets.
    names = {x.filename for x in store.targets.list_by_case(case.id)}
    assert "TestFuzzVuln2" in names, f"in-tree harness not registered as a target: {names}"

    # the source tree is archived, keyed to the harness targets, tagged as the cmake-fuzzers build and
    # carrying the shared-lib dirs a runner needs (the definitive signal the harness path fired, not
    # the loose-library fallback).
    arts = [a for a in ArtifactDAO(store.conn).list_by_case(case.id) if a.kind == "source-project"]
    assert arts, "no source-project artifact archived"
    assert any((a.meta or {}).get("build_system") == "cmake-fuzzers" for a in arts), \
        f"harness path did not fire (build_system): {[(a.meta or {}).get('build_system') for a in arts]}"
    assert any((a.meta or {}).get("lib_dirs") for a in arts), \
        f"lib_dirs not recorded: {[a.meta for a in arts]}"


def test_collect_cmake_libraries_picks_bounded_core_libs(tmp_path):
    """The library collector returns the largest few REAL shared libraries (the core libs that
    hold the code), skipping symlinks, sanitizer runtimes and the long tail of small plugins --
    bounded so a project that builds dozens of .so's does not explode into dozens of targets."""
    from lykos.analyze.libfuzzer import _LIB_TARGET_MAX, _collect_cmake_libraries
    bd = tmp_path / "build"
    bd.mkdir()

    def mk(rel, body):
        p = bd / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"\x7fELF" + body)
        return p

    mk("libcore/libcore3.so.3.20", b"A" * 5000)             # largest core lib (versioned real file)
    (bd / "libcore" / "libcore3.so").symlink_to(bd / "libcore" / "libcore3.so.3.20")  # skipped
    mk("libsup/libsupport3.so.3", b"B" * 3000)              # second core lib
    mk("lib/libclang_rt.asan.so", b"D" * 9000)              # sanitizer runtime -> excluded
    for i, nm in enumerate(("liba", "libb", "libc", "libd")):  # small plugins
        mk(f"ch/{nm}.so", bytes([65 + i]) * (50 + i))
    libs = _collect_cmake_libraries(bd)
    names = [os.path.basename(p) for p in libs]
    assert len(libs) <= _LIB_TARGET_MAX
    assert "libcore3.so.3.20" in names and "libsupport3.so.3" in names
    assert not any("clang_rt" in n for n in names)          # sanitizer runtime never a target
    assert not any(p.endswith("/libcore3.so") for p in libs)  # the symlink is not picked
    assert names[0] == "libcore3.so.3.20"                   # largest first
