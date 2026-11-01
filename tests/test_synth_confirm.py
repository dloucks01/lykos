"""Driver synthesis for proof: synthesize a (buf,size) driver for a candidate's function, build it
with ASan, and prove the bug via the smart-fuzz rung -- the discovery->proof loop for undriven code.
"""
import shutil
import subprocess

import pytest

from lykos.analyze import synth_confirm_stage as SC
from lykos.db.dao import FindingDAO, TargetDAO


class _Ctx:
    def __init__(self, conn):
        self.conn = conn


def test_candidate_functions_from_source_candidates(store, case, tmp_path):
    t = TargetDAO(store.conn).upsert(case.id, "t", "a" * 64, arch="source", bits=0)
    (tmp_path / "pdu.c").write_text(
        "int parse_pdu(const unsigned char *d, unsigned long n)\n{\n"
        "    char b[8];\n    if (n) d++;\n    return 0;\n}\n")
    FindingDAO(store.conn).upsert(t.id, t.case_id, {
        "cwe": "CWE-120", "title": "copy", "severity": "high", "detector": "cpg",
        "state": "candidate", "confidence": 0.6, "dedup_key": "k1",
        "evidence": [{"channel": "source", "detail": "pdu.c:4: strcpy of untrusted data"}]})
    # a non-candidate (already confirmed) finding must NOT be re-driven
    FindingDAO(store.conn).upsert(t.id, t.case_id, {
        "cwe": "CWE-416", "title": "done", "severity": "high", "detector": "uaf",
        "state": "confirmed", "confidence": 0.9, "dedup_key": "k2",
        "evidence": [{"channel": "source", "detail": "pdu.c:5: ..."}]})
    cands = SC._candidate_functions(_Ctx(store.conn), t, tmp_path, limit=10)
    # Now carries the suspected bug SITE (basename, line) alongside the function, for steering.
    assert cands == [("parse_pdu", "pdu.c", 4)]


_VULN = ("#include <stdint.h>\n#include <string.h>\n"
         "void parse(const uint8_t *d, unsigned long n) {\n"
         "  char buf[16];\n"
         "  if (n >= 20) { memcpy(buf, d, n < 64 ? n : 64); __asm__ volatile(\"\" :: \"r\"(buf) : \"memory\"); }\n}\n")


@pytest.mark.skipif(not (shutil.which("clang") or shutil.which("gcc")), reason="needs a C compiler")
def test_synthesized_driver_confirms_the_overflow(tmp_path):
    """build_libfuzzer synthesizes a (buf,size) driver for `parse`, and the smart-fuzz rung confirms
    the overflow under ASan with a negative control -- the proof half of #4."""
    from lykos.analyze import libfuzzer as LF
    from lykos.analyze.symbolic import directed_confirm as DC
    if subprocess.run([shutil.which("clang") or shutil.which("gcc"),
                       "-fsanitize=fuzzer,address", "-xc", "-", "-o", str(tmp_path / "p.bin")],
                      input=b"int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}",
                      capture_output=True).returncode:
        pytest.skip("this compiler cannot link -fsanitize=fuzzer")
    d = tmp_path / "proj"
    d.mkdir()
    (d / "parse.c").write_text(_VULN)
    out = d / "_synthdrv.bin"
    b = LF.build_libfuzzer(d, out, harness_fn="parse", timeout=150)
    assert b.get("ok") and b.get("binary"), f"synthesis/build failed:\n{(b.get('log') or '')[-500:]}"
    assert "synthesized" in (b.get("harness") or "")
    res = DC.smartfuzz_confirm(b["binary"], lib_dirs=b.get("lib_dirs"), seeds=[b"A" * 64],
                               input_size=256, timeout=60)
    assert res.get("confirmed"), f"synthesized-driver confirm failed: {res.get('reason')}"
    assert "overflow" in (res.get("report") or "")


# An overflow gated by a 4-byte MAGIC: blind reach to the function entry is trivial, but reaching
# the memcpy LINE needs the guard solved. Directed concolic reach to the bug line (line 6) solves it;
# the function-entry steer alone would short-circuit at the entry and skip the guard.
_VULN_GUARDED = (
    "#include <stdint.h>\n"                                    # 1
    "#include <string.h>\n"                                    # 2
    "void parse(const uint8_t *d, unsigned long n){\n"         # 3
    "  char buf[16];\n"                                        # 4
    "  if (n >= 20 && d[0]==0xDE && d[1]==0xAD && d[2]==0xBE && d[3]==0xEF){\n"  # 5
    "    memcpy(buf, d, n < 64 ? n : 64);\n"                   # 6  <- bug line
    "    __asm__ volatile(\"\" :: \"r\"(buf) : \"memory\");\n" # 7
    "  }\n}\n")                                                # 8-9


def _angr_ok():
    try:
        from lykos.analyze.symbolic import concolic
        return concolic.locate_angr_python() is not None
    except Exception:
        return False


@pytest.mark.skipif(not shutil.which("clang"), reason="needs clang for -fsanitize=fuzzer")
def test_synth_driver_directed_concolic_reaches_guarded_sink(tmp_path):
    """The synthesized driver is driven through the DIRECTED ladder: the concolic rung steers to the
    bug LINE in the clean EXPLORE build, solves the 4-byte magic guard, and the solved input is
    confirmed under ASan with a negative control -- a library sink reached via a synthesized driver,
    proven without blind fuzzing. (Directed to the line, not the function entry, which any input
    reaches.)"""
    from lykos.analyze import libfuzzer as LF
    from lykos.analyze.symbolic import directed_confirm as DC, dwarfline
    if not _angr_ok():
        pytest.skip("needs the vendored angr venv")
    if subprocess.run([shutil.which("clang"), "-fsanitize=fuzzer", "-xc", "-", "-o",
                       str(tmp_path / "p.bin")],
                      input=b"int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}",
                      capture_output=True).returncode:
        pytest.skip("this clang cannot link -fsanitize=fuzzer")
    d = tmp_path / "proj"
    d.mkdir()
    (d / "parse.c").write_text(_VULN_GUARDED)
    asan = LF.build_libfuzzer(d, d / "_a.bin", harness_fn="parse", timeout=150, sanitize=True)
    clean = LF.build_libfuzzer(d, d / "_c.bin", harness_fn="parse", timeout=150, sanitize=False)
    assert asan.get("ok") and clean.get("ok"), \
        f"build failed asan={asan.get('log','')[-200:]} clean={clean.get('log','')[-200:]}"
    targets = dwarfline.site_addrs(clean["binary"], [("parse.c", 6)])
    assert targets, "could not resolve the bug line to a steering target (needs DWARF)"
    harness = {"name": "synth:parse", "explore_binary": clean["binary"],
               "replay_binary": asan["binary"], "fuzz_binary": asan["binary"],
               "lib_dirs": asan.get("lib_dirs"), "input_size": 64,
               "harness_fn": "LLVMFuzzerTestOneInput", "target_syms": None, "targets": targets,
               "seeds": [b"A" * 64]}
    attempts: list = []
    proven = DC.confirm_ladder([harness], timeout_per=120, attempts_out=attempts)
    assert proven, f"synthesized-driver directed confirm failed; attempts={attempts}"
    # The concolic rung (directed reach) proves it before the smart-fuzz floor is even tried.
    assert proven[0]["rung"] == "concolic", f"expected concolic to prove it, got {proven[0]['rung']}"
    assert "overflow" in (proven[0].get("class") or ""), proven[0]
    assert any(a["rung"] == "concolic" and a["outcome"] == "confirmed" for a in attempts)


@pytest.mark.skipif(not shutil.which("clang"), reason="needs clang for -fsanitize=fuzzer")
def test_clean_explore_build_omits_asan(tmp_path):
    """The EXPLORE build (`sanitize=False`) is the SAME synthesized driver with libFuzzer
    instrumentation only -- no ASan -- so the concolic rung can explore it without being confused by
    ASan's shadow-memory accesses. It builds, links, and (unlike the ASan build) contains no ASan
    runtime, while the ASan build does."""
    from lykos.analyze import libfuzzer as LF
    if subprocess.run([shutil.which("clang"), "-fsanitize=fuzzer", "-xc", "-", "-o",
                       str(tmp_path / "p.bin")],
                      input=b"int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}",
                      capture_output=True).returncode:
        pytest.skip("this clang cannot link -fsanitize=fuzzer")
    d = tmp_path / "proj"
    d.mkdir()
    (d / "parse.c").write_text(_VULN)
    asan = LF.build_libfuzzer(d, d / "_asan.bin", harness_fn="parse", timeout=150, sanitize=True)
    clean = LF.build_libfuzzer(d, d / "_clean.bin", harness_fn="parse", timeout=150, sanitize=False)
    assert asan.get("ok") and clean.get("ok"), \
        f"asan={asan.get('log','')[-200:]} clean={clean.get('log','')[-200:]}"
    syms = subprocess.run(["nm", str(clean["binary"])], capture_output=True, text=True).stdout
    asan_syms = subprocess.run(["nm", str(asan["binary"])], capture_output=True, text=True).stdout
    assert "__asan_init" not in syms, "explore build must not carry the ASan runtime"
    assert "__asan_init" in asan_syms, "confirmation build must carry the ASan runtime"
