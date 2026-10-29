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
    names = SC._candidate_functions(_Ctx(store.conn), t, tmp_path, limit=10)
    assert names == ["parse_pdu"]


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
