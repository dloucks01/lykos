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


def _uc_lead(store, t, fn):
    # exactly the shape uc_stage._file_uc_lead writes: the function name lives only in the
    # uc-symbolic evidence detail ("...execution of <fn>() in isolation..."), not in a struct field.
    FindingDAO(store.conn).upsert(t.id, t.case_id, {
        "cwe": "CWE-94", "title": f"Control flow reaches data-derived pointer in {fn}() "
                                  f"(under-constrained)",
        "severity": "medium", "detector": "uc_symbolic", "state": "candidate", "confidence": 0.3,
        "dedup_key": f"uc:CWE-94:{t.id}:{fn}", "site_detail": fn,
        "evidence": [{"channel": "uc-symbolic",
                      "detail": f"under-constrained symbolic execution of {fn}() in isolation: data "
                                f"the function READ reaches the instruction pointer. CAVEAT: ..."}]})


def test_uc_candidate_functions_recovered_from_uc_leads(store, case, tmp_path):
    """UC control-hijack leads become driver-synthesis candidates (fn, None, None) -- the function
    name recovered from the uc-symbolic evidence detail, with no source line to steer to. This is the
    bridge that lets undriven, static-invisible functions reach the proof ladder."""
    t = TargetDAO(store.conn).upsert(case.id, "t", "b" * 64, arch="source", bits=0)
    _uc_lead(store, t, "decode_frame")
    _uc_lead(store, t, "_internal_helper")          # leading underscore -> runtime/helper, skipped
    cands = SC._uc_candidate_functions(_Ctx(store.conn), t, already=set(), limit=10)
    assert cands == [("decode_frame", None, None)]


def test_uc_candidate_is_deduped_against_a_static_candidate(store, case, tmp_path):
    """A function already offered by a static candidate is NOT re-driven as a UC candidate."""
    t = TargetDAO(store.conn).upsert(case.id, "t", "c" * 64, arch="source", bits=0)
    _uc_lead(store, t, "parse")
    assert SC._uc_candidate_functions(_Ctx(store.conn), t, already={"parse"}, limit=10) == []
    # and a zero/negative remaining budget short-circuits
    assert SC._uc_candidate_functions(_Ctx(store.conn), t, already=set(), limit=0) == []


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


# ---- a candidate function that lives in a PROGRAM's translation unit, beside its main() ----------

_PROG = ("#include <string.h>\n#include <stdio.h>\n"
         "struct rec { char name[16]; void (*h)(const char *); };\n"
         "static void dflt(const char *s) { puts(s); }\n"
         "void dispatch_record(const unsigned char *d, unsigned long n) {\n"        # line 5
         "  struct rec r; r.h = dflt;\n"
         "  if (n < 4 || d[0] != 'R') return;\n"
         "  unsigned len = d[1]; if (len > n - 2) return;\n"
         "  memcpy(r.name, d + 2, len);\n"                                            # line 9: bug
         "  r.h(r.name);\n}\n"
         "int main(int argc, char **argv) { return argc > 5; }\n")


def test_program_unit_function_gets_its_real_signature(tmp_path):
    """A function defined beside main() is not a library entry point, but when it is NAMED for a
    driver its real (buf,len) signature must be found. Without it the harness fell back to
    `void fn(char *)` -- a one-argument call to a two-argument function, whose garbage second
    argument can fault and fabricate a confirmation."""
    from lykos.analyze import libfuzzer as LF
    (tmp_path / "svc.c").write_text(_PROG)
    assert LF.fn_def_file(tmp_path, "dispatch_record") == tmp_path / "svc.c"
    assert LF.fn_params(tmp_path, "dispatch_record") == ["const unsigned char *d", "unsigned long n"]
    assert LF.harness_kind_for(tmp_path, "dispatch_record") == "buflen"
    # ...but the RANKING still treats a program unit as not-the-library
    assert all(p.name != "svc.c" for p, _ in LF._library_srcs(tmp_path))


def test_library_definition_wins_over_a_program_unit_one(tmp_path):
    from lykos.analyze import libfuzzer as LF
    (tmp_path / "lib.c").write_text("int parse(const char *s) { return s[0]; }\n")
    (tmp_path / "tool.c").write_text("int parse(const char *s, int n) { return n; }\n"
                                     "int main(void) { return 0; }\n")
    assert LF.fn_def_file(tmp_path, "parse") == tmp_path / "lib.c"


def test_program_unit_shim_renames_main_and_keeps_the_original_file(tmp_path):
    from lykos.analyze import libfuzzer as LF
    (tmp_path / "svc.c").write_text(_PROG)
    shim = LF._program_unit_shim(tmp_path / "svc.c", [], tmp_path)
    txt = shim.read_text()
    assert f"#define main {LF._PROGRAM_MAIN}" in txt and str((tmp_path / "svc.c").resolve()) in txt
    # already compiled (no main to rename) -> no shim
    assert LF._program_unit_shim(tmp_path / "svc.c", [tmp_path / "svc.c"], tmp_path) is None


@pytest.mark.skipif(not shutil.which("clang"), reason="needs clang for -fsanitize=fuzzer")
def test_synthesized_driver_for_a_program_unit_function_confirms(tmp_path):
    """End to end: the driver links the function out of the program unit (main renamed) and the
    smart-fuzz rung confirms the overflow AT ITS SOURCE LINE in the original file."""
    from lykos.analyze import libfuzzer as LF
    from lykos.analyze.symbolic import directed_confirm as DC
    if subprocess.run([shutil.which("clang"), "-fsanitize=fuzzer,address", "-xc", "-", "-o",
                       str(tmp_path / "p.bin")],
                      input=b"int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}",
                      capture_output=True).returncode:
        pytest.skip("this clang cannot link -fsanitize=fuzzer")
    d = tmp_path / "proj"
    d.mkdir()
    (d / "svc.c").write_text(_PROG)
    b = LF.build_libfuzzer(d, d / "_drv.bin", harness_fn="dispatch_record", timeout=150)
    assert b.get("ok"), (b.get("log") or "")[-500:]
    assert "[buflen]" in b["harness"] and "main() renamed" in b["harness"]
    res = DC.smartfuzz_confirm(b["binary"], lib_dirs=b.get("lib_dirs"), seeds=[b"A" * 64],
                               input_size=256, timeout=90)
    assert res.get("confirmed"), res.get("reason")
    assert "svc.c:9" in (res.get("report") or "")


# ---- a synth_confirm proof links back to the UC lead that prompted it ----------------------------

_REPORT = ("==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x1\n"
           "WRITE of size 48 at 0x1 thread T0\n"
           "    #0 0x5d in __asan_memcpy (/x+0x1)\n"
           "    #1 0x5e in dispatch_record /src/svc.c:9:5\n"
           "    #2 0x5f in LLVMFuzzerTestOneInput /tmp/harness.c:7:5\n\n"
           "Address 0x1 is located in stack of thread T0 at offset 56 in frame\n"
           "    #0 0x60 in other_owner /src/svc.c:3\n")


def test_fn_in_fault_stack_reads_only_the_faulting_stack():
    assert SC._fn_in_fault_stack(_REPORT, "dispatch_record")
    assert not SC._fn_in_fault_stack(_REPORT, "dispatch")          # a prefix is not a frame
    assert not SC._fn_in_fault_stack(_REPORT, "other_owner")       # frame-owner section, not the fault


class _ArtCtx(_Ctx):
    def put_artifact(self, kind, data=b"", **kw):
        return "f" * 64


def test_a_proof_corroborates_its_uc_lead_but_never_confirms_the_hijack(store, case):
    t = TargetDAO(store.conn).upsert(case.id, "t", "9" * 64, arch="source", bits=0)
    _uc_lead(store, t, "dispatch_record")
    ctx = _ArtCtx(store.conn)
    SC._file_confirmed(ctx, t, "dispatch_record",
                       {"report": _REPORT, "input": b"R0AAAA", "class": "stack-buffer-overflow",
                        "source": "svc.c:9"}, from_uc=True)
    fs = FindingDAO(store.conn).list_by_target(t.id)
    lead = next(f for f in fs if f.detector == "uc_symbolic")
    proof = next(f for f in fs if f.detector == "synth_confirm")
    assert proof.state == "confirmed"
    assert any(e.get("channel") == "uc-symbolic" for e in proof.evidence)     # discovery credit
    assert lead.state == "corroborated"                                        # NOT confirmed
    assert any(e.get("channel") == "dynamic-confirm" and "not demonstrated" in e.get("detail", "")
               for e in lead.evidence)


def test_a_fault_outside_the_function_does_not_touch_the_uc_lead(store, case):
    t = TargetDAO(store.conn).upsert(case.id, "t", "8" * 64, arch="source", bits=0)
    _uc_lead(store, t, "decode_frame")
    SC._file_confirmed(_ArtCtx(store.conn), t, "decode_frame",
                       {"report": _REPORT, "input": b"x", "class": "stack-buffer-overflow",
                        "source": "svc.c:9"}, from_uc=True)
    lead = next(f for f in FindingDAO(store.conn).list_by_target(t.id)
                if f.detector == "uc_symbolic")
    assert lead.state == "candidate"


def test_a_driver_proof_replays_against_the_stored_driver(store, case):
    """The proving input crashes the synthesized DRIVER, not the ingested program, so its run is
    tagged like a libFuzzer harness crash -- build_poc then replays against the driver."""
    from lykos.db.dao import DynResultDAO
    t = TargetDAO(store.conn).upsert(case.id, "t", "5" * 64, arch="source", bits=0)
    SC._file_confirmed(_ArtCtx(store.conn), t, "dispatch_record",
                       {"report": _REPORT, "input": b"R0", "class": "stack-buffer-overflow",
                        "source": "svc.c:9"}, driver_sha="ab" * 32)
    runs = DynResultDAO(store.conn).list_by_target(t.id)
    assert runs and runs[0].isolation == "libfuzzer/" + ("ab" * 6)
