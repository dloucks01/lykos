"""End-to-end: the source_confirm STAGE drives the non-fuzzing confirmation ladder from a source
target. A cmake project ships a parser with a stack overflow behind a 2-byte magic gate and an in-tree
libFuzzer harness. ingest() registers the harness as a target (+ archives the tree); source_confirm
materializes the tree, builds the clean + ASan static harnesses, runs the ladder (concolic rung solves
the gate), and files a CONFIRMED finding + a DynResult the exploit ladder can see -- a proven,
non-fuzzing PoC with a reproducing input."""
import shutil
import time

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
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/gen.h.in ${CMAKE_CURRENT_BINARY_DIR}/gen.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_library(vuln vuln.c)
if(BUILD_FUZZERS)
  add_executable(TestFuzzGate TestFuzzGate.c)
  target_link_libraries(TestFuzzGate vuln)
  target_compile_options(TestFuzzGate PRIVATE -fsanitize=fuzzer-no-link)
  target_link_options(TestFuzzGate PRIVATE -fsanitize=fuzzer)
  add_custom_target(fuzzers DEPENDS TestFuzzGate)
endif()
"""
_VULN = ('#include <stdint.h>\n#include <string.h>\n#include "gen.h"\n'
         'void parse(const uint8_t *d, unsigned long n) {\n'
         '  char buf[16];\n'
         '  if (n >= 32 && d[0] == 0x42 && d[1] == 0x43) { memcpy(buf, d, 32);\n'
         '    __asm__ volatile("" :: "r"(buf) : "memory"); }\n}\n')
_HARNESS = ('#include <stdint.h>\n#include <stddef.h>\n'
            'void parse(const uint8_t *, unsigned long);\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { parse(data, size); return 0; }\n')


def _mk(d):
    d.mkdir(parents=True, exist_ok=True)
    (d / "CMakeLists.txt").write_text(_CM)
    (d / "gen.h.in").write_text("#define OK 1\n")
    (d / "vuln.c").write_text(_VULN)
    (d / "TestFuzzGate.c").write_text(_HARNESS)


@pytest.mark.skipif(not (shutil.which("cmake") and shutil.which("clang")), reason="needs cmake + clang")
def test_source_confirm_stage_files_confirmed_poc(store, tmp_path):
    import subprocess
    from lykos.analyze import register
    from lykos.analyze.ingest import ingest
    from lykos.analyze.source_confirm_stage import enqueue_source_confirm
    from lykos.analyze.symbolic import concolic as C
    from lykos.db.dao import DynResultDAO, FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    if C.locate_angr_python() is None:
        pytest.skip("angr not available")
    if subprocess.run([shutil.which("clang"), "-fsanitize=fuzzer,address", "-xc", "-",
                       "-o", str(tmp_path / "p.bin")],
                      input=b"int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}",
                      capture_output=True).returncode:
        pytest.skip("this clang cannot link -fsanitize=fuzzer")

    proj = tmp_path / "proj"
    _mk(proj)
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("sc").id, proj, filename="proj")
        run = enqueue_source_confirm(JobQueue(store.conn), t, params={"max_seconds": 240,
                                                                      "input_size": 64})
        assert pool.wait_idle(600) and JobQueue(store.conn).runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)

    finds = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "source_confirm"]
    assert finds, "source_confirm filed no confirmed finding"
    assert any(f.state == "confirmed" for f in finds)
    assert any("overflow" in (f.title or "") for f in finds), f"titles={[f.title for f in finds]}"
    # a DynResult the exploit ladder can see, carrying the reproducing input
    drs = [d for d in DynResultDAO(store.conn).list_by_target(t.id)
           if (d.defect_key or "").startswith("source_confirm")]
    assert drs and drs[0].crashed and drs[0].input_sha
    # ...tagged with the HARNESS that proved it, stored, so build_poc replays there and not
    # against the ingested program
    assert (drs[0].isolation or "").startswith("libfuzzer/"), drs[0].isolation
    prefix = drs[0].isolation.split("/", 1)[1]
    assert any(a.kind == "libfuzzer-harness" and a.sha256.startswith(prefix)
               for a in store.artifacts.list_by_case(t.case_id))


def test_the_build_phase_shares_one_deadline_and_the_ladder_takes_what_remains(store, tmp_path,
                                                                               monkeypatch):
    """Regression for the wedge on a huge tree (FreeRDP): the stage must bound its TOTAL wall-clock,
    not give each of four builds its own timeout*4 deadline. Pin that every build gets the SAME
    absolute `deadline`, and that when the build phase spends the budget the ladder is SKIPPED
    rather than started with time it cannot finish in."""
    from lykos.analyze import libfuzzer as LF
    from lykos.analyze.symbolic import directed_confirm as DC
    from lykos.analyze import source_confirm_stage as SC
    from lykos.analyze.ingest import ingest

    proj = tmp_path / "proj"
    _mk(proj)
    t = ingest(store, store.cases.create("scbudget").id, proj, filename="proj")

    from types import SimpleNamespace
    deadlines, ladder_kw = [], []
    monkeypatch.setattr(SC, "_materialize_source", lambda ctx, target: proj)
    monkeypatch.setattr(LF, "find_harnesses", lambda root, limit=1: [proj / "h.c"])

    def fake_build(sleep, root, *, shared, sanitize, timeout, deadline=None, **kw):
        deadlines.append(deadline)
        time.sleep(sleep)
        return {"ok": True, "log": "", "lib_dirs": [],
                "harnesses": [{"name": "h", "source": str(proj / "h.c"), "binary": str(proj / "h")}]}
    monkeypatch.setattr(DC, "confirm_ladder", lambda *a, **k: ladder_kw.append(dict(k)) or [])

    # (1) tiny budget spent by the builds -> the ladder is SKIPPED, and the builds SHARE one deadline
    monkeypatch.setattr(LF, "cmake_build_harnesses", lambda *a, **k: fake_build(0.4, *a, **k))
    SC.source_confirm_stage(SimpleNamespace(conn=store.conn, target_id=t.id, params={"max_seconds": 1},
                                            emit=lambda *a, **k: None, progress=lambda **k: None))
    built = [d for d in deadlines if d is not None]
    assert built and len(set(built)) == 1, f"builds must share ONE deadline, got {deadlines}"
    assert not ladder_kw, "ladder ran despite the budget being spent on builds"

    # (2) ample budget, instant builds -> the ladder RUNS and is handed a hard overall deadline
    deadlines.clear()
    monkeypatch.setattr(LF, "cmake_build_harnesses", lambda *a, **k: fake_build(0.0, *a, **k))
    SC.source_confirm_stage(SimpleNamespace(conn=store.conn, target_id=t.id, params={"max_seconds": 120},
                                            emit=lambda *a, **k: None, progress=lambda **k: None))
    assert ladder_kw, "ladder did not run on an ample budget"
    assert ladder_kw[-1].get("deadline") is not None, "ladder must get a hard overall deadline"


def test_in_surface_memory_findings_get_a_nonfuzzing_recipe(store):
    """Non-fuzzing-first: an in-surface memory-corruption finding whose srctaint is NOT provably
    strong (the FreeRDP case -- multi-layer flow) still earns a reachability-grounded recipe, so the
    engagement carries a deliverable without any fuzzing. Off-surface findings do not."""
    from types import SimpleNamespace
    from lykos.analyze import source_confirm_stage as SC
    from lykos.db.dao import FindingDAO, TargetDAO
    c = store.cases.create("surf")
    t = TargetDAO(store.conn).upsert(c.id, "t", "d" * 64)
    fd = FindingDAO(store.conn)
    # a CWE-190 in a file ON the fuzzed surface, and a CWE-787 OFF it -- both merely `candidate`
    fd.upsert(t.id, c.id, {"cwe": "CWE-190", "title": "int-overflow alloc", "severity": "medium",
              "detector": "int_overflow", "state": "candidate", "confidence": 0.45,
              "dedup_key": "io:on", "evidence": [{"channel": "source", "detail": "geometry.c:120: realloc()"}]})
    fd.upsert(t.id, c.id, {"cwe": "CWE-787", "title": "oob write", "severity": "medium",
              "detector": "oob_write", "state": "candidate", "confidence": 0.45,
              "dedup_key": "ow:off", "evidence": [{"channel": "source", "detail": "buildtool.c:9: arr[i]="}]})
    ctx = SimpleNamespace(conn=store.conn, put_artifact=lambda *a, **k: "x" * 64)
    ranked = SC._rank_by_surface(ctx, t, {"geometry.c"})     # only geometry.c is on the surface
    assert ranked["in_surface"] == 1 and ranked["off_surface"] == 1
    assert ranked["surface_recipes"] == 1                    # the in-surface CWE-190, not the off one
    recs = [f for f in fd.list_by_target(t.id) if f.detector == "surface_recipe"]
    assert len(recs) == 1 and recs[0].cwe == "CWE-190" and recs[0].state == "corroborated"


# ---- a confirmation is replayed against the binary that proved it ------------------------------
def test_the_ladder_names_the_binary_each_rung_proved_on():
    from lykos.analyze.symbolic.directed_confirm import _rung_binary
    h = {"explore_binary": "/e", "replay_binary": "/r", "fuzz_binary": "/f"}
    assert _rung_binary(h, "concolic") == "/r"
    assert _rung_binary(h, "template") == "/r"
    assert _rung_binary(h, "smart-fuzz") == "/f"
    assert _rung_binary({"fuzz_binary": "/f"}, "template") == "/f"


def test_a_confirmation_is_stored_as_its_own_replay_harness(tmp_path):
    """source_confirm tagged its proofs `source_confirm/<name>`, which no replay path reads, so the
    PoC was replayed against the ingested PROGRAM and every bundle shipped unverified."""
    from types import SimpleNamespace as NS
    from lykos.analyze.source_confirm_stage import _replay_harness
    b = tmp_path / "h_static"
    b.write_bytes(b"\x7fELF-static-asan-harness")
    stored = {}

    class Ctx:
        def put_artifact(self, kind, data=b"", meta=None):
            stored[kind] = (data, meta)
            return "ab" * 32
    iso, libs = _replay_harness(Ctx(), NS(sha256="t" * 64),
                                {"harness": "fuzz_x", "binary": str(b), "lib_dirs": ["/lib/x"],
                                 "input": b"A"}, {"fuzz_x": str(b)})
    assert iso == "libfuzzer/" + ("ab" * 6)
    assert libs == []                                    # the static build needs no .so dirs
    assert stored["libfuzzer-harness"][0] == b.read_bytes()
    assert stored["libfuzzer-harness"][1]["lib_dirs"] == []


def test_uc_leads_steer_the_concolic_rung_to_their_function(store, tmp_path):
    """The from-entry half of a UC lead: steer concolic from the harness's real entry to the
    function UC flagged, so a proof need not assume its arguments are attacker-controlled."""
    from types import SimpleNamespace as NS
    from lykos.analyze.source_confirm_stage import _uc_sites
    from lykos.db.dao import FindingDAO, TargetDAO
    (tmp_path / "lib.c").write_text("#include <string.h>\n\nstatic int x;\n"
                                    "void dispatch_record(const unsigned char *d,\n"
                                    "                     unsigned long n)\n{\n  (void)d; (void)n;\n}\n")
    c = store.cases.create("u")
    t = TargetDAO(store.conn).upsert(c.id, "t", "e" * 64)
    FindingDAO(store.conn).upsert(t.id, c.id, {
        "cwe": "CWE-94", "title": "Control flow reaches data-derived pointer in dispatch_record() "
        "(under-constrained)", "severity": "medium", "detector": "uc_symbolic",
        "state": "candidate", "confidence": 0.4, "dedup_key": "uc:x", "evidence": []})
    assert _uc_sites(NS(conn=store.conn), t, tmp_path) == [("lib.c", 4)]
    assert _uc_sites(NS(conn=store.conn), t, None) == []
