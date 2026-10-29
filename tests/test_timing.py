"""analyze.timing: per-technique time + yield and the overall analysis time (one source for the
report's timing section and the GUI's timing panel)."""
from __future__ import annotations

from lykos.analyze.timing import build_timing, format_duration
from lykos.db.dao import DynResultDAO, FindingDAO
from lykos.hashing import hash_bytes


def test_format_duration():
    assert format_duration(0) == "0s"
    assert format_duration(93) == "1m 33s"
    assert format_duration(3671) == "1h 1m 11s"


def test_build_timing_overall_and_per_technique_yield(store, case):
    t = store.targets.upsert(case.id, filename="t", sha256=hash_bytes(b"t"), size=4, arch="x86_64",
                             bits=64, endianness="little", stripped=False, file_type="ELF",
                             linking="dynamic")
    rd = store.runs
    rf = rd.create(case.id, "fuzz", target_id=t.id, status="done")
    rd.set_status(rf.id, "done", started_at=1000, ended_at=1300)        # 300s, no yield
    ri = rd.create(case.id, "int_overflow_scan", target_id=t.id, status="done")
    rd.set_status(ri.id, "done", started_at=1000, ended_at=1010)        # 10s
    rc = rd.create(case.id, "concolic", target_id=t.id, status="done")
    rd.set_status(rc.id, "done", started_at=1010, ended_at=1060)        # 50s
    fd = FindingDAO(store.conn)
    for k in ("io1", "io2"):
        fd.upsert(t.id, case.id, {"dedup_key": k, "cwe": "CWE-190", "title": "o", "severity": "high",
                  "state": "candidate", "detector": "int_overflow", "stage": "int_overflow_scan",
                  "evidence": []})
    DynResultDAO(store.conn).insert(t.id, case.id, run_id=rc.id, input_sha=hash_bytes(b"c"),
                                    input_mode="arg", signal=11, signal_name="SIGSEGV",
                                    crashed=True, isolation="bwrap")

    tm = build_timing(store, case.id)
    ov = tm["overall"]
    assert ov["wall_seconds"] == 300 and ov["compute_seconds"] == 360   # span vs sum (parallel)
    assert ov["wall_human"] == "5m 0s" and ov["runs"] == 3
    assert ov["started_at"].endswith("Z") and ov["ended_at"].endswith("Z")
    assert tm["techniques"][0]["stage"] == "fuzz"                       # dearest first
    by = {d["stage"]: d for d in tm["techniques"]}
    assert by["fuzz"]["findings"] == 0 and by["fuzz"]["crashes"] == 0   # the honest no-yield row
    assert by["int_overflow_scan"]["findings"] == 2
    assert by["concolic"]["findings"] == 0 and by["concolic"]["crashes"] == 1   # crash, no finding
