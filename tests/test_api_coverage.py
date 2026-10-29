"""The coverage-ledger API endpoint (GET /cases/{id}/coverage) the GUI's dashboard reads."""
from lykos.api.server import serve, shutdown

from tests.test_api import _tcp_json


def test_coverage_endpoint_serves_the_ledger(tmp_path):
    from lykos.casestore import CaseStore
    from lykos.db.dao import FindingDAO

    cspath = tmp_path / "cov-cs"
    servers, pool = serve(cspath, http=("127.0.0.1", 0), workers=1, block=False)
    port = servers[0].server_address[1]
    try:
        _, c = _tcp_json(port, "POST", "/cases", {"name": "cov"})
        s = CaseStore.open(cspath)
        try:
            t = s.targets.upsert(c["id"], "libx.so", "ab" * 32, arch="source", bits=0)
            fd = FindingDAO(s.conn)
            fd.upsert(t.id, c["id"], {"cwe": "CWE-416", "title": "uaf", "severity": "high",
                      "state": "confirmed", "confidence": 0.9, "detector": "uaf",
                      "dedup_key": "k1", "evidence": []})
            fd.upsert(t.id, c["id"], {"cwe": "CWE-78", "title": "cand", "severity": "high",
                      "state": "candidate", "confidence": 0.4, "detector": "source_sink",
                      "dedup_key": "k2", "evidence": []})
        finally:
            s.close()
        st, led = _tcp_json(port, "GET", f"/cases/{c['id']}/coverage")
        assert st == 200 and led.get("schema") == "lykos.coverage-ledger/1"
        assert "checks" in led and "weaponization" in led and "code" in led and "gaps" in led
        assert led["weaponization"]["findings"] == 2 and led["weaponization"]["weaponized"] == 1
        # a bad case id is a 404, not 200 with an empty ledger
        st2, _ = _tcp_json(port, "GET", "/cases/nope/coverage")
        assert st2 == 404
    finally:
        shutdown(servers, pool)


def test_timing_endpoint_serves_per_technique_time_and_yield(tmp_path):
    """GET /cases/{id}/timing: the GUI timing panel's data -- per-technique durations + yield."""
    from lykos.casestore import CaseStore
    from lykos.db.dao import DynResultDAO, FindingDAO

    cspath = tmp_path / "tm-cs"
    servers, pool = serve(cspath, http=("127.0.0.1", 0), workers=1, block=False)
    port = servers[0].server_address[1]
    try:
        _, c = _tcp_json(port, "POST", "/cases", {"name": "tm"})
        s = CaseStore.open(cspath)
        try:
            t = s.targets.upsert(c["id"], "x", "cd" * 32, arch="x86_64", bits=64)
            rf = s.runs.create(c["id"], "fuzz", target_id=t.id, status="done")
            s.runs.set_status(rf.id, "done", started_at=1000, ended_at=1300)   # 300s, no yield
            rc = s.runs.create(c["id"], "concolic", target_id=t.id, status="done")
            s.runs.set_status(rc.id, "done", started_at=1010, ended_at=1060)   # 50s
            FindingDAO(s.conn).upsert(t.id, c["id"], {"cwe": "CWE-787", "title": "b", "severity": "high",
                      "state": "corroborated", "detector": "concolic", "stage": "concolic",
                      "dedup_key": "k1", "evidence": []})
            DynResultDAO(s.conn).insert(t.id, c["id"], run_id=rc.id, input_sha="aa" * 16,
                      input_mode="arg", signal=11, signal_name="SIGSEGV", crashed=True, isolation="bwrap")
        finally:
            s.close()
        st, tm = _tcp_json(port, "GET", f"/cases/{c['id']}/timing")
        assert st == 200
        assert tm["overall"]["wall_seconds"] == 300 and tm["overall"]["compute_seconds"] == 350
        by = {d["stage"]: d for d in tm["techniques"]}
        assert tm["techniques"][0]["stage"] == "fuzz"          # dearest first
        assert by["fuzz"]["findings"] == 0 and by["fuzz"]["crashes"] == 0   # the no-yield technique
        assert by["concolic"]["findings"] == 1 and by["concolic"]["crashes"] == 1
        st2, _ = _tcp_json(port, "GET", "/cases/nope/timing")
        assert st2 == 404
    finally:
        shutdown(servers, pool)
