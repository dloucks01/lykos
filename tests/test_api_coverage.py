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
