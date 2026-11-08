"""The weaponization-backlog API endpoint (GET /cases/{id}/backlog) the GUI's Backlog tab reads.

The live mirror of the report's backlog section: findings lykos hasn't yet carried to a validated
PoC, grouped by the technique to build next. Same `ceiling_ledger` source the report uses, so the
two can never disagree.
"""
from lykos.api.server import serve, shutdown

from tests.test_api import _tcp_json


def _ceiling_ev(level, why, needs):
    # The forward, stored machine marker an emitter records on a lead (recipe-ceiling channel).
    return [{"channel": "recipe-ceiling",
             "detail": f"lykos reached {level} here; next technique to carry it further: "
                       f"{why} [needs: {needs}]"}]


def test_backlog_endpoint_serves_the_ledger(tmp_path):
    from lykos.casestore import CaseStore
    from lykos.db.dao import FindingDAO

    cspath = tmp_path / "bk-cs"
    servers, pool = serve(cspath, http=("127.0.0.1", 0), workers=1, block=False)
    port = servers[0].server_address[1]
    try:
        _, c = _tcp_json(port, "POST", "/cases", {"name": "bk"})
        s = CaseStore.open(cspath)
        try:
            t = s.targets.upsert(c["id"], "vuln", "ab" * 32, arch="x86_64", bits=64)
            fd = FindingDAO(s.conn)
            # Two OOB-write findings that share one technique to build (so it groups, advances:2)...
            fd.upsert(t.id, c["id"], {"cwe": "CWE-787", "title": "oob write A", "severity": "high",
                      "state": "corroborated", "confidence": 0.5, "detector": "oob",
                      "dedup_key": "k1", "evidence": _ceiling_ev("L2", "drove the OOB write",
                      "a reaching driver plus the write-target layout")})
            fd.upsert(t.id, c["id"], {"cwe": "CWE-787", "title": "oob write B", "severity": "high",
                      "state": "corroborated", "confidence": 0.5, "detector": "oob",
                      "dedup_key": "k2", "evidence": _ceiling_ev("L2", "drove the OOB write",
                      "a reaching driver plus the write-target layout")})
            # ...and one format-leak finding with a different technique (critical -> ranks first).
            fd.upsert(t.id, c["id"], {"cwe": "CWE-134", "title": "fmt leak", "severity": "critical",
                      "state": "corroborated", "confidence": 0.5, "detector": "fmt",
                      "dedup_key": "k3", "evidence": _ceiling_ev("L2", "leaked a base",
                      "a wider multi-read format leak to anchor the live frame")})
            # A finding with NO ceiling marker must not appear in the backlog.
            fd.upsert(t.id, c["id"], {"cwe": "CWE-476", "title": "npd", "severity": "low",
                      "state": "candidate", "confidence": 0.3, "detector": "x",
                      "dedup_key": "k4", "evidence": []})
        finally:
            s.close()

        st, led = _tcp_json(port, "GET", f"/cases/{c['id']}/backlog")
        assert st == 200
        assert led["count"] == 3                       # the three with a ceiling, not the npd
        assert "not a limit of the target" in led["framing"]      # never a clearance / wall
        # Ranked best-ROI-first: the critical format-leak before the high OOB writes.
        assert led["entries"][0]["cwe"] == "CWE-134"
        assert led["entries"][0]["missing_technique"].startswith("a wider multi-read")
        # Grouped by technique: the OOB-write build advances both of its findings.
        bycap = {t["missing_technique"]: t["advances"] for t in led["techniques"]}
        assert bycap["a reaching driver plus the write-target layout"] == 2
        assert bycap["a wider multi-read format leak to anchor the live frame"] == 1

        # An empty case is a 200 shell (distinct from a missing case), never 200-with-nothing wall.
        _, c2 = _tcp_json(port, "POST", "/cases", {"name": "empty"})
        st2, led2 = _tcp_json(port, "GET", f"/cases/{c2['id']}/backlog")
        assert st2 == 200 and led2["count"] == 0 and led2["entries"] == []
        assert "not a limit of the target" in led2["framing"]
        # A missing case is a 404.
        st3, _ = _tcp_json(port, "GET", "/cases/nope/backlog")
        assert st3 == 404
    finally:
        shutdown(servers, pool)
