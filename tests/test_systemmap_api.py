"""Phase 8 — System Map API (component graph nodes + edges)."""
from __future__ import annotations

import http.client
import json

import pytest
from lykos.api.server import serve, shutdown
from lykos.casestore import CaseStore
from lykos.db.dao import ComponentEdgeDAO
from lykos.hashing import hash_bytes


@pytest.fixture
def srv(tmp_path):
    cs = tmp_path / "cs"
    servers, pool = serve(cs, http=("127.0.0.1", 0), workers=1, block=False)
    port = servers[0].server_address[1]
    try:
        yield port, cs
    finally:
        shutdown(servers, pool)


def _get(port, url):
    c = http.client.HTTPConnection("127.0.0.1", port)
    try:
        c.request("GET", url)
        r = c.getresponse()
        return r.status, json.loads(r.read())
    finally:
        c.close()


def test_systemmap_nodes_and_edges(srv):
    port, cs = srv
    s = CaseStore(cs)
    c = s.cases.create("multi")
    a = s.targets.upsert(c.id, filename="app", sha256=hash_bytes(b"a"), size=1, arch="x86_64")
    b = s.targets.upsert(c.id, filename="libcfg.so", sha256=hash_bytes(b"b"), size=1,
                         arch="x86_64")
    ComponentEdgeDAO(s.conn).upsert(c.id, a.id, b.id, kind="dynamic-link", symbol="",
                                    detail='{"symbols": ["cfg_get"], "count": 1}')
    s.conn.commit()
    s.close()

    st, doc = _get(port, f"/cases/{c.id}/systemmap")
    assert st == 200
    assert {n["filename"] for n in doc["nodes"]} == {"app", "libcfg.so"}
    assert len(doc["edges"]) == 1
    e = doc["edges"][0]
    assert e["src"] == a.id and e["dst"] == b.id and e["kind"] == "dynamic-link"
    assert e["symbols"] == ["cfg_get"]


def test_systemmap_unknown_case_404(srv):
    port, _ = srv
    st, doc = _get(port, "/cases/nope/systemmap")
    assert st == 404
