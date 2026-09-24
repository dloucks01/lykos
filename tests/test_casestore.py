"""DM-19 — content store integrity + case export/import round-trip (DM-18)."""
from lykos.casestore import CaseStore
from lykos.hashing import hash_bytes


def test_content_store_put_get_integrity(store, case):
    data = b"triage-json-bytes"
    art = store.put_artifact(case.id, "triage-json", data=data)
    assert art.sha256 == hash_bytes(data)
    assert store.content.exists(art.sha256)
    assert store.content.get_bytes(art.sha256) == data


def test_put_artifact_from_file(store, case, tmp_path):
    p = tmp_path / "blob"
    p.write_bytes(b"file-content")
    art = store.put_artifact(case.id, "target-blob", src=p)
    assert store.content.get_bytes(art.sha256) == b"file-content"


def test_export_import_roundtrip(store, tmp_path):
    c = store.cases.create("portable")
    art = store.put_artifact(c.id, "triage-json", data=b"{\"k\":1}")
    store.targets.upsert(c.id, "s.bin", hash_bytes(b"s.bin"), arch="ppc")

    archive = store.export(tmp_path / "case.tar.gz")
    store.close()

    dest = tmp_path / "imported"
    reopened = CaseStore.import_(archive, dest)
    try:
        cases = reopened.cases.list()
        assert any(x.name == "portable" for x in cases)
        cid = next(x.id for x in cases if x.name == "portable")
        # rows preserved
        assert reopened.targets.list_by_case(cid)[0].arch == "ppc"
        # artifact blob preserved + intact
        assert reopened.content.get_bytes(art.sha256) == b"{\"k\":1}"
    finally:
        reopened.close()


def test_delete_case_that_shares_a_cached_artifact(store):
    """A cross-case cache hit links case B's run to case A's artifact ROW (sha256 is global).
    Deleting A must not raise IntegrityError (the artifact is re-homed to B, its live referrer),
    and B's link must survive."""
    a = store.cases.create("owner")
    b = store.cases.create("consumer")
    art = store.put_artifact(a.id, "triage-json", data=b"shared-cache-bytes")
    conn = store.conn
    conn.execute("INSERT INTO analysis_run(id,case_id,stage,status,created_at) VALUES(?,?,?,?,?)",
                 ("runB", b.id, "detect_cwe", "done", 0))
    conn.execute("INSERT INTO run_artifact(run_id,artifact_sha256,role) VALUES(?,?,?)",
                 ("runB", art.sha256, "output"))

    store.cases.delete(a.id)                      # previously raised IntegrityError

    assert store.cases.get(a.id) is None
    row = conn.execute("SELECT case_id FROM artifact WHERE sha256=?", (art.sha256,)).fetchone()
    assert row is not None and row["case_id"] == b.id     # re-homed to B, link intact
