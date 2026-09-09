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
