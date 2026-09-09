"""Phase 7 — per-case portable export/import (rows + artifact blobs)."""
from __future__ import annotations

from lykos.casestore import CaseStore
from lykos.db.dao import FindingDAO, PocDAO
from lykos.hashing import hash_bytes


def _seed_case(store, name="engagement"):
    c = store.cases.create(name, notes="scope note")
    content = b"\x7fELF" + name.encode()
    sha = hash_bytes(content)
    t = store.targets.upsert(c.id, filename=f"{name}.bin", sha256=sha, size=len(content),
                             arch="x86_64", bits=64)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, c.id, {"dedup_key": "k1", "cwe": "CWE-121", "title": "overflow",
                           "severity": "high", "state": "poc-backed", "confidence": 0.9,
                           "evidence": [{"channel": "dynamic", "detail": "SIGSEGV"}]})
    f = fd.list_by_target(t.id)[0]
    bundle = store.put_artifact(c.id, "poc-bundle", data=b"BUNDLE-" + name.encode())
    PocDAO(store.conn).insert(t.id, c.id, finding_id=f.id, level="L2", verified=True,
                              bundle_sha=bundle.sha256)
    store.runs.create(c.id, "concolic", target_id=t.id, status="done",
                      tool="angr", tool_version="9.3.4")
    return c, t, bundle.sha256


def test_export_import_roundtrip(tmp_path):
    a = CaseStore.open(tmp_path / "A")
    c, t, bundle_sha = _seed_case(a, "acme")
    arc = a.export_case(c.id, tmp_path / "acme.tar.gz")
    assert arc.exists()
    a.close()

    b = CaseStore.open(tmp_path / "B")
    ids = b.import_archive(arc)
    assert ids == [c.id]
    # case + target present
    assert b.cases.get(c.id).name == "acme"
    tt = b.targets.list_by_case(c.id)
    assert len(tt) == 1 and tt[0].sha256 == t.sha256
    # finding + poc present
    fs = FindingDAO(b.conn).list_by_case(c.id)
    assert fs and fs[0].cwe == "CWE-121"
    pocs = PocDAO(b.conn).list_by_target(tt[0].id)
    assert pocs and pocs[0].level == "L2"
    # artifact blob physically copied and readable
    assert b.content.exists(bundle_sha)
    assert b.content.get_bytes(bundle_sha) == b"BUNDLE-acme"
    b.close()


def test_import_is_idempotent(tmp_path):
    a = CaseStore.open(tmp_path / "A")
    c, _, _ = _seed_case(a, "one")
    arc = a.export_case(c.id, tmp_path / "one.tar.gz")
    a.close()
    b = CaseStore.open(tmp_path / "B")
    b.import_archive(arc)
    b.import_archive(arc)  # second time must not duplicate
    assert len(b.cases.list()) == 1
    assert len(FindingDAO(b.conn).list_by_case(c.id)) == 1
    b.close()


def test_import_merges_alongside_existing(tmp_path):
    a = CaseStore.open(tmp_path / "A")
    c1, _, _ = _seed_case(a, "alpha")
    arc = a.export_case(c1.id, tmp_path / "alpha.tar.gz")
    a.close()
    b = CaseStore.open(tmp_path / "B")
    c2, _, _ = _seed_case(b, "beta")   # b already has its own case
    b.import_archive(arc)
    names = sorted(x.name for x in b.cases.list())
    assert names == ["alpha", "beta"]
    b.close()


def test_export_unknown_case_raises(tmp_path):
    a = CaseStore.open(tmp_path / "A")
    try:
        a.export_case("nope", tmp_path / "x.tar.gz")
        assert False, "expected KeyError"
    except KeyError:
        pass
    finally:
        a.close()
