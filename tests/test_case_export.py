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


def test_export_import_roundtrips_sites_and_verdicts(tmp_path):
    """finding_site and finding_verdict have no case_id -- they hang off finding(id). If the
    export plan omits them, an imported case loses which sites are proven and every channel's
    standing verdict (the loss migration 12's seed guards against)."""
    a = CaseStore.open(tmp_path / "A")
    c = a.cases.create("proof")
    sha = hash_bytes(b"\x7fELFproof")
    t = a.targets.upsert(c.id, filename="p.bin", sha256=sha, size=8)
    fd = FindingDAO(a.conn)
    fd.upsert(t.id, c.id, {"dedup_key": "k", "cwe": "CWE-125", "title": "oob",
                           "severity": "low", "state": "candidate", "confidence": 0.3,
                           "detector": "rules", "channel": "rules",
                           "function_addr": "0x1000", "site_addr": "0x1010",
                           "site_state": "candidate"})
    fd.upsert(t.id, c.id, {"dedup_key": "k", "cwe": "CWE-125", "title": "oob",
                           "severity": "high", "state": "poc-backed", "confidence": 0.95,
                           "detector": "dynamic", "channel": "dynamic",
                           "function_addr": "0x1000", "site_addr": "0x1010",
                           "site_state": "poc-backed"})
    f = fd.list_by_target(t.id)[0]
    assert fd.proven_sites(t.id) == {f.id: 1}
    assert {v["channel"] for v in fd.verdicts(f.id)} == {"rules", "dynamic"}
    arc = a.export_case(c.id, tmp_path / "proof.tar.gz")
    a.close()

    b = CaseStore.open(tmp_path / "B")
    b.import_archive(arc)
    fdb = FindingDAO(b.conn)
    fb = fdb.list_by_case(c.id)[0]
    assert fdb.proven_sites(fb.target_id) == {fb.id: 1}      # per-site proof survived
    assert len(fdb.sites(fb.id)) >= 1
    assert {v["channel"] for v in fdb.verdicts(fb.id)} == {"rules", "dynamic"}   # verdicts too
    b.close()


def test_reimport_of_a_changed_row_warns_and_stays_add_only(tmp_path):
    """Import is add-only (INSERT OR IGNORE): a row that CHANGED in the source is skipped and
    the destination keeps its old copy. That must be surfaced, not swallowed."""
    import warnings

    a = CaseStore.open(tmp_path / "A")
    c, t, _ = _seed_case(a, "acme")
    arc1 = a.export_case(c.id, tmp_path / "v1.tar.gz")
    f = FindingDAO(a.conn).list_by_case(c.id)[0]
    a.conn.execute("UPDATE finding SET title=? WHERE id=?", ("CHANGED", f.id))
    arc2 = a.export_case(c.id, tmp_path / "v2.tar.gz")
    a.close()

    b = CaseStore.open(tmp_path / "B")
    b.import_archive(arc1)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        b.import_archive(arc2)                       # v2's finding differs -> conflict
    assert any("stale row" in str(x.message) for x in w)
    # add-only kept the ORIGINAL row, never overwrote it
    assert FindingDAO(b.conn).list_by_case(c.id)[0].title == "overflow"
    b.close()
