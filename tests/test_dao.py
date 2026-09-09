"""DM-19 — DAO round-trips, dedup, cache lookup, cascade, pagination."""
import pytest
from factories import make_artifact, make_run, make_target


def test_case_crud(store):
    c = store.cases.create("engagement-x", notes="n", engagement_ref="ENG-1")
    got = store.cases.get(c.id)
    assert got.name == "engagement-x" and got.engagement_ref == "ENG-1"
    assert any(x.id == c.id for x in store.cases.list())


def test_target_upsert_dedup(store, case):
    t1 = make_target(store, case.id, arch="aarch64")
    t2 = make_target(store, case.id, arch="aarch64", bits=64)  # same content hash
    assert t1.id == t2.id  # deduped by (case, sha256)
    reloaded = store.targets.get(t1.id)
    assert reloaded.bits == 64 and reloaded.arch == "aarch64"
    assert len(store.targets.list_by_case(case.id)) == 1


def test_target_json_and_bool_roundtrip(store, case):
    t = make_target(store, case.id, stripped=True,
                    mitigations={"nx": "on", "pie": "on"})
    got = store.targets.get(t.id)
    assert got.stripped is True
    assert got.mitigations == {"nx": "on", "pie": "on"}


def test_artifact_register_idempotent(store, case):
    a1 = make_artifact(store, case.id, data=b"payload")
    a2 = make_artifact(store, case.id, data=b"payload")
    assert a1.sha256 == a2.sha256
    assert len(store.artifacts.list_by_case(case.id)) == 1


def test_run_status_and_cache_lookup(store, case):
    t = make_target(store, case.id)
    run = make_run(store, case.id, target_id=t.id, cache_key="CK", tool_version="lief-0.14")
    assert store.runs.find_cached("CK") is None  # not done yet
    store.runs.set_status(run.id, "running", started_at=1)
    store.runs.set_status(run.id, "done", ended_at=2)
    cached = store.runs.find_cached("CK")
    assert cached is not None and cached.id == run.id


def test_run_artifact_link_and_role_validation(store, case):
    t = make_target(store, case.id)
    run = make_run(store, case.id, target_id=t.id)
    art = make_artifact(store, case.id, data=b"triage")
    store.run_artifacts.link(run.id, art.sha256, "output")
    links = store.run_artifacts.list_by_run(run.id)
    assert len(links) == 1 and links[0].role == "output"
    with pytest.raises(ValueError):
        store.run_artifacts.link(run.id, art.sha256, "bogus")


def test_event_append_and_cursor_pagination(store, case):
    for i in range(5):
        store.events.append("job.log", case_id=case.id, payload={"i": i})
    first_two = store.events.list(case_id=case.id, limit=2)
    assert [e.payload["i"] for e in first_two] == [0, 1]
    after = store.events.list(case_id=case.id, after_id=first_two[-1].id, limit=10)
    assert [e.payload["i"] for e in after] == [2, 3, 4]


def test_event_filter_by_run(store, case):
    run = make_run(store, case.id)
    store.events.append("job.started", case_id=case.id, run_id=run.id)
    store.events.append("job.log", case_id=case.id)  # no run
    only_run = store.events.list(run_id=run.id)
    assert len(only_run) == 1 and only_run[0].type == "job.started"


def test_fk_cascade_delete_case(store):
    c = store.cases.create("to-delete")
    t = make_target(store, c.id)
    run = make_run(store, c.id, target_id=t.id)
    make_artifact(store, c.id, data=b"z")
    store.events.append("job.log", case_id=c.id, run_id=run.id)
    store.cases.delete(c.id)
    assert store.targets.list_by_case(c.id) == []
    assert store.runs.list_by_case(c.id) == []
    assert store.artifacts.list_by_case(c.id) == []
    assert store.events.list(case_id=c.id) == []


def test_target_delete_cascades_and_clears_component_edges(store, case):
    """Deleting a target removes its rows (findings, runs) and any System Map edges that
    touch it, while leaving other targets and their edges intact."""
    from factories import make_run, make_target
    from lykos.db.dao import ComponentEdgeDAO, FindingDAO

    a = make_target(store, case.id, content=b"\x7fELFaaa", file_type="elf")
    b = make_target(store, case.id, content=b"\x7fELFbbb", file_type="elf")
    findings = FindingDAO(store.conn)
    findings.upsert(a.id, case.id, {
        "cwe": "CWE-120", "title": "x", "severity": "high", "detector": "rule",
        "evidence": [], "dedup_key": "k-a", "state": "candidate", "confidence": 0.4})
    findings.upsert(b.id, case.id, {
        "cwe": "CWE-78", "title": "y", "severity": "high", "detector": "rule",
        "evidence": [], "dedup_key": "k-b", "state": "candidate", "confidence": 0.4})
    make_run(store, case.id, target_id=a.id, stage="ingest_triage", status="done")
    edges = ComponentEdgeDAO(store.conn)
    edges.upsert(case.id, a.id, b.id, kind="dynamic-link", symbol="foo")   # a -> b
    edges.upsert(case.id, b.id, a.id, kind="ipc", symbol="mq:/q")          # b -> a
    assert len(edges.list_by_case(case.id)) == 2

    assert store.targets.delete(a.id) is True

    assert store.targets.get(a.id) is None                   # gone
    assert store.targets.get(b.id) is not None               # sibling survives
    assert findings.list_by_target(a.id) == []               # cascaded
    assert len(findings.list_by_target(b.id)) == 1           # untouched
    assert store.runs.list_by_case(case.id) == []            # a's run cascaded
    assert edges.list_by_case(case.id) == []                 # BOTH edges (a in either slot) gone
    assert store.targets.delete(a.id) is False               # idempotent: already gone
