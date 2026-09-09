"""Phase 8 (doc 17.1/17.2) — cross-binary import/export resolution + component graph."""
from __future__ import annotations

import subprocess

import pytest

from lykos.analyze import register
from lykos.analyze.elf import parse
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.analyze.link import enqueue_link
from lykos.analyze.link.resolve import resolve_case, symbol_resolution
from lykos.db.dao import ComponentEdgeDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


@pytest.fixture(scope="module")
def linked_bins(gcc, tmp_path_factory):
    """A shared library exporting cfg_get + a program importing it."""
    d = tmp_path_factory.mktemp("link")
    (d / "cfg.c").write_text("int cfg_get(int k){return k+1;}\n")
    (d / "main.c").write_text(
        "extern int cfg_get(int);\nint main(){return cfg_get(41);}\n")
    so = d / "libcfg.so"
    if subprocess.run([gcc, "-shared", "-fPIC", str(d / "cfg.c"), "-o", str(so)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build shared lib")
    exe = d / "app"
    if subprocess.run([gcc, str(d / "main.c"), "-o", str(exe), "-L", str(d), "-lcfg"],
                      capture_output=True, env={"PATH": "/usr/bin:/bin"}).returncode != 0:
        pytest.skip("cannot link program")
    return {"so": so, "app": exe}


def test_elf_captures_import_export_names(linked_bins):
    lib = parse(linked_bins["so"].read_bytes())
    app = parse(linked_bins["app"].read_bytes())
    assert "cfg_get" in lib.exported_symbols
    assert "cfg_get" in app.imported_symbols
    assert "cfg_get" not in app.exported_symbols     # app imports, does not export it
    assert "cfg_get" not in lib.imported_symbols     # lib defines, does not import it


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _triage_both(store, case, pool, bins):
    q = JobQueue(store.conn)
    for key in ("so", "app"):
        t = ingest(store, case.id, bins[key])
        enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)


def test_resolve_case_links_importer_to_exporter(store, case, pool, linked_bins):
    _triage_both(store, case, pool, linked_bins)
    res = symbol_resolution(store.conn, store.content, case.id)
    # exactly one pair: app -> libcfg over cfg_get
    pairs = res["pairs"]
    assert any("cfg_get" in syms for syms in pairs.values()), pairs

    summary = resolve_case(store.conn, store.content, case.id, persist=True)
    assert summary["components"] == 2
    assert summary["edges"] >= 1
    edges = ComponentEdgeDAO(store.conn).list_by_case(case.id)
    assert edges and edges[0].kind == "dynamic-link"
    # the edge points from the app (importer) to the lib (exporter)
    tmap = {t.id: t.filename for t in store.targets.list_by_case(case.id)}
    e = edges[0]
    assert tmap[e.src_target] == "app" and tmap[e.dst_target] == "libcfg.so"


def test_resolve_is_idempotent(store, case, pool, linked_bins):
    _triage_both(store, case, pool, linked_bins)
    resolve_case(store.conn, store.content, case.id, persist=True)
    n1 = ComponentEdgeDAO(store.conn).count_by_case(case.id)
    resolve_case(store.conn, store.content, case.id, persist=True)
    n2 = ComponentEdgeDAO(store.conn).count_by_case(case.id)
    assert n1 == n2 and n1 >= 1


def test_link_stage_via_queue(store, case, pool, linked_bins):
    _triage_both(store, case, pool, linked_bins)
    q = JobQueue(store.conn)
    run = enqueue_link(q, case.id)
    assert pool.wait_idle(20) and q.runs.get(run.id).status == "done"
    assert ComponentEdgeDAO(store.conn).count_by_case(case.id) >= 1


def test_empty_case_resolves_to_nothing(store, case):
    summary = resolve_case(store.conn, store.content, case.id, persist=True)
    assert summary == {"components": 0, "edges": 0, "resolved_symbols": 0, "pairs": []}
