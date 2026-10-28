"""The patch_diff stage: localize the function that changed between two builds and file it as a
steerable lead (the diff->drive N-day loop). Previously patchdiff was CLI print-only; this proves
it now runs as a pipeline stage and produces a finding the directed/concolic search steers at."""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.analyze.patch_diff_stage import enqueue_patch_diff
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# Two builds: parse() is the function that CHANGES (the "patch"); main() is identical. The patched
# build adds a bounds check + an extra call, so parse()'s fingerprint differs while everything else
# matches -- exactly the signal patchdiff keys on.
_OLD = r"""
#include <string.h>
#include <stdio.h>
void parse(const char *s){ char b[64]; strcpy(b, s); puts(b); }
int main(int c, char **v){ if (c > 1) parse(v[1]); return 0; }
"""
_NEW = r"""
#include <string.h>
#include <stdio.h>
void parse(const char *s){ char b[64]; size_t n = strlen(s); if (n >= sizeof b) n = sizeof b - 1;
  memcpy(b, s, n); b[n] = 0; fprintf(stderr, "len=%zu\n", n); puts(b); }
int main(int c, char **v){ if (c > 1) parse(v[1]); return 0; }
"""


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _build(gcc, tmp_path, name, src):
    c = tmp_path / f"{name}.c"; c.write_text(src)
    out = tmp_path / name
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-O0", "-w", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    return out


def test_patch_diff_localizes_the_changed_function(store, case, pool, gcc, tmp_path):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("disassembly backend is host-arch bound here")
    old = _build(gcc, tmp_path, "old", _OLD)
    new = _build(gcc, tmp_path, "new", _NEW)
    a = ingest(store, case.id, old, filename="old")      # baseline
    b = ingest(store, case.id, new, filename="new")       # the build to analyse
    q = JobQueue(store.conn)
    for t in (a, b):
        enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
        enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
    enqueue_patch_diff(q, b, params={"baseline_target_id": a.id}, force=True)
    assert pool.wait_idle(120)

    leads = [f for f in FindingDAO(store.conn).list_by_target(b.id) if f.detector == "patch_diff"]
    assert leads, "patch_diff filed no changed-function lead on an obviously-changed function"
    # the changed function is parse(); main() did not change -> must NOT be a lead
    assert any("parse" in (f.title or "") for f in leads), "the changed function parse() was not localized"
    assert not any("main" in (f.title or "") for f in leads), "main() did not change; must not be flagged"
    # a lead carries a function address so the directed/concolic search can steer at it
    assert all(f.function_addr for f in leads)
    # doc 49 Theme 4 figure 5: each lead ALSO carries structured patch-diff data (not just the
    # prose line), so the report draws the patch-diff map from numbers, never by re-parsing text.
    import json as _json
    for f in leads:
        pdm = next((e for e in (f.evidence or []) if e.get("channel") == "patch-diff-map"), None)
        assert pdm, "patch_diff lead is missing the structured patch-diff-map evidence"
        data = _json.loads(pdm["detail"])
        assert data.get("name") and isinstance(data.get("moved"), int)
        assert isinstance(data.get("blocks"), list) and isinstance(data.get("insns"), list)
