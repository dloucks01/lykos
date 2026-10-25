"""The operator scans as stages (variant_scan, weggli_scan, diff_test) -- the GUI's route to what was
CLI-only. Each reuses what the case already holds and labels its results as candidates."""
import io
import shutil
import subprocess
import tarfile
from types import SimpleNamespace

import pytest
from lykos.analyze import register, scan_stages
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

gcc = shutil.which("gcc")
need_gcc = pytest.mark.skipif(not gcc, reason="needs a C compiler")


def _ctx(store, case_id, tmp_path, *, target_id=None, params=None):
    events = []
    scratch = tmp_path / "scratch"
    scratch.mkdir(exist_ok=True)
    return SimpleNamespace(conn=store.conn, content=store.content, case_id=case_id,
                           target_id=target_id, params=params or {}, run_id=None,
                           scratch=lambda: scratch, check_cancel=lambda: None,
                           progress=lambda pct=None, msg=None: None, events=events,
                           emit=lambda type, level="info", payload=None:
                               events.append((type, level, payload)))


def _build(tmp_path, name, src, *flags):
    c = tmp_path / f"{name}.c"
    c.write_text(src)
    out = tmp_path / name
    r = subprocess.run([gcc, "-O0", "-fno-stack-protector", *flags, str(c), "-o", str(out)],
                       capture_output=True)
    if r.returncode:
        pytest.skip("cannot build the fixture")
    return out


# ------------------------------------------------------------------------------- diff_test
STRICT = r'''
#include <stdio.h>
#include <unistd.h>
int main(void){ char b[64]; ssize_t n = read(0, b, sizeof b);
  if(n > 0 && b[0] == 'X') { puts("reject"); return 2; } puts("ok"); return 0; }
'''
LENIENT = r'''
#include <stdio.h>
#include <unistd.h>
int main(void){ char b[64]; ssize_t n = read(0, b, sizeof b); (void)n; puts("ok"); return 0; }
'''


@need_gcc
def test_diff_test_reports_where_two_implementations_disagree(store, case, tmp_path):
    a = ingest(store, case.id, _build(tmp_path, "strict", STRICT), filename="strict")
    b = ingest(store, case.id, _build(tmp_path, "lenient", LENIENT), filename="lenient")
    seed = tmp_path / "seed"
    seed.write_bytes(b"X")
    ctx = _ctx(store, case.id, tmp_path, params={"target_ids": [a.id, b.id], "iterations": 40,
                                                 "seed_files": [str(seed)], "timeout": 3})
    out = scan_stages.diff_test_stage(ctx)
    assert out["applicable"] and out["compared"] and out["execs"] > 0
    assert out["discrepancies"], out
    assert any(set(p) for d in out["discrepancies"] for p in d["partitions"].values())
    assert ctx.events[-1][0] == "diff_test.done"


def test_diff_test_needs_two_targets_from_this_case(store, case, tmp_path):
    other = store.cases.create("other")
    t = store.targets.upsert(other.id, "x", "ab" * 32, file_type="elf", arch="x86_64")
    out = scan_stages.diff_test_stage(_ctx(store, case.id, tmp_path,
                                           params={"target_ids": [t.id, "nope"]}))
    assert out["applicable"] is False and "2+" in out["note"]


@need_gcc
def test_diff_test_stops_at_its_time_budget_and_says_so(store, case, tmp_path):
    a = ingest(store, case.id, _build(tmp_path, "strict", STRICT), filename="strict")
    b = ingest(store, case.id, _build(tmp_path, "lenient", LENIENT), filename="lenient")
    out = scan_stages.diff_test_stage(_ctx(store, case.id, tmp_path, params={
        "target_ids": [a.id, b.id], "iterations": 100000, "max_seconds": 0.5}))
    assert out["stopped"] == "time budget reached" and "stopped early" in out["note"]
    assert out["execs"] < 100000


# ----------------------------------------------------------------------------- weggli_scan
VULN_SRC = r'''
#include <string.h>
void copy_name(char *dst, const char *src) { strcpy(dst, src); }
int main(int argc, char **argv) { char b[8]; if (argc > 1) copy_name(b, argv[1]); return 0; }
'''


def _source_tree(store, case_id, files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    store.put_artifact(case_id, "source-project", data=buf.getvalue(), meta={"binary_sha": "x"})


def test_weggli_scan_declines_without_a_source_tree(store, case, tmp_path):
    t = store.targets.upsert(case.id, "x", "ab" * 32, file_type="elf", arch="x86_64")
    out = scan_stages.weggli_scan_stage(_ctx(store, case.id, tmp_path, target_id=t.id))
    assert out["applicable"] is False and "source" in out["note"]


def test_weggli_scan_files_candidate_findings(store, case, tmp_path):
    from lykos.analyze import weggli
    if weggli.weggli_bin() is None:
        pytest.skip("weggli not installed")
    t = store.targets.upsert(case.id, "x", "ab" * 32, file_type="elf", arch="x86_64")
    _source_tree(store, case.id, {"proj/main.c": VULN_SRC})
    out = scan_stages.weggli_scan_stage(_ctx(store, case.id, tmp_path, target_id=t.id))
    assert out["applicable"] and out["findings"], out
    assert all(not f.startswith("/") for r in out["findings"] for f in r["files"])
    fs = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "weggli"]
    assert fs and all(f.state == "candidate" for f in fs)


# ----------------------------------------------------------------------------- variant_scan
FN = r'''
#include <string.h>
#include <unistd.h>
int parse_header(char *out, const char *in, int n) {
  int i, sum = 0;
  for (i = 0; i < n; i++) { out[i] = in[i] ^ 0x5a; sum += out[i]; if (in[i] == 0) break; }
  if (sum > 1000) memcpy(out, in, n);
  return sum;
}
'''
MAIN_A = FN + r'''
int main(void){ char in[64], out[64]; int n = read(0, in, 64); return parse_header(out, in, n) & 1; }
'''
MAIN_B = FN + r'''
int helper(int x){ return x * 3; }
int main(void){ char in[32], out[32]; int n = read(0, in, 32); return helper(parse_header(out, in, n)); }
'''
OTHER = r'''
#include <stdio.h>
int main(int c, char **v){ printf("%d\n", c); return 0; }
'''


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


@need_gcc
def test_variant_scan_finds_the_function_in_another_build(store, case, pool, tmp_path):
    from lykos.analyze import native_re
    if not native_re.locate_native():
        pytest.skip("needs the native RE backend")
    ref = ingest(store, case.id, _build(tmp_path, "a", MAIN_A), filename="a")
    var = ingest(store, case.id, _build(tmp_path, "b", MAIN_B), filename="b")
    other = ingest(store, case.id, _build(tmp_path, "c", OTHER), filename="c")
    q = JobQueue(store.conn)
    for t in (ref, var, other):
        enqueue_triage(q, t, force=True)
    assert pool.wait_idle(60)
    for t in (ref, var, other):
        enqueue_disassemble(q, t, force=True)
    assert pool.wait_idle(240)
    out = scan_stages.variant_scan_stage(_ctx(store, case.id, tmp_path, target_id=ref.id,
                                              params={"function": "parse_header"}))
    assert out["applicable"], out
    by = {r["filename"]: r for r in out["results"]}
    assert by["b"]["hits"] and by["b"]["hits"][0]["similarity"] >= 0.9
    assert not by["c"]["hits"] and by["c"]["scanned"]
    missing = scan_stages.variant_scan_stage(_ctx(store, case.id, tmp_path, target_id=ref.id,
                                                  params={"function": "no_such_fn"}))
    assert missing["applicable"] is False and "no function named" in missing["note"]


def test_variant_scan_says_not_scanned_rather_than_clean(store, case, tmp_path):
    ref = store.targets.upsert(case.id, "ref", "ab" * 32, file_type="elf", arch="x86_64")
    out = scan_stages.variant_scan_stage(_ctx(store, case.id, tmp_path, target_id=ref.id,
                                              params={"function": "f"}))
    assert out["applicable"] is False and "disassemble" in out["note"]
