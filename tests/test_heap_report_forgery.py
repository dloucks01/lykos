"""heap_check's report is EVIDENCE, so a hostile target must not be able to write it.

The shim's report used to be a file in the target's own writable workdir, named in its
environment: any target could append `{"error":"use-after-free",...}` and have a critical
CWE-416 filed against itself. Now the report is an inherited descriptor to a file the target
cannot reach by path or read back, and every genuine line carries a per-run nonce that only the
shim in the target's process holds (delivered over a pipe it consumes -- never the environment,
which the sandbox's pid 1 keeps readable at /proc/1/environ)."""
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import enqueue_heap_check, heap_stage, sandbox
from lykos.analyze.ingest import ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

NONCE = "0123456789abcdef0123456789abcdef"


def test_parse_report_keeps_only_nonced_lines():
    raw = (b'{"loaded":1,"n":"' + NONCE.encode() + b'"}\n'
           b'{"error":"double-free","addr":"0x10","size":32,"func":"free","n":"'
           + NONCE.encode() + b'"}\n'
           # forged: wrong nonce, and no nonce at all
           b'{"error":"use-after-free","addr":"0x41","size":64,"func":"access","n":"deadbeef"}\n'
           b'{"error":"heap-buffer-overflow","addr":"0x42","size":8,"func":"access"}\n')
    loaded, errors, forged = heap_stage.parse_report(raw, NONCE)
    assert loaded
    assert [e["error"] for e in errors] == ["double-free"]
    assert forged == 2


def test_parse_report_unloaded_without_nonced_marker():
    # a forged `loaded` marker does not prove the shim loaded
    loaded, errors, forged = heap_stage.parse_report(b'{"loaded":1,"n":"abcd"}\n', NONCE)
    assert not loaded and not errors


def test_parse_report_partial_line_cannot_swallow_a_genuine_one():
    # the target writes junk with no newline; the shim's real line lands glued onto it
    raw = (b'{"loaded":1,"n":"' + NONCE.encode() + b'"}\n{"error":"junk'
           b'{"error":"double-free","addr":"0x10","size":32,"func":"free","n":"'
           + NONCE.encode() + b'"}\n')
    loaded, errors, _ = heap_stage.parse_report(raw, NONCE)
    assert loaded and [e["error"] for e in errors] == ["double-free"]


# A target that does everything it can to forge: writes heap-error lines to every descriptor it
# has and to the old report path, with whatever nonce it can find in its environment, in the
# sandbox init's environment, or by reading back any descriptor it (or pid 1) holds.
_HOSTILE = r"""
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static char nonce[128];
static void grab(const char *b, long k) {
    for (long i = 0; i + 5 < k; i++) {
        if (!strncmp(b + i, "LYKOS_HEAP_NONCE=", 17) && b[i + 17]) {
            snprintf(nonce, sizeof nonce, "%s", b + i + 17); return; }
        if (!strncmp(b + i, "\"n\":\"", 5)) {
            int j = 0; while (j < 64 && i + 5 + j < k && b[i + 5 + j] != '"') j++;
            if (j) { memcpy(nonce, b + i + 5, j); nonce[j] = 0; return; } }
    }
}
static void scan(const char *path) {
    int f = open(path, O_RDONLY | O_NONBLOCK);
    if (f < 0) return;
    char b[65536]; long k = read(f, b, sizeof b - 1);
    close(f);
    if (k > 0) { b[k] = 0; grab(b, k); }
}
int main(int c, char **v) {
    const char *e = getenv("LYKOS_HEAP_NONCE");
    if (e) snprintf(nonce, sizeof nonce, "%s", e);
    scan("/proc/1/environ"); scan("/proc/self/environ");
    char p[64];
    for (int fd = 0; fd < 64; fd++) {
        snprintf(p, sizeof p, "/proc/1/fd/%d", fd); scan(p);
        snprintf(p, sizeof p, "/proc/self/fd/%d", fd); scan(p);
    }
    char line[512];
    snprintf(line, sizeof line,
             "{\"error\":\"use-after-free\",\"addr\":\"0x41414141\",\"size\":64,"
             "\"func\":\"access\",\"n\":\"%s\"}\n"
             "{\"error\":\"heap-buffer-overflow\",\"addr\":\"0x4242\",\"size\":8,"
             "\"func\":\"access\"}\n", nonce);
    for (int fd = 1; fd < 256; fd++) (void)!write(fd, line, strlen(line));
    int g = open("heap.json", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g >= 0) { (void)!write(g, line, strlen(line)); close(g); }
    if (c > 1 && atoi(v[1]) == 1) { char *q = malloc(32); free(q); free(q); }  /* a REAL bug */
    return 0;
}
"""


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=120, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _heap_findings(store, tid):
    return {f.cwe for f in FindingDAO(store.conn).list_by_target(tid)
            if f.detector == "heap_monitor"}


def _events(store, run_id, kind):
    rows = store.conn.execute("SELECT type, payload_json FROM event WHERE run_id=?",
                              (run_id,)).fetchall()
    import json
    return [json.loads(r[1] or "{}") for r in rows if r[0] == kind]


@pytest.mark.skipif(sandbox.host_arch() != "x86-64" or not shutil.which("cc"),
                    reason="native x86-64 + a C compiler required")
@pytest.mark.parametrize("real_bug", [False, True])
def test_hostile_target_cannot_forge_heap_errors(store, case, pool, gcc, tmp_path, real_bug):
    c = tmp_path / "hostile.c"
    c.write_text(_HOSTILE)
    b = tmp_path / ("hostile_bug" if real_bug else "hostile")
    if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True,
                      check=False).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    q = JobQueue(store.conn)
    run = enqueue_heap_check(q, target, params={"input_mode": "arg",
                                                "argv": ["1" if real_bug else "0"],
                                                "timeout": 12})
    assert pool.wait_idle(40)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("heap stage could not run: " + str(rec.error))
    done = _events(store, run.id, "heap.done")
    assert done and done[-1].get("ok"), done        # the shim DID load (authenticated marker)
    got = _heap_findings(store, target.id)
    # the forged use-after-free / overflow are never filed ...
    assert "CWE-416" not in got and "CWE-122" not in got, got
    # ... a genuine double free still is
    assert ("CWE-415" in got) == real_bug, got
    # and the forgery is reported, not silently dropped
    assert done[-1].get("forged_ignored", 0) >= 1
