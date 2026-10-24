"""Per-attempt fuzz log (fuzz/attempts.py): every execution recorded with how it ENDED, and the
verdict that tells a campaign from an error loop.

The motivating failure: a fuzzer that tried 20,000 times and never got the program to start looked,
from its totals, like a 20,000-execution campaign that found nothing -- the health panel said "ran"
or, at best, "needs a config file". These tests pin the log, the verdicts, and that the real
engines write one line per attempt.
"""
import base64
import gzip
import json
import shutil
import subprocess
import types

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic.sandbox import RunResult
from lykos.analyze.fuzz import aflpp, attempts, envfuzz, health
from lykos.analyze.fuzz.stage import enqueue_fuzz
from lykos.analyze.ingest import ingest
from lykos.db.dao import ArtifactDAO, EventDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


# ------------------------------------------------------------------------------- classification
def test_loader_failure_is_never_started_not_an_error_exit():
    r = RunResult(isolation="bwrap", exit_code=127,
                  stderr=b"./t: error while loading shared libraries: libfoo.so.1: cannot open "
                         b"shared object file: No such file or directory\n")
    assert attempts.classify(r) == "no_start"
    r2 = RunResult(isolation="bwrap", exit_code=1,
                   stderr=b"./t: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.99' not found\n")
    assert attempts.classify(r2) == "no_start"


def test_classify_each_outcome():
    assert attempts.classify(RunResult(isolation="not-runnable")) == "no_start"
    assert attempts.classify(RunResult(isolation="bwrap", crashed=True, signal_name="SIGSEGV")) == "crash"
    assert attempts.classify(RunResult(isolation="bwrap", timed_out=True)) == "timeout"
    assert attempts.classify(RunResult(isolation="bwrap", exit_code=0)) == "clean_exit"
    # A program that prints "No such file" about its OWN input and exits 1 ran; it is not a loader error.
    assert attempts.classify(RunResult(isolation="bwrap", exit_code=1,
                                       stderr=b"cannot open input: No such file or directory")) == "error_exit"


def test_classify_rc_for_bare_return_code_engines():
    assert attempts.classify_rc(None, spawn_failed=True) == "no_start"
    assert attempts.classify_rc(None, timed_out=True) == "timeout"
    assert attempts.classify_rc(-11) == "crash"
    assert attempts.classify_rc(127) == "no_start"
    assert attempts.classify_rc(0) == "clean_exit"
    assert attempts.classify_rc(2) == "error_exit"


# ------------------------------------------------------------------------------------- verdicts
def _tally(**counts):
    t = attempts.Tally()
    for o, n in counts.items():
        for _ in range(n):
            t.add(o, 1 if o == "error_exit" else None, "usage: prog -c config" if o == "error_exit" else "")
    return t


def test_verdict_erroring_quotes_the_error():
    t = attempts.Tally()
    for _ in range(50):
        t.add("no_start", 127, "error while loading shared libraries: libfoo.so.1")
    v, note = t.verdict(progressed=True)            # an error loop whatever else happened
    assert v == attempts.ERRORING
    assert "libfoo.so.1" in note and "50 of 50" in note


def test_rejecting_only_when_nothing_was_reached():
    t = _tally(error_exit=95, clean_exit=5)
    assert t.verdict(progressed=False)[0] == attempts.REJECTING
    assert "usage: prog -c config" in t.verdict(progressed=False)[1]
    # Most mutated inputs are rejected by ANY parser; with coverage climbing that is a campaign.
    assert t.verdict(progressed=True)[0] == attempts.WORKING


def test_timing_out_crashing_all_working_too_few():
    assert _tally(timeout=40).verdict()[0] == attempts.TIMING_OUT
    assert _tally(crash=40).verdict()[0] == attempts.CRASHING_ALL
    assert _tally(clean_exit=30, error_exit=10).verdict()[0] == attempts.WORKING
    assert _tally(clean_exit=3).verdict()[0] == attempts.TOO_FEW


# --------------------------------------------------------------------------------- log round trip
class _Ctx:
    def __init__(self, tmp_path):
        self._tmp = tmp_path
        self.events, self.artifacts = [], {}
        self.run_id = "run-1"

    def scratch(self):
        return self._tmp

    def put_artifact(self, kind, *, src=None, data=None, meta=None):
        b = data if data is not None else open(src, "rb").read()
        sha = "%064x" % (len(self.artifacts) + 1)
        self.artifacts[sha] = (kind, b, meta)
        return sha

    def emit(self, typ, payload=None):
        self.events.append((typ, payload))


def test_log_records_every_attempt_and_reads_back_filtered(tmp_path):
    ctx = _Ctx(tmp_path)
    log = attempts.AttemptLog(ctx, "fuzz", "fuzz", unit="blocks", target_id="t1")
    log.record_result(b"seed1", RunResult(isolation="bwrap", exit_code=0), phase="seed", new=5)
    for i in range(30):
        log.record_result(bytes([i]) * 4, RunResult(isolation="bwrap", exit_code=1,
                                                    stderr=b"bad magic\n"), phase="mutate")
    log.record_result(b"AAAA", RunResult(isolation="bwrap", exit_code=None, crashed=True,
                                         signal_name="SIGSEGV"), phase="mutate", new=3, kept=True)
    out = log.finish()
    assert out["attempts"] == 32 and out["counts"]["error_exit"] == 30
    assert out["value"]["seed_coverage"] == 5 and out["value"]["gained"] == 3
    assert ("fuzz.attempts", out) in ctx.events
    kind, blob, meta = ctx.artifacts[out["log"]]
    assert kind == attempts.LOG_KIND and meta["engine"] == "fuzz" and meta["target_id"] == "t1"
    lines = gzip.decompress(blob).decode().splitlines()
    assert json.loads(lines[0])["log"] == "lykos-fuzz-attempts"
    assert len(lines) == 33                          # header + one line per attempt
    row = json.loads(lines[-1])
    assert row["o"] == "crash" and row["sig"] == "SIGSEGV" and row["kept"] and row["new"] == 3
    assert row["head"] == b"AAAA".hex() and len(row["in"]) == 16

    rd = attempts.read_log(blob, outcome="crash")
    assert rd["total"] == 32 and rd["matched"] == 1 and rd["rows"][0]["o"] == "crash"
    rd2 = attempts.read_log(blob, errors_only=True, offset=10, limit=5)
    assert rd2["matched"] == 31 and len(rd2["rows"]) == 5 and rd2["rows"][0]["i"] == 12
    assert rd2["summary"]["counts"] == out["counts"]
    assert attempts.read_log(blob, phase="seed")["matched"] == 1


# ------------------------------------------------------------------------------------- health
def _health(stage, evs, state="done"):
    return health.summarize([{"stage": stage, "state": state, "detail": ""}], evs)


def test_health_marks_an_error_loop_failed_with_the_real_error():
    att = {"engine": "fuzz", "attempts": 900, "counts": {"no_start": 900},
           "verdict": "erroring", "verdict_note": "900 of 900 attempts never reached the program -- "
           "exit 127, “error while loading shared libraries: libfoo.so.1”", "log": "ab" * 32,
           "value": {"unit": "behaviours", "seed_coverage": 1, "gained": 0}}
    r = _health("fuzz", [{"type": "fuzz.done", "payload": {"execs": 900, "crashes": 0}},
                         {"type": "fuzz.attempts", "payload": att}])
    e = r["engines"][0]
    assert e["status"] == health.FAILED and "libfoo.so.1" in e["reason"]
    assert e["outcomes"] == {"no_start": 900} and e["log"] == "ab" * 32


def test_health_no_gain_when_mutation_reached_nothing_new():
    att = {"engine": "fuzz", "attempts": 5000, "counts": {"clean_exit": 5000}, "verdict": "working",
           "verdict_note": "", "value": {"unit": "blocks", "seed_coverage": 40, "gained": 0}}
    r = _health("fuzz", [{"type": "fuzz.done", "payload": {"execs": 5000, "crashes": 0}},
                         {"type": "fuzz.attempts", "payload": att}])
    assert r["engines"][0]["status"] == health.NO_GAIN
    assert r["verdict"] == "idle" and "did not test anything new" in r["note"]
    # ...but a crash found means it earned its time, gain or not.
    r2 = _health("fuzz", [{"type": "fuzz.done", "payload": {"execs": 5000, "crashes": 2}},
                          {"type": "fuzz.attempts", "payload": att}])
    assert r2["engines"][0]["status"] == health.OK


def test_health_reads_directed_and_boundary_under_their_real_prefixes():
    r = _health("directed_fuzz", [{"type": "directed.done", "payload": {"execs": 1234}}])
    assert r["engines"][0]["execs"] == 1234
    r = _health("boundary_fuzz", [{"type": "harness.done", "payload": {"execs": 77}}])
    assert r["engines"][0]["execs"] == 77


def test_health_not_applicable_is_declined_not_ran():
    r = _health("env_fuzz", [{"type": "env_fuzz.done",
                              "payload": {"applicable": False, "note": "no getenv"}}])
    assert r["engines"][0]["status"] == health.DECLINED


# ----------------------------------------------------------------------------------------- AFL
def test_afl_saved_entries_and_plot_series(tmp_path):
    q = tmp_path / "default" / "queue"
    q.mkdir(parents=True)
    (q / "id:000000,time:0,execs:0,orig:seed0").write_bytes(b"a")
    (q / "id:000001,src:000000,time:812,execs:4410,op:havoc,rep:2,+cov").write_bytes(b"bb")
    rows = aflpp.saved_entries(tmp_path, "queue")
    assert [m.get("id") for _f, m in rows] == ["000000", "000001"]
    assert rows[1][1]["op"] == "havoc" and rows[1][1]["cov"] is True and rows[1][1]["execs"] == 4410
    (tmp_path / "default" / "plot_data").write_text(
        "# relative_time, cycles_done, cur_item, corpus_count, pending_total, pending_favs, "
        "map_size, saved_crashes, saved_hangs, max_depth, execs_per_sec, total_execs, edges_found\n"
        "1, 0, 0, 2, 2, 1, 1.20%, 0, 0, 1, 900.0, 900, 31\n"
        "9, 0, 1, 5, 2, 1, 2.40%, 0, 0, 2, 950.0, 8000, 64\n")
    s = aflpp.plot_series(tmp_path)
    assert s[0]["edges_found"] == 31 and s[-1]["edges_found"] == 64 and s[0]["map_size"] == 1.2


# ------------------------------------------------------------------------------------- env fuzz
def test_env_runner_tells_timeout_from_spawn_failure(tmp_path):
    """Also the regression for the flat RLIMIT_NPROC=64 this runner used: it counts every process
    the user runs, so on a desktop every fork failed ("Cannot fork") and a script target -- or any
    program that calls system()/popen() -- errored on every single attempt."""
    sh = shutil.which("sh")
    if not sh:
        pytest.skip("no sh")
    hang = tmp_path / "hang.sh"
    hang.write_text("#!/bin/sh\nsleep 5\n")
    hang.chmod(0o755)
    d = envfuzz._run_with_env_detail(str(hang), [], {}, timeout=0.3)
    assert d["timed_out"] and not d["spawn_failed"] and d["rc"] is None
    d2 = envfuzz._run_with_env_detail(str(tmp_path / "missing"), [], {}, timeout=1)
    assert d2["spawn_failed"]
    err = tmp_path / "err.sh"
    err.write_text("#!/bin/sh\necho 'need FOO_HOME' >&2\nexit 3\n")
    err.chmod(0o755)
    d3 = envfuzz._run_with_env_detail(str(err), [], {}, timeout=2)
    assert d3["rc"] == 3 and b"need FOO_HOME" in d3["stderr"]
    seen = []
    envfuzz.fuzz_env(str(err), ["FOO_HOME"], max_execs=12, timeout=2,
                     on_attempt=lambda data, det, ph, ov: seen.append((ph, det["rc"], sorted(ov))))
    assert len(seen) >= 12 and all(rc == 3 for _ph, rc, _ov in seen)
    assert seen[0][0] == "seed" and seen[0][2] == ["FOO_HOME"]


# ------------------------------------------------------------------- real campaigns, end to end
_OK = "#include <unistd.h>\nint main(){char b[64];int n=read(0,b,63);if(n>2&&b[0]=='x')return 2;return 0;}\n"
_REJECT = ('#include <stdio.h>\n#include <unistd.h>\nint main(){char b[64];read(0,b,63);'
           'fprintf(stderr,"usage: prog -c <config>\\n");return 1;}\n')
_LIB = "int helper(int x){return x+1;}\n"
_USES_LIB = "#include <unistd.h>\nint helper(int);\nint main(){char b[8];read(0,b,8);return helper(0)-1;}\n"


@pytest.fixture(scope="module")
def progs(gcc, tmp_path_factory):
    d = tmp_path_factory.mktemp("attempt_bins")
    out = {}
    for name, src in (("ok", _OK), ("reject", _REJECT)):
        c = d / f"{name}.c"
        c.write_text(src)
        if subprocess.run([gcc, "-O0", str(c), "-o", str(d / name)], capture_output=True).returncode == 0:
            out[name] = d / name
    # A program linked against a shared library that is then removed: the loader refuses it on
    # every single execution -- the error loop.
    (d / "lib.c").write_text(_LIB)
    (d / "main.c").write_text(_USES_LIB)
    ok = subprocess.run([gcc, "-shared", "-fPIC", str(d / "lib.c"), "-o", str(d / "liblykosgone.so")],
                        capture_output=True).returncode == 0
    ok = ok and subprocess.run([gcc, str(d / "main.c"), "-L", str(d), "-llykosgone", "-o",
                                str(d / "noload")], capture_output=True).returncode == 0
    if ok:
        (d / "liblykosgone.so").unlink()
        out["noload"] = d / "noload"
    return out


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=60, poll_interval=0.02, heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _events(store, case_id):
    return list(EventDAO(store.conn).walk(case_id=case_id))


def _last(store, case_id, typ):
    evs = [e for e in _events(store, case_id) if e.type == typ]
    assert evs, f"no {typ} event"
    return evs[-1].payload


def _attempts_event(store, case_id, prefix="fuzz"):
    return _last(store, case_id, f"{prefix}.attempts")


def _run_fuzz(store, case, pool, path, **params):
    target = ingest(store, case.id, path)
    q = JobQueue(store.conn)
    p = {"input_mode": "stdin", "max_execs": 120, "max_seconds": 15, "exec_timeout": 1,
         "seeds": [base64.b64encode(b"hello").decode()]}
    p.update(params)
    run = enqueue_fuzz(q, target, params=p)
    assert pool.wait_idle(60) and q.runs.get(run.id).status == "done"
    return target


def test_a_working_campaign_logs_every_attempt(store, case, pool, progs):
    if "ok" not in progs:
        pytest.skip("build failed")
    _run_fuzz(store, case, pool, progs["ok"])
    att = _attempts_event(store, case.id)
    done = _last(store, case.id, "fuzz.done")
    assert att["verdict"] == attempts.WORKING
    blob = store.content.get_bytes(att["log"])
    rd = attempts.read_log(blob, limit=100000)
    # one line per execution the campaign counted (seeds + mutations + any minimize/reproduce)
    assert rd["total"] == done["execs"] == att["attempts"]
    assert {r["ph"] for r in rd["rows"]} >= {"seed", "mutate"}
    assert done["attempts"]["verdict"] == attempts.WORKING
    arts = [a for a in ArtifactDAO(store.conn).list_by_case(case.id) if a.kind == attempts.LOG_KIND]
    assert arts and arts[0].meta["engine"] == "fuzz"


def test_an_error_loop_is_named_as_one_with_the_loader_message(store, case, pool, progs):
    if "noload" not in progs:
        pytest.skip("build failed")
    _run_fuzz(store, case, pool, progs["noload"])
    att = _attempts_event(store, case.id)
    assert att["verdict"] == attempts.ERRORING, att
    assert "liblykosgone.so" in att["verdict_note"]
    fh = health.summarize([{"stage": "fuzz", "state": "done", "detail": ""}],
                          [{"type": e.type, "payload": e.payload} for e in _events(store, case.id)])
    eng = fh["engines"][0]
    assert eng["status"] == health.FAILED and "liblykosgone.so" in eng["reason"]


def test_a_target_rejecting_every_input_is_named_with_its_message(store, case, pool, progs):
    if "reject" not in progs:
        pytest.skip("build failed")
    _run_fuzz(store, case, pool, progs["reject"])
    att = _attempts_event(store, case.id)
    assert att["verdict"] == attempts.REJECTING, att
    assert "usage: prog -c <config>" in att["verdict_note"]
    done = _last(store, case.id, "fuzz.done")
    assert "usage: prog -c <config>" in (done.get("starved_reason") or "")


# --------------------------------------------------------------------------------- API and CLI
def _stored_log(tmp_path):
    from lykos.casestore import CaseStore
    ctx = _Ctx(tmp_path)
    log = attempts.AttemptLog(ctx, "fuzz", "fuzz", target_id="t1")
    for i in range(25):
        log.record_result(bytes([i]), RunResult(isolation="bwrap", exit_code=127,
                          stderr=b"error while loading shared libraries: libx.so"), phase="mutate")
    out = log.finish()
    _kind, blob, meta = ctx.artifacts[out["log"]]
    store = CaseStore.open(tmp_path / "cs")
    case = store.cases.create("c")
    sha, rel, size = store.content.put_bytes(blob)
    ArtifactDAO(store.conn).register(sha, case.id, attempts.LOG_KIND, rel, size=size, meta=meta)
    return store, case, sha


def test_api_serves_filtered_attempts_and_lists_logs(tmp_path):
    from lykos.api.server import serve, shutdown
    from test_api import _tcp
    store, case, sha = _stored_log(tmp_path)
    store.close()
    servers, p = serve(tmp_path / "cs", http=("127.0.0.1", 0), workers=1, block=False)
    port = servers[0].server_address[1]
    try:
        st, body = _tcp(port, "GET", f"/artifacts/{sha}/attempts?outcome=no_start&limit=10")
        assert st == 200, body[:200]
        d = json.loads(body)
        assert d["total"] == 25 and d["matched"] == 25 and len(d["rows"]) == 10
        assert d["summary"]["verdict"] == attempts.ERRORING
        st, body = _tcp(port, "GET", f"/cases/{case.id}/attempt-logs")
        assert st == 200
        logs = json.loads(body)
        assert logs[0]["sha256"] == sha and logs[0]["engine"] == "fuzz" and logs[0]["verdict"] == "erroring"
    finally:
        shutdown(servers, p)


def test_cli_fuzz_log_prints_every_attempt(tmp_path, capsys):
    from lykos import cli
    store, _case, sha = _stored_log(tmp_path)
    store.close()
    ns = types.SimpleNamespace(case_store=str(tmp_path / "cs"), engine="fuzz", target=None, log=None,
                               list=False, outcome=None, phase=None, errors_only=False, offset=0,
                               limit=200, json=False)
    assert cli._cmd_fuzz_log(ns) == 0
    out = capsys.readouterr().out
    assert "verdict erroring" in out and "libx.so" in out
    rows = [ln for ln in out.splitlines() if ln[:7].strip().isdigit()]
    assert len(rows) == 25 and all(" no_start " in ln for ln in rows)
