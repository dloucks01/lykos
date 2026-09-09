"""Phase 6 — hybrid concolic execution (angr).

angr is an optional bundled tool run in its own interpreter. These tests cover the locator,
the result parser, graceful failure when angr is absent, and the full stage pipeline
(locate -> drive -> validate-in-sandbox -> Confirmed finding) using a *stub* interpreter that
stands in for angr's solver on a real binary. The real-angr exploration runs only when angr
is actually installed (skipped otherwise, matching the Ghidra/AFL++ real-run tests)."""
import base64
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.ingest import ingest
from lykos.analyze.symbolic import concolic, enqueue_concolic, symqemu
from lykos.db.dao import DynResultDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# strcpy overflow reached only when the input contains the magic token -> exactly the kind of
# narrow check a black-box fuzzer stalls on but a concolic solver drives straight to.
_GATED = ("#include <string.h>\n#include <unistd.h>\n"
          "void handle(char*in){ if(strstr(in,\"OVERFLOWME\")){char s[16];strcpy(s,in);} }\n"
          "int main(void){char b[256];int n=read(0,b,255);if(n<0)n=0;b[n]=0;handle(b);"
          "return 0;}\n")


@pytest.fixture
def gated(gcc, tmp_path_factory):
    d = tmp_path_factory.mktemp("gated")
    c = d / "g.c"; c.write_text(_GATED)
    b = d / "g"
    r = subprocess.run([gcc, "-O0", "-fno-stack-protector", str(c), "-o", str(b)],
                       capture_output=True, check=False)
    if r.returncode:
        pytest.skip("build failed")
    return b


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


def _stub_angr(tmp_path, emit_input: bytes, reached="0x2020"):
    """A fake interpreter: `-c import angr` succeeds, and a driver invocation writes a canned
    result whose single generated input is `emit_input`."""
    py = tmp_path / "fake-angr-python"
    b64 = base64.b64encode(emit_input).decode()
    py.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "-c" ]; then exit 0; fi\n'          # import angr check
        f'printf \'{{"ok":true,"angr_version":"stub","generated":'
        f'[{{"input_b64":"{b64}","reached":"{reached}"}}],'
        f'"reached_targets":["{reached}"],"stats":{{"steps":1}}}}\' > "$3"\n')
    py.chmod(0o755)
    return py


# ------------------------------------------------------------------- locator
def test_locate_angr_python_verifies_import(tmp_path, monkeypatch):
    monkeypatch.delenv("LYKOS_ANGR_PYTHON", raising=False)
    good = _stub_angr(tmp_path, b"x")                     # `-c import angr` -> exit 0
    assert concolic.locate_angr_python(str(good)) == good
    bad = tmp_path / "no-angr"
    bad.write_text("#!/bin/sh\nexit 1\n"); bad.chmod(0o755)   # import always fails
    # with a failing candidate and angr absent from the real interpreters, nothing is found
    monkeypatch.setattr(concolic, "_imports_angr",
                        lambda py, timeout=20.0: str(py) == str(bad) and False)
    assert concolic.locate_angr_python(str(bad)) is None


# ------------------------------------------------------------------- result parser
def test_parse_result_ok_and_failures(tmp_path):
    ok = tmp_path / "ok.json"
    ok.write_text('{"ok":true,"generated":[{"input_b64":"QQ=="}]}')
    assert concolic.parse_result(ok)["generated"][0]["input_b64"] == "QQ=="
    bad = tmp_path / "bad.json"
    bad.write_text('{"ok":false,"generated":[],"error":"state explosion"}')
    with pytest.raises(RuntimeError, match="state explosion"):
        concolic.parse_result(bad)
    missing = tmp_path / "m.json"
    missing.write_text('{"ok":true}')
    with pytest.raises(ValueError, match="missing 'generated'"):
        concolic.parse_result(missing)


def test_run_explore_invokes_driver_and_parses(tmp_path):
    py = _stub_angr(tmp_path, b"AAAA")
    res = concolic.run_explore(py, {"binary": "/bin/true", "targets": ["0x2020"]}, timeout=10)
    assert res["ok"] and res["generated"][0]["reached"] == "0x2020"


# ------------------------------------------------------------------- graceful absence
def test_concolic_errors_clearly_when_no_backend(store, case, pool, gated, monkeypatch):
    monkeypatch.setattr(concolic, "locate_angr_python", lambda *a, **k: None)
    monkeypatch.setattr(symqemu, "locate_symqemu", lambda *a, **k: None)
    target = ingest(store, case.id, gated)
    q = JobQueue(store.conn)
    run = enqueue_concolic(q, target, params={"max_seconds": 5})
    assert pool.wait_idle(30)
    rec = q.runs.get(run.id)
    assert rec.status == "error" and "no concolic backend available" in (rec.error or "")


# ------------------------------------------------------------------- full pipeline (stubbed)
def test_concolic_pipeline_confirms_crash_with_stub_solver(store, case, pool, gated, tmp_path):
    """locate -> drive (stub emits a token-bearing overflow input) -> replay in the real
    sandbox -> Confirmed crash finding. Exercises the whole stage minus angr's own solving."""
    py = _stub_angr(tmp_path, b"OVERFLOWME" + b"A" * 80)      # token + overflow the char[16]
    target = ingest(store, case.id, gated)
    q = JobQueue(store.conn)
    run = enqueue_concolic(q, target, params={
        "input_mode": "stdin", "targets": ["0x2020"], "angr_python": str(py),
        "max_seconds": 10, "exec_timeout": 1})
    assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"
    confirmed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
                 if f.state == "confirmed" and f.detector == "concolic"]
    assert confirmed and confirmed[0].cwe in ("CWE-119", "CWE-787")
    assert [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed]


def test_concolic_corroborates_reached_sink_with_stub(store, case, pool, gated, tmp_path):
    """A generated input that reaches a flagged sink WITHOUT crashing promotes the static
    finding to corroborated (second channel agrees the sink is reachable)."""
    py = _stub_angr(tmp_path, b"OVERFLOWME")                  # reaches sink, no overflow
    target = ingest(store, case.id, gated)
    FindingDAO(store.conn).upsert(target.id, target.case_id, {
        "cwe": "CWE-120", "title": "Unbounded strcpy into a buffer", "severity": "high",
        "state": "candidate", "confidence": 0.4, "detector": "dangerous_api",
        "function_addr": "0x2000", "site_addr": "0x2020",
        "dedup_key": "CWE-120:0x2000:0x2020:strcpy", "evidence": []})
    q = JobQueue(store.conn)
    run = enqueue_concolic(q, target, params={
        "input_mode": "stdin", "targets": ["0x2020"], "angr_python": str(py),
        "max_seconds": 10, "exec_timeout": 1})
    assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"
    f = next(x for x in FindingDAO(store.conn).list_by_target(target.id)
             if x.dedup_key == "CWE-120:0x2000:0x2020:strcpy")
    assert f.state == "corroborated"
    assert any(e.get("channel") == "symbolic" for e in f.evidence)



@pytest.mark.skipif(concolic.locate_angr_python() is None, reason="angr not installed")
def test_concolic_real_angr_solves_branch_and_confirms(store, case, pool, gcc, tmp_path):
    """Real angr: solve the 4-byte magic gate so the generated input reaches win() and, when
    replayed concretely in the sandbox, crashes -> a Confirmed concolic finding."""
    if not shutil.which("nm"):
        pytest.skip("nm not available")
    src = ("#include <unistd.h>\n"
           "void win(void){ volatile char*p=0; *p=1; }\n"
           "int main(void){ char b[8]; int n=read(0,b,8); "
           "if(n>=4 && b[0]=='M'&&b[1]=='A'&&b[2]=='G'&&b[3]=='C') win(); return 0; }\n")
    c = tmp_path / "magc.c"; c.write_text(src)
    b = tmp_path / "magc"
    if subprocess.run([gcc, "-O0", "-no-pie", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    nm = subprocess.run(["nm", str(b)], capture_output=True, text=True, check=False).stdout
    win = next((f"0x{ln.split()[0]}" for ln in nm.splitlines()
                if ln.split()[-1] == "win"), None)
    assert win, "could not find win() address"
    target = ingest(store, case.id, b)
    q = JobQueue(store.conn)
    run = enqueue_concolic(q, target, params={
        "backend": "angr", "input_mode": "stdin", "input_size": 8, "targets": [win],
        "max_seconds": 90, "exec_timeout": 2})
    assert pool.wait_idle(150) and q.runs.get(run.id).status == "done"
    confirmed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
                 if f.state == "confirmed" and f.detector == "concolic"]
    assert confirmed, "expected a concolic-confirmed crash from the solved branch"
