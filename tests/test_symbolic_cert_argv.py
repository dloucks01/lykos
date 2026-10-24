"""A reachability certificate must name the invocation angr ACTUALLY explored.

The stage used to record the operator's argv (`-c @@`) in the certificate while the angr driver
built its initial state with NO flags -- a certificate vouching for a path under an invocation that
was never explored. Now the flags reach the driver, and the certificate records the argv the driver
echoes back (or says plainly it is not the explored one).
"""
import base64
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from lykos.analyze import register
from lykos.analyze.ingest import ingest
from lykos.analyze.symbolic import enqueue_concolic
from lykos.db.dao import ArtifactDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_DRIVER = Path(__file__).resolve().parents[1] / "core/lykos/analyze/symbolic/angr_driver.py"


def _driver():
    spec = importlib.util.spec_from_file_location("lykos_angr_driver_t", _DRIVER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SYM = object()                                      # stands in for the claripy bitvector


@pytest.mark.parametrize("base,mode,args,shown", [
    ([], "stdin", [], []),
    (["-v"], "stdin", ["-v"], ["-v"]),
    (["-c", "@@"], "stdin", ["-c", "/dev/stdin"], ["-c", "/dev/stdin"]),
    (["-c", "@@", "-v"], "file", ["-c", "/lykos_input", "-v"], ["-c", "@@", "-v"]),
    (["-c"], "file", ["-c", "/lykos_input"], ["-c", "@@"]),
    (["--name"], "arg", ["--name", SYM], ["--name", "@@"]),
    ([], "arg", [SYM], ["@@"]),
])
def test_driver_builds_the_operators_invocation(base, mode, args, shown):
    got_args, got_shown = _driver().build_args(base, mode, SYM)
    assert got_args == args and got_shown == shown


_GATED = ("#include <string.h>\n#include <unistd.h>\n"
          "void handle(char*in){ if(strstr(in,\"OVERFLOWME\")){char s[16];strcpy(s,in);} }\n"
          "int main(void){char b[256];int n=read(0,b,255);if(n<0)n=0;b[n]=0;handle(b);"
          "return 0;}\n")


@pytest.fixture
def gated(gcc, tmp_path_factory):
    import subprocess
    d = tmp_path_factory.mktemp("gated")
    c = d / "g.c"
    c.write_text(_GATED)
    b = d / "g"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    return b


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=120, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _echo_stub(tmp_path, echo_argv: bool):
    """A fake angr interpreter (python): passes the import probe, saves the spec it was given,
    and returns a canned 'reached the sink' result -- echoing spec.argv like the real driver, or
    (an older driver) not reporting it."""
    py = tmp_path / "fake-angr-python"
    seen = tmp_path / "spec-seen.json"
    inp = base64.b64encode(b"OVERFLOWME").decode()
    py.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "if sys.argv[1] == '-c': sys.exit(0)\n"
        "spec = json.load(open(sys.argv[2]))\n"
        f"open({str(seen)!r}, 'w').write(json.dumps(spec))\n"
        f"res = {{'ok': True, 'angr_version': 'stub', 'generated': [{{'input_b64': {inp!r}, "
        "'reached': '0x2020'}], 'reached_targets': ['0x2020'], 'drained': False, "
        "'cutoff': False, 'stats': {}}\n"
        + ("res['argv'] = spec.get('argv')\n" if echo_argv else "")
        + "json.dump(res, open(sys.argv[3], 'w'))\n")
    py.chmod(0o755)
    return py, seen


def _cert(store, pool, case, gated, py, argv):
    target = ingest(store, case.id, gated)
    FindingDAO(store.conn).upsert(target.id, target.case_id, {
        "cwe": "CWE-120", "title": "Unbounded strcpy", "severity": "high",
        "state": "candidate", "confidence": 0.4, "detector": "dangerous_api",
        "function_addr": "0x2000", "site_addr": "0x2020",
        "dedup_key": "CWE-120:0x2000:0x2020:strcpy", "evidence": []})
    q = JobQueue(store.conn)
    run = enqueue_concolic(q, target, params={
        "input_mode": "stdin", "targets": ["0x2020"], "angr_python": str(py),
        "max_seconds": 10, "exec_timeout": 1, "argv": argv})
    assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"
    certs = [a for a in ArtifactDAO(store.conn).list_by_case(case.id)
             if a.kind == "reachability-certificate"]
    assert certs
    return json.loads(store.content.get_bytes(certs[0].sha256))


def test_flags_reach_angr_and_the_certificate_records_the_explored_argv(
        store, case, pool, gated, tmp_path):
    py, seen = _echo_stub(tmp_path, echo_argv=True)
    cert = _cert(store, pool, case, gated, py, ["-v", "--strict"])
    spec = json.loads(seen.read_text())
    assert spec["argv"] == ["-v", "--strict"], "the operator's flags never reached angr"
    assert cert["argv"] == ["-v", "--strict"] and cert["argv_explored"] is True
    # the replayed execution is recorded with its flag prefix, so root_cause/build_poc replay it
    # under the same invocation (argv=[] made a flag-gated crash read "did not fault")
    from lykos.db.dao import DynResultDAO, TargetDAO
    tgt = next(t for t in TargetDAO(store.conn).list_by_case(case.id))
    rows = [d for d in DynResultDAO(store.conn).list_by_target(tgt.id)
            if "concolic-generated" in (d.note or "")]
    assert rows and all(list(d.argv or []) == ["-v", "--strict"] for d in rows)


def test_a_backend_that_does_not_report_its_argv_is_not_certified_as_explored(
        store, case, pool, gated, tmp_path):
    py, _seen = _echo_stub(tmp_path, echo_argv=False)
    cert = _cert(store, pool, case, gated, py, ["-v"])
    assert cert["argv_explored"] is False


def test_real_angr_reaches_a_flag_gated_sink_only_with_the_flag(gcc, tmp_path):
    """Without the flags angr DRAINS without reaching a `-x`-gated sink -- which the stage would
    have annotated 'unreachable' for a site that is reachable under the operator's invocation."""
    import shutil
    import subprocess

    from lykos.analyze.symbolic import concolic
    py = concolic.locate_angr_python()
    if py is None or not shutil.which("nm"):
        pytest.skip("angr / nm not installed")
    src = ("#include <unistd.h>\n#include <string.h>\n"
           "void win(void){ volatile char*p=0; *p=1; }\n"
           "int main(int argc,char**argv){ char b[8]; int n=read(0,b,8);\n"
           " if(argc>1 && strcmp(argv[1],\"-x\")==0 && n>=2 && b[0]=='O' && b[1]=='K') win();"
           " return 0; }\n")
    c = tmp_path / "f.c"
    c.write_text(src)
    b = tmp_path / "f"
    if subprocess.run([gcc, "-O0", "-no-pie", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    nm = subprocess.run(["nm", str(b)], capture_output=True, text=True, check=False).stdout
    win = next(hex(int(ln.split()[0], 16)) for ln in nm.splitlines() if ln.split()[-1] == "win")
    res = concolic.run_explore(py, {"binary": str(b), "input_mode": "stdin", "input_size": 8,
                                    "targets": [win], "max_seconds": 60, "argv": ["-x"]},
                               timeout=60)
    assert win in res["reached_targets"] and res["argv"] == ["-x"]
