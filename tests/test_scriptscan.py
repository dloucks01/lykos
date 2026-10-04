"""Interpreted-script source detection (scriptscan): a dangerous sink is a candidate; an untrusted
source reaching it (directly or via a one-hop tainted variable) makes it corroborated. Covers
PHP / Python / JavaScript / Ruby, and the detect_cwe route that fires for a script target."""
import tempfile
from pathlib import Path

from lykos.analyze.detect import scriptscan as S

_PHP = (b"<?php\n$cmd=$_GET['c'];\nsystem($cmd);\n"
        b"mysqli_query($db,\"SELECT * FROM u WHERE id=\".$_POST['id']);\n"
        b"include($_GET['page']);\neval($_REQUEST['x']);\nsystem(\"ls -la\");\n")
_PY = (b"import os, subprocess, pickle, sys\nu = sys.argv[1]\nos.system('ping '+u)\n"
       b"subprocess.run('echo '+u, shell=True)\npickle.loads(request.data)\nopen('/safe/path')\n")
# NOTE: child_process.exec(...) (explicit), not an aliased `cp.exec(...)`: a bare `.exec(` is
# RegExp.prototype.exec far more often than a shell call, so scriptscan deliberately requires the
# child_process receiver (see the CWE-78 pattern) to avoid flagging every regex in the wild.
_JS = (b"const child_process=require('child_process');\nlet u=req.query.cmd;\n"
       b"child_process.exec('ls '+u);\n"
       b"eval(req.body.code);\ndb.query(`SELECT * FROM t WHERE id=${req.params.id}`);\n")


def _by_cwe(findings):
    return {(f["cwe"], f["state"]) for f in findings}


def test_php_sinks_and_source_corroboration():
    got = _by_cwe(S.scan(_PHP, "php"))
    assert ("CWE-78", "corroborated") in got        # system($cmd), $cmd tainted from $_GET
    assert ("CWE-89", "corroborated") in got        # mysqli_query with $_POST concat
    assert ("CWE-98", "corroborated") in got        # include($_GET[...])
    assert ("CWE-95", "corroborated") in got        # eval($_REQUEST[...])
    # the hardcoded system("ls -la") must NOT be corroborated by an unrelated earlier source
    assert ("CWE-78", "candidate") in got


def test_python_sinks_and_taint():
    got = _by_cwe(S.scan(_PY, "python"))
    assert ("CWE-78", "corroborated") in got        # os.system / subprocess shell=True with argv
    assert ("CWE-502", "corroborated") in got       # pickle.loads(request.data)
    assert ("CWE-22", "candidate") in got           # open('/safe/path') hardcoded -> lead only


def test_javascript_sinks_and_taint():
    got = _by_cwe(S.scan(_JS, "javascript"))
    assert ("CWE-78", "corroborated") in got        # cp.exec('ls '+u)
    assert ("CWE-95", "corroborated") in got        # eval(req.body.code)
    assert ("CWE-89", "corroborated") in got        # db.query(template literal with req.params)


def test_js_regex_exec_is_not_command_injection():
    """A bare `.exec(` is RegExp.prototype.exec, not a shell call -- it must NOT be CWE-78 (this FP
    flagged all of jQuery as critical command injection). child_process's own calls still fire."""
    regexy = b"var m = /ab+c/.exec(input); if (rquickExpr.exec(selector)) {} str.exec(x);\n"
    assert not any(f["cwe"] == "CWE-78" for f in S.scan(regexy, "javascript"))
    assert any(f["cwe"] == "CWE-78" for f in S.scan(b"child_process.exec(userInput)\n", "javascript"))
    assert any(f["cwe"] == "CWE-78" for f in S.scan(b"const {execSync}=require('child_process');execSync(c)\n", "javascript"))


def test_minified_megaline_yields_candidates_not_corroborated():
    """A minified module is a whole file on one physical line, so line-scoped corroboration (source
    and sink in the same statement) is meaningless there -- it must stay candidate, never promote."""
    mega = (b"!function(){" + b"var x=1;" * 500 + b"var u=req.query.q;child_process.exec(u);"
            + b"a.innerHTML=u;" * 200 + b"}();\n")   # one line, well over the minified threshold
    got = {(f["cwe"], f["state"]) for f in S.scan(mega, "javascript")}
    assert ("CWE-78", "candidate") in got
    assert not any(st == "corroborated" for _, st in got)   # nothing corroborates on a megaline


def test_taint_var_is_whole_token_not_substring():
    # a 1-char tainted var `u` must not corroborate a sink merely because 'u' is inside "execute"
    src = b"u = sys.argv[1]\ncursor.execute('SELECT 1 FROM t WHERE n=%s' % name)\n"
    got = _by_cwe(S.scan(src, "python"))
    assert ("CWE-89", "candidate") in got and ("CWE-89", "corroborated") not in got


def test_language_detection_by_extension_and_shebang():
    assert S.language_for("x.php", b"<?php") == "php"
    assert S.language_for("x.py", b"print(1)") == "python"
    assert S.language_for("x.js", b"1") == "javascript"
    assert S.language_for("noext", b"#!/usr/bin/env python3\n") == "python"
    assert S.language_for("noext", b"#!/usr/bin/node\n") == "javascript"
    assert S.language_for("a.out", b"\x7fELF") is None     # a binary is not a script


def test_detect_route_files_scriptscan_findings(store, case):
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.detect.stage import DETECT_STAGE
    from lykos.db.dao import FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    d = Path(tempfile.mkdtemp())
    php = d / "app.php"; php.write_bytes(_PHP)
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, case.id, php, filename="app.php")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True); assert pool.wait_idle(30)
        run = q.enqueue(case.id, DETECT_STAGE, target_id=t.id, force=True)
        assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    fs = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "scriptscan"]
    assert fs, "the script route must file scriptscan findings"
    assert any(f.cwe == "CWE-78" and f.state == "corroborated" for f in fs)
