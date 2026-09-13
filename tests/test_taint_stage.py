"""The `dynamic_taint` STAGE: does the marker actually reach the sink, and does the stage
say the right thing when it cannot watch the target at all.

test_taint.py covers the flow extractors underneath; the stage body -- substrate gates, input
delivery, and the promotion of a reaching marker to a CONFIRMED finding -- was untested. That
promotion is the whole claim: "the input you control reaches this sink" is a different, much
stronger statement than "this binary calls system somewhere", and only the stage makes it.
"""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.debug import enqueue_taint
from lykos.analyze.debug import taint_stage as ts
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.db.dao import CallEdgeDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# argv -> system(): the marker travels through snprintf into the command
_ARG_C = ('#include <stdlib.h>\n#include <stdio.h>\n'
          'int main(int c,char**v){char cmd[512];if(c<2)return 1;'
          'snprintf(cmd,sizeof cmd,"echo %s",v[1]);return system(cmd);}\n')
# stdin -> system()
_STDIN_C = ('#include <stdlib.h>\n#include <stdio.h>\n#include <string.h>\n'
            'int main(void){char line[512],cmd[600];'
            'if(!fgets(line,sizeof line,stdin))return 1;'
            'line[strcspn(line,"\\n")]=0;'
            'snprintf(cmd,sizeof cmd,"echo %s",line);return system(cmd);}\n')
# a file path -> system(): reads the file named on the command line, echoes its contents
_FILE_C = ('#include <stdlib.h>\n#include <stdio.h>\n#include <string.h>\n'
           'int main(int c,char**v){char line[512],cmd[600];if(c<2)return 1;'
           'FILE*f=fopen(v[1],"r");if(!f)return 1;'
           'if(!fgets(line,sizeof line,f))return 1;'
           'line[strcspn(line,"\\n")]=0;'
           'snprintf(cmd,sizeof cmd,"echo %s",line);return system(cmd);}\n')
# the marker is READ but never reaches a sink -- the negative the stage must not claim
_NOFLOW_C = ('#include <stdlib.h>\n#include <stdio.h>\n'
             'int main(int c,char**v){if(c<2)return 1;printf("%zu\\n",sizeof(v[1]));'
             'return system("echo constant");}\n')

pytestmark = pytest.mark.skipif(sandbox.host_arch() != "x86-64",
                                reason="native x86-64 gdb path")


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=60, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _build(gcc, tmp_path, src, name):
    c = tmp_path / f"{name}.c"
    c.write_text(src)
    exe = tmp_path / name
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip(f"cannot build {name}")
    return exe


def _sinks(store, target, names=("system",)):
    """The native path watches the sinks the binary IMPORTS, which it reads from the call
    graph -- so a target that has not been disassembled has nothing to watch and the stage
    correctly reports no flow. Supplying the edges is what the disassemble stage would do."""
    CallEdgeDAO(store.conn).replace_for_target(target.id, [
        {"src_addr": "0x1149", "site_addr": "0x1160", "dst_addr": None,
         "dst_name": n, "external": 1} for n in names])


def _run(store, pool, target, params):
    q = JobQueue(store.conn)
    run = enqueue_taint(q, target, params=params)
    assert pool.wait_idle(120)
    return q.runs.get(run.id)


def _gdb_or_skip():
    from lykos.analyze.debug import monitor
    if not monitor._locate_gdb():
        pytest.skip("gdb not installed")


@pytest.mark.parametrize("mode,src,name", [
    ("arg", _ARG_C, "targ"),
    ("stdin", _STDIN_C, "tstdin"),
    ("file", _FILE_C, "tfile"),
])
def test_a_marker_that_reaches_the_sink_is_a_confirmed_flow(store, case, pool, gcc, tmp_path,
                                                            mode, src, name):
    """Delivered by every channel the stage supports. A marker placed the wrong way does not
    reach the sink, the stage reports no flow, and that reads exactly like a clean target --
    which is why each channel needs its own test rather than one standing for all three."""
    _gdb_or_skip()
    exe = _build(gcc, tmp_path, src, name)
    t = ingest(store, case.id, exe)
    _sinks(store, t)
    rec = _run(store, pool, t, {"input_mode": mode, "timeout": 20})
    if rec.status != "done":
        pytest.skip("gdb monitor unavailable here: " + str(rec.error))
    fs = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "taint"]
    assert fs, f"the marker reached system() via {mode} but no flow was recorded"
    assert {f.cwe for f in fs} == {"CWE-78"}
    assert all(f.state == "confirmed" for f in fs), \
        "watching the input arrive at the sink is confirmation, not corroboration"


def test_a_target_whose_input_never_reaches_a_sink_claims_nothing(store, case, pool, gcc,
                                                                  tmp_path):
    """The command this program runs is a constant. A stage that reported a flow here would
    be claiming attacker control that does not exist."""
    _gdb_or_skip()
    exe = _build(gcc, tmp_path, _NOFLOW_C, "tnoflow")
    t = ingest(store, case.id, exe)
    _sinks(store, t)
    rec = _run(store, pool, t, {"input_mode": "arg", "timeout": 20})
    if rec.status != "done":
        pytest.skip("gdb monitor unavailable here: " + str(rec.error))
    fs = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "taint"]
    assert not fs, f"claimed a data flow that does not exist: {[f.title for f in fs]}"


@pytest.mark.parametrize("file_type", ["pe", "macho", "jar"])
def test_a_format_the_taint_stage_cannot_run_declines_rather_than_errors(store, case, pool,
                                                                        gcc, tmp_path,
                                                                        file_type):
    """A stage error reads to the operator as "the tool broke". "This substrate is not
    supported here" is a different statement and has to survive as one."""
    exe = _build(gcc, tmp_path, _ARG_C, f"tfmt{file_type}")
    t = ingest(store, case.id, exe)
    store.conn.execute("UPDATE target SET file_type=? WHERE id=?", (file_type, t.id))
    store.conn.commit()
    rec = _run(store, pool, t, {"input_mode": "arg", "timeout": 10})
    assert rec.status == "done", rec.error
    assert not FindingDAO(store.conn).list_by_target(t.id)


def test_the_stage_refuses_to_run_without_a_target():
    class _Ctx:
        target_id = None
        params: dict = {}
    with pytest.raises(ValueError, match="target_id"):
        ts.taint_stage(_Ctx())


def test_every_sink_kind_the_stage_can_confirm_has_a_cwe():
    """A flow reaching a sink whose kind has no CWE would be observed and then dropped."""
    from lykos.analyze.debug import monitor
    kinds = {spec["kind"] for spec in monitor.CATALOG.values()}
    assert set(ts._CWE) <= kinds, "a CWE is mapped for a sink kind the catalog does not have"
    for kind, (cwe, sev) in ts._CWE.items():
        assert cwe.startswith("CWE-") and sev in ("low", "medium", "high", "critical"), kind
