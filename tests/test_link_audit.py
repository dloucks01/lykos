"""Audit regressions for analyze/link: detonation outcome honesty and process cleanup."""
import os
import subprocess
import time

from lykos.analyze.link import harness as chharness
from lykos.analyze.link import whole_system
from lykos.analyze.link.detonate import DetonateResult, detonate


def _script(tmp_path, name, body):
    p = tmp_path / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    os.chmod(p, 0o755)
    return p


def test_a_hung_entry_is_reported_as_timed_out_not_clean(tmp_path):
    entry = _script(tmp_path, "entry", "sleep 30")
    svc = _script(tmp_path, "svc", "sleep 30")
    r = detonate([{"exe": svc, "filename": "svc", "role": "service"},
                  {"exe": entry, "filename": "entry", "role": "entry"}],
                 timeout=0.5, readiness=0.1, grace=0.1, baseline=False)
    by = {o.filename: o for o in r.outcomes}
    assert by["entry"].timed_out and not by["entry"].crashed
    assert by["svc"].timed_out and not by["svc"].crashed   # our SIGKILL is not its crash
    assert r.blame is None


def test_a_component_that_cannot_exec_is_not_a_clean_negative(tmp_path):
    bad = tmp_path / "notexec"
    bad.write_bytes(b"\x00garbage")
    os.chmod(bad, 0o755)
    r = detonate([{"exe": bad, "filename": "x", "role": "entry"}], timeout=0.5, baseline=False)
    assert not r.outcomes
    assert r.note and "launch failed" in r.note
    assert whole_system._not_run(r)


def test_unsupported_arch_is_detected_as_not_run():
    r = DetonateResult(isolation="unsupported-arch", note="no qemu-user for mips on x86-64")
    assert whole_system._not_run(r)
    assert not whole_system._not_run(DetonateResult(outcomes=[object()]))


def test_kill_session_takes_forked_workers_with_it():
    p = subprocess.Popen(["sh", "-c", "sleep 60 & echo $!; exit 0"],
                         stdout=subprocess.PIPE, start_new_session=True)
    child = int(p.stdout.readline())
    p.stdout.close()
    p.wait(timeout=5)                         # leader gone and reaped, worker still alive
    os.kill(child, 0)
    chharness._kill_session(p)
    for _ in range(100):
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        # reparented to init/subreaper: a zombie still answers kill(0) until reaped
        try:
            with open(f"/proc/{child}/stat") as fh:
                if fh.read().split()[2] == "Z":
                    break
        except OSError:
            break
        time.sleep(0.02)
    else:
        raise AssertionError("forked worker survived _kill_session")


def test_channel_argv_keeps_the_subcommand_and_fills_the_address():
    from lykos.analyze.link.harness_stage import _channel_argv
    found = {"flags": [{"flag": "-v", "takes_value": False},
                       {"flag": "-g", "takes_value": True, "kind": "host"},
                       {"flag": "-p", "takes_value": True, "kind": "port"},
                       {"flag": "-f", "takes_value": True, "kind": "config"}]}
    got = _channel_argv(["recv", "-g", "x", "-p", "8080", "-f", "@@"], found, "239.9.9.9:5004")
    assert got == ["recv", "-g", "239.9.9.9", "-p", "5004"]
    assert _channel_argv(["parse", "@@"], {"flags": []}, None) == ["parse"]


# ---- cross-component taint over the function ceiling: ranked top-N, loss reported -------------
def test_ranked_component_loss_is_reported_and_outranks_a_clean_callee():
    from lykos.analyze.detect import taint
    from lykos.analyze.link.crosstaint import _why_nothing
    base = {"no_components": False, "no_links": False, "edges_without_tainted_symbol": 0,
            "edges_with_clean_callee": 3, "callers_without_ir": 0, "callees_without_ir": 0,
            "components_over_cap": 0, "skipped_reachable": 0, "components_ranked": 0}
    assert "real negative" in _why_nothing(base, 0)            # under cap: unchanged
    msg = _why_nothing({**base, "skipped_reachable": 412, "components_ranked": 1}, 0)
    assert "412" in msg and str(taint._MAX_FUNCS) in msg
    assert "not a negative result" in msg and "real negative" not in msg
    assert _why_nothing({**base, "skipped_reachable": 5, "components_ranked": 2}, 1) is None
