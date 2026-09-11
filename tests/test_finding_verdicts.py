"""Can a channel change its mind?

The merge took the higher state/severity/confidence and kept it forever. That is right for
promotion -- it is how a finding climbs candidate -> corroborated -> confirmed -> poc-backed
when channels agree -- and wrong for everything else: a channel could never revise its own
verdict downward, so every demotion was computed and discarded.

`enqueue_detect` forces by default ("re-detect after re-analysis should re-run rather than
cache-hit"), so that was the designed path, not an edge case. gzip 1.3.5's provably guarded
strcpy demoted on a fresh case and stayed high on a re-run of the same one -- which meant the
bounds, dominating-guard and strlen-bounding work only ever helped targets nobody had
analysed yet.
"""
from lykos.db.dao import FindingDAO


def _c(key="k", *, state="candidate", severity="info", confidence=0.4,
       detector="d", **extra):
    return {"cwe": "CWE-120", "title": "t", "severity": severity, "state": state,
            "confidence": confidence, "detector": detector, "dedup_key": key,
            "evidence": [], **extra}


def _target(store, case):
    return store.targets.upsert(case.id, filename="t", sha256="a" * 64, size=1,
                                arch="x86-64", bits=64)


def _f(store, tid, cid):
    return FindingDAO(store.conn).list_by_target(tid)[0]


def test_channels_that_agree_still_promote(store, case):
    """The behaviour the old rule existed for, unchanged."""
    t = _target(store, case)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, _c(detector="rules", state="candidate", confidence=0.4))
    fd.upsert(t.id, case.id, _c(detector="taint", state="corroborated", severity="high",
                                confidence=0.8))
    f = _f(store, t.id, case.id)
    assert f.state == "corroborated" and f.severity == "high" and f.confidence == 0.8


def test_a_channel_can_lower_its_own_verdict_on_a_later_run(store, case):
    """The bug: a copy later proven bounded stayed high forever."""
    t = _target(store, case)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, _c(detector="rules", state="corroborated", severity="high",
                                confidence=0.8, run_id="run-1"))
    fd.upsert(t.id, case.id, _c(detector="rules", state="candidate", severity="info",
                                confidence=0.15, run_id="run-2"))
    f = _f(store, t.id, case.id)
    assert f.severity == "info" and f.confidence == 0.15 and f.state == "candidate"


def test_a_channel_cannot_lower_ANOTHER_channels_verdict(store, case):
    """A weak late channel must not be able to undo a crash-proven promotion -- which is
    exactly why the old rule was monotonic in the first place."""
    t = _target(store, case)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, _c(channel="crash-attribution", state="poc-backed",
                                severity="high", confidence=0.97, run_id="r1"))
    fd.upsert(t.id, case.id, _c(detector="rules", state="candidate", severity="info",
                                confidence=0.15, run_id="r2"))
    f = _f(store, t.id, case.id)
    assert f.state == "poc-backed" and f.confidence == 0.97


def test_many_sites_in_ONE_run_take_the_strongest(store, case):
    """A channel speaks once per site. Nine sites of a sink, one of them demoted, must not
    leave whichever happened to be written last."""
    t = _target(store, case)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, _c(detector="rules", state="corroborated", severity="high",
                                confidence=0.8, run_id="run-1"))
    fd.upsert(t.id, case.id, _c(detector="rules", state="candidate", severity="info",
                                confidence=0.15, run_id="run-1"))
    f = _f(store, t.id, case.id)
    assert f.severity == "high" and f.confidence == 0.8


def test_an_unstamped_channel_keeps_the_old_monotonic_behaviour(store, case):
    """A caller that does not identify its run cannot be told apart from the same run, so it
    max-merges -- the conservative reading, and what every existing caller gets."""
    t = _target(store, case)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, _c(detector="rules", state="corroborated", confidence=0.8))
    fd.upsert(t.id, case.id, _c(detector="rules", state="candidate", confidence=0.1))
    assert _f(store, t.id, case.id).confidence == 0.8


def test_the_verdict_trail_says_who_said_what(store, case):
    t = _target(store, case)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, _c(detector="rules", state="corroborated", confidence=0.8))
    fd.upsert(t.id, case.id, _c(channel="crash-attribution", state="poc-backed",
                                confidence=0.97))
    by = {v["channel"]: v for v in fd.verdicts(_f(store, t.id, case.id).id)}
    assert set(by) == {"rules", "crash-attribution"}
    assert by["crash-attribution"]["state"] == "poc-backed"


def test_a_retracting_channel_falls_back_to_what_others_still_say(store, case):
    """Lowering one channel must not drop the finding below another channel's standing
    verdict."""
    t = _target(store, case)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, _c(detector="taint", state="corroborated", severity="high",
                                confidence=0.8, run_id="a1"))
    fd.upsert(t.id, case.id, _c(detector="rules", state="corroborated", severity="high",
                                confidence=0.9, run_id="b1"))
    fd.upsert(t.id, case.id, _c(detector="rules", state="candidate", severity="info",
                                confidence=0.1, run_id="b2"))
    f = _f(store, t.id, case.id)
    assert f.severity == "high" and f.confidence == 0.8, "taint's verdict still stands"
