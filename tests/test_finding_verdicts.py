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


# ---------------------------------------------------------------- verdicts about a PLACE
# Every ruling the analysis makes is about one occurrence -- bounds proves a particular copy
# bounded, a dominating guard bounds a particular index, crash attribution proves a particular
# instruction -- and all of it used to collapse into one badge on the finding. jhead's
# poc-backed CWE-125 has 99 sites and exactly ONE is proven; all 99 carried the identical
# detail string, so a 99-site finding with one proven site rendered like one with 99.
def _site(key="k", fn="0x900", site="0x1000", **kw):
    return _c(key, function_addr=fn, site_addr=site, **kw)


def test_a_site_carries_its_own_verdict(store, case):
    t = _target(store, case)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, _site(site_verdict="bounded", site_state="candidate"))
    s = fd.sites(_f(store, t.id, case.id).id)[0]
    assert s["verdict"] == "bounded" and s["state"] == "candidate"


def test_only_the_proven_occurrence_is_marked(store, case):
    """The whole point: one site proven out of many must be distinguishable from the rest."""
    t = _target(store, case)
    fd = FindingDAO(store.conn)
    for a in ("0x1000", "0x2000", "0x3000"):
        fd.upsert(t.id, case.id, _site(site=a))
    fd.upsert(t.id, case.id, _site(site="0x2000", site_state="poc-backed",
                                   site_verdict="proven", site_confidence=0.97))
    f = _f(store, t.id, case.id)
    assert fd.proven_sites(t.id) == {f.id: 1}
    assert len(fd.sites(f.id)) == 3, "marking a site must not create a new one"


def test_the_proven_occurrence_sorts_first(store, case):
    """Oldest-first was the only order available when a site was just an address."""
    t = _target(store, case)
    fd = FindingDAO(store.conn)
    for a in ("0x1000", "0x2000", "0x3000"):
        fd.upsert(t.id, case.id, _site(site=a))
    fd.upsert(t.id, case.id, _site(site="0x3000", site_state="poc-backed",
                                   site_verdict="proven"))
    assert fd.sites(_f(store, t.id, case.id).id)[0]["site_addr"] == "0x3000"


def test_a_channel_may_only_raise_a_site(store, case):
    """Same asymmetry the finding row uses: a later weak channel cannot unprove a site."""
    t = _target(store, case)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, _site(site_state="poc-backed", site_verdict="proven"))
    fd.upsert(t.id, case.id, _site(site_state="candidate", site_verdict="unknown"))
    s = fd.sites(_f(store, t.id, case.id).id)[0]
    assert s["state"] == "poc-backed"


def test_a_channel_that_says_nothing_about_a_site_blanks_nothing(store, case):
    """Most channels have no opinion on most fields; silence must not erase another's work."""
    t = _target(store, case)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, _site(site_state="poc-backed", site_verdict="proven",
                                   site_detail="the faulting instruction"))
    fd.upsert(t.id, case.id, _site())                 # no site_* fields at all
    s = fd.sites(_f(store, t.id, case.id).id)[0]
    assert s["state"] == "poc-backed" and s["verdict"] == "proven"
    assert s["detail"] == "the faulting instruction"


def test_sites_of_different_findings_are_counted_separately(store, case):
    t = _target(store, case)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, _site("k1", site="0x1000", site_state="poc-backed"))
    fd.upsert(t.id, case.id, _site("k2", site="0x2000"))
    by = {f.dedup_key: f.id for f in FindingDAO(store.conn).list_by_target(t.id)}
    assert fd.proven_sites(t.id) == {by["k1"]: 1}


def test_a_finding_filed_directly_at_poc_backed_gets_the_severity_floor(store, case):
    """A first-time finding created straight at poc-backed must get the same poc-backed->high
    severity floor a promoted one does -- not the detector's low guess. Before the fix the new-
    finding path stored the raw severity and only the merge path recomputed."""
    t = _target(store, case)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, _c(key="direct", state="poc-backed", severity="low",
                                confidence=0.9, detector="dynamic"))
    f = _f(store, t.id, case.id)
    assert f.state == "poc-backed"
    assert f.severity == "high"          # bumped on the very first upsert, not just on merge
