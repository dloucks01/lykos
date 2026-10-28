"""Cross-reference: a ladder-confirmed ASan crash UPGRADES a co-located static source candidate.

The discovery scanners (int_overflow, uaf, source_sink, ...) file `candidate` findings at file:line.
When the non-fuzzing confirmation ladder later proves a crash at the SAME site with the SAME class,
that static lead is promoted to `confirmed` -- found AND proved. Precision: the upgrade fires only on
an exact file+line match AND a matching CWE; a crash of a different class, or at a different line,
leaves the candidate untouched. The static channel's own verdict is preserved (the discoverer keeps
credit); the proof is recorded on a distinct `dynamic-confirm` channel.
"""
from __future__ import annotations

from lykos.analyze import source_confirm_stage as SC
from lykos.db.dao import FindingDAO, TargetDAO


class _Ctx:
    def __init__(self, conn):
        self.conn = conn


def _target(store, case):
    return TargetDAO(store.conn).upsert(case.id, "t", "f" * 64, arch="source", bits=0)


def _candidate(conn, t, *, detector, cwe, path, line, key):
    FindingDAO(conn).upsert(t.id, t.case_id, {
        "cwe": cwe, "title": f"{detector} candidate", "severity": "medium", "detector": detector,
        "state": "candidate", "confidence": 0.4, "dedup_key": key,
        "evidence": [{"channel": "source", "detail": f"{path}:{line}: suspected {cwe}"}]})


def _state(conn, t, key):
    return next(f.state for f in FindingDAO(conn).list_by_target(t.id) if f.dedup_key == key)


def test_matching_site_and_class_is_upgraded(store, case):
    t = _target(store, case)
    _candidate(store.conn, t, detector="int_overflow", cwe="CWE-190",
               path="libfreerdp/core/foo.c", line=50, key="intovf:foo:50")
    n = SC._crossref_static(_Ctx(store.conn), t,
                            "/build/abs/libfreerdp/core/foo.c:50:12", "CWE-190", "d" * 64, "TestFuzzFoo")
    assert n == 1
    assert _state(store.conn, t, "intovf:foo:50") == "confirmed"
    # the proof is recorded as evidence, keyed to the reproducing input and the harness
    f = next(x for x in FindingDAO(store.conn).list_by_target(t.id) if x.dedup_key == "intovf:foo:50")
    ev = " ".join(str(e.get("detail", "")) for e in (f.evidence or []))
    assert "confirmed by source_confirm" in ev and "TestFuzzFoo" in ev
    assert f.detector == "int_overflow"              # discoverer keeps credit


def test_a_different_class_at_the_same_site_is_not_upgraded(store, case):
    t = _target(store, case)
    _candidate(store.conn, t, detector="uaf", cwe="CWE-416",
               path="libfreerdp/core/foo.c", line=50, key="uaf:foo:50")
    n = SC._crossref_static(_Ctx(store.conn), t,
                            "/build/abs/libfreerdp/core/foo.c:50", "CWE-190", "d" * 64, "H")
    assert n == 0 and _state(store.conn, t, "uaf:foo:50") == "candidate"


def test_a_different_line_is_not_upgraded(store, case):
    t = _target(store, case)
    _candidate(store.conn, t, detector="int_overflow", cwe="CWE-190",
               path="libfreerdp/core/foo.c", line=99, key="intovf:foo:99")
    n = SC._crossref_static(_Ctx(store.conn), t,
                            "/build/abs/libfreerdp/core/foo.c:50", "CWE-190", "d" * 64, "H")
    assert n == 0 and _state(store.conn, t, "intovf:foo:99") == "candidate"


def test_a_different_file_with_the_same_basename_is_not_matched(store, case):
    """Suffix matching aligns on path components, so `a/foo.c` and `b/foo.c` are NOT the same file."""
    t = _target(store, case)
    _candidate(store.conn, t, detector="int_overflow", cwe="CWE-190",
               path="channels/other/foo.c", line=50, key="intovf:other:50")
    n = SC._crossref_static(_Ctx(store.conn), t,
                            "/build/abs/libfreerdp/core/foo.c:50", "CWE-190", "d" * 64, "H")
    assert n == 0 and _state(store.conn, t, "intovf:other:50") == "candidate"


def test_suffix_match_is_path_component_aligned():
    assert SC._suffix_match("/build/x/libfreerdp/core/foo.c", "libfreerdp/core/foo.c")
    assert SC._suffix_match("libfreerdp/core/foo.c", "libfreerdp/core/foo.c")
    assert not SC._suffix_match("/build/x/barfoo.c", "foo.c")        # not a component boundary
    assert not SC._suffix_match("/build/a/foo.c", "b/foo.c")
