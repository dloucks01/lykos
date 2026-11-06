"""Semantic finding dedup (analyze/dedup.py): collapse per-site candidates into distinct bugs.

The clustering and representative choice are pure, so they are unit-tested without a database. The
canonical key is (CWE, enclosing function) -- the prover's granularity -- with a (CWE, file) fallback
when the function cannot be resolved, which must never merge across files.
"""
from __future__ import annotations

from types import SimpleNamespace

from lykos.analyze import dedup as D


def _f(cwe, detail, *, conf=0.5, state="candidate", fid="x"):
    return SimpleNamespace(cwe=cwe, confidence=conf, state=state, id=fid,
                           evidence=[{"channel": "source", "detail": detail}])


class _NoResolver:
    """Resolver that never resolves a function -> forces the (CWE, file) fallback key."""
    def enclosing(self, fp, line):
        return None


class _FnMap:
    """Resolver stub mapping (file, line) -> a function name, for the (CWE, fn) key."""
    def __init__(self, m):
        self.m = m

    def enclosing(self, fp, line):
        return self.m.get((fp, line))


def test_parse_loc_reads_the_source_site():
    assert D.parse_loc([{"channel": "source", "detail": "sink at libfreerdp/core/input.c:887 bad"}]) \
        == ("libfreerdp/core/input.c", 887)
    assert D.parse_loc([{"channel": "other", "detail": "x.c:5"}]) == (None, None)
    assert D.parse_loc([]) == (None, None)


def test_canonical_key_prefers_function_then_file():
    assert D.canonical_key("CWE-190", "parse_hdr", "a/b.c") == ("CWE-190", "fn:parse_hdr")
    assert D.canonical_key("CWE-190", None, "a/b.c") == ("CWE-190", "file:b.c")
    # no function and no file still yields a stable key, never a crash
    # no location at all: the finding is its own bug, never "the same place" as another
    assert D.canonical_key(None, None, None, "k1") == ("CWE-unknown", "id:k1")


def test_same_function_same_cwe_collapses_to_one_cluster():
    # three int-overflow sites in one function -> one distinct bug
    fns = _FnMap({("env.c", 10): "load", ("env.c", 20): "load", ("env.c", 30): "load"})
    fs = [_f("CWE-190", "env.c:10", fid="a"), _f("CWE-190", "env.c:20", fid="b"),
          _f("CWE-190", "env.c:30", fid="c")]
    groups = D.cluster(fs, fns)
    assert len(groups) == 1
    assert list(groups)[0] == ("CWE-190", "fn:load")
    assert len(next(iter(groups.values()))) == 3


def test_different_cwe_or_function_do_not_merge():
    fns = _FnMap({("a.c", 1): "f", ("a.c", 2): "g"})
    fs = [_f("CWE-190", "a.c:1"), _f("CWE-787", "a.c:1"), _f("CWE-190", "a.c:2")]
    groups = D.cluster(fs, fns)
    assert len(groups) == 3                                  # (190,f) (787,f) (190,g) all distinct


def test_file_fallback_never_merges_across_files():
    fs = [_f("CWE-787", "dsp.c:5"), _f("CWE-787", "dsp.c:9"), _f("CWE-787", "rdg.c:5")]
    groups = D.cluster(fs, _NoResolver())
    keys = set(groups)
    assert keys == {("CWE-787", "file:dsp.c"), ("CWE-787", "file:rdg.c")}
    assert len(groups[("CWE-787", "file:dsp.c")]) == 2      # two dsp.c sites collapse


def test_representative_prefers_resolved_site_then_confidence():
    fns = _FnMap({("a.c", 10): "f", ("a.c", 40): "f"})
    low = _f("CWE-190", "a.c:40", conf=0.3, fid="low")
    high = _f("CWE-190", "a.c:10", conf=0.9, fid="high")
    groups = D.cluster([low, high], fns)
    rep = next(iter(groups.values()))[0]
    assert rep.id == "high"                                 # higher confidence wins the representative


def test_advanced_findings_are_not_clustered():
    fns = _FnMap({("a.c", 1): "f"})
    fs = [_f("CWE-190", "a.c:1", state="confirmed"), _f("CWE-190", "a.c:1", state="poc-backed")]
    assert D.cluster(fs, fns) == {}                         # nothing raw to dedup


def test_newer_detectors_site_channels_are_read():
    """guard_gap / alloc_overflow / sibling_guard record file:line on their OWN channel."""
    ev = [{"channel": "guard-gap", "detail": "libfreerdp/codec/planar.c:712: 'rawSizes' is read"}]
    assert D.parse_loc(ev) == ("libfreerdp/codec/planar.c", 712)
    wf = [{"channel": "source", "detail": "libfreerdp/codec/clear.c: clear_decompress_subcode_rlex() "
                                          "uses wire-read 'numBits' as a index"}]
    assert D.parse_loc(wf) == ("libfreerdp/codec/clear.c", None)
    assert D.parse_fn(wf) == "clear_decompress_subcode_rlex"


def test_unlocated_findings_are_never_merged_together():
    from types import SimpleNamespace as N
    a = N(id="a", cwe="CWE-129", state="candidate", confidence=0.5, dedup_key="oobindex:tbl",
          evidence=[{"channel": "oob-index-static", "detail": "array _ZL11ioctl_table"}])
    b = N(id="b", cwe="CWE-129", state="candidate", confidence=0.5, dedup_key="wf:clear:numBits",
          evidence=[{"channel": "source", "detail": "libfreerdp/codec/clear.c: "
                                                    "clear_decompress_subcode_rlex() uses wire-read"}])
    c = N(id="c", cwe="CWE-129", state="candidate", confidence=0.5, dedup_key="wf:lic:dwErr",
          evidence=[{"channel": "source", "detail": "libfreerdp/core/license.c: "
                                                    "license_read_error_alert_packet() uses wire"}])
    groups = D.cluster([a, b, c], None)
    assert len(groups) == 3, groups


def test_site_of_recovers_the_sink_line_of_a_function_form_site(tmp_path):
    from types import SimpleNamespace as N
    (tmp_path / "codec").mkdir()
    (tmp_path / "codec" / "clear.c").write_text(
        "static int helper(int);\n"
        "static BOOL clear_decompress_subcode_rlex(wStream* s, UINT32 numBits)\n{\n"
        "\tUINT32 tmp = 0;\n\tstopIndex = tmp & CLEAR_8BIT_MASKS[numBits];\n\treturn TRUE;\n}\n")
    f = N(evidence=[{"channel": "source", "detail": "codec/clear.c: clear_decompress_subcode_rlex() "
                     "uses wire-read 'numBits' as a index -- stopIndex = tmp & CLEAR_8BIT_MASKS[numBits];"}])
    assert D.site_of(f, tmp_path) == ("codec/clear.c", 5)
    g = N(evidence=[{"channel": "source", "detail": "codec/clear.c: clear_decompress_subcode_rlex() "
                     "frees 'p'"}])
    assert D.site_of(g, tmp_path) == ("codec/clear.c", 2)        # no statement: the definition
