"""The offline SVG figure library (doc 49, Theme 4).

A report figure is reviewed in git and embedded in a byte-stable PDF, so these tests hold the
library to its guarantees: deterministic output, well-formed XML, no external request, escaped
labels, and a hard node cap.
"""
import xml.dom.minidom as minidom

from lykos.report import figures as F


def _parse(svg: str):
    return minidom.parseString(svg)   # raises on malformed XML


def _call_edges(n=4):
    # main -> parse -> {copy, log}; parse -> validate -> copy  (a small DAG with a shared sink)
    return [
        {"src_addr": "0x1000", "dst_addr": "0x1100", "dst_name": "parse_record"},
        {"src_addr": "0x1100", "dst_addr": "0x1200", "dst_name": "memcpy"},
        {"src_addr": "0x1100", "dst_addr": "0x1300", "dst_name": "log"},
        {"src_addr": "0x1000", "dst_addr": "0x1300", "dst_name": "log"},
    ]


# -- call graph -------------------------------------------------------------------------------

def test_call_graph_is_wellformed_and_has_labels():
    svg = F.call_graph_svg(_call_edges())
    assert svg and svg.lstrip().startswith("<svg")
    _parse(svg)                                    # well-formed XML
    assert "parse_record" in svg and "memcpy" in svg
    assert 'role="img"' in svg                     # accessible


def test_call_graph_is_deterministic():
    a = F.call_graph_svg(_call_edges())
    b = F.call_graph_svg(_call_edges())
    assert a == b, "identical input must produce byte-identical SVG"


def test_call_graph_focus_slices_to_the_ego_graph():
    svg = F.call_graph_svg(_call_edges(), focus_addr="0x1100")
    _parse(svg)
    assert "focus" in svg                           # the focus node is marked
    # ego graph of 0x1100 = itself + caller 0x1000 + callees 0x1200/0x1300 = 4 nodes
    assert svg.count('class="node') == 4


def test_call_graph_caps_nodes_and_says_how_many_more():
    # a star with far more than the cap: one hub calling many leaves
    edges = [{"src_addr": "0x1", "dst_addr": hex(0x1000 + i), "dst_name": f"f{i}"}
             for i in range(F._MAX_NODES + 25)]
    svg = F.call_graph_svg(edges)
    _parse(svg)
    drawn = svg.count('class="node')
    assert drawn <= F._MAX_NODES, f"drew {drawn}, cap is {F._MAX_NODES}"
    assert "more not shown" in svg


def test_call_graph_empty_is_none():
    assert F.call_graph_svg([]) is None
    assert F.call_graph_svg([{"src_addr": "0x1"}]) is None   # no dst_addr -> nothing to draw


def test_call_graph_handles_a_cycle_without_hanging():
    # recursion / a 2-cycle must not spin the layering
    edges = [{"src_addr": "0xa", "dst_addr": "0xb", "dst_name": "b"},
             {"src_addr": "0xb", "dst_addr": "0xa", "dst_name": "a"}]
    svg = F.call_graph_svg(edges)
    _parse(svg)
    assert svg.count('class="node') == 2


# -- coverage bars ----------------------------------------------------------------------------

def test_coverage_bars_wellformed_and_deterministic():
    rows = [{"name": "libfoo.so", "pct": 72, "detail": "720/1000 blocks"},
            {"name": "bar", "pct": 5}, {"name": "baz", "pct": None}]
    a = F.coverage_bars_svg(rows)
    b = F.coverage_bars_svg(rows)
    assert a == b
    _parse(a)
    assert "libfoo.so" in a and "72%" in a
    assert F.coverage_bars_svg([]) is None


def test_coverage_tone_thresholds():
    assert F._cov_tone(80) == "good"
    assert F._cov_tone(40) == "warn"
    assert F._cov_tone(10) == "bad"
    assert F._cov_tone(None) == "warn"


# -- the cross-cutting guarantees -------------------------------------------------------------

def test_no_figure_makes_an_external_request():
    svgs = [F.call_graph_svg(_call_edges()), F.coverage_bars_svg([{"name": "x", "pct": 1}])]
    for svg in svgs:
        # the SVG namespace URI is a declaration, never a network fetch -- strip it, then no
        # other http(s) reference (a CDN, a web font, an xlink:href image) may remain.
        bare = svg.replace('xmlns="http://www.w3.org/2000/svg"', "")
        assert "http://" not in bare and "https://" not in bare, "no external request allowed"
        assert "cdn" not in bare.lower() and "@import" not in bare and "<script" not in bare


def test_labels_are_escaped():
    evil = '"><script>alert(1)</script>'
    svg = F.call_graph_svg([{"src_addr": "0x1", "dst_addr": "0x2", "dst_name": evil}])
    _parse(svg)                                     # still well-formed
    assert "<script>alert" not in svg               # the payload is escaped, not injected
    assert "&lt;script&gt;" in svg


def test_layered_dag_viewbox_is_sane():
    svg = F.call_graph_svg(_call_edges())
    doc = _parse(svg)
    vb = doc.documentElement.getAttribute("viewBox").split()
    assert len(vb) == 4
    w, h = int(vb[2]), int(vb[3])
    assert 0 < w < 5000 and 0 < h < 5000


# -- chain (provenance / reachability) --------------------------------------------------------

def _chain_steps():
    return [{"label": "Static detectors", "sub": "found by", "tone": "source"},
            {"label": "dangerous_api", "sub": "detector"},
            {"label": "2 signals", "sub": "evidence"},
            {"label": "L2", "sub": "verified rung", "tone": "sink"}]


def test_chain_is_wellformed_deterministic_and_has_an_arrow_marker():
    a = F.chain_svg(_chain_steps(), title="How this finding was established")
    b = F.chain_svg(_chain_steps(), title="How this finding was established")
    assert a == b
    _parse(a)
    assert "Static detectors" in a and "dangerous_api" in a and "L2" in a
    assert 'marker id="lyk-arr"' in a              # the arrowhead is defined
    assert a.count('class="arrow"') == 3           # three arrows between four pills


def test_chain_source_and_sink_tones():
    svg = F.chain_svg(_chain_steps(), title="t")
    assert 'class="pill source"' in svg and 'class="pill sink"' in svg


def test_chain_empty_is_none():
    assert F.chain_svg([], title="t") is None
    assert F.chain_svg([{"sub": "x"}], title="t") is None   # no label -> dropped -> empty


def test_chain_escapes_labels():
    svg = F.chain_svg([{"label": "<b>a</b>"}, {"label": "b"}], title="t")
    _parse(svg)
    assert "<b>a</b>" not in svg and "&lt;b&gt;" in svg


# -- model integration: a finding carries provenance + reachability ---------------------------

def _seed_case(store):
    from lykos.db.dao import CallEdgeDAO, CaseDAO, FindingDAO, TargetDAO
    from lykos.db.provenance import reset_current_stage, set_current_stage
    case = CaseDAO(store.conn).create("demo")
    t = TargetDAO(store.conn).upsert(case.id, "vuln", "a" * 64, size=100, arch="x86_64",
                                     bits=64, endianness="little", file_type="elf")
    # main(0x1000) reads input (calls read) and reaches parse_record(0x1100), the vuln function
    CallEdgeDAO(store.conn).replace_for_target(t.id, [
        {"src_addr": "0x1000", "dst_addr": "0x2000", "dst_name": "read"},
        {"src_addr": "0x1000", "dst_addr": "0x1100", "dst_name": "parse_record"},
        {"src_addr": "0x1100", "dst_addr": "0x2100", "dst_name": "strcpy"},
    ])
    tok = set_current_stage("detect_cwe")
    try:
        FindingDAO(store.conn).upsert(t.id, case.id, {
            "dedup_key": "k", "cwe": "CWE-121", "title": "overflow", "severity": "high",
            "state": "confirmed", "function_addr": "0x1100", "detector": "dangerous_api",
            "evidence": [{"channel": "pattern", "detail": "unbounded strcpy"}]})
    finally:
        reset_current_stage(tok)
    return case.id


def test_report_finding_has_provenance_and_reachability_figures(store):
    from lykos.report.model import build_report
    case_id = _seed_case(store)
    rep = build_report(store, case_id, min_state="candidate")
    f = rep["targets"][0]["findings"][0]
    figs = f["figures"]
    assert figs["provenance"] and "Static detectors" in figs["provenance"]
    assert figs["reachability"] and "parse_record" in figs["reachability"]
    # the reachability figure must NOT overclaim: it is labelled reachability, not dataflow taint
    assert "not verified dataflow" in figs["reachability"]
    _parse(figs["provenance"])
    _parse(figs["reachability"])


# -- patch-diff map ---------------------------------------------------------------------------

def _pd_rows():
    return [{"name": "parse_hdr", "moved": 14, "blocks": [4, 7], "insns": [40, 61]},
            {"name": "copy_field", "moved": 6, "blocks": [2, 3], "insns": [12, 18]},
            {"name": "noop", "moved": 1, "blocks": [1, 1], "insns": [3, 4]}]


def test_patch_diff_map_wellformed_ranked_and_deterministic():
    a = F.patch_diff_map_svg(_pd_rows())
    b = F.patch_diff_map_svg(_pd_rows())
    assert a == b
    _parse(a)
    # ranked most-moved first regardless of input order
    assert a.index("parse_hdr") < a.index("copy_field") < a.index("noop")
    assert "moved 14" in a and "blocks 4→7" in a


def test_patch_diff_map_input_order_does_not_change_output():
    import random
    rows = _pd_rows()
    shuffled = rows[::-1]
    assert F.patch_diff_map_svg(rows) == F.patch_diff_map_svg(shuffled)


def test_patch_diff_map_empty_and_caps():
    assert F.patch_diff_map_svg([]) is None
    assert F.patch_diff_map_svg([{"moved": 3}]) is None          # no name -> dropped
    big = [{"name": f"fn{i}", "moved": i, "blocks": [1, 2], "insns": [1, 2]}
           for i in range(F._MAX_NODES + 20)]
    svg = F.patch_diff_map_svg(big)
    _parse(svg)
    assert svg.count('class="bar-bg"') <= F._MAX_NODES


def test_patch_diff_map_escapes_names():
    svg = F.patch_diff_map_svg([{"name": "<x>", "moved": 2, "blocks": [1, 1], "insns": [1, 1]}])
    _parse(svg)
    assert "<x>" not in svg and "&lt;x&gt;" in svg


def test_report_attaches_patch_diff_map_from_structured_evidence(store):
    """The report builds the map from the patch-diff-map evidence channel the stage records."""
    import json
    from lykos.db.dao import CaseDAO, FindingDAO, TargetDAO
    from lykos.report.model import build_report
    case = CaseDAO(store.conn).create("pd")
    t = TargetDAO(store.conn).upsert(case.id, "patched", "c" * 64, size=10, arch="x86_64",
                                     bits=64, endianness="little", file_type="elf")
    for nm, mv, addr in [("parse_hdr", 14, "0x1100"), ("copy_field", 6, "0x1200")]:
        FindingDAO(store.conn).upsert(t.id, case.id, {
            "dedup_key": f"patch_diff:{nm}:{addr}", "cwe": "NVD-CWE-noinfo", "severity": "medium",
            "state": "candidate", "title": f"Patch-diff lead: '{nm}'", "detector": "patch_diff",
            "function_addr": addr,
            "evidence": [{"channel": "patch-diff", "detail": f"{nm} changed"},
                         {"channel": "patch-diff-map", "detail": json.dumps(
                             {"name": nm, "moved": mv, "blocks": [1, 2], "insns": [3, 4]})}]})
    rep = build_report(store, case.id, min_state="candidate")
    fig = rep["targets"][0]["figures"]["patch_diff"]
    assert fig and "parse_hdr" in fig and fig.index("parse_hdr") < fig.index("copy_field")
    # the structured data is surfaced on the finding, and the prose channel still reads in the trail
    f0 = next(f for f in rep["targets"][0]["findings"] if f["detector"] == "patch_diff")
    assert f0["patch_diff"]["moved"] in (6, 14)


def test_reachability_is_none_without_a_source_path(store):
    """No input-source call -> no honest reachability path -> the figure is omitted, not faked."""
    from lykos.db.dao import CallEdgeDAO, CaseDAO, FindingDAO, TargetDAO
    from lykos.report.model import build_report
    case = CaseDAO(store.conn).create("d2")
    t = TargetDAO(store.conn).upsert(case.id, "x", "b" * 64, size=1, arch="x86_64",
                                     bits=64, endianness="little", file_type="elf")
    CallEdgeDAO(store.conn).replace_for_target(t.id, [
        {"src_addr": "0x1000", "dst_addr": "0x1100", "dst_name": "helper"}])   # no input source
    FindingDAO(store.conn).upsert(t.id, case.id, {
        "dedup_key": "k", "cwe": "CWE-121", "severity": "high", "state": "candidate",
        "function_addr": "0x1100", "detector": "dangerous_api"})
    rep = build_report(store, case.id, min_state="candidate")
    assert rep["targets"][0]["findings"][0]["figures"]["reachability"] is None
