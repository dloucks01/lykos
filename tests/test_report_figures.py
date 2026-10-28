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
