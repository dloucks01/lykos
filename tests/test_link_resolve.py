"""Cross-binary symbol resolution: which component calls into which.

This is the edge set every other multi-binary capability is built on -- cross_taint chases
data across these boundaries, whole_system picks a scenario from them. A missed edge is not a
visible failure: the graph simply has one fewer link, and cross-component analysis then
reports "nothing found" for a boundary it never knew existed.

Soname matching is where that happens. A NEEDED entry says `libcfg.so.1`, the component in the
case is named `libcfg.so.1.2.3`, and a matcher that compares them literally links neither.
"""
from __future__ import annotations

import json

import pytest
from lykos.analyze.link import resolve

# ---- soname normalisation ----------------------------------------------------------------

@pytest.mark.parametrize("a,b", [
    ("libcfg.so", "libcfg.so.1"),
    ("libcfg.so.1", "libcfg.so.1.2"),
    ("libcfg.so.1.2", "libcfg.so.1.2.3"),
    ("libc.so.6", "libc.so"),
    ("LIBCFG.SO.1", "libcfg.so.1"),
    ("  libcfg.so.1  ", "libcfg.so.1"),
])
def test_versioned_sonames_reduce_to_the_same_stem(a, b):
    assert resolve._norm_soname(a) == resolve._norm_soname(b), f"{a!r} vs {b!r}"


@pytest.mark.parametrize("a,b", [
    ("libcfg.so.1", "libother.so.1"),
    ("libssl.so", "libcrypto.so"),
    ("libz.so.1", "libzip.so.1"),
])
def test_different_libraries_do_not_collapse_together(a, b):
    """Over-normalising is worse than under-normalising: it invents edges between components
    that never call each other, and every downstream analysis then chases a boundary that is
    not there."""
    assert resolve._norm_soname(a) != resolve._norm_soname(b)


def test_normalisation_is_stable_under_repetition():
    once = resolve._norm_soname("libcfg.so.1.2.3")
    assert resolve._norm_soname(once) == once


def test_a_name_with_no_suffix_survives():
    assert resolve._norm_soname("busybox") == "busybox"
    assert resolve._norm_soname("") == ""
    assert resolve._norm_soname(None) == ""


# ---- the symbol sample stored on an edge -------------------------------------------------

def test_edge_symbols_round_trips_what_was_stored():
    detail = json.dumps({"symbols": ["parse_cfg", "read_key"]})
    assert resolve.edge_symbols(detail) == ["parse_cfg", "read_key"]


@pytest.mark.parametrize("junk", [None, "", "not json", "{", "[1,2]", '{"other": 1}'])
def test_a_malformed_edge_detail_is_no_symbols_rather_than_an_exception(junk):
    """These are read while rendering the case graph. A decode error there takes out the whole
    view, not one edge."""
    assert resolve.edge_symbols(junk) == []


def test_the_symbol_sample_is_capped():
    """A component importing thousands of symbols would otherwise store all of them on the
    edge and render an unreadable graph."""
    assert resolve._MAX_DETAIL_SYMS > 0
    assert resolve._MAX_DETAIL_SYMS <= 200


# ---- resolution over a synthetic case ----------------------------------------------------

class _T:
    def __init__(self, tid, filename):
        self.id, self.filename = tid, filename


def _resolve(targets, recs):
    """Drive symbol_resolution with injected triage records."""
    class _TDao:
        def __init__(self, ts):
            self._ts = ts

        def list_by_case(self, _cid):
            return list(self._ts.values())

    orig_dao, orig_recs = resolve.TargetDAO, resolve._triage_records
    resolve.TargetDAO = lambda _conn: _TDao(targets)
    resolve._triage_records = lambda _conn, _content, _cid: recs
    try:
        return resolve.symbol_resolution(None, None, "case1")
    finally:
        resolve.TargetDAO, resolve._triage_records = orig_dao, orig_recs


def _rec(imports=(), exports=(), needed=()):
    return {"imports": {"symbols": list(imports), "libraries": list(needed)},
            "exports": {"symbols": list(exports)}}


def test_an_importer_is_linked_to_the_component_that_exports_the_symbol():
    targets = {"app": _T("app", "app"), "lib": _T("lib", "libcfg.so.1")}
    recs = {"app": _rec(imports=["parse_cfg"], needed=["libcfg.so.1"]),
            "lib": _rec(exports=["parse_cfg"])}
    out = _resolve(targets, recs)
    assert out["pairs"][("app", "lib")] == ["parse_cfg"]


def test_a_needed_library_links_even_when_no_symbol_resolves():
    """A stripped or lazily-bound import list still tells you the program loads the library.
    Dropping the edge loses the boundary entirely."""
    targets = {"app": _T("app", "app"), "lib": _T("lib", "libcfg.so.1.2.3")}
    recs = {"app": _rec(needed=["libcfg.so.1"]), "lib": _rec(exports=["unrelated"])}
    out = _resolve(targets, recs)
    assert out["needed"][("app", "lib")] == ["libcfg.so.1"], \
        "a versioned NEEDED entry did not match the library's filename"


def test_a_component_is_never_linked_to_itself():
    targets = {"one": _T("one", "libself.so")}
    recs = {"one": _rec(imports=["f"], exports=["f"], needed=["libself.so"])}
    out = _resolve(targets, recs)
    assert out["pairs"] == {} and out["needed"] == {}


def test_two_exporters_of_the_same_symbol_both_get_an_edge():
    """Which one the loader actually binds is a runtime question; the graph shows both
    candidates rather than silently picking one."""
    targets = {"app": _T("app", "app"), "a": _T("a", "liba.so"), "b": _T("b", "libb.so")}
    recs = {"app": _rec(imports=["shared"]), "a": _rec(exports=["shared"]),
            "b": _rec(exports=["shared"])}
    out = _resolve(targets, recs)
    assert ("app", "a") in out["pairs"] and ("app", "b") in out["pairs"]


def test_an_unresolved_import_produces_no_edge():
    targets = {"app": _T("app", "app"), "lib": _T("lib", "libcfg.so")}
    recs = {"app": _rec(imports=["nowhere"]), "lib": _rec(exports=["elsewhere"])}
    assert _resolve(targets, recs)["pairs"] == {}


def test_an_empty_case_resolves_to_nothing():
    out = _resolve({}, {})
    assert out["pairs"] == {} and out["needed"] == {} and out["targets"] == {}


def test_a_component_with_no_triage_record_is_not_a_crash():
    """Carved firmware components arrive without triage; the rest of the case still resolves."""
    targets = {"app": _T("app", "app"), "lib": _T("lib", "libcfg.so")}
    recs = {"app": _rec(imports=["parse_cfg"])}          # lib has no record at all
    out = _resolve(targets, recs)
    assert out["targets"]["lib"]["imports"] == set()
    assert out["pairs"] == {}


def test_symbols_on_an_edge_are_sorted_so_the_graph_is_stable():
    targets = {"app": _T("app", "app"), "lib": _T("lib", "libcfg.so")}
    recs = {"app": _rec(imports=["zeta", "alpha", "mid"]),
            "lib": _rec(exports=["zeta", "alpha", "mid"])}
    out = _resolve(targets, recs)
    assert out["pairs"][("app", "lib")] == ["alpha", "mid", "zeta"]
