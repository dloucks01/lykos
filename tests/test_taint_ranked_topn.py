"""Inter-procedural taint above the function budget: ranked top-N, never a silent hard drop.

The data-flow channel used to return an EMPTY result for any program over `_MAX_FUNCS`
functions (libcrypto: 13,529 functions -> no taint, no dereference channel, nothing corroborated).
It now analyses the functions nearest the taint origins and reports exactly how many it skipped.
"""
from lykos.analyze.detect import taint


class _Edge:
    def __init__(self, src, site, name, dst=None, external=True):
        self.src_addr, self.site_addr, self.dst_name = src, site, name
        self.dst_addr, self.external = dst, external


def _fn(addr, *instrs):
    return {"blocks": [{"addr": addr, "succ": [], "instructions": list(instrs)}]}


def _i(addr, *pcode):
    return {"addr": addr, "pcode": list(pcode)}


MAIN, HELPER = "0x1000", "0x2000"


def _program(reachable_fillers=0, unreachable_fillers=0):
    """main: getenv() -> RDI -> helper(); helper: strcpy(dst, param0). Plus filler functions,
    some called from main (reachable from the origin), some connected to nothing."""
    irs = {
        MAIN: _fn(MAIN,
                  _i("0x1010", "CALL ram:0x9000:8"),                   # getenv -> RAX tainted
                  _i("0x1014", "COPY reg:RAX:8 -> reg:RDI:8"),
                  _i("0x1018", "CALL ram:0x2000:8")),                  # helper(tainted)
        HELPER: _fn(HELPER,
                    _i("0x2004", "COPY reg:RDI:8 -> reg:RSI:8"),
                    _i("0x2010", "CALL ram:0x9100:8")),                 # strcpy(?, tainted)
    }
    edges = [_Edge(MAIN, "0x1010", "getenv"),
             _Edge(MAIN, "0x1018", "helper", dst=HELPER, external=False),
             _Edge(HELPER, "0x2010", "strcpy")]
    for k in range(reachable_fillers):
        a = hex(0x10000 + k * 0x100)
        irs[a] = _fn(a, _i(hex(0x10000 + k * 0x100 + 4), "COPY reg:RDI:8 -> reg:RAX:8"))
        edges.append(_Edge(MAIN, hex(0x1100 + k), f"fill{k}", dst=a, external=False))
    for k in range(unreachable_fillers):
        a = hex(0x40000 + k * 0x100)
        irs[a] = _fn(a, _i(hex(0x40000 + k * 0x100 + 4), "COPY reg:RDI:8 -> reg:RAX:8"))
    return irs, edges


def test_under_the_budget_is_unchanged():
    irs, edges = _program(reachable_fillers=3, unreachable_fillers=3)
    rep = {}
    flagged = taint.analyze_program(irs, edges, "x86-64", ranked_out=rep)
    assert "0x2010" in flagged                 # the inter-procedural flow
    assert rep == {}                           # no ranking below the cap


def test_over_the_budget_is_ranked_not_dropped():
    """The old behaviour returned set() here. The flow (main -> helper -> strcpy) sits nearest the
    origin and next to the sink, so it survives a budget far below the program size."""
    irs, edges = _program(reachable_fillers=20, unreachable_fillers=40)
    full = taint.analyze_program(irs, edges, "x86-64")
    rep = {}
    ranked = taint.analyze_program(irs, edges, "x86-64", max_funcs=2, ranked_out=rep)
    assert "0x2010" in full and ranked == {"0x2010"}
    assert rep["total"] == 62 and rep["analyzed"] == 2 and rep["skipped"] == 60
    assert rep["unreachable"] == 40            # cannot carry taint: no loss
    assert rep["skipped_reachable"] == 20      # the honest size of the capability loss
    assert rep["exact"] is False and "NOT analysed" in rep["note"]


def test_only_unreachable_functions_skipped_is_exact():
    """Functions with no call-graph path to any taint origin can never be tainted, so dropping them
    loses nothing: the ranked result must EQUAL the unbounded one, derefs included."""
    irs, edges = _program(reachable_fillers=2, unreachable_fillers=50)
    d_full, d_rank = [], []
    full = taint.analyze_program(irs, edges, "x86-64", mem_out=d_full)
    rep = {}
    ranked = taint.analyze_program(irs, edges, "x86-64", max_funcs=10, mem_out=d_rank,
                                   ranked_out=rep)
    assert ranked == full and d_rank == d_full
    assert rep["exact"] is True and rep["skipped_reachable"] == 0 and rep["analyzed"] == 4


def test_entry_seeds_are_origins():
    """argv at main is an origin even with no SOURCE call: the seeded entry is ranked first."""
    irs = {MAIN: _fn(MAIN, _i("0x1014", "COPY reg:RSI:8 -> reg:RDI:8"),
                     _i("0x1018", "CALL ram:0x2000:8")),
           HELPER: _fn(HELPER, _i("0x2004", "COPY reg:RDI:8 -> reg:RSI:8"),
                       _i("0x2010", "CALL ram:0x9100:8"))}
    edges = [_Edge(MAIN, "0x1018", "helper", dst=HELPER, external=False),
             _Edge(HELPER, "0x2010", "strcpy")]
    for k in range(30):
        a = hex(0x40000 + k * 0x100)
        irs[a] = _fn(a, _i(hex(0x40000 + k * 0x100 + 4), "COPY reg:RDI:8 -> reg:RAX:8"))
    rep = {}
    flagged = taint.analyze_program(irs, edges, "x86-64", entry_seeds={MAIN: {1}},
                                    max_funcs=2, ranked_out=rep)
    assert "0x2010" in flagged and rep["origins"] == 1 and rep["exact"]


def test_rank_prefers_sink_adjacent_within_a_layer():
    irs, edges = _program(reachable_fillers=5)
    sel, rep = taint.rank_functions(set(irs), edges, 2)
    assert sel == {MAIN, HELPER}               # helper (calls strcpy) beats the 5 fillers
    assert rep["max_depth"] == 1 and rep["sink_functions"] == 1


def test_cross_component_summary_is_ranked_too():
    irs, edges = _program(reachable_fillers=0, unreachable_fillers=10)
    old = taint._MAX_FUNCS
    try:
        taint._MAX_FUNCS = 3
        rep = {}
        out = taint.callee_sink_exports(irs, edges, "x86-64", {"helper": HELPER}, ["helper"],
                                        ranked_out=rep)
    finally:
        taint._MAX_FUNCS = old
    assert out.get("helper") and rep["helper"]["exact"] is True
