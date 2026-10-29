"""Taint-to-entry reachability: is a finding's function actually reachable from an attacker entry,
or is its 'untrusted input' an assumed-untrusted parameter no attacker path feeds? The key property
is CROSS-BINARY: a harness holds entry->parse, the library holds parse->deep; reachability must
reconnect them by name, not BFS each binary alone (which severs the path)."""
from lykos.analyze import taint_reach as TR
from lykos.db.dao import CallEdgeDAO, FunctionDAO, TargetDAO


class _F:
    def __init__(self, addr, name): self.addr, self.name = addr, name


class _E:
    def __init__(self, s, d=None, dn=None): self.src_addr, self.dst_addr, self.dst_name = s, d, dn


def test_reachable_within_a_single_target():
    funcs = [_F("0x1000", "LLVMFuzzerTestOneInput"), _F("0x1100", "parse"), _F("0x1200", "helper"),
             _F("0x9000", "orphan")]
    edges = [_E("0x1000", "0x1100"), _E("0x1100", "0x1200")]
    r = TR.reachable_names_for_target(funcs, edges)
    assert "parse" in r and "helper" in r and "orphan" not in r


def test_a_bare_library_with_no_entry_reaches_nothing():
    funcs = [_F("0x1", "a"), _F("0x2", "b")]
    edges = [_E("0x1", "0x2")]
    assert TR.reachable_names_for_target(funcs, edges) == set()


def test_cross_binary_union_reconnects_the_deep_chain(store, case):
    """The regression this module was rewritten for: harness has entry->parse (1 hop), the library
    has parse->deep->sink (no entry of its own). Per-target BFS + union severs it; the unified
    name graph must reach `sink`."""
    conn = store.conn
    har = TargetDAO(conn).upsert(case.id, "harness", "a" * 64, arch="x86-64", bits=64)
    lib = TargetDAO(conn).upsert(case.id, "lib.so", "b" * 64, arch="x86-64", bits=64)
    # harness: entry -> parse (and parse exists here as a thin stub)
    FunctionDAO(conn).replace_for_target(har.id, [
        {"addr": "0x1000", "name": "LLVMFuzzerTestOneInput"}, {"addr": "0x1100", "name": "parse"}])
    CallEdgeDAO(conn).replace_for_target(har.id, [{"src_addr": "0x1000", "dst_addr": "0x1100"}])
    # library: parse -> deep -> sink (the real chain), plus an unrelated island
    FunctionDAO(conn).replace_for_target(lib.id, [
        {"addr": "0x2000", "name": "parse"}, {"addr": "0x2100", "name": "deep"},
        {"addr": "0x2200", "name": "sink"}, {"addr": "0x3000", "name": "island"}])
    CallEdgeDAO(conn).replace_for_target(lib.id, [
        {"src_addr": "0x2000", "dst_addr": "0x2100"}, {"src_addr": "0x2100", "dst_addr": "0x2200"}])
    reach = TR.harness_reachable_names(conn, case.id)
    assert {"parse", "deep", "sink"} <= reach      # cross-binary chain reconnected
    assert "island" not in reach                   # genuinely unreached stays out


def test_enclosing_function_finds_the_definition():
    src = ("int other(void) { return 0; }\n"
           "static int parse_cs2(ParseCtx* file)\n"
           "{\n"
           "\tchar* a = NULL;\n"
           "\ta[alen] = '\\0';\n"           # line 5 -- the sink
           "\treturn TRUE;\n"
           "}\n")
    assert TR.enclosing_function(src, 5) == "parse_cs2"
    assert TR.enclosing_function(src, 1) == "other"


def test_ground_reach_positive_negative_and_undecided():
    reach = {"parse_cs2", "deep"}
    on = {"cwe": "CWE-787", "evidence": [{"channel": "source", "detail": "x.c:5: oob in parse_cs2"}],
          "function_addr": None}
    off = {"cwe": "CWE-416", "evidence": [{"channel": "source", "detail": "y.c:9: uaf in local_only"}],
           "function_addr": None}
    none = {"cwe": "CWE-190", "evidence": [{"channel": "recipe", "detail": "overflow-prone arithmetic"}],
            "function_addr": None}
    assert TR.ground_reach(on, reach)["reachable"] is True
    assert TR.ground_reach(off, reach)["reachable"] is False
    assert TR.ground_reach(none, reach)["reachable"] is None     # no name -> undecided, not dropped


def test_mangled_symbol_tail_matches():
    reach = {"parse_cs2"}
    f = {"cwe": "CWE-787", "evidence": [{"channel": "source", "detail": "in method.libx.parse_cs2 at 0x10"}]}
    assert TR.ground_reach(f, reach)["reachable"] is True
