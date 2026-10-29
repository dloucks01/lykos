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


def test_source_finding_reachability_decided_via_file_text_lookup(tmp_path):
    """A source finding that cites only file:line (no function name in prose) is still DECIDED:
    a whole-file text lookup resolves the enclosing function, which here is a wire parser by role
    -- so reachability is True, not the undecided it would be without the lookup. This is what lets
    the confirm promoter populate the rung on a source case."""
    from lykos.analyze import grounding
    (tmp_path / "chan.c").write_text(
        "int helper(int x){ return x; }\n"
        "void recv_pdu(Stream* s){\n"
        "    char buf[8];\n"
        "    memcpy(buf, s->data, s->len);   // line 5: the oob write\n"
        "}\n")
    text_lookup = grounding.make_file_text_lookup(tmp_path)
    assert "recv_pdu" in (text_lookup("chan.c") or "")
    f = {"cwe": "CWE-787", "function_addr": None,
         "evidence": [{"channel": "source", "detail": "chan.c:5: out-of-bounds write"}]}
    # Without the text lookup the name cannot be resolved -> undecided.
    assert TR.ground_reach(f, set())["reachable"] is None
    # With it, the enclosing function resolves to recv_pdu, a peer parser by role -> reachable.
    r = TR.ground_reach(f, set(), source_lookup=text_lookup)
    assert r["reachable"] is True and r["name"] == "recv_pdu" and r["basis"] == "peer-entry"


def test_is_peer_entry_recognizes_wire_parsers_and_reads():
    # role-y names the regex catches (the rest -- e.g. vendor_SurfaceCommand_Handler -- are caught
    # by reachability from these, or by source-path role, not by name).
    for n in ("recv", "SSL_read", "proto_recv_pdu", "codec_process_message", "lz_decompress",
              "tile_decode", "channel_recv", "read_order_header"):
        assert TR.is_peer_entry(n), n
    for n in ("spread_value", "readable", "main", "config_settings_new", "compute_crc"):
        assert not TR.is_peer_entry(n), n


def test_attacker_reachable_seeds_from_peer_parsers_even_without_a_read_edge(store, case):
    """A codec decoder reached only via indirect PDU dispatch (no edge from a read) is still on the
    attacker surface by role, and its callees come along -- the fix for protocol targets."""
    conn = store.conn
    lib = TargetDAO(conn).upsert(case.id, "lib.so", "a" * 64, arch="x86-64", bits=64)
    FunctionDAO(conn).replace_for_target(lib.id, [
        {"addr": "0x1000", "name": "codec_process_message"},   # peer parser (role), no caller edge
        {"addr": "0x1100", "name": "codec_rle_decode"}, {"addr": "0x1200", "name": "write_pixel"},
        {"addr": "0x9000", "name": "config_load_local"}])    # unrelated local helper
    CallEdgeDAO(conn).replace_for_target(lib.id, [
        {"src_addr": "0x1000", "dst_addr": "0x1100"}, {"src_addr": "0x1100", "dst_addr": "0x1200"}])
    reach = TR.attacker_reachable_names(conn, case.id)
    assert {"codec_process_message", "codec_rle_decode", "write_pixel"} <= reach
    assert "config_load_local" not in reach
    # and the old fuzz-only view does NOT see it (no fuzz/read entry present)
    assert "codec_process_message" not in TR.harness_reachable_names(conn, case.id)


def test_ground_reach_marks_peer_parser_reachable_with_basis():
    f = {"cwe": "CWE-122", "evidence": [{"channel": "source", "detail": "x.c:9: oob in tile_decode"}]}
    g = TR.ground_reach(f, set())            # empty graph set; role alone suffices
    assert g["reachable"] is True and g["basis"] == "peer-entry"
