"""F2 (doc 60): grounding's reachability for a source finding comes from the real source call graph
(source_reach), not the fuzz-harness heuristic. Unit-level: source_reach + taint_reach.ground_reach
agree on a fixture (a wire-reached function is reachable; an isolated one is not)."""
from lykos.analyze import source_reach, taint_reach


def test_source_reach_feeds_ground_reach(tmp_path):
    (tmp_path / "p.c").write_text(
        'static int sink(int* b, int i){ b[i] = 0; return 0; }\n'
        'int parse(wStream* s){ int i; Stream_Read_UINT32(s, i); int b[4]; return sink(b, i); }\n'
        'static int orphan(int* b, int i){ b[i] = 0; return 0; }\n')
    reach, _adj, _entries = source_reach.reachable_from_wire(str(tmp_path))
    assert "sink" in reach and "parse" in reach      # reached from the wire parser
    assert "orphan" not in reach                     # never called by any entry

    text = (tmp_path / "p.c").read_text()
    lookup = lambda path: text
    # a finding in sink() is attacker-reachable; one in orphan() is not
    r_sink = taint_reach.ground_reach({"evidence": [{"channel": "source", "detail": "p.c:1: write to b[i] in sink()"}]},
                                      reach, source_lookup=lookup)
    r_orphan = taint_reach.ground_reach({"evidence": [{"channel": "source", "detail": "p.c:3: write to b[i] in orphan()"}]},
                                        reach, source_lookup=lookup)
    assert r_sink.get("reachable") is True
    assert r_orphan.get("reachable") in (False, None)   # not on the reachable set
