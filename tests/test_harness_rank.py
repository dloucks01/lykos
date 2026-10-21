"""T1 fuzz-worthiness ranker (doc 46): a function that INGESTS input, touches a dangerous sink,
has a pointer+length prototype and loops ranks above one that does none of those, and a function
with no attack-surface signal at all is dropped."""
from __future__ import annotations

from lykos.analyze.harness.rank import _ptr_len_confidence, _param_types, rank_functions
from lykos.db.dao import CallEdgeDAO, FunctionDAO


def test_ptr_len_confidence():
    assert _ptr_len_confidence(["char * buf", "size_t len"]) == 2        # ptr + len
    assert _ptr_len_confidence(["char * s"]) == 1                        # ptr only
    assert _ptr_len_confidence(["int flag"]) == 0                        # neither
    assert _ptr_len_confidence([]) == 0


def test_param_types_from_signature():
    assert _param_types(None, "int parse(char *buf, unsigned long n)") == \
        ["char *buf", "unsigned long n"]
    assert _param_types(None, "void f(void)") == []


def test_rank_prefers_input_parsers(store, case):
    from tests.factories import make_target
    t = make_target(store, case.id)
    FunctionDAO(store.conn).replace_for_target(t.id, [
        # a parser: reads input + dangerous sink + (buf,len) prototype + loops
        {"addr": "0x1000", "name": "parse", "size": 0x200, "blocks": 5, "edges": 8,
         "params": [{"type": "char *", "name": "buf"}, {"type": "size_t", "name": "len"}]},
        # a leaf utility: no input, no sink, no loop, trivial prototype
        {"addr": "0x2000", "name": "noop", "size": 0x40, "blocks": 1, "edges": 0,
         "params": [{"type": "int", "name": "flag"}]},
    ])
    CallEdgeDAO(store.conn).replace_for_target(t.id, [
        {"src_addr": "0x1000", "dst_name": "recv"},     # parse() reads input
        {"src_addr": "0x1000", "dst_name": "strcpy"},   # ...into a dangerous sink
        {"src_addr": "0x2000", "dst_name": "puts"},     # noop() does nothing interesting
    ])
    ranked = rank_functions(store.conn, t.id, top=10)
    assert ranked, "the parser should rank"
    assert ranked[0].name == "parse"
    top = ranked[0]
    assert "recv" in top.sources and "strcpy" in top.sinks
    assert top.ptr_len == 2
    # the scoreless leaf is dropped, not ranked.
    assert all(r.name != "noop" for r in ranked)
