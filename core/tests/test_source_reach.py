"""Source call-graph attacker-reachability."""
from lykos.analyze import source_reach

def test_reaches_callee_of_wire_entry(tmp_path):
    (tmp_path/"a.c").write_text(
        'int helper(int x){ return x+1; }\n'
        'int parse(wStream* s){ int v; Stream_Read_UINT32(s, v); return helper(v); }\n'
        'int unrelated(void){ return 0; }\n')
    reach, adj, entries = source_reach.reachable_from_wire(str(tmp_path))
    assert "parse" in entries              # reads a stream -> wire entry
    assert "helper" in reach               # called by a wire entry -> reachable
    assert "unrelated" not in reach        # never reached

def test_name_based_entry(tmp_path):
    (tmp_path/"b.c").write_text('int foo_recv(void){ return bar(); }\nint bar(void){return 0;}\n')
    reach,_,entries = source_reach.reachable_from_wire(str(tmp_path))
    assert "foo_recv" in entries and "bar" in reach
