"""Sink-directed basic-block distance (AFLGo-style) over the recovered CFG."""
from lykos.analyze.fuzz import blockdist


class _F:
    def __init__(self, addr, blocks):
        self.addr = addr
        self.ir = {"blocks": blocks}


def _blk(addr, succ=(), instr=()):
    return {"addr": hex(addr), "succ": [hex(s) for s in succ],
            "instructions": [{"addr": hex(i)} for i in instr]}


class _E:
    def __init__(self, src, site, dst):
        self.src_addr, self.site_addr, self.dst_addr = hex(src), hex(site), hex(dst)


def _program():
    # main@0x1000: 1000 -> {1010,1020}; 1010 calls parse@0x1015 -> 1030; 1020 -> 1030; 1030 ret
    main = _F(0x1000, [
        _blk(0x1000, succ=(0x1010, 0x1020), instr=(0x1000, 0x1004)),
        _blk(0x1010, succ=(0x1030,), instr=(0x1010, 0x1015)),   # 0x1015 = call parse
        _blk(0x1020, succ=(0x1030,), instr=(0x1020,)),
        _blk(0x1030, succ=(), instr=(0x1030,)),
    ])
    # parse@0x2000: single block that calls strcpy (the SINK) at 0x2005
    parse = _F(0x2000, [_blk(0x2000, succ=(), instr=(0x2000, 0x2005))])
    edges = [_E(0x1000, 0x1015, 0x2000),               # main -> parse
             _E(0x2000, 0x2005, 0x3000)]               # parse -> strcpy (sink call)
    return [main, parse], edges


def test_sink_block_is_distance_zero():
    funcs, edges = _program()
    dist = blockdist.block_distance(funcs, edges, target_sites={0x2005})
    assert dist[0x2000] == 0.0                          # block holding the sink call


def test_calling_block_is_closer_than_its_predecessor():
    funcs, edges = _program()
    dist = blockdist.block_distance(funcs, edges, target_sites={0x2005})
    # 0x1010 calls parse (df=0) -> cost 10*(0+1)=10; 0x1000 is one hop before it -> 11.
    assert dist[0x1010] == 10.0
    assert dist[0x1000] == 11.0
    assert dist[0x1010] < dist[0x1000]


def test_offpath_blocks_have_no_distance():
    funcs, edges = _program()
    dist = blockdist.block_distance(funcs, edges, target_sites={0x2005})
    # 0x1020 / 0x1030 are on no path to the sink -> unreachable, no entry.
    assert 0x1020 not in dist and 0x1030 not in dist


def test_min_distance_scores_an_input_by_closest_block_reached():
    funcs, edges = _program()
    dist = blockdist.block_distance(funcs, edges, target_sites={0x2005})
    assert blockdist.min_distance([0x1000, 0x1010], dist) == 10.0
    assert blockdist.min_distance([0x1000, 0x1020], dist) == 11.0
    assert blockdist.min_distance([0x2000], dist) == 0.0     # reached the sink block
    assert blockdist.min_distance([0x9999], dist) is None    # reached nothing on a path


def test_no_targets_is_empty():
    funcs, edges = _program()
    assert blockdist.block_distance(funcs, edges, target_sites=set()) == {}


def test_callgraph_distance_backward_bfs():
    _, edges = _program()
    df = blockdist.callgraph_distance(edges, [0x2000])
    assert df[0x2000] == 0 and df[0x1000] == 1
