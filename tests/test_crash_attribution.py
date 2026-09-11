"""Does the crash prove any of the static findings?

A verified PoC used to land as an orphan row keyed on the signal, sitting beside an
undifferentiated pile of static findings. On jhead that was one "out-of-bounds read" next to
38 unknown copy sites -- several in the very function the fault was in -- with nothing joining
them. The backtrace already records which calls were executing; this reads it, and grades how
strong the resulting claim is.
"""
from lykos.analyze.debug import rootcause


class _F:
    def __init__(self, fid, fn=None, site=None, title="t", cwe="CWE-120", key="k"):
        self.id, self.function_addr, self.site_addr = fid, fn, site
        self.title, self.cwe, self.dedup_key = title, cwe, key
        self.state, self.confidence, self.severity, self.detector = "corroborated", 0.8, "high", "d"
        self.evidence = []


def _frame(addr, func=None, symbol=None, fault_pc=False):
    e = {"addr": addr, "static_addr": addr, "module": "t", "symbol": symbol}
    if func is not None:
        e["func_addr"] = func
    if fault_pc:
        e["fault_pc"] = True
    return e


# a copy site at 0x1000; a `call` is 5 bytes on x86, so the return address is 0x1005
_SITE, _RET = "0x1000", 0x1005


def test_a_fault_inside_the_call_a_finding_names_is_a_demonstration():
    """The strongest claim available: the sink itself faulted, so the finding is proven and
    the PoC is its evidence."""
    f = _F("a", fn="0x900", site=_SITE)
    frames = [_frame(0x7f0000, symbol="memcpy", fault_pc=True),   # inside libc, unsymbolized
              _frame(_RET, func="0x900", symbol="parse")]
    got = rootcause.attribute(frames, [f])
    assert [a["tier"] for a in got] == ["fault-site"]
    assert got[0]["site"] == _SITE and "0x1000 in parse" in got[0]["detail"]


def test_a_call_deeper_on_the_stack_is_on_the_path_but_not_proven():
    """The call was executing, but the fault happened further in -- that does not show this
    copy overflowed anything."""
    f = _F("a", fn="0x900", site=_SITE)
    frames = [_frame(0x2000, func="0xb00", symbol="inner", fault_pc=True),
              _frame(0x2100, func="0xb00", symbol="inner"),
              _frame(_RET, func="0x900", symbol="parse")]
    got = rootcause.attribute(frames, [f])
    assert [a["tier"] for a in got] == ["on-stack"]


def test_sharing_a_function_with_the_crash_is_only_proximity():
    f = _F("a", fn="0x900", site="0x1400")            # no frame returns near this site
    frames = [_frame(0x950, func="0x900", symbol="parse", fault_pc=True)]
    got = rootcause.attribute(frames, [f])
    assert [a["tier"] for a in got] == ["crash-function"]
    assert "not proof" in got[0]["detail"]


def test_a_finding_nowhere_near_the_crash_is_not_attributed():
    f = _F("a", fn="0x4000", site="0x4100")
    frames = [_frame(0x950, func="0x900", symbol="parse", fault_pc=True)]
    assert rootcause.attribute(frames, [f]) == []


def test_every_occurrence_is_considered_not_just_the_first():
    """Findings are deduped at DEFECT grain -- one CWE-120 row covers twenty memcpy sites, and
    the row's own site_addr is merely the first. Matching against that alone would see a
    twentieth of the program."""
    f = _F("a", fn="0x100", site="0x110")             # first occurrence, far from the crash
    sites = {"a": [{"function_addr": "0x100", "site_addr": "0x110"},
                   {"function_addr": "0x900", "site_addr": _SITE}]}
    frames = [_frame(0x7f0000, fault_pc=True), _frame(_RET, func="0x900", symbol="parse")]
    got = rootcause.attribute(frames, [f], sites)
    assert [a["tier"] for a in got] == ["fault-site"] and got[0]["site"] == _SITE


def test_the_site_is_named_in_every_tier():
    """At defect grain, "this defect occurs in a function on the stack" is close to vacuous.
    Which occurrence is the whole content of the claim."""
    f = _F("a", fn="0x900", site="0x1400")
    frames = [_frame(0x950, func="0x900", symbol="parse", fault_pc=True)]
    assert "0x1400 in parse" in rootcause.attribute(frames, [f])[0]["detail"]


def test_the_strongest_tier_wins_for_a_finding_matched_twice():
    f = _F("a", fn="0x900", site=_SITE)
    frames = [_frame(0x7f0000, fault_pc=True), _frame(_RET, func="0x900", symbol="parse")]
    got = rootcause.attribute(frames, [f])
    assert len(got) == 1 and got[0]["tier"] == "fault-site"


def test_a_return_address_picks_the_closest_preceding_call_site():
    """Two sites can sit within a call's length of one another; the one the frame actually
    returned from is the nearest below it."""
    near, far = _F("near", fn="0x900", site="0x1000"), _F("far", fn="0x900", site="0xff0")
    frames = [_frame(0x7f0000, fault_pc=True), _frame(_RET, func="0x900", symbol="parse")]
    got = {a["finding"].id: a["tier"] for a in rootcause.attribute(frames, [near, far])}
    assert got["near"] == "fault-site"
    assert got.get("far") == "crash-function", "the far site is only in the same function"


def test_a_return_address_far_past_a_site_is_not_that_call():
    f = _F("a", fn="0x900", site="0x100")             # 0x1005 is ~4 KiB later
    frames = [_frame(0x7f0000, fault_pc=True), _frame(_RET, func="0xb00", symbol="other")]
    assert rootcause.attribute(frames, [f]) == []


# ---------------------------------------------------------------- PIE address rebasing
# Symbolization was absolute-only, so on a PIE target no runtime address ever fell inside the
# static function table: no frame resolved, and nothing could be attributed at all.
class _Fn:
    def __init__(self, addr, name, size=0x100):
        self.addr, self.name, self.size = addr, name, size


_MAPS = [{"start": 0x555500000000, "end": 0x555500010000, "path": "/tmp/target.bin"}]


def test_a_pie_frame_is_rebased_into_the_static_image():
    ranges = rootcause._fn_ranges([_Fn("0x1200", "parse")])
    base = rootcause.module_base(_MAPS, "/tmp/target.bin")
    assert base == 0x555500000000
    got = rootcause.symbolize(0x555500001234, _MAPS, ranges, "/tmp/target.bin", base)
    assert got["symbol"] == "parse" and got["static_addr"] == 0x1234


def test_a_no_pie_frame_still_matches_absolutely():
    maps = [{"start": 0x400000, "end": 0x410000, "path": "/tmp/target.bin"}]
    ranges = rootcause._fn_ranges([_Fn("0x401200", "parse")])
    got = rootcause.symbolize(0x401234, maps, ranges, "/tmp/target.bin",
                              rootcause.module_base(maps, "/tmp/target.bin"))
    assert got["symbol"] == "parse" and got["static_addr"] == 0x401234


def test_an_address_in_another_module_is_not_rebased():
    """Rebasing a libc address into the target's function table would invent a symbol."""
    maps = _MAPS + [{"start": 0x7f0000000000, "end": 0x7f0000100000, "path": "/lib/libc.so.6"}]
    ranges = rootcause._fn_ranges([_Fn("0x1200", "parse")])
    got = rootcause.symbolize(0x7f0000001234, maps, ranges, "/tmp/target.bin",
                              rootcause.module_base(maps, "/tmp/target.bin"))
    assert got["symbol"] is None and "static_addr" not in got


# ---------------------------------------------------------------- gdb frame parsing
# The capture dropped the frame the whole feature depends on. gdb omits the address for the
# INNERMOST frame, so "#0" never parsed, and slicing the first element off the parsed list
# threw away "#1" -- the caller that names the faulting call site. On the worked example that
# turned a provable finding into an unattributed crash.
_BT = """
Program received signal SIGSEGV, Segmentation fault.
#0  __memcpy_avx512_unaligned_erms () at ../sysdeps/x86_64/multiarch/memmove.S:265
#1  0x0000555555555214 in parse ()
#2  0x00005555555552e1 in main ()
"""


def test_the_innermost_frame_is_dropped_by_number_not_by_position():
    from lykos.analyze.debug import gdb
    frames = []
    for line in _BT.splitlines():
        m = gdb._FRAME.match(line.strip())
        if m and m.group(2) and m.group(1) != "0":
            frames.append(int(m.group(2), 16))
    assert frames == [0x555555555214, 0x5555555552e1], "frame #1 must survive"


def test_an_addressed_frame_zero_is_still_dropped():
    """When gdb DOES print an address for #0 it is the faulting PC, which the capture already
    records separately -- counting it as a return address would misattribute the crash."""
    from lykos.analyze.debug import gdb
    text = "#0  0x00007ffff7db0a0d in memcpy ()\n#1  0x0000555555555214 in parse ()"
    frames = []
    for line in text.splitlines():
        m = gdb._FRAME.match(line.strip())
        if m and m.group(2) and m.group(1) != "0":
            frames.append(int(m.group(2), 16))
    assert frames == [0x555555555214]
