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


# ---------------------------------------------------------------- how the input is fed back in
# The stage defaulted to stdin, so a file parser reported "no fault reproduced" -- which reads
# as a clean negative and actually meant "we fed it the wrong way". On jhead that silently
# discarded a real, reproducible crash until the mode was passed by hand. Three stages had it
# (root_cause, build_poc, poc_primitive), so the rule lives in one shared place now.
from lykos.analyze.poc import capture as feed  # noqa: E402
from lykos.db.dao import DynResultDAO  # noqa: E402


def _target(store, case):
    return store.targets.upsert(case.id, filename="t", sha256="a" * 64, size=1,
                                arch="x86-64", bits=64)


def test_an_explicit_mode_wins(store, case):
    t = _target(store, case)
    got = feed.how_to_feed(store.conn, t, "s" * 64,
                                 {"input_mode": "arg", "argv": ["-x"]})
    assert got == ("arg", ["-x"], "given")


def test_the_run_that_found_the_crash_says_how_it_fed_it(store, case):
    """Authoritative whenever the crash came from this pipeline: the dynamic run recorded the
    mode and argv it actually used."""
    t = _target(store, case)
    DynResultDAO(store.conn).insert(t.id, case.id, input_sha="c" * 64, input_mode="file",
                                    argv=["-v"], crashed=True, signal_name="SIGSEGV")
    assert feed.how_to_feed(store.conn, t, "c" * 64, {}) == (
        "file", ["-v"], "recorded by the run that found it")


def test_an_unrelated_run_is_not_consulted(store, case):
    """A different input's run says nothing about this one, so the answer falls through to
    inference rather than borrowing a mode that was never used for this payload."""
    t = _target(store, case)
    DynResultDAO(store.conn).insert(t.id, case.id, input_sha="d" * 64, input_mode="file",
                                    crashed=True, signal_name="SIGSEGV")
    mode, _argv, why = feed.how_to_feed(store.conn, t, "c" * 64, {})
    assert "recorded by the run" not in why and mode in feed.MODES


def test_the_fallback_infers_rather_than_assuming_stdin(store, case):
    """"Default to stdin" is a coin flip that loses on most real targets: a file parser reads
    nothing from stdin, so a campaign or probe aimed there does no work and reports a clean
    zero. The channels are ranked by the input functions the binary actually imports."""
    assert feed.modes_for([], None)[0] == "arg", "no input imports at all: argv is all that is left"

    class _E:
        def __init__(self, n):
            self.dst_name = n
    assert feed.modes_for([_E("fopen"), _E("fread")])[0] == "file"
    assert feed.modes_for([_E("fgets")])[0] == "stdin"
    # every channel is still attempted, whatever the ranking
    assert set(feed.modes_for([_E("fopen")])) == set(feed.MODES)


def test_every_mode_is_a_candidate_for_the_sweep():
    """Correctness must not rest on the opening guess -- the stage tries the rest before it
    concludes anything, so "no fault reproduced" finally means what it says."""
    assert set(feed.MODES) == {"stdin", "file", "arg"}


# ---------------------------------------------------------------- the promotion rule
def test_only_a_fault_site_promotes():
    f = _F("a", fn="0x900", site=_SITE)
    up = rootcause.attribution_upsert(
        f, {"tier": "fault-site", "detail": "d", "site": _SITE}, "SIGSEGV")
    assert up["state"] == "poc-backed" and up["confidence"] == 0.97


def test_a_weaker_tier_leaves_the_state_alone():
    """Being near a crash is not being the crash."""
    f = _F("a", fn="0x900", site=_SITE)
    for tier in ("on-stack", "crash-function"):
        up = rootcause.attribution_upsert(f, {"tier": tier, "detail": "d", "site": _SITE},
                                          "SIGSEGV")
        assert up["state"] == f.state and up["confidence"] == f.confidence


def test_attribution_keeps_the_original_detector():
    """upsert rewrites the detector on merge, so a crash attributed to a `dangerous_api`
    finding would relabel it as the debugger that noticed."""
    f = _F("a", fn="0x900", site=_SITE)
    f.detector = "dangerous_api"
    up = rootcause.attribution_upsert(
        f, {"tier": "fault-site", "detail": "d", "site": _SITE}, "SIGSEGV")
    assert up["detector"] == "dangerous_api" and up["dedup_key"] == f.dedup_key


# ---------------------------------------------------------------- the faulting instruction
# A finding that is not a CALL can never be reached by matching return addresses to call
# sites. jhead's only demonstrated bug is an out-of-bounds read -- a `mov`, not a call to
# anything -- so without this the one bug the tool actually proved could not be attributed to
# anything it had predicted.
def test_the_faulting_instruction_itself_is_the_strongest_match():
    f = _F("a", fn="0x900", site="0x1234", cwe="CWE-125")
    frames = [_frame(0x1234, func="0x900", symbol="ProcessGpsInfo", fault_pc=True)]
    got = rootcause.attribute(frames, [f])
    assert [a["tier"] for a in got] == ["fault-site"]
    assert "faulting instruction IS this site" in got[0]["detail"]
    assert "0x1234 in ProcessGpsInfo" in got[0]["detail"]


def test_a_nearby_instruction_is_not_the_faulting_one():
    """Exact match only. A dereference two instructions later is a different statement, and
    calling it proven would put a PoC behind the wrong line."""
    f = _F("a", fn="0x900", site="0x1230")
    frames = [_frame(0x1234, func="0x900", symbol="fn", fault_pc=True)]
    assert [a["tier"] for a in rootcause.attribute(frames, [f])] == ["crash-function"]


def test_a_pc_match_needs_the_frame_to_be_the_fault():
    """A return address that happens to equal a site is a call that RETURNED there, not the
    instruction that faulted."""
    f = _F("a", fn="0x900", site="0x1234")
    frames = [_frame(0x2000, func="0xb00", symbol="inner", fault_pc=True),
              _frame(0x1234, func="0x900", symbol="fn")]
    assert [a["tier"] for a in rootcause.attribute(frames, [f])] != ["fault-site"]


def test_two_defects_that_both_segfault_are_two_findings():
    """Crash findings were keyed by signal alone, so every SIGSEGV in a program was one
    finding: a jhead campaign reported 8,516 crashes as a single "unique". The faulting
    instruction is what separates two defects that raise the same signal."""
    from lykos.analyze.dynamic.stage import crash_dedup_key, crash_finding_candidate
    a = crash_finding_candidate("SIGSEGV", "a" * 64, "bwrap", "fuzz", fault_pc=0x40637A)
    b = crash_finding_candidate("SIGSEGV", "b" * 64, "bwrap", "fuzz", fault_pc=0x4099C0)
    assert a["dedup_key"] != b["dedup_key"]
    assert a["site_addr"] == "0x40637a", "and the finding says where"
    # the same defect found twice is still one finding, however many inputs reach it
    c = crash_finding_candidate("SIGSEGV", "c" * 64, "bwrap", "poc", fault_pc=0x40637A)
    assert c["dedup_key"] == a["dedup_key"]
    # no address (an untraced run): the old behaviour, not a third bucket per input
    assert crash_dedup_key("SIGSEGV") == "dynamic-crash:SIGSEGV"
    assert crash_finding_candidate("SIGSEGV", "d" * 64, "rlimit", "fuzz")["dedup_key"] == \
        crash_dedup_key("SIGSEGV")


def test_every_stage_derives_the_same_key(store, case):
    """A verified PoC must PROMOTE the crash it just proved, not file a second finding beside
    it. The address therefore lives on the crash row, so build_poc, root_cause and synthesize
    all read the same value rather than each deriving its own."""
    from lykos.analyze.dynamic.stage import crash_dedup_key, find_crash_finding
    from lykos.db.dao import DynResultDAO, FindingDAO
    t = _target(store, case)
    dd = DynResultDAO(store.conn)
    dd.insert(t.id, case.id, input_sha="e" * 64, input_mode="file", crashed=True,
              signal_name="SIGSEGV", fault_pc=0x40637A)
    assert dd.fault_pc_for(t.id, "e" * 64) == 0x40637A
    assert dd.fault_pc_for(t.id, "f" * 64) is None, "a different input says nothing"

    fd = FindingDAO(store.conn)
    from lykos.analyze.dynamic.stage import crash_finding_candidate
    fd.upsert(t.id, case.id, crash_finding_candidate(
        "SIGSEGV", "e" * 64, "bwrap", "fuzz", fault_pc=0x40637A))
    found = find_crash_finding(store.conn, t.id, "SIGSEGV", "e" * 64)
    assert found and found == fd.id_for_dedup(t.id, crash_dedup_key("SIGSEGV", 0x40637A))


def test_a_legacy_crash_finding_is_still_found():
    """Cases recorded before the key carried an address only have the signal, and the lookup
    has to keep matching them or a re-run files a duplicate."""
    from lykos.analyze.dynamic.stage import crash_dedup_key
    assert crash_dedup_key("SIGABRT", None) == "dynamic-crash:SIGABRT"
    assert crash_dedup_key("SIGABRT", 0) == "dynamic-crash:SIGABRT", "0 is not an address"


def test_sigabrt_buckets_by_signal_even_with_a_fault_pc():
    """A SIGABRT is raised by a runtime CHECK (glibc malloc/free, a canary, ASan) -- its PC is in
    the abort machinery (often a randomized image-relative libc offset), not the defect. Keying it
    by that PC split ONE double-free into dozens of findings, so an abort is bucketed by signal
    alone; a SIGSEGV (a real fault at an instruction) still keeps its faulting address."""
    from lykos.analyze.dynamic.stage import crash_dedup_key
    assert crash_dedup_key("SIGABRT", 0x730f5eca61ac) == "dynamic-crash:SIGABRT"
    assert crash_dedup_key("SIGABRT", 0x7c54aaea61ac) == "dynamic-crash:SIGABRT"   # same bucket
    assert crash_dedup_key("SIGSEGV", 0x40117a) == "dynamic-crash:SIGSEGV:40117a"  # PC kept
    assert crash_dedup_key("SIGSEGV", 0x409999) != crash_dedup_key("SIGSEGV", 0x40117a)


def test_an_emulated_crash_still_gets_a_fault_locus():
    """The ptrace tracer cannot reach inside qemu, so a cross-architecture crash had no
    faulting address and every SIGSEGV in the program bucketed as one finding -- on eleven of
    the twelve architectures the platform builds real targets for. qemu's own block log stops
    at the fault, so the last block it translated is the closest thing to a locus available
    there: a block address rather than the exact instruction, which is enough to tell two
    defects apart."""
    import pathlib
    import shutil
    import subprocess

    import pytest
    from lykos.analyze.dynamic import sandbox
    exe = pathlib.Path("examples/vuln-targets/bin/jhead_aarch64").resolve()
    bad = pathlib.Path("examples/vuln-targets/inputs/jhead-crash.jpg").resolve()
    if not exe.exists() or not shutil.which("qemu-aarch64") or not shutil.which("readelf"):
        pytest.skip("run examples/vuln-targets/fetch_build.sh; qemu-aarch64 needed")
    out = subprocess.run(["readelf", "-sW", str(exe)], capture_output=True, text=True).stdout
    blocks = tuple(sorted({int(f[1], 16) for f in (ln.split() for ln in out.splitlines())
                           if len(f) >= 8 and f[3] in ("FUNC", "IFUNC") and f[6] != "UND"
                           and int(f[1], 16)}))
    res = sandbox.run(exe, argv=[str(bad)], arch="aarch64", timeout=30, blocks=blocks)
    assert res.crashed
    assert res.fault_pc, "a crash under emulation must still say where it died"
    # a clean run has nowhere to point
    ok = pathlib.Path("examples/vuln-targets/inputs/jhead-ok.jpg").resolve()
    clean = sandbox.run(exe, argv=[str(ok)], arch="aarch64", timeout=30, blocks=blocks)
    assert not clean.crashed and clean.fault_pc is None
