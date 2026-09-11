"""Can the tool see a bug that is not a function call?

Every other detector keys on a call edge, a string, or a triage mitigation. jhead's only
demonstrated bug -- the one AFL++ found, the debugger root-caused and the L1 PoC reproduces --
is an out-of-bounds read at `movzx eax,BYTE PTR [rax]`. That is not a call to anything, so the
static channel could not see it and never could. A reproduced crash therefore had nothing to
promote: not because attribution was weak, but because no finding existed for the only bug
proven in real software.
"""
from lykos.analyze.detect.stage import _deref_candidates


class _Fn:
    def __init__(self, addr, name):
        self.addr, self.name = addr, name


_FNS = [_Fn("0x900", "ProcessGpsInfo"), _Fn("0xb00", "ReadJpegSections")]


def _acc(kind, fn, site):
    return {"kind": kind, "function_addr": fn, "site_addr": site, "addr_key": ("reg", "RAX")}


def test_a_tainted_load_is_an_out_of_bounds_read_candidate():
    out = _deref_candidates([_acc("load", "0x900", "0x1234")], _FNS)
    assert len(out) == 1
    assert out[0]["cwe"] == "CWE-125" and out[0]["site_addr"] == "0x1234"
    assert out[0]["detector"] == "tainted_deref"


def test_a_tainted_store_is_the_more_serious_write_candidate():
    out = _deref_candidates([_acc("store", "0x900", "0x1234")], _FNS)
    assert out[0]["cwe"] == "CWE-787" and out[0]["severity"] == "medium"


def test_reads_and_writes_are_separate_defects():
    out = _deref_candidates([_acc("load", "0x900", "0x10"),
                             _acc("store", "0xb00", "0x20")], _FNS)
    assert {c["cwe"] for c in out} == {"CWE-125", "CWE-787"}
    assert len({c["dedup_key"] for c in out}) == 2


def test_every_occurrence_becomes_its_own_site_under_one_defect():
    """122 separate findings would bury the board; one defect with 122 sites is the grain the
    call-sink detectors already use, and it is what lets a crash promote the right occurrence.
    """
    accs = [_acc("load", "0x900", hex(0x1000 + i)) for i in range(20)]
    out = _deref_candidates(accs, _FNS)
    assert len(out) == 20, "one candidate per site"
    assert len({c["dedup_key"] for c in out}) == 1, "merging into a single defect"
    assert len({c["site_addr"] for c in out}) == 20


def test_it_is_filed_as_inventory_not_as_an_assertion():
    """Whether a given dereference is actually unchecked needs a bound on the index, which
    this does not have. What it has is where attacker data reaches a pointer -- a crash
    landing on one of those sites is what turns it into a finding."""
    out = _deref_candidates([_acc("load", "0x900", "0x1234")], _FNS)
    assert out[0]["state"] == "candidate" and out[0]["confidence"] <= 0.4
    assert out[0]["severity"] == "low"


def test_nothing_is_reported_when_no_input_reaches_a_pointer():
    assert _deref_candidates([], _FNS) == []


def test_the_site_detail_names_the_function():
    out = _deref_candidates([_acc("load", "0x900", "0x1234")], _FNS)
    assert "ProcessGpsInfo" in out[0]["site_detail"]


def test_an_unnamed_function_still_produces_a_site():
    out = _deref_candidates([_acc("load", "0xdead", "0x1234")], _FNS)
    assert len(out) == 1 and "0xdead" in out[0]["site_detail"]
