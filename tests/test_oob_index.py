"""Out-of-bounds array-index discovery: array-candidate selection + boundary-index driving."""
from lykos.analyze.dynamic import oob_index


def test_array_candidates_picks_fixed_size_tables_skips_scalars():
    objs = {
        "authors": (0x2030c0, 80),        # 10-pointer table -> a candidate
        "heap": (0x203080, 8),            # scalar -> skipped (size 8)
        "grid": (0x2040a0, 64),           # 8-entry table -> a candidate
        "name_buf": (0x2050a0, 33),       # not a word multiple -> skipped
        "stdout@@GLIBC": (0x203060, 8),   # imported scalar -> skipped
    }
    cands = oob_index._array_candidates(objs)
    names = {c["name"] for c in cands}
    assert names == {"authors", "grid"}
    authors = next(c for c in cands if c["name"] == "authors")
    assert authors["cap"] == 10 and authors["size"] == 80


def test_array_candidates_empty_without_tables():
    assert oob_index._array_candidates({"x": (0x1000, 8), "y": (0x1008, 4)}) == []


def test_idx_options_prefers_index_taking_then_falls_back_to_all():
    model = {"1": ["str", "str", "num", "num", "str"], "2": ["idx"], "3": ["idx", "str"]}
    assert oob_index._idx_options(model, ["1", "2", "3"]) == ["2", "3"]
    # no template learned (stateful options short-circuit on a clean process) -> probe every option
    assert oob_index._idx_options({}, ["1", "2", "3"]) == ["1", "2", "3"]


def test_drive_places_boundary_in_the_index_field():
    model = {"2": ["idx"], "3": ["idx", "str"]}
    # a bare index option: option then the boundary value
    assert oob_index._drive("2", model, 0) == b"2\n0\n"
    # index-then-string: boundary in the idx slot, a typed filler for the string
    assert oob_index._drive("3", model, 11) == b"3\n11\nAAAA\n"
    # no template: still selects the option and supplies the boundary
    assert oob_index._drive("4", {}, 99) == b"4\n99\n"


# ------------------------------------------------ symbol-free (stripped) array recovery ----

def test_candidates_from_disasm_recovers_indexed_global_arrays():
    ranges = [(0x404060, 0x4040c8)]                       # .bss
    disasm = (
        "  401378:\tmov    rax,QWORD PTR [rax*8+0x404080]\n"   # notes[i] -> base 0x404080, stride 8
        "  40139a:\tmov    edx,DWORD PTR [rcx*4+0x404060]\n"   # a second table, stride 4
        "  4013b0:\tlea    rax,[rip+0x2c00]\n"                 # not indexed -> ignored
        "  4013c0:\tmov    rax,QWORD PTR [rbx*8+0x600000]\n"   # outside .bss -> ignored
    )
    cands = oob_index._candidates_from_disasm(disasm, ranges)
    by_addr = {c["addr"]: c for c in cands}
    assert 0x404080 in by_addr and by_addr[0x404080]["stride"] == 8
    assert 0x404060 in by_addr and by_addr[0x404060]["stride"] == 4
    assert 0x600000 not in by_addr                        # displacement outside a data section


def test_candidates_from_disasm_empty_without_data_ranges_or_hits():
    assert oob_index._candidates_from_disasm("mov rax,[rax*8+0x404080]", []) == []
    assert oob_index._candidates_from_disasm("nop\nret\n", [(0x404000, 0x404100)]) == []


def test_array_candidates_carry_stride():
    cands = oob_index._array_candidates({"authors": (0x2030c0, 80)})
    assert cands[0]["stride"] == 8 and cands[0]["cap"] == 10
