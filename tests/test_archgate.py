"""Architecture coverage gate (doc 18) -- the table and the verdict logic.

The expensive half (build + detonate + drive the PoC stages per ISA) is exercised by
`make arch-gate`; these are the fast checks that the matrix stays coherent and that a
regression actually fails rather than passing quietly.
"""
from lykos.eval import archgate


def test_matrix_is_coherent():
    labels = [c.label for c in archgate.MATRIX]
    assert len(labels) == len(set(labels)), "duplicate architecture label"
    top = max(archgate._RANK[c.expect] for c in archgate.MATRIX)
    for c in archgate.MATRIX:
        assert c.expect in ("L1", "L2", "L3"), f"{c.label}: unexpected level {c.expect}"
        assert c.cc, f"{c.label}: no compiler"
        # anything expected below the best any arch achieves must say why, or the bar
        # silently drifts down one architecture at a time
        if archgate._RANK[c.expect] < top:
            assert c.note, f"{c.label} expects only {c.expect} but records no reason"


def test_matrix_covers_every_arch_the_parser_can_name():
    """A new arch in the ELF machine table without a gate row would go unmeasured."""
    from lykos.analyze import elf
    machines = [v for k, v in vars(elf).items()
                if isinstance(v, dict) and "x86-64" in str(v)][0]
    named = set(machines.values())
    gated = set()
    for c in archgate.MATRIX:
        gated.add("ppc64" if c.label == "ppc64le" else c.label)
    # mips has no cross toolchain in current Ubuntu and no corpus binary; the rest must be gated
    missing = named - gated - {"mips", "sparc"}
    assert not missing, f"architectures with no arch-gate row: {sorted(missing)}"


def _r(label, expect, reached, ok=None):
    return {"label": label, "expect": expect, "reached": reached,
            "ok": archgate._RANK[reached] >= archgate._RANK[expect] if ok is None else ok}


def test_gate_passes_when_every_arch_meets_its_bar():
    rep = {"results": [_r("x86-64", "L2", "L2"), _r("s390", "L1", "L1")], "skipped": []}
    passed, verdict, _ = archgate.gate(rep)
    assert passed and verdict == "PASS"


def test_gate_fails_on_a_downgrade_and_names_the_arch():
    """The exact regression shape this gate exists for: ppc64le silently dropping to L1
    because endianness stopped reaching the sandbox."""
    rep = {"results": [_r("x86-64", "L2", "L2"), _r("ppc64le", "L2", "L1")], "skipped": []}
    passed, verdict, reason = archgate.gate(rep)
    assert not passed and verdict == "FAIL"
    assert "ppc64le" in reason and "L1" in reason


def test_gate_fails_when_an_arch_reaches_nothing():
    """sparcv9 reached nothing at all before the qemu mapping existed."""
    rep = {"results": [_r("sparcv9", "L2", "")], "skipped": []}
    passed, _, reason = archgate.gate(rep)
    assert not passed and "sparcv9" in reason


def test_gate_skips_rather_than_fails_without_toolchains():
    """Same rule the static gate uses for Ghidra: absent backend SKIPs, it does not fail."""
    rep = {"results": [], "skipped": [{"label": "m68k", "reason": "no m68k-linux-gnu-gcc"}]}
    passed, verdict, _ = archgate.gate(rep)
    assert passed and verdict == "SKIP"


def test_table_marks_the_regressed_row():
    rep = {"results": [_r("ppc64le", "L2", "L1")], "skipped": [{"label": "sh", "reason": "no cc"}]}
    out = archgate.table(rep)
    assert "REGRESSED" in out and "ppc64le" in out and "SKIP" in out


def test_source_uses_a_nul_transparent_unbounded_channel():
    """read()+memcpy, not fgets()+strcpy: fgets caps at its buffer so it cannot reach SPARC's
    saved %i7 (~2KB away), and strcpy stops at the first NUL, which every L2 confirmation
    payload contains once it embeds an address."""
    src = archgate._SRC
    assert "read(" in src and "memcpy(" in src
    assert "fgets" not in src and "strcpy" not in src
