"""A CONFIRMED primitive must not be labelled with a weakness that contradicts it.

`primitive_stage` relabels a reproduced crash once it has confirmed what the input can actually
do -- instruction-pointer control, an arbitrary write, a controlled read -- and it deliberately
keeps `root_cause`'s CWE rather than its own signal-derived one, because root_cause reads the
sanitizer/debugger report and is usually more specific.

That is right only while root_cause's class is itself a memory-corruption defect. Measured on a
service carved out of a SquashFS firmware image: the stack smash left a near-null return
address, root_cause classified the fault as CWE-476 (null-pointer dereference), and the finding
went out titled "Control-flow hijack (demonstrated): L2 primitive" carrying a DoS-grade weakness
id -- so anyone filtering for memory corruption would never see a confirmed IP hijack at a known
stack offset.
"""
import pytest

from lykos.analyze.poc import primitive_stage as PS


def test_the_tables_cover_every_effect_the_stage_can_headline():
    """If a primitive type can produce a headline it must have a weakness to fall back on, or
    the override silently does nothing for that type."""
    # the effect map lives inside the stage function; assert against the primitive types it keys
    for kind in ("instruction-pointer-control", "write-what-where", "arbitrary-write",
                 "arbitrary-read", "controlled-read"):
        assert kind in PS._PRIM_CWE, kind


@pytest.mark.parametrize("kind,cwe", [
    ("instruction-pointer-control", "CWE-787"),
    ("write-what-where", "CWE-787"),
    ("arbitrary-write", "CWE-787"),
    ("arbitrary-read", "CWE-125"),
    ("controlled-read", "CWE-125"),
])
def test_a_confirmed_primitive_says_what_the_access_was(kind, cwe):
    """Reaching a saved return address or an arbitrary address IS an out-of-bounds write; a
    controlled read of memory the program did not mean to expose IS an out-of-bounds read."""
    assert PS._PRIM_CWE[kind] == cwe


def test_the_fallback_is_only_used_where_root_cause_said_something_else():
    """Every weakness the override would REPLACE must be outside the keep-list, and every
    memory-corruption class root_cause can produce must be inside it -- otherwise the override
    either never fires or fires over a better answer."""
    # a confirmed hijack whose root cause is already memory corruption keeps that specific class
    for kept in ("CWE-121", "CWE-122", "CWE-416", "CWE-415", "CWE-125", "CWE-787"):
        assert kept in PS._MEM_CORRUPTION, kept
    # ...and the classes that contradict a confirmed primitive do NOT keep theirs
    for replaced in ("CWE-476", "CWE-248", "CWE-369", "CWE-674", "CWE-20", "CWE-129"):
        assert replaced not in PS._MEM_CORRUPTION, replaced


def test_the_replacement_is_itself_a_memory_corruption_class():
    """The override must not take the finding OUT of the family it is moving it into, or a
    second pass over the same finding would flip it back."""
    assert set(PS._PRIM_CWE.values()) <= PS._MEM_CORRUPTION
