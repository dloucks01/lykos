"""F5 (doc 60): non-fuzzing-first confirmation router + constructed payload PoCs."""
from lykos.analyze.drivable_confirm import strategy_for, construct_payload


def test_strategy_injection_traversal_is_construct():
    for cwe in ("CWE-22", "CWE-78", "CWE-134", "CWE-89"):
        assert strategy_for(cwe, True) == "construct-payload"


def test_strategy_memory_is_concolic_not_fuzz():
    for cwe in ("CWE-787", "CWE-416", "CWE-190"):
        assert strategy_for(cwe, False) == "concolic-solve"   # non-fuzzing first


def test_strategy_fallback_is_fuzz_last():
    assert strategy_for("CWE-999", False) == "bounded-fuzz"


def test_construct_traversal_payload():
    poc = construct_payload("CWE-22", "net.c:5 -> open.c:9")
    assert poc and ".." in poc["payload"] and poc["provenance"] == "constructed"
    assert "dataflow" in poc["proof"]


def test_construct_command_injection_payload():
    poc = construct_payload("CWE-78")
    assert poc and poc["payload"].strip().startswith(";")


def test_no_payload_for_memory_class():
    assert construct_payload("CWE-787") is None     # handed to the solver, not a canned payload
