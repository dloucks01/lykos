"""Patch-signature classification: turn a bindiff 'changed function' into a typed N-day candidate
(the hand-off from patch-diff to the exploit loop). A labelled hypothesis from the patch shape --
memory-corruption fixes rank first -- never an assertion."""
from lykos.analyze import patchdiff as PD


def test_unsafe_to_bounded_copy_swap_is_overflow():
    c = {"name": "f", "moved": 20, "new_callees": ["strncpy", "helper"],
         "dropped_callees": ["strcpy"], "new_consts": [], "dropped_consts": []}
    r = PD.classify_change(c)
    assert r["cwe"] == "CWE-787" and r["exploit_class"] == "overflow" and r["confidence"] >= 0.75
    assert "strcpy" in r["why"] and "strncpy" in r["why"]


def test_added_bounds_check_constant_is_overflow():
    c = {"name": "parse", "moved": 8, "new_callees": [], "dropped_callees": [],
         "new_consts": ["cmp:0x400"], "dropped_consts": []}
    r = PD.classify_change(c)
    assert r["cwe"] == "CWE-787" and r["exploit_class"] == "overflow"
    assert "cmp:0x400" in r["why"]


def test_added_length_validator_call_is_overflow():
    c = {"name": "recv_pdu", "moved": 12, "new_callees": ["Stream_CheckAndLogRequiredLength"],
         "dropped_callees": [], "new_consts": [], "dropped_consts": []}
    r = PD.classify_change(c)
    assert r["exploit_class"] == "overflow" and "CheckAndLog".lower() in r["why"].lower()


def test_size_arithmetic_guard_is_integer_overflow():
    c = {"name": "alloc_rects", "moved": 10, "new_callees": ["ckd_mul", "malloc"],
         "dropped_callees": [], "new_consts": [], "dropped_consts": []}
    r = PD.classify_change(c)
    assert r["cwe"] == "CWE-190" and r["exploit_class"] == "overflow"


def test_free_reorder_is_uaf():
    c = {"name": "cleanup", "moved": 6, "new_callees": ["stream_free"], "dropped_callees": [],
         "new_consts": [], "dropped_consts": []}
    r = PD.classify_change(c)
    assert r["cwe"] == "CWE-416" and r["exploit_class"] == "uaf"


def test_no_memory_signature_is_unknown_low_rank():
    c = {"name": "set_flag", "moved": 3, "new_callees": ["log_debug"], "dropped_callees": [],
         "new_consts": [], "dropped_consts": []}
    r = PD.classify_change(c)
    assert r["cwe"] == "NVD-CWE-noinfo" and r["exploit_class"] == "unknown" and r["confidence"] <= 0.3


def test_worklist_ranks_memory_corruption_first():
    diff = {"changed": [
        {"name": "cosmetic", "moved": 99, "new_callees": ["printf"], "dropped_callees": [],
         "new_consts": [], "dropped_consts": []},
        {"name": "overflow_fix", "moved": 5, "new_callees": ["Stream_EnsureCapacity"],
         "dropped_callees": [], "new_consts": ["cmp:0x20"], "dropped_consts": []},
        {"name": "uaf_fix", "moved": 7, "new_callees": ["g_free"], "dropped_callees": [],
         "new_consts": [], "dropped_consts": []},
    ]}
    wl = PD.exploit_worklist(diff)
    classes = [e["classification"]["exploit_class"] for e in wl]
    assert classes[0] == "overflow"            # memory corruption ranks above the big cosmetic move
    assert classes.index("uaf") < classes.index("unknown")
    assert wl[0]["name"] == "overflow_fix"
