"""Finding grounding: the honest filter in front of weaponization. A detector flags a pattern;
grounding decides whether it is a real, reachable, arch-relevant defect worth an exploit -- and
only ever DEMOTES when provably benign, with a cited reason. These tests pin the soundness: a
maybe-real finding is never silently dropped, and each false-positive killer fires only on a
genuinely benign case.
"""
from lykos.analyze import grounding as G


def _f(cwe, title="t", detector="d", evidence=None):
    return {"cwe": cwe, "title": title, "detector": detector, "evidence": evidence or []}


def test_instrumentation_runtime_is_demoted():
    f = _f("CWE-190", title="bounds wrap",
           evidence=[{"channel": "pcode",
                      "detail": "INT_ADD -> INT_SLESS at 0x15b97 in method.fuzzer.FuzzerDriver_int"}])
    g = G.ground_finding(f)
    assert g["grounded"] is False and g["verdict"] == "instrumentation-noise"


def test_sanitizer_symbol_is_noise():
    f = _f("CWE-129", evidence=[{"channel": "pattern",
            "detail": "oob index in __sanitizer::internal_allocator"}])
    assert G.ground_finding(f)["grounded"] is False


def test_non_shipping_code_is_demoted_by_path():
    f = _f("CWE-416", evidence=[{"channel": "source",
            "detail": "src/common/test/TestFuzzThing.c:42: pointer freed then used"}])
    g = G.ground_finding(f)
    assert g["grounded"] is False and g["verdict"] == "non-shipping-code" and g["role"] == "non-shipping"


def test_format_string_literal_is_a_false_positive():
    f = _f("CWE-134", evidence=[{"channel": "source",
            "detail": "core/foo.c:771: snprintf() uses a non-literal format string"},
           {"channel": "attack-surface", "detail": "on the fuzzed attack surface"}])
    # the real source line shows a developer literal -> not attacker-controlled
    src = {("core/foo.c", 771): 'snprintf(buf, sizeof(buf), "location %s", loc);'}
    g = G.ground_finding(f, source_lookup=lambda p, n: src.get((p, n)))
    assert g["grounded"] is False and g["verdict"] == "format-literal"


def test_format_string_variable_is_kept():
    f = _f("CWE-134", evidence=[{"channel": "source",
            "detail": "core/foo.c:771: snprintf() uses a non-literal format string"},
           {"channel": "attack-surface", "detail": "on the fuzzed attack surface"}])
    src = {("core/foo.c", 771): 'snprintf(buf, sizeof(buf), fmt_from_wire, loc);'}
    g = G.ground_finding(f, source_lookup=lambda p, n: src.get((p, n)))
    assert g["grounded"] is True            # a variable format is NOT disproven -> kept


def test_integer_overflow_multiply_is_arch_safe_on_64bit():
    f = _f("CWE-190", evidence=[{"channel": "source",
            "detail": "src/codec/region.c:263: multiply before realloc"},
           {"channel": "attack-surface", "detail": "on the fuzzed attack surface"}])
    src = {("src/codec/region.c", 263):
           'RECTANGLE_16* rects = realloc(region->data->rects, nbItems * sizeof(RECTANGLE_16));'}
    g = G.ground_finding(f, source_lookup=lambda p, n: src.get((p, n)), bits=64)
    assert g["grounded"] is False and g["verdict"] == "arch-safe-mul"


def test_integer_overflow_multiply_is_kept_on_32bit():
    f = _f("CWE-190", evidence=[{"channel": "source",
            "detail": "x.c:10: multiply before malloc"}])
    src = {("x.c", 10): 'p = malloc(count * sizeof(T));'}
    g = G.ground_finding(f, source_lookup=lambda p, n: src.get((p, n)), bits=32)
    assert g["grounded"] is True            # on 32-bit the multiply CAN wrap -> not disproven


def test_64bit_operand_multiply_is_never_called_safe():
    f = _f("CWE-190", evidence=[{"channel": "source", "detail": "x.c:10: mul"}])
    src = {("x.c", 10): 'p = malloc((uint64_t)count * (uint64_t)stride);'}
    g = G.ground_finding(f, source_lookup=lambda p, n: src.get((p, n)), bits=64)
    assert g["grounded"] is True            # a 64-bit multiply can wrap -> kept, never "safe"


def test_off_surface_is_kept_but_deprioritised_not_dropped():
    f = _f("CWE-416", evidence=[{"channel": "source", "detail": "src/client/ui/input.c:155: uaf"},
           {"channel": "attack-surface",
            "detail": "off the fuzzed attack surface (its file is not compiled into any in-tree harness)"}])
    g = G.ground_finding(f)
    assert g["grounded"] is True and g["verdict"] == "off-surface-candidate" and g.get("priority") == "low"


def test_on_surface_real_finding_survives():
    f = _f("CWE-787", evidence=[{"channel": "source", "detail": "src/core/foo.c:50: oob write"},
           {"channel": "attack-surface", "detail": "on the fuzzed attack surface"}])
    g = G.ground_finding(f)
    assert g["grounded"] is True and g["verdict"] == "exploitable-candidate"


def test_ground_findings_rollup_separates_real_from_noise():
    fs = [
        _f("CWE-190", evidence=[{"channel": "pcode", "detail": "in method.fuzzer.FuzzerDriver"}]),
        _f("CWE-416", evidence=[{"channel": "source", "detail": "common/test/TestX.c:1: uaf"}]),
        _f("CWE-787", evidence=[{"channel": "source", "detail": "core/real.c:9: oob"},
                                {"channel": "attack-surface", "detail": "on the fuzzed attack surface"}]),
    ]
    out = G.ground_findings(fs)
    assert out["total"] == 3 and len(out["grounded"]) == 1 and len(out["dropped"]) == 2
    assert out["grounded"][0]["grounding"]["verdict"] == "exploitable-candidate"
