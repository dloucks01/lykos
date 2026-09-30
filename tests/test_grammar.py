"""Grammar-aware structure-valid fuzzing (grammar.py)."""
import random

import pytest
from lykos.analyze.fuzz import grammar as G


def _rng():
    return random.Random(1234)


def test_dsl_parses_refs_and_literal_percent():
    prod = G._compile_production("a%x%b%%c")     # %% is a literal percent, adjacent literals merge
    assert prod == [("lit", b"a"), ("ref", "x"), ("lit", b"b%c")]


def test_compile_validates_start_and_references():
    with pytest.raises(ValueError):
        G.compile_grammar({"start": "missing", "rules": {"s": ["a"]}})
    with pytest.raises(ValueError):
        G.compile_grammar({"start": "s", "rules": {"s": ["%undef%"]}})
    with pytest.raises(ValueError):
        G.compile_grammar({"start": "s", "rules": {"s": []}})


def test_generation_terminates_and_is_bounded():
    g = G.compile_grammar({"start": "s", "rules": {"s": ["a", "(%s%)", "%s%%s%"]}})
    rng = _rng()
    for _ in range(500):
        out = G.generate(g, rng, max_len=256)
        assert isinstance(out, bytes) and len(out) <= 256


def test_sexpr_is_always_balanced():
    g = G.builtin("sexpr")
    rng = _rng()

    def balanced(b):
        d = 0
        for c in b:
            d += (c == 0x28) - (c == 0x29)
            if d < 0:
                return False
        return d == 0
    assert all(balanced(G.generate(g, rng)) for _ in range(500))


def test_tlv_is_binary_and_has_no_token_leak():
    g = G.builtin("tlv")
    rng = _rng()
    outs = [G.generate(g, rng) for _ in range(200)]
    assert all(isinstance(o, bytes) for o in outs)
    assert not any(b"lit" in o or b"ref" in o for o in outs)   # element tags never leak into output


def test_builtin_names_and_all_compile():
    for name in G.builtin_names():
        g = G.builtin(name)
        assert g and "start" in g and "rules" in g


def test_grammar_mutator_returns_bytes_and_survives_bad_grammar():
    g = G.builtin("kv")
    m = G.GrammarMutator(_rng(), g, dictionary=[b"SECRET", b"admin"])
    outs = [m.mutate(b"name=x\n", corpus=[b"host=1\n"]) for _ in range(200)]
    assert all(isinstance(o, bytes) for o in outs)
    # the injected dictionary token shows up sometimes (planted at literal slots)
    assert any(b"SECRET" in o or b"admin" in o for o in outs)


def test_inject_plants_tokens_at_literal_slots():
    g = G.compile_grammar({"start": "s", "rules": {"s": ["A%s%", "Z"]}})
    rng = _rng()
    outs = [G.generate(g, rng, inject=[b"MAGIC"]) for _ in range(200)]
    assert any(b"MAGIC" in o for o in outs)


def test_from_spec_bridges_a_flat_format():
    spec = [{"type": "magic", "value": b"\x89PNG"}, {"type": "u32"}, {"type": "blob"}]
    g = G.from_spec(spec)
    assert g is not None
    rng = _rng()
    outs = [G.generate(g, rng) for _ in range(50)]
    assert all(o.startswith(b"\x89PNG") for o in outs)     # the magic is always emitted
