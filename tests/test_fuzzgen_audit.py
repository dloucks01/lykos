"""Regression tests for the input-generation audit (mutator / structure / grammar / xmlgrammar /
textconf / cmpdict / distill / blockdist / attempts). Each test pins one verified defect."""
import gzip
import json
import os
import random
import shutil
import subprocess
import sys
import zlib

import pytest
from lykos.analyze.dynamic.sandbox import RunResult
from lykos.analyze.fuzz import attempts, blockdist, cmpdict, distill, grammar, mutator, structure, textconf, xmlgrammar


# ----------------------------------------------------------------------------------- mutator
def test_a_str_dictionary_token_does_not_raise():
    m = mutator.Mutator(random.Random(0), ["GET ", b"PUT"])
    for _ in range(500):
        assert isinstance(m.mutate(b"abc", [b"abc"]), bytes)
    assert all(isinstance(t, bytes) for t in m.dict)


def test_a_seed_longer_than_the_cap_is_not_chopped():
    """A ZIP/PDF keeps its directory at the END; the cap used to cut every mutant to 8 KiB."""
    big = b"%PDF" + b"x" * 20000 + b"%%EOF"
    m = mutator.Mutator(random.Random(1))
    lens = [len(m.mutate(big, [big])) for _ in range(300)]
    assert max(lens) <= len(big)                      # never grows past what it arrived as
    assert sum(1 for n in lens if n > mutator._MAX_LEN) > 150, "most mutants keep their size"


# ----------------------------------------------------------------------------------- grammar
def test_a_grammar_that_can_never_terminate_fails_at_build_time():
    with pytest.raises(ValueError, match="never terminate"):
        grammar.compile_grammar({"start": "a", "rules": {"a": ["x%a%"]}})
    with pytest.raises(ValueError):
        grammar.compile_grammar({"start": "a", "rules": {"a": ["%b%"], "b": ["(%a%)"]}})


def test_the_size_cap_closes_structure_instead_of_cutting_it():
    g = grammar.compile_grammar({"start": "s", "rules": {"s": ["a", "(%s%)", "%s%%s%"]}})
    rng = random.Random(0)
    for _ in range(2000):
        out = grammar.generate(g, rng, max_len=256)
        assert len(out) <= 256
        assert out.count(b"(") == out.count(b")"), out


def test_the_json_builtin_emits_valid_json():
    g = grammar.builtin("json")
    rng = random.Random(0)
    for _ in range(3000):
        json.loads(grammar.generate(g, rng))


def test_grammar_mutator_takes_any_iterable_corpus_and_str_tokens():
    gm = grammar.GrammarMutator(random.Random(2), grammar.builtin("kv"), dictionary=["magic"])
    for _ in range(200):
        assert isinstance(gm.mutate(b"", iter([b"a=1", b"b=2"])), bytes)


# ------------------------------------------------------------------------------------- xml
_wf = shutil.which("xmllint")


def _well_formed(doc: bytes, tmp_path) -> bool:
    p = tmp_path / "d.xml"
    p.write_bytes(doc)
    return subprocess.run([_wf, "--noout", "--huge", "--nonet", str(p)],
                          capture_output=True).returncode == 0


SEED = b'<?xml version="1.0"?>\n<root a="1"><item id="x">text</item><item/></root>\n'


def test_dup_element_repeats_the_whole_element():
    m = xmlgrammar.XmlMutator(random.Random(4))
    for _ in range(50):
        out = m._dup_element(SEED)
        assert out is not None
        assert out.count(b"<item id=\"x\">") == out.count(b"</item>"), "every copy is closed"


@pytest.mark.skipif(not _wf, reason="xmllint not installed")
def test_structural_ops_keep_documents_well_formed(tmp_path):
    m = xmlgrammar.XmlMutator(random.Random(7))
    with_doctype = structure.seed_for_name("xml")
    for seed in (SEED, b"<cfg/>", with_doctype):
        for op in (m._dup_element, m._entities, m._text):
            for _ in range(8):
                out = op(seed)
                assert out is not None and _well_formed(out, tmp_path), (op.__name__, seed, out[:200])


def test_tags_inside_cdata_are_not_structure():
    m = xmlgrammar.XmlMutator(random.Random(0))
    doc = b"<r><![CDATA[<raw>]]><!-- <c> --></r>"
    assert [t.group(1) for t in m._tags(doc)] == [b"r"]


def test_a_lineage_of_xml_mutants_stays_bounded():
    m = xmlgrammar.XmlMutator(random.Random(3))
    cur = SEED
    for _ in range(300):
        cur = m.mutate(cur)
        assert len(cur) <= xmlgrammar._MAX_DOC


# -------------------------------------------------------------------------------- textconf
def test_keys_from_respects_its_limit_for_key_equals_strings():
    strs = ["key%s=%%s" % ("abcdefghij"[i % 10] * (i // 10 + 1)) for i in range(200)]
    assert len(textconf.keys_from(strs, limit=10)) == 10


def test_a_lineage_of_config_mutants_stays_bounded_and_bytes_keys_work():
    m = textconf.KeyValueMutator(random.Random(1), [b"name", "port"])
    cur = textconf.seed_for(["name", "port"])
    for _ in range(600):
        cur = m.mutate(cur)
        assert len(cur) <= textconf._MAX_TEXT


# --------------------------------------------------------------------------------- cmpdict
def test_a_sign_extended_char_compare_yields_the_input_byte():
    # char c = in[0]; if (c == -2)  ->  movsx + cmp eax, 0xfffffffe
    toks = cmpdict.cmp_tokens(["INT_EQUAL reg:eax:4 const:0xfffffffe:4 -> unique:0x1:1"])
    assert b"\xfe" in toks and b"\xfe\xff" in toks


def test_a_non_power_of_two_width_is_emitted_at_its_own_width():
    toks = cmpdict.cmp_tokens(["INT_EQUAL reg:x:3 const:0x123456:3 -> unique:0x1:1"])
    assert bytes.fromhex("563412") in toks and bytes.fromhex("123456") in toks


def test_a_large_unsigned_constant_is_not_mistaken_for_a_sign_extension():
    toks = cmpdict.cmp_tokens(["INT_EQUAL reg:eax:4 const:0x7fff8000:4 -> unique:0x1:1"])
    assert b"\x00\x80" not in toks                   # 0x7fff8000 is not a widened 0x8000


# --------------------------------------------------------------------------------- distill
def _eager(coverage, sizes):
    remaining = {k: set(v) for k, v in coverage.items() if v}
    universe = set().union(*remaining.values()) if remaining else set()
    order = {k: i for i, k in enumerate(sorted(remaining))}
    covered, sel = set(), []
    while covered != universe:
        best = max(remaining, key=lambda k: (len(remaining[k] - covered), -sizes.get(k, 0),
                                             -order[k]))
        sel.append(best)
        covered |= remaining.pop(best)
    return sel


def test_lazy_greedy_matches_eager_greedy():
    for trial in range(150):
        r = random.Random(trial)
        n = r.randint(1, 50)
        cov = {i: set(r.sample(range(60), r.randint(0, 12))) for i in range(n)}
        sizes = {i: r.randint(1, 4) for i in range(n)}
        assert distill.greedy_minset(cov, sizes) == _eager(cov, sizes), trial


def test_string_keys_tie_break_the_same_in_every_process():
    code = ("from lykos.analyze.fuzz import distill;"
            "print(distill.greedy_minset({'k%d' % i: {1, 2, 3} for i in range(40)}))")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    outs = set()
    for seed in ("1", "2", "3"):
        env["PYTHONHASHSEED"] = seed
        outs.add(subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                                text=True, check=True).stdout)
    assert outs == {"['k0']\n"}


# ------------------------------------------------------------------------------- blockdist
class _F:
    def __init__(self, addr, blocks):
        self.addr, self.ir = addr, {"blocks": blocks}


def _blk(addr, succ=(), instr=()):
    return {"addr": hex(addr), "succ": [hex(s) for s in succ],
            "instructions": [{"addr": hex(i)} for i in instr]}


def test_a_sink_outside_every_recovered_block_is_not_pinned_to_a_neighbour():
    funcs = [_F(0x1000, [_blk(0x1000, instr=(0x1000, 0x1004))])]
    # 0x5000 is far past the only block: an unrecovered function, not block 0x1000
    assert blockdist.block_distance(funcs, [], {0x5000}) == {}


def test_a_mid_instruction_site_maps_to_its_block():
    funcs = [_F(0x1000, [_blk(0x1000, succ=(0x1010,), instr=(0x1000, 0x1004)),
                         _blk(0x1010, instr=(0x1010, 0x1015))])]
    dist = blockdist.block_distance(funcs, [], {0x1017})
    assert dist[0x1010] == 0.0 and dist[0x1000] == 1.0


# ------------------------------------------------------------------------------- structure
def test_a_driven_crc_does_not_leave_other_chunks_stale(monkeypatch):
    """One driven CRC used to skip the WHOLE fixup, so another chunk edited in the same round
    shipped with a stale CRC and was rejected at the door."""
    model = structure.builtin("png")
    seed = structure.seed_for_name("png")

    class Drive(structure.StructMutator):
        def _mutate_field(self, fields):
            names = {f["f"].get("name"): f for f in structure._every_field(fields)}
            names["ihdr_crc"]["val"] = 0x41414141
            self._driven.add(id(names["ihdr_crc"]))
            # same length, so the (deliberately unfixed) length field still frames the chunk
            names["idat_data"]["val"] = bytes(b ^ 0xFF for b in names["idat_data"]["val"])
            return "cover"

    monkeypatch.setattr(structure, "_scopes", lambda fields: [fields])     # the whole tree
    out = Drive(random.Random(0), model).mutate(seed)
    fields = {f["f"].get("name"): f for f in structure._every_field(model.parse(out))}
    assert fields["ihdr_crc"]["val"] == 0x41414141, "the driven CRC stays driven"
    body = b"IDAT" + fields["idat_data"]["val"]
    assert fields["idat_crc"]["val"] == zlib.crc32(body) & 0xFFFFFFFF, "the other is recomputed"


def test_a_named_covers_length_is_actually_driven():
    seed = structure.seed_for_name("jpeg")
    mut = structure.StructMutator(random.Random(11), structure.builtin("jpeg"))
    off = 0
    for _ in range(600):
        d = mut.mutate(seed, [seed])
        n = int.from_bytes(d[4:6], "big")
        off += d[4 + n:4 + n + 2] != b"\xff\xdb"
    assert off > 5, "the APP1 length was never driven"


def test_an_offset_size_pair_on_a_derived_offset_survives_the_fixup():
    """ELF e_shoff is offset_of AND role=offset; a pair driven from e_shnum used to be undone."""
    model = structure.builtin("elf")
    seed = structure.seed_for_name("elf")
    real = int.from_bytes(seed[0x28:0x30], "little")
    mut = structure.StructMutator(random.Random(5), model)
    moved = sum(int.from_bytes(mut.mutate(seed, [seed])[0x28:0x30], "little") != real
                for _ in range(600))
    assert moved > 10


@pytest.mark.parametrize("name", structure.builtin_names())
def test_builtin_specs_survive_json_and_preview(name):
    seed = structure.seed_for_name(name)
    json.dumps(structure.suggest_spec(seed))                    # used to raise on nested bytes
    spec = json.loads(json.dumps(structure._jsonable_spec(structure._BUILTINS[name]["spec"])))
    d = structure.describe(spec, seed)
    assert d["error"] is None and d["ok"] and d["roundtrip"], d["error"]
    assert d["consumed"] == len(seed)
    model = structure.from_spec(spec)
    assert model.serialize(model.parse(seed)) == seed


def test_layout_lengths_match_serialization():
    for name in structure.builtin_names():
        model = structure.builtin(name)
        seed = structure.seed_for_name(name)
        mut = structure.StructMutator(random.Random(2), model)
        for _ in range(100):
            fields = model.parse(mut.mutate(seed, [seed]))
            _spans, _n, total = structure._layout(model, fields)
            assert total == len(model.serialize(fields)), name


# -------------------------------------------------------------------------------- attempts
class _Ctx:
    def __init__(self, tmp_path):
        self._tmp, self.events = tmp_path, []
        self.run_id = "r"

    def scratch(self):
        return self._tmp

    def put_artifact(self, kind, *, src=None, data=None, meta=None):
        return "sha"

    def emit(self, typ, payload=None):
        self.events.append((typ, payload))


def test_a_definitive_did_not_run_is_erroring_not_too_few(tmp_path):
    log = attempts.AttemptLog(_Ctx(tmp_path), "fuzz", "fuzz")
    log.record_result(b"x", RunResult(isolation="bwrap", exit_code=127,
                                      stderr=b"error while loading shared libraries: libq.so\n"),
                      phase="seed")
    out = log.finish(did_not_run=True)
    assert out["verdict"] == attempts.ERRORING and "libq.so" in out["verdict_note"]
    t = attempts.Tally()
    t.add("no_start", 127, "x")
    assert t.verdict()[0] == attempts.TOO_FEW         # without the flag, still too few


def test_a_log_cut_off_before_finish_is_still_readable(tmp_path, monkeypatch):
    monkeypatch.setattr(attempts, "_FLUSH_S", 0.0)
    log = attempts.AttemptLog(_Ctx(tmp_path), "fuzz", "fuzz")
    for i in range(300):
        log.record_result(bytes([i % 256]) * 4,
                          RunResult(isolation="bwrap", exit_code=1, stderr=b"bad\n"),
                          phase="mutate")
    raw = log.path.read_bytes()                       # abrupt stop: no finish(), no gzip trailer
    with pytest.raises(EOFError):
        gzip.decompress(raw)
    for src in (raw, log.path):
        rd = attempts.read_log(src, offset=295, limit=10)
        assert rd["truncated"] and rd["total"] == 300
        assert [r["i"] for r in rd["rows"]] == [296, 297, 298, 299, 300]
    log.finish()
    assert attempts.read_log(log.path)["truncated"] is False


def test_read_log_paging_clamps_and_judges_gain_like_the_live_log(tmp_path):
    log = attempts.AttemptLog(_Ctx(tmp_path), "fuzz", "fuzz")
    for i in range(30):
        log.record_result(b"a", RunResult(isolation="bwrap", exit_code=1, stderr=b"no\n"),
                          phase="reproduce", new=5)   # not a coverage phase
    log.finish()
    rd = attempts.read_log(log.path, offset=-5, limit=3)
    assert rd["offset"] == 0 and [r["i"] for r in rd["rows"]] == [1, 2, 3]
    assert rd["summary"]["verdict"] == attempts.REJECTING == log.tally.verdict(log.progressed())[0]


def test_idle_tail_is_clamped(tmp_path):
    log = attempts.AttemptLog(_Ctx(tmp_path), "afl", "afl")
    log.set_value(last_gain_s=1e9)
    assert 0 <= log.value()["idle_tail_pct"] <= 100
    log.finish()
