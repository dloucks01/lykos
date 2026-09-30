"""Corpus distillation (minset) over block-coverage sets."""
from lykos.analyze.fuzz import distill


def test_redundant_subset_input_is_dropped():
    cov = {"A": {1, 2, 3}, "B": {1, 2}, "C": {4}}      # B ⊂ A -> redundant
    sel = distill.greedy_minset(cov)
    assert set(sel) == {"A", "C"}
    assert "B" not in sel


def test_minset_preserves_total_coverage():
    cov = {i: s for i, s in enumerate([{1, 2}, {2, 3}, {3, 4}, {1, 4}, {2, 3, 4}])}
    sel = distill.greedy_minset(cov)
    union_all = set().union(*cov.values())
    union_sel = set().union(*(cov[k] for k in sel))
    assert union_sel == union_all
    assert len(sel) < len(cov)                          # something was distilled away


def test_tie_break_prefers_smaller_input():
    cov = {"big": {1, 2, 3}, "small": {1, 2, 3}}        # identical coverage
    sizes = {"big": 1000, "small": 10}
    sel = distill.greedy_minset(cov, sizes)
    assert sel == ["small"]                             # the smaller one is kept


def test_empty_coverage_inputs_are_not_selected():
    cov = {"real": {1, 2}, "blind": set()}
    assert distill.greedy_minset(cov) == ["real"]


def test_distill_keeps_crashers_and_unmeasured():
    inputs = [b"seedA", b"seedB", b"crashX", b"unmeasured"]
    cover = [{1, 2, 3}, {1, 2}, {1}, set()]             # B redundant, C is a crasher, D unmeasured
    d = distill.distill(inputs, cover, keep_idx={2})    # index 2 = crasher, force-keep
    assert b"seedA" in d["kept"]                        # covers the most -> kept
    assert b"seedB" not in d["kept"]                    # redundant subset -> dropped
    assert b"crashX" in d["kept"]                       # forced keep despite being redundant
    assert b"unmeasured" in d["kept"]                   # no evidence of redundancy -> kept
    assert d["stats"]["in"] == 4 and d["stats"]["out"] == 3 and d["stats"]["dropped"] == 1


def test_distill_corpus_with_cover_fn_override():
    inputs = [b"aa", b"bb", b"cc"]
    # aa covers {1,2}, bb covers {2} (redundant), cc covers {3}
    cmap = {b"aa": {1, 2}, b"bb": {2}, b"cc": {3}}
    d = distill.distill_corpus(None, inputs, blocks=(1, 2, 3), cover_fn=lambda x: cmap[x])
    assert set(d["kept"]) == {b"aa", b"cc"}
    assert d["stats"]["blocks_preserved"] == 3


def test_distill_is_deterministic():
    cov = {i: s for i, s in enumerate([{1, 2}, {3, 4}, {1, 2}, {3, 4}])}
    assert distill.greedy_minset(cov) == distill.greedy_minset(cov)
