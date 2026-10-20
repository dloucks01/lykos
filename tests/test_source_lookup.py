"""The archived source tree must reach a binary target even when their hashes do not match.

Source is keyed to one binary's sha256, but the binary a source detector analyses is often NOT that
one (a multi-binary project keys its tree to the primary only; a source archive uploaded separately
is keyed to lykos's rebuilt binaries, never the operator's). An exact-sha-only lookup made every
source detector report "no archived source tree" -- the real engagement symptom. `source_project_for`
adds a case-level fallback: the sole source tree in a case enriches every binary target.
"""
from types import SimpleNamespace

from lykos.analyze.source_lookup import source_project_for


def _tree(store, case_id, sha, data):
    store.put_artifact(case_id, "source-project", data=data, meta={"binary_sha": sha})


def test_exact_binary_sha_match_wins(store, case):
    _tree(store, case.id, "AAA", b"tree-a")
    _tree(store, case.id, "BBB", b"tree-b")
    t = SimpleNamespace(case_id=case.id, sha256="BBB")
    got = source_project_for(store.conn, t)
    assert got is not None and (got.meta or {}).get("binary_sha") == "BBB"


def test_sole_tree_reaches_a_binary_whose_hash_does_not_match(store, case):
    # One source tree keyed to the PRIMARY; a different binary target (separately uploaded, or an
    # extra entry point) shares none of its hashes -- the fallback must still hand it the tree.
    _tree(store, case.id, "PRIMARY", b"the-only-tree")
    t = SimpleNamespace(case_id=case.id, sha256="A-DIFFERENT-BINARY")
    got = source_project_for(store.conn, t)
    assert got is not None, "the sole source tree must enrich a non-matching binary target"
    assert (got.meta or {}).get("binary_sha") == "PRIMARY"


def test_several_trees_and_no_exact_match_declines(store, case):
    # Ambiguous: more than one source tree and none match -- decline rather than cross-contaminate.
    _tree(store, case.id, "A", b"tree-1")
    _tree(store, case.id, "B", b"tree-2")
    t = SimpleNamespace(case_id=case.id, sha256="C")
    assert source_project_for(store.conn, t) is None


def test_none_when_the_case_has_no_source_tree(store, case):
    t = SimpleNamespace(case_id=case.id, sha256="X")
    assert source_project_for(store.conn, t) is None


def test_source_code_kind_is_selectable(store, case):
    store.put_artifact(case.id, "source-code", data=b"int main(){}", meta={"binary_sha": "S"})
    t = SimpleNamespace(case_id=case.id, sha256="unrelated")
    assert source_project_for(store.conn, t) is None                      # default kind is the tree
    assert source_project_for(store.conn, t, kind="source-code") is not None
