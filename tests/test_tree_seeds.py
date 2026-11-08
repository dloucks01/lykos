"""Seeds mined from a source project's own tests (analyze/tree_seeds.py)."""
from lykos.analyze import tree_seeds as T


def test_mines_inputs_from_test_dirs_but_never_known_crashers(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "parse.c").write_text("int x;")
    t = tmp_path / "test"
    (t / "fuzz-input").mkdir(parents=True)
    (t / "fuzz-input" / "gfm.md").write_text("| a | b |\n|---|---|\n")
    (t / "spec.txt").write_text("example\n")
    (t / "runtests").write_text("#!/bin/sh\necho hi\n")
    (t / "crash-1234").write_bytes(b"\x00boom")
    (t / "fuzztest_past_fails").mkdir()
    (t / "fuzztest_past_fails" / "x.jpg").write_bytes(b"\xff\xd8bad")
    (t / "CMakeLists.txt").write_text("project(x)")
    (t / "dup.md").write_text("| a | b |\n|---|---|\n")                  # same bytes as gfm.md
    got = sorted(p.name for p in T.candidates(tmp_path))
    assert "gfm.md" in got or "dup.md" in got
    assert len([n for n in got if n in ("gfm.md", "dup.md")]) == 1       # deduped by content
    assert "spec.txt" in got
    for bad in ("runtests", "crash-1234", "x.jpg", "CMakeLists.txt", "parse.c"):
        assert bad not in got, got


def test_mine_copies_seeds_out_of_the_tree(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "a.bin").write_bytes(b"ABC")
    out = T.mine(tmp_path, tmp_path / "out")
    assert len(out) == 1 and open(out[0], "rb").read() == b"ABC"
    assert T.mine(tmp_path / "nothing-here", tmp_path / "o2") == []
