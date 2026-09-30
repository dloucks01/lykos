"""Source variant analysis via weggli (weggli.py)."""
import tempfile
from pathlib import Path

import pytest
from lykos.analyze import weggli


def test_query_pack_is_well_formed():
    pack = weggli.query_pack()
    assert len(pack) >= 10
    for q in pack:
        assert q["name"] and q["query"] and q["cwe"].startswith("CWE-")
        assert q["severity"] in ("critical", "high", "medium", "low")
        # every statement pattern is a brace-wrapped snippet or a function pattern
        assert "{" in q["query"] and "}" in q["query"]


def test_matched_files_recovers_paths_format_tolerantly():
    d = Path(tempfile.mkdtemp())
    (d / "a.c").write_text("int a;")
    (d / "sub").mkdir()
    (d / "sub" / "b.c").write_text("int b;")
    # weggli-style output: path headers (some with ANSI color and a :line suffix) + snippet lines
    out = (f"\x1b[35m{d/'a.c'}\x1b[0m\n  strcpy(dst, src);\n\n"
           f"{d/'sub'/'b.c'}:42\n  strcpy(x, y);\n")
    files = weggli._matched_files(out, d)
    assert str((d / "a.c").resolve()) in files
    assert str((d / "sub" / "b.c").resolve()) in files
    assert len(files) == 2                                # deduped, real files only


def test_matched_files_ignores_non_paths():
    d = Path(tempfile.mkdtemp())
    (d / "real.c").write_text("x")
    out = f"{d/'real.c'}\n  memcpy(buf, src, n);\n  // /nonexistent/path.c not a real file\n"
    files = weggli._matched_files(out, d)
    assert files == [str((d / "real.c").resolve())]


def test_variant_query_generalization_levels():
    snippet = "strcpy(dest, source)"
    assert weggli.variant_query(snippet, level=0) == "{ strcpy(dest, source); }"
    # level 1: local identifiers become metavariables, the sink name is kept
    q1 = weggli.variant_query(snippet, level=1)
    assert "strcpy" in q1 and "$v0" in q1 and "dest" not in q1


def test_variant_query_level2_wildcards_numbers():
    q = weggli.variant_query("memcpy(buf, src, 64)", level=2)
    assert "memcpy" in q and "64" not in q and "_" in q


def test_scan_declines_gracefully_without_weggli(monkeypatch):
    monkeypatch.setattr(weggli, "weggli_bin", lambda: None)
    r = weggli.scan("/tmp")
    assert r["supported"] is False and r["findings"] == [] and "install" in r["note"]


def test_run_query_declines_without_weggli(monkeypatch):
    monkeypatch.setattr(weggli, "weggli_bin", lambda: None)
    r = weggli.run_query("{ strcpy(_, _); }", "/tmp")
    assert r["ok"] is False and r["error"]


@pytest.mark.skipif(weggli.weggli_bin() is None, reason="weggli binary not installed")
def test_end_to_end_finds_strcpy(tmp_path):
    src = tmp_path / "v.c"
    src.write_text("#include <string.h>\n"
                   "void f(char*s){ char b[16]; strcpy(b, s); }\n"
                   "void g(char*s){ char b[16]; strncpy(b, s, 15); }\n")
    r = weggli.scan(tmp_path)
    assert r["supported"]
    names = {f["name"] for f in r["findings"]}
    assert "unbounded_strcpy" in names                    # f() matches; g() (strncpy) does not
