"""Source variant analysis via weggli (weggli.py)."""
import shutil
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


def test_parse_matches_extracts_the_enclosing_function():
    d = Path(tempfile.mkdtemp())
    (d / "h.c").write_text("void parse_header(char*s){char b[16]; strcpy(b,s);}\n")
    out = f"{d/'h.c'}:1\nvoid parse_header(char*s){{char b[16]; strcpy(b,s);}}\n"
    matches = weggli._parse_matches(out, d)
    assert len(matches) == 1
    assert matches[0]["function"] == "parse_header" and matches[0]["line"] == 1


def test_to_targets_maps_source_hits_to_binary_functions():
    # a scan result whose hit is in function parse_header, and recovered binary functions
    scan = {"supported": True, "findings": [
        {"name": "unbounded_strcpy", "cwe": "CWE-120", "severity": "high",
         "matches": [{"function": "parse_header", "file": "h.c", "line": 3}]}]}
    functions = [{"name": "parse_header", "addr": "0x1139"},
                 {"name": "sym.helper", "addr": "0x1180"}]
    targets = weggli.to_targets(scan, functions)
    assert len(targets) == 1
    t = targets[0]
    assert t["function_addr"] == "0x1139" and t["cwe"] == "CWE-120"
    assert t["detector"] == "weggli" and "parse_header" in t["title"]


def test_to_targets_skips_unmapped_functions():
    scan = {"findings": [{"name": "x", "cwe": "CWE-120", "severity": "high",
                          "matches": [{"function": "not_in_binary"}]}]}
    assert weggli.to_targets(scan, [{"name": "other", "addr": "0x1"}]) == []


@pytest.mark.skipif(weggli.weggli_bin() is None or not (shutil.which("gcc") or shutil.which("cc")),
                    reason="needs weggli + a C compiler")
def test_auto_weggli_targets_from_retained_source(tmp_path):
    """The directed stage auto-runs weggli on the source archived at ingest and maps hits to binary
    targets with no operator step. Build a project, register its source-project artifact, and check
    _auto_weggli_targets recovers a target at the flagged function's address."""
    import hashlib
    import io
    import subprocess
    import tarfile
    import types

    from lykos import vendorenv
    vendorenv.activate()
    from lykos.analyze import native_re
    from lykos.analyze.fuzz import directed
    from lykos.casestore import CaseStore
    if native_re.locate_native() is None:
        pytest.skip("no native RE backend")
    gcc = shutil.which("gcc") or shutil.which("cc")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.c").write_text(
        "#include <string.h>\n"
        "void parse_header(char*s){char b[16]; strcpy(b,s);}\n"
        "int main(int c,char**v){ if(c>1) parse_header(v[1]); return 0; }\n")
    binp = tmp_path / "app"
    if subprocess.run([gcc, "-O0", "-g", str(proj / "app.c"), "-o", str(binp)],
                      capture_output=True).returncode:
        pytest.skip("build failed")
    bsha = hashlib.sha256(binp.read_bytes()).hexdigest()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        tf.add(str(proj / "app.c"), arcname="app.c")
    store = CaseStore.open(tmp_path / "store")
    case = store.cases.create("t")
    store.put_artifact(case.id, "source-project", data=buf.getvalue(),
                       meta={"binary_sha": bsha, "filename": "proj"})
    target = store.targets.upsert(case.id, "app", bsha)
    funcs = native_re.analyze(str(binp)).get("functions", [])
    ctx = types.SimpleNamespace(conn=store.conn, content=store.content, emit=lambda *a, **k: None)
    targets = directed._auto_weggli_targets(ctx, target, funcs)
    assert any(t["cwe"] == "CWE-120" and "parse_header" in t["title"] for t in targets), targets
    assert all(t["detector"] == "weggli" for t in targets)


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
