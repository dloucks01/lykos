"""bench/recall/score.py address matching: a no-debug binary's dossier carries only a site VA, which
the scorer maps through the target's -g "debug twin" (addr2line -f -i) to (function, file, line)
frames and then matches like any other frame.

Builds a tiny program with a static helper and an always-inlined helper, once plain + stripped (the
"shipped" binary) and once with -g added (the twin), checks the twin's .text is byte-identical, and
then pins: a VA inside the static helper maps to the helper; a VA inside inlined code yields the
inlined chain (helper first, then its caller); `main` is NOT skipped on the debug map; a dossier
whose own frames already match is unchanged; and `--rescore` credits the CVE through the twin.
"""
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("recall_score", ROOT / "bench" / "recall" / "score.py")
sc = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sc)

pytestmark = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("gcc", "addr2line", "objcopy", "strip", "nm")),
    reason="needs gcc + binutils")

PROG = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static __attribute__((noinline)) int parse_record(const char *buf, int n)
{
    int acc = 0;
    for (int i = 0; i < n; i++)
        acc = acc * 31 + buf[i];
    return acc;
}

static inline __attribute__((always_inline)) int fold_header(const char *buf, int n)
{
    int h = 7;
    for (int i = 0; i < n; i++)
        h ^= (h << 5) + (unsigned char)buf[i];
    return h;
}

int main(int argc, char **argv)
{
    const char *s = argc > 1 ? argv[1] : "seed";
    int n = (int)strlen(s);
    int r = parse_record(s, n);
    r += fold_header(s, n);
    printf("%d\n", r);
    return 0;
}
"""


def _text(path: Path, out: Path) -> bytes:
    subprocess.run(["objcopy", "-O", "binary", "--only-section=.text", str(path), str(out)],
                   check=True)
    return out.read_bytes()


def _sym(binary: Path, name: str):
    """(address, size) of a symbol, from `nm -S`."""
    for line in subprocess.run(["nm", "-S", str(binary)], capture_output=True, text=True,
                               check=True).stdout.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[3] == name:
            return int(parts[0], 16), int(parts[1], 16)
    raise AssertionError(f"{name} not in {binary}")


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    d = tmp_path_factory.mktemp("addr")
    (d / "rec.c").write_text(PROG)
    flags = ["-O1", "-fno-pie", "-no-pie", "-w"]
    subprocess.run(["gcc", *flags, "-o", "rec", "rec.c"], cwd=d, check=True)
    subprocess.run(["gcc", *flags, "-g", "-o", "rec.dbg", "rec.c"], cwd=d, check=True)
    subprocess.run(["strip", "-s", "-o", "rec.stripped", "rec"], cwd=d, check=True)
    t0 = _text(d / "rec", d / "a.text")
    assert t0 == _text(d / "rec.dbg", d / "b.text"), "-g moved code: twin is not identical"
    assert t0 == _text(d / "rec.stripped", d / "c.text")
    sc._ADDR_CACHE.clear()
    return d


def test_va_in_static_helper_maps_to_helper(built):
    va, size = _sym(built / "rec.dbg", "parse_record")
    inside = va + size // 2
    frames = sc.addr_frames(built / "rec.dbg", [inside])[inside]
    assert frames and frames[0][0] == "parse_record" and frames[0][1] == "rec.c"
    assert isinstance(frames[0][2], int) and frames[0][2] > 0
    # outside the twin entirely -> nothing, never a guess
    assert sc.addr_frames(built / "rec.dbg", [0x10])[0x10] == []


def test_inlined_chain_names_helper_then_caller(built):
    va, size = _sym(built / "rec.dbg", "main")
    vas = list(range(va, va + size))
    chains = sc.addr_frames(built / "rec.dbg", vas)        # one addr2line call for all of them
    inl = [c for c in chains.values() if c and c[0][0] == "fold_header"]
    assert inl, "no VA in main resolved into the inlined fold_header"
    assert [f[0] for f in inl[0][:2]] == ["fold_header", "main"]


def _dossier(site, function=None, **kw):
    loc = {"site": hex(site)}
    if function:
        loc["function"] = function
    return {"title": "Heap buffer over-read (QASan-demonstrated)", "level": "L1",
            "cwe": "CWE-125", "location": loc, **kw}


def test_match_through_debug_map(built):
    va, size = _sym(built / "rec.dbg", "parse_record")
    cves = [{"id": "CVE-X-1", "function": "parse_record", "file": "src/rec.c", "line": 9}]
    # a stripped binary's dossier: the site lands in code it attributes to main (or nothing)
    d = _dossier(va + 4, function="main")
    assert sc.match(d, cves) == []                          # no twin: main is skipped, no hit
    hits, how = sc.match_how(d, cves, built / "rec.dbg")
    assert [c["id"] for c in hits] == ["CVE-X-1"] and how == "addr"


def test_main_kept_on_debug_map(built):
    va, size = _sym(built / "rec.dbg", "main")
    chains = sc.addr_frames(built / "rec.dbg", list(range(va, va + size)))
    in_main = next(v for v, c in sorted(chains.items()) if c and c[0][0] == "main")
    cves = [{"id": "BUG-MAIN", "function": "main", "file": "rec.c", "line": 30}]
    hits, how = sc.match_how(_dossier(in_main, function="main"), cves, built / "rec.dbg")
    assert [c["id"] for c in hits] == ["BUG-MAIN"] and how == "addr"


def test_existing_frame_match_unchanged(built):
    va, _ = _sym(built / "rec.dbg", "main")
    cves = [{"id": "CVE-X-1", "function": "parse_record", "file": "rec.c", "line": 9},
            {"id": "BUG-MAIN", "function": "main", "file": "rec.c", "line": 30}]
    # own frames already name parse_record: the debug map (which would say main) is not consulted
    d = _dossier(va, function="parse_record")
    hits, how = sc.match_how(d, cves, built / "rec.dbg")
    assert [c["id"] for c in hits] == ["CVE-X-1"] and how == "frame"


def test_rescore_uses_debug_binary(built, tmp_path, monkeypatch, capsys):
    va, size = _sym(built / "rec.dbg", "parse_record")
    bench = tmp_path / "bench"
    (bench / "rec-1.0").mkdir(parents=True)
    shutil.copy(built / "rec", tmp_path / "rec")
    shutil.copy(built / "rec.dbg", tmp_path / "rec.dbg")
    shutil.copy(built / "rec.stripped", tmp_path / "rec.stripped")
    (bench / "rec-1.0" / "meta.json").write_text(json.dumps({
        "id": "rec-1.0", "binary_path": "rec", "debug_binary": "rec.dbg",
        "cves": [{"id": "CVE-X-1", "class": "heap-overflow-read", "file": "rec.c",
                  "function": "parse_record", "line": 9, "confidence": "high"}]}))
    runs = tmp_path / "runs"
    for surf in ("binary", "binary-stripped"):
        rd = runs / f"rec-1.0--{surf}"
        rd.mkdir(parents=True)
        (rd / "report.json").write_text(json.dumps(
            {"narrative": {"targets": [{"dossiers": [_dossier(va + 4)]}]}}))
    monkeypatch.setattr(sc, "HERE", bench)
    monkeypatch.setattr(sc, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["score.py", "--rescore", str(runs)])
    assert sc.main() == 0
    rows = {r["surface"]: r for r in json.loads((runs / "summary.json").read_text())}
    assert set(rows) == {"binary", "binary-stripped"}     # every run on disk, nothing invented
    for surf, row in rows.items():
        s = row["score"]
        assert s["defects_found"] == 1 and s["cve_ids_found"] == 1, (surf, s)
        assert s["found"]["CVE-X-1"]["how"] == "addr"
        assert s["debug_binary"] == "rec.dbg"
    assert "[addr " in capsys.readouterr().out
    # the same run without a twin on disk scores nothing (and says it is unlisted)
    (tmp_path / "rec.dbg").unlink()
    sc._ADDR_CACHE.clear()
    s = sc.score_run(json.loads((bench / "rec-1.0" / "meta.json").read_text()),
                     runs / "rec-1.0--binary" / "report.json", "binary")
    assert s["defects_found"] == 0 and len(s["unlisted"]) == 1


def test_one_crash_credits_only_the_nearest_line_group_in_a_function():
    """giflib's DumpScreen2RGB holds two CVE groups (lines 294 and 317); a single crash at 294
    must not credit the 317 group too."""
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "recall_score", Path(__file__).resolve().parents[1] / "bench" / "recall" / "score.py")
    sc = importlib.util.module_from_spec(spec); spec.loader.exec_module(sc)
    cves = [{"id": "A", "function": "DumpScreen2RGB", "file": "gif2rgb.c", "line": 294},
            {"id": "B", "function": "DumpScreen2RGB", "file": "gif2rgb.c", "line": 317}]
    with_line = {"location": {"stack": ["DumpScreen2RGB (gif2rgb.c:294)"]}}
    assert [c["id"] for c in sc.match(with_line, cves)] == ["A"]
    no_line = {"location": {"function": "DumpScreen2RGB"}}
    assert {c["id"] for c in sc.match(no_line, cves)} == {"A", "B"}    # unknown line: unchanged
