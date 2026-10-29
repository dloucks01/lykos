"""Attack-surface ranking: a source finding whose file is compiled into a fuzz harness (or the libs it
links) is on the surface the fuzzers exercise, so it is boosted over build tools / platform clients.
The signal is the DWARF line table (a file contributed code iff it is linked in) -- sound and
conservative; off-surface findings are annotated and lowered in ranking, never hidden or dismissed.
"""
import shutil
import subprocess

import pytest

from lykos.analyze import source_confirm_stage as SC
from lykos.analyze.symbolic import dwarfline
from lykos.db.dao import FindingDAO, TargetDAO


# ---- dwarfline.source_files (needs a -g build) -----------------------------------------------

@pytest.mark.skipif(not (shutil.which("gcc") or shutil.which("cc")), reason="needs a C compiler")
@pytest.mark.skipif(not shutil.which("objdump"), reason="needs objdump")
def test_source_files_lists_compiled_files(tmp_path):
    cc = shutil.which("gcc") or shutil.which("cc")
    (tmp_path / "parser.c").write_text("int parse(int x){ return x + 1; }\n")
    (tmp_path / "main.c").write_text("int parse(int);\nint main(void){ return parse(2); }\n")
    exe = tmp_path / "prog"
    assert subprocess.run([cc, "-g", "-O0", str(tmp_path / "parser.c"), str(tmp_path / "main.c"),
                           "-o", str(exe)], capture_output=True).returncode == 0
    files = dwarfline.source_files(exe)
    assert "parser.c" in files and "main.c" in files
    assert "notlinked.c" not in files


# ---- _rank_by_surface (store, no build) ------------------------------------------------------

class _Ctx:
    def __init__(self, conn):
        self.conn = conn


def _cand(conn, t, *, det, cwe, path, line, key, conf=0.5):
    FindingDAO(conn).upsert(t.id, t.case_id, {
        "cwe": cwe, "title": f"{det} cand", "severity": "high", "detector": det,
        "state": "candidate", "confidence": conf, "dedup_key": key,
        "evidence": [{"channel": "source", "detail": f"{path}:{line}: suspected {cwe}"}]})


def _get(conn, t, key):
    return next(f for f in FindingDAO(conn).list_by_target(t.id) if f.dedup_key == key)


def test_in_surface_is_boosted_off_surface_is_annotated_not_hidden(store, case):
    t = TargetDAO(store.conn).upsert(case.id, "t", "a" * 64, arch="source", bits=0)
    _cand(store.conn, t, det="int_overflow", cwe="CWE-190", path="libfreerdp/core/pdu.c", line=10,
          key="in:1", conf=0.5)
    _cand(store.conn, t, det="int_overflow", cwe="CWE-190", path="tools/gen_manpage.c", line=5,
          key="off:1", conf=0.5)
    counts = SC._rank_by_surface(_Ctx(store.conn), t, surface={"pdu.c"})
    assert counts == {"in_surface": 1, "off_surface": 1}
    f_in, f_off = _get(store.conn, t, "in:1"), _get(store.conn, t, "off:1")
    # in-surface boosted above its base; off-surface NOT penalised (kept at base, still present)
    assert f_in.confidence > 0.5 and abs(f_off.confidence - 0.5) < 1e-6
    ev_in = " ".join(str(e.get("detail", "")) for e in (f_in.evidence or []))
    ev_off = " ".join(str(e.get("detail", "")) for e in (f_off.evidence or []))
    assert "on the fuzzed attack surface" in ev_in
    assert "off the fuzzed attack surface" in ev_off
    # neither is hidden: both remain candidate findings
    assert f_in.state == "candidate" and f_off.state == "candidate"


def test_ranks_recipes_too(store, case):
    t = TargetDAO(store.conn).upsert(case.id, "t", "b" * 64, arch="source", bits=0)
    FindingDAO(store.conn).upsert(t.id, t.case_id, {
        "cwe": "CWE-190", "title": "Exploitation recipe: x", "severity": "high",
        "detector": "source_recipe", "state": "corroborated", "confidence": 0.5,
        "dedup_key": "rec:1",
        "evidence": [{"channel": "recipe-source", "detail": "libfreerdp/codec/zgfx.c:200; subject ..."}]})
    counts = SC._rank_by_surface(_Ctx(store.conn), t, surface={"zgfx.c"})
    assert counts["in_surface"] == 1
    assert _get(store.conn, t, "rec:1").confidence > 0.5
