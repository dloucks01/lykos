"""Per-CWE source/sink queries (cpg_scan): classes the dedicated detectors miss -- unbounded buffer
copy (CWE-120) and path traversal (CWE-22) -- taint-gated, sanitizer-aware, bounded-variants excluded.
"""
from __future__ import annotations

import hashlib

from lykos.analyze.fingerprint import cpg_scan as CP
from lykos.db.dao import FindingDAO, PocDAO, TargetDAO


def _scan(tmp_path, src):
    (tmp_path / "a.c").write_text(src)
    return CP.scan_source(tmp_path)


def _cwes(rows):
    return sorted(r["cwe"] for r in rows)


def test_unbounded_copy_of_tainted_data_is_cwe120(tmp_path):
    f = _scan(tmp_path, "void f(char *u){ char b[16]; strcpy(b, u); }")[0]
    assert f["cwe"] == "CWE-120" and f["fn"] == "strcpy" and f["taint"]


def test_bounded_variant_and_literal_and_untainted_are_not_flagged(tmp_path):
    assert _scan(tmp_path, "void f(char *u){ char b[16]; strncpy(b, u, 15); }") == []
    assert _scan(tmp_path, 'void f(void){ char b[16]; strcpy(b, "hi"); }') == []
    assert _scan(tmp_path, "char *c(void);\nvoid f(void){ char b[16]; strcpy(b, c()); }") == []


def test_gets_is_flagged_universally(tmp_path):
    f = _scan(tmp_path, "void f(void){ char b[64]; gets(b); }")[0]
    assert f["cwe"] == "CWE-120" and f["fn"] == "gets"


def test_path_from_input_is_cwe22(tmp_path):
    f = _scan(tmp_path, 'void f(char *u){ FILE *fp = fopen(u, "r"); (void)fp; }')[0]
    assert f["cwe"] == "CWE-22" and f["fn"] == "fopen" and f["taint"]


def test_path_with_a_normalising_guard_is_not_flagged(tmp_path):
    src = ('void f(char *u){ char rb[4096]; char *r = realpath(u, rb); '
           'FILE *fp = fopen(r, "r"); (void)fp; }')
    assert _scan(tmp_path, src) == []            # realpath in the function -> sanitised


def test_strcat_and_openat_positions(tmp_path):
    rows = _scan(tmp_path, "void f(int fd, char *u){ char b[8]; strcat(b, u); openat(fd, u, 0); }")
    assert _cwes(rows) == ["CWE-120", "CWE-22"]  # strcat src arg + openat path arg (2nd)


# ---- stage filing + recipe floor ----

class _FakeCtx:
    def __init__(self, conn):
        self.conn = conn
        self.stored = {}

    def put_artifact(self, kind, *, data, meta=None):
        sha = hashlib.sha256(bytes(data)).hexdigest()
        self.stored[sha] = bytes(data)
        return sha


def test_file_findings_files_candidates_and_recipes(store, case, tmp_path):
    t = TargetDAO(store.conn).upsert(case.id, "t", "a" * 64, arch="source", bits=0)
    rows = _scan(tmp_path, "void f(char *u){ char b[16]; strcpy(b, u); FILE*x=fopen(u,\"r\"); (void)x; }")
    n = CP._file_findings(_FakeCtx(store.conn), t, rows)
    assert n == 2                                 # both taint-linked -> both get recipes
    recs = [f for f in FindingDAO(store.conn).list_by_target(t.id)
            if f.detector == "source_recipe"]
    assert sorted(r.cwe for r in recs) == ["CWE-120", "CWE-22"]
    assert all(r.state == "corroborated" for r in recs)     # corroborated, never a verified PoC
    assert not PocDAO(store.conn).list_by_target(t.id)
