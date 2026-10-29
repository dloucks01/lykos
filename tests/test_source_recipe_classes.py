"""Taint-lite + the non-fuzzing recipe floor extended to the memory-safety source detectors:
integer-overflow allocations (CWE-190) and use-after-free / double-free (CWE-416/415).

Same discipline as the sink floor: a candidate earns a corroborated recipe only when its subject
(a size operand, a freed pointer) is syntactically linked to an untrusted source. The int-overflow /
UAF recipes carry no fixed payload bytes -- the weaponization is a CONDITION (wrap the size; reclaim
the chunk), stated in prose with what the compiled target is still needed for -- and are filed
`corroborated`, never a verified PoC.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from lykos.analyze.fingerprint import int_overflow as IO
from lykos.analyze.fingerprint import uaf as UAF
from lykos.analyze.poc import source_recipe as SR
from lykos.db.dao import FindingDAO, PocDAO, TargetDAO


def _tree(tmp_path, src: str) -> Path:
    (tmp_path / "a.c").write_text(src)
    return tmp_path


# ---- int_overflow (CWE-190) taint-lite --------------------------------------------------------

def test_intovf_size_operand_from_a_parser_parameter_is_strong(tmp_path):
    # a parser's parameters carry attacker wire data, so a size computed from them is a STRONG
    # (exploitable, high) integer-overflow finding.
    src = "void decode_frame(int n, int sz)\n{\n    char *p = malloc(n * sz);\n    (void)p;\n}\n"
    f = IO.scan_source(_tree(tmp_path, src))[0]
    assert f["cwe"] == "CWE-190" and f["strong"] and f["severity"] == "high" and f["taint"]


def test_intovf_size_variable_operand_from_a_parser_parameter_is_strong(tmp_path):
    src = ("void parse_hdr(int a, int b)\n{\n    unsigned long sz = a * b;\n"
           "    char *p = malloc(sz);\n    (void)p;\n}\n")
    f = IO.scan_source(_tree(tmp_path, src))[0]
    assert f["strong"] and f["taint"] and "a" in f["taint"]["source"]


def test_intovf_generic_function_parameter_is_weak_hygiene(tmp_path):
    # the precision fix: a size from a GENERIC function's parameter is not established
    # attacker-controlled (the caller decides) -> a low hygiene note, not a high finding.
    src = "void f(int n, int sz)\n{\n    char *p = malloc(n * sz);\n    (void)p;\n}\n"
    f = IO.scan_source(_tree(tmp_path, src))[0]
    assert f["cwe"] == "CWE-190" and not f["strong"] and f["severity"] == "low" and f["taint"] is None


def test_intovf_local_operands_are_not_linked(tmp_path):
    src = "void h(void)\n{\n    int a = 2, b = 3;\n    char *p = malloc(a * b);\n    (void)p;\n}\n"
    f = IO.scan_source(_tree(tmp_path, src))[0]
    assert f["cwe"] == "CWE-190" and f["taint"] is None        # no input link -> candidate only


# ---- uaf (CWE-416) taint-lite -----------------------------------------------------------------

def test_uaf_freed_parameter_is_linked(tmp_path):
    src = "void f(char *p)\n{\n    free(p);\n    p[0] = 1;\n}\n"
    f = UAF.scan_source(_tree(tmp_path, src))[0]
    assert f["cwe"] == "CWE-416" and f["taint"] and f["taint"]["via"] == "parameter"


def test_uaf_reader_filled_pointer_is_linked(tmp_path):
    src = 'void g(void)\n{\n    char *p = getenv("X");\n    free(p);\n    p[0] = 1;\n}\n'
    f = UAF.scan_source(_tree(tmp_path, src))[0]
    assert f["taint"] and "getenv" in f["taint"]["source"]


def test_uaf_local_pointer_is_not_linked(tmp_path):
    src = "void h(void)\n{\n    char *p = malloc(8);\n    free(p);\n    p[0] = 1;\n}\n"
    f = UAF.scan_source(_tree(tmp_path, src))[0]
    assert f["cwe"] == "CWE-416" and f["taint"] is None


# ---- the recipes these classes file -----------------------------------------------------------

class _FakeCtx:
    def __init__(self, conn):
        self.conn = conn
        self.stored = {}

    def put_artifact(self, kind, *, data, meta=None):
        sha = hashlib.sha256(bytes(data)).hexdigest()
        self.stored[sha] = bytes(data)
        return sha


def _target(store, case):
    return TargetDAO(store.conn).upsert(case.id, "t", "a" * 64, arch="source", bits=0)


def _recipe(conn, tid, cwe):
    return next((f for f in FindingDAO(conn).list_by_target(tid)
                 if f.detector == "source_recipe" and f.cwe == cwe), None)


def test_cwe190_recipe_is_corroborated_prose(store, case):
    t = _target(store, case)
    ctx = _FakeCtx(store.conn)
    fid = SR.file_source_recipe(ctx, t, cwe="CWE-190", fn="malloc", arg="n * sz",
                                file="x/parse.c", line=10,
                                taint={"via": "parameter", "source": "function parameter 'n'"})
    assert fid
    r = _recipe(store.conn, t.id, "CWE-190")
    assert r and r.state == "corroborated"
    ev = " ".join(str(e.get("detail", "")) for e in (r.evidence or []))
    assert "integer-overflow" in (r.title or "") and "wraps" in ev and "NOT executed" in ev
    # a condition, not fixed bytes -> no candidate-input artifact, and never a verified PoC
    assert not any("candidate input" in str(e.get("detail", "")) for e in (r.evidence or []))
    assert not PocDAO(store.conn).list_by_target(t.id)


def test_cwe416_recipe_is_corroborated_prose(store, case):
    t = _target(store, case)
    ctx = _FakeCtx(store.conn)
    fid = SR.file_source_recipe(ctx, t, cwe="CWE-416", fn="free()", arg="p",
                                file="x/obj.c", line=42,
                                taint={"via": "input-reader", "source": "getenv() into 'p'"})
    assert fid
    r = _recipe(store.conn, t.id, "CWE-416")
    assert r and r.state == "corroborated"
    ev = " ".join(str(e.get("detail", "")) for e in (r.evidence or []))
    assert "use-after-free" in (r.title or "") and "reclaim" in ev
    assert not PocDAO(store.conn).list_by_target(t.id)
