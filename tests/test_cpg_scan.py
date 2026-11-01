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
    # the untrusted value is a parameter of a PARSER (its parameters are attacker wire data).
    f = _scan(tmp_path, "void parse_pdu(char *u){ char b[16]; strcpy(b, u); }")[0]
    assert f["cwe"] == "CWE-120" and f["fn"] == "strcpy" and f["taint"]


def test_generic_function_parameter_is_not_flagged(tmp_path):
    """Precision: a strcpy/fopen of a plain parameter of a GENERIC function is a forwarding wrapper
    (the caller decides), not an established untrusted flow -- not flagged."""
    assert _scan(tmp_path, "void copy_name(char *dst, char *u){ strcpy(dst, u); }") == []
    assert _scan(tmp_path, 'void open_cfg(char *u){ FILE *fp = fopen(u, "r"); (void)fp; }') == []


def test_bounded_variant_and_literal_and_untainted_are_not_flagged(tmp_path):
    assert _scan(tmp_path, "void f(char *u){ char b[16]; strncpy(b, u, 15); }") == []
    assert _scan(tmp_path, 'void f(void){ char b[16]; strcpy(b, "hi"); }') == []
    assert _scan(tmp_path, "char *c(void);\nvoid f(void){ char b[16]; strcpy(b, c()); }") == []


def test_wire_length_into_fixed_buffer_is_cwe787(tmp_path):
    # The dominant protocol-parser overflow: an untrusted length read off a wStream drives a copy
    # into a FIXED-size buffer. Stream_Read* is recognised as an input-reader (the wire), so `len`
    # is strongly untrusted; the destination `name[64]` is fixed -> CWE-787 OOB write.
    f = _scan(tmp_path,
              "int p(wStream* s){ char name[64]; UINT32 len; Stream_Read_UINT32(s, len);"
              " Stream_Read(s, name, len); return 0; }")
    assert [r["cwe"] for r in f] == ["CWE-787"], f
    assert f[0]["fn"] == "Stream_Read" and f[0]["taint"]


def test_interprocedural_struct_field_length_is_cwe787(tmp_path):
    # Phase A (interprocedural): a length filled into a struct field in ONE function and used as a
    # copy size into a FIXED buffer in ANOTHER is caught via the project-wide wire-field index. The
    # bounded twin (checked against the buffer size) is still suppressed -> 0 false positive.
    src = ("typedef struct { UINT32 len; } Hdr;\n"
           "int parse(wStream* s, Hdr* h){ Stream_Read_UINT32(s, h->len); return 0; }\n"
           "int use(Hdr* h, const BYTE* src){ char buf[64]; memcpy(buf, src, h->len); return 0; }\n"
           "int use_ok(Hdr* h, const BYTE* src){ char buf[64];"
           " if (h->len > sizeof(buf)) return -1; memcpy(buf, src, h->len); return 0; }\n")
    rows = _scan(tmp_path, src)
    assert [r["cwe"] for r in rows] == ["CWE-787"], rows
    assert rows[0]["line"] == 3                       # the unguarded cross-function use, not use_ok


def test_interprocedural_return_value_length_is_cwe787(tmp_path):
    # Phase B (interprocedural): a function whose return value is wire-derived (read_len reads a
    # length off the stream and returns it) taints `len = read_len(s)` at the call site, so a copy of
    # that length into a FIXED buffer in another function is caught. The bounded twin is suppressed.
    src = ("UINT32 read_len(wStream* s)\n{\n    UINT32 n;\n    Stream_Read_UINT32(s, n);\n"
           "    return n;\n}\n"
           "int use(wStream* s, const BYTE* src)\n{\n    char buf[64];\n"
           "    UINT32 len = read_len(s);\n    memcpy(buf, src, len);\n    return 0;\n}\n"
           "int use_ok(wStream* s, const BYTE* src)\n{\n    char buf[64];\n"
           "    UINT32 len = read_len(s);\n    if (len > sizeof(buf)) return -1;\n"
           "    memcpy(buf, src, len);\n    return 0;\n}\n")
    rows = _scan(tmp_path, src)
    assert [r["cwe"] for r in rows] == ["CWE-787"], rows
    assert "read_len() return" in rows[0]["evidence"][1]["detail"]   # the taint is via the returner


def test_interprocedural_caller_tainted_param_length_is_cwe787(tmp_path):
    # Phase C (interprocedural): a length that is a bare PARAMETER of a copy helper is tainted when a
    # caller passes an untrusted argument into it. caller() reads a wire length and passes it to
    # copy_into(len); copy_into memcpy's len into a fixed buf -> CWE-787. The bounded helper (copy_ok,
    # also called with the untrusted value) is suppressed by its own length check.
    src = ("void copy_into(const BYTE* src, UINT32 len)\n{\n    char buf[64];\n"
           "    memcpy(buf, src, len);\n}\n"
           "void copy_ok(const BYTE* src, UINT32 len)\n{\n    char buf[64];\n"
           "    if (len > sizeof(buf)) return;\n    memcpy(buf, src, len);\n}\n"
           "int caller(wStream* s, const BYTE* src)\n{\n    UINT32 n;\n"
           "    Stream_Read_UINT32(s, n);\n    copy_into(src, n);\n    copy_ok(src, n);\n    return 0;\n}\n")
    rows = _scan(tmp_path, src)
    assert [r["cwe"] for r in rows] == ["CWE-787"], rows
    assert rows[0]["line"] == 4                       # the unguarded copy_into, not copy_ok


def test_signed_untrusted_length_with_upper_bound_only_is_cwe195(tmp_path):
    # Signedness (CWE-195): a SIGNED untrusted length with only an UPPER-bound check is a bug -- a
    # negative value passes `len > CAP` and becomes a huge size_t at the copy. The negativity-guarded
    # twin and the unsigned twin are both suppressed.
    def one(body):
        return [r["cwe"] for r in _scan(tmp_path, body)]
    vuln = ("int f(wStream* s, const BYTE* src){ char buf[64]; int len; Stream_Read_UINT32(s, len);"
            " if (len > (int)sizeof(buf)) return -1; memcpy(buf, src, len); return 0; }")
    assert one(vuln) == ["CWE-195"], one(vuln)
    neg = ("int f(wStream* s, const BYTE* src){ char buf[64]; int len; Stream_Read_UINT32(s, len);"
           " if (len < 0 || len > (int)sizeof(buf)) return -1; memcpy(buf, src, len); return 0; }")
    assert one(neg) == [], one(neg)
    uns = ("int f(wStream* s, const BYTE* src){ char buf[64]; UINT32 len; Stream_Read_UINT32(s, len);"
           " if (len > sizeof(buf)) return -1; memcpy(buf, src, len); return 0; }")
    assert one(uns) == [], one(uns)


def test_wire_length_is_not_flagged_when_bounded_or_heap_sized(tmp_path):
    # Precision (0-FP on well-guarded code, the FreeRDP idiom): a length checked against the buffer
    # size, OR a destination heap-allocated to the length, must NOT be flagged.
    assert _scan(tmp_path,
                 "int p(wStream* s){ char name[64]; UINT32 len; Stream_Read_UINT32(s, len);"
                 " if (len > sizeof(name)) return -1; Stream_Read(s, name, len); return 0; }") == []
    assert _scan(tmp_path,
                 "int p(wStream* s){ BYTE* d; UINT32 len; Stream_Read_UINT32(s, len);"
                 " d = malloc(len); memcpy(d, Stream_Pointer(s), len); return 0; }") == []


def test_gets_is_flagged_universally(tmp_path):
    f = _scan(tmp_path, "void f(void){ char b[64]; gets(b); }")[0]
    assert f["cwe"] == "CWE-120" and f["fn"] == "gets"


def test_path_from_input_is_cwe22(tmp_path):
    f = _scan(tmp_path, 'void parse_pdu(char *u){ FILE *fp = fopen(u, "r"); (void)fp; }')[0]
    assert f["cwe"] == "CWE-22" and f["fn"] == "fopen" and f["taint"]


def test_path_with_an_allowlist_prefix_check_is_not_flagged(tmp_path):
    """An allowlist (a strncmp of the path against a literal prefix) restricts it to a known-safe
    set -- not an uncontrolled traversal."""
    src = ('int parse_pdu(char *u){ if (strncmp(u, "/dev/video", 10) != 0) return -1; '
           'FILE *fp = fopen(u, "r"); (void)fp; return 0; }')
    assert _scan(tmp_path, src) == []


def test_path_with_a_normalising_guard_is_not_flagged(tmp_path):
    src = ('void f(char *u){ char rb[4096]; char *r = realpath(u, rb); '
           'FILE *fp = fopen(r, "r"); (void)fp; }')
    assert _scan(tmp_path, src) == []            # realpath in the function -> sanitised


def test_strcat_and_openat_positions(tmp_path):
    rows = _scan(tmp_path,
                 "void parse_pdu(int fd, char *u){ char b[8]; strcat(b, u); openat(fd, u, 0); }")
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
    rows = _scan(tmp_path,
                 "void parse_pdu(char *u){ char b[16]; strcpy(b, u); FILE*x=fopen(u,\"r\"); (void)x; }")
    n = CP._file_findings(_FakeCtx(store.conn), t, rows)
    assert n == 2                                 # both taint-linked -> both get recipes
    recs = [f for f in FindingDAO(store.conn).list_by_target(t.id)
            if f.detector == "source_recipe"]
    assert sorted(r.cwe for r in recs) == ["CWE-120", "CWE-22"]
    assert all(r.state == "corroborated" for r in recs)     # corroborated, never a verified PoC
    assert not PocDAO(store.conn).list_by_target(t.id)
