"""The source-level taint-lite + the non-fuzzing weaponization FLOOR for tainted sinks.

A `system(cmd)` / `printf(fmt)` with a non-literal argument is a candidate. When that argument is
syntactically linked to an UNTRUSTED SOURCE in the same function -- a parameter, an input reader,
argv -- the finding earns more confidence AND a corroborated exploitation recipe carrying the
technique + a concrete candidate payload. The link is a CHECKABLE SYNTACTIC FACT, so the recipe is
never filed on a fabricated flow; a value the scanner cannot connect to input stays a bare candidate.
The recipe is `corroborated`, NEVER a verified PoC -- precision is paramount.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from lykos.analyze.fingerprint import source_sinks as ss
from lykos.db.dao import FindingDAO, PocDAO, TargetDAO

_SHA = "e" * 64


def _tree(tmp_path, files: dict) -> Path:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path


def _scan(tmp_path, src: str):
    return ss.scan_source(_tree(tmp_path, {"a.c": src}))


# ---- taint-lite: which sinks get a proven source link ----------------------------------------

def test_bare_parameter_is_NOT_a_strong_link(tmp_path):
    """A generic parameter is NOT an established untrusted source -- `void run(char *cmd){
    system(cmd); }` is a forwarding WRAPPER (the caller decides cmd). Flagging it as exploitable
    was the false-positive class that lit up every printf/exec wrapper in real code. It stays a
    low-severity hygiene note with no proven flow (precision is paramount)."""
    f = _scan(tmp_path, "void run(char *cmd){ system(cmd); }")[0]
    assert f["cwe"] == "CWE-78" and not f["strong"] and f["taint"] is None
    assert f["severity"] == "low" and "hygiene" in f["title"]


def test_getenv_return_is_linked(tmp_path):
    f = _scan(tmp_path, 'void f(){ char *p = getenv("X"); system(p); }')[0]
    assert f["taint"] and f["taint"]["via"] == "input-reader" and "getenv" in f["taint"]["source"]


def test_read_into_buffer_is_linked(tmp_path):
    f = _scan(tmp_path, "void f(int fd){ char b[64]; read(fd,b,64); printf(b); }")[0]
    assert f["cwe"] == "CWE-134" and f["taint"] and "read" in f["taint"]["source"]


def test_fgets_into_buffer_is_linked(tmp_path):
    f = _scan(tmp_path, "void f(){ char b[64]; fgets(b,64,stdin); system(b); }")[0]
    assert f["taint"] and "fgets" in f["taint"]["source"]


def test_argv_subscript_is_a_strong_untrusted_source(tmp_path):
    """argv is genuinely attacker-controlled even though it arrives as main()'s parameter -- it is
    STRONG (an exploitable finding worth a PoC), unlike a generic parameter."""
    f = _scan(tmp_path, "int main(int argc, char **argv){ system(argv[1]); return 0; }")[0]
    assert f["strong"] and f["taint"] and "argv" in f["taint"]["source"]
    assert f["severity"] == "high"


def test_a_computed_value_is_not_linked(tmp_path):
    """`x = compute()` is neither a parameter nor a known reader -> candidate, but NO taint link
    (so no recipe is fabricated for a flow we cannot see)."""
    f = _scan(tmp_path, "char *compute(void);\nvoid f(){ char *x = compute(); printf(x); }")[0]
    assert f["cwe"] == "CWE-134" and f["taint"] is None


def test_the_count_argument_of_read_is_not_mistaken_for_the_buffer(tmp_path):
    """`read(fd, other, n)` fills `other`, not `n`; a sink on `n` must not be called reader-linked.
    `n` is a bare parameter, so after the precision fix it is weak (no input reader fills it) --
    crucially NOT misattributed to read() as a strong source."""
    src = ("void f(int fd, char *n){ char other[64]; read(fd, other, (unsigned long)n); "
           "system(n); }")
    f = _scan(tmp_path, src)[0]
    assert not f["strong"] and f["taint"] is None          # not strong, and NOT read()-attributed


# ---- the recipe floor ------------------------------------------------------------------------

class _FakeCtx:
    def __init__(self, conn):
        self.conn = conn
        self.stored = {}

    def put_artifact(self, kind, *, data, meta=None):
        sha = hashlib.sha256(bytes(data)).hexdigest()
        self.stored[sha] = bytes(data)
        return sha


def _target(store, case):
    return TargetDAO(store.conn).upsert(case.id, "t", _SHA, arch="source", bits=0)


def _recipes(conn, tid):
    return [f for f in FindingDAO(conn).list_by_target(tid)
            if (f.title or "").startswith("Exploitation recipe")]


def test_file_findings_files_candidate_and_recipe_for_strongly_linked_sinks(store, case, tmp_path):
    t = _target(store, case)
    ctx = _FakeCtx(store.conn)
    # STRONG sources only: argv -> system, and a read() buffer -> printf. Both are genuinely
    # attacker-controlled, so both earn a recipe.
    findings = _scan(tmp_path,
                     "int main(int c, char**v){ if(c>1) system(v[1]); return 0; }\n"
                     "void logit(int fd){ char b[64]; read(fd,b,64); printf(b); }\n")
    n = ss._file_findings(ctx, t, findings)
    assert n == 2                                            # both are strongly linked
    recs = _recipes(store.conn, t.id)
    cwes = sorted(r.cwe for r in recs)
    assert cwes == ["CWE-134", "CWE-78"]
    # Honesty: corroborated, NEVER a verified PoC row.
    assert all(r.state == "corroborated" for r in recs)
    assert not PocDAO(store.conn).list_by_target(t.id)
    # The concrete candidate payloads were handed over as artifacts.
    assert b"; id #" in ctx.stored.values()
    assert any(b"%n" in v for v in ctx.stored.values())
    # The candidate findings carry the raised confidence and the flow evidence.
    cands = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "source_sink"]
    assert cands and all(abs((c.confidence or 0) - 0.6) < 1e-6 for c in cands)
    ev = " ".join(str(e.get("detail", "")) for c in cands for e in (c.evidence or []))
    assert "flows from" in ev


def test_parameter_forwarding_wrapper_gets_no_recipe(store, case, tmp_path):
    """The precision fix: a bare-parameter sink (a forwarding wrapper) is a low hygiene note, not a
    recipe-worthy exploitable finding."""
    t = _target(store, case)
    ctx = _FakeCtx(store.conn)
    findings = _scan(tmp_path, "void run(char *cmd){ system(cmd); }\n"
                               "void logit(const char *fmt){ syslog(3, fmt); }\n")
    n = ss._file_findings(ctx, t, findings)
    assert n == 0                                            # no recipe for parameter-forwarded sinks
    assert not _recipes(store.conn, t.id)
    cands = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "source_sink"]
    assert cands and all(c.severity == "low" for c in cands)


def test_an_unlinked_sink_gets_no_recipe(store, case, tmp_path):
    t = _target(store, case)
    ctx = _FakeCtx(store.conn)
    findings = _scan(tmp_path, "char *compute(void);\nvoid f(){ char *x = compute(); printf(x); }")
    n = ss._file_findings(ctx, t, findings)
    assert n == 0 and not _recipes(store.conn, t.id)
    cands = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "source_sink"]
    assert cands and abs((cands[0].confidence or 0) - 0.4) < 1e-6   # unlinked keeps the base score
