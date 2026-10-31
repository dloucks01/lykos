"""The shared non-executed exploitation-recipe helper (`analyze.poc.recipe`).

A recipe is the honest middle rung: a weaponization computed from the recovered program, filed
when the target could not be EXECUTED to confirm it. These tests pin the honesty contract --
`corroborated`, never a verified PoC row, the concrete bytes handed over, and a ceiling annotation
on the originating lead -- so a later change cannot quietly let a recipe masquerade as a demonstrated
exploit.
"""
import hashlib

from lykos.analyze.poc import recipe
from lykos.db.dao import FindingDAO, PocDAO, TargetDAO

_SHA = "d" * 64


class _FakeCtx:
    """Minimal stage context: just the DB handle + an artifact sink (content-addressed stub)."""
    def __init__(self, conn):
        self.conn = conn
        self.stored = {}

    def put_artifact(self, kind, *, data, meta=None):
        sha = hashlib.sha256(bytes(data)).hexdigest()
        self.stored[sha] = bytes(data)
        return sha


def _target(store, case):
    return TargetDAO(store.conn).upsert(case.id, "t", _SHA, arch="x86-64", bits=64)


def _recipes(conn, tid):
    return [f for f in FindingDAO(conn).list_by_target(tid)
            if (f.title or "").startswith("Exploitation recipe")]


def test_recipe_is_corroborated_and_carries_the_bytes_but_no_verified_poc(store, case):
    t = _target(store, case)
    ctx = _FakeCtx(store.conn)
    fid = recipe.file_recipe(
        ctx, t, cwe="CWE-78", technique="command-injection via stdin", target_level="L3",
        summary="the binary imports system(); candidate payload ';id;' over stdin",
        why_not_executed="no execution available here",
        input_bytes=b";id;\n", input_mode="stdin")
    assert fid
    recs = _recipes(store.conn, t.id)
    assert len(recs) == 1
    r = recs[0]
    # Honest state: corroborated, NOT poc-backed / confirmed.
    assert r.state == "corroborated"
    # The actual bytes were stored as a plain artifact and referenced -- but NO verified PoC row.
    assert not PocDAO(store.conn).list_by_target(t.id)
    assert ctx.stored and b";id;\n" in ctx.stored.values()
    ev = " ".join(str(e.get("detail", "")) for e in (r.evidence or []))
    assert "NOT executed" in ev and "candidate input" in ev and "L3" in ev


def test_recipe_annotates_the_lead_ceiling_without_regressing_it(store, case):
    t = _target(store, case)
    ctx = _FakeCtx(store.conn)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, t.case_id, {
        "cwe": "CWE-121", "title": "Stack buffer overflow", "severity": "high",
        "detector": "stack_buffer_overflow", "state": "candidate", "confidence": 0.55,
        "dedup_key": "lead-121", "evidence": [{"channel": "static", "detail": "recovered frame"}]})
    lead = next(f for f in fd.list_by_target(t.id) if f.dedup_key == "lead-121")

    recipe.file_recipe(
        ctx, t, cwe="CWE-121", technique="stack-overflow return-address overwrite",
        target_level="L1", summary="write 72 bytes then a sentinel at the return slot",
        why_not_executed="no crash in this sandbox", lead=lead)

    # A separate recipe row exists...
    assert len(_recipes(store.conn, t.id)) == 1
    # ...and the LEAD now carries a ceiling note in its own channel, still at >= its prior state.
    lead2 = next(f for f in fd.list_by_target(t.id) if f.dedup_key == "lead-121")
    chans = {e.get("channel") for e in (lead2.evidence or [])}
    assert "recipe-ceiling" in chans
    assert lead2.state in ("candidate", "corroborated", "confirmed", "poc-backed")


def test_recipe_records_specific_next_technique_end_to_end(store, case):
    """A specific `missing_technique` an emitter passes is written inline on the lead, parsed back
    by the confirm ladder (overriding the class default), and surfaced in the weaponization backlog
    -- the full emitter -> store -> report path, not just the parse in isolation."""
    from lykos.analyze.confirm_ladder import ceiling_ledger, finding_exploitability
    t = _target(store, case)
    ctx = _FakeCtx(store.conn)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, t.case_id, {
        "cwe": "CWE-134", "title": "Format string in parser", "severity": "high",
        "detector": "format_string", "state": "candidate", "confidence": 0.55,
        "dedup_key": "lead-134", "site_addr": "0x401abc",
        "evidence": [{"channel": "static", "detail": "printf(user)"}]})
    lead = next(f for f in fd.list_by_target(t.id) if f.dedup_key == "lead-134")
    want_tech = ("a format sink reached MORE THAN ONCE so a %p leak can precede the %hhn write -- a "
                 "single-shot sink cannot leak-then-write in one run")
    recipe.file_recipe(
        ctx, t, cwe="CWE-134", technique="format-string %n write-what-where", target_level="L2",
        summary="write-what-where via %hhn", why_not_executed="the sink runs once",
        lead=lead, missing_technique=want_tech)

    # The lead now carries the inline [needs: ...] marker.
    lead2 = next(f for f in fd.list_by_target(t.id) if f.dedup_key == "lead-134")
    ev = " ".join(str(e.get("detail", "")) for e in (lead2.evidence or []))
    assert "[needs:" in ev and "reached MORE THAN ONCE" in ev

    # The confirm ladder parses the SPECIFIC technique (not the generic class default) + framing.
    lf = {"cwe": lead2.cwe, "severity": lead2.severity, "site_addr": "0x401abc",
          "title": lead2.title, "dedup_key": lead2.dedup_key,
          "evidence": [{"channel": e.get("channel"), "detail": e.get("detail")}
                       for e in (lead2.evidence or [])]}
    ex = finding_exploitability(lf, None)
    assert ex["missing_technique"] == want_tech
    assert "not a limit of the target" in ex["ceiling_framing"]

    # ...and the backlog surfaces it as an entry grouped by the technique to build.
    lf["exploitability"] = ex
    led = ceiling_ledger([lf])
    assert led and led["count"] == 1
    assert led["entries"][0]["missing_technique"] == want_tech
    assert led["techniques"][0]["missing_technique"] == want_tech


def test_recipe_filing_never_raises_on_a_bad_artifact_sink(store, case):
    """The prose recipe must still be filed even if storing the bytes fails."""
    t = _target(store, case)

    class _BadCtx(_FakeCtx):
        def put_artifact(self, *a, **k):
            raise RuntimeError("no content store")

    fid = recipe.file_recipe(
        _BadCtx(store.conn), t, cwe="CWE-134", technique="format-string %n write", target_level="L2",
        summary="write-what-where via %n", why_not_executed="not executed",
        input_bytes=b"%n%n%n")
    assert fid and len(_recipes(store.conn, t.id)) == 1
