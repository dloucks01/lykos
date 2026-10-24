"""Size-tiered native recovery: a large binary gets a function list + call graph even when
whole-program `aaa` cannot finish (it used to degrade to strings-only), and every rung that fell
short is reported. A small binary keeps the original single-`aaa` path unchanged."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from lykos.analyze import native_re


class _StageTimeout(Exception):
    pass


_StageTimeout.__name__ = "StageTimeout"


class _Ctx:
    def __init__(self, cancel=False):
        self.cancel, self.deadline, self.msgs = cancel, None, []

    def should_cancel(self):
        return self.cancel

    def progress(self, pct=None, msg=None):
        self.msgs.append(msg)


def _script_of(cli, binary, script, **kw):
    return script


def test_checkpoint_survives_a_cut_mid_ladder(tmp_path, monkeypatch):
    """`aa` landed, `aac` was being written when the per-call cap fired (torn JSON): the `aa`
    function list is kept, the cut is reported, nothing is raised."""
    def fake_run(cli, binary, script, *, ctx=None, timeout, scratch=None):
        assert "aaa" not in script.split(";")[:2]           # cheap facts + `aa` come first
        (tmp_path / "funcs.0").write_text(json.dumps([{"offset": 0x1000, "name": "main"}]))
        (tmp_path / "funcs.1").write_text('[{"offset": 4096, "na')        # torn by the kill
        raise subprocess.TimeoutExpired("rizin", timeout)

    monkeypatch.setattr(native_re, "_run", fake_run)
    r = native_re._tiered_pass1(Path("/bin/rizin"), Path("/x"), tmp_path, "", 20.0, [1, 2],
                                ctx=None, timeout=100)
    assert r["cut"] and r["tier"] == "aa" and len(r["aflj"]) == 1
    assert r["planned"] == ["aa", "aa+aac", "aaa"] and r["budget"] == 60
    assert not r["xrefs_done"]


def test_no_aaa_rung_above_the_full_threshold(tmp_path, monkeypatch):
    seen = {}

    def fake_run(cli, binary, script, *, ctx=None, timeout, scratch=None):
        seen["s"] = script
        for i in range(2):
            (tmp_path / f"funcs.{i}").write_text("[]")

    monkeypatch.setattr(native_re, "_run", fake_run)
    r = native_re._tiered_pass1(Path("/bin/rizin"), Path("/x"), tmp_path, "", 200.0, [],
                                ctx=None, timeout=100)
    cmds = [c.strip() for c in seen["s"].split(";")]
    assert "aaa" not in cmds and "aac" in cmds and r["planned"] == ["aa", "aa+aac"]
    assert r["tier"] == "aa+aac" and r["aflj"] == []


def test_aaa_deepening_is_a_separate_bounded_call(tmp_path, monkeypatch):
    """Below the full threshold `aaa` deepens in its OWN call, after the essential ladder landed;
    if it is cut, the `aa+aac` list stands and the shortfall is a note, not a partial result."""
    seen = []

    def fake_run(cli, binary, script, *, ctx=None, timeout, scratch=None):
        seen.append((script.split(";")[0].strip(), timeout))
        if script.startswith("aaa"):
            raise subprocess.TimeoutExpired("rizin", timeout)
        for i in range(2):
            (tmp_path / f"funcs.{i}").write_text(json.dumps([{"offset": 16 * (i + 1)}] * (i + 1)))

    monkeypatch.setattr(native_re, "_run", fake_run)
    r = native_re._tiered_pass1(Path("/bin/rizin"), Path("/x"), tmp_path, "", 20.0, [],
                                ctx=None, timeout=100)
    assert [s for s, _ in seen] == ["ij > %s" % (tmp_path / "ij"), "aaa"]
    assert seen[1][1] == 25                                 # its own bounded share
    assert r["tier"] == "aa+aac" and len(r["aflj"]) == 2 and not r["cut"]
    assert r["notes"] and "did not finish" in r["notes"][0]


def test_an_empty_deeper_rung_never_hides_a_shallower_list(tmp_path, monkeypatch):
    def fake_run(cli, binary, script, *, ctx=None, timeout, scratch=None):
        (tmp_path / "funcs.0").write_text(json.dumps([{"offset": 1}]))
        (tmp_path / "funcs.1").write_text("[]")

    monkeypatch.setattr(native_re, "_run", fake_run)
    r = native_re._tiered_pass1(Path("/bin/rizin"), Path("/x"), tmp_path, "", 200.0, [],
                                ctx=None, timeout=100)
    assert r["tier"] == "aa" and len(r["aflj"]) == 1


def test_a_real_stage_cancel_still_propagates(tmp_path, monkeypatch):
    def fake_run(cli, binary, script, *, ctx=None, timeout, scratch=None):
        raise _StageTimeout("deadline")

    monkeypatch.setattr(native_re, "_run", fake_run)
    with pytest.raises(_StageTimeout):
        native_re._tiered_pass1(Path("/bin/rizin"), Path("/x"), tmp_path, "", 20.0, [],
                                ctx=_Ctx(cancel=True), timeout=100)
    # ...but the same exception as a per-CALL cap (stage still alive) is a recoverable cut
    r = native_re._tiered_pass1(Path("/bin/rizin"), Path("/x"), tmp_path, "", 20.0, [],
                                ctx=_Ctx(cancel=False), timeout=100)
    assert r["cut"] and r["tier"] is None


def test_string_xref_cut_keeps_the_analysis(tmp_path, monkeypatch):
    """A per-call timeout in the best-effort xref pass used to propagate and discard every
    function already built. Now the strings come back without xrefs and the gap is noted."""
    def fake_run(cli, binary, script, *, ctx=None, timeout, scratch=None):
        raise subprocess.TimeoutExpired("rizin", timeout)

    monkeypatch.setattr(native_re, "_run", fake_run)
    izj = [{"vaddr": 0x4000, "string": "hello"}, {"vaddr": 0x4010, "string": "x"}]
    strings, note = native_re._build_strings(Path("/bin/rizin"), Path("/x"), izj, tmp_path,
                                             ctx=None, timeout=10)
    assert [s["value"] for s in strings] == ["hello", "x"]
    assert "0/2" in note


def test_time_share_respects_the_stage_deadline():
    import time
    ctx = _Ctx()
    ctx.deadline = time.time() + 100
    assert 45 <= native_re._time_share(ctx, 1800, 0.5) <= 50
    assert native_re._time_share(None, 1800, 0.5) == 900
    ctx.deadline = time.time() - 5                         # already past: floored, not negative
    assert native_re._time_share(ctx, 1800, 0.5) == 30


def test_mapped_view_is_byte_identical(tmp_path):
    p = tmp_path / "b"
    p.write_bytes(b"\x7fELF" + bytes(range(256)) * 4)
    with native_re._Mapped(p) as m:
        assert m[:4] == b"\x7fELF" and len(m) == p.stat().st_size and m[4] == 0
        assert m.find(b"\x10\x11") == p.read_bytes().find(b"\x10\x11")
    e = tmp_path / "empty"
    e.write_bytes(b"")
    with native_re._Mapped(e) as m:                         # mmap refuses 0 bytes: falls back
        assert m == b""


_HAVE_NATIVE = native_re.locate_native() is not None
try:
    import pypcode  # noqa: F401
    _HAVE_PYPCODE = True
except Exception:
    _HAVE_PYPCODE = False

_SRC = (
    "#include <string.h>\n#include <stdio.h>\n"
    "void bug(char *in){ char buf[16]; strcpy(buf, in); puts(buf); puts(\"marker-string\"); }\n"
    "int main(int c, char **v){ if (c > 1) bug(v[1]); return 0; }\n"
)


@pytest.mark.skipif(not (_HAVE_NATIVE and _HAVE_PYPCODE),
                    reason="needs rizin/radare2 + pypcode")
def test_tiered_recovery_matches_the_small_path(gcc, tmp_path, monkeypatch):
    """Forcing the large-binary ladder (aa -> aac, no aaa) on a small program recovers the same
    functions, call edges, P-Code and string xrefs as the original single-`aaa` path."""
    src = tmp_path / "v.c"
    src.write_text(_SRC)
    out = tmp_path / "v"
    subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-g", str(src), "-o",
                    str(out)], check=True, capture_output=True)
    small = native_re.analyze(out, timeout=180)
    assert small["tiered"] is False and small["analysis_tier"] == "aaa"
    assert small["degradations"] == []
    monkeypatch.setattr(native_re, "_AAA_TIER_MB", 0.0)
    monkeypatch.setattr(native_re, "_AAA_FULL_MAX_MB", 0.0)
    big = native_re.analyze(out, timeout=180)
    assert big["tiered"] is True and big["analysis_tier"] == "aa+aac"
    assert not big["partial"] and big["degradations"] == []

    def summary(r):
        return {f["name"]: (len(f["calls"]), sum(len(b["instructions"]) for b in f["cfg"]["blocks"]),
                            bool(any(i["pcode"] for b in f["cfg"]["blocks"]
                                     for i in b["instructions"])))
                for f in r["functions"]}
    assert summary(big) == summary(small)
    assert "bug" in summary(big) and "main" in summary(big)
    xs = {s["value"]: s["xrefs"] for s in small["strings"]}
    xb = {s["value"]: s["xrefs"] for s in big["strings"]}
    assert xb == xs and xb.get("marker-string")


def test_lifter_resumes_after_a_native_crash_and_skips_only_the_crasher(monkeypatch):
    """pypcode aborts on some encodings. The lift used to keep only what was flushed before the
    crash (everything after it silently had no P-Code); it now resumes, pinpoints the encoding,
    skips just that one and reports it."""
    bad = 300
    instrs = [(a, "90") for a in range(1000)]
    calls = []

    def fake_invoke(self, spec, *, ctx=None, timeout=600):
        todo = spec["instrs"]
        calls.append((todo[0][0], spec["flush_first"]))
        rows = []
        for i, (a, _h) in enumerate(todo):
            if a == bad:
                # a native abort: rows beyond the last flush are lost
                keep = i if i < spec["flush_first"] else (i // 256) * 256
                return rows[:keep], "crashed"
            rows.append({"a": hex(a), "p": ["COPY"]})
        return rows, "ok"

    monkeypatch.setattr(native_re._Lifter, "_invoke_status", fake_invoke)
    lf = native_re._Lifter("x86:LE:64:default")
    lf.available = True
    out = lf.lift_all(instrs, timeout=60)
    assert len(out) == 999 and hex(bad) not in out
    assert lf.crashed_at == [bad] and lf.unlifted == 0 and lf.lift_status == "crashed"
    assert calls == [(0, 0), (256, 256), (bad + 1, 0)]


def test_lifter_timeout_reports_the_unlifted_remainder(monkeypatch):
    def fake_invoke(self, spec, *, ctx=None, timeout=600):
        return [{"a": hex(a), "p": []} for a, _ in spec["instrs"][:10]], "timeout"

    monkeypatch.setattr(native_re._Lifter, "_invoke_status", fake_invoke)
    lf = native_re._Lifter("x86:LE:64:default")
    lf.available = True
    out = lf.lift_all([(a, "90") for a in range(50)], timeout=60)
    assert len(out) == 10 and lf.unlifted == 40 and lf.lift_status == "timeout"


@pytest.mark.skipif(not (_HAVE_NATIVE and _HAVE_PYPCODE),
                    reason="needs rizin/radare2 + pypcode")
def test_disassemble_stage_reports_the_tier(store, case, gcc, tmp_path, monkeypatch):
    """Through the real stage: a large-binary run persists functions and says which rung of the
    ladder produced them (here forced, with the `aaa` rung disabled)."""
    from lykos.analyze import register
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.db.dao import EventDAO, FunctionDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    monkeypatch.setenv("LYKOS_DECOMPILER", "native")
    monkeypatch.setattr(native_re, "_AAA_TIER_MB", 0.0)
    monkeypatch.setattr(native_re, "_AAA_FULL_MAX_MB", 0.0)
    src = tmp_path / "v.c"
    src.write_text(_SRC)
    out = tmp_path / "v"
    subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-g", str(src), "-o",
                    str(out)], check=True, capture_output=True)
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=1, poll_interval=0.02))
    pool.start()
    try:
        target = ingest(store, case.id, out, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, target, force=True)
        assert pool.wait_idle(30)
        enqueue_disassemble(q, target, force=True)
        assert pool.wait_idle(90)
    finally:
        pool.stop(grace=3.0)
    names = {f.name for f in FunctionDAO(store.conn).list_by_target(target.id)}
    assert {"main", "bug"} <= names
    done = EventDAO(store.conn).payloads_of_type("re.done", case_id=case.id)
    assert done and done[-1]["analysis_tier"] == "aa+aac" and not done[-1]["partial"]
    assert done[-1]["degradations"] is None


def test_deadline_stops_batching_but_keeps_every_function(tmp_path, monkeypatch):
    """Under a stage deadline the batched structural pass stops while time is left for the lift
    and persist: the unreached functions keep their name + call edges (the call graph stays
    whole) and the cut is a reported, partial result -- not an exception that loses everything."""
    funcs = [{"offset": 0x1000 + 0x100 * k, "name": f"sym.f{k}", "size": 16,
              "callrefs": [{"to": 0x9000, "from": 0x1004 + 0x100 * k, "type": "CALL"}]}
             for k in range(3)]
    funcs.append({"offset": 0x9000, "name": "sym.imp.strcpy", "size": 6})
    scripts = []

    def fake_run(cli, binary, script, *, ctx=None, timeout, scratch=None):
        scripts.append(script)
        for part in script.split(";"):
            part = part.strip()
            if part.startswith("aflj > "):
                Path(part[7:]).write_text(json.dumps(funcs))
            elif part.startswith("ij > "):
                Path(part[5:]).write_text(json.dumps({"bin": {"arch": "x86", "bits": 64}}))

    lefts = iter([100.0, 90.0, 10.0, 10.0, 10.0, 10.0])
    monkeypatch.setattr(native_re, "_run", fake_run)
    monkeypatch.setattr(native_re, "locate_native", lambda *a, **k: Path("/usr/bin/rizin"))
    monkeypatch.setattr(native_re, "_deadline_left", lambda ctx: next(lefts, 10.0))
    monkeypatch.setattr(native_re, "_AAA_MAX", 0)
    monkeypatch.setattr(native_re, "_BATCH", 1)
    b = tmp_path / "b"
    b.write_bytes(b"\x7fELF" + b"\0" * 60)
    ctx = _Ctx()
    ctx.scratch = lambda: tmp_path / "scratch"
    ctx.check_cancel = lambda: None
    r = native_re.analyze(b, ctx=ctx, timeout=100)
    assert r["function_count"] == 4 and r["partial"] is True
    assert any("stopped ahead of the stage deadline" in d for d in r["degradations"])
    batches = [s for s in scripts if s.startswith("af @ ")]
    assert len(batches) == 1                       # one batch ran, then the reserve stopped it
    # the functions that call the sink were batched FIRST, and every function kept its call edge
    assert batches[0].startswith(f"af @ {0x1000}")
    assert sum(1 for f in r["functions"] if f["calls"]) == 3
