"""The false-positive review replay (analyze/review.replay_verdict) must deliver a PoC input the
way its crash was found. A PoC's (often minimized) input has no crash row of its own; the replay
defaulted to stdin and ran without the guard-page oracle, so the workbench showed proven gif2rgb
findings as "did not reproduce 0/5". Found while porting the replay button to the new GUI."""
from __future__ import annotations

from lykos.analyze import review
from lykos.analyze.ingest import ingest
from lykos.db.dao import DynResultDAO


def test_poc_input_without_a_row_replays_on_the_targets_crash_channel(store, case, sample_elf,
                                                                       monkeypatch):
    t = ingest(store, case.id, sample_elf)
    crash_sha, _, _ = store.content.put_bytes(b"crashing-input")
    poc_sha, _, _ = store.content.put_bytes(b"minimized")          # no dyn_result row
    dd = DynResultDAO(store.conn)
    dd.insert(t.id, case.id, input_sha=crash_sha, input_mode="file", argv=["-v", "@@"],
              crashed=True, signal_name="SIGSEGV", isolation="bwrap+netns+batch+guardpage")
    dd.insert(t.id, case.id, input_sha="0" * 64, input_mode="stdin", crashed=False,
              isolation="bwrap+netns")
    seen = []

    def fake_run_input(exe, mode, workfile, timeout, arch, data, **kw):
        seen.append((mode, data, kw.get("guard_page"), list(kw.get("base_argv") or [])))
        from types import SimpleNamespace
        return None, SimpleNamespace(crashed=True, signal_name="SIGSEGV")
    monkeypatch.setattr(review, "run_input", fake_run_input)
    v = review.replay_verdict(store, t, poc_sha, times=2, persist=False)
    assert v["input_mode"] == "file" and v["crashed"] == 2
    assert all(m == "file" and g is True and d == b"minimized" for m, d, g, _a in seen), seen
    # an input WITH its own row keeps that row's delivery, and its own oracle
    seen.clear()
    review.replay_verdict(store, t, crash_sha, times=1, persist=False)
    assert seen[0][0] == "file" and seen[0][2] is True
