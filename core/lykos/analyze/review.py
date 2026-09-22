"""False-positive review: replay a recorded crashing input several times and judge whether it is
a TRUE, deterministic crash.

A demonstrated finding is only trustworthy if its own reproducer fires every time; a crash that
appears once in five runs is flaky evidence, not a proof. This replays the recorded input in the
sandbox N times and reports how many crashed and with which signal, persisting the verdict as a
`replay-verdict` artifact keyed to the input -- so the workbench can badge a finding verified or
flaky, and the review survives into the report and a reopened case.

Shared by the `/targets/{id}/replay` endpoint and the server-side Autopilot, so both paths apply
the same review (the background run had none, and its findings shipped unreviewed).
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from ..db.dao import DynResultDAO
from .fuzz.runner import run_input


def replay_verdict(store, target, input_sha: str, *, times: int = 5,
                   timeout: float = 8.0, persist: bool = True) -> Optional[dict]:
    """Replay `input_sha` against `target` `times` times (bounded 1..10) and return the verdict
    {runs, crashed, signal, deterministic, input_sha, input_mode}, or None if the input is
    unknown. When `persist`, also writes it as a `replay-verdict` artifact on the case.

    Delivery (stdin/arg/file) and the argv the crash was found under come from the crash row, so a
    target that faults behind a flag is replayed under that flag; run_input() handles placement
    and NUL-safe argv."""
    times = max(1, min(int(times), 10))
    try:
        data = store.content.get_bytes(input_sha)
    except Exception:
        return None
    dr = next((d for d in DynResultDAO(store.conn).list_by_target(target.id)
               if d.input_sha == input_sha), None)
    mode = (dr.input_mode if dr else None) or "stdin"
    argv = list(dr.argv) if (dr and dr.argv) else []
    base_argv = argv[:-1] if (mode in ("arg", "file") and argv) else argv
    blob = store.content.path(target.sha256).read_bytes()

    d = Path(tempfile.mkdtemp(prefix="lykos-replay-"))
    try:
        exe = d / "target.bin"
        exe.write_bytes(blob)
        os.chmod(exe, 0o755)
        workfile = d / "in.bin"
        crashed = 0
        signals: dict = {}
        for _ in range(times):
            try:
                _, res = run_input(exe, mode, workfile, timeout, target.arch, data,
                                   endianness=target.endianness, bits=target.bits,
                                   base_argv=base_argv)
            except Exception:
                continue                          # a delivery that cannot be built is not a crash
            if res.crashed:
                crashed += 1
                signals[res.signal_name] = signals.get(res.signal_name, 0) + 1
    finally:
        shutil.rmtree(d, ignore_errors=True)

    sig = max(signals, key=signals.get) if signals else None
    verdict = {"runs": times, "crashed": crashed, "signal": sig,
               "deterministic": crashed == times, "input_sha": input_sha, "input_mode": mode}
    if persist:
        try:
            store.put_artifact(target.case_id, "replay-verdict",
                               data=json.dumps(verdict).encode(),
                               meta={"input_sha": input_sha, "target_id": target.id, **verdict})
        except Exception:
            pass
    return verdict
