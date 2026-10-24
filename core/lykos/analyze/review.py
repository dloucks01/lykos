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
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from .. import observe
from ..db.dao import DynResultDAO
from .fuzz.runner import run_input

_log = logging.getLogger(__name__)


def _flag_prefix(argv: list, mode: str, data: bytes) -> list:
    """The recorded argv minus the input CARRIER, when the row recorded one.

    Writers disagree: `dynamic_run` and the fuzz campaign record only the flag PREFIX (the carrier
    is a scratch path that is gone by replay time -- see `poc.capture.how_to_feed`), while the
    synthesizer and the MSan/LSan detonations record the whole invocation. Dropping the last
    element unconditionally therefore cut a real flag off every prefix row (`tool parse` replayed
    as `tool <file>`, which never reaches the parser) and the crash read as non-deterministic.
    Strip it only when it IS the carrier: the input itself for `arg`, a scratch path for `file`."""
    argv = [str(a) for a in (argv or [])]
    if not argv or mode not in ("arg", "file"):
        return argv
    last = argv[-1]
    if last == "@@":
        return argv
    if mode == "arg":
        carried = data.split(b"\x00", 1)[0].decode("latin-1")
        return argv[:-1] if last in (carried, data.decode("latin-1")) else argv
    p = Path(last)
    if p.is_absolute() and (not p.exists() or str(p).startswith(tempfile.gettempdir())):
        return argv[:-1]
    return argv


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
        _log.debug("replay input load failed for %s", input_sha, exc_info=True)
        return None
    dr = next((d for d in DynResultDAO(store.conn).list_by_target(target.id)
               if d.input_sha == input_sha), None)
    mode = (dr.input_mode if dr else None) or "stdin"
    argv = list(dr.argv) if (dr and dr.argv) else []
    base_argv = _flag_prefix(argv, mode, data)

    d = Path(tempfile.mkdtemp(prefix="lykos-replay-"))
    try:
        # Staged WITH its companion deps and under the name a multi-call image dispatches on,
        # like every other stage that executes the target. A bare `target.bin` write made a
        # bundle with a relative loader (or busybox) fail to start on every replay, which this
        # verdict then reported as "not deterministic" for a crash that reproduces.
        name = "target.bin"
        try:
            from .invocation import exec_name_for
            name = exec_name_for(store.content.path(target.sha256).read_bytes()) or name
        except Exception:                         # noqa: BLE001 -- the default name still runs
            name = "target.bin"
        exe = store.content.stage_target(target, d, name)
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
                _log.debug("replay run_input failed for %s", input_sha, exc_info=True)
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
            observe.absorbed(_log, "continuing")
    return verdict
