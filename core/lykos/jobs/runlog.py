"""The live run console: everything an analysis actually does, as it does it.

One JSON-lines file per case (``<case>/console/<case_id>.jsonl``) that every stage of every run
appends to: stage starts and ends, every TARGET execution (the sandbox runs and the batch runner's
executions -- the bulk of what an autopilot does), every tool command, progress notes, and one
live telemetry record per fuzzing campaign. The GUI tails it by byte offset
(``GET /cases/{id}/console?after=N``): a terminal-like console, and one window per fuzzing
technique.

Before this the console showed ``job.exec`` events only -- tool subprocesses like rizin. A whole
7.5-minute jhead run produced 13 console lines while the target was executed thousands of times.

Volume is bounded by design, never by dropping what matters:
  * a crash, a timeout, a sanitizer report and the first ``_FULL_PER_STAGE`` executions of a
    stage are always written in full;
  * the rest are folded into one summary line per ``_WINDOW_S`` per stage ("x 50 executions,
    exit 0 x48 exit 1 x2, avg 9 ms");
  * fuzz telemetry is throttled to one record per campaign per ``_FUZZ_EVERY_S``;
  * past ``_CAP_BYTES`` per case only stage / crash / fuzz-final records are kept, and the log
    says so once.

The sink is ambient (a ContextVar the job worker sets around each stage, like
``db.provenance``), so ``sandbox.run`` and the fuzz engines record without an argument threaded
through ~100 call sites. Outside a stage (tests, ingest) there is no sink and every call is a
no-op. Every function here is best-effort: telemetry never fails the work it describes.
"""
from __future__ import annotations

import contextvars
import json
import os
import threading
import time
from pathlib import Path
from typing import Optional

_FULL_PER_STAGE = 25          # executions per stage written in full before sampling
_WINDOW_S = 1.0               # one summary line per stage per window once sampling
_FUZZ_EVERY_S = 1.0           # fuzz telemetry: at most one record per campaign per second
_CAP_BYTES = 256 << 20        # per case; past it only stage/crash/fuzz-final records are kept
_TAIL = 600                   # characters of stdout/stderr kept per record

_sink: contextvars.ContextVar[Optional["RunLog"]] = contextvars.ContextVar(
    "lykos_runlog", default=None)
_locks: dict = {}
_locks_guard = threading.Lock()


def _lock_for(path: str) -> threading.Lock:
    with _locks_guard:
        lk = _locks.get(path)
        if lk is None:
            lk = _locks[path] = threading.Lock()
        return lk


def console_path(root, case_id: str) -> Path:
    """Where a case's console log lives (``root`` = the case store's directory)."""
    return Path(root) / "console" / f"{case_id}.jsonl"


def _tail(b, n: int = _TAIL) -> Optional[str]:
    if b is None:
        return None
    s = b[-n:].decode("utf-8", "replace") if isinstance(b, (bytes, bytearray)) else str(b)[-n:]
    s = s.strip()
    return s or None


def _disp_argv(argv) -> str:
    """A readable command line: scratch paths shortened to their basenames."""
    out = []
    for a in argv or ():
        a = str(a)
        out.append(os.path.basename(a) if (a.startswith("/") and os.sep in a[1:]) else a)
    return " ".join(out)[:400]


class RunLog:
    """The console sink for ONE stage run (shared file, per-stage sampling state)."""

    def __init__(self, root, case_id: str, *, run_id: str = "", stage: str = "",
                 target_id: Optional[str] = None):
        self.path = console_path(root, case_id)
        self.run_id, self.stage, self.target_id = run_id, stage, target_id
        self._lock = _lock_for(str(self.path))
        self._full = 0                    # executions written in full this stage
        self._win: Optional[dict] = None  # the open sampling window
        self._fuzz_last: dict = {}        # engine -> last telemetry write time
        self._capped = False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    # -------------------------------------------------------------------- writing
    def write(self, kind: str, essential: bool = False, **fields) -> None:
        rec = {"t": round(time.time(), 3), "k": kind, "stage": self.stage,
               "run": self.run_id[:12] if self.run_id else None}
        if self.target_id:
            rec["target"] = self.target_id
        rec.update({k: v for k, v in fields.items() if v is not None})
        try:
            line = json.dumps(rec, separators=(",", ":"), default=str) + "\n"
            with self._lock:
                try:
                    size = self.path.stat().st_size
                except OSError:
                    size = 0
                if size > _CAP_BYTES and not essential:
                    if not self._capped:
                        self._capped = True
                        line = json.dumps({"t": rec["t"], "k": "note", "stage": self.stage,
                                           "text": "console log size cap reached: routine lines "
                                                   "are no longer kept for this case"}) + "\n"
                    else:
                        return
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line)
        except Exception:                                    # noqa: BLE001 -- telemetry only
            pass

    # -------------------------------------------------------------------- record kinds
    def stage_event(self, state: str, **fields) -> None:
        if state != "start":
            self.flush()
        self.write("stage", True, state=state, **fields)

    def note(self, text: str) -> None:
        if text:
            self.write("note", text=str(text)[:500])

    def tool(self, argv, *, rc=None, ms=None, out=None, err=None) -> None:
        self.write("tool", cmd=_disp_argv(argv), rc=rc, ms=ms, out=_tail(out), err=_tail(err))

    def target_run(self, argv, *, mode: Optional[str] = None, in_len: Optional[int] = None,
                   rc=None, signal: Optional[str] = None, crashed: bool = False,
                   timed_out: bool = False, ms=None, isolation: Optional[str] = None,
                   out=None, err=None, fault_pc=None, fault_addr=None) -> None:
        """One execution of the TARGET. Crashes/timeouts and the first executions of a stage are
        written in full; the rest fold into a once-a-second summary line."""
        interesting = crashed or timed_out
        if interesting or self._full < _FULL_PER_STAGE:
            self._full += 1
            self.write("crash" if crashed else "run", interesting,
                       cmd=_disp_argv(argv), mode=mode, bytes=in_len, rc=rc, sig=signal,
                       timeout=True if timed_out else None, ms=ms, iso=isolation,
                       pc=(hex(fault_pc) if isinstance(fault_pc, int) else fault_pc),
                       addr=(hex(fault_addr) if isinstance(fault_addr, int) else fault_addr),
                       out=_tail(out, 240), err=_tail(err, 240))
            return
        now = time.time()
        w = self._win
        if w is None:
            w = self._win = {"t0": now, "n": 0, "rc": {}, "ms": 0, "cmd": None}
        w["n"] += 1
        key = signal or str(rc)
        w["rc"][key] = w["rc"].get(key, 0) + 1
        w["ms"] += int(ms or 0)
        w["cmd"] = _disp_argv(argv)
        if now - w["t0"] >= _WINDOW_S:
            self.flush()

    def flush(self) -> None:
        """Write the open sampling window's summary line."""
        w, self._win = self._win, None
        if not w or not w["n"]:
            return
        self.write("runs", n=w["n"], exits=w["rc"], avg_ms=round(w["ms"] / w["n"], 1),
                   last=w["cmd"])

    def fuzz(self, engine: str, *, final: bool = False, **stats) -> None:
        """Live telemetry for one fuzzing campaign: execs, eps, cov, cov_label, crashes, hangs,
        corpus, status, out (the engine's own recent output lines)."""
        now = time.time()
        if not final and now - self._fuzz_last.get(engine, 0.0) < _FUZZ_EVERY_S:
            return
        self._fuzz_last[engine] = now
        out = stats.pop("out", None)
        if out:
            out = [str(x)[:200] for x in list(out)[-8:]]
        self.write("fuzz", final, engine=engine, final=True if final else None, out=out, **stats)


# ------------------------------------------------------------------------ ambient API
def current() -> Optional[RunLog]:
    return _sink.get()


def bind(log: Optional[RunLog]):
    return _sink.set(log)


def unbind(token) -> None:
    try:
        _sink.reset(token)
    except (ValueError, LookupError):
        pass


def target_run(*a, **k) -> None:
    s = _sink.get()
    if s is not None:
        s.target_run(*a, **k)


def tool(*a, **k) -> None:
    s = _sink.get()
    if s is not None:
        s.tool(*a, **k)


def note(text: str) -> None:
    s = _sink.get()
    if s is not None:
        s.note(text)


def fuzz(engine: str, **k) -> None:
    s = _sink.get()
    if s is not None:
        s.fuzz(engine, **k)


def read(root, case_id: str, after: int = 0, limit: int = 2000) -> dict:
    """{"lines": [...], "next": byte_offset, "size": file_size} from ``after`` on, at most
    ``limit`` records (the GUI's poll). A partial trailing line is left for the next poll."""
    p = console_path(root, case_id)
    try:
        size = p.stat().st_size
    except OSError:
        return {"lines": [], "next": 0, "size": 0}
    after = max(0, min(int(after or 0), size))
    lines, nxt = [], after
    with open(p, "rb") as fh:
        fh.seek(after)
        while len(lines) < limit:
            raw = fh.readline()
            if not raw or not raw.endswith(b"\n"):
                break
            nxt += len(raw)
            try:
                lines.append(json.loads(raw))
            except ValueError:
                continue
    return {"lines": lines, "next": nxt, "size": size}
