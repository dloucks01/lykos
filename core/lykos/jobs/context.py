"""JE-24/19/20/21/22/27 — Job context handed to a stage.

Gives a stage: params, artifact I/O, event/log emission, a cooperative cancel/timeout
check, a scratch dir, and a managed-subprocess helper that kills the child's process
group on cancel or timeout (readies native tools in later phases).
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from ..casestore import ContentStore
from ..db.dao import ArtifactDAO, EventDAO
from ..db.models import AnalysisRun


class StageCancelled(Exception):
    """Raised by check_cancel() when cancellation was requested."""


class StageTimeout(Exception):
    """Raised by check_cancel() when the wall-clock deadline passed."""


@dataclass
class JobContext:
    conn: Any                       # this worker's own sqlite connection
    content: ContentStore
    run: AnalysisRun
    deadline: Optional[float] = None       # epoch seconds; None = unbounded
    on_event: Optional[Callable[[dict], None]] = None
    _scratch: Optional[Path] = field(default=None, init=False)

    # -- convenience accessors --
    @property
    def run_id(self) -> str: return self.run.id
    @property
    def case_id(self) -> str: return self.run.case_id
    @property
    def target_id(self) -> Optional[str]: return self.run.target_id
    @property
    def params(self) -> dict: return self.run.params or {}
    @property
    def tool_version(self) -> Optional[str]: return self.run.tool_version

    # -- events (JE-22/27) --
    def emit(self, type: str, level: str = "info", payload: Optional[dict] = None) -> None:
        ev = EventDAO(self.conn).append(type, level, case_id=self.case_id,
                                        run_id=self.run_id, payload=payload)
        if self.on_event:
            self.on_event({"id": ev.id, "type": ev.type, "level": ev.level,
                           "case_id": ev.case_id, "run_id": ev.run_id, "ts": ev.ts,
                           "payload": ev.payload})

    def log(self, msg: str, level: str = "info") -> None:
        self.emit("job.log", level, {"msg": msg})

    def progress(self, pct: Optional[float] = None, msg: Optional[str] = None) -> None:
        self.emit("job.progress", "info", {"pct": pct, "msg": msg})

    # -- cancellation / timeout (JE-19/21) --
    def _db_cancel(self) -> bool:
        r = self.conn.execute("SELECT cancel_requested FROM analysis_run WHERE id=?",
                              (self.run_id,)).fetchone()
        return bool(r["cancel_requested"]) if r else False

    def timed_out(self) -> bool:
        return self.deadline is not None and time.time() > self.deadline

    def should_cancel(self) -> bool:
        return self.timed_out() or self._db_cancel()

    def check_cancel(self) -> None:
        if self.timed_out():
            raise StageTimeout(f"run {self.run_id} exceeded deadline")
        if self._db_cancel():
            raise StageCancelled(f"run {self.run_id} cancelled")

    # -- artifacts --
    def put_artifact(self, kind: str, *, data: Optional[bytes] = None,
                     src: Optional[str | Path] = None,
                     meta: Optional[dict] = None) -> str:
        if (data is None) == (src is None):
            raise ValueError("provide exactly one of data= or src=")
        if data is not None:
            sha, rel, size = self.content.put_bytes(data)
        else:
            sha, rel, size = self.content.put_file(src)  # type: ignore[arg-type]
        ArtifactDAO(self.conn).register(sha, self.case_id, kind, rel, size=size, meta=meta)
        return sha

    # -- scratch dir --
    def scratch(self) -> Path:
        if self._scratch is None:
            self._scratch = Path(tempfile.mkdtemp(prefix=f"lykos-{self.run_id[:8]}-"))
        return self._scratch

    def cleanup(self) -> None:
        if self._scratch and self._scratch.exists():
            shutil.rmtree(self._scratch, ignore_errors=True)
        self._scratch = None

    # -- managed subprocess (JE-20) --
    def run_subprocess(self, cmd: list[str], timeout: Optional[float] = None,
                       poll: float = 0.1,
                       **popen_kw: Any) -> subprocess.CompletedProcess:
        """Run a child in its own process group; kill the group on cancel/timeout/deadline."""
        start = time.time()
        # A tool subprocess must never inherit the server's stdin: a worker's stdin can be an open
        # pipe (not /dev/null), and tools like rizin then BLOCK reading it as a command stream --
        # the stage hangs at "running" with no CPU. Default to /dev/null; a caller that genuinely
        # feeds stdin can still override via popen_kw.
        popen_kw.setdefault("stdin", subprocess.DEVNULL)
        proc = subprocess.Popen(cmd, start_new_session=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, **popen_kw)
        while True:
            try:
                out, err = proc.communicate(timeout=poll)
                self._emit_exec(cmd, start, rc=proc.returncode, out=out, err=err)
                return subprocess.CompletedProcess(cmd, proc.returncode, out, err)
            except subprocess.TimeoutExpired:
                over_local = timeout is not None and (time.time() - start) > timeout
                if over_local or self.should_cancel():
                    self._kill_group(proc)
                    reason = "timeout" if (over_local or self.timed_out()) else "cancelled"
                    self._emit_exec(cmd, start, rc=None, note=reason)
                    raise (StageTimeout if reason == "timeout" else StageCancelled)(
                        f"subprocess {cmd[0]} {reason}")

    def _emit_exec(self, cmd, start, *, rc=None, out=b"", err=b"", note=None) -> None:
        """Publish one 'job.exec' event: the tool command that just ran and a short tail of its
        output. Feeds the live console panel so an operator can see the actual commands and I/O go
        by. Best-effort -- a telemetry emit must never fail the subprocess it describes."""
        try:
            import os as _os

            def _short(b, n=400):
                s = (b or b"")[-n:].decode("utf-8", "replace") if isinstance(b, (bytes, bytearray)) \
                    else str(b or "")[-n:]
                return s.strip() or None
            # A readable command line: the tool's basename, then args with temp/scratch paths
            # shortened to their basenames so a 40-char /var/tmp/rzscript-... reads as `rzscript-…rz`.
            argv = [str(a) for a in (cmd or [])]
            disp = [_os.path.basename(argv[0]) if argv else ""]
            for a in argv[1:]:
                disp.append(_os.path.basename(a) if (a.startswith("/") and _os.sep in a[1:]) else a)
            self.emit("job.exec", "info", {
                "tool": _os.path.basename(argv[0]) if argv else "",
                "cmd": " ".join(disp)[:500],
                "rc": rc, "ms": int((time.time() - start) * 1000),
                "out": _short(out), "err": _short(err), "note": note})
        except Exception:                                    # noqa: BLE001
            pass

    @staticmethod
    def _kill_group(proc: subprocess.Popen) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            time.sleep(0.2)
            if proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
