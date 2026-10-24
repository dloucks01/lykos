"""JE-24/19/20/21/22/27 — Job context handed to a stage.

Gives a stage: params, artifact I/O, event/log emission, a cooperative cancel/timeout
check, a scratch dir, and a managed-subprocess helper that kills the child's process
group on cancel or timeout (readies native tools in later phases).
"""
from __future__ import annotations

import atexit
import logging
import os
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from ..casestore import ContentStore
from ..db.dao import ArtifactDAO, EventDAO
from ..db.models import AnalysisRun

# Cap on per-stream captured child output. `communicate()` buffered the child's ENTIRE
# stdout/stderr, so a verbose or runaway tool could grow the worker's memory without bound
# (only the last 400 bytes are ever shown). Beyond this the reader keeps draining but discards,
# so the child never blocks on a full pipe.
_MAX_CAPTURE = 16 << 20  # 16 MiB per stream

# Live child process-group ids, killed on interpreter exit so a bare exit / KeyboardInterrupt
# does not orphan still-running tool groups (each child is its own session via
# start_new_session=True). A SIGKILL of lykos itself cannot run this -- nothing can.
_LIVE_PGIDS: set[int] = set()
_LIVE_LOCK = threading.Lock()


def _atexit_kill_children() -> None:
    with _LIVE_LOCK:
        pgids = list(_LIVE_PGIDS)
    for pgid in pgids:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            pass


atexit.register(_atexit_kill_children)

_log = logging.getLogger("lykos.jobs.context")

#: Attempts an event write gets against a transient 'database is locked' (see JobContext.emit).
_EMIT_RETRIES = 4

# Scratch targets are STAGED here and then EXECUTED, so the staging filesystem must allow exec. A
# hardened / air-gapped box frequently mounts /tmp (and $TMPDIR) `noexec`, where `chmod +x` succeeds
# but execve() returns EACCES -- which makes every staged native target "not executable" and
# silently kills the whole dynamic pipeline (no L1/L2/L3, only static findings). Probe the system
# tempdir once; if it is noexec, stage under a lykos-owned work dir on the case-store filesystem.
_SYS_TMP_EXECOK: Optional[bool] = None


def _is_exec_capable(d: Path) -> bool:
    """True if a file written under `d` and chmod +x can actually be execve()'d (i.e. `d` is not on
    a noexec mount). Best-effort: a probe directory is created, a 2-line /bin/sh no-op is run, and
    the directory removed. False on any error (treated as not exec-capable)."""
    try:
        d.mkdir(parents=True, exist_ok=True)
        probe = Path(tempfile.mkdtemp(dir=str(d), prefix=".xchk-"))
    except OSError:
        return False
    try:
        f = probe / "x"
        f.write_text("#!/bin/sh\nexit 0\n")
        f.chmod(0o755)
        try:
            return subprocess.run([str(f)], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=5).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
    finally:
        shutil.rmtree(probe, ignore_errors=True)


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
        # An event INSERT is an autocommit write: under a write storm it can still see 'database
        # is locked' after the connection's full busy_timeout, and that exception used to kill
        # the stage outright -- a campaign that had found a crash ended `error` on its progress
        # heartbeat. Ride out a few more lock waits (as the queue's own writers do) before letting
        # it surface; a non-lock error surfaces at once.
        for attempt in range(_EMIT_RETRIES):
            try:
                ev = EventDAO(self.conn).append(type, level, case_id=self.case_id,
                                                run_id=self.run_id, payload=payload)
                break
            except sqlite3.OperationalError as e:
                msg = str(e).lower()
                if ("lock" not in msg and "busy" not in msg) or attempt == _EMIT_RETRIES - 1:
                    raise
                time.sleep(0.05 * (attempt + 1))
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
        # A transient lock on this READ must not crash the stage polling it (every campaign loop
        # calls should_cancel() per batch): answer "not cancelled" this time and ask again on the
        # next poll. A cancel is still seen one poll later; the deadline check needs no database.
        try:
            r = self.conn.execute("SELECT cancel_requested FROM analysis_run WHERE id=?",
                                  (self.run_id,)).fetchone()
        except sqlite3.OperationalError:
            _log.warning("cancel poll for run %s failed; retrying on the next poll", self.run_id,
                         exc_info=True)
            return False
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
            self._scratch = Path(tempfile.mkdtemp(prefix=f"lykos-{self.run_id[:8]}-",
                                                  dir=self._scratch_base()))
        return self._scratch

    def _scratch_base(self) -> Optional[str]:
        """Base dir for the (executable) scratch staging area: the system tempdir normally, but a
        lykos-owned work dir on the case-store filesystem when the tempdir is mounted noexec -- the
        cause of "executables were not executable". None means "use the system tempdir". The noexec
        probe is cached per process; the fallback dir is chosen from this context's content root."""
        global _SYS_TMP_EXECOK
        if _SYS_TMP_EXECOK is None:
            _SYS_TMP_EXECOK = _is_exec_capable(Path(tempfile.gettempdir()))
        if _SYS_TMP_EXECOK:
            return None
        try:
            work = Path(self.content.root) / ".work"
            if _is_exec_capable(work):
                _log.warning("system tempdir (%s) is noexec; staging runnable targets under %s",
                             tempfile.gettempdir(), work)
                return str(work)
        except Exception:                               # noqa: BLE001 -- fall back to the tempdir
            pass
        _log.warning("system tempdir is noexec and no exec-capable fallback was found; staged "
                     "targets may fail to execute -- set TMPDIR to an exec-capable path")
        return None

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
        try:
            pgid = os.getpgid(proc.pid)
        except OSError:
            pgid = None
        if pgid is not None:
            with _LIVE_LOCK:
                _LIVE_PGIDS.add(pgid)
        # Drain both pipes concurrently into bounded buffers: reading the whole of stdout/stderr
        # into memory (as communicate did) lets a flooding child OOM the worker, and reading them
        # serially would deadlock on a full pipe.
        out_buf, err_buf = bytearray(), bytearray()
        t_out = threading.Thread(target=self._drain, args=(proc.stdout, out_buf), daemon=True)
        t_err = threading.Thread(target=self._drain, args=(proc.stderr, err_buf), daemon=True)
        t_out.start()
        t_err.start()
        try:
            while True:
                try:
                    proc.wait(timeout=poll)
                except subprocess.TimeoutExpired:
                    over_local = timeout is not None and (time.time() - start) > timeout
                    if over_local or self.should_cancel():
                        self._kill_group(proc)
                        reason = "timeout" if (over_local or self.timed_out()) else "cancelled"
                        self._emit_exec(cmd, start, rc=None, note=reason)
                        raise (StageTimeout if reason == "timeout" else StageCancelled)(
                            f"subprocess {cmd[0]} {reason}") from None
                    continue
                break  # child exited on its own
            t_out.join(timeout=5)
            t_err.join(timeout=5)
            out, err = bytes(out_buf), bytes(err_buf)
            self._emit_exec(cmd, start, rc=proc.returncode, out=out, err=err)
            return subprocess.CompletedProcess(cmd, proc.returncode, out, err)
        finally:
            # ANY exit path that leaves the child alive kills it: the deliberate timeout/cancel
            # raise has already done so, but an exception from the poll itself (a database error
            # in should_cancel, a KeyboardInterrupt) used to propagate with the tool still running
            # in its own session -- an orphan the worker no longer tracked.
            if proc.poll() is None:
                self._kill_group(proc)
            if pgid is not None:
                with _LIVE_LOCK:
                    _LIVE_PGIDS.discard(pgid)

    @staticmethod
    def _drain(stream: Any, sink: bytearray) -> None:
        """Read a child pipe to EOF, keeping at most _MAX_CAPTURE bytes and discarding the rest
        (still draining so the child never blocks on a full pipe)."""
        if stream is None:
            return
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                if len(sink) < _MAX_CAPTURE:
                    sink.extend(chunk[: _MAX_CAPTURE - len(sink)])
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def _emit_exec(self, cmd: Sequence[str], start: float, *, rc: int | None = None,
                   out: bytes = b"", err: bytes = b"", note: str | None = None) -> None:
        """Publish one 'job.exec' event: the tool command that just ran and a short tail of its
        output. Feeds the live console panel so an operator can see the actual commands and I/O go
        by. Best-effort -- a telemetry emit must never fail the subprocess it describes."""
        try:
            import os as _os

            def _short(b: bytes | str | None, n: int = 400) -> str | None:
                s = (b or b"")[-n:].decode("utf-8", "replace") if isinstance(b, (bytes, bytearray)) \
                    else str(b or "")[-n:]
                return s.strip() or None
            # A readable command line: the tool's basename, then args with temp/scratch paths
            # shortened to their basenames so a 40-char /var/tmp/rzscript-... reads as `rzscript-…rz`.
            argv = [str(a) for a in (cmd or [])]
            disp = [_os.path.basename(argv[0]) if argv else ""]
            for a in argv[1:]:
                disp.append(_os.path.basename(a) if (a.startswith("/") and _os.sep in a[1:]) else a)
            # Only a FAILED run's stderr is an error. rizin (and many analysers) write benign
            # analysis warnings to stderr on a clean rc==0 run; surfacing those in `err` made the
            # autopilot console render them as red "errors" -- the "Rizin errors in the console"
            # the operator saw. So carry stderr in `err` only when the process actually failed
            # (rc not in (0, None)); a clean run keeps its stderr tail in the non-error `warn`
            # field. A non-zero rc still ships its stderr in `err`, so real failures stay visible.
            failed = rc not in (0, None)
            err_tail = _short(err)
            self.emit("job.exec", "info", {
                "tool": _os.path.basename(argv[0]) if argv else "",
                "cmd": " ".join(disp)[:500],
                "rc": rc, "ms": int((time.time() - start) * 1000),
                "out": _short(out),
                "err": err_tail if failed else None,
                "warn": err_tail if (not failed and err_tail) else None,
                "note": note})
        except Exception:                                    # noqa: BLE001
            pass

    def record_exec(self, cmd: Sequence[str], *, start: float, rc: int | None = None,
                    out: bytes = b"", err: bytes = b"", note: str | None = None) -> None:
        """Publish a 'job.exec' console event for a tool a stage ran through its OWN subprocess
        (not run_subprocess) -- e.g. valgrind, which must feed the target's stdin and so cannot use
        the managed runner. `start` is time.time() captured just before the tool launched. This is
        how such a tool still shows up in the live tool-command console. Best-effort."""
        self._emit_exec(cmd, start, rc=rc, out=out, err=err, note=note)

    @staticmethod
    def _kill_group(proc: subprocess.Popen) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            time.sleep(0.2)
            if proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            try:
                proc.wait(timeout=2)   # reap the child so it does not linger as a zombie
            except (subprocess.TimeoutExpired, OSError):
                pass
