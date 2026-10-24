"""Logging setup, and a counter for errors the pipeline deliberately absorbs.

A LEAF module (no lykos imports), because every layer swallows something.

Two problems this exists for, both measured.

**The log went nowhere.** Nothing in the tree ever configured logging, so the root logger sat at
its default WARNING with no handlers. Every `_log.debug(..., exc_info=True)` in the codebase --
58 of them, written precisely so a swallowed error would leave evidence -- was discarded before
it reached anything, and a `_log.warning` escaped only through `logging.lastResort`, with no
timestamp, module or line. The evidence channel was never connected.

**Most handlers did not even try.** Of 456 broad `except` handlers in core, 187 were silent AND
carried no comment saying why silence was correct. One of them hid the bug that made L3
unreachable: `_l2_offset` wrapped its whole body in `except Exception: pass`, so when it started
returning None for every target, nothing anywhere said so.

So `absorbed()` does two things at once. It logs with a traceback, for whoever turns the log on
-- and it COUNTS, because nobody reads a debug log. The count goes in the run scorecard, which
turns "something degraded quietly" from invisible into a number an operator can see without
knowing this file exists. A run that absorbs nothing says so; a run that absorbs forty says
that too, and names the sites.
"""
from __future__ import annotations

import collections
import logging
import os
import sys
import threading

#: Env var selecting the level: LYKOS_LOG=debug|info|warning|error, or a number.
LEVEL_VAR = "LYKOS_LOG"
#: Env var adding a file sink alongside stderr. An offline engagement wants the log on disk.
FILE_VAR = "LYKOS_LOG_FILE"

#: module:operation -> how many times it was absorbed. Process-wide and thread-safe: the worker
#: pool runs stages concurrently, and a Counter update is not atomic under the GIL for `+=`.
_counts: collections.Counter = collections.Counter()
_lock = threading.Lock()
_configured = False

# Module, line and function come from the LogRecord, so a handler's own message only has to name
# the OPERATION. That is what keeps 187 of these affordable to write and still useful to read.
_FORMAT = "%(asctime)s %(levelname)-7s %(name)s:%(lineno)d %(funcName)s() %(message)s"


def configure(level: str | int | None = None, *, stream=None, force: bool = False) -> None:
    """Attach a stderr handler (and optionally a file one) to the `lykos` logger tree.

    Idempotent, and scoped to the `lykos` logger rather than the root: this is a library as well
    as an application, and configuring the root would hijack logging for anything embedding it.
    Called from the CLI and the API server; a caller that wants no logging simply never calls it,
    and every `_log` call then costs an `isEnabledFor` check.
    """
    global _configured
    if _configured and not force:
        return
    if level is None:
        level = os.environ.get(LEVEL_VAR, "warning")
    if isinstance(level, str) and level.strip().isdigit():
        level = int(level.strip())                       # LYKOS_LOG=10, as documented
    if isinstance(level, str):
        level = logging.getLevelName(level.strip().upper())
        if not isinstance(level, int):                   # getLevelName returns a str on a miss
            level = logging.WARNING
    log = logging.getLogger("lykos")
    for h in list(log.handlers):
        log.removeHandler(h)
    fmt = logging.Formatter(_FORMAT)
    sh = logging.StreamHandler(stream or sys.stderr)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    path = os.environ.get(FILE_VAR)
    if path:
        try:
            fh = logging.FileHandler(path)
            fh.setFormatter(fmt)
            log.addHandler(fh)
        except OSError:
            log.warning("cannot open %s=%s for writing; logging to stderr only", FILE_VAR, path)
    log.setLevel(level)
    # Propagate only when something upstream is actually listening. With a bare root logger --
    # the normal case for the CLI -- `logging.lastResort` would print a second, unformatted copy
    # of every warning, so propagation is off. But a host that embeds this (or pytest's caplog,
    # which attaches to the ROOT and depends on propagation) does have handlers, and silently
    # cutting those off is how a library makes itself undebuggable inside someone else's app.
    log.propagate = bool(logging.getLogger().handlers)
    _configured = True


def absorbed(log: logging.Logger, what: str = "", **detail: object) -> None:
    """Record that a best-effort step failed and the failure was deliberately absorbed.

    The SITE is derived from the caller's frame, not from `what`: a hand-written key would have
    to be unique across 187 call sites to be useful as a counter, which is a promise nobody can
    keep. `module.function:line` is unique by construction and needs no maintenance.

    `what` is therefore a short hint about the FALLBACK -- what the handler does instead of
    failing ("skipping this candidate", "answering None"). The exception is in the traceback and
    the location is in the key, so the hint is the only thing neither of those carries.

    Call this from inside the `except` block, so `exc_info` picks up the live exception.
    """
    try:
        frame = sys._getframe(1)
        site = f"{frame.f_globals.get('__name__', log.name)}.{frame.f_code.co_name}:{frame.f_lineno}"
    except Exception:                                    # noqa: BLE001
        site = log.name                                  # no frame introspection: still count it
    key = f"{site} ({what})" if what else site
    with _lock:
        _counts[key] += 1
    if log.isEnabledFor(logging.DEBUG):
        # stacklevel=2 so the record's module/line/function name the HANDLER that absorbed the
        # error, not this function. Without it every one of these reports `observe.py:absorbed()`
        # and the location -- the only reason a short message is enough -- is lost.
        log.debug("absorbed: %s%s", what,
                  ("".join(f" {k}={v!r}" for k, v in detail.items()) if detail else ""),
                  exc_info=True, stacklevel=2)


def absorbed_remote(driver: str, entries: object) -> int:
    """Fold a subprocess driver's absorbed list into this process's counter.

    The tracers and emulator drivers run as standalone scripts under a different interpreter --
    two of them under the vendored angr and unicorn venvs -- so they cannot import this module.
    Each keeps its own `_ABSORBED` list and ships it in the JSON result it already hands back;
    the parent calls this when it parses that result. Without it, the silent step most likely to
    turn a real crash into "no crash observed" is the one step the counter cannot see.

    Returns how many entries were folded in. Tolerant of a malformed list, because the thing on
    the other end is a subprocess that may have been killed mid-write.
    """
    if not isinstance(entries, list):
        return 0
    n = 0
    with _lock:
        for e in entries:
            if not isinstance(e, dict):
                continue
            what = str(e.get("what") or "absorbed")[:80]
            _counts[f"{driver} (remote: {what})"] += 1
            n += 1
    if n and (log := logging.getLogger(driver)).isEnabledFor(logging.DEBUG):
        for e in entries:
            if isinstance(e, dict):
                log.debug("absorbed in the driver: %s -- %s", e.get("what"), e.get("exc"))
    return n


def absorbed_counts() -> dict[str, int]:
    """A snapshot of every absorbed site and its count, worst first."""
    with _lock:
        return dict(_counts.most_common())


def absorbed_total() -> int:
    with _lock:
        return sum(_counts.values())


def absorbed_since(baseline: dict[str, int]) -> dict[str, int]:
    """What has been absorbed since `baseline` was taken.

    The counter is process-wide, so a per-run number has to be a difference. The autopilot
    snapshots before it starts and diffs at the end, which is what lets the scorecard say
    "this run absorbed N" rather than "this process has absorbed N since it booted".
    """
    now = absorbed_counts()
    out = {}
    for key, n in now.items():
        delta = n - int(baseline.get(key, 0))
        if delta > 0:
            out[key] = delta
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def reset_absorbed() -> None:
    """Clear the counter. For tests, which must not see another test's absorptions."""
    with _lock:
        _counts.clear()
