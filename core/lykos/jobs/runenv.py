"""Per-RUN environment settings for the stages (target libraries, deep-seed), not process-wide.

`LYKOS_QEMU_SYSROOT` / `LYKOS_BUFFER_SEED` used to be written into `os.environ` for the length of
an autopilot run. The server runs every case's stages in one process, so two cases running at
once shared the last writer's value -- one case's target libraries became the other's
QEMU_LD_PREFIX. Now:

* the autopilot registers its settings under its CASE (`set_case` / `clear_case`);
* a single-stage run carries `sysroot_sha` in its params (a hash, not a path) and the worker
  resolves it;
* the worker binds the merged settings for each job it executes (`bind` / `unbind`, a
  ContextVar, so concurrent workers never see each other's);
* the readers ask `get(name)`; with nothing bound they fall back to the process environment (the
  CLI / server operator's own setting).

A thread a stage spawns does not inherit the ContextVar. When exactly one case has settings
registered, `get` uses them there too; with several it cannot tell and uses the process
environment rather than guess another case's.
"""
from __future__ import annotations

import os
import threading
from contextvars import ContextVar
from typing import Optional

SYSROOT = "LYKOS_QEMU_SYSROOT"
BUFFER_SEED = "LYKOS_BUFFER_SEED"

_lock = threading.Lock()
_BY_CASE: dict = {}
_cur: ContextVar = ContextVar("lykos_runenv", default=None)


def set_case(case_id: str, env: dict) -> None:
    with _lock:
        _BY_CASE[case_id] = {k: str(v) for k, v in (env or {}).items() if v is not None}


def clear_case(case_id: str) -> None:
    with _lock:
        _BY_CASE.pop(case_id, None)


def for_case(case_id: Optional[str]) -> dict:
    with _lock:
        return dict(_BY_CASE.get(case_id) or {})


def bind(env: Optional[dict]):
    return _cur.set(dict(env) if env else None)


def unbind(token) -> None:
    try:
        _cur.reset(token)
    except (ValueError, LookupError):
        pass


def get(name: str, default=None):
    cur = _cur.get()
    if cur is None:
        with _lock:
            only = list(_BY_CASE.values())
        cur = only[0] if len(only) == 1 else None
    if cur and name in cur:
        return cur[name]
    return os.environ.get(name, default)
