"""Job engine (Phase 0 P0.3): queue, state machine, stage registry, context, worker pool.

Deterministic, air-gapped, single Kali VM. SQLite-backed queue (no external broker).
See tasks/phase-0-P0.3-job-engine-tickets.md (JE-00..JE-30).
"""
from .config import JobConfig
from .context import JobContext, StageCancelled, StageTimeout
from .queue import JobQueue
from .registry import StageDef, get_stage, list_stages, register_stage
from .worker import WorkerPool

__all__ = [
    "JobConfig", "JobContext", "StageCancelled", "StageTimeout", "JobQueue",
    "StageDef", "register_stage", "get_stage", "list_stages", "WorkerPool",
]
