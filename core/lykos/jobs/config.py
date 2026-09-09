"""JE-30 — Job engine configuration with Kali-VM defaults (4+ cores, ~32 GB)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _default_workers() -> int:
    return max(1, (os.cpu_count() or 2) - 1)


def _default_caps() -> dict[str, int]:
    # per resource-class concurrency caps (sum bounded by the box)
    return {"quick": 8, "io": 4, "cpu": 2, "vm": 1}


@dataclass
class JobConfig:
    workers: int = field(default_factory=_default_workers)
    poll_interval: float = 0.1          # queue poll when idle (seconds)
    lease_seconds: int = 30             # job lease TTL
    heartbeat_interval: float = 10.0    # worker heartbeat cadence
    default_timeout: float | None = None  # per-stage wall-clock (None = unbounded)
    class_caps: dict[str, int] = field(default_factory=_default_caps)
    mem_min_mb_for_heavy: int = 1024    # admission guard for cpu/vm classes
    heavy_classes: tuple[str, ...] = ("cpu", "vm")
    shutdown_grace: float = 10.0        # graceful-stop grace period
