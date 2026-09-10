"""JE-23 — Stage registry.

The core has no hardcoded list of stages; capabilities register themselves (wires to the
plugin API, P0.9). A stage is a callable `fn(ctx) -> Optional[dict]`; the optional dict may
carry {"output_shas": [...], "output_kind": str, "metrics": {...}} which the worker links.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# fn(ctx: JobContext) -> Optional[dict]
StageFn = Callable[[Any], Optional[dict]]
# on_cache_hit(store, target_id: str, run_id: str) -> None
CacheHitFn = Callable[[Any, str, str], None]


@dataclass(frozen=True)
class StageDef:
    name: str
    fn: StageFn
    resource_class: str = "quick"
    default_params: dict = field(default_factory=dict)
    tool: Optional[str] = None
    tool_version: Optional[str] = None
    timeout: Optional[float] = None      # per-stage wall-clock override
    on_cache_hit: Optional[CacheHitFn] = None   # re-project per-target DB rows on a cache hit


_STAGES: dict[str, StageDef] = {}


def register_stage(name: str, fn: StageFn, *, resource_class: str = "quick",
                   default_params: Optional[dict] = None, tool: Optional[str] = None,
                   tool_version: Optional[str] = None,
                   timeout: Optional[float] = None,
                   on_cache_hit: Optional[CacheHitFn] = None) -> StageDef:
    sd = StageDef(name=name, fn=fn, resource_class=resource_class,
                  default_params=default_params or {}, tool=tool,
                  tool_version=tool_version, timeout=timeout, on_cache_hit=on_cache_hit)
    _STAGES[name] = sd
    return sd


def cached_output_json(store, run_id: str):
    """The parsed JSON of a run's first 'output' artifact, or None. Shared by cache-hit
    reprojection hooks, which rebuild per-target DB rows from a cloned output artifact."""
    for link in store.run_artifacts.list_by_run(run_id):
        if link.role == "output":
            try:
                return json.loads(store.content.get_bytes(link.artifact_sha256))
            except Exception:
                continue
    return None


def reproject_cache_hit(store, stage: str, target_id: str, run_id: str) -> bool:
    """Re-apply a cached stage's per-target DB denormalization onto a (possibly new) target row.

    A content-addressed cache hit clones the prior run's output artifacts to the new run but
    never re-runs the stage body -- so DB rows the body writes keyed by target_id (triage's
    denormalized columns, disassembly's function/edge/string rows) are absent for a freshly
    uploaded copy of the same bytes (e.g. the same binary in a second case). The stage's
    on_cache_hit hook rebuilds them from the cloned output artifact. No-op (returns False) when
    the stage declares no hook or isn't registered."""
    sd = _STAGES.get(stage)
    if sd is None or sd.on_cache_hit is None:
        return False
    sd.on_cache_hit(store, target_id, run_id)
    return True


def get_stage(name: str) -> StageDef:
    if name not in _STAGES:
        raise KeyError(f"unknown stage {name!r}; registered: {sorted(_STAGES)}")
    return _STAGES[name]


def list_stages() -> list[str]:
    return sorted(_STAGES)


def clear_stages() -> None:
    """Test helper."""
    _STAGES.clear()
