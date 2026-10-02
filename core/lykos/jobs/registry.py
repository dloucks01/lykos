"""JE-23 — Stage registry.

The core has no hardcoded list of stages; capabilities register themselves (wires to the
plugin API, P0.9). A stage is a callable `fn(ctx) -> Optional[dict]`; the optional dict may
carry {"output_shas": [...], "output_kind": str, "metrics": {...}} which the worker links.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Optional

_log = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ..casestore import CaseStore

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
    # The param keys this stage understands (doc 30 P5.4). When set, a run carrying a key NOT in
    # this set (or in default_params) fails LOUD at dispatch -- a typo'd param no longer silently
    # does nothing. None = opt-out (no validation), so an undeclared stage is not newly restricted.
    param_schema: Optional[frozenset] = None


_STAGES: dict[str, StageDef] = {}


def register_stage(name: str, fn: StageFn, *, resource_class: str = "quick",
                   default_params: Optional[dict] = None, tool: Optional[str] = None,
                   tool_version: Optional[str] = None,
                   timeout: Optional[float] = None,
                   on_cache_hit: Optional[CacheHitFn] = None,
                   param_schema: Optional[set] = None) -> StageDef:
    sd = StageDef(name=name, fn=fn, resource_class=resource_class,
                  default_params=default_params or {}, tool=tool,
                  tool_version=tool_version, timeout=timeout, on_cache_hit=on_cache_hit,
                  param_schema=frozenset(param_schema) if param_schema is not None else None)
    _STAGES[name] = sd
    return sd


def validate_params(name: str, params: Optional[dict]) -> None:
    """Raise ValueError if `params` carries a key the stage does not declare (doc 30 P5.4).

    A stage opts in by passing `param_schema` to `register_stage`; `default_params` keys are always
    allowed. A stage with no schema is not validated, so this is additive -- turning it on for a
    stage is what makes a typo'd param a loud failure instead of a silent no-op. The common control
    keys every stage's harness threads through are always permitted."""
    sd = _STAGES.get(name)
    if sd is None or sd.param_schema is None:
        return
    allowed = set(sd.param_schema) | set(sd.default_params or {}) | _COMMON_PARAMS
    unknown = sorted(k for k in (params or {}) if k not in allowed)
    if unknown:
        raise ValueError(f"stage {name!r}: unknown param(s) {unknown}; allowed: {sorted(allowed)}")


# Control keys the queue/harness may thread onto any run; never a stage-specific typo.
_COMMON_PARAMS = frozenset({"force", "max_seconds", "max_execs", "exec_timeout", "timeout",
                            "workers", "seed", "seeds"})


def cached_output_json(store: "CaseStore", run_id: str) -> Any:
    """The parsed JSON of a run's first 'output' artifact, or None. Shared by cache-hit
    reprojection hooks, which rebuild per-target DB rows from a cloned output artifact."""
    for link in store.run_artifacts.list_by_run(run_id):
        if link.role == "output":
            try:
                return json.loads(store.content.get_bytes(link.artifact_sha256))
            except Exception:
                # Corrupt/unreadable output artifact: keep scanning, but leave a trace so a
                # silently-dropped cache output is observable.
                _log.debug("cached_output_json: skipping output artifact %s for run %s",
                           link.artifact_sha256, run_id, exc_info=True)
                continue
    return None


def reproject_cache_hit(store: "CaseStore", stage: str, target_id: str,
                        run_id: str) -> bool:
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
