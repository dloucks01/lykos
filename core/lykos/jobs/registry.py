"""JE-23 — Stage registry.

The core has no hardcoded list of stages; capabilities register themselves (wires to the
plugin API, P0.9). A stage is a callable `fn(ctx) -> Optional[dict]`; the optional dict may
carry {"output_shas": [...], "output_kind": str, "metrics": {...}} which the worker links.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# fn(ctx: JobContext) -> Optional[dict]
StageFn = Callable[[Any], Optional[dict]]


@dataclass(frozen=True)
class StageDef:
    name: str
    fn: StageFn
    resource_class: str = "quick"
    default_params: dict = field(default_factory=dict)
    tool: Optional[str] = None
    tool_version: Optional[str] = None
    timeout: Optional[float] = None      # per-stage wall-clock override


_STAGES: dict[str, StageDef] = {}


def register_stage(name: str, fn: StageFn, *, resource_class: str = "quick",
                   default_params: Optional[dict] = None, tool: Optional[str] = None,
                   tool_version: Optional[str] = None,
                   timeout: Optional[float] = None) -> StageDef:
    sd = StageDef(name=name, fn=fn, resource_class=resource_class,
                  default_params=default_params or {}, tool=tool,
                  tool_version=tool_version, timeout=timeout)
    _STAGES[name] = sd
    return sd


def get_stage(name: str) -> StageDef:
    if name not in _STAGES:
        raise KeyError(f"unknown stage {name!r}; registered: {sorted(_STAGES)}")
    return _STAGES[name]


def list_stages() -> list[str]:
    return sorted(_STAGES)


def clear_stages() -> None:
    """Test helper."""
    _STAGES.clear()
