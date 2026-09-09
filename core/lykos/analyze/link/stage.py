"""The `link_case` stage (doc 17.1) — case-level, zero-dependency.

Resolves imports<->exports across every target in the case and persists the merged
component graph. Case-level (no target_id): it operates on the whole case at once.
"""
from __future__ import annotations

from ...jobs.registry import register_stage
from .resolve import resolve_case

LINK_STAGE = "link_case"
TOOL = "lykos-link"
TOOL_VERSION = "link-1"


def link_case_stage(ctx) -> dict:
    ctx.progress(msg="resolving imports <-> exports across components")
    summary = resolve_case(ctx.conn, ctx.content, ctx.case_id, persist=True)
    ctx.emit("link.done", payload=summary)
    ctx.progress(pct=100, msg=(f"linked {summary['components']} components: "
                               f"{summary['edges']} edges, "
                               f"{summary['resolved_symbols']} symbols"))
    return {"metrics": summary}


def register() -> None:
    register_stage(LINK_STAGE, link_case_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION)


def enqueue_link(queue, case_id: str, *, force: bool = True):
    return queue.enqueue(case_id, LINK_STAGE, tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
