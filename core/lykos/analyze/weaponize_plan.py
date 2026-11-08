"""`weaponize_plan` router -- turn confirmed primitives into concrete TTP exploitation plans.

This is the consumer that wires the TTP planners in `weaponize_advanced` (heap grooming, leak->write
chaining, RCE primitive-graph search, format/UAF weaponizers) into the engine. The `build_exploit`
stage detonates a single primitive and tops out at an honest L3 ceiling; this module answers the
*next* question the operator always asks there -- "given everything this run confirmed, what is the
concrete technique that carries it to RCE, and what is still missing?" -- per the standing rule that a
weaponization ceiling must NAME the technique to build next, never read as a wall.

Pure + testable: it maps a finding's CWE to a per-finding weaponizer and composes the whole target's
primitive set into an RCE plan. The stage (`weaponize_plan_stage`) attaches the result as finding
evidence so the report's weaponization section shows the chain. No detonation here.
"""
from __future__ import annotations

from . import weaponize_advanced as wa

#: CWE -> the abstract primitive tag plan_rce reasons over.
_PRIMITIVE_TAG = {
    "CWE-125": "oob-read", "CWE-126": "oob-read", "CWE-200": "leak",
    "CWE-787": "oob-write", "CWE-122": "oob-write", "CWE-120": "oob-write",
    "CWE-121": "oob-write", "CWE-190": "oob-write", "CWE-787-w": "write-what-where",
    "CWE-416": "uaf", "CWE-415": "arbitrary-free", "CWE-134": "fmt",
}

#: memory-corruption classes that get a per-finding weaponization plan.
_WRITE = {"CWE-787", "CWE-122", "CWE-120", "CWE-121", "CWE-190", "CWE-124", "CWE-131"}
_LEAK = {"CWE-125", "CWE-126", "CWE-200"}


def primitive_tag(cwe: "str | None") -> "str | None":
    """The abstract primitive a finding of this CWE provides, for plan_rce's graph search."""
    return _PRIMITIVE_TAG.get((cwe or "").strip())


def plan_for_finding(cwe: "str | None", *, overflow_size: int = 64, victim_size: int = 64,
                     freed_size: int = 64, controlled_bytes: int = 256) -> "dict | None":
    """A per-finding weaponization plan from the matching TTP, or None for a class that only
    contributes to the whole-target chain (a bare leak). Sizes default to a representative heap
    chunk when the finding does not carry measured ones; the plan is a technique sketch, not a
    detonation, so the exact sizes are refined when the primitive is actually driven."""
    cwe = (cwe or "").strip()
    if cwe == "CWE-134":
        p = wa.fmt_write_what_where(0x0, 0x0)
        return {"ttp": "fmt-write-what-where", "primitive": p["primitive"],
                "plan": [w["spec"] for w in p["writes"]], "note": p["note"], "feasible": True}
    if cwe in ("CWE-416", "CWE-415"):
        p = wa.uaf_reclaim_plan(freed_size, controlled_bytes)
        return {"ttp": "uaf-reclaim", "feasible": p["feasible"], "plan": p["steps"],
                "note": p["reason"]}
    if cwe in _WRITE:
        g = wa.heap_groom_plan(overflow_size, victim_size)
        return {"ttp": "heap-groom", "feasible": g.feasible, "plan": g.steps, "note": g.reason}
    return None


def plan_target(findings: list) -> dict:
    """Compose the whole target's confirmed primitives into an RCE plan plus, when both a leak and a
    write are present, an explicit ASLR-defeating leak->write chain. `findings` is a list of dicts
    with at least {cwe, function}. Honest: names exactly what is still missing when RCE is not yet
    reachable."""
    tags = sorted({t for f in findings if (t := primitive_tag(f.get("cwe")))})
    rce = wa.plan_rce(tags)
    chain = None
    leak = next((f for f in findings if (f.get("cwe") or "") in _LEAK), None)
    write = next((f for f in findings if (f.get("cwe") or "") in _WRITE), None)
    if leak and write:
        c = wa.leak_to_write_chain(leak, write)
        chain = {"stages": c.stages, "defeats": c.defeats, "verdict": c.verdict}
    return {"primitives": tags, "rce": rce, "leak_write_chain": chain}
