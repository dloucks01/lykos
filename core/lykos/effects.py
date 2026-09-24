"""End-effect merge policy -- a LEAF module (no lykos imports), so both the analysis layer
(`analyze.debug.exploitability`) and the persistence layer (`db.dao`) can share the one definition
of how effects promote, without the persistence layer depending on the analysis layer.

An "effect" is a dict {kind, title, status ('demonstrated'|'potential'), detail?, proof?}. A
finding accumulates them across stages: root_cause files the ceiling as potential, then the PoC
stages mark the ones they actually demonstrate, each attaching the artifact that proves it."""
from __future__ import annotations

# Severity ranking of end effects, worst first. Drives both the merge order and the headline pick.
EFFECT_SEV = {"rce": 5, "memory-corruption": 4, "info-disclosure": 3, "injection": 3, "dos": 1}


def merge_effects(base: list, updates: list) -> list:
    """Merge two effect lists by kind, keeping the stronger status (demonstrated > potential) and
    carrying a proof forward. Lets the pipeline PROMOTE an effect as later stages actually achieve
    it -- root_cause files the ceiling as potential, then poc_primitive/build_poc mark the ones
    they demonstrate, each attaching the artifact that proves it -- without losing the others."""
    by_kind = {e["kind"]: dict(e) for e in (base or [])}
    for u in updates or []:
        k = u.get("kind")
        cur = by_kind.get(k)
        if cur is None:
            by_kind[k] = dict(u)
            continue
        # demonstrated wins; a proof (or richer detail) is kept.
        if u.get("status") == "demonstrated" or cur.get("status") != "demonstrated":
            cur["status"] = u.get("status", cur.get("status"))
        if u.get("proof"):
            cur["proof"] = u["proof"]
        if u.get("detail"):
            cur["detail"] = u["detail"]
        if u.get("title"):
            cur["title"] = u["title"]
    return sorted(by_kind.values(), key=lambda e: -EFFECT_SEV.get(e.get("kind"), 0))


def primary_effect(effs: list) -> dict | None:
    """The headline effect for a finding: the most SEVERE achievable effect (the ceiling), with
    its own status. So a stack overflow headlines RCE even while only DoS is demonstrated so far
    -- the point is what the defect can be driven to, and whether the PoC has got there yet.
    Ties break toward a demonstrated effect over a merely potential one of equal severity."""
    if not effs:
        return None
    return max(effs, key=lambda e: (EFFECT_SEV.get(e.get("kind"), 0),
                                    1 if e.get("status") == "demonstrated" else 0))
