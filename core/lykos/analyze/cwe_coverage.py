"""CWE coverage matrix -- the honest account of what the platform can DETECT and WEAPONIZE, across
every weakness class, and how far each class can honestly be carried.

Breadth is not the hard part: the detectors already emit most relevant CWE classes. The honest
questions "consider all CWEs" really asks are (1) which classes we detect, (2) which we can turn
into a demonstrated exploit vs. which top out at a DoS / info-leak / a logic finding by their
nature, and (3) on a given run, how far each class that appeared was actually carried. This module
answers all three from data: the declared CWE names, a per-class weaponization CEILING, and the
run's own findings. It never inflates -- a class whose exploit ceiling is "dos" is reported as
dos, not as a missed RCE.
"""
from __future__ import annotations

from typing import Optional

from ..cwe import CWE_NAMES

#: The honest WEAPONIZATION CEILING per class -- how far a *sound* exploit of this weakness can be
#: carried, independent of whether a given target allows it:
#:   rce       -> a working code-execution / command-execution exploit is achievable (lykos emits a
#:                script or a confirmed PoC for the class).
#:   primitive -> a corruption/control primitive (L2): real, but RCE needs more (a leak, grooming).
#:   leak      -> information disclosure (read primitive); not control.
#:   dos       -> availability only (crash / hang / exhaustion); not control. The common HONEST
#:                ceiling -- most memory-SAFETY *reads* and all abort/resource classes stop here.
#:   logic     -> the finding itself is the impact (auth bypass, traversal, weak crypto); no memory
#:                exploit, the weakness is demonstrated by reaching the sink, not by a payload.
CEILING: dict[str, str] = {
    # code / command / query / deserialization execution -> RCE
    "CWE-77": "rce", "CWE-78": "rce", "CWE-88": "rce", "CWE-89": "rce", "CWE-94": "rce",
    "CWE-95": "rce", "CWE-98": "rce", "CWE-502": "rce", "CWE-917": "rce", "CWE-1336": "rce",
    "CWE-1321": "rce",
    # memory-corruption WRITES / dangling -> RCE (overflow/format-write/UAF/type-confusion)
    "CWE-787": "rce", "CWE-121": "rce", "CWE-120": "rce", "CWE-122": "rce", "CWE-124": "rce",
    "CWE-123": "rce", "CWE-134": "rce", "CWE-416": "rce", "CWE-415": "rce", "CWE-843": "rce",
    "CWE-190": "rce", "CWE-191": "rce", "CWE-680": "rce", "CWE-131": "rce", "CWE-193": "rce",
    "CWE-824": "rce", "CWE-763": "rce", "CWE-562": "rce", "CWE-825": "rce",
    # hard-coded / recoverable secrets -> authentication (a usable credential)
    "CWE-798": "logic", "CWE-321": "logic", "CWE-259": "logic",
    # reads / disclosure -> leak
    "CWE-125": "leak", "CWE-126": "leak", "CWE-127": "leak", "CWE-200": "leak", "CWE-209": "leak",
    "CWE-201": "leak", "CWE-212": "leak", "CWE-457": "leak", "CWE-908": "leak", "CWE-522": "leak",
    "CWE-203": "leak", "CWE-643": "leak", "CWE-786": "leak", "CWE-788": "leak",
    "CWE-129": "primitive", "CWE-823": "primitive", "CWE-822": "primitive", "CWE-119": "primitive",
    # availability -> dos
    "CWE-476": "dos", "CWE-617": "dos", "CWE-835": "dos", "CWE-400": "dos", "CWE-770": "dos",
    "CWE-369": "dos", "CWE-674": "dos", "CWE-401": "dos", "CWE-789": "dos", "CWE-248": "dos",
    "CWE-252": "dos", "CWE-690": "dos", "CWE-833": "dos", "CWE-409": "dos", "CWE-776": "dos",
    "CWE-590": "dos", "CWE-761": "dos", "CWE-762": "dos",
    # logic / auth / crypto / traversal -> the finding is the impact
    "CWE-22": "logic", "CWE-23": "logic", "CWE-59": "logic", "CWE-79": "logic", "CWE-20": "logic",
    "CWE-287": "logic", "CWE-306": "logic", "CWE-862": "logic", "CWE-863": "logic",
    "CWE-732": "logic", "CWE-276": "logic", "CWE-295": "logic", "CWE-297": "logic",
    "CWE-319": "logic", "CWE-327": "logic", "CWE-328": "logic", "CWE-310": "logic",
    "CWE-347": "logic", "CWE-290": "logic", "CWE-384": "logic", "CWE-352": "logic",
    "CWE-918": "logic", "CWE-611": "logic", "CWE-362": "logic", "CWE-367": "logic",
    "CWE-696": "logic", "CWE-250": "logic", "CWE-330": "logic", "CWE-338": "logic",
    "CWE-494": "logic", "CWE-693": "logic", "CWE-1188": "logic", "CWE-1395": "logic",
    "CWE-116": "logic", "CWE-1066": "logic",
}

#: The confidence ladder, ordered, so a run's "best state reached" for a class is comparable.
_STATE_ORDER = {"candidate": 0, "corroborated": 1, "confirmed": 2, "poc-backed": 3}
_CEILING_WORD = {"rce": "code/command execution", "primitive": "corruption primitive",
                 "leak": "information disclosure", "dos": "denial of service",
                 "logic": "logic / auth / crypto impact"}


def detected_classes() -> set:
    """The CWE classes the platform can name/explain (≈ the classes its detectors emit; CWE_NAMES
    is kept in sync with the emitted set)."""
    return set(CWE_NAMES)


def weaponizable(cwe: str) -> Optional[str]:
    """The honest exploit ceiling for a class ('rce'/'primitive'/'leak'/'dos'/'logic'), or None when
    the class has no modelled exploitation path."""
    return CEILING.get((cwe or "").upper())


def capability_matrix() -> list:
    """The static capability: every known CWE class with its name, whether a detector covers it, and
    its weaponization ceiling. The map the operator reads to see coverage across ALL classes."""
    out = []
    for cwe, (name, _desc) in sorted(CWE_NAMES.items(), key=lambda kv: int(kv[0].split("-")[1])):
        c = weaponizable(cwe)
        out.append({"cwe": cwe, "name": name, "detected": True,
                    "ceiling": c, "ceiling_label": _CEILING_WORD.get(c) if c else None,
                    "rce_capable": c == "rce"})
    return out


def run_matrix(findings) -> dict:
    """How far each CWE class that APPEARED in this run was carried: per class, the count and the
    best confidence state reached, plus its ceiling. `findings` are serialized dicts or rows with
    `.cwe`/`.state` (or ["cwe"]/["state"]). Deduplicated by (cwe, dedup_key)."""
    seen: set = set()
    by_cwe: dict = {}
    for f in findings:
        cwe = (f.get("cwe") if isinstance(f, dict) else getattr(f, "cwe", None)) or "(none)"
        state = (f.get("state") if isinstance(f, dict) else getattr(f, "state", None)) or "candidate"
        key = (f.get("dedup_key") if isinstance(f, dict) else getattr(f, "dedup_key", None))
        k = (cwe, key)
        if key and k in seen:
            continue
        seen.add(k)
        e = by_cwe.setdefault(cwe, {"cwe": cwe, "name": CWE_NAMES.get(cwe, (cwe, ""))[0],
                                    "count": 0, "best_state": "candidate",
                                    "ceiling": weaponizable(cwe)})
        e["count"] += 1
        if _STATE_ORDER.get(state, 0) > _STATE_ORDER.get(e["best_state"], 0):
            e["best_state"] = state
    rows = sorted(by_cwe.values(), key=lambda e: (-e["count"], e["cwe"]))
    demonstrated = [e for e in rows if _STATE_ORDER.get(e["best_state"], 0) >= 2]
    return {"schema": "lykos.cwe-coverage/1", "classes_present": len(rows), "rows": rows,
            "demonstrated_classes": len(demonstrated),
            "rce_capable_present": [e["cwe"] for e in rows if e["ceiling"] == "rce"]}


def summary() -> dict:
    """A one-call rollup of the static capability: how many classes are detected, and the ceiling
    distribution (how many classes can reach RCE vs top out at a primitive/leak/DoS/logic)."""
    m = capability_matrix()
    dist: dict = {}
    for e in m:
        c = e["ceiling"] or "none"
        dist[c] = dist.get(c, 0) + 1
    return {"detected_classes": len(m), "ceiling_distribution": dist,
            "rce_capable": sum(1 for e in m if e["rce_capable"])}


_DIST_ORDER = ["rce", "primitive", "leak", "dos", "logic", "none"]
_DIST_WORD = {"rce": "code/command execution (RCE)", "primitive": "corruption primitive (L2)",
              "leak": "information disclosure", "dos": "denial of service (availability)",
              "logic": "logic / auth / crypto / traversal impact",
              "none": "no modelled exploit path (honest: typically hygiene/config)"}


def format_report(run: dict | None = None) -> str:
    """Human-readable coverage report: the static capability (what classes we detect and how far
    each can honestly be weaponized), and -- when `run` (from run_matrix) is given -- how far each
    class that actually appeared on a run was carried."""
    s = summary()
    out = ["CWE coverage -- detection breadth and the honest weaponization ceiling", ""]
    out.append(f"  classes the platform detects/names : {s['detected_classes']}")
    out.append(f"  classes that can reach RCE         : {s['rce_capable']}")
    out.append("")
    out.append("  weaponization ceiling by class (how far a SOUND exploit of the class can go):")
    for c in _DIST_ORDER:
        n = s["ceiling_distribution"].get(c, 0)
        if n:
            out.append(f"    {n:>3}  {_DIST_WORD[c]}")
    out.append("")
    out.append("  Reading this honestly: breadth is wide -- most relevant classes are detected.")
    out.append("  The leverage is DEPTH (landing on the actually-vulnerable function) and the")
    out.append("  classes above the 'logic/none' line, which are the ones an exploit can prove out.")
    if run is not None:
        out += ["", "-" * 72, "On this run -- how far each CWE class that appeared was carried:", ""]
        if not run["rows"]:
            out.append("  (no findings)")
        else:
            out.append(f"  {'CWE':<10} {'best state':<13} {'ceiling':<10} count  name")
            for e in run["rows"]:
                ceil = e["ceiling"] or "-"
                out.append(f"  {e['cwe']:<10} {e['best_state']:<13} {ceil:<10} "
                           f"{e['count']:>5}  {e['name']}")
            out.append("")
            out.append(f"  classes present: {run['classes_present']}   "
                       f"carried to confirmed/poc: {run['demonstrated_classes']}   "
                       f"RCE-capable classes present: {len(run['rce_capable_present'])}")
    return "\n".join(out)
