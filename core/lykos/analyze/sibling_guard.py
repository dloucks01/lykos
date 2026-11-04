"""Missing-sibling-validation detector -- the generalized variant-analysis TTP. In a family of
sibling handlers (functions sharing a prefix, e.g. the surface-command handlers
`gdi_SurfaceCommand_{Uncompressed,Planar,Alpha,Progressive,ClearCodec,RemoteFX,...}` all dispatched
from one switch), a VALIDATION call that most siblings gate on but one omits is the copy-paste bug
pattern behind many CVEs. CVE-2026-26955 is exactly this: every sibling calls
`is_within_surface(surface, cmd)` as a guard except `gdi_SurfaceCommand_ClearCodec`, so attacker
geometry flows unchecked into the codec -> heap overflow.

Mechanism (pure string analysis over brace-matched bodies, no execution):
  1. group functions by family (shared prefix, >= 3 members with distinct suffixes);
  2. for each member collect its GUARD CALLS -- a callee used inside an `if (...)` whose action is
     return/goto/FALSE/break (a bail-out gate);
  3. for each guard callee used by >= 2 members, flag the members that DON'T use it, ranked by how
     many siblings do (the dominance fraction = confidence).

This is a lead generator, not a proof: a member may legitimately not need the check (it may validate
internally). So a finding carries the sibling evidence (who does guard) for review, and the fraction
ranks the strongest asymmetries first. The stage wrapper lives in sibling_guard_stage.py.
"""
from __future__ import annotations

import re
from collections import defaultdict
from .dispatcher_harness import _functions

#: a call used as a bail-out guard: inside an `if (...)` condition whose action is return/goto/break
#: or that returns FALSE. We join up to 2 physical lines so a wrapped `if`/action still matches.
_IF_CALL = re.compile(r'\bif\s*\(\s*!?\s*([A-Za-z_]\w*)\s*\(')
_BAILS = ("return", "goto", "break", "FALSE", "false")

#: calls that are never "validation" even when they gate a return (logging / asserts / trivial).
_NOT_GUARDS = frozenset({"WLog_Print", "WLog_ERR", "WINPR_ASSERT", "printf", "fprintf", "sizeof",
                         "IFCALLRESULT", "IFCALLRET", "memcpy", "memset", "free"})

#: a guard callee only counts as a VALIDATION guard if its name reads like one -- a bounds/length/
#: range check. This is what separates a security asymmetry (one sibling skips the bounds check) from
#: incidental call-mix noise (`omits strcmp`, `omits gettimeofday`, `omits FAILED`).
_VALIDATION_RE = re.compile(r'(?i)(check|valid|within|bound|ensure|verify|require|safe|_is_|^is_|'
                            r'RequiredLength|RequiredCapacity|RemainingLength)')


def _family_key(name: str) -> str:
    """Prefix family key: everything up to the last underscore-delimited segment. So
    `gdi_SurfaceCommand_ClearCodec` -> `gdi_SurfaceCommand`, keeping siblings together."""
    i = name.rfind("_")
    return name[:i] if i > 0 else name


def _guard_calls(body: str) -> set:
    """Callees used as bail-out guards in `body` (a call in an `if` condition whose nearby action is
    return/goto/break/FALSE)."""
    flat = re.sub(r'[ \t]+', ' ', body)
    out = set()
    for m in _IF_CALL.finditer(flat):
        callee = m.group(1)
        if callee in _NOT_GUARDS or not _VALIDATION_RE.search(callee):
            continue
        window = flat[m.start():m.start() + 160]            # the if + its immediate action
        if any(b in window for b in _BAILS):
            out.add(callee)
    return out


def find_missing_sibling_guards(text: str, *, min_family: int = 3, min_siblings: int = 2,
                                min_confidence: float = 0.5) -> list:
    """Per file: members of a handler family that omit a guard call >= min_siblings of their siblings
    make, where that guard is made by at least `min_confidence` of the family (default half -- a
    majority asymmetry, which is the precise signal; lower fractions are coincidental call-mix noise).
    Returns {fn, missing, used_by, family, family_size, confidence, line}."""
    funcs = [(n, body, text.count("\n", 0, text.find(body)) + 1 if text.find(body) >= 0 else 0)
             for (n, _s, _p, body) in _functions(text)]
    fams = defaultdict(list)
    for n, body, ln in funcs:
        fams[_family_key(n)].append((n, body, ln))
    out = []
    for fam, members in fams.items():
        names = {m[0] for m in members}
        if len(members) < min_family or len(names) < min_family:
            continue
        guards = {n: _guard_calls(body) for n, body, _ln in members}
        # count, across the family, how many members use each guard callee
        usage = defaultdict(set)
        for n, gs in guards.items():
            for g in gs:
                usage[g].add(n)
        for n, body, ln in members:
            for g, users in usage.items():
                if n in users or len(users) < min_siblings:
                    continue
                if len(users) / len(members) < min_confidence:    # only majority-guard asymmetries
                    continue
                # the member must plausibly be in the same role: it references a param-ish object the
                # guard also takes (cheap check: the guard callee name appears >=2x family-wide).
                out.append({"fn": n, "missing": g, "used_by": sorted(users), "family": fam,
                            "family_size": len(members),
                            "confidence": round(len(users) / len(members), 2), "line": ln})
    # strongest asymmetry first
    out.sort(key=lambda d: (-d["confidence"], -len(d["used_by"])))
    return out
