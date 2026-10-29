"""The confirmation ladder, per finding: where it sits, WHY, and what would climb it.

One source for both the report (`report.model`) and the live web GUI (`api.serializers`), so the
two can never give a finding a different account. Pure and dependency-free: it reads only the
finding's own serialized fields (state, evidence channels, verified PoC levels) and never asserts
a per-finding specific (a proven reachable path, a recovered leak) it has not established -- those
specifics sit in the evidence beside it.
"""
from __future__ import annotations

from typing import Any, Optional

#: The ladder's next rung up from each state (None at the top).
NEXT_STATE = {"candidate": "corroborated", "corroborated": "confirmed",
              "confirmed": "poc-backed", "poc-backed": None}


def finding_analysis(f: dict) -> dict:
    """{state, next_state, why_state, to_promote, signals} for a serialized finding dict."""
    state = f.get("state") or "candidate"
    channels = sorted({(e.get("channel") or "").strip() for e in (f.get("evidence") or [])
                       if isinstance(e, dict) and (e.get("channel") or "").strip()})
    verified = [p.get("level") for p in (f.get("pocs") or [])
                if isinstance(p, dict) and p.get("verified") and p.get("level")]
    why = {
        "candidate": "A single detector flagged this pattern; no independent signal has "
                     "corroborated it yet.",
        "corroborated": "A second independent signal supports the initial detection"
                        + (f" ({', '.join(channels)})" if channels else "") + ".",
        "confirmed": "Verified by analysis as a real, reachable defect.",
        "poc-backed": "A reproducer ran and the fault fired"
                      + (f" (verified {max(verified)})" if verified else "")
                      + " -- demonstrated, not suspected.",
    }.get(state, "")
    to_promote: Optional[str] = {
        "candidate": "To corroborate: a second signal agreeing with the detector -- a synthesized "
                     "exploitation recipe, a dataflow/reachability check, or dynamic corroboration.",
        "corroborated": "To confirm: prove the sink is reachable from an attacker-controlled input "
                        "(a call-path from an input source, its guards satisfiable). Reachability "
                        "is not yet demonstrated here.",
        "confirmed": "To PoC-back: a reproducer that fires -- a synthesized driver that reaches the "
                     "sink on a runnable (uninstrumented) build, or delivery to the live target.",
        "poc-backed": None,
    }.get(state)
    return {
        "state": state,
        "next_state": NEXT_STATE.get(state),
        "why_state": why,
        "to_promote": to_promote,
        "signals": channels,
    }


#: The PRIMITIVE a CWE class yields, by definition of the class -- not a claim this instance was
#: demonstrated (that is what the ceiling / demonstrated level carry). Labelled "class primitive".
CLASS_PRIMITIVE = {
    "CWE-120": "unbounded copy -> buffer overflow (out-of-bounds write)",
    "CWE-121": "stack buffer overflow -> saved-return / local overwrite",
    "CWE-122": "heap buffer overflow (out-of-bounds write)",
    "CWE-125": "out-of-bounds read (information disclosure)",
    "CWE-129": "unchecked array index -> out-of-bounds read/write primitive",
    "CWE-134": "format string -> %n write-what-where + %s/%p disclosure",
    "CWE-190": "integer overflow -> undersized allocation -> heap overflow (out-of-bounds write)",
    "CWE-191": "integer underflow -> oversized length -> out-of-bounds access",
    "CWE-415": "double free -> allocator metadata corruption",
    "CWE-416": "use-after-free -> controlled reclaimed object (read/write via a dangling pointer)",
    "CWE-457": "uninitialised memory use -> disclosure / control-flow influence",
    "CWE-476": "null-pointer dereference -> denial of service",
    "CWE-787": "out-of-bounds write",
    "CWE-78": "OS command injection -> arbitrary command execution",
    "CWE-94": "code injection -> arbitrary code execution",
    "CWE-798": "hard-coded credential -> authentication bypass / credential disclosure",
}

#: How an ENABLED target mitigation stands between the primitive and a full exploit.
_MIT_GLOSS = {
    "nx": "NX — no executable stack/heap, so a code-reuse chain (ROP/ret2libc) is needed, "
          "not shellcode",
    "pie": "PIE — ASLR, so an address leak is needed before any code-reuse chain",
    "canary": "stack canary — a linear stack overflow must leak or avoid it",
}


def finding_exploitability(f: dict, mitigations: Optional[dict]) -> Optional[dict]:
    """{class_primitive, mitigations_in_way, demonstrated_level?, ceiling?, ceiling_reason?,
    targets_live?} for a finding, or None. Faithful: primitive = class definition, mitigations =
    target metadata, ceiling = the finding's own "weaponization reached L_n and stopped" words."""
    import re
    prim = CLASS_PRIMITIVE.get(f.get("cwe"))
    m = mitigations or {}
    mi: list[str] = []
    for k in ("nx", "pie", "canary"):
        if m.get(k):
            mi.append(_MIT_GLOSS[k])
    relro = m.get("relro")
    if relro in ("full", True) or m.get("bind_now"):
        mi.append("full RELRO/BIND_NOW — the GOT is read-only at runtime")
    elif relro == "partial":
        mi.append("partial RELRO — the GOT is still writable at runtime")
    ceiling = reason = targets_live = None
    for e in f.get("evidence") or []:
        d = e.get("detail") or "" if isinstance(e, dict) else ""
        mo = re.search(r"weaponization reached (L\d)\b.*?stopped(?: here)?[:]?\s*(.+)", d)
        if mo:
            ceiling, reason = mo.group(1), mo.group(2).strip().rstrip(".")[:240]
        to = re.search(r"[Tt]argets (L\d) if run against the live target", d)
        if to:
            targets_live = to.group(1)
    verified = [p.get("level") for p in (f.get("pocs") or [])
                if isinstance(p, dict) and p.get("verified") and p.get("level")]
    out: dict[str, Any] = {}
    if prim:
        out["class_primitive"] = prim
    if mi:
        out["mitigations_in_way"] = mi
    if verified:
        out["demonstrated_level"] = max(verified)
    if ceiling:
        out["ceiling"] = ceiling
        out["ceiling_reason"] = reason
    if targets_live:
        out["targets_live"] = targets_live
    return out or None


def attack_surface(f: dict) -> Optional[str]:
    """'on' / 'off' the fuzzed attack surface, lifted from the finding's own evidence prose."""
    for e in f.get("evidence") or []:
        d = (e.get("detail") or "").lower() if isinstance(e, dict) else ""
        if "on the fuzzed attack surface" in d:
            return "on"
        if "off the fuzzed attack surface" in d:
            return "off"
    return None


#: Symbols that mark a finding as anchored in INSTRUMENTATION / sanitizer / fuzzer RUNTIME code
#: rather than the target's own code -- an artifact of analysing the instrumented build, not a real
#: target defect. Conservative: only unambiguous runtime symbols, so de-noising never hides a real
#: finding (a false "noise" flag would be worse than none).
_NOISE_MARKERS = ("__sanitizer", "internal_allocator", "_zn6fuzzer", "fuzzer::executecommand",
                  "__asan", "__ubsan", "__lsan", "asan_report", "sanitizer_cov")


def instrumentation_noise(f: dict) -> dict:
    """{noise: bool, reason?} -- True when the finding is anchored in sanitizer/fuzzer runtime code.
    Scans the title + evidence prose for unambiguous runtime symbols (addresses alone never match)."""
    hay = (f.get("title") or "").lower()
    for e in f.get("evidence") or []:
        if isinstance(e, dict):
            hay += " " + (e.get("detail") or "").lower()
    for m in _NOISE_MARKERS:
        if m in hay:
            return {"noise": True, "reason": f"anchored in instrumentation/runtime symbol ({m})"}
    return {"noise": False}


def finding_verification(f: dict, reachable: Optional[bool] = None) -> dict:
    """The "is this an actual finding?" review verdict -- sound and conservative, it NEVER sets the
    earned `confirmed` state (that is reserved for a fired reproducer / dynamic confirm). It
    separates the pile into:

      * noise             -- an instrumentation/runtime artifact, not a target defect (de-prioritise)
      * prove-out shortlist -- a real finding on the fuzzed attack surface (attacker-reachable
                               surface): the slice worth synthesizing a driver for and proving out
      * off-surface       -- a real finding not compiled into any harness (lower remote priority)

    `reachable` (optional, from the call-graph path) is a BONUS signal noted when present; its
    absence is not held against a finding (the recovered call graph is incomplete, so a missing
    path is usually graph incompleteness, not proof of unreachability). `shortlist` is the
    actionable flag #5 consumes.
    """
    noise = instrumentation_noise(f)
    surf = attack_surface(f)
    if noise["noise"]:
        verdict = "instrumentation-noise"
    elif surf == "on":
        verdict = "prove-out-shortlist"
    elif surf == "off":
        verdict = "off-surface"
    else:
        verdict = "unclassified"
    return {
        "verdict": verdict,
        "noise": noise["noise"],
        "noise_reason": noise.get("reason"),
        "attack_surface": surf,
        "reachable": reachable,
        "shortlist": verdict == "prove-out-shortlist",
    }
