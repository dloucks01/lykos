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

#: How far lykos's CURRENT techniques reach is a fact about LYKOS, never about the target. The
#: defect is still there; lykos just hasn't implemented the technique to carry it further YET.
#: Every surface that shows this must carry the framing so a reader never reads "lykos reached L2"
#: as "the target is safe" -- that false clearance is the exact mechanism by which a bug that
#: "passed analysis" becomes a later zero-day. Mirror of the 0-false-confirmation invariant: a
#: 0-false-CLEARANCE admission. It is never "blocked" -- there is no wall, only a technique we have
#: not built yet.
CEILING_FRAMING = ("not a limit of the target -- lykos hasn't implemented the technique to carry "
                   "this further yet. The defect stands; this is the next thing to build, not a "
                   "clearance and not a wall.")

#: Per CWE class, the technique lykos WOULD BUILD NEXT to carry weaponization further for that class
#: -- the "what to implement next" answer, never "what blocks us" (there is no wall, only unbuilt
#: technique). A class-level statement (like CLASS_PRIMITIVE), never a per-instance claim; when an
#: emitter named a MORE specific technique it records it inline ("[needs: ...]") and that overrides
#: this default. This is the raw material of the weaponization backlog: each distinct technique here
#: is one build that advances a whole column of findings to PoCs (as the fmt->PIE leak just did for
#: CWE-134/121 -- last week's "ceiling", this week's PoC).
MISSING_TECHNIQUE = {
    "CWE-121": "recover the LIVE saved-return stack address under ASLR (a wider/multi-read leak to "
               "anchor the frame, or a stack-pivot that sidesteps needing it)",
    "CWE-122": "a heap-layout (grooming) solver to place the overflow adjacent to a target object",
    "CWE-125": "steer the out-of-bounds read at a chosen secret and recover the disclosed bytes "
               "through the program's own output path",
    "CWE-129": "constrain the attacker-controlled index and the write value to land the computed "
               "write on a live code/function pointer",
    "CWE-134": "a wider or multi-read format leak to capture the LIVE saved-return (or a writable "
               "code pointer) through printf's opaque vararg positioning",
    "CWE-190": "a heap-layout solver to turn the undersized allocation into a controlled overflow "
               "against a chosen object",
    "CWE-191": "bound the underflowed length and a reaching driver to steer the oversized access",
    "CWE-415": "an allocator-state model to turn the double free into a controlled reclaim",
    "CWE-416": "a reclaim/grooming solver to reoccupy the freed chunk with an attacker-shaped object",
    "CWE-457": "a path that observes the uninitialised bytes through the program's output",
    "CWE-787": "a reaching driver plus the write-target layout to steer the OOB write onto a live "
               "pointer",
    "CWE-78": "a reaching input channel that carries the injected command unsanitised to the sink",
    "CWE-94": "a reaching input channel that carries the injected code to the interpreter sink",
    "CWE-22": "a reaching input channel that carries the path-traversal payload to the filesystem "
              "sink, plus a runnable target to confirm a read/write outside the intended directory",
}


def missing_technique(cwe: Optional[str], ceiling_reason: Optional[str] = None) -> Optional[str]:
    """The technique lykos would build next to carry weaponization further: the SPECIFIC one an
    emitter named inline as "[needs: ...]" if present, else the class-level default for `cwe`.
    Never a wall -- an unbuilt technique. Pure."""
    if ceiling_reason:
        import re as _re
        mo = _re.search(r"\[needs:\s*(.+?)\]\s*$", ceiling_reason.strip())
        if mo:
            return mo.group(1).strip()
    return MISSING_TECHNIQUE.get(cwe or "")


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
    ceiling = reason = targets_live = inline_tech = None
    for e in f.get("evidence") or []:
        d = e.get("detail") or "" if isinstance(e, dict) else ""
        # Tolerant of both the forward wording ("lykos reached L2 here; next technique ...: X") and
        # the legacy marker ("weaponization reached L2 and stopped here: X") in older stored cases.
        mo = re.search(r"(?:weaponization reached|lykos reached) (L\d)\b[^:]*:\s*(.+)", d)
        if mo:
            ceiling, raw = mo.group(1), mo.group(2).strip().rstrip(".")[:240]
            # Split off an inline "[needs: ...]" the emitter recorded -- the specific technique to
            # build next -- so the reason reads clean and the technique overrides the class default.
            bm = re.search(r"\s*\[needs:\s*(.+?)\]\s*$", raw)
            if bm:
                inline_tech, raw = bm.group(1).strip(), raw[:bm.start()].strip().rstrip(".")
            reason = raw
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
        # lykos's current reach, never a target clearance -- carry the framing + the specific
        # technique to build next so no surface can present it as "safe" or as a wall.
        out["ceiling_framing"] = CEILING_FRAMING
        bp = inline_tech or missing_technique(f.get("cwe"))
        if bp:
            out["missing_technique"] = bp
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


#: How actionable each verdict is (highest wins when folding a distinct issue's copies): a real
#: on-surface finding (shortlist) beats off-surface beats unclassified beats instrumentation noise.
VERDICT_RANK = {"prove-out-shortlist": 3, "off-surface": 2, "unclassified": 1,
                "instrumentation-noise": 0}


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


#: Per CWE class, the (solver lykos would run, oracle that would confirm it) once a driver reaches
#: the sink -- the directed path from a corroborated finding to a fired reproducer (poc-backed).
_CWE_SOLVER = {
    "CWE-190": ("the integer-overflow -> undersized-alloc -> heap-overflow detonator",
                "an ASan heap-buffer-overflow abort"),
    "CWE-122": ("the heap-overflow detonator", "an ASan heap-buffer-overflow abort"),
    "CWE-121": ("the stack-overflow detonator built from the recovered frame, then the ROP solver",
                "a controlled saved-return (and, past the leak, a spawned shell)"),
    "CWE-787": ("the out-of-bounds-write detonator", "an ASan out-of-bounds-write abort"),
    "CWE-125": ("the out-of-bounds-read detonator", "an ASan out-of-bounds-read report"),
    "CWE-129": ("the unchecked-index detonator (the computed array/GOT write)",
                "an ASan out-of-bounds abort / the overwritten slot's effect"),
    "CWE-134": ("the format-string %hhn write-what-where solver",
                "a win-address write (and, on non/partial-RELRO, a spawned shell)"),
    "CWE-416": ("the use-after-free reclaim detonator (groom the freed chunk)",
                "an ASan use-after-free abort"),
    "CWE-415": ("the double-free detonator", "an ASan double-free / allocator abort"),
    "CWE-78": ("the command-injection payload over the reaching channel",
               "the injected command's runtime marker"),
    "CWE-22": ("the path-traversal payload over the reaching channel",
               "a read/write resolved outside the intended directory"),
}


def prove_out_plan(f: dict, verification: Optional[dict] = None) -> Optional[dict]:
    """For a PROVE-OUT-SHORTLIST finding, the directed plan lykos would run to raise it to
    poc-backed: synthesize a driver that reaches the sink, drive the attacker-controlled source,
    run the CWE-specific solver against the uninstrumented build, confirm with its oracle. This is
    a PLAN (what to run next), never a demonstrated exploit -- it is emitted only for findings the
    verification step put on the shortlist, and names the finding's own site/function, so it cannot
    overstate. None for anything not on the shortlist."""
    v = verification or f.get("verification") or finding_verification(f)
    if not v.get("shortlist"):
        return None
    solver, oracle = _CWE_SOLVER.get(f.get("cwe"), ("the matching weaponizer for this class",
                                                     "its sanitizer / runtime-marker oracle"))
    where = f.get("function_addr") or "the finding's function"
    site = f.get("site_addr")
    reach_note = (" (seed it with the gate-passing inputs the harness recovered)"
                  if v.get("reachable") else
                  " (synthesize a driver / harness; the recovered call graph showed no path, so "
                  "reachability must be established)")
    steps = [
        f"synthesize a driver that reaches {where}" + reach_note,
        "drive the attacker-controlled input named in the dataflow to the sink"
        + (f" at {site}" if site else ""),
        f"run {solver} against the uninstrumented build",
        f"confirm with {oracle} — this raises the finding to poc-backed",
    ]
    return {"solver": solver, "oracle": oracle, "steps": steps}


#: Rank a finding in the weaponization backlog: higher = better ROI to build next. Highest severity
#: first, then CLOSEST to a demonstrated PoC (an L2 one rung short of L3 is a smaller build than an
#: L1). Severity/level are the only ordering signals; neither asserts anything not already set.
_LEDGER_SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_LEDGER_LEVEL = {"L1": 1, "L2": 2, "L3": 3}


def ceiling_ledger(findings: list) -> Optional[dict]:
    """The WEAPONIZATION BACKLOG: every distinct finding lykos hasn't yet carried to a validated
    PoC, with the level its current techniques reach, the specific technique to BUILD NEXT, and the
    framing that this is lykos's reach -- never a wall, never a target clearance. Ranked
    best-ROI-first. Pure -- reads the already-serialized findings (each may carry a precomputed
    `exploitability`, else it is derived with no mitigation context, which does not affect the
    reach). Deduped by `dedup_key` so a source bug filed once per target that compiles it appears
    once. None when there is nothing in the backlog.

    This is the mirror of the PoC list: the PoC list is what lykos weaponizes TODAY; this is what it
    hasn't built the technique for YET, itemized -- so a 'clean' area is never read as 'no bugs',
    only as 'no bugs lykos's current reach found', and each entry is a build task. Shipping an
    entry's technique is exactly how lykos grows; the backlog IS the roadmap."""
    seen: dict = {}
    entries: list[dict] = []
    for f in findings or []:
        ex = f.get("exploitability")
        if ex is None:
            ex = finding_exploitability(f, None)
        if not ex or not ex.get("ceiling"):
            continue
        key = f.get("dedup_key") or f.get("id") or id(f)
        if key in seen:
            continue
        seen[key] = True
        entries.append({
            "cwe": f.get("cwe"),
            "title": f.get("title"),
            "site": f.get("site_addr") or f.get("function_addr"),
            "severity": f.get("severity") or "medium",
            "reached": ex.get("ceiling"),
            "would_reach": ex.get("targets_live") or "L3",
            "missing_technique": ex.get("missing_technique"),
            "reason": ex.get("ceiling_reason"),
            "dedup_key": f.get("dedup_key"),
        })
    if not entries:
        return None
    entries.sort(key=lambda e: (_LEDGER_SEV.get(e["severity"], 2),
                                _LEDGER_LEVEL.get(e["reached"], 0)), reverse=True)
    # Group the backlog by the technique to build: each one is a single build that advances N
    # findings toward a PoC -- the highest-leverage thing to implement next.
    by_cap: dict = {}
    for e in entries:
        by_cap.setdefault(e.get("missing_technique") or "(technique not yet classified)", 0)
        by_cap[e["missing_technique"] or "(technique not yet classified)"] += 1
    techniques = [{"missing_technique": k, "advances": v}
                  for k, v in sorted(by_cap.items(), key=lambda kv: kv[1], reverse=True)]
    return {"framing": CEILING_FRAMING, "count": len(entries),
            "entries": entries, "techniques": techniques}
