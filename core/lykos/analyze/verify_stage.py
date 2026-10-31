"""The `verify` stage -- populate the CONFIRMED rung, then weaponize what it confirms.

The confidence ladder ran wide and shallow: detectors filed hundreds of `candidate`/`corroborated`
findings, but the `confirmed` rung sat empty on static runs -- so the report could show "132
corroborated" and not one finding the platform would stand behind as a real, attacker-reachable
defect. This stage fills that rung soundly, with no execution, and then drives the exploit-script
emitters / recipe path on the RCE-capable ones it confirms.

PROMOTION (precision is paramount -- confirmed is a claim the platform stands behind):
A finding is promoted `corroborated -> confirmed` only when ALL THREE legs hold, read from the
`grounding-map` channel the grounding stage already wrote:
  * de-noise : grounding kept it (`grounded` -- it is NOT a provable false positive: not
               instrumentation noise, dead code, a dev-controlled format literal, or arch-safe).
  * dataflow : the finding is already `corroborated` AND a real analysis channel backs it
               (taint-dataflow / bounds / observed effect / source-sink / cpg) -- above a flat
               `pattern` match. A bare `candidate`, a finding corroborated on `pattern` alone, and a
               synthesized `recipe` row (corroborated at most by its own honesty contract) are never
               promoted.
  * reach    : taint_reach positively places the enclosing function on the malicious-peer
               attack surface (`reachable is True`). Reachability merely UNDECIDED is not enough --
               an undecided finding stays corroborated (the honest ceiling), never confirmed.
`confirmed` here means verified-real-and-reachable; it does NOT claim exploitability -- that is
`poc-backed`, reserved for an artifact an execution confirmed. The stage files its verdict on its
own `confirm` channel keyed to the run, so a later run whose basis has changed revises its own claim
and nothing else (the finding's state is still the max over all channels -- doc 05).

WEAPONIZE: for every finding now at `confirmed`/`poc-backed` whose class can reach code execution
(cwe_coverage ceiling == "rce"), emit the honest weaponization artifact once:
  * format-string (CWE-134) and command-injection (CWE-78/77/88): a self-contained exploit SCRIPT
    (the emitters self-calibrate / confirm by effect at runtime -- no binary facts needed), stored
    as an `exploit-script` artifact marked synthesized (proven=False): the operator's starting
    weapon, to run against a build of the target.
  * overflow / integer-overflow (CWE-120/121/122/787/190): a `file_recipe` -- a runnable script
    needs a recovered-frame offset this source-level finding does not have, so the honest artifact
    is the concrete technique + the confirmed site + why it was not executed here.
Each weaponized finding is annotated so a re-run does not emit twice.
"""
from __future__ import annotations

import json
import logging
import re

from ..db.dao import FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from . import cwe_coverage

_log = logging.getLogger(__name__)

VERIFY_STAGE = "confirm"
TOOL = "confirm"
TOOL_VERSION = "confirm-1"

#: RCE-capable classes whose exploit emitter runs soundly from a SOURCE finding (self-calibrating).
_SCRIPT_EMIT = {"CWE-134": "format", "CWE-78": "injection", "CWE-77": "injection",
                "CWE-88": "injection"}
#: RCE-capable classes that top out at a recipe at source level (a runnable script needs a
#: recovered-frame offset we do not have here): (technique, target_level).
_RECIPE_EMIT = {"CWE-120": ("stack-overflow-ret-overwrite", "L3"),
                "CWE-121": ("stack-overflow-ret-overwrite", "L3"),
                "CWE-122": ("heap-overflow-write", "L3"),
                "CWE-787": ("out-of-bounds-write", "L2"),
                "CWE-190": ("integer-overflow-to-memory-corruption", "L2")}

_SITE_RE = re.compile(r"([\w./\-]+\.(?:c|cc|cpp|cxx|h|hpp)):(\d+)")

#: Evidence channels that are a REAL analysis corroboration (dataflow / bounds / observed effect),
#: so a finding carrying one is above a flat pattern match -- the positive dataflow leg. A finding
#: corroborated on `pattern` alone, or only by a synthesized `recipe`, does NOT qualify.
_DERIVATION_CHANNELS = frozenset({
    "taint-dataflow", "taint-reachability", "bounds", "oob-index", "chain", "compare-probe",
    "effects", "poc_primitive", "source-sink", "cpg"})


def _evidence(f) -> list:
    ev = getattr(f, "evidence", None) or []
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except Exception:                                # noqa: BLE001
            ev = []
    return ev if isinstance(ev, list) else []


def _grounding_map(f) -> dict | None:
    """The structured grounding verdict the grounding stage wrote, or None if it has not run."""
    for e in _evidence(f):
        if isinstance(e, dict) and e.get("channel") == "grounding-map":
            try:
                return json.loads(e.get("detail") or "{}")
            except Exception:                            # noqa: BLE001
                return None
    return None


def _has_channel(f, channel: str) -> bool:
    return any(isinstance(e, dict) and e.get("channel") == channel for e in _evidence(f))


def _is_recipe(f) -> bool:
    """A synthesized exploitation recipe -- corroborated at most, NEVER confirmed (recipe.py's
    honesty contract). Such a row must never be promoted."""
    return (f.detector or "") == "recipe" or (f.title or "").startswith("Exploitation recipe")


def _has_derivation(f) -> bool:
    """True when a real analysis corroboration channel backs the finding (the positive dataflow
    leg) -- not merely a flat `pattern` match or a synthesized `recipe`."""
    return any(isinstance(e, dict) and e.get("channel") in _DERIVATION_CHANNELS
               for e in _evidence(f))


def _source_str(f) -> str:
    """A human source locator for the emitted artifact: 'func() at file:line' when the evidence
    carries a file:line, else the finding title."""
    for e in _evidence(f):
        m = _SITE_RE.search(str(e.get("detail", "")) if isinstance(e, dict) else "")
        if m:
            return f"{f.title} [{m.group(1)}:{m.group(2)}]"
    return f.title or "the confirmed finding"


def promote(fd: FindingDAO, target, run_id: str | None) -> list:
    """Promote every corroborated + real + attacker-reachable finding to confirmed. Returns the
    list of (finding, grounding_map) that are now confirmed (just promoted or already confirmed)."""
    confirmed = []
    for f in fd.list_by_target(target.id):
        if (f.detector or "") == "confirm":
            continue
        gm = _grounding_map(f)
        if gm is None:
            continue
        real = bool(gm.get("grounded"))
        reach_ok = gm.get("reachable") is True
        if (f.state == "corroborated" and real and reach_ok
                and not _is_recipe(f) and _has_derivation(f)):
            basis = (f"verified REAL and attacker-reachable: grounding kept it "
                     f"(verdict={gm.get('verdict')}), the enclosing function is on the "
                     f"malicious-peer attack surface (reach basis: {gm.get('reach_basis')}), and a "
                     f"real analysis channel (dataflow/bounds/effect) corroborates it. Confirmed = a "
                     f"real, reachable defect -- NOT a demonstrated exploit (that is poc-backed).")
            fd.upsert(target.id, target.case_id, {
                "cwe": f.cwe, "title": f.title, "severity": f.severity, "detector": f.detector,
                "state": "confirmed", "confidence": max(f.confidence or 0.0, 0.7),
                "dedup_key": f.dedup_key, "function_addr": f.function_addr,
                "site_addr": f.site_addr, "channel": "confirm", "run_id": run_id,
                "evidence": [{"channel": "confirm", "detail": basis}]})
            confirmed.append((f, gm))
        elif f.state in ("confirmed", "poc-backed"):
            confirmed.append((f, gm))
    return confirmed


def _emit_script(ctx, target, f, kind: str) -> str | None:
    """Render and store a self-contained exploit script for a confirmed format-string / injection
    finding. Synthesized (proven=False): the operator runs it against a build of the target."""
    try:
        from .poc import exploit_script
        facts = {"cwe": f.cwe, "source": _source_str(f), "delivery": "stdin", "argv": [],
                 "bits": target.bits or 64, "exec_name": getattr(target, "filename", "./target"),
                 "mitigations": {}}
        if kind == "format":
            facts.update({"sink": "printf-family", "arg_offset": None, "write_target": None})
            script = exploit_script.render_format_string_exploit(facts)
            proof = ("the script self-calibrates the stack argument offset with a %p probe and "
                     "proves the sink is attacker-controlled by leaking memory (crash-free)")
        else:
            facts.update({"sink": "system/popen/exec", "nav": ""})
            script = exploit_script.render_injection_exploit(facts)
            proof = ("the script confirms BY EFFECT -- a per-run marker appears in the output only "
                     "because the injected command ran, not because the program echoed it")
        review = (
            "# Exploit review\n"
            f"- Source: SYNTHESIZED from a confirmed, attacker-reachable finding at {facts['source']} "
            "-- NOT run or observed here (proven=False).\n"
            f"- Confirmation at runtime: {proof}.\n"
            "- Delivery is a template (stdin / no args): set it to the real attacker entry for this "
            "target before running against a build.\n"
            "- Scope: demonstrates the class without a crash; it is the operator's starting weapon, "
            "not a claim the exploit already landed.")
        sha = ctx.put_artifact("exploit-script", data=script.encode(),
                               meta={"proven": False, "kind": kind, "cwe": f.cwe,
                                     "dedup_key": f.dedup_key, "review": review})
        return sha
    except Exception:                                    # noqa: BLE001 -- weaponization is additive
        _log.debug("script emit failed for %s", f.dedup_key, exc_info=True)
        return None


def _emit_recipe(ctx, target, f, technique: str, level: str) -> bool:
    """File an honest exploitation recipe for a confirmed overflow / integer-overflow finding."""
    try:
        from .poc import recipe
        recipe.file_recipe(
            ctx, target, cwe=f.cwe, technique=technique, target_level=level,
            summary=(f"{technique} at {_source_str(f)} -- the confirmed, attacker-reachable defect "
                     f"weaponizes to {level}; the concrete offset/payload needs the recovered frame "
                     f"from a build of the target."),
            why_not_executed="source-level finding; no build was executed in this environment",
            severity="high", detector="confirm", lead=f,
            blocking_primitive=("a build of the target to recover the concrete stack frame (the "
                                "exact offset / payload) and detonate -- this is a source finding "
                                "with no binary to measure"),
            dedup_key=f"recipe:{f.cwe}:{technique}:{f.dedup_key}")
        return True
    except Exception:                                    # noqa: BLE001
        _log.debug("recipe emit failed for %s", f.dedup_key, exc_info=True)
        return False


def weaponize(ctx, fd: FindingDAO, target, confirmed: list) -> dict:
    """Emit the honest weaponization artifact for each confirmed RCE-capable finding, once."""
    counts: dict = {}
    for f, _gm in confirmed:
        if cwe_coverage.weaponizable(f.cwe) != "rce":
            continue
        if _has_channel(f, "weaponized"):               # already emitted on a prior run
            continue
        ref = None
        if f.cwe in _SCRIPT_EMIT:
            sha = _emit_script(ctx, target, f, _SCRIPT_EMIT[f.cwe])
            if sha:
                ref = f"exploit-script {sha[:12]} ({_SCRIPT_EMIT[f.cwe]}, synthesized)"
                counts[_SCRIPT_EMIT[f.cwe]] = counts.get(_SCRIPT_EMIT[f.cwe], 0) + 1
        elif f.cwe in _RECIPE_EMIT:
            tech, level = _RECIPE_EMIT[f.cwe]
            if _emit_recipe(ctx, target, f, tech, level):
                ref = f"exploitation recipe ({tech}, targets {level})"
                counts["recipe"] = counts.get("recipe", 0) + 1
        if ref:
            fd.upsert(target.id, target.case_id, {
                "cwe": f.cwe, "title": f.title, "severity": f.severity, "detector": f.detector,
                "state": f.state, "confidence": f.confidence, "dedup_key": f.dedup_key,
                "function_addr": f.function_addr, "site_addr": f.site_addr,
                "evidence": [{"channel": "weaponized", "detail": ref}]})
    return counts


def verify_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("verify requires a target_id")
    fd = FindingDAO(ctx.conn)
    ctx.progress(msg="verifying corroborated findings against reach + dataflow + de-noise")
    confirmed = promote(fd, target, ctx.run_id)
    counts = weaponize(ctx, fd, target, confirmed)
    emitted = sum(counts.values())
    ctx.emit("confirm.done", payload={"confirmed": len(confirmed), "weaponized": counts})
    ctx.progress(pct=100, msg=f"{len(confirmed)} confirmed defect(s); {emitted} weaponization "
                              f"artifact(s) emitted {counts}")
    return {"metrics": {"confirmed": len(confirmed), "weaponized_artifacts": emitted}}


def register() -> None:
    register_stage(VERIFY_STAGE, verify_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=180)


def enqueue_verify(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, VERIFY_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="quick", force=force)
