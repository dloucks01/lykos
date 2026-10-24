"""SARIF 2.1.0 export (doc 08 §8.5) for interop with other tooling/pipelines.

One SARIF run per case: findings become `results`, CWE classes become `rules`,
and each target becomes an `artifact` carrying its sha-256 so results are anchored
to reproducible inputs.
"""
from __future__ import annotations

import hashlib
from typing import Any, Optional
from urllib.parse import quote

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# finding severity -> (SARIF level, GitHub security-severity numeric band)
_LEVEL = {
    "critical": ("error", "9.5"),
    "high": ("error", "8.0"),
    "medium": ("warning", "5.5"),
    "low": ("note", "3.0"),
    "info": ("note", "1.0"),
}


def _level(sev: str) -> tuple[str, str]:
    return _LEVEL.get(sev or "info", ("note", "1.0"))


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    tool = report.get("tool", {})
    rules: dict[str, dict] = {}
    rule_index: dict[str, int] = {}
    results: list[dict] = []
    artifacts: list[dict] = []
    artifact_index: dict[str, int] = {}

    notifications: list[dict] = []
    any_failure = False
    for t in report.get("targets", []):
        # A URI REFERENCE, so a filename with a space, '#' or '%' has to be percent-encoded --
        # emitted raw it is an invalid (or silently truncated, at '#') artifact location.
        uri = quote(str(t.get("filename") or t.get("sha256") or "target.bin"), safe="/._-~")
        # Keyed by CONTENT, not name: two different binaries both called `server` used to share
        # one artifact entry, and the second one's results were anchored to the first one's hash.
        akey = t.get("sha256") or uri
        if akey not in artifact_index:
            artifact_index[akey] = len(artifacts)
            art: dict[str, Any] = {"location": {"uri": uri}}
            if t.get("sha256"):
                art["hashes"] = {"sha-256": t["sha256"]}
            if isinstance(t.get("size"), int) and t["size"] >= 0:
                art["length"] = t["size"]
            artifacts.append(art)
        a_idx = artifact_index[akey]
        failed, notes = _target_notifications(t, a_idx, uri)
        any_failure = any_failure or failed
        notifications.extend(notes)

        for f in t.get("findings", []):
            cwe = f.get("cwe") or "GENERIC"
            if cwe not in rule_index:
                rule_index[cwe] = len(rules)
                rules[cwe] = {
                    "id": cwe,
                    "name": (f.get("cwe_name") or cwe).replace(" ", ""),
                    "shortDescription": {"text": f.get("cwe_name") or cwe},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html"
                    if cwe.startswith("CWE-") else None,
                    "properties": {
                        "cwe": [cwe] if cwe.startswith("CWE-") else [],
                        "security-severity": _level(f.get("severity"))[1],
                    },
                }
                if rules[cwe]["helpUri"] is None:
                    rules[cwe].pop("helpUri")

            level, sec = _level(f.get("severity"))
            # "detected" is not "demonstrated", and SARIF is read by machines: a `candidate` is
            # an unproven pattern match, so emitting it at a severity-derived `error` made an
            # advisory indistinguishable from a reproduced crash in CI, where `error` fails a
            # build. Cap an unproven finding at `warning` and leave everything a channel has
            # actually corroborated, confirmed or proven at its own level. The `state` property
            # below still carries the full truth for a consumer that wants it.
            if f.get("state") == "candidate" and level == "error":
                level = "warning"
            msg = f.get("title") or f.get("cwe_name") or cwe
            ev = "; ".join(e.get("detail", "") for e in f.get("evidence", []) if e.get("detail"))
            if ev:
                msg = f"{msg} — {ev}"

            # A binary location is an ADDRESS (SARIF 3.32), not a region: a `region` SHALL carry
            # startLine/charOffset/byteOffset (3.30.2), and one holding only a property bag was
            # a schema-valid but spec-invalid location that consumers discard.
            phys: dict[str, Any] = {"artifactLocation": {"uri": uri, "index": a_idx}}
            addr = _address(f.get("site_addr"))
            if addr is not None:
                phys["address"] = {"absoluteAddress": addr, "kind": "instruction"}
            loc: dict[str, Any] = {"physicalLocation": phys}
            logical = _logical(f)
            if logical:
                loc["logicalLocations"] = logical
            if f.get("site_addr"):
                loc["properties"] = {"address": f["site_addr"]}

            res: dict[str, Any] = {
                "ruleId": cwe,
                "ruleIndex": rule_index[cwe],
                "level": level,
                "message": {"text": msg},
                "locations": [loc],
                # STABLE across runs and cases, which is what a fingerprint is for: the finding's
                # row id is a fresh uuid every time a case is analysed, so keying on it made every
                # re-scan of the same binary look like all-new alerts to a code-scanning consumer.
                "partialFingerprints": {"lykosFindingHash/v1": _fingerprint(t, f)},
                "properties": {
                    "finding_id": f.get("id"),
                    # The highest rung a VERIFIED PoC reached -- the same level the HTML/PDF claim.
                    "impact_level": f.get("level") or None,
                    "state": f.get("state"),
                    # Structured, not stringified into the message a reader sees: this blob
                    # used to land verbatim in a GitHub code-scanning alert.
                    "effects": f.get("effects") or [],
                    "confidence": f.get("confidence"),
                    "detector": f.get("detector"),
                    "security-severity": sec,
                    "poc_backed": bool(f.get("pocs")),
                    "poc_levels": sorted({p.get("level") for p in f.get("pocs", [])
                                          if p.get("verified") and p.get("level")}),
                },
            }
            cur = f.get("curation") or {}
            if cur.get("status") or cur.get("note"):
                res["properties"]["curation"] = cur
            # Operator triage in SARIF's own vocabulary, so a code-scanning consumer honours it:
            # a false positive is an ACCEPTED external suppression (kept, not deleted). Every
            # other verdict (true positive, needs review) rides in `properties.curation` only --
            # a suppression of any status can hide an alert, and those are not dismissals. The
            # tool's level/state are untouched.
            if cur.get("status") == "false_positive":
                sup: dict[str, Any] = {"kind": "external", "status": "accepted"}
                if cur.get("note"):
                    sup["justification"] = cur["note"]
                res["suppressions"] = [sup]
            results.append(res)

    driver: dict[str, Any] = {
        "name": tool.get("name") or "lykos",
        "informationUri": "https://cwe.mitre.org/",
        "rules": [rules[c] for c in sorted(rules, key=lambda c: rule_index[c])],
    }
    # `version` is a string in the schema; a null one made the whole log schema-invalid.
    if tool.get("version"):
        driver["version"] = str(tool["version"])
    engine_notes = ", ".join(
        f"{e.get('tool')} {e.get('version') or ''}".strip() for e in report.get("engines", []))
    summ = report.get("summary") or {}
    # The run's HONESTY record: a SARIF consumer sees only `results`, so a static-only run where no
    # dynamic engine could execute the target was indistinguishable from a clean dynamic pass.
    # `invocations` is where SARIF carries "the tool did not fully execute", with a notification
    # per failed/declined engine and per execution that never happened.
    invocation: dict[str, Any] = {
        "executionSuccessful": not any_failure,
        "toolExecutionNotifications": notifications,
    }
    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "invocations": [invocation],
        "artifacts": artifacts,
        "results": results,
        "properties": {
            "case": report.get("case", {}).get("name"),
            "generated_at": report.get("generated_at"),
            "engines": engine_notes,
            "highest_level": summ.get("highest_level") or None,
            "engine_health": summ.get("engine_health"),
            "curation": summ.get("curation") or {},
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def _address(v) -> Optional[int]:
    """A site address as an integer (SARIF `absoluteAddress`), or None if it is not one."""
    if isinstance(v, int) and not isinstance(v, bool):
        return v if v >= 0 else None
    if not isinstance(v, str) or not v.strip():
        return None
    try:
        n = int(v.strip(), 16 if v.strip().lower().startswith("0x") else 10)
    except ValueError:
        return None
    return n if n >= 0 else None


def _fingerprint(t: dict, f: dict) -> str:
    """A stable identity for a finding: the target's content hash, the class, the detector and
    the location. Same binary + same defect -> same fingerprint, across runs and cases."""
    where = f.get("site_addr") or f.get("function_addr") or f.get("title") or ""
    key = "\x00".join(str(x or "") for x in (
        t.get("sha256") or t.get("filename"), f.get("cwe"), f.get("detector"), where))
    return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()


#: engine status -> SARIF notification level
_NOTE_LEVEL = {"failed": "error", "error": "error", "noprogress": "warning",
               "starved": "warning", "no_gain": "note", "declined": "note", "skipped": "note"}


def _target_notifications(t: dict, a_idx: int, uri: str) -> tuple:
    """(execution_failed, [toolExecutionNotification]) for one target, from the report model's
    engine health and execution record."""
    out: list[dict] = []
    ex = t.get("execution") or {}
    eh = t.get("engine_health") or {}
    loc = [{"physicalLocation": {"artifactLocation": {"uri": uri, "index": a_idx}}}]

    def note(level, text, desc_id):
        out.append({"level": level, "message": {"text": text}, "locations": loc,
                    "descriptor": {"id": desc_id}})
    failed = False
    hv = eh.get("verdict")
    if hv in ("none", "degraded"):
        failed = True
        note("error" if hv == "none" else "warning",
             f"{t.get('filename')}: dynamic engine health {hv} -- {eh.get('note') or ''}".strip(),
             "lykos/engine-health")
    elif hv == "unrecorded":
        note("warning", f"{t.get('filename')}: {eh.get('note') or 'no engine-health record'}",
             "lykos/engine-health")
    for e in eh.get("engines") or []:
        lvl = _NOTE_LEVEL.get(e.get("status"))
        if not lvl:
            continue
        if lvl == "error":
            failed = True
        note(lvl, f"{t.get('filename')}: {e.get('engine')} {e.get('status')}"
                  + (f" -- {e['reason']}" if e.get("reason") else ""), "lykos/engine")
    base = ex.get("baseline")
    if base is not None and not base.get("ran"):
        failed = True
        note("error", f"{t.get('filename')}: the baseline execution never started the target "
                      f"({base.get('note') or base.get('isolation') or 'no reason given'})",
             "lykos/did-not-run")
    if ex.get("did_not_run_count"):
        failed = True
        note("error", f"{t.get('filename')}: {ex['did_not_run_count']} execution(s) never ran",
             "lykos/did-not-run")
    for st in ex.get("failed_stages") or []:
        failed = True
        note("error", f"{t.get('filename')}: stage {st} failed", "lykos/stage-failed")
    return failed, out


def _logical(f: dict) -> list[dict]:
    out = []
    if f.get("function_addr"):
        out.append({"name": f["function_addr"], "kind": "function"})
    return out
