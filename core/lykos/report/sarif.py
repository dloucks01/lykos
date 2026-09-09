"""SARIF 2.1.0 export (doc 08 §8.5) for interop with other tooling/pipelines.

One SARIF run per case: findings become `results`, CWE classes become `rules`,
and each target becomes an `artifact` carrying its sha-256 so results are anchored
to reproducible inputs.
"""
from __future__ import annotations

from typing import Any

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

    for t in report.get("targets", []):
        uri = t.get("filename") or t.get("sha256") or "target.bin"
        if uri not in artifact_index:
            artifact_index[uri] = len(artifacts)
            art: dict[str, Any] = {"location": {"uri": uri}}
            if t.get("sha256"):
                art["hashes"] = {"sha-256": t["sha256"]}
            if t.get("size") is not None:
                art["length"] = t["size"]
            artifacts.append(art)
        a_idx = artifact_index[uri]

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
            msg = f.get("title") or f.get("cwe_name") or cwe
            ev = "; ".join(e.get("detail", "") for e in f.get("evidence", []) if e.get("detail"))
            if ev:
                msg = f"{msg} — {ev}"

            region = {}
            if f.get("site_addr"):
                region = {"properties": {"address": f["site_addr"]}}

            res: dict[str, Any] = {
                "ruleId": cwe,
                "ruleIndex": rule_index[cwe],
                "level": level,
                "message": {"text": msg},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri, "index": a_idx},
                        **({"region": region} if region else {}),
                    },
                    "logicalLocations": _logical(f),
                }],
                "partialFingerprints": {"lykos/dedup": f.get("id", "")},
                "properties": {
                    "state": f.get("state"),
                    "confidence": f.get("confidence"),
                    "detector": f.get("detector"),
                    "security-severity": sec,
                    "poc_backed": bool(f.get("pocs")),
                    "poc_levels": sorted({p.get("level") for p in f.get("pocs", [])
                                          if p.get("verified") and p.get("level")}),
                },
            }
            results.append(res)

    driver: dict[str, Any] = {
        "name": tool.get("name", "lykos"),
        "version": tool.get("version"),
        "informationUri": "https://cwe.mitre.org/",
        "rules": [rules[c] for c in sorted(rules, key=lambda c: rule_index[c])],
    }
    engine_notes = ", ".join(
        f"{e['tool']} {e.get('version') or ''}".strip() for e in report.get("engines", []))
    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "artifacts": artifacts,
        "results": results,
        "properties": {
            "case": report.get("case", {}).get("name"),
            "generated_at": report.get("generated_at"),
            "engines": engine_notes,
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def _logical(f: dict) -> list[dict]:
    out = []
    if f.get("function_addr"):
        out.append({"name": f["function_addr"], "kind": "function"})
    return out
