"""Crash triage for the web GUI: one row per ROOT CAUSE, ranked, linked to its finding / PoC.

A fuzzing run can record hundreds of crashing inputs that are a handful of bugs. The raw
`/dynresults` list shows each input; this groups them with the SAME bucket key the autopilot's
prove loop uses (`orchestrate._crash_representatives`), so "47 crashes" reads as "3 defects, 40 +
5 + 2 inputs", and each defect carries what the run made of it:

  * bucket key -- `(signal, sanitizer defect_key)` when a sanitizer classified it, else
    `(signal, fault_pc)`, else `(signal, None, channel)` for a crash with no PC (a hijacked
    return, an emulated target) -- the same separation the prove loop applies;
  * the BEST VERIFIED level any PoC built from one of the group's inputs reached. An unverified
    PoC level is reported separately, as a candidate, and never as the group's level -- the GUI
    must not overstate what was demonstrated;
  * the exploitability rating recorded on the linked finding(s), and the finding(s) themselves,
    so the operator can jump from a crash group straight to its evidence.

Pure functions over the API's own serialized rows (`_dynresult` + `defect_key`, `_finding`,
`_poc`). Unlike `_crash_representatives` this never re-runs the target to recover a missing fault
PC -- a read endpoint has no business executing anything -- so a group whose PC could not be read
says so (`resolved: False`) rather than pretending to be one defect.
"""
from __future__ import annotations

import re
from typing import Any, Optional

#: Finding states, strongest first (mirrors the GUI's STATE_ORDER).
_STATE_RANK = {"poc-backed": 4, "confirmed": 3, "corroborated": 2, "candidate": 1}
_EXPLOIT_RE = re.compile(r"exploitability:\s*([A-Z_]+)\s*\((\d+)/100\)\s*(?:--\s*)?(.*)")
#: How many member inputs a group lists (the count is always exact).
_MAX_INPUTS = 20


def _level_num(level) -> int:
    m = re.search(r"(\d)", str(level or ""))
    return int(m.group(1)) if m else 0


def _channel(d: dict) -> str:
    """The delivery channel a crash was found on (orchestrate._crash_channel)."""
    if "prompted" in (d.get("isolation") or ""):
        return "prompt"
    return d.get("input_mode") or "stdin"


def bucket_key(d: dict) -> tuple:
    """The prove loop's bucket for one crashing row."""
    sig = d.get("signal") or "?"
    if d.get("defect_key"):
        return (sig, "defect", d["defect_key"])
    if d.get("fault_pc"):
        return (sig, "pc", str(d["fault_pc"]).lower())
    return (sig, "unresolved", _channel(d))


def _exploitability(f: dict) -> Optional[dict]:
    for e in f.get("evidence") or []:
        if isinstance(e, dict) and e.get("channel") == "exploitability":
            m = _EXPLOIT_RE.search(e.get("detail") or "")
            if m:
                return {"rating": m.group(1), "score": int(m.group(2)), "why": m.group(3)[:200]}
            return {"rating": None, "score": None, "why": (e.get("detail") or "")[:200]}
    return None


def _finding_inputs(f: dict) -> set:
    out = set()
    for e in f.get("evidence") or []:
        if isinstance(e, dict) and e.get("input_sha"):
            out.add(e["input_sha"])
    return out


def _dedup_keys(key: tuple) -> set:
    """The crash-finding dedup keys a bucket can have been filed under (dynamic.crash_dedup_key)."""
    sig, kind, val = key
    if kind == "defect":
        return {f"dynamic-crash:{sig}:{val}"}
    if kind == "pc":
        try:
            return {f"dynamic-crash:{sig}:{int(val, 16):x}"}
        except ValueError:
            return set()
    return set()                     # an unresolved bucket matches no specific finding by key


def crash_groups(dyns: list[dict], findings: list[dict], pocs: list[dict], *,
                 prove_cap: Optional[int] = None) -> dict[str, Any]:
    """Group crashing rows by root cause and rank the groups.

    Rank: best VERIFIED level desc, then exploitability score desc, then the strongest linked
    finding's state, then how many inputs hit it. Returns {groups, crashes, distinct, prove_cap}.
    """
    crashing = [d for d in dyns or [] if d.get("crashed")]
    groups: dict = {}
    for d in crashing:
        k = bucket_key(d)
        g = groups.get(k)
        if g is None:
            g = groups[k] = {"key": k, "rows": []}
        g["rows"].append(d)
    poc_by_input: dict = {}
    for p in pocs or []:
        if p.get("input_sha"):
            poc_by_input.setdefault(p["input_sha"], []).append(p)
    by_id = {f.get("id"): f for f in findings or []}
    f_inputs = {f.get("id"): _finding_inputs(f) for f in findings or []}
    by_dedup: dict = {}
    for f in findings or []:
        if f.get("dedup_key"):
            by_dedup.setdefault(f["dedup_key"], []).append(f)
    out = []
    for g in groups.values():
        sig, kind, val = g["key"]
        rows = g["rows"]
        inputs = [r["input_sha"] for r in rows if r.get("input_sha")]
        uniq_inputs = list(dict.fromkeys(inputs))
        iset = set(uniq_inputs)
        gpocs = [p for s in uniq_inputs for p in poc_by_input.get(s, [])]
        linked: dict = {}
        for p in gpocs:
            if p.get("finding_id") in by_id:
                linked[p["finding_id"]] = by_id[p["finding_id"]]
        for fid, ins in f_inputs.items():
            if ins & iset:
                linked[fid] = by_id[fid]
        for dk in _dedup_keys(g["key"]):
            for f in by_dedup.get(dk, []):
                linked[f.get("id")] = f
        verified = [p for p in gpocs if p.get("verified")]
        best = max((_level_num(p.get("level")) for p in verified), default=0)
        cand = max((_level_num(p.get("level")) for p in gpocs if not p.get("verified")),
                   default=0)
        best_poc = max(verified, key=lambda p: (_level_num(p.get("level")),
                                                 bool(p.get("bundle_sha"))), default=None)
        expl = None
        for f in linked.values():
            x = _exploitability(f)
            if x and (expl is None or (x.get("score") or -1) > (expl.get("score") or -1)):
                expl = x
        flist = sorted(linked.values(),
                       key=lambda f: -_STATE_RANK.get(f.get("state") or "", 0))
        # Representative: the input a verified PoC was built from, else the newest crash with one.
        rep = (best_poc or {}).get("input_sha") or (uniq_inputs[0] if uniq_inputs else None)
        rep_row = next((r for r in rows if r.get("input_sha") == rep), rows[0])
        out.append({
            "signal": sig,
            "fault_pc": val if kind == "pc" else None,
            "defect_key": val if kind == "defect" else None,
            "channel": _channel(rep_row),
            "resolved": kind != "unresolved",
            "count": len(rows),
            "inputs": uniq_inputs[:_MAX_INPUTS],
            "input_count": len(uniq_inputs),
            "representative": rep,
            "argv": rep_row.get("argv") or [],
            "isolation": rep_row.get("isolation"),
            "best_level": best,                   # verified only
            "candidate_level": cand if cand > best else 0,
            "poc": ({"id": best_poc.get("id"), "level": best_poc.get("level"),
                     "bundle_sha": best_poc.get("bundle_sha"),
                     "input_sha": best_poc.get("input_sha")} if best_poc else None),
            "exploitability": expl,
            "findings": [{"id": f.get("id"), "title": f.get("title"), "cwe": f.get("cwe"),
                          "state": f.get("state"), "severity": f.get("severity")}
                         for f in flist[:5]],
            "first_seen": min((r.get("created_at") or 0) for r in rows),
        })
    out.sort(key=lambda g: (
        -g["best_level"],
        -((g["exploitability"] or {}).get("score") or -1),
        -max((_STATE_RANK.get(f["state"] or "", 0) for f in g["findings"]), default=0),
        -g["count"],
        g["first_seen"]))
    for i, g in enumerate(out):
        g["rank"] = i + 1
    # The autopilot proves at most `prove_cap` distinct crashes per target. Over it, a group with
    # no level may simply never have been worked on -- which is not "not exploitable" -- so the
    # GUI says so once, for the whole list (which groups the prove loop took is its own ranking).
    return {"groups": out, "crashes": len(crashing), "distinct": len(out),
            "prove_cap": prove_cap,
            "over_prove_cap": bool(prove_cap and len(out) > prove_cap)}
