"""Durable autopilot run history + run-to-run comparison.

The server-side autopilot keeps its live status in memory only (api.autopilot._AUTOPILOTS), so a
restart forgot every run and nothing recorded what a past run did. This module writes a durable
RUN RECORD into the case store at the run's start and end -- an ``autopilot-run`` artifact (JSON
blob; the summary also lives in the artifact row's meta so a listing never reads the blobs) plus an
``autopilot.run_recorded`` event -- and compares two records, possibly from DIFFERENT cases (two
cases of the same source tree, two rebuilds of one program).

Comparability is the point, so each finding in a record's end-of-run SNAPSHOT carries an identity
key that names the BUG, not the database row: target ids and binary hashes change on every rebuild,
so the key uses the source site (``CWE | basename:line``) when the finding has one, and otherwise
``CWE | detector | function | normalised title`` (+ the target FILENAME for a binary-only finding).

Nothing here carries a server filesystem path: overrides are scrubbed, site files are
tree-relative (an absolute one is cut to its basename), and titles have absolute paths reduced to
basenames. Read-only callers (the API) never write; only the autopilot's start/end hooks do.
"""
from __future__ import annotations

import json
import logging
import re
import time
import uuid
from collections import Counter
from typing import Any, Optional

_log = logging.getLogger(__name__)

KIND = "autopilot-run"
EVENT = "autopilot.run_recorded"
SNAPSHOT_CAP = 20000
SYNTH_PREFIX = "current:"

STATE_RANK = {"candidate": 0, "corroborated": 1, "confirmed": 2, "poc-backed": 3}
LEVEL_RANK = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# status["state"] at the end of run_case_autopilot -> the recorded outcome. Anything else (still
# "running" when the finally ran: a BaseException tore the thread down) is an interrupted run.
_OUTCOME = {"done": "done", "cancelled": "stopped", "stopped": "stopped", "error": "error"}

_ABS_PATH = re.compile(r"(?<![\w.])(?:~/|/)(?:[\w.+@-]+/)+([\w.+@-]+)")
_PATHY_KEY = re.compile(r"(path|dir|file|root|sysroot|prefix)", re.I)
_HEX = re.compile(r"0x[0-9a-fA-F]+")
_LONGNUM = re.compile(r"\b\d{4,}\b")


# ---------------------------------------------------------------------------------- scrubbing
def scrub_text(s: Optional[str], limit: int = 240) -> Optional[str]:
    """`s` with every absolute path reduced to its basename, bounded."""
    if s is None:
        return None
    s = _ABS_PATH.sub(lambda m: m.group(1), str(s))
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _scrub_val(v: Any) -> Any:
    if isinstance(v, str):
        return "<path>" if v.startswith(("/", "~")) else scrub_text(v, 200)
    if isinstance(v, (list, tuple)):
        return [_scrub_val(x) for x in list(v)[:64]]
    if isinstance(v, dict):
        return scrub_overrides(v)
    if isinstance(v, (int, float, bool)) or v is None:
        return v
    return scrub_text(str(v), 120)


def scrub_overrides(over: Optional[dict]) -> dict:
    """The run's overrides minus anything path-like: keys that name a path/dir/file (the CLI-only
    seed_files / seed_dir / sysroot channels, among others) are dropped, and an absolute-path
    string anywhere is replaced by a placeholder."""
    out: dict = {}
    for k, v in (over or {}).items():
        if _PATHY_KEY.search(str(k)):
            if k == "seed_files" and isinstance(v, (list, tuple)):
                out["seeds"] = len(v)                 # how many, never where
            continue
        out[str(k)] = _scrub_val(v)
    return out


def _rel_site_file(fp: Optional[str]) -> Optional[str]:
    if not fp:
        return None
    fp = str(fp)
    if fp.startswith(("/", "~")):
        return fp.rsplit("/", 1)[-1]
    return fp[2:] if fp.startswith("./") else fp


def _base(fp: Optional[str]) -> str:
    return (fp or "").rsplit("/", 1)[-1]


def norm_title(title: Optional[str]) -> str:
    t = scrub_text(title or "", 400) or ""
    t = _HEX.sub("0x_", t)
    t = _LONGNUM.sub("#", t)
    return re.sub(r"\s+", " ", t).strip().lower()


# ---------------------------------------------------------------------------------- snapshot
def _site_and_fn(f) -> tuple:
    """(file, line, function) a finding names, from its evidence; best-effort, no tree reads."""
    try:
        from .dedup import parse_fn, parse_loc
        fp, line = parse_loc(f.evidence)
        fn = parse_fn(f.evidence)
    except Exception:                                   # noqa: BLE001 -- odd evidence = no site
        fp, line, fn = None, None, None
    return _rel_site_file(fp), line, fn


def identity_key(cwe, detector, title, site_file, line, fn, target_filename) -> str:
    """The cross-case/rebuild identity of a finding's BUG (see module doc)."""
    cwe = cwe or "CWE-unknown"
    if site_file and line:
        return f"{cwe}|{_base(site_file)}:{int(line)}"
    if site_file:
        return f"{cwe}|{_base(site_file)}|{fn or ''}|{detector or ''}|{norm_title(title)}"
    return f"{cwe}|bin:{target_filename or ''}|{detector or ''}|{fn or ''}|{norm_title(title)}"


def _best_pocs(store, target_ids) -> dict:
    """finding_id -> (best level, provenance) over the PoCs that RAN (verified / detonated) first,
    else the best constructed one."""
    from ..db.dao import PocDAO
    pd = PocDAO(store.conn)
    best: dict = {}
    for tid in target_ids:
        try:
            pocs = pd.list_by_target(tid)
        except Exception:                               # noqa: BLE001
            continue
        for p in pocs:
            if not p.finding_id:
                continue
            ran = bool(p.verified or p.provenance == "detonated")
            lvl = str(p.level or "").upper()
            if lvl and not lvl.startswith("L"):
                lvl = "L" + lvl
            score = (1 if ran else 0, LEVEL_RANK.get(lvl, -1))
            cur = best.get(p.finding_id)
            if cur is None or score > cur[0]:
                best[p.finding_id] = (score, lvl if lvl in LEVEL_RANK else None,
                                      "detonated" if ran else (p.provenance or "constructed"))
    return {k: (v[1], v[2]) for k, v in best.items()}


def _addr_int(a):
    try:
        a = str(a).strip().lower()
        return int(a, 16) if a.startswith("0x") else int(a)
    except (TypeError, ValueError):
        return None


def _fn_names(store, target_id) -> dict:
    """int(addr) -> function name (addresses are stored as hex or decimal strings)."""
    try:
        return {_addr_int(r[0]): r[1] for r in store.conn.execute(
            "SELECT addr, name FROM function WHERE target_id=?", (target_id,)) if r[1]}
    except Exception:                                   # noqa: BLE001
        return {}


def build_snapshot(store, case_id: str) -> dict:
    """The case's findings NOW, one entry per distinct identity key (co-keyed rows merge: best
    state / level / severity kept, `n` counts them). Bounded to SNAPSHOT_CAP entries, strongest
    first. Also returns per-target counts (by filename) and totals."""
    from ..db.dao import FindingDAO
    targets = {t.id: t for t in store.targets.list_by_case(case_id)}
    fs = FindingDAO(store.conn).list_by_case(case_id)
    pocs = _best_pocs(store, list(targets))
    fnames: dict = {}
    by_key: dict = {}
    per_t: dict = {}
    for f in fs:
        t = targets.get(f.target_id)
        tfile = t.filename if t else None
        site_file, line, fn = _site_and_fn(f)
        if not fn and not site_file and f.function_addr:
            if f.target_id not in fnames:
                fnames[f.target_id] = _fn_names(store, f.target_id)
            fn = fnames[f.target_id].get(_addr_int(f.function_addr))
        key = identity_key(f.cwe, f.detector, f.title, site_file, line, fn, tfile)
        lvl, prov = pocs.get(f.id, (None, None))
        state = f.state or "candidate"
        if site_file:
            site = f"{site_file}:{line}" if line else (f"{site_file}: {fn}()" if fn else site_file)
        else:
            site = (fn or "") + (f" @ {f.site_addr or f.function_addr}"
                                 if (f.site_addr or f.function_addr) else "")
            site = site.strip()
            site = (f"{tfile}: {site}" if tfile else site) if site else None
        e = by_key.get(key)
        if e is None:
            by_key[key] = {"key": key, "cwe": f.cwe, "title": scrub_text(f.title, 200),
                           "state": state, "severity": f.severity, "detector": f.detector,
                           "site": scrub_text(site, 200), "level": lvl, "poc": prov, "n": 1,
                           "targets": [tfile] if tfile else [], "fid": f.id}
        else:
            e["n"] += 1
            if STATE_RANK.get(state, 0) > STATE_RANK.get(e["state"], 0):
                e["state"], e["fid"] = state, f.id
            if LEVEL_RANK.get(lvl or "", -1) > LEVEL_RANK.get(e["level"] or "", -1):
                e["level"], e["poc"] = lvl, prov
            if _SEV_RANK.get(f.severity or "", 0) > _SEV_RANK.get(e["severity"] or "", 0):
                e["severity"] = f.severity
            if tfile and tfile not in e["targets"] and len(e["targets"]) < 6:
                e["targets"].append(tfile)
        pt = per_t.setdefault(tfile or f.target_id, {"filename": tfile, "findings": 0,
                                                     "confirmed": 0, "poc_backed": 0})
        pt["findings"] += 1
        if state == "confirmed":
            pt["confirmed"] += 1
        elif state == "poc-backed":
            pt["poc_backed"] += 1
    for t in targets.values():                         # a target with no findings still counts
        per_t.setdefault(t.filename or t.id, {"filename": t.filename, "findings": 0,
                                              "confirmed": 0, "poc_backed": 0})
    entries = sorted(by_key.values(), key=_entry_rank)
    truncated = max(0, len(entries) - SNAPSHOT_CAP)
    entries = entries[:SNAPSHOT_CAP]
    return {"findings": entries, "truncated": truncated,
            "counts": _counts(entries, raw=len(fs)),
            "per_target": sorted(per_t.values(), key=lambda r: str(r.get("filename") or "")),
            "targets": [{"id": t.id, "filename": t.filename} for t in targets.values()]}


def _entry_rank(e) -> tuple:
    return (-LEVEL_RANK.get(e.get("level") or "", -1), -STATE_RANK.get(e.get("state") or "", 0),
            -_SEV_RANK.get(e.get("severity") or "", 0), str(e.get("cwe") or ""),
            str(e.get("site") or ""), e["key"])


def _counts(entries, raw: int) -> dict:
    st = Counter(e["state"] for e in entries)
    return {"findings": raw, "distinct": len(entries), "confirmed": st.get("confirmed", 0),
            "poc_backed": st.get("poc-backed", 0),
            "with_poc": sum(1 for e in entries if e.get("level"))}


# ---------------------------------------------------------------------------------- recording
def _write(store, case_id: str, rec: dict, phase: str) -> None:
    summary = {k: v for k, v in rec.items() if k != "snapshot"}
    summary["phase"] = phase
    blob = dict(rec, phase=phase)
    store.put_artifact(case_id, KIND, data=json.dumps(blob, sort_keys=True).encode("utf-8"),
                       meta=summary)
    store.events.append(EVENT, case_id=case_id,
                        payload={"run_id": rec["run_id"], "phase": phase,
                                 "outcome": rec.get("outcome"),
                                 "findings": (rec.get("counts") or {}).get("findings")})


def record_start(store, case_id: str, target_ids, status: dict, *, overrides=None,
                 budget_seconds=None, converge=False, skip_stages=None) -> Optional[dict]:
    """Write the run's START record; return it (the end hook completes it). Never raises."""
    try:
        run_id = uuid.uuid4().hex
        status["run_id"] = run_id
        case = store.cases.get(case_id)
        tg = []
        for tid in target_ids or []:
            t = store.targets.get(tid)
            tg.append({"id": tid, "filename": t.filename if t else None})
        rec = {"run_id": run_id, "case_id": case_id, "case_name": case.name if case else None,
               "started": status.get("started") or time.time(), "ended": None,
               "outcome": "running", "budget_seconds": budget_seconds,
               "converge": bool(converge), "skip_stages": list(skip_stages or []),
               "overrides": scrub_overrides(overrides), "targets": tg}
        _write(store, case_id, rec, "start")
        return rec
    except Exception:                                   # noqa: BLE001 -- history never fails a run
        _log.debug("run-history start record failed", exc_info=True)
        return None


def record_end(store, case_id: str, rec: Optional[dict], status: dict) -> None:
    """Complete and write the run's END record (normal finish, stop, or error). Never raises."""
    if not rec:
        return
    try:
        rec = dict(rec)
        rec["ended"] = time.time()
        rec["outcome"] = _OUTCOME.get(str(status.get("state")), "interrupted")
        if status.get("outcome"):
            rec["result"] = status.get("outcome")         # poc / crash / static
        if status.get("error"):
            rec["error"] = scrub_text(status.get("error"), 400)
        rec["per_target"] = [
            {k: r.get(k) for k in ("target_id", "filename", "stages", "skipped_for_budget",
                                   "elapsed", "findings", "poc_backed", "confirmed")}
            for r in (status.get("per_target") or [])][:500]
        if status.get("targets_skipped_for_budget"):
            rec["targets_skipped_for_budget"] = [
                scrub_text(x, 120) for x in status["targets_skipped_for_budget"]][:500]
        if status.get("target_errors"):
            rec["target_errors"] = len(status["target_errors"])
        snap = build_snapshot(store, case_id)
        rec["counts"] = snap["counts"]
        rec["snapshot"] = {"findings": snap["findings"], "truncated": snap["truncated"],
                           "scope": "case"}
        _write(store, case_id, rec, "end")
    except Exception:                                   # noqa: BLE001
        _log.debug("run-history end record failed", exc_info=True)


# ---------------------------------------------------------------------------------- reading
def _rows(store, case_id: Optional[str] = None):
    q = "SELECT sha256, case_id, meta_json, created_at FROM artifact WHERE kind=?"
    args: list = [KIND]
    if case_id is not None:
        q += " AND case_id=?"
        args.append(case_id)
    for r in store.conn.execute(q, args).fetchall():
        try:
            meta = json.loads(r[2]) if r[2] else {}
        except ValueError:
            continue
        if isinstance(meta, dict) and meta.get("run_id"):
            yield r[0], r[1], meta


def _merge(rows) -> dict:
    """run_id -> (sha of the authoritative blob, summary): the END record wins over the START."""
    out: dict = {}
    for sha, _cid, meta in rows:
        cur = out.get(meta["run_id"])
        if cur is None or (meta.get("phase") == "end" and cur[1].get("phase") != "end"):
            out[meta["run_id"]] = (sha, meta)
    return out


def _live_run_ids() -> set:
    """Run ids whose autopilot thread is alive in THIS server process."""
    try:
        from ..api.autopilot import AutopilotMixin
        with AutopilotMixin._AUTOPILOTS_LOCK:
            return {r["status"].get("run_id") for r in AutopilotMixin._AUTOPILOTS.values()
                    if r.get("thread") is not None and r["thread"].is_alive()}
    except Exception:                                   # noqa: BLE001
        return set()


def _finish_summary(meta: dict, live: set) -> dict:
    d = dict(meta)
    if d.get("phase") != "end":
        # a START with no END: still running here, or the server went down mid-run
        d["outcome"] = "running" if d.get("run_id") in live else "interrupted"
    d.pop("phase", None)
    d["synthetic"] = False
    return d


def synthetic_record(store, case_id: str, *, with_snapshot: bool = True) -> Optional[dict]:
    """A "current state" pseudo-run built from the case DB now -- so a case with no recorded run
    (or any case, as of now) can be compared immediately."""
    case = store.cases.get(case_id)
    if not case:
        return None
    snap = build_snapshot(store, case_id)
    rec = {"run_id": SYNTH_PREFIX + case_id, "case_id": case_id, "case_name": case.name,
           "synthetic": True, "started": None, "ended": time.time(), "outcome": "current",
           "budget_seconds": None, "targets": snap["targets"], "per_target": snap["per_target"],
           "counts": snap["counts"]}
    if with_snapshot:
        rec["snapshot"] = {"findings": snap["findings"], "truncated": snap["truncated"],
                           "scope": "case"}
    return rec


def list_runs(store, case_id: str) -> list:
    """The case's recorded runs, newest first (no snapshots), then the synthetic current state."""
    live = _live_run_ids()
    runs = [_finish_summary(m, live) for _sha, m in _merge(_rows(store, case_id)).values()]
    runs.sort(key=lambda r: -(r.get("started") or 0))
    cur = synthetic_record(store, case_id, with_snapshot=False)
    if cur:
        runs.append(cur)
    return runs


def get_run(store, run_id: str) -> Optional[dict]:
    """One record WITH its snapshot (the synthetic `current:<case>` id is built on the fly)."""
    if run_id.startswith(SYNTH_PREFIX):
        return synthetic_record(store, run_id[len(SYNTH_PREFIX):])
    hits = [(sha, m) for sha, _c, m in _rows(store) if m.get("run_id") == run_id]
    if not hits:
        return None
    sha, meta = _merge((s, None, m) for s, m in hits)[run_id]
    try:
        rec = json.loads(store.content.get_bytes(sha))
    except Exception:                                   # noqa: BLE001 -- blob gone: summary only
        rec = dict(meta)
    out = _finish_summary(rec, _live_run_ids())
    out.setdefault("snapshot", {"findings": [], "truncated": 0, "scope": "case"})
    return out


# ---------------------------------------------------------------------------------- compare
def _brief(e: dict) -> dict:
    return {k: e.get(k) for k in ("key", "cwe", "title", "site", "detector", "state", "level",
                                  "severity", "n", "targets", "fid")}


def compare(a: dict, b: dict, cap: int = 5000) -> dict:
    """What changed from run A to run B: findings NEW in B, GONE from A, CHANGED (state or PoC
    level moved), the unchanged count, and per-target count deltas matched by filename."""
    fa = {e["key"]: e for e in (a.get("snapshot") or {}).get("findings") or []}
    fb = {e["key"]: e for e in (b.get("snapshot") or {}).get("findings") or []}
    new = [_brief(fb[k]) for k in fb if k not in fa]
    gone = [_brief(fa[k]) for k in fa if k not in fb]
    changed, same = [], 0
    for k in fa.keys() & fb.keys():
        x, y = fa[k], fb[k]
        if x.get("state") == y.get("state") and x.get("level") == y.get("level"):
            same += 1
            continue
        up = ((LEVEL_RANK.get(y.get("level") or "", -1), STATE_RANK.get(y.get("state"), 0))
              > (LEVEL_RANK.get(x.get("level") or "", -1), STATE_RANK.get(x.get("state"), 0)))
        d = _brief(y)
        d["from"] = {"state": x.get("state"), "level": x.get("level")}
        d["to"] = {"state": y.get("state"), "level": y.get("level")}
        d["direction"] = "up" if up else "down"
        changed.append(d)
    new.sort(key=_entry_rank)
    gone.sort(key=_entry_rank)
    changed.sort(key=lambda d: (0 if d["direction"] == "up" else 1,) + _entry_rank(d))

    def _pt(rec):
        return {(r.get("filename") or r.get("target_id")): r for r in rec.get("per_target") or []}
    pa, pb = _pt(a), _pt(b)
    delta = []
    for fn in sorted(set(pa) | set(pb), key=lambda s: str(s)):
        ra, rb = pa.get(fn) or {}, pb.get(fn) or {}
        row = {"filename": fn,
               "a": {k: ra.get(k) for k in ("findings", "confirmed", "poc_backed", "elapsed")} if ra else None,
               "b": {k: rb.get(k) for k in ("findings", "confirmed", "poc_backed", "elapsed")} if rb else None}
        row["delta"] = {k: (rb.get(k) or 0) - (ra.get(k) or 0)
                        for k in ("findings", "confirmed", "poc_backed")}
        delta.append(row)

    def _head(rec):
        return {k: rec.get(k) for k in ("run_id", "case_id", "case_name", "synthetic", "started",
                                        "ended", "outcome", "result", "budget_seconds", "counts")}
    return {"a": _head(a), "b": _head(b),
            "summary": {"new": len(new), "gone": len(gone), "changed": len(changed),
                        "up": sum(1 for d in changed if d["direction"] == "up"),
                        "down": sum(1 for d in changed if d["direction"] == "down"),
                        "same": same},
            "new": new[:cap], "gone": gone[:cap], "changed": changed[:cap],
            "truncated": {"new": max(0, len(new) - cap), "gone": max(0, len(gone) - cap),
                          "changed": max(0, len(changed) - cap)},
            "same_count": same, "per_target_delta": delta}
