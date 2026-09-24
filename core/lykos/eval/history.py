"""Benchmark history + regression detection (doc 14's "metrics over time").

Each scored `eval` run appends one JSON line to a history file (append-only, offline). The
history is grouped into **series** by (stage, min_state) -- comparing like with like -- and a
run is a **regression** when its overall recall drops or its false-positive rate rises versus
the previous run in the same series. The dashboard renders these; the CLI can fail on one.
"""
from __future__ import annotations

import json
import logging
import subprocess
import time
from pathlib import Path

DEFAULT_PATH = "eval-history.jsonl"

_log = logging.getLogger(__name__)


def _git_rev():
    try:
        r = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None
    except Exception:
        return None


def record(path, report, *, stage: str, min_state=None, label=None, ts=None) -> dict:
    """Append one run's scored metrics to the history file; returns the stored record."""
    backend = ({"ghidra": bool(report.meta.get("ghidra"))} if stage == "static"
               else {"fuzz_execs": report.meta.get("max_execs")})
    rec = {
        "ts": int(ts if ts is not None else time.time()),
        "git": _git_rev(), "stage": stage, "min_state": min_state, "label": label,
        "backend": backend, "n_cases": report.metrics.get("n_cases", 0),
        "overall": report.metrics.get("overall", {}),
        "per_cwe": report.metrics.get("per_cwe", {}),
    }
    p = Path(path)
    with p.open("a") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def load(path) -> list:
    """Read the history file (skips blank/corrupt lines); [] if it doesn't exist."""
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            # Skip a corrupt history line but record it, so a truncated/garbled append is
            # observable instead of silently vanishing from every dashboard.
            _log.debug("history load: skipping corrupt line in %s: %r", p, line, exc_info=True)
            continue
    return out


def series_key(rec) -> str:
    s = rec.get("stage", "?")
    return f"{s}/{rec['min_state']}" if rec.get("min_state") else s


def series(history) -> dict:
    """Group runs into {series_key: [runs...]} sorted by timestamp (like-with-like)."""
    groups: dict = {}
    for r in history:
        groups.setdefault(series_key(r), []).append(r)
    for k in groups:
        groups[k].sort(key=lambda r: r.get("ts", 0))
    return groups


def _num(x):
    return x if isinstance(x, (int, float)) else 0.0


def regressions(history, *, recall_drop=0.0, fp_rise=0.0) -> list:
    """Series whose latest run regressed vs the previous one: recall fell by more than
    `recall_drop`, or the FP-rate rose by more than `fp_rise`. Returns one dict per regression.
    """
    out = []
    for key, runs in series(history).items():
        if len(runs) < 2:
            continue
        prev, cur = runs[-2]["overall"], runs[-1]["overall"]
        dr = _num(cur.get("recall")) - _num(prev.get("recall"))
        df = _num(cur.get("fp_rate")) - _num(prev.get("fp_rate"))
        reasons = []
        if dr < -recall_drop:
            reasons.append(f"recall {round(dr, 3):+}")
        if df > fp_rise:
            reasons.append(f"fp_rate {round(df, 3):+}")
        if reasons:
            out.append({"series": key, "recall_delta": round(dr, 3),
                        "fp_rate_delta": round(df, 3), "reasons": reasons,
                        "git": runs[-1].get("git")})
    return out
