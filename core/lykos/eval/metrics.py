"""Deterministic scoring for the validation harness (doc 14).

Given per-case OUTCOMES (each: the CWE class the case belongs to, whether the case is a
`bad` sample that contains the bug or a `good` sample that does not, and the set of CWEs the
platform actually flagged on it), compute the confusion matrix and precision / recall / F1 /
false-positive-rate per CWE class and overall.

Juliet-style semantics per CWE class C:
  * a `bad` case is an actual positive  -> flagging C on it is a TRUE  positive, else a FN.
  * a `good` case is an actual negative -> flagging C on it is a FALSE positive, else a TN.
So recall measures detection power and the FP-rate measures noise (doc 14's two axes).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Outcome:
    """One scored corpus case."""
    name: str
    cwe: str                       # the CWE class this case belongs to (ground truth)
    verdict: str                   # "bad" (contains the bug) | "good" (safe variant)
    found_cwes: set                # CWEs the platform flagged on this target
    state: str = ""                # best finding state for `cwe` (candidate/…/confirmed)
    note: str = ""

    @property
    def flagged(self) -> bool:
        return self.cwe in self.found_cwes


def _prf(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    if precision and recall:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = 0.0 if (tp + fp + fn) else None
    return {"precision": precision, "recall": recall, "f1": f1}


def _round(x):
    return round(x, 3) if isinstance(x, float) else x


def score(outcomes: list[Outcome]) -> dict:
    """Confusion matrix + metrics per CWE class and overall (micro-averaged)."""
    by_cwe: dict[str, dict] = {}
    for o in outcomes:
        c = by_cwe.setdefault(o.cwe, {"tp": 0, "fp": 0, "fn": 0, "tn": 0,
                                      "bad": 0, "good": 0})
        if o.verdict == "bad":
            c["bad"] += 1
            c["tp" if o.flagged else "fn"] += 1
        else:
            c["good"] += 1
            c["fp" if o.flagged else "tn"] += 1

    per_cwe = {}
    agg = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for cwe, c in sorted(by_cwe.items()):
        m = _prf(c["tp"], c["fp"], c["fn"])
        fpr = c["fp"] / (c["fp"] + c["tn"]) if (c["fp"] + c["tn"]) else None
        per_cwe[cwe] = {**c, **{k: _round(v) for k, v in m.items()},
                        "fp_rate": _round(fpr)}
        for k in agg:
            agg[k] += c[k]

    overall = _prf(agg["tp"], agg["fp"], agg["fn"])
    overall_fpr = (agg["fp"] / (agg["fp"] + agg["tn"])
                   if (agg["fp"] + agg["tn"]) else None)
    return {
        "per_cwe": per_cwe,
        "overall": {**agg, **{k: _round(v) for k, v in overall.items()},
                    "fp_rate": _round(overall_fpr)},
        "n_cases": len(outcomes),
        "n_cwe_classes": len(by_cwe),
    }


@dataclass
class Report:
    """A scored benchmark run: the outcomes, the metrics, and run metadata."""
    outcomes: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "meta": self.meta,
            "metrics": self.metrics,
            "outcomes": [{"name": o.name, "cwe": o.cwe, "verdict": o.verdict,
                          "flagged": o.flagged, "state": o.state,
                          "found_cwes": sorted(o.found_cwes), "note": o.note}
                         for o in self.outcomes],
        }

    def table(self) -> str:
        """A compact human-readable metrics table."""
        m = self.metrics
        rows = ["CWE        bad good   TP FP FN TN   prec  recall    F1  FP-rate",
                "-" * 62]
        def fmt(x):
            return "  -  " if x is None else f"{x:5.2f}"
        for cwe, c in m.get("per_cwe", {}).items():
            rows.append(f"{cwe:<10} {c['bad']:>3} {c['good']:>4}  "
                        f"{c['tp']:>3}{c['fp']:>3}{c['fn']:>3}{c['tn']:>3}  "
                        f"{fmt(c['precision'])} {fmt(c['recall'])} {fmt(c['f1'])} "
                        f"{fmt(c['fp_rate'])}")
        o = m.get("overall", {})
        if o:
            rows.append("-" * 62)
            rows.append(f"{'OVERALL':<10} {'':>3} {'':>4}  "
                        f"{o['tp']:>3}{o['fp']:>3}{o['fn']:>3}{o['tn']:>3}  "
                        f"{fmt(o['precision'])} {fmt(o['recall'])} {fmt(o['f1'])} "
                        f"{fmt(o['fp_rate'])}")
        return "\n".join(rows)
