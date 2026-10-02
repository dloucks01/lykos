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

# CWE families: a detector naming the sink's generic CWE (e.g. strcpy -> CWE-120) counts as
# detecting a case labeled with a sibling (e.g. Juliet's CWE-121 stack overflow). Matching is
# family-wise so external suites that use specific labels still score correctly.
_FAMILIES = [
    {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-123", "CWE-124", "CWE-125", "CWE-126",
     "CWE-127", "CWE-680", "CWE-786", "CWE-787", "CWE-788"},           # buffer bounds
    {"CWE-134"},                                                       # format string
    {"CWE-77", "CWE-78", "CWE-88"},                                    # command/arg injection
    {"CWE-476"},                                                       # NULL deref
    {"CWE-415", "CWE-416"},                                            # free/UAF
    {"CWE-190", "CWE-191", "CWE-192"},                                 # integer wrap
    {"CWE-259", "CWE-321", "CWE-798"},                                 # hard-coded creds
    {"CWE-327", "CWE-328"},                                            # weak crypto
    {"CWE-330", "CWE-338"},                                            # weak RNG
    {"CWE-242", "CWE-676"},                                            # dangerous function
]


def same_family(a: str, b: str) -> bool:
    if a == b:
        return True
    return any(a in fam and b in fam for fam in _FAMILIES)


def matches(ground_truth: str, found_cwes) -> bool:
    """True if any flagged CWE is in the ground-truth CWE's family."""
    return any(same_family(ground_truth, f) for f in found_cwes)


def gate(metrics: dict, meta: dict, *, stage: str = "static", min_recall: float = 1.0,
         max_fp_rate: float = 0.0, require_backend: bool = False, min_negative: int = 0):
    """Release-gate decision over a scored run. Returns (passed, verdict, reason).

    verdict is PASS / FAIL / SKIP. A run whose required backend is absent (static without
    Ghidra, dynamic/lava without a compiler) SKIPs rather than fails, unless `require_backend`,
    so a CI host lacking the backend doesn't produce a false regression. Otherwise the gate
    FAILs if recall drops below `min_recall` or the false-positive rate exceeds `max_fp_rate`.

    Recall and fp_rate are recomputed here from the exact integer confusion-matrix counts, NOT
    read from `overall`'s rounded display floats: rounding recall to 3 dp lets a 0.9996 recall
    pass a 1.0 ratchet, and rounding fp_rate lets a handful of false positives in a large
    negative set pass a 0.0 ceiling. The ratchet must see the true value.

    `min_negative` guards the precision axis: fp_rate is None when no `good` cases were scored,
    which otherwise passes the fp check vacuously. Require a floor of negatives so a corpus that
    lost its discrimination negatives FAILs instead of silently passing precision.
    """
    o = metrics.get("overall", {})
    tp, fp = o.get("tp", 0), o.get("fp", 0)
    fn, tn = o.get("fn", 0), o.get("tn", 0)
    n_positive = tp + fn
    n_negative = fp + tn
    recall = tp / n_positive if n_positive else None
    fp_rate = fp / n_negative if n_negative else None

    # A static run needs Ghidra; a dynamic/lava run needs a compiler for the crash corpus (the
    # sandbox runs the native binaries -- there is no qemu in that path). Check backend-absence
    # FIRST: the corpus still "scores" with the backend missing (every bad case a false
    # negative), so n_positive > 0 and the recall check below would FAIL a CI host that simply
    # lacks the backend. That is the false regression the SKIP exists to avoid.
    if stage == "static":
        # EITHER backend (Ghidra headless, or the no-JVM rizin+pypcode) satisfies the static run;
        # `decompiler` is truthy when either is present (older reports only carry `ghidra`).
        backend_absent = not (meta.get("decompiler") or meta.get("ghidra") or meta.get("native"))
        need = "an RE backend (Ghidra or rizin+pypcode)"
    elif stage in ("dynamic", "lava"):
        backend_absent, need = (not meta.get("gcc")), "a compiler"
    else:
        backend_absent, need = False, ""
    if backend_absent and not require_backend:
        return True, "SKIP", f"{stage} benchmark needs {need} (not found)"
    if n_positive == 0:
        return False, "FAIL", "no bad cases were scored"
    if n_negative < min_negative:
        return False, "FAIL", (
            f"only {n_negative} negative case(s) scored (need >= {min_negative}); "
            "fp_rate is not measurable")
    ok = (recall is not None and recall >= min_recall
          and (fp_rate is None or fp_rate <= max_fp_rate))
    return ok, ("PASS" if ok else "FAIL"), (
        f"recall {_round(recall)} (min {min_recall}), "
        f"fp_rate {_round(fp_rate)} (max {max_fp_rate})")


@dataclass
class Outcome:
    """One scored corpus case."""
    name: str
    cwe: str                       # the CWE class this case belongs to (ground truth)
    verdict: str                   # "bad" (contains the bug) | "good" (safe variant)
    found_cwes: set                # CWEs the platform flagged on this target
    state: str = ""                # best finding state for `cwe` (candidate/…/confirmed)
    note: str = ""
    matched: bool = None           # set by the harness (family-aware); else exact membership

    @property
    def flagged(self) -> bool:
        if self.matched is not None:
            return self.matched
        return matches(self.cwe, self.found_cwes)


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
