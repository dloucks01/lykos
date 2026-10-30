#!/usr/bin/env python3
"""Tier-1 scorer: run the hunt loop on DARPA CGC challenges (cb-multios Linux port) and measure
validated, vulnerability-specific crashes (doc 52 §3, Step 5 exit criterion).

Ground truth is the vulnerable/patched PAIR each challenge ships: a crash is counted ONLY when
the solved input crashes the vulnerable binary AND does NOT crash the patched one. A crash that
also crashes the patched binary is an incidental defect, not the planted vulnerability, and is
reported separately -- this keeps "false confirmations = 0" meaningful on real binaries.

CGC binaries are statically linked and stdin/stdout driven (the Linux port maps transmit/receive
to fd 1/0), so the driver is run with input_mode=stdin and CB scoping (own-code only).

usage: score_cgc.py [--budget S] [--jobs N] [--input-size N] [--limit N] [challenge-dir ...]
"""
import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "core"))
CB = os.path.join(ROOT, "bench", "external", "cb-multios", "build64", "challenges")


def _pairs(limit=None):
    """(name, vuln_path, patched_path) for each built challenge binary with a patched twin."""
    out = []
    if not os.path.isdir(CB):
        return out
    for d in sorted(os.listdir(CB)):
        cdir = os.path.join(CB, d)
        if not os.path.isdir(cdir):
            continue
        for f in sorted(os.listdir(cdir)):
            full = os.path.join(cdir, f)
            if (f.endswith("_patched") or not os.access(full, os.X_OK)
                    or not os.path.isfile(full) or "." in f):
                continue
            patched = full + "_patched"
            if os.path.exists(patched):
                out.append((f, full, patched))
        if limit and len(out) >= limit:
            return out[:limit]
    return out


def score_one(name, vuln, patched, budget, input_size):
    from lykos.hypo import engine
    from lykos.hypo.validate import Target, _native_runs
    t0 = time.time()
    out = engine.run_driver(vuln, argv=[], input_mode="stdin", budget=budget,
                            input_size=input_size, extra={"cb_scope": True})
    hyps = engine.hypotheses_from(out, vuln)
    tv = Target(exe=Path(vuln), argv=[], mode="stdin")
    tp = Target(exe=Path(patched), argv=[], mode="stdin")
    vuln_crash = incidental = 0
    detail = []
    for h in hyps:
        for s in h.solutions:
            rv = _native_runs(tv, s.data, 1)[0]
            if not rv.crashed:
                continue
            rp = _native_runs(tp, s.data, 1)[0]
            if rp.crashed:
                incidental += 1
            else:
                vuln_crash += 1
                detail.append(f"{h.kind}@{h.func}:{rv.signal}")
    return {"name": name, "hyps": len(hyps), "own": out.get("stats", {}).get("own_functions"),
            "vuln_crash": vuln_crash, "incidental": incidental, "detail": detail,
            "wall": round(time.time() - t0, 1), "error": out.get("error")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=180)
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--input-size", type=int, default=512)
    ap.add_argument("--limit", type=int, default=5)
    ap.add_argument("dirs", nargs="*")
    a = ap.parse_args()
    if a.dirs:
        items = []
        for d in a.dirs:
            cdir = d if os.path.isabs(d) else os.path.join(CB, d)
            for f in sorted(os.listdir(cdir)):
                full = os.path.join(cdir, f)
                if (not f.endswith("_patched") and os.access(full, os.X_OK)
                        and os.path.isfile(full) and "." not in f
                        and os.path.exists(full + "_patched")):
                    items.append((f, full, full + "_patched"))
    else:
        items = _pairs(limit=a.limit)
    if not items:
        print("no built CGC challenge pairs found under", CB)
        return 2
    t0 = time.time()
    with ThreadPoolExecutor(a.jobs) as ex:
        results = list(ex.map(lambda it: score_one(*it, a.budget, a.input_size), items))
    found = sum(1 for r in results if r["vuln_crash"] > 0)
    inc = sum(r["incidental"] for r in results)
    for r in results:
        mark = "VULN" if r["vuln_crash"] else "----"
        print(f"{mark} {r['name']:<38} hyps={r['hyps']:<4} own={r['own']} "
              f"wall={r['wall']}s {';'.join(r['detail'][:3])}"
              + (f" | {r['incidental']} incidental" if r["incidental"] else ""))
    print(f"\nTIER-1 {found}/{len(items)} challenges with a vuln-specific crash, "
          f"{inc} incidental (patched-also-crash), wall {time.time() - t0:.0f}s, "
          f"budget {a.budget}s/challenge")
    return 0


if __name__ == "__main__":
    sys.exit(main())
