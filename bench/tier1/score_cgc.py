#!/usr/bin/env python3
"""!! INVALID AS A TIER-1 MEASUREMENT -- DO NOT TRUST ITS NUMBER (see docs/internal/57) !!

This harness assumed a CGC challenge takes raw stdin and that the `.pov` file is an input to
replay. Both are wrong: cb-multios CBs are SOCKET-driven, and a `.pov` is itself an ELF *driver
program* run via tools/cb-replay-pov.py over a type-1/type-2 negotiation. Feeding the POV as stdin
does not reproduce the bug, so the vuln/patched differential here never fires -- the 0/N it reports
reflects the WRONG INPUT MODEL, not the engine. A correct Tier-1 harness must drive the CB through
cb-replay-pov.py (POV -> confirmed crash = ground truth) and feed our loop the CB's real channel,
seeded from the poller/ traffic. Kept only as a record of the mistake and the CB-scoping result
(scoping DID work: ~150-270 own functions, ~75-135 hypotheses, not the 3145-hyp libc flood).
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
