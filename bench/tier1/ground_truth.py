#!/usr/bin/env python3
"""Tier-1 GROUND TRUTH: classify CGC challenges by what their reference POV proves, and find the
crash-measurable set (doc 57 'A'). For each challenge: replay its POV against the vulnerable CB and
the patched CB (py3 cgc_replay). A type-1 POV that makes the vuln CB take a fatal signal while the
patched CB survives is a real, crash-reproducible bug -- the denominator our crash-oriented loop can
be measured against. Type-2 (memory disclosure) POVs are counted separately (info-leak, CWE-200, not
a crash our ASan/native oracle targets).

usage: ground_truth.py [--limit N] [challenge-dir ...]
"""
import argparse
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cgc_replay import replay  # noqa: E402

CB = HERE.parent.parent / "bench/external/cb-multios/build64/challenges"


def _bins(cdir):
    vuln, patched, povs = [], [], []
    for f in sorted(os.listdir(cdir)):
        full = cdir / f
        if f.endswith(".pov"):
            povs.append(str(full))
        elif os.access(full, os.X_OK) and full.is_file() and "." not in f:
            (patched if f.endswith("_patched") else vuln).append(str(full))
    return vuln, patched, povs


def scan_challenge(name):
    cdir = CB / name
    vuln, patched, povs = _bins(cdir)
    if not vuln or not povs:
        return {"name": name, "skip": "no vuln binary / pov"}
    v, p = vuln[0], (patched[0] if patched else None)
    best = {"name": name, "type": None, "vuln_crash": False, "patched_crash": False, "sig": None}
    for pov in povs[:3]:
        try:
            cvc, svc, typ = replay(v, pov, timeout=10.0)
        except Exception:
            continue
        if best["type"] is None:
            best["type"] = typ
        if cvc:
            best.update(type=typ, vuln_crash=True, sig=svc)
            if p:
                try:
                    cpc, _, _ = replay(p, pov, timeout=10.0)
                    best["patched_crash"] = cpc
                except Exception:
                    pass
            break
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("dirs", nargs="*")
    a = ap.parse_args()
    names = a.dirs or sorted(d for d in os.listdir(CB) if (CB / d).is_dir())[:a.limit]
    t1 = t2 = crashable = 0
    for name in names:
        r = scan_challenge(name)
        if r.get("skip"):
            print(f"SKIP {name:<40} {r['skip']}")
            continue
        typ = r["type"]
        if typ == 2:
            t2 += 1
        elif typ == 1:
            t1 += 1
        diff = r["vuln_crash"] and not r["patched_crash"]
        crashable += 1 if diff else 0
        tag = ("CRASHABLE" if diff else ("vuln-crash+patched-crash" if r["vuln_crash"] else "-"))
        print(f"{name:<40} type={typ} {tag} {r.get('sig') or ''}")
    print(f"\nTIER-1 GROUND TRUTH over {len(names)} challenges: type1(crash)={t1} type2(leak)={t2}; "
          f"{crashable} crash-reproducible (POV crashes vuln, patched survives)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
