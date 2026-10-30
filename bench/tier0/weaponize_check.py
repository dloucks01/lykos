#!/usr/bin/env python3
"""Step 4 check: the hunt loop climbs a control-flow-hijack to a confirmed ret2win L3.

Builds the ret2win corpus cases as no-PIE binaries (a fixed win address is the ret2win
precondition) and runs the PRODUCT loop (core/lykos/hypo) on each binary:
  * w01_ret2win  -> expect a confirmed L3 ret2win exploit redirecting to win()
  * n17_...bounded -> expect NO exploit (no overflow, no RIP control)

usage: weaponize_check.py [case-id ...]
Exits non-zero on any mismatch.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "core"))

POSITIVE = {"w01_ret2win"}
NEGATIVE = {"n17_ret2win_bounded"}


def run_case(cid, budget):
    from lykos.hypo import loop
    src = os.path.join(HERE, cid, "prog.c")
    tmp = tempfile.mkdtemp(prefix=f"wpn-{cid}-")
    binp = os.path.join(tmp, "prog")
    cc = os.environ.get("CC", "gcc")
    r = subprocess.run([cc, "-O0", "-g", "-no-pie", "-fno-stack-protector", "-w",
                        "-o", binp, src], capture_output=True, text=True)
    if r.returncode != 0:
        return None, f"build failed: {r.stderr[-300:]}"
    report = loop.hunt(binp, budget=budget, out_dir=os.path.join(tmp, "out"),
                       input_size=300, log=lambda m: None)
    best = None
    for res in report["results"]:
        for h in res["hypotheses"]:
            ex = h.get("exploit") if isinstance(h, dict) else getattr(h, "exploit", None)
            if ex and (best is None or ex.get("level", "") > best.get("level", "")):
                best = ex
    return best, "ok"


def main():
    ids = sys.argv[1:] or sorted(POSITIVE | NEGATIVE)
    budget = float(os.environ.get("WPN_BUDGET", "180"))
    fails = 0
    for cid in ids:
        best, note = run_case(cid, budget)
        if note != "ok":
            print(f"FAIL {cid:<22} {note}")
            fails += 1
            continue
        level = (best or {}).get("level")
        if cid in POSITIVE:
            ok = level == "L3" and (best or {}).get("confirmed")
            print(f"{'PASS' if ok else 'FAIL'} {cid:<22} exploit={level} "
                  f"{(best or {}).get('evidence', '')[:80]}")
            fails += 0 if ok else 1
        else:
            ok = best is None or level != "L3"
            print(f"{'PASS' if ok else 'FAIL'} {cid:<22} exploit={level or 'none'}")
            fails += 0 if ok else 1
    print(f"{len(ids) - fails}/{len(ids)} weaponization checks passed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
