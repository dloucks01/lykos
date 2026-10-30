#!/usr/bin/env python3
"""Step 5 check: the hybrid fuzz fallback confirms a bug the DIRECTED solver misses.

h02_offbyone_nul hides an off-by-one heap overflow behind a "comment:" tag parser -- the directed
symbolic engine does not crack the keyword structure in budget, but AFL++ with CmpLog does, and the
SAME validator confirms the crash at the declared site. Asserts the confirming solution came from
the fuzz fallback (not the directed engine), proving the undirected engine adds reach.

usage: fuzz_check.py            (needs afl-fuzz + afl-clang-fast; ~3 min)
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "core"))
SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "h02_offbyone_nul", "prog.c")


def main():
    from lykos.hypo import loop, fuzzrun
    if not fuzzrun.available():
        print("SKIP fuzz_check: afl-fuzz not found")
        return 0
    budget = float(os.environ.get("FUZZ_BUDGET", "180"))
    rep = loop.hunt(SRC, budget=budget, input_size=300, log=lambda _m: None)
    fuzz_confirmed = []
    for r in rep["results"]:
        for h in r["hypotheses"]:
            if h.status != "confirmed":
                continue
            for s in h.solutions:
                if s.verdict and s.verdict.confirmed and "fuzz" in (s.detail or "").lower():
                    fuzz_confirmed.append((h.kind, h.location, h.func))
    if fuzz_confirmed:
        for k, loc, fn in fuzz_confirmed:
            print(f"PASS fuzz_fallback  CONFIRMED {k} at {loc} in {fn} (via fuzz fallback)")
        print(f"{len(fuzz_confirmed)}/1+ fuzz-fallback confirmations")
        return 0
    print("FAIL fuzz_fallback  no hypothesis confirmed via the fuzz fallback")
    return 1


if __name__ == "__main__":
    sys.exit(main())
