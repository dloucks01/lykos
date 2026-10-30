#!/usr/bin/env python3
"""Score the hypothesis driver (core/lykos/hypo/hyp_driver.py) on the Tier-0 corpus.

North-star metric (docs/internal/52 §3): validated PoCs at the correct site / known bugs, with
false confirmations = 0.

The driver sees only `prog` and the invocation. Each solution is validated by the PRODUCT's
validator (core/lykos/hypo/validate.py, the same code `lykos hunt` ships), without the answer key:
  * sandboxed replay on `prog_asan`, 3 runs; the sanitizer report must land on the source line of
    the hypothesis site (DWARF of `prog`); an allocation-size wrap matches its "allocated by" frame;
  * cmd-injection: the injected `id>&2` must actually run (its `uid=N(` output appears).
Only then is the answer key consulted:
  * found               = a confirmation at a declared bug line (exec oracle: injected exec)
  * false confirmation  = a confirmation anywhere else, or on a negative case

usage: score_hyp.py [--budget S] [--jobs N] [--out DIR] [--json FILE] [--keep DIR] [case-id ...]
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "core"))   # the product's hypo package: engine + validator


def score_case(cid, bindir, budget, keep=None):
    """Run the PRODUCT engine + validator (core/lykos/hypo) on one case, then -- only then --
    label each confirmation with the answer key."""
    from lykos.hypo import engine
    from lykos.hypo.validate import Target, validate
    cdir = os.path.join(HERE, cid)
    with open(os.path.join(cdir, "case.json")) as fh:
        case = json.load(fh)
    if keep:
        work = os.path.join(keep, cid)
        shutil.rmtree(work, ignore_errors=True)
        os.makedirs(work)
    else:
        work = tempfile.mkdtemp(prefix=f"hyp-{cid}-")
    # the analyzer sees only prog (+ seed) in a clean directory
    prog = os.path.join(work, "prog")
    shutil.copy(os.path.join(bindir, cid, "prog"), prog)
    asan = os.path.join(bindir, cid, "prog_asan")
    seed = os.path.join(cdir, "seed.bin")
    seed_len = os.path.getsize(seed) if os.path.exists(seed) else 0
    inv = case["invocation"]
    t0 = time.time()
    out = engine.run_driver(prog, argv=inv["argv"], input_mode=inv["input_mode"], budget=budget,
                            input_size=max(300, min(4096, 2 * seed_len)), mem_mb=8192,
                            extra=json.loads(os.environ.get("HYP_SPEC_EXTRA") or "{}"),
                            workdir=Path(work))
    wall = round(time.time() - t0, 1)
    hyps = engine.hypotheses_from(out, prog)
    target = Target(exe=Path(prog), argv=list(inv["argv"]), mode=inv["input_mode"],
                    asan_exe=Path(asan))
    bug_lines = {b["line"]: b for b in case["bugs"]}
    found, false_conf, rows = {}, [], []
    for h in hyps:
        for sol in h.solutions:
            v, _inc = validate(target, h, sol.data)
            row = {"hyp": h.id, "kind": h.kind, "func": h.func, "site_line": h.line,
                   "t": sol.t, "confirmed": v.confirmed, "detail": f"{v.method}: {v.detail}"}
            rows.append(row)
            if not v.confirmed:
                continue
            if h.kind == "cmd-injection":
                bug = next((b for b in case["bugs"] if b["oracle"] == "exec"), None)
            else:
                bug = bug_lines.get(v.line)
            if bug is not None:
                found.setdefault(bug["id"], row)
            else:
                false_conf.append(row)
    if not keep:
        shutil.rmtree(work, ignore_errors=True)
    return {"id": cid, "class": case["class"], "bugs": [b["id"] for b in case["bugs"]],
            "found": sorted(found), "found_rows": found, "false": false_conf, "rows": rows,
            "error": out.get("error"), "stats": out.get("stats", {}), "wall": wall,
            "proposed": len(hyps)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=120)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--out", help="build dir to (re)use")
    ap.add_argument("--json", help="write full results here")
    ap.add_argument("--keep", help="keep each case's work dir (spec, out.json, driver.log) here")
    ap.add_argument("cases", nargs="*")
    a = ap.parse_args()
    ids = a.cases or sorted(d for d in os.listdir(HERE)
                            if os.path.isfile(os.path.join(HERE, d, "case.json")))
    bindir = a.out or tempfile.mkdtemp(prefix="tier0-bin-")
    b = subprocess.run([os.path.join(HERE, "build.sh"), bindir] + ids,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if b.returncode:
        print(b.stdout)
        return 2
    t0 = time.time()
    with ThreadPoolExecutor(a.jobs) as ex:
        results = list(ex.map(lambda c: score_case(c, bindir, a.budget, a.keep), ids))
    nb = sum(len(r["bugs"]) for r in results)
    nf = sum(len(r["found"]) for r in results)
    nfalse = sum(len(r["false"]) for r in results)
    for r in results:
        mark = "-" if not r["bugs"] else f"{len(r['found'])}/{len(r['bugs'])}"
        extra = []
        if r["false"]:
            extra.append("FALSE " + "; ".join(f"{x['hyp']} {x['detail']}" for x in r["false"]))
        if r["error"]:
            extra.append("err: " + str(r["error"])[:80])
        unconf = [x for x in r["rows"] if not x["confirmed"]]
        if unconf:
            extra.append(f"{len(unconf)} unconfirmed")
        times = [f"{x['t']}s" for x in r["found_rows"].values()]
        print(f"{r['id']:<24} {mark:>4}  hyps={r['proposed']:<3} wall={r['wall']}s "
              f"{' '.join(times)} {' | '.join(extra)}")
    print(f"\nSCORE validated {nf}/{nb} bugs ({100.0 * nf / max(nb, 1):.0f}%), "
          f"false confirmations {nfalse}, wall {time.time() - t0:.0f}s, budget {a.budget}s/case")
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(results, fh, indent=1, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main())
