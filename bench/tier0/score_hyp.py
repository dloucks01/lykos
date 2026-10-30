#!/usr/bin/env python3
"""Score the hypothesis driver (core/lykos/hypo/hyp_driver.py) on the Tier-0 corpus.

North-star metric (docs/internal/52 §3): validated PoCs at the correct site / known bugs, with
false confirmations = 0.

The driver sees only `prog` and the invocation. Each solution it emits is VALIDATED the way the
product must do it, without the answer key:
  * replay on `prog_asan`; a sanitizer report must land on the source line of the hypothesis
    site (addr2line on `prog`). For an allocation-size wrap the overflow fires downstream, so the
    match is on ASan's "allocated by" frame instead.
  * cmd-injection: the injected marker command (`id`) must actually execve (strace).
Only then is the answer key consulted:
  * found               = a confirmation at a declared bug line (exec oracle: injected exec)
  * false confirmation  = a confirmation anywhere else, or on a negative case

usage: score_hyp.py [--budget S] [--jobs N] [--out DIR] [--json FILE] [case-id ...]
"""
import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DRIVER = os.path.join(ROOT, "core", "lykos", "hypo", "hyp_driver.py")
ANGR_PY = os.path.join(ROOT, "vendor", "angr-venv", "bin", "python")
sys.path.insert(0, HERE)
import selfcheck as sc  # noqa: E402  (same replay environment and report parser)

ALLOC_FRAME = re.compile(r"allocated by thread.*?\n((?:\s*#\d+ .*\n)+)", re.S)
CALL_KINDS = {"format-string", "cmd-injection", "copy", "double-free"}


def site_lines(prog, addrs):
    """addr (file vaddr) -> (function, line) via addr2line; inlined frames: innermost."""
    if not addrs:
        return {}
    p = subprocess.run(["addr2line", "-f", "-e", prog] + [hex(a) for a in addrs],
                       stdout=subprocess.PIPE, text=True)
    out = p.stdout.splitlines()
    res = {}
    for i, a in enumerate(addrs):
        fn, loc = (out[2 * i:2 * i + 2] + ["?", "?"])[:2]
        m = re.search(r"prog\.c:(\d+)", loc)
        res[a] = (fn, int(m.group(1)) if m else None)
    return res


def alloc_line(stderr):
    m = ALLOC_FRAME.search(stderr)
    if not m:
        return None
    fr = sc.FRAME.search(m.group(1))
    return int(fr.group(3)) if fr else None


def run_driver(case, prog, work, budget, seed_len):
    inv = case["invocation"]
    spec = {"binary": prog, "argv": inv["argv"], "input_mode": inv["input_mode"],
            "input_size": max(300, min(4096, 2 * seed_len)), "max_seconds": budget,
            "max_rss_mb": 6000}
    sp, op = os.path.join(work, "spec.json"), os.path.join(work, "out.json")
    with open(sp, "w") as fh:
        json.dump(spec, fh)
    cmd = ["systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=8G", "-p",
           "MemorySwapMax=0", "timeout", str(budget + 90), ANGR_PY, "-I", DRIVER, sp, op]
    t0 = time.time()
    with open(os.path.join(work, "driver.log"), "w") as log:
        rc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT).returncode
    out = {"ok": False, "hypotheses": [], "stats": {}, "error": f"no output (rc={rc})"}
    if os.path.exists(op):
        with open(op) as fh:
            out = json.load(fh)
    out["wall"] = round(time.time() - t0, 1)
    out["rc"] = rc
    return out


def validate(case, h, sol, asan, lines, work):
    """-> (confirmed: bool, report_line|None, detail)"""
    data = base64.b64decode(sol["input_b64"])
    if case["invocation"]["input_mode"] == "arg" and b"\0" in data:
        data = data.split(b"\0")[0]
    if h["kind"] == "cmd-injection":
        _, _, execs = sc.run(asan, case, data, work, strace=True)
        hit = [e for e in execs if os.path.basename(e) == "id"]
        return bool(hit), None, f"execs={[os.path.basename(e) for e in execs]}"
    rc, err, _ = sc.run(asan, case, data, work)
    rep = sc.parse_report(err)
    if not rep:
        return False, None, f"no sanitizer report (rc={rc})"
    kind, func, line = rep
    site = lines.get(h["_site_file"], (None, None))[1]
    if h["kind"] == "int-overflow-alloc":
        al = alloc_line(err)
        ok = site is not None and al == site and "heap-buffer-overflow" in kind
        return ok, line, f"{kind} at {line}, allocated at {al}, site line {site}"
    ok = site is not None and line == site
    return ok, line, f"{kind} at {func}:{line}, site line {site}"


def score_case(cid, bindir, budget):
    cdir = os.path.join(HERE, cid)
    with open(os.path.join(cdir, "case.json")) as fh:
        case = json.load(fh)
    work = tempfile.mkdtemp(prefix=f"hyp-{cid}-")
    # the analyzer sees only prog (+ seed) in a clean directory
    prog = os.path.join(work, "prog")
    shutil.copy(os.path.join(bindir, cid, "prog"), prog)
    asan = os.path.join(bindir, cid, "prog_asan")
    seed = os.path.join(cdir, "seed.bin")
    seed_len = os.path.getsize(seed) if os.path.exists(seed) else 0
    out = run_driver(case, prog, work, budget, seed_len)
    img = out.get("image") or {}
    delta = img.get("mapped_base", 0) - img.get("linked_base", 0)
    hyps = out.get("hypotheses", [])
    for h in hyps:
        h["_site_file"] = int(h["site"], 16) - delta if h.get("site") else None
    lines = site_lines(prog, sorted({h["_site_file"] for h in hyps if h["_site_file"]}))
    bug_lines = {b["line"]: b for b in case["bugs"]}
    found, false_conf, rows = {}, [], []
    for h in hyps:
        for sol in h["solutions"]:
            ok, line, detail = validate(case, h, sol, asan, lines, work)
            row = {"hyp": h["id"], "kind": h["kind"], "func": h.get("func"),
                   "site_line": lines.get(h["_site_file"], (None, None))[1],
                   "t": sol.get("t"), "confirmed": ok, "detail": detail}
            rows.append(row)
            if not ok:
                continue
            bug = None
            if h["kind"] == "cmd-injection":
                bug = next((b for b in case["bugs"] if b["oracle"] == "exec"), None)
            else:
                bug = bug_lines.get(line)
            if bug is not None:
                found.setdefault(bug["id"], row)
            else:
                false_conf.append(row)
    shutil.rmtree(work, ignore_errors=True)
    return {"id": cid, "class": case["class"], "bugs": [b["id"] for b in case["bugs"]],
            "found": sorted(found), "found_rows": found, "false": false_conf, "rows": rows,
            "error": out.get("error"), "stats": out.get("stats", {}), "wall": out.get("wall"),
            "proposed": len(hyps)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=120)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--out", help="build dir to (re)use")
    ap.add_argument("--json", help="write full results here")
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
        results = list(ex.map(lambda c: score_case(c, bindir, a.budget), ids))
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
