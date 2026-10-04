#!/usr/bin/env python3
"""Recall benchmark over the real known-vulnerable corpus (examples/vuln-targets/).

Runs each present target through the FULL chain (triage -> disassemble -> detect -> fuzz ->
root_cause -> build_poc -> poc_primitive -> build_exploit) and scores two independent things
against ground truth the corpus already records:

  DETECT  -- did the static detectors surface the expected CWE?
  EXPLOIT -- did the dynamic chain reach the expected PoC level (crash L1 / IP-control L2 / shell L3)?

Negative targets (no known bug) invert the exploit check: reaching a crash-backed PoC is a FALSE
POSITIVE, i.e. a MISS. So the scoreboard measures BOTH recall (we catch the real bugs) and
precision (we don't fabricate bugs on clean code).

"100% of all known bugs" is not a guarantee any tool can make; this makes the real question
measurable instead -- "N/M known bugs caught, here are the misses" -- and lets a test gate it so a
catch never silently regresses. Binaries are gitignored (built by fetch_build.sh), so absent
targets are reported as SKIP, never as a pass.

Usage:
  PYTHONPATH=core python3 tools/recall_benchmark.py [--only name1,name2] [--fuzz-timeout 60] [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VT = ROOT / "examples" / "vuln-targets"
BIN = VT / "bin"
INPUTS = VT / "inputs"

LEVELS = ["none", "L0", "L1", "L2", "L3"]            # ordered; index gives comparability


def _lvl(x: str | None) -> int:
    return LEVELS.index(x) if x in LEVELS else 0


# Ground truth. `cwe` = CWEs the static detectors should surface (checked against finding.cwe).
# `min_level` = the lowest PoC level the dynamic chain must reach to count as caught (None for a
# negative target). `mode` = the input channel the bug lives on. `seed` = a corpus input to prime
# fuzzing (a known-crashing seed for positives, a benign file for negatives). `negative` = a clean
# target where ANY crash-backed PoC is a false positive. Values are justified from manifest.tsv and
# the in-repo notes (e.g. test_realgate.py records ncompress reaching L2 at offset 1048).
GROUND_TRUTH: dict[str, dict] = {
    # --- x86-64 positives: full ladder available natively ---
    "ncompress_x86-64_cve": {
        "cwe": {"CWE-121", "CWE-120"}, "min_level": "L2", "mode": "arg", "negative": False,
        "note": "CVE-2001-1413 argv strcpy; NUL in the slot caps it at L2 (IP control)"},
    "jhead_x86-64": {
        "cwe": {"CWE-125"}, "min_level": "L1", "mode": "file", "seed": "jhead-crash.jpg",
        "negative": False, "known_gap": True,
        "note": "CWE-125 OOB read in ProcessGpsInfo. KNOWN GAP: the seed SIGSEGVs under a direct "
                "`jhead <file>` run, but the fuzz harness records 0 crashing execs -- jhead reads its "
                "input from an argv FILENAME (not stdin), and file-argument delivery isn't reaching "
                "the parser. Dynamic-recall gap in file-arg harnessing, tracked not hidden."},
    # --- x86-64 negatives: precision controls ---
    "gif2rgb_x86-64": {
        "cwe": set(), "min_level": None, "mode": "file", "negative": True,
        "seed_glob": "src/giflib-5.1.4/pic/*.gif",
        "note": "giflib with the screen-confinement check in place -- no known bug"},
    "unzip_x86-64": {
        "cwe": set(), "min_level": None, "mode": "file", "negative": True,
        "note": "Info-ZIP 6.0 -- no crash reached; precision control"},
    # --- cross-arch positives: same bug, exercises the emulated dynamic path (crash under qemu) ---
    **{f"jhead_{a}": {"cwe": {"CWE-125"}, "min_level": "L1", "mode": "file",
                      "seed": "jhead-crash.jpg", "negative": False, "cross": True, "known_gap": True,
                      "note": f"CWE-125 OOB read, {a} under qemu-user (same file-arg harness gap as x86-64)"}
       for a in ("aarch64", "arm", "ppc64le", "riscv64", "s390x", "ppc64", "ppc",
                 "mips" if False else "sparc64", "m68k", "loongarch64", "sh4")},
}

# Default run set: the x86-64 targets (fast, full ladder + precision controls). Cross-arch jhead is
# opt-in via --only or --cross because emulated disassembly of each is slow.
DEFAULT_SET = ["ncompress_x86-64_cve", "jhead_x86-64", "gif2rgb_x86-64", "unzip_x86-64"]


def run_target(binpath: Path, spec: dict, fuzz_timeout: int, log=print) -> dict:
    """Run the full chain on one binary; return {arch, cwes, max_level, crash_confirmed}."""
    from lykos.analyze import register
    from lykos.analyze.ingest import ingest, enqueue_triage
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.detect.stage import enqueue_detect
    from lykos.analyze.fuzz.stage import enqueue_fuzz
    from lykos.analyze.debug.stage import enqueue_root_cause
    from lykos.analyze.poc.stage import enqueue_build_poc
    from lykos.analyze.poc.primitive_stage import enqueue_primitive
    from lykos.analyze.poc.exploit_stage import enqueue_exploit
    from lykos.casestore import CaseStore
    from lykos.db.dao import DynResultDAO, FindingDAO, PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    register()
    store = CaseStore.open(Path(tempfile.mkdtemp()) / "store")
    case = store.cases.create("recall").id
    t = ingest(store, case, binpath, filename=binpath.name)
    mode = spec.get("mode", "stdin")

    seeds = []
    if spec.get("seed"):
        sp = INPUTS / spec["seed"]
        if sp.exists():
            seeds = [str(sp)]
    elif spec.get("seed_glob"):
        seeds = [str(p) for p in sorted(VT.glob(spec["seed_glob"]))[:4]]
    fuzz_params = {"timeout": fuzz_timeout, "input_mode": mode}
    if seeds:
        fuzz_params["seeds"] = seeds

    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=4, poll_interval=0.02))
    pool.start()
    q = JobQueue(store.conn)

    def stage(fn, label, **kw):
        try:
            fn(q, store.targets.get(t.id), **kw)
        except TypeError:
            fn(q, store.targets.get(t.id))
        pool.wait_idle(1800)
        log(f"      [{label}]")

    try:
        stage(enqueue_triage, "triage", force=True)
        stage(enqueue_disassemble, "disassemble", force=True)
        stage(enqueue_detect, "detect", force=True)
        stage(enqueue_fuzz, "fuzz", params=fuzz_params, force=True)
        stage(enqueue_root_cause, "root_cause", force=True)
        crashes = [r for r in DynResultDAO(store.conn).list_by_target(t.id)
                   if r.crashed and r.input_sha]
        if crashes:
            c0 = next((r for r in crashes if (r.signal_name or "") == "SIGSEGV"), crashes[0])
            pl = {"input_sha": c0.input_sha, "input_mode": c0.input_mode or mode}
            stage(enqueue_build_poc, "build_poc", params=dict(pl), force=True)
            stage(enqueue_primitive, "poc_primitive", params=dict(pl), force=True)
            stage(enqueue_exploit, "build_exploit",
                  params={"strategy": "auto", "timeout": 25, **pl}, force=True)
    finally:
        pool.stop(grace=3.0)

    tt = store.targets.get(t.id)
    finds = FindingDAO(store.conn).list_by_target(t.id)
    cwes = {f.cwe for f in finds if f.cwe}
    crash_confirmed = any(f.detector == "fuzz" and f.state == "confirmed" for f in finds)
    pocs = PocDAO(store.conn).list_by_target(t.id)
    max_level = max((p.level for p in pocs if p.verified), default="none", key=_lvl)
    return {"arch": tt.arch, "cwes": sorted(cwes), "max_level": max_level,
            "crash_confirmed": crash_confirmed, "n_findings": len(finds)}


def score(result: dict, spec: dict) -> dict:
    """DETECT = expected CWE surfaced; EXPLOIT = level reached vs expected (inverted for negatives)."""
    want_cwe = spec.get("cwe", set())
    detect_ok = (not want_cwe) or bool(want_cwe & set(result["cwes"]))
    if spec.get("negative"):
        # precision: a clean target must NOT yield a crash-backed/IP-control PoC
        exploit_ok = _lvl(result["max_level"]) < _lvl("L1") and not result["crash_confirmed"]
        verdict = "PASS" if exploit_ok else "FALSE-POSITIVE"
        return {"detect_ok": detect_ok, "exploit_ok": exploit_ok, "verdict": verdict}
    exploit_ok = _lvl(result["max_level"]) >= _lvl(spec["min_level"])
    # detection is advisory on cross-arch stripped binaries (static recall is weaker there); the
    # authoritative recall signal there is the reproduced crash.
    if spec.get("cross"):
        caught = exploit_ok
    else:
        caught = detect_ok and exploit_ok
    if caught:
        verdict = "PASS"
    elif spec.get("known_gap"):
        # a documented, pre-existing recall gap: reported as NOT caught (it does not count toward the
        # score), but it is expected, so it must not redden the regression gate. If it ever starts
        # passing, drop the flag.
        verdict = "XFAIL"
    else:
        verdict = "MISS"
    return {"detect_ok": detect_ok, "exploit_ok": exploit_ok, "verdict": verdict}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="lykos recall benchmark over the vuln-targets corpus")
    ap.add_argument("--only", help="comma-separated target basenames (default: x86-64 set)")
    ap.add_argument("--cross", action="store_true", help="also run the cross-arch jhead targets")
    ap.add_argument("--fuzz-timeout", type=int, default=60)
    ap.add_argument("--json", help="write the scoreboard as JSON to this path")
    args = ap.parse_args(argv)

    if args.only:
        names = args.only.split(",")
    else:
        names = list(DEFAULT_SET)
        if args.cross:
            names += [n for n in GROUND_TRUTH if GROUND_TRUTH[n].get("cross")]

    rows, hits, total, skipped, xfails = [], 0, 0, 0, 0
    for name in names:
        spec = GROUND_TRUTH.get(name)
        binpath = BIN / name
        if spec is None:
            print(f"  ?? {name}: no ground truth entry -- skipping"); continue
        if not binpath.exists():
            print(f"  -- SKIP {name}: not built (run examples/vuln-targets/fetch_build.sh)")
            skipped += 1
            rows.append({"target": name, "verdict": "SKIP", **spec_public(spec)})
            continue
        kind = "NEG" if spec.get("negative") else f"want>={spec['min_level']}"
        print(f"  .. {name}  [{kind}]")
        try:
            res = run_target(binpath, spec, args.fuzz_timeout, log=print)
        except Exception as e:                       # noqa: BLE001
            print(f"     ERROR: {type(e).__name__}: {e}")
            rows.append({"target": name, "verdict": "ERROR", "error": str(e)[:200],
                         **spec_public(spec)})
            total += 1
            continue
        sc = score(res, spec)
        total += 1
        if sc["verdict"] == "PASS":
            hits += 1
        elif sc["verdict"] == "XFAIL":
            xfails += 1
        rows.append({"target": name, "arch": res["arch"], "cwes": res["cwes"],
                     "max_level": res["max_level"], "crash_confirmed": res["crash_confirmed"],
                     "detect_ok": sc["detect_ok"], "exploit_ok": sc["exploit_ok"],
                     "verdict": sc["verdict"], **spec_public(spec)})
        print(f"     {sc['verdict']:<14} arch={res['arch']} cwes={res['cwes']} "
              f"level={res['max_level']} detect={sc['detect_ok']} exploit={sc['exploit_ok']}")

    print("\n" + "=" * 92)
    print(f"{'TARGET':<26}{'EXPECT':<12}{'ARCH':<11}{'LEVEL':<7}{'DETECT':<8}{'VERDICT'}")
    print("-" * 92)
    for r in rows:
        exp = "NEG" if r.get("negative") else (r.get("min_level") or "-")
        print(f"{r['target']:<26}{exp:<12}{str(r.get('arch','-')):<11}"
              f"{str(r.get('max_level','-')):<7}{str(r.get('detect_ok','-')):<8}{r['verdict']}")
    print("-" * 92)
    print(f"RECALL+PRECISION SCORE: {hits}/{total} caught  "
          f"({xfails} known-gap/xfail, {skipped} skipped-not-built)")

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"score": f"{hits}/{total}", "hits": hits, "total": total,
             "xfails": xfails, "skipped": skipped, "rows": rows}, indent=2))
        print(f"wrote {args.json}")
    # exit non-zero only on a REGRESSION: a real miss / false positive / error on a target that is
    # not a documented known-gap. Skips and xfails never fail the gate.
    missed = [r for r in rows if r["verdict"] in ("MISS", "FALSE-POSITIVE", "ERROR")]
    if missed:
        print("REGRESSIONS: " + ", ".join(f"{r['target']}({r['verdict']})" for r in missed))
    return 1 if missed else 0


def spec_public(spec: dict) -> dict:
    return {"negative": spec.get("negative", False), "min_level": spec.get("min_level"),
            "want_cwe": sorted(spec.get("cwe", set()))}


if __name__ == "__main__":
    sys.exit(main())
