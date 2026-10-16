"""Does the pipeline do real work on a binary nobody prepared for it?

The conformance gate cannot answer this, and the reason is structural rather than a gap in its
case list: every gate fixture is a 2-8 KB binary that the gate itself compiled, `-O0 -no-pie`,
with a planted defect reachable from the first few hundred inputs -- and the harness stops the
moment the case's criterion is met. So the gate measures "can it find this bug", which is a
different question from "how much of the budget reached the target", and only the second one
predicts behaviour on arbitrary software.

This probe asks the second question. It points the REAL autopilot at ordinary binaries and
records the WORK, not a verdict: whether the program ever started, how many times it was
executed, where the time went, which stages were reached, and what each declining stage said
about itself. There is no pass mark. The output is a table you read.

What it found on first use, four stock /usr/bin binaries at 420s each:

    /usr/bin/cat        1,511 executions   27 of ~40 stages   ended inside directed_fuzz
    /usr/bin/xxd        2,756 executions   30 stages (done)   --
    /usr/bin/readelf    1,473 executions   26 stages          ended inside concolic
    /usr/bin/jpegtran           0          15 stages          ended inside build_exploit

Three defects, none about analysis quality: the campaign was never budgeted (every target got
the stage default of 30s/3,000 execs); a single stage could outlast the whole run (two are
registered at 3600s against a 420s case); and the two binaries that found nothing produced
identical-looking reports, one after 2,756 executions and one after none. See analyze/budget.py.

    python3 tools/breadth_probe.py                      # 8 random /usr/bin binaries
    python3 tools/breadth_probe.py --budget 300 /bin/ls /usr/bin/xxd
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from lykos import observe  # noqa: E402
from lykos.analyze import register  # noqa: E402
from lykos.analyze.ingest import enqueue_triage, ingest  # noqa: E402
from lykos.analyze.orchestrate import SCORECARD_EVENT, run_case_autopilot  # noqa: E402
from lykos.casestore import CaseStore  # noqa: E402
from lykos.db.dao import AnalysisRunDAO, EventDAO, FindingDAO, TargetDAO  # noqa: E402
from lykos.jobs import JobConfig, JobQueue, WorkerPool  # noqa: E402


def probe(path: Path, workdir: Path, budget: float, overrides=None) -> dict:
    out: dict = {"binary": str(path), "size": path.stat().st_size}
    register()
    store = CaseStore.open(workdir / "case")
    case = store.cases.create(path.name)
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=3, poll_interval=0.02))
    pool.start()
    t0 = time.time()
    try:
        staged = workdir / path.name
        shutil.copy2(path, staged)
        t = ingest(store, case.id, staged, filename=path.name)
        enqueue_triage(JobQueue(store.conn), t, force=True)
        pool.wait_idle(180)
        tg = TargetDAO(store.conn).get(t.id)
        mit = tg.mitigations or {}
        out["triage"] = {"file_type": tg.file_type, "arch": tg.arch, "stripped": tg.stripped,
                         "linking": tg.linking, "pie": mit.get("pie"),
                         "canary": mit.get("canary"), "relro": mit.get("relro")}
        status: dict = {}
        stop = threading.Event()
        th = threading.Thread(target=run_case_autopilot,
                              args=(workdir / "case", case.id, [t.id], status, stop, budget,
                                    overrides), daemon=True)
        th.start()
        # The budget is the autopilot's to keep; allow a grace for the tail before forcing it.
        th.join(timeout=budget * 1.5 + 120)
        if th.is_alive():
            stop.set()
            th.join(timeout=90)
            out["forced_stop"] = True
        out["seconds"] = int(time.time() - t0)

        # By type, unwindowed: the scorecard is the LAST event of the case, so `limit=8000` was
        # a ceiling that a longer budget or a multi-target case would silently cross -- and the
        # probe would then report an empty scorecard as if the run had done nothing.
        events = EventDAO(store.conn)
        cards = events.payloads_of_type(SCORECARD_EVENT, case_id=case.id)
        out["scorecard"] = cards[-1] if cards else {}

        runs = AnalysisRunDAO(store.conn).list_by_case(case.id)
        by: dict = {}
        for r in runs:
            by[r.status] = by.get(r.status, 0) + 1
        out["run_status"] = by
        out["errors"] = [(r.stage, (r.error or "")[:100]) for r in runs if r.status == "error"]

        # What each stage said when it declined -- the operator-facing half of a null result.
        # `walk`, because this one really does need every event: it matches on payload fields
        # across every event type rather than on one type.
        says = []
        for e in events.walk(case_id=case.id):
            pl = e.payload if isinstance(e.payload, dict) else {}
            note = pl.get("note")
            if note and (pl.get("applicable") is False or pl.get("supported") is False
                         or pl.get("ran") is False):
                says.append(f"{e.type}: {str(note)[:140]}")
        out["declines"] = says

        fs = FindingDAO(store.conn).list_by_target(t.id)
        states: dict = {}
        for f in fs:
            states[f.state] = states.get(f.state, 0) + 1
        out["finding_states"] = states
        out["findings"] = [{"state": f.state, "cwe": f.cwe, "detector": f.detector,
                            "title": (f.title or "")[:60]} for f in fs]
    except Exception as e:                                           # noqa: BLE001
        out["harness_error"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            pool.stop()
        finally:
            store.close()
    return out


def _row(r: dict) -> str:
    card = r.get("scorecard") or {}
    ex = card.get("executions") or {}
    base = card.get("baseline") or {}
    st = card.get("stages") or {}
    base_txt = ("ran" if base.get("ran") and not base.get("crashed")
                else "FAULT" if base.get("ran") else "NO-RUN" if base else "-")
    return ("%-26s %-7s %9s %7s  %-18s %s" % (
        Path(r["binary"]).name[:26],
        base_txt,
        f'{ex.get("total", 0):,}',
        f'{ex.get("per_second", 0):g}/s',
        "done %s skip %s err %s" % (st.get("done", 0), st.get("skipped", 0),
                                    st.get("error", 0)),
        ",".join(f"{k} {v}" for k, v in sorted((r.get("finding_states") or {}).items())) or "-"))


def main() -> int:
    # These harnesses are diagnostic instruments, so their diagnostics have to be readable. With
    # nothing configured, a `_log.warning` from inside the engine reaches stderr through
    # `logging.lastResort` -- no timestamp, no module, no line -- which is how a gate run prints
    # "run <uuid> is past its deadline" with no indication of which stage said it. `LYKOS_LOG`
    # still selects the level, so the default stays quiet.
    observe.configure()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("binaries", nargs="*",
                    help="files to probe (default: a random /usr/bin sample)")
    ap.add_argument("--budget", type=float, default=420.0, help="seconds per binary")
    ap.add_argument("-n", type=int, default=8, help="how many to sample when none are named")
    ap.add_argument("--seed", type=int, default=None, help="sampling seed (default: time-based)")
    ap.add_argument("--json", default=None, help="write the full records here")
    args = ap.parse_args()

    if args.binaries:
        paths = [Path(b) for b in args.binaries]
    else:
        cands = [p for p in Path("/usr/bin").iterdir()
                 if p.is_file() and not p.is_symlink() and os.access(p, os.X_OK)]
        random.Random(args.seed).shuffle(cands)
        paths = cands[:args.n]

    results = []
    print("%-26s %-7s %9s %7s  %-18s %s" % ("BINARY", "BASELINE", "EXECS", "RATE",
                                            "STAGES", "FINDINGS"))
    for p in paths:
        if not p.is_file():
            print(f"{p}: not a file", file=sys.stderr)
            continue
        d = Path(tempfile.mkdtemp(prefix="breadth-"))
        try:
            r = probe(p, d, args.budget)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        results.append(r)
        print(_row(r), flush=True)

    ran = [r for r in results if ((r.get("scorecard") or {}).get("executions") or {}).get("total")]
    print(f"\n{len(ran)}/{len(results)} executed the target at all.")
    starved = [Path(r["binary"]).name for r in results
               if (r.get("scorecard") or {}).get("stages_skipped_for_budget")]
    if starved:
        print("ran out of budget before some stages: " + ", ".join(starved))
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1))
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
