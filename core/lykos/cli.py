"""Minimal CLI (DM-02): `lykos db init|upgrade|version --case-store DIR`.

Enough to create/migrate a case DB; `serve` and other commands arrive in later epics.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, observe
from .casestore import CaseStore
from .db.migrations import current_version


def _cmd_db(args: argparse.Namespace) -> int:
    case_dir = Path(args.case_store)
    if args.db_command in ("init", "upgrade"):
        store = CaseStore.open(case_dir)  # init_db() migrates to head either way
        v = current_version(store.conn)
        action = "initialized" if args.db_command == "init" else "upgraded"
        print(f"case store {action}: {case_dir} (schema v{v})")
        store.close()
        return 0
    if args.db_command == "version":
        store = CaseStore.open(case_dir)
        print(current_version(store.conn))
        store.close()
        return 0
    print(f"unknown db command: {args.db_command}", file=sys.stderr)
    return 2


def _cmd_serve(args: argparse.Namespace) -> int:
    from .api import serve
    http = None
    if args.http:
        host, _, port = args.http.rpartition(":")
        # A malformed bind ("localhost", "127.0.0.1:http") died in a traceback; say what is wrong.
        try:
            http = (host or "127.0.0.1", int(port))
        except ValueError:
            print(f"--http needs HOST:PORT (e.g. 127.0.0.1:8787), got {args.http!r}",
                  file=sys.stderr)
            return 2
        if not 0 < http[1] < 65536:
            print(f"--http port out of range: {http[1]}", file=sys.stderr)
            return 2
    if not args.socket and not http:
        print("serve needs --socket and/or --http", file=sys.stderr)
        return 2
    serve(args.case_store, args.socket, http=http, workers=args.workers)
    return 0


def _cmd_analyze(args) -> int:
    """Point the pipeline at a binary and print what it did and what it found.

    This did not exist. The platform's entry points were `serve` (the browser console) and the
    gates, so the only way to analyse a file was through the UI or by importing the orchestrator
    in Python -- which also meant the pipeline was never exercised the way an operator would
    exercise it, on a binary nobody had prepared. The first run of this command over four stock
    /usr/bin binaries is what produced the budget findings recorded in `analyze/budget.py`.
    """
    import tempfile
    import threading
    import time

    from .analyze import register
    from .analyze.ingest import enqueue_triage, ingest
    from .analyze.orchestrate import run_case_autopilot
    from .casestore import CaseStore
    from .db.dao import FindingDAO, TargetDAO
    from .jobs import JobConfig, JobQueue, WorkerPool

    path = Path(args.binary)
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2
    case_dir = Path(args.case_store) if args.case_store else Path(
        tempfile.mkdtemp(prefix="lykos-case-"))
    register()
    store = CaseStore.open(case_dir)
    case = store.cases.create(args.name or path.name)
    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=args.workers, poll_interval=0.02))
    pool.start()
    rc = 0
    try:
        # The operator's facts, threaded to every stage that can use them. Without this channel
        # the autopilot could only ever GUESS how the target takes its input -- and a program
        # given its input on the wrong channel looks exactly like a program with no bugs.
        over = {}
        if args.argv:
            import shlex
            over["argv"] = shlex.split(args.argv)
        if args.seed:
            over["seed_files"] = [str(Path(x).resolve()) for x in args.seed]
        if args.input_mode:
            over["input_mode"] = args.input_mode
        t = ingest(store, case.id, path, filename=path.name)
        enqueue_triage(JobQueue(store.conn), t, force=True)
        pool.wait_idle(180)
        tg = TargetDAO(store.conn).get(t.id)
        print(f"target   {path.name}  {tg.file_type or '?'} {tg.arch or '?'} "
              f"{'stripped' if tg.stripped else 'with symbols'} "
              f"{(tg.mitigations or {}).get('pie', '?')}/pie")
        print(f"budget   {args.budget:g}s   case {case_dir}")
        status: dict = {"state": "starting"}
        stop = threading.Event()
        th = threading.Thread(target=run_case_autopilot,
                              args=(case_dir, case.id, [t.id], status, stop, args.budget,
                                    over),
                              daemon=True)
        th.start()
        # `--budget N` has to mean something to the person who typed it, so this is a hard
        # wall-clock wait, not a poll-until-done. The budget bounds what each STAGE may be
        # allowed; a stage that never polls its own deadline cannot be interrupted, so the
        # tail allowance below is what keeps the command from hanging on one wedged stage.
        deadline = time.monotonic() + args.budget * 1.5 + 120.0
        # WHAT EACH STAGE DID, as it happens. This printed `.. <stage>` on the stage NAME
        # changing, so an operator watching a 15-minute run saw a dozen bare names and learned
        # nothing: not whether a stage worked, refused, was skipped for budget or errored, and
        # not what it found. All of that is already in `status["plan"]` -- the autopilot writes a
        # state and a detail per stage -- and the loop was throwing it away.
        seen: dict = {}
        while th.is_alive() and time.monotonic() < deadline:
            th.join(timeout=2.0)
            if not args.quiet:
                _tick_plan(status, seen)
        if th.is_alive():
            stop.set()
            th.join(timeout=90)
            print("\n(stopped: the run outlasted its budget and the tail allowance; the "
                  "scorecard below covers what finished)")
        card = status.get("scorecard") or {}
        _print_scorecard(card)
        findings = [f for f in FindingDAO(store.conn).list_by_target(t.id)]
        _print_findings(findings)
        # THE DELIVERABLE. A verified PoC is a self-contained tarball with the target, the input
        # and a runner script -- and the run never said it existed, let alone where. Anyone who
        # wanted the thing the tool is for had to know that artifacts live in the case directory
        # and that a bundle is the one with `poc-bundle` in its kind. Write them out next to
        # wherever the operator is standing, and print the command that runs one.
        _export_pocs(store, t, Path(args.out or ".").resolve())
        if args.report:
            # Format follows the file suffix (.pdf/.sarif/.json, else HTML), and the file is
            # written as UTF-8 explicitly -- the HTML carries non-ASCII ("—", "·") and a
            # non-UTF-8 locale on an offline box raised UnicodeEncodeError after the whole run.
            _write_report(store, case.id, Path(args.report), None)
            print(f"\nreport   {args.report}")
        # Exit code says whether anything was DEMONSTRATED, not whether anything was printed.
        rc = 0 if any(f.state in ("confirmed", "poc-backed") for f in findings) else 1
    finally:
        pool.stop()
        store.close()
    return rc


#: How a plan state reads in the live view. The words are chosen so that "nothing was found" and
#: "this could not run here" and "we ran out of time" are never the same line.
_STATE_WORD = {
    "running": "..",
    "done": "ok",
    "skipped": "--",       # out of budget, or not applicable before it started
    "declined": "no",
    "error": "!!",
    "cancelled": "--",
}


def _tick_plan(status: dict, seen: dict) -> None:
    """Print every plan entry whose state changed since the last tick."""
    for p in list(status.get("plan") or []):
        stage, state = p.get("stage"), p.get("state") or "pending"
        if not stage or state == "pending":
            continue
        detail = (p.get("detail") or "").strip()
        key = (state, detail)
        if seen.get(stage) == key:
            continue
        seen[stage] = key
        # A stage the run never reached is `skipped` with nothing to say, and `_finalize_plan`
        # marks every remaining one at once -- which flooded the tail of the run with a dozen
        # blank lines. The scorecard's "not reached" line already names them; a skip WITH a
        # reason ("no budget left in the search phase") is the useful case and still prints.
        if state in ("skipped", "cancelled") and not detail:
            continue
        word = _STATE_WORD.get(state, state[:2])
        label = p.get("label") or stage
        line = f"  {word} {label:<28}"
        if state != "running" and detail:
            line += f" {detail[:84]}"
        print(line, flush=True)


def _export_pocs(store, target, out_dir) -> None:
    """Write every verified PoC bundle to disk and say how to run it."""
    from .db.dao import PocDAO
    try:
        pocs = [p for p in PocDAO(store.conn).list_by_target(target.id)
                if getattr(p, "verified", False) and getattr(p, "bundle_sha", None)]
    except Exception:                                    # noqa: BLE001 -- advisory
        return
    if not pocs:
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    print("\n-- proof of concept " + "-" * 57)
    for p in sorted(pocs, key=lambda x: str(x.level), reverse=True)[:6]:
        name = f"{target.filename}-{p.level}-{str(p.bundle_sha)[:8]}.tar.gz"
        dest = out_dir / name
        try:
            dest.write_bytes(store.content.get_bytes(p.bundle_sha))
        except Exception:                                # noqa: BLE001 -- one bad artifact
            continue
        print(f"  {p.level}  {dest}")
        print(f"      tar xzf {name} && sh poc/runner.sh   # prints what it proves, exits "
              f"non-zero on the fault")
    print("  RUN IN A SANDBOX OR VM: a PoC executes an untrusted binary. Authorized use only.")


def _print_fuzz_health(fh) -> None:
    """Per-engine fuzzing health -- the same verdicts the web GUI's panel shows, including how the
    attempts ENDED, so a CLI run can tell a campaign from an error loop too."""
    if not fh or not fh.get("engines"):
        return
    print(f"  fuzzing      {fh.get('verdict')}: {fh.get('note')}")
    for e in fh["engines"]:
        oc = e.get("outcomes") or {}
        mix = ", ".join(f"{k.replace('_', ' ')} {v:,}" for k, v in oc.items() if v)
        val = e.get("value") or {}
        gain = (f"; +{val['gained']} {val['unit']} beyond seeds"
                if val.get("unit") in ("blocks", "behaviours", "edges") and val.get("gained") is not None
                else "")
        line = f"    - {e['engine']:<14} {e['status']:<10}"
        if e.get("execs"):
            line += f" {e['execs']:,} attempts"
        if mix:
            line += f" ({mix})"
        line += gain
        if e.get("reason"):
            line += f" -- {e['reason']}"
        print(line[:300])
        if e.get("log"):
            print(f"      log: lykos fuzz-log --case-store <case> --log {e['log'][:12]}")


def _cmd_fuzz_log(args: argparse.Namespace) -> int:
    """Print a fuzz engine's per-attempt log: every execution, what was sent and how it ended.
    The CLI twin of the web GUI's attempt-log viewer."""
    import json as _json

    from .analyze.fuzz import attempts as _attempts
    from .casestore import CaseStore
    store = CaseStore.open(Path(args.case_store))
    logs = []
    for case in store.cases.list():
        for a in store.artifacts.list_by_case(case.id):
            if a.kind == _attempts.LOG_KIND:
                logs.append(a)
    logs.sort(key=lambda a: a.created_at)
    if args.engine:
        logs = [a for a in logs if (a.meta or {}).get("engine") == args.engine]
    if args.target:
        logs = [a for a in logs if str((a.meta or {}).get("target_id") or "").startswith(args.target)]
    if args.log:
        logs = [a for a in logs if a.sha256.startswith(args.log)]
    if not logs:
        print("no fuzz attempt logs match (they are written by runs made with this build)",
              file=sys.stderr)
        return 1
    if not (args.log or args.engine) or args.list:
        for a in logs:
            m = a.meta or {}
            c = m.get("counts") or {}
            mix = ", ".join(f"{k.replace('_', ' ')} {v:,}" for k, v in c.items() if v)
            print(f"{a.sha256[:12]}  {str(m.get('engine')):<14} {m.get('attempts', 0):>8,} "
                  f"attempts  {str(m.get('verdict')):<12} {mix}")
        if args.list or len(logs) > 1:
            print("\nshow one: --log <id>  (or --engine <name> for its latest)")
            return 0
    a = logs[-1]
    out = _attempts.read_log(store.content.path(a.sha256),
                             outcome=[x for x in (args.outcome or "").split(",") if x] or None,
                             phase=[x for x in (args.phase or "").split(",") if x] or None,
                             offset=args.offset, limit=args.limit, errors_only=args.errors_only)
    if args.json:
        print(_json.dumps(out, indent=1))
        return 0
    sm, hd = out["summary"], out["header"]
    print(f"engine {hd.get('engine')}  log {a.sha256[:12]}  {out['total']:,} attempts  "
          f"verdict {sm['verdict']}")
    print(f"  {sm['verdict_note']}")
    for o, tops in (sm.get("top_errors") or {}).items():
        for t in tops[:2]:
            print(f"  top {o:<10} x{t['count']:<6,} rc={t['rc']}  {t['msg']}")
    print(f"\n{'#':>7} {'t(s)':>8} {'phase':<9} {'outcome':<11} {'rc/sig':<9} {'ms':>6} "
          f"{'len':>6} {'new':>4}  input / stderr")
    for r in out["rows"]:
        rcs = r.get("sig") or ("" if r.get("rc") is None else str(r.get("rc")))
        tail = r.get("err") or r.get("note") or ""
        print(f"{r.get('i', 0):>7} {r.get('t', 0):>8.2f} {str(r.get('ph')):<9} "
              f"{str(r.get('o')):<11} {rcs:<9} {r.get('ms', ''):>6} {r.get('len', 0):>6} "
              f"{r.get('new', ''):>4}  {r.get('head', '')[:24]}{'  ' + tail if tail else ''}"[:220])
    shown = len(out["rows"])
    if out["matched"] > args.offset + shown:
        print(f"\n{out['matched'] - args.offset - shown:,} more -- use --offset {args.offset + shown}")
    return 0


def _print_scorecard(card: dict) -> None:
    """What the run DID. Printed before the findings, because it is what makes them readable."""
    if not card:
        print("\nscorecard unavailable (the run did not complete a target)")
        return
    base = card.get("baseline") or {}
    ex = card.get("executions") or {}
    bud = card.get("budget") or {}
    print("\n-- what this run did " + "-" * 56)
    if base:
        print("  baseline     " + ("ran, exited normally" if base.get("ran")
                                   and not base.get("crashed")
                                   else "ran, FAULTED" if base.get("ran")
                                   else "DID NOT RUN: " + str(base.get("note") or
                                                              base.get("isolation"))))
    else:
        print("  baseline     not attempted")
    rate = ex.get("per_second")
    print(f"  executions   {_fmt_n(ex.get('total'))}" + (f"  ({_fmt_g(rate)}/s)" if rate else ""))
    by = ex.get("by_engine") or {}
    for k, v in sorted(by.items(), key=lambda kv: -(kv[1] if isinstance(kv[1], (int, float))
                                                    else 0)):
        print(f"               {k:<14} {_fmt_n(v)}")
    st = card.get("stages") or {}
    print("  stages       " + ", ".join(f"{k} {v}" for k, v in sorted(st.items())))
    if card.get("stages_skipped_for_budget"):
        print("  out of time  " + ", ".join(card["stages_skipped_for_budget"][:8]))
    if bud.get("total"):
        print(f"  budget       {_fmt_g(bud.get('elapsed'))}s of {_fmt_g(bud['total'])}s")
        # What that clock was WORTH here. 2,761 executions is a good result at 5 exec/s and a
        # near-total failure at 580, and the count alone cannot tell them apart.
        _adv = bud.get("advice") or {}
        if _adv.get("note"):
            print(f"  exec rate    {_adv['note']}"
                  + ("" if _adv.get("measured") else "  (estimated from the substrate)"))
        dear = list((bud.get("by_stage") or {}).items())[:4]
        if dear:
            print("  dearest      " + ", ".join(f"{k} {v:g}s" for k, v in dear))
    # HOW MUCH OF THAT WAS SEARCH. "budget 134s of 180s" does not answer it, and a null result is
    # worth exactly what the search behind it was worth: libtiff at a 200s budget showed six
    # capabilities working and no crashes -- indistinguishable from a clean library -- while the
    # same tarball with a real search slice found a heap overflow in six executions.
    if card.get("search_seconds") is not None:
        _s = card["search_seconds"]
        _tot = bud.get("elapsed") or 0
        print(f"  search       {_s:g}s in the engines"
              + (f" ({_s / _tot * 100:.0f}% of the run)" if _tot else "")
              + ("   <- little of this run was spent searching" if _tot and _s < _tot * 0.25
                 else ""))
    # THE DOORS. In-process fuzzing goes through one harness at a time, and a library has many
    # entry points: "2,501 executions" is a different fact depending on whether they went through
    # the parser or one string helper. Naming each door, and saying which were never opened, is
    # what makes a null result on a library readable.
    ip = card.get("in_process") or {}
    if ip.get("doors"):
        n, planned = ip.get("entry_points", 0), ip.get("planned", 0)
        print(f"  entry points {n} fuzzed in-process"
              + (f" of {planned} planned" if planned > n else ""))
        for d in ip["doors"][:8]:
            if d.get("built"):
                mark = f"{d['execs']:,} execs" + (f", {d['findings']} finding(s)"
                                                  if d.get("findings") else "")
            elif "budget" in (d.get("why") or ""):
                # It was planned and never reached, which is the budget's doing and not a
                # failure of the harness -- the two must not read alike.
                mark = "NOT RUN: " + d["why"]
            else:
                mark = "NOT BUILT: " + (d.get("why") or "no reason given")
            print(f"    - {str(d.get('entry') or '?'):28} {mark}")
    _print_fuzz_health(card.get("fuzz_health"))
    # THE LADDER. This is what the tool exists to produce and the run never printed it.
    poc = card.get("poc") or {}
    ncr = card.get("crashes")
    if ncr is not None or poc:
        lvl = poc.get("level", 0)
        ladder = {0: "L0 (no verified reproducer)",
                  1: "L1 (verified crash reproducer)",
                  2: "L2 (confirmed exploitation primitive)",
                  3: "L3 (working exploit)"}.get(lvl, f"L{lvl}")
        print(f"  crashes      {ncr or 0} recorded")
        print(f"  poc          {ladder}"
              + (f", {poc.get('verified', 0)} verified of {poc.get('total', 0)} built"
                 if poc.get("total") else ""))
        # A crash with no verified reproducer is the one outcome that most needs saying out loud.
        if (ncr or 0) > 0 and lvl == 0:
            print("               ^ a crash was recorded but NOTHING was verified -- the "
                  "reproducer did not re-crash")
    # WHICH CAPABILITIES DID THEIR JOB. Without this the only readable signal was elapsed
    # seconds, and a stage that refuses in nine seconds prints exactly like one that worked for
    # nine. `libfuzzer` on an ASan libtiff build reported "build failed: 'tiffio.h' not found"
    # and still showed up as 9.0s among the completed stages.
    cap = card.get("capability") or {}
    declined = card.get("declined") or {}
    if cap:
        print(f"  capability   {len(cap.get('worked') or [])} did work, "
              f"{len(cap.get('declined') or [])} declined, "
              f"{len(cap.get('errored') or [])} errored, "
              + (f"{len(cap['cancelled'])} cut short, " if cap.get("cancelled") else "")
              + f"{len(cap.get('never_scheduled') or [])} never scheduled "
              f"(of {cap.get('registered', 0)} registered)")
        if cap.get("errored"):
            print("  ERRORED      " + ", ".join(cap["errored"][:6]))
        # A stage the budget stopped is not a failure and not a result: it is a stage whose
        # answer nobody has. Saying so is the difference between "found nothing" and
        # "was not allowed to look".
        if cap.get("cancelled"):
            print("  cut short    " + ", ".join(cap["cancelled"][:6])
                  + " (out of budget -- raise --budget to let them finish)")
        if cap.get("never_scheduled"):
            print("  not reached  " + ", ".join(cap["never_scheduled"][:8])
                  + (" ..." if len(cap["never_scheduled"]) > 8 else ""))
    # Errors the run absorbed on purpose, counted at their own site. Zero is the interesting
    # number: it says the thin result above is the target's doing and not ours. A non-zero one is
    # not a failure either -- a parser that did not apply absorbs on every candidate -- but it is
    # the first place to look when a run found less than expected, and `--log debug` then prints
    # each one with its traceback.
    if card.get("settled") is False:
        print("  INCOMPLETE   a stage was still finishing when this card was built, so the "
              "counts above\n               are a floor, not a total")
    absorbed = card.get("absorbed") or {}
    if absorbed.get("total"):
        print(f"  absorbed     {absorbed['total']} best-effort step(s) failed quietly, "
              f"at {absorbed.get('sites', 0)} site(s)")
        for row in (absorbed.get("top") or [])[:3]:
            print(f"               {row.get('count'):>4}x {row.get('site')}")
        print("               (re-run with --log debug for each one's traceback)")
    elif absorbed:
        print("  absorbed     nothing -- no step failed quietly in this run")
    if declined:
        # WHOSE FAULT. These two printed identically until now:
        #   libfuzzer  no source for this target (libFuzzer needs C/C++ source to build a harness)
        #   libfuzzer  libFuzzer build failed: 'tiffio.h' file not found
        # The first is a fact about the target. The second is our defect, and it means this run
        # is INCOMPLETE for a reason that can be fixed -- which the operator needs before they
        # read "0 crashes" as an answer.
        from .analyze.capabilities import classify_decline
        kinds = {stage: classify_decline(why) for stage, why in declined.items()}
        ours = [s for s, k in kinds.items() if k == "ours"]
        unknown = [s for s, k in kinds.items() if k == "unknown"]
        print("  declined (ran, but could not apply here):")
        for stage, why in sorted(declined.items())[:10]:
            mark = {"ours": "  [OUR DEFECT]", "unknown": "  [unclassified]"}.get(
                kinds.get(stage), "")
            print(f"               {stage:<14} {why[:74]}{mark}")
        if ours:
            print("  INCOMPLETE   " + ", ".join(sorted(ours))
                  + " declined because of a defect on OUR side, not a property of this target."
                  + " Treat this run's null results as unproven.")
        if unknown:
            print("  unclassified " + ", ".join(sorted(unknown))
                  + " -- nobody has judged whether that reason is the target's or ours")


def _fmt_n(v) -> str:
    """A count with separators; a missing (None) or odd value prints instead of raising -- the
    scorecard is printed AFTER a long run, and one null field used to lose all of it."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return "0" if v is None else str(v)
    return f"{v:,}" if isinstance(v, int) else f"{v:,.1f}"


def _fmt_g(v) -> str:
    return f"{v:g}" if isinstance(v, (int, float)) and not isinstance(v, bool) else str(v or 0)


_REPORT_FORMATS = ("html", "pdf", "sarif", "json")


def _report_format(path: Path, fmt) -> str:
    if fmt:
        return fmt
    suf = path.suffix.lower().lstrip(".")
    return {"htm": "html", "sarif": "sarif", "json": "json", "pdf": "pdf"}.get(suf, "html")


def _render_report(rep: dict, fmt: str) -> bytes:
    import json as _json
    if fmt == "pdf":
        from .report.pdf import to_pdf
        return to_pdf(rep)
    if fmt == "sarif":
        from .report.sarif import to_sarif
        return _json.dumps(to_sarif(rep), indent=2).encode("utf-8")
    if fmt == "json":
        from .report.casejson import to_case_json_bytes
        return to_case_json_bytes(rep)
    from .report.html import to_html
    return to_html(rep).encode("utf-8")


def _write_report(store, case_id: str, path: Path, fmt, **kw) -> str:
    from .report.model import build_report
    fmt = _report_format(path, fmt)
    rep = build_report(store, case_id, embed_pocs=kw.pop("embed_pocs", fmt in ("html", "json")),
                       **kw)
    path.write_bytes(_render_report(rep, fmt))
    return fmt


def _cmd_report(args: argparse.Namespace) -> int:
    """Render a kept case's report offline -- the CLI twin of the web GUI's report builder
    (`GET /cases/{id}/report`). Before this the only CLI report was `analyze --report`, written
    once at the end of a run; a case curated or re-run afterwards could not be re-reported
    without the server."""
    case_dir = Path(args.case_store)
    if not (case_dir / "case.db").is_file():
        # CaseStore.open would CREATE an empty store here and report on nothing.
        print(f"no case store at {case_dir} (expected {case_dir / 'case.db'})", file=sys.stderr)
        return 2
    store = CaseStore.open(case_dir)
    try:
        cases = list(store.cases.list())
        if args.case:
            hit = [c for c in cases if c.id == args.case or c.id.startswith(args.case)
                   or c.name == args.case]
        else:
            hit = cases if len(cases) == 1 else []
        if len(hit) != 1:
            why = ("no case matches " + repr(args.case) if args.case and not hit
                   else "several cases match; pass --case <id>" if hit
                   else "this store holds no case" if not cases
                   else "this store holds several cases; pass --case <id>")
            print(why, file=sys.stderr)
            for c in cases[:20]:
                print(f"  {c.id}  {c.name}", file=sys.stderr)
            return 2
        states = [x.strip() for x in (args.states or "").split(",") if x.strip()] or None
        out = Path(args.out) if args.out else None
        fmt = args.format or (_report_format(out, None) if out else "html")
        kw = dict(min_severity=args.min_severity, min_state=args.min_state, states=states)
        try:
            if out is None:
                from .report.model import build_report
                rep = build_report(store, hit[0].id, embed_pocs=args.embed_pocs, **kw)
                data = _render_report(rep, fmt)
                if fmt == "pdf":
                    sys.stdout.buffer.write(data)
                else:
                    sys.stdout.write(data.decode("utf-8"))
                return 0
            _write_report(store, hit[0].id, out, fmt,
                          embed_pocs=args.embed_pocs or fmt in ("html", "json"), **kw)
        except ValueError as e:                          # an unknown --states value
            print(f"report: {e}", file=sys.stderr)
            return 2
        print(f"{fmt} report written to {out}", file=sys.stderr)
        return 0
    finally:
        store.close()


def _print_findings(findings) -> None:
    print("\n-- findings " + "-" * 64)
    if not findings:
        print("  none. Read that against the scorecard above: no findings after a campaign that "
              "ran\n  is a result; no findings after one that did not is not.")
        return
    order = {"poc-backed": 0, "confirmed": 1, "corroborated": 2, "candidate": 3}
    for f in sorted(findings, key=lambda f: (order.get(f.state, 9), f.cwe or "")):
        # str(): a finding row with a NULL state/severity raised TypeError in the format spec
        # and lost the whole findings list at the end of a long run.
        print(f"  [{str(f.state or '?'):<12}] {str(f.severity or '?'):<8} {f.cwe or '-':<10} "
              f"{(f.title or '')[:52]:<52} {f.detector or ''}")
    demod = [f for f in findings if f.state in ("confirmed", "poc-backed")]
    print(f"\n  {len(demod)} demonstrated, {len(findings) - len(demod)} detected only.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lykos", description="lykos core CLI")
    p.add_argument("--version", action="version", version=f"lykos {__version__}")
    # Nothing in the tree configured logging, so every `_log.debug(..., exc_info=True)` written
    # to leave evidence of a swallowed error was discarded before it reached anything. This is
    # the switch that connects it. `debug` also makes `observe.absorbed` print each absorbed
    # step with its traceback and the exact handler that absorbed it.
    p.add_argument("--log", default=None, metavar="LEVEL",
                   choices=["debug", "info", "warning", "error"],
                   help=f"log level for diagnostics (default from ${observe.LEVEL_VAR}, else "
                        f"warning); ${observe.FILE_VAR} adds a file sink")
    sub = p.add_subparsers(dest="command", required=True)

    db = sub.add_parser("db", help="database lifecycle")
    db.add_argument("db_command", choices=["init", "upgrade", "version"])
    db.add_argument("--case-store", required=True, help="case directory")
    db.set_defaults(func=_cmd_db)

    sv = sub.add_parser("serve", help="run the local API + event stream (+ UI)")
    sv.add_argument("--socket", default=None, help="unix socket path to bind")
    sv.add_argument("--http", default=None, help="loopback bind for the UI, e.g. 127.0.0.1:8787")
    sv.add_argument("--case-store", required=True, help="case directory")
    sv.add_argument("--workers", type=int, default=None, help="worker count (default cores-1)")
    sv.set_defaults(func=_cmd_serve)

    ev = sub.add_parser("eval", help="run the validation benchmark (doc 14) and score it")
    ev.add_argument("--stage", choices=["static", "dynamic", "lava"], default="static",
                    help="static = candidate-stage CWE detection (Ghidra); "
                         "dynamic = confirmed-stage crash reproduction via fuzzing; "
                         "lava = LAVA-M injected-bug finding recall")
    ev.add_argument("--lava", default=None,
                    help="path to an unpacked NIST LAVA-M drop to fuzz (implies --stage lava)")
    ev.add_argument("--corpus", default=None,
                    help="directory of <CWE>__<name>__<good|bad>.c cases (default: bundled)")
    ev.add_argument("--juliet", default=None,
                    help="path to an unpacked NIST Juliet C drop to score")
    ev.add_argument("--cwe", default=None,
                    help="comma-separated CWE filter for --juliet, e.g. CWE-121,CWE-134")
    ev.add_argument("--limit", type=int, default=None,
                    help="cap the number of Juliet testcases (drops are huge)")
    ev.add_argument("--min-state", choices=["candidate", "corroborated", "confirmed"],
                    default="candidate",
                    help="finding state a static case must reach to count as detected "
                         "(candidate = rule/sink channel; corroborated = taint-discriminated)")
    ev.add_argument("--benchmark", action="store_true",
                    help="score the detection BENCHMARK and print precision/recall/F1 as a TRACKED "
                         "number, not a gate (always exits 0). Runs the vendored breadth corpus "
                         "(10 CWE classes) at both candidate and corroborated, plus the LAVA-M "
                         "recall mini, and records each to the dashboard history. Use --juliet/"
                         "--lava to benchmark a real NIST drop instead of the bundled set.")
    ev.add_argument("--out", default=None, help="write the full JSON report to this path")
    ev.add_argument("--arch", default=None,
                    help="static only: cross-compile the corpus and score detection PER arch "
                         "(comma-list like aarch64,arm,riscv64, or 'all'); an arch whose "
                         "cross-compiler is absent is skipped. Ratchets each arch against "
                         "eval/arch_baseline.json: fails if any arch gains a false positive or a "
                         "false negative versus its baseline.")
    ev.add_argument("--arch-update-baseline", action="store_true",
                    help="with --arch: rewrite eval/arch_baseline.json to the measured counts "
                         "instead of gating (use after a deliberate detection change).")
    ev.add_argument("--workers", type=int, default=2, help="worker count (default 2)")
    ev.add_argument("--min-recall", type=float, default=1.0,
                    help="release gate: fail if overall recall is below this (default 1.0)")
    ev.add_argument("--max-fp-rate", type=float, default=0.0,
                    help="release gate: fail if the FP-rate exceeds this (default 0.0)")
    ev.add_argument("--require-backend", action="store_true",
                    help="fail (not skip) when the static backend (Ghidra) is absent")
    ev.add_argument("--min-negative", type=int, default=0,
                    help="release gate: fail if fewer than this many 'good' cases were scored "
                         "(guards against a vacuous fp_rate; default 0 = off)")
    ev.add_argument("--record", action="store_true",
                    help="append this run's metrics to the history (for the dashboard)")
    ev.add_argument("--history", default=None,
                    help="history file for --record (default: eval-history.jsonl)")
    ev.add_argument("--label", default=None, help="optional label for the recorded run")
    ev.set_defaults(func=_cmd_eval)

    ag = sub.add_parser("archgate",
                        help="architecture coverage gate: every ISA still reaches its PoC level")
    ag.add_argument("--timeout", type=float, default=30.0, help="per-detonation timeout")
    ag.add_argument("--only", default=None,
                    help="comma-separated arch labels to check (default: all)")
    ag.add_argument("--out", default=None, help="write the JSON report here")
    ag.set_defaults(func=_cmd_archgate)

    rg = sub.add_parser("realgate",
                        help="full-chain gate: detect -> PoC -> attribution on a real program")
    rg.add_argument("--timeout", type=float, default=30.0, help="per-detonation timeout")
    rg.add_argument("--only", default=None,
                    help="comma-separated case labels to check (default: all)")
    rg.add_argument("--out", default=None, help="write the JSON report here")
    rg.set_defaults(func=_cmd_realgate)

    an = sub.add_parser("analyze",
                        help="run the full pipeline on one binary and report what it did")
    an.add_argument("binary", help="the file to analyse")
    an.add_argument("--budget", type=float, default=900.0,
                    help="wall-clock seconds for this target (default 900); divided among the "
                         "recover/search/prove phases")
    an.add_argument("--argv", default=None,
                    help="how the program is invoked, as one shell-quoted string with @@ where "
                         "the input file goes, e.g. --argv '-c @@'. A list form cannot work "
                         "here: argparse reads a leading-dash element as an unknown option.")
    an.add_argument("--seed", action="append", default=None,
                    help="a valid sample input to seed the fuzzer (repeatable)")
    an.add_argument("--input-mode", choices=["stdin", "file", "arg", "env"], default=None,
                    help="how the input reaches the program (default: inferred from its imports)")
    an.add_argument("--case-store", default=None,
                    help="case directory to keep (default: a temporary one)")
    an.add_argument("--name", default=None, help="case name")
    an.add_argument("--report", default=None,
                    help="write the report here; the format follows the suffix (.pdf, .sarif, "
                         ".json, else HTML)")
    an.add_argument("--out", default=None,
                    help="where to write verified PoC bundles (default: the current directory)")
    an.add_argument("--workers", type=int, default=3, help="worker threads (default 3)")
    an.add_argument("-q", "--quiet", action="store_true", help="no per-stage progress")
    an.set_defaults(func=_cmd_analyze)

    rp = sub.add_parser("report",
                        help="render a kept case's report (html | pdf | sarif | json) offline")
    rp.add_argument("--case-store", required=True, help="the case directory")
    rp.add_argument("--case", default=None,
                    help="case id (prefix) or name (default: the store's only case)")
    rp.add_argument("--format", choices=list(_REPORT_FORMATS), default=None,
                    help="default: from the --out suffix, else html")
    rp.add_argument("--out", default=None, help="output file (default: stdout)")
    rp.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"],
                    default=None, help="drop findings below this severity")
    rp.add_argument("--min-state", choices=["candidate", "corroborated", "confirmed", "poc-backed"],
                    default="candidate", help="drop findings below this state (default candidate)")
    rp.add_argument("--states", default=None,
                    help="keep only these states (comma-separated)")
    rp.add_argument("--embed-pocs", action="store_true",
                    help="embed PoC bundles (always on for html/json written to a file)")
    rp.set_defaults(func=_cmd_report)

    fl = sub.add_parser("fuzz-log",
                        help="show a fuzz engine's per-attempt log: every execution and how it ended")
    fl.add_argument("--case-store", required=True, help="the case directory")
    fl.add_argument("--engine", default=None,
                    help="fuzz | directed_fuzz | coverage_fuzz | env_fuzz | net_fuzz | boundary_fuzz")
    fl.add_argument("--target", default=None, help="target id (prefix)")
    fl.add_argument("--log", default=None, help="a log id (prefix) from --list")
    fl.add_argument("--list", action="store_true", help="list the logs only")
    fl.add_argument("--outcome", default=None,
                    help="filter: no_start,crash,timeout,error_exit,clean_exit (comma-separated)")
    fl.add_argument("--phase", default=None,
                    help="filter: seed,mutate,minimize,reproduce,afl-seed,afl-queue,afl-crash,...")
    fl.add_argument("--errors-only", action="store_true", help="every attempt that did not exit 0")
    fl.add_argument("--offset", type=int, default=0)
    fl.add_argument("--limit", type=int, default=200)
    fl.add_argument("--json", action="store_true", help="raw JSON (summary + rows)")
    fl.set_defaults(func=_cmd_fuzz_log)

    dr = sub.add_parser("doctor",
                        help="what this host can and cannot do, and how to fix the gaps")
    dr.add_argument("--json", action="store_true", help="machine-readable output")
    dr.add_argument("-v", "--verbose", action="store_true",
                    help="also say what each present tool unlocks")
    dr.add_argument("--strict", action="store_true",
                    help="exit non-zero unless every REQUIRED tool is present")
    dr.set_defaults(func=_cmd_doctor)

    dp = sub.add_parser("deps",
                        help="build-dependency pre-flight for a source dir: what to stage offline")
    dp.add_argument("path", help="source project directory to pre-flight")
    dp.add_argument("--json", action="store_true", help="machine-readable output")
    dp.add_argument("--no-include-scan", action="store_true",
                    help="skip the #include scan (declarations in the build system only)")
    dp.add_argument("--strict", action="store_true",
                    help="exit non-zero if any declared dependency or build tool is missing")
    dp.set_defaults(func=_cmd_deps)

    db2 = sub.add_parser("dashboard", help="render the detection-quality regression dashboard")
    db2.add_argument("--history", default=None,
                     help="history file to read (default: eval-history.jsonl)")
    db2.add_argument("--html", default=None, help="write a self-contained HTML dashboard here")
    db2.add_argument("--fail-on-regression", action="store_true",
                     help="exit non-zero if the latest run regressed in any series")
    db2.set_defaults(func=_cmd_dashboard)

    bd = sub.add_parser("bindiff",
                        help="patch-diff two binary versions: which functions changed (the fix)")
    bd.add_argument("old", help="the OLD / vulnerable binary")
    bd.add_argument("new", help="the NEW / patched binary")
    bd.add_argument("--json", action="store_true", help="emit the full diff as JSON")
    bd.add_argument("--timeout", type=int, default=600, help="per-binary analysis budget (s)")
    bd.set_defaults(func=_cmd_bindiff)

    vs = sub.add_parser("variant-scan",
                        help="hunt a known-vulnerable function across a corpus of binaries (N-day)")
    vs.add_argument("--ref", required=True,
                    help="reference binary containing the vulnerable function")
    vs.add_argument("--function", "--func", dest="target_func", required=True,
                    help="name of the vulnerable function in --ref")
    vs.add_argument("corpus", nargs="+", help="binaries to scan for an unpatched variant")
    vs.add_argument("--threshold", type=float, default=0.9, help="min similarity to report (0..1)")
    vs.add_argument("--timeout", type=int, default=600, help="per-binary analysis budget (s)")
    vs.add_argument("--json", action="store_true", help="emit results as JSON")
    vs.set_defaults(func=_cmd_variant_scan)

    wg = sub.add_parser("weggli-scan",
                        help="source variant analysis: run the weggli vuln-pattern pack over C/C++")
    wg.add_argument("path", help="source directory (or file) to scan")
    wg.add_argument("--cpp", action="store_true", help="C++ mode")
    wg.add_argument("--json", action="store_true", help="emit findings as JSON")
    wg.add_argument("--timeout", type=int, default=120, help="per-query budget (s)")
    wg.set_defaults(func=_cmd_weggli_scan)

    dt = sub.add_parser("diff-test",
                        help="differential testing: fuzz 2+ implementations, report disagreements")
    dt.add_argument("programs", nargs="+", help="2+ program binaries implementing the same spec")
    dt.add_argument("--mode", choices=("stdin", "arg", "file"), default="stdin",
                    help="how each program takes the input (default stdin)")
    dt.add_argument("--seed", action="append", default=[], help="a seed input FILE (repeatable)")
    dt.add_argument("--iterations", type=int, default=2000, help="mutation iterations")
    dt.add_argument("--compare", choices=("status", "output"), default="status",
                    help="status = accept/reject/crash; output = also compare produced bytes")
    dt.add_argument("--timeout", type=float, default=5.0, help="per-run budget (s)")
    dt.add_argument("--json", action="store_true", help="emit discrepancies as JSON")
    dt.set_defaults(func=_cmd_diff_test)
    return p


def _cmd_diff_test(args: argparse.Namespace) -> int:
    import json
    import random
    from pathlib import Path

    from .analyze.fuzz import differential as D
    if len(args.programs) < 2:
        print("diff-test needs at least two programs", file=sys.stderr)
        return 2
    for pth in args.programs:
        if not Path(pth).exists():
            print(f"no such file: {pth}", file=sys.stderr)
            return 2
    progs = [D.Program(Path(p).name, p, mode=args.mode) for p in args.programs]
    seeds = []
    for s in args.seed:
        try:
            seeds.append(Path(s).read_bytes())
        except OSError as e:
            print(f"skip seed {s}: {e}", file=sys.stderr)
    st = D.differential_campaign(progs, seeds, rng=random.Random(0), iterations=args.iterations,
                                 timeout=args.timeout, compare=args.compare)
    if args.json:
        print(json.dumps({"execs": st.execs, "delta_diversity": st.delta_diversity,
                          "discrepancies": st.discrepancies,
                          "inconclusive": st.inconclusive}, indent=2, default=list))
        return 0
    print(f"diff-test: {st.execs} execs, {st.delta_diversity} distinct behaviour-combinations, "
          f"{len(st.discrepancies)} disagreement(s):\n")
    for d in st.discrepancies[:40]:
        parts = "  ".join(f"[{o}] {','.join(names)}" for o, names in d["partitions"].items())
        print(f"  {d['kind']:<13} on {d['input'][:48]}...")
        print(f"                {parts}")
    if st.discrepancies:
        print("\nEach disagreement is a candidate bug -- one implementation accepts/handles input "
              "another does not. Confirm which behaviour violates the spec.")
    # A program that never ran or timed out casts no vote; "identical" is only true of the inputs
    # every implementation actually executed.
    inc = {n: c for n, c in (st.inconclusive or {}).items() if c}
    if inc:
        print("\ninconclusive runs (never started or timed out -- not counted as a behaviour): "
              + ", ".join(f"{n} x{c}" for n, c in sorted(inc.items())))
    if not st.discrepancies:
        # each program runs every input once: one whose inconclusive count reaches `execs` never
        # produced a single result, and fewer than two such programs means nothing was compared
        live = [p for p in progs if inc.get(p.name, 0) < max(1, st.execs)]
        if len(live) < 2:
            print("no comparison possible: fewer than two implementations produced a conclusive "
                  "result.")
            return 3
        print("no disagreements found on the inputs every implementation executed"
              + (" (some runs were inconclusive, see above)." if inc else "."))
    return 0


def _cmd_weggli_scan(args: argparse.Namespace) -> int:
    import json
    from pathlib import Path

    from .analyze import weggli
    if not Path(args.path).exists():
        print(f"no such path: {args.path}", file=sys.stderr)
        return 2
    r = weggli.scan(args.path, cpp=args.cpp, timeout=args.timeout)
    if args.json:
        print(json.dumps(r, indent=2, default=list))
        # The same exit status as the text form: an unsupported scan (no weggli) is not a clean
        # one, and a script reading --json was told 0 for a scan that never happened.
        return 0 if r.get("supported", True) else 3
    if not r["supported"]:
        print(r["note"], file=sys.stderr)
        return 3
    if not r["findings"]:
        print(f"no vulnerable patterns matched ({r['queries_run']} queries, clean).")
        return 0
    print(f"weggli found {len(r['findings'])} vulnerable pattern(s) "
          f"({r['queries_run']} queries):\n")
    for f in r["findings"]:
        from pathlib import Path as _P
        files = ", ".join(_P(x).name for x in f["files"][:6])
        more = f" (+{len(f['files']) - 6} more)" if len(f["files"]) > 6 else ""
        print(f"  [{f['severity']:<8}] {f['cwe']:<8} {f['name']}  x{f['count']}: {files}{more}")
        print(f"             {f['why']}")
    print("\nEach is a candidate -- confirm the source reaching the sink is untrusted, then "
          "generalize from a confirmed bug with weggli.variant_query to hunt more variants.")
    return 0


def _cmd_variant_scan(args: argparse.Namespace) -> int:
    import json
    from pathlib import Path

    from .analyze import native_re, variant
    ref = Path(args.ref)
    if not ref.exists():
        print(f"no such file: {ref}", file=sys.stderr)
        return 2
    ref_funcs = native_re.analyze(ref, timeout=args.timeout).get("functions") or []
    sigf = next((f for f in ref_funcs if (f.get("name") or "").split(".")[-1] == args.target_func
                 or f.get("name") == args.target_func), None)
    if sigf is None:
        print(f"function {args.target_func!r} not found in {ref.name} "
              f"(has {len(ref_funcs)} functions)", file=sys.stderr)
        return 2
    sig = variant.function_features(sigf)
    results = []
    for path in args.corpus:
        p = Path(path)
        if not p.exists():
            print(f"skip (no such file): {p}", file=sys.stderr)
            continue
        funcs = native_re.analyze(p, timeout=args.timeout).get("functions") or []
        hits = variant.variant_scan(sig, funcs, threshold=args.threshold)
        results.append({"binary": str(p), "hits": hits})
    if not results:
        # Every corpus path was missing: "hunting across 0 binaries" then exit 0 read as clean.
        print("no corpus binary exists; nothing was scanned", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"function": args.target_func, "reference": str(ref), "results": results},
                         indent=2, default=list))
        return 0
    print(f"hunting {args.target_func!r} (from {ref.name}) across {len(results)} binaries, "
          f"threshold {args.threshold}:")
    any_hit = False
    for r in results:
        name = Path(r["binary"]).name
        if r["hits"]:
            any_hit = True
            top = r["hits"][0]
            print(f"  MATCH  {name:<28} {top['name'] or '(unnamed)'} @ {top['addr']}  "
                  f"similarity {top['similarity']}")
        else:
            print(f"  clean  {name}")
    if any_hit:
        print("\nA MATCH is a candidate unpatched variant -- confirm the defect is there, not just "
              "the shape (recompiled-but-fixed code can still look similar).")
    return 0


def _cmd_bindiff(args: argparse.Namespace) -> int:
    import json
    from pathlib import Path

    from .analyze import native_re, patchdiff
    old, new = Path(args.old), Path(args.new)
    for pth in (old, new):
        if not pth.exists():
            print(f"no such file: {pth}", file=sys.stderr)
            return 2
    fa = native_re.analyze(old, timeout=args.timeout).get("functions") or []
    fb = native_re.analyze(new, timeout=args.timeout).get("functions") or []
    d = patchdiff.diff(fa, fb)
    if args.json:
        print(json.dumps(d, indent=2, default=list))
        return 0
    print(f"old {old.name}: {d['n_old']} functions   new {new.name}: {d['n_new']} functions")
    if not d["symbols"]:
        print("(stripped: no symbols to match by name -- structural inventory only)")
        print(f"  functions added: {d['stripped_added']}   removed: {d['stripped_removed']}")
        print("  supply symbolized builds to localise the exact changed function.")
        return 0
    print(f"unchanged: {d['unchanged']}   added: {len(d['added'])}   removed: {len(d['removed'])}")
    if d["changed"]:
        print(f"\nCHANGED functions ({len(d['changed'])}) -- a security fix lives in the top ones:")
        for c in d["changed"][:25]:
            extra = ""
            if c["new_callees"]:
                extra += f"  +calls {', '.join(c['new_callees'][:4])}"
            print(f"  {c['name']:<32} blocks {c['blocks'][0]}->{c['blocks'][1]}  "
                  f"insns {c['insns'][0]}->{c['insns'][1]}  (moved {c['moved']}){extra}")
    else:
        print("\nno named function changed -- the two builds are identical where symbols match.")
    return 0


def _cmd_archgate(args: argparse.Namespace) -> int:
    import json

    from .eval import archgate
    cases = archgate.MATRIX
    if args.only:
        want = {x.strip() for x in args.only.split(",") if x.strip()}
        cases = [c for c in cases if c.label in want]
    rep = archgate.run(cases, timeout=args.timeout,
                       progress=lambda m: print(m, file=sys.stderr, flush=True))
    print(archgate.table(rep))
    passed, verdict, reason = archgate.gate(rep)
    if args.out:
        Path(args.out).write_text(json.dumps(rep, indent=2))
        print(f"report written to {args.out}", file=sys.stderr)
    print(f"\nGATE: {verdict} -- {reason}", file=sys.stderr)
    return 0 if passed else 1


def _cmd_realgate(args: argparse.Namespace) -> int:
    import json

    from .eval import realgate
    cases = realgate.MATRIX
    if args.only:
        want = {x.strip() for x in args.only.split(",") if x.strip()}
        cases = [c for c in cases if c.label in want]
    rep = realgate.run(cases, timeout=args.timeout,
                       progress=lambda m: print(m, file=sys.stderr, flush=True))
    print(realgate.table(rep))
    passed, verdict, reason = realgate.gate(rep)
    if args.out:
        Path(args.out).write_text(json.dumps(rep, indent=2))
        print(f"report written to {args.out}", file=sys.stderr)
    print(f"\nGATE: {verdict} -- {reason}", file=sys.stderr)
    return 0 if passed else 1


def _cmd_doctor(args: argparse.Namespace) -> int:
    """What works on THIS host. On an offline workstation there is no package manager to
    ask, and "the stage declined" is a poor way to find out Ghidra was never installed."""
    import json

    from . import toolchain, vendorenv
    if args.json:
        print(json.dumps(toolchain.as_dict(), indent=2))
    else:
        print(vendorenv.status_line())
        # Probe with a live indicator: several probes spawn subprocesses with multi-second timeouts,
        # so the whole report used to appear only after many seconds of silence -- indistinguishable
        # from a hang, worse right after the first-run relink. Stream which tool is being probed
        # (overwritten in place), then print the full grouped report from the same single survey.
        _tty = sys.stdout.isatty()

        def _progress(t):
            if _tty:
                sys.stdout.write(f"\r  probing {t.title:<40}")
            else:
                sys.stdout.write(f"  probing {t.title}...\n")
            sys.stdout.flush()
        rows = toolchain.survey(progress=_progress)
        if _tty:
            sys.stdout.write("\r" + " " * 52 + "\r")     # clear the progress line
            sys.stdout.flush()
        print(toolchain.report(verbose=args.verbose, rows=rows))
    if args.strict:
        return 1 if toolchain.missing("required") else 0
    return 0


def _cmd_deps(args: argparse.Namespace) -> int:
    """Build-dependency PRE-FLIGHT for a source directory: what it declares it needs vs. what this
    host has, so the gaps are staged BEFORE the box goes offline. A failed build on an air-gapped
    host costs the whole binary/dynamic capability for that target; this turns that silent failure
    into an up-front checklist.  Exit non-zero (with --strict) when anything is MISSING."""
    import json

    from .analyze import dep_preflight
    pf = dep_preflight.scan_dependencies(args.path, scan_includes=not args.no_include_scan)
    if args.json:
        print(json.dumps(pf, indent=2))
    else:
        print(dep_preflight.format_report(pf))
    if args.strict:
        return 1 if (pf["missing"] or pf["toolchain_missing"]) else 0
    return 0


def _cmd_dashboard(args: argparse.Namespace) -> int:
    from .eval import dashboard as dashmod
    from .eval import history as histmod
    path = args.history or histmod.DEFAULT_PATH
    hist = histmod.load(path)
    print(dashmod.render_text(hist))
    if args.html:
        Path(args.html).write_text(dashmod.render_html(hist), encoding="utf-8")
        print(f"\nHTML dashboard written to {args.html}", file=sys.stderr)
    regs = histmod.regressions(hist)
    if args.fail_on_regression and regs:
        print(f"\nREGRESSION: {len(regs)} series regressed", file=sys.stderr)
        return 1
    return 0


def _run_benchmark(args: argparse.Namespace, cases) -> int:
    """`eval --benchmark`: score detection as a TRACKED number, never a gate (always exits 0).

    Scores the static corpus at BOTH channels -- candidate (detection breadth, including the
    rule/weak-primitive detectors) and corroborated (the taint-discriminated precision lever) --
    then the LAVA-M recall mini, and records each to the dashboard history. `cases` is an external
    drop (--juliet/--lava/--corpus) when given, else the vendored breadth corpus. Unlike the gate,
    a drop in a number here is information to track over time, not a failure.
    """
    import json

    from .eval import corpus as corpusmod
    from .eval import harness
    from .eval import history as histmod

    # `--lava` loads LAVA-M PROGRAMS into `cases`; those are scored by the lava leg below, not
    # by the static one (which scored them as if they were CWE corpus cases).
    if getattr(args, "lava", None):
        cases = None
    static_cases = cases if cases is not None else corpusmod.benchmark()
    hist_path = args.history or histmod.DEFAULT_PATH
    print("BENCHMARK (tracked, non-gating)\n")
    rows = []
    for state in ("candidate", "corroborated"):
        rep = harness.run(static_cases, stage="static", min_state=state, workers=args.workers,
                          progress=lambda m: print(m, file=sys.stderr, flush=True))
        o = rep.metrics.get("overall", {})
        n, g = rep.metrics.get("n_cases", 0), rep.metrics.get("n_cwe_classes", 0)
        backend = ("ghidra" if rep.meta.get("ghidra")
                   else "native" if rep.meta.get("native") else "NONE")
        rows.append((f"static/{state}", o.get("precision"), o.get("recall"), o.get("f1"),
                     f"{n} cases, {g} classes, backend={backend}"))
        histmod.record(hist_path, rep, stage="static", min_state=state,
                       label=args.label or "benchmark")
        if args.out:
            Path(args.out).write_text(json.dumps(rep.to_dict(), indent=2))

    # LAVA-M injected-bug recall (the bundled mini, or an external drop via --lava)
    lava_line = None
    try:
        progs = corpusmod.load_lava(args.lava) if args.lava else corpusmod.bundled_lava()
        lrep = harness.run_lava_corpus(progs, progress=lambda m: print(m, file=sys.stderr, flush=True))
        lo = lrep.metrics.get("overall", {})
        found, total = int(lo.get("tp", 0)), int(lo.get("tp", 0)) + int(lo.get("fn", 0))
        lava_line = (found, total, lo.get("recall"))
        histmod.record(hist_path, lrep, stage="lava", min_state=None,
                       label=args.label or "benchmark")
    except Exception as e:                                # a benchmark never fails the caller
        print(f"warning: lava benchmark skipped: {e}", file=sys.stderr)

    def _f(x):
        return f"{x:.3f}" if isinstance(x, (int, float)) else "  -  "

    print(f"  {'channel':22} {'P':>6} {'R':>6} {'F1':>6}   detail")
    for name, p, r, f1, detail in rows:
        print(f"  {name:22} {_f(p):>6} {_f(r):>6} {_f(f1):>6}   {detail}")
    if lava_line:
        found, total, rec = lava_line
        print(f"  {'lava/recall':22} {'':>6} {_f(rec):>6} {'':>6}   {found}/{total} injected bugs found")
    print(f"\nrecorded to {hist_path} (view with `lykos dashboard`)", file=sys.stderr)
    return 0                                              # tracked, never a gate


def _cmd_eval(args: argparse.Namespace) -> int:
    import json

    from .eval import corpus as corpusmod
    from .eval import harness
    stage = args.stage
    if args.lava:
        cases = corpusmod.load_lava(args.lava, limit=args.limit)
        stage = "lava"
    elif args.juliet:
        cwes = set(args.cwe.split(",")) if args.cwe else None
        cases = corpusmod.load_juliet(args.juliet, cwes=cwes, limit=args.limit)
    elif args.corpus:
        cases = corpusmod.load_dir(args.corpus)
    else:
        cases = None

    if args.benchmark:
        return _run_benchmark(args, cases)

    # Per-architecture static scoring: cross-compile the corpus for each requested arch and
    # ratchet detection against eval/arch_baseline.json -- a new false positive or false negative
    # on any arch fails. An arch whose cross-compiler is absent is skipped (not failed); an arch
    # with no baseline entry is reported but not gated. Cross-arch detection is x86-64-tuned and
    # weak off it (see the baseline's comment), so this is a regression ratchet, not a 0-FP bar.
    if args.arch and stage == "static":
        from pathlib import Path as _P
        base_path = _P(__file__).resolve().parent / "eval" / "arch_baseline.json"
        baseline = {}
        if base_path.exists():
            baseline = json.loads(base_path.read_text()).get("arches", {})
        want = None if args.arch == "all" else [a.strip() for a in args.arch.split(",")]
        targets = harness.available_arches(want)
        if not targets:
            print("no requested cross-compilers installed; per-arch scoring skipped",
                  file=sys.stderr)
            return 0
        all_pass = True
        measured = {}
        for arch, cc in targets:
            rep = harness.run(cases, stage="static", min_state=args.min_state,
                              workers=args.workers, gcc=cc,
                              progress=lambda m, arch=arch: print(f"[{arch}] {m}",
                                                                 file=sys.stderr, flush=True))
            o = rep.metrics.get("overall", {})
            fp, fn = int(o.get("fp", 0)), int(o.get("fn", 0))
            measured[arch] = {"fp": fp, "fn": fn}
            base = baseline.get(arch)
            if args.arch_update_baseline:
                verdict = "RECORDED"
            elif base is None:
                verdict = "no-baseline (reported, not gated)"
            else:
                regressed = fp > base["fp"] or fn > base["fn"]
                improved = fp < base["fp"] or fn < base["fn"]
                verdict = ("REGRESSED" if regressed
                           else "IMPROVED (lower the baseline)" if improved else "ok")
                all_pass = all_pass and not regressed
            btxt = f" [baseline fp={base['fp']} fn={base['fn']}]" if base else ""
            print(f"[{arch:8}] {verdict}: fp={fp} fn={fn} "
                  f"recall={o.get('recall')} fp_rate={o.get('fp_rate')}{btxt}")
        if args.arch_update_baseline:
            doc = {}
            if base_path.exists():
                doc = json.loads(base_path.read_text())
            doc.setdefault("arches", {}).update(measured)
            base_path.write_text(json.dumps(doc, indent=2) + "\n")
            print(f"\nbaseline updated for {len(measured)} arch(es): {base_path}")
            return 0
        print(f"\nper-arch static ratchet over {len(targets)} arch(es): "
              f"{'PASS' if all_pass else 'FAIL'}")
        return 0 if all_pass else 1

    kw = {"stage": stage, "workers": args.workers,
          "progress": lambda m: print(m, file=sys.stderr, flush=True)}
    if stage == "static":
        kw["min_state"] = args.min_state
    elif stage == "lava":
        del kw["workers"]                              # lava harness takes no workers arg
    rep = harness.run(cases, **kw)
    for w in rep.meta.get("warnings", []):
        print(f"warning: {w}", file=sys.stderr)
    if rep.metrics.get("n_unscored"):
        print(f"warning: {rep.metrics['n_unscored']} case(s) could not be evaluated (compile "
              "failure or a stage that never finished); counted conservatively -- a bad one as "
              "a miss, a good one NOT as a true negative", file=sys.stderr)
    print(rep.table())
    backend = (f"backend={'ghidra' if rep.meta.get('ghidra') else ('native' if rep.meta.get('native') else 'NONE')}"
               f", min_state={args.min_state}"
               if stage == "static"
               else f"fuzz budget={rep.meta.get('max_execs')} execs/{rep.meta.get('max_seconds')}s")
    ncases, ngroups = rep.metrics.get("n_cases", 0), rep.metrics.get("n_cwe_classes", 0)
    if stage == "lava":
        print(f"\nlava-stage: {ncases} injected bugs across {ngroups} program(s), "
              f"{rep.meta.get('elapsed_s')}s ({backend})")
    else:
        print(f"\n{stage}-stage: {ncases} cases, {ngroups} CWE classes, "
              f"{rep.meta.get('elapsed_s')}s ({backend})")
    if args.out:
        Path(args.out).write_text(json.dumps(rep.to_dict(), indent=2))
        print(f"report written to {args.out}")
    if args.record:
        from .eval import history as histmod
        path = args.history or histmod.DEFAULT_PATH
        min_state = args.min_state if stage == "static" else None
        histmod.record(path, rep, stage=stage, min_state=min_state, label=args.label)
        print(f"recorded to {path}", file=sys.stderr)
    # release gate: PASS / FAIL / SKIP (SKIP when the static backend is absent)
    from .eval.metrics import gate
    passed, verdict, reason = gate(rep.metrics, rep.meta, stage=stage,
                                   min_recall=args.min_recall, max_fp_rate=args.max_fp_rate,
                                   require_backend=args.require_backend,
                                   min_negative=args.min_negative)
    print(f"\nGATE: {verdict} -- {reason}", file=sys.stderr)
    return 0 if passed else 1


def main(argv: list[str] | None = None) -> int:
    # Before any command runs a tool locator, point the environment at the run-in-place
    # toolchain under vendor/ (a no-op when there is none). This is what lets the offline
    # bundle work with nothing installed: every locator resolves through PATH, and this puts
    # the vendored bin/lib dirs on it. See vendorenv.activate.
    from . import vendorenv
    vendorenv.activate()
    parser = build_parser()
    args = parser.parse_args(argv)
    observe.configure(getattr(args, "log", None))
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
