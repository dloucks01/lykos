"""Minimal CLI (DM-02): `lykos db init|upgrade|version --case-store DIR`.

Enough to create/migrate a case DB; `serve` and other commands arrive in later epics.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
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
        http = (host or "127.0.0.1", int(port))
    if not args.socket and not http:
        print("serve needs --socket and/or --http", file=sys.stderr)
        return 2
    serve(args.case_store, args.socket, http=http, workers=args.workers)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lykos", description="lykos core CLI")
    p.add_argument("--version", action="version", version=f"lykos {__version__}")
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
    ev.add_argument("--stage", choices=["static", "dynamic"], default="static",
                    help="static = candidate-stage CWE detection (Ghidra); "
                         "dynamic = confirmed-stage crash reproduction via fuzzing")
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
    ev.add_argument("--out", default=None, help="write the full JSON report to this path")
    ev.add_argument("--workers", type=int, default=2, help="worker count (default 2)")
    ev.add_argument("--min-recall", type=float, default=1.0,
                    help="release gate: fail if overall recall is below this (default 1.0)")
    ev.add_argument("--max-fp-rate", type=float, default=0.0,
                    help="release gate: fail if the FP-rate exceeds this (default 0.0)")
    ev.add_argument("--require-backend", action="store_true",
                    help="fail (not skip) when the static backend (Ghidra) is absent")
    ev.set_defaults(func=_cmd_eval)
    return p


def _cmd_eval(args: argparse.Namespace) -> int:
    import json

    from .eval import corpus as corpusmod
    from .eval import harness
    if args.juliet:
        cwes = set(args.cwe.split(",")) if args.cwe else None
        cases = corpusmod.load_juliet(args.juliet, cwes=cwes, limit=args.limit)
    elif args.corpus:
        cases = corpusmod.load_dir(args.corpus)
    else:
        cases = None
    kw = {"stage": args.stage, "workers": args.workers,
          "progress": lambda m: print(m, file=sys.stderr, flush=True)}
    if args.stage == "static":
        kw["min_state"] = args.min_state
    rep = harness.run(cases, **kw)
    for w in rep.meta.get("warnings", []):
        print(f"warning: {w}", file=sys.stderr)
    print(rep.table())
    backend = (f"ghidra={'yes' if rep.meta.get('ghidra') else 'NO'}, min_state={args.min_state}"
               if args.stage == "static"
               else f"fuzz budget={rep.meta.get('max_execs')} execs/{rep.meta.get('max_seconds')}s")
    print(f"\n{args.stage}-stage: {rep.metrics.get('n_cases', 0)} cases, "
          f"{rep.metrics.get('n_cwe_classes', 0)} CWE classes, "
          f"{rep.meta.get('elapsed_s')}s ({backend})")
    if args.out:
        Path(args.out).write_text(json.dumps(rep.to_dict(), indent=2))
        print(f"report written to {args.out}")
    # release gate: PASS / FAIL / SKIP (SKIP when the static backend is absent)
    from .eval.metrics import gate
    passed, verdict, reason = gate(rep.metrics, rep.meta, stage=args.stage,
                                   min_recall=args.min_recall, max_fp_rate=args.max_fp_rate,
                                   require_backend=args.require_backend)
    print(f"\nGATE: {verdict} -- {reason}", file=sys.stderr)
    return 0 if passed else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
