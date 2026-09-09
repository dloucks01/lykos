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
    ev.add_argument("--corpus", default=None,
                    help="directory of <CWE>__<name>__<good|bad>.c cases (default: bundled)")
    ev.add_argument("--out", default=None, help="write the full JSON report to this path")
    ev.add_argument("--workers", type=int, default=2, help="worker count (default 2)")
    ev.set_defaults(func=_cmd_eval)
    return p


def _cmd_eval(args: argparse.Namespace) -> int:
    import json

    from .eval import corpus as corpusmod
    from .eval import harness
    cases = corpusmod.load_dir(args.corpus) if args.corpus else None
    rep = harness.run(cases, workers=args.workers,
                      progress=lambda m: print(m, file=sys.stderr, flush=True))
    for w in rep.meta.get("warnings", []):
        print(f"warning: {w}", file=sys.stderr)
    print(rep.table())
    o = rep.metrics.get("overall", {})
    print(f"\n{rep.metrics.get('n_cases', 0)} cases, {rep.metrics.get('n_cwe_classes', 0)} "
          f"CWE classes, {rep.meta.get('elapsed_s')}s "
          f"(ghidra={'yes' if rep.meta.get('ghidra') else 'NO'})")
    if args.out:
        Path(args.out).write_text(json.dumps(rep.to_dict(), indent=2))
        print(f"report written to {args.out}")
    # non-zero exit if any bug was missed or any good case falsely flagged (CI gate)
    return 0 if (o.get("fn", 0) == 0 and o.get("fp", 0) == 0 and o.get("tp", 0) > 0) else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
