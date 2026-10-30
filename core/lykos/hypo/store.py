"""Persist a hunt: hunt.json (every hypothesis + evidence), findings.md, and one folder per
confirmed PoC with the input, a replay script and the validator's verdict."""
from __future__ import annotations

import json
import os
import re
import shlex
import time
from pathlib import Path

from .model import Hypothesis

VERSION = 1


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:60].strip("_") or "site"


def _replay_script(binary: str, argv: list, mode: str, sanitizer: bool = False) -> str:
    q = shlex.quote(binary)
    if mode == "stdin":
        cmd = f'{q} {" ".join(shlex.quote(a) for a in argv)} < "$HERE/input.bin"'
    elif mode == "arg":
        parts = ['"$(cat "$HERE/input.bin")"' if a == "@@" else shlex.quote(a) for a in argv]
        if "@@" not in argv:
            parts.append('"$(cat "$HERE/input.bin")"')
        cmd = f"{q} {' '.join(parts)}"
    else:
        parts = ['"$HERE/input.bin"' if a == "@@" else shlex.quote(a) for a in argv]
        if "@@" not in argv:
            parts.append('"$HERE/input.bin"')
        cmd = f"{q} {' '.join(parts)}"
    env = ("# the sanitizer build: its report names the faulting line\n"
           "export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 "
           "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1\n") if sanitizer else ""
    return ("#!/bin/sh\n# Replays this PoC. Run it in a disposable environment: it triggers the bug.\n"
            'HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
            f"{env}{cmd}\n")


def save(out_dir, report: dict) -> Path:
    """`report`: {target, kind, budget, started, results:[{binary, asan, argv, mode, stats,
    error, hypotheses:[Hypothesis], incidental:[...]}]}. Returns the hunt.json path."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    pocs = out / "pocs"
    n = 0
    lines = [f"# lykos hunt: {report['target']}", "",
             f"{report.get('kind')} · budget {report.get('budget')} s · "
             f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(report.get('started', time.time())))}",
             ""]
    serial = dict(report)
    serial["version"] = VERSION
    serial["results"] = []
    for res in report["results"]:
        hyps = res["hypotheses"]
        conf = [h for h in hyps if h.status == "confirmed"]
        lines.append(f"## {res['binary']}")
        if res.get("error"):
            lines.append(f"\nsolver error: `{res['error']}`\n")
        lines.append(f"\n{len(conf)} confirmed, "
                     f"{sum(1 for h in hyps if h.status == 'unconfirmed')} unconfirmed, "
                     f"{len(hyps)} hypotheses\n")
        for h in sorted(conf, key=lambda h: (h.location or "", h.id)):
            sol = h.confirmed_solution()
            n += 1
            d = pocs / f"{n:02d}-{_slug(h.kind)}-{_slug(h.location or h.id)}"
            d.mkdir(parents=True, exist_ok=True)
            (d / "input.bin").write_bytes(sol.data)
            sh = d / "replay.sh"
            use_san = bool(res.get("asan")) and sol.verdict.method == "asan"
            sh.write_text(_replay_script(res["asan"] if use_san else res["binary"], res["argv"],
                                         res["mode"], sanitizer=use_san))
            os.chmod(sh, 0o755)
            (d / "verdict.txt").write_text(
                f"{h.kind} ({h.cwe}) at {h.location or hex(h.site or 0)} in {h.func}\n"
                f"solver: {sol.detail}\nvalidator ({sol.verdict.method}, "
                f"{sol.verdict.runs} run(s)): {sol.verdict.detail}\n")
            lines.append(f"- **{h.kind}** ({h.cwe}) at `{h.location or hex(h.site or 0)}` in "
                         f"`{h.func}` — {sol.detail}. Validated by {sol.verdict.method}: "
                         f"{sol.verdict.detail}. PoC: `{d.relative_to(out)}/`")
        crash = [h for h in hyps if h.crashes_unattributed()]
        if crash:
            lines.append("\nReproducible crashes NOT attributable to their site (no sanitizer build; "
                         "the fault was outside the site's function):")
            for h in crash:
                lines.append(f"- {h.kind} hypothesis at `{h.location or hex(h.site or 0)}` in `{h.func}`")
        inc = res.get("incidental") or []
        if inc:
            lines.append("\nOther sanitizer reports hit while replaying (real crashes at a "
                         "different line than the hypothesis claimed):")
            for i in inc:
                lines.append(f"- {i['kind']} at `{i['where']}` (from {i['hypothesis']})")
        lines.append("")
        r2 = dict(res)
        r2["hypotheses"] = [h.to_dict() for h in hyps]
        serial["results"].append(r2)
    p = out / "hunt.json"
    p.write_text(json.dumps(serial, indent=1, default=str))
    (out / "findings.md").write_text("\n".join(lines) + "\n")
    return p


def load(path) -> dict:
    d = json.loads(Path(path).read_text())
    for r in d.get("results", []):
        r["hypotheses"] = [Hypothesis.from_dict(h) for h in r.get("hypotheses", [])]
    return d
