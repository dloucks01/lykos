#!/usr/bin/env python3
"""Recall benchmark: point lykos BLIND at real projects with published CVEs and score it.

For each `<id>/meta.json` (schema in README.md) this runs `lykos analyze` on the project exactly as
an operator would -- the source TREE (surface "source") and/or the shipped BINARY (surface
"binary", when meta names one) -- with no seeds, no hints and no knowledge of the CVEs. It then
reads the JSON report and asks two questions per demonstrated defect:

  * WHICH KNOWN BUG is it?  A dossier matches a CVE when one of its first project stack frames
    (or, for a stripped binary, its crash function) is the CVE's (file, function). Class is
    reported beside it but does not gate the match: ASan's class for a defect and the CVE's
    prose often disagree ("heap overflow" vs "out-of-bounds read").
  * HOW FAR did lykos prove it?  The dossier's level (L1 verified crash, L2 primitive, L3
    working exploit) and whether its PoC bundle verified.

Recall is reported two ways, because several CVE ids often name ONE defect (giflib's
DumpScreen2RGB is three CVEs): over distinct (file, function) DEFECTS, and over ids. Entries
marked `in_build: false` (compiled out) or `confidence: low` are listed but never count as misses.
A demonstrated defect matching no entry is reported as UNLISTED: a real crash lykos verified that
the ground truth does not name (an unfiled bug, or a ground-truth gap) -- never silently dropped.

A binary built without debug info gives a dossier only a site address (`location.site`) and maybe a
symbol. When the target's meta names a `debug_binary` (the same build with -g, .text byte-identical),
an unmatched dossier's site is mapped through it with addr2line -- inlined chain included -- and the
resulting (function, file, line) frames are matched the same way ("addr" in `found[*].how`).

usage: score.py [--budget S] [--surface source|binary|binary-stripped|both|all] [--parallel N]
                [--out DIR] [ids...]
       score.py --rescore DIR       (re-match existing runs without re-running lykos; scores every
                                     <id>--<surface> run in DIR unless --surface/ids narrow it)
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
LYKOS = ROOT / "lykos"
sys.path.insert(0, str(ROOT / "core"))
LEVELS = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}
SURFACES = ("source", "binary", "binary-stripped")


def subject_path(meta: dict, surface: str) -> "Path | None":
    """What lykos is pointed at for a surface: the source tree, the shipped binary, or a `strip -s`
    copy of it (`stripped_path`, default `<binary_path>.stripped`, made by fetch_build.sh)."""
    if surface == "source":
        return ROOT / meta["tree"] if meta.get("tree") else None
    if not meta.get("binary_path"):
        return None
    if surface == "binary":
        return ROOT / meta["binary_path"]
    return ROOT / (meta.get("stripped_path") or meta["binary_path"] + ".stripped")


def load_targets(ids=None) -> list:
    out = []
    for m in sorted(HERE.glob("*/meta.json")):
        meta = json.loads(m.read_text())
        if ids and meta["id"] not in ids:
            continue
        out.append(meta)
    return out


def _argv_str(argv) -> str:
    import shlex
    return " ".join(a if a == "@@" else shlex.quote(a) for a in argv)


def run_lykos(meta: dict, surface: str, budget: int, outdir: Path) -> dict:
    """One blind lykos run. Returns {ok, seconds, report, run_dir}."""
    rd = outdir / f"{meta['id']}--{surface}"
    rd.mkdir(parents=True, exist_ok=True)
    subject = subject_path(meta, surface)
    entry = meta.get("entry") or {}
    cmd = ["systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=24G",
           "-p", "MemorySwapMax=0", str(LYKOS), "analyze", str(subject),
           "--budget", str(budget), "--case-store", str(rd / "case"), "--out", str(rd / "pocs"),
           "--report", str(rd / "report.json"), "-q"]
    # The ONE thing an operator supplies: how the program is invoked. Never the CVE trigger flags.
    if surface != "source" and entry.get("argv"):
        cmd += ["--argv", _argv_str(entry["argv"])]
    t0 = time.time()
    with open(rd / "run.log", "wb") as log:
        r = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT,
                           timeout=budget * 3 + 900)
    return {"ok": r.returncode == 0, "rc": r.returncode, "seconds": round(time.time() - t0, 1),
            "run_dir": str(rd)}


# ------------------------------------------------------------------------------------ matching

_FRAME = re.compile(r"^(?P<fn>[^ (]*) ?\((?P<file>[^:)]*):?(?P<line>\d+)?\)")
#: file:line matches a CVE whose line is within this many lines (symbol-stripped dossiers carry
#: only file:line, and a sanitizer line sits a few lines off the CVE's cited line across versions).
_LINE_WINDOW = 25


def _frames(d: dict) -> list:
    """[(function, file-basename, line|None)] for a dossier: its symbolised stack, then its source
    line and crash function. A sanitizer/stripped frame often has only file:line (no function)."""
    loc = d.get("location") or {}
    out = []
    for s in loc.get("stack") or []:
        m = _FRAME.match(s)
        if m:
            out.append((m.group("fn") or "", os.path.basename(m.group("file") or ""),
                        int(m.group("line")) if m.group("line") else None))
    if loc.get("source"):
        m = re.match(r"(?P<file>[^:]+):(?P<line>\d+)(?: in (?P<fn>\S+))?", loc["source"])
        if m:
            out.append((m.group("fn") or "", os.path.basename(m.group("file")),
                        int(m.group("line"))))
    if loc.get("function"):
        out.append((loc["function"], "", None))
    return out


_RUNTIME = re.compile(r"^(__asan|__interceptor|__sanitizer|asan_|__ubsan|_?_?mem(cpy|move|set)|"
                      r"str(n?cpy|n?cat|len|cmp)|crc32$|__libc|abort|raise|_start|main$)")


#: A demonstrated injection is confirmed BY EFFECT (the marker ran / the file came back), so the
#: dossier often has no crashing frame to pin -- blind on a stripped binary lykos cannot name the
#: sink function. Credit it to a ground-truth entry of the SAME class when one exists (these tools
#: carry exactly one CVE per injection class); never invent a hit for a class the CVE list lacks.
_CWE_CLASS = {"CWE-78": "cmd-injection", "CWE-22": "path-traversal", "CWE-89": "sql-injection",
              "CWE-90": "ldap-injection", "CWE-134": "format-string"}


# ------------------------------------------------------------- address -> source (debug twin)

#: {(twin realpath, size, mtime_ns): {va: [(function, file-basename, line|None)]}}. addr2line on a
#: fixed file is deterministic, so a VA is resolved at most once per twin per process.
_ADDR_CACHE: dict = {}


def _site_va(dossier: dict) -> "int | None":
    site = (dossier.get("location") or {}).get("site")
    if isinstance(site, int):
        return site
    if isinstance(site, str) and re.fullmatch(r"\s*0[xX][0-9a-fA-F]+\s*", site):
        return int(site, 16)
    return None


def _a2l_line(fn: str, loc: str):
    """One addr2line -f -i pair -> (function, file-basename, line|None), or None when unknown."""
    m = re.match(r"(?P<file>.*?):(?P<line>\d+|\?)(?: \(discriminator \d+\))?$", loc.strip())
    f = m.group("file") if m else loc.strip()
    ln = int(m.group("line")) if m and m.group("line").isdigit() else None
    fn = fn.strip()
    if fn in ("", "??") or f in ("", "??"):
        return None
    return (fn, os.path.basename(f), ln or None)


def addr_frames(debug_binary, vas) -> dict:
    """{va: [(function, file, line)]} for link-time VAs, mapped through a -g twin with
    `addr2line -a -f -i` (innermost inlined function first, then its callers). VAs addr2line cannot
    place (outside the twin, no line info) map to []. One addr2line call per twin for all new VAs."""
    path = Path(debug_binary)
    try:
        st = path.stat()
    except OSError:
        return {va: [] for va in vas}
    cache = _ADDR_CACHE.setdefault((str(path.resolve()), st.st_size, st.st_mtime_ns), {})
    todo = sorted({va for va in vas if va not in cache})
    if todo:
        try:
            out = subprocess.run(["addr2line", "-a", "-f", "-i", "-e", str(path)]
                                 + [hex(va) for va in todo], capture_output=True, text=True,
                                 timeout=60).stdout.splitlines()
        except (OSError, subprocess.SubprocessError):
            out = []
        cur = None
        i = 0
        while i < len(out):
            line = out[i].strip()
            if re.fullmatch(r"0x[0-9a-fA-F]+", line):     # -a: each address opens its block
                cur = int(line, 16)
                cache.setdefault(cur, [])
                i += 1
                continue
            if cur is not None and i + 1 < len(out):
                fr = _a2l_line(out[i], out[i + 1])
                if fr:
                    cache[cur].append(fr)
            i += 2
        for va in todo:
            cache.setdefault(va, [])
    return {va: list(cache[va]) for va in vas}


#: Runtime frames to skip in a debug-map chain. Unlike `_RUNTIME` this keeps `main`: addr2line on a
#: -g twin names the true function, so `main` here means the code really is in main (several CVEs
#: are), not a stripped binary's catch-all for code it could not attribute.
_ADDR_RUNTIME = re.compile(r"^(__asan|__interceptor|__sanitizer|asan_|__ubsan|_?_?mem(cpy|move|set)|"
                           r"str(n?cpy|n?cat|len|cmp)|__libc|abort|raise|_start$)")


def _match_frames(frames: list, cves: list) -> list:
    hits = []
    for c in cves:
        cfn, cfile = c.get("function") or "", os.path.basename(c.get("file") or "")
        cline = c.get("line")
        for fn, f, ln in frames:
            by_fn = bool(cfn) and fn == cfn and (not f or not cfile or f == cfile)
            by_fileline = (not fn and bool(cfile) and f == cfile and ln is not None
                           and isinstance(cline, int) and abs(ln - cline) <= _LINE_WINDOW)
            if by_fn or by_fileline:
                hits.append(c)
                break
    return hits


def _class_match(dossier: dict, cves: list) -> list:
    cls = _CWE_CLASS.get(dossier.get("cwe"))
    if not cls or LEVELS.get(dossier.get("level") or "L0", 0) < 1:
        return []
    return [c for c in cves if (c.get("class") or "") == cls]


def match_how(dossier: dict, cves: list, debug_binary=None):
    """(hits, how) -- the ground-truth entries this dossier is, and which evidence named them:
    "frame" (the dossier's own frames), "addr" (its site VA through the debug twin), "class"
    (effect-confirmed injection). A frame matches a CVE when its FUNCTION is the CVE's (file
    agreeing when both name one), OR -- for a symbol-stripped frame that has only file:line -- when
    the FILE agrees and the line is within `_LINE_WINDOW` of the CVE's. Runtime/libc frames are
    skipped (the CVE names the caller; ASan names memcpy/crc32). The debug map is consulted only
    when the dossier's own frames match nothing, so a dossier that already matches is unchanged."""
    frames = [(fn, f, ln) for fn, f, ln in _frames(dossier)
              if not (fn and _RUNTIME.match(fn))][:8]
    va = _site_va(dossier)
    chain = []
    if debug_binary and va is not None:
        chain = [fr for fr in addr_frames(debug_binary, [va])[va]
                 if not _ADDR_RUNTIME.match(fr[0])][:8]
    # the defect's own line, when anything names it: the dossier's frames, else the debug twin
    site_line = next((ln for _fn, _f, ln in frames + chain if ln is not None), None)
    hits = _match_frames(frames, cves)
    if hits:
        return _narrow_by_line(hits, site_line), "frame"
    if chain:
        hits = _match_frames(chain, cves)
        if hits:
            return _narrow_by_line(hits, site_line), "addr"
    hits = _class_match(dossier, cves)                   # effect-confirmed injection, no frame
    return hits, ("class" if hits else None)


def _narrow_by_line(hits: list, line) -> list:
    """One crash is ONE defect. When several ground-truth entries share a function but cite
    different lines (giflib's DumpScreen2RGB: the 294 group and the 317 group), a function-name
    match credited every group from a single crash. With the crash's own line known, keep only
    the entries nearest it within each function; without a line, leave the hits as they are."""
    if line is None:
        return hits
    by_fn: dict = {}
    for c in hits:
        by_fn.setdefault((c.get("function"), os.path.basename(c.get("file") or "")), []).append(c)
    out = []
    for group in by_fn.values():
        lined = [c for c in group if isinstance(c.get("line"), int)]
        if len({c["line"] for c in lined}) <= 1:
            out += group
            continue
        best = min(abs(c["line"] - line) for c in lined)
        out += [c for c in group if not isinstance(c.get("line"), int)
                or abs(c["line"] - line) == best]
    return out


def match(dossier: dict, cves: list, debug_binary=None):
    return match_how(dossier, cves, debug_binary)[0]


def debug_binary_of(meta: dict) -> "Path | None":
    """The target's -g twin (meta `debug_binary`, repo-relative), when it is on disk."""
    db = meta.get("debug_binary")
    p = ROOT / db if db else None
    return p if p is not None and p.is_file() else None


def _report_from_case(run_dir: Path) -> "dict | None":
    """Rebuild the report model from the run's case DB with the CURRENT report code, so a rescore
    reflects dossier/narrative fixes made after the run. None when there is no case DB."""
    case_db = run_dir / "case" / "case.db"
    if not case_db.exists():
        return None
    try:
        from lykos.casestore import CaseStore
        from lykos.report.model import build_report
        store = CaseStore.open(str(run_dir / "case"))
        try:
            cid = store.conn.execute("SELECT id FROM \"case\" LIMIT 1").fetchone()[0]
            return build_report(store, cid, min_state="candidate")
        finally:
            store.close()
    except Exception as e:                               # noqa: BLE001
        return {"_rebuild_error": str(e)}


def score_run(meta: dict, report_path: Path, surface: str = "binary") -> dict:
    run_dir = Path(report_path).parent
    rep = _report_from_case(run_dir)
    if rep is None or "_rebuild_error" in (rep or {}):
        try:
            rep = json.loads(Path(report_path).read_text())
        except (OSError, ValueError) as e:
            return {"error": f"no report ({e})"}
    nar = rep.get("narrative") or {}
    # Dossiers live per target under narrative.targets[*].dossiers (a multi-binary project has
    # several); the top level has only the executive summary.
    dossiers = list(nar.get("dossiers") or [])
    for tg in nar.get("targets") or []:
        dossiers += tg.get("dossiers") or []
    cves = meta.get("cves") or []
    # The address map is for binary surfaces: a source run's sites are not the shipped binary's VAs.
    dbg = debug_binary_of(meta) if surface != "source" else None
    scoreable = [c for c in cves if c.get("in_build", True) and c.get("confidence") != "low"]
    found: dict = {}
    unlisted = []
    for d in dossiers:
        hits, how = match_how(d, cves, dbg)
        loc = d.get("location") or {}
        if not hits:
            unlisted.append({"title": d.get("title"), "level": d.get("level"),
                             "where": loc.get("source") or loc.get("function") or loc.get("site"),
                             "cwe": d.get("cwe")})
        for c in hits:
            prev = found.get(c["id"])
            lvl = d.get("level") or "L0"
            if prev is None or LEVELS.get(lvl, 0) > LEVELS.get(prev["level"], 0):
                found[c["id"]] = {"level": lvl, "verified": bool(d.get("verified")),
                                  "title": d.get("title"), "how": how, "site": loc.get("site")}
    defects = {}
    for c in scoreable:
        defects.setdefault((os.path.basename(c.get("file") or ""), c.get("function")), []).append(c["id"])
    hit_defects = [k for k, ids in defects.items() if any(i in found for i in ids)]
    return {
        "debug_binary": meta.get("debug_binary") if dbg else None,
        "dossiers": len(dossiers),
        "cve_ids": len(scoreable), "cve_ids_found": sum(1 for c in scoreable if c["id"] in found),
        "defects": len(defects), "defects_found": len(hit_defects),
        "found": found, "unlisted": unlisted,
        "missed": [f"{k[1]} ({k[0]}): {', '.join(v)}" for k, v in defects.items()
                   if k not in hit_defects],
        "max_level": max((LEVELS.get(v["level"], 0) for v in found.values()), default=0),
        "max_level_any": max((LEVELS.get(d.get("level") or "L0", 0) for d in dossiers),
                             default=0),
    }


def table(rows: list) -> str:
    lines = [f"{'target':28} {'surface':15} {'defects':>9} {'cve ids':>9} {'best':>4} "
             f"{'unlisted':>8} {'secs':>6}"]
    tot_d = tot_df = tot_c = tot_cf = 0
    for r in rows:
        s = r.get("score") or {}
        if "error" in s or not s:
            lines.append(f"{r['id']:28} {r['surface']:15} {'error: ' + str(s.get('error'))[:40]}")
            continue
        tot_d += s["defects"]
        tot_df += s["defects_found"]
        tot_c += s["cve_ids"]
        tot_cf += s["cve_ids_found"]
        lines.append(f"{r['id']:28} {r['surface']:15} {s['defects_found']:>4}/{s['defects']:<4} "
                     f"{s['cve_ids_found']:>4}/{s['cve_ids']:<4} L{s['max_level_any']:<3} "
                     f"{len(s['unlisted']):>8} {r.get('seconds', 0):>6}")
    lines.append(f"{'TOTAL':28} {'':15} {tot_df:>4}/{tot_d:<4} {tot_cf:>4}/{tot_c:<4}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ids", nargs="*")
    ap.add_argument("--budget", type=int, default=900)
    ap.add_argument("--surface", choices=SURFACES + ("both", "all"), default=None,
                    help="default: source for a run; every surface present in DIR for --rescore "
                         "(both = source+binary, all = source+binary+binary-stripped)")
    ap.add_argument("--parallel", type=int, default=2)
    ap.add_argument("--out", default=str(HERE / "runs"))
    ap.add_argument("--rescore", default=None, help="re-match the runs in DIR; run nothing")
    a = ap.parse_args()
    outdir = Path(a.rescore or a.out)
    outdir.mkdir(parents=True, exist_ok=True)
    if a.surface == "both":
        surfaces = ("source", "binary")
    elif a.surface == "all":
        surfaces = SURFACES
    elif a.surface:
        surfaces = (a.surface,)
    else:
        surfaces = SURFACES if a.rescore else ("source",)
    jobs = []
    for meta in load_targets(a.ids):
        for surf in surfaces:
            if a.rescore:                    # rescore what was run; never invent a missing run
                if not (outdir / f"{meta['id']}--{surf}").is_dir():
                    continue
            else:
                subj = subject_path(meta, surf)
                if subj is None:
                    continue
                if not subj.exists():
                    print(f"skip {meta['id']} ({surf}): {subj.relative_to(ROOT)} not built "
                          f"(examples/vuln-targets/fetch_build.sh)", flush=True)
                    continue
            jobs.append((meta, surf))
    rows = []

    def _one(job):
        meta, surf = job
        row = {"id": meta["id"], "surface": surf}
        if not a.rescore:
            row.update(run_lykos(meta, surf, a.budget, outdir))
        rd = outdir / f"{meta['id']}--{surf}"
        row["score"] = score_run(meta, rd / "report.json", surf)
        (rd / "score.json").write_text(json.dumps(row, indent=2))
        return row

    with cf.ThreadPoolExecutor(max_workers=max(1, a.parallel)) as ex:
        for row in ex.map(_one, jobs):
            rows.append(row)
            print(f"done {row['id']} ({row['surface']})", flush=True)
    (outdir / "summary.json").write_text(json.dumps(rows, indent=2))
    print(table(rows))
    for r in rows:
        s = r.get("score") or {}
        for cid, v in sorted((s.get("found") or {}).items()):
            print(f"  {r['id']} ({r['surface']}): {cid} -> {v['level']}"
                  f"{' verified' if v['verified'] else ''} [{v.get('how')}"
                  f"{' ' + str(v['site']) if v.get('how') == 'addr' else ''}]  {v['title']}")
        for u in s.get("unlisted") or []:
            print(f"  {r['id']} ({r['surface']}): UNLISTED {u['level']} {u['cwe']} {u['where']}  {u['title']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
