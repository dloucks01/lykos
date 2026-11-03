"""Semantic finding dedup -- collapse co-located candidates into one DISTINCT BUG before PoCs.

A static detector files one candidate per (file, line) SITE. A single bug shows up as many sites:
one `malloc(n * w)` int-overflow pattern expanded at 10 call sites, 22 unchecked writes in one
`smartcard_emulate` parser, 32 reachable-assert sites in one `shadow_client` function. Building a
potential PoC per site would mean 346 near-identical recipes for ~100 real bugs, and proving them
out would drive the same function 22 times.

So the pipeline is: DEDUP -> one potential PoC per distinct bug -> prove out. The canonical bug key
is (CWE, enclosing function): that is exactly the granularity the prover works at -- one synthesized
driver reaches one function and an ASan fault there confirms the class -- so collapsing to it loses
no provable bug while cutting the set to what an operator can actually read.

Nothing is deleted. One representative site per cluster stays `candidate` (and carries the count of
co-located sites); the rest are set to `merged`, excluded from the candidate set and the PoC floor
but kept in the database with a pointer to their representative, so the evidence is never lost.
Only raw `candidate` findings are clustered -- a finding already corroborated/confirmed/poc-backed
has advanced past this step and is left alone.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from ..db.dao import FindingDAO
from .fingerprint import srctaint

_LOC_RE = re.compile(r"([\w./+-]+\.[ch](?:pp|xx|c|h)?):(\d+)")
#: states that have advanced past raw candidacy -- never touched by dedup.
_ADVANCED = ("corroborated", "confirmed", "poc-backed", "merged", "rejected")


def parse_loc(evidence) -> tuple:
    """(file, line) from a finding's source-ish evidence, or (None, None). Reads the first
    `source` / `recipe-source` channel detail -- the site a detector recorded."""
    for e in (evidence or []):
        if e.get("channel") in ("source", "recipe-source"):
            m = _LOC_RE.search(e.get("detail") or "")
            if m:
                return m.group(1), int(m.group(2))
    return None, None


class _FnResolver:
    """Resolve a finding's (file, line) to its enclosing function name, robustly: the evidence path
    may be a full relative path or a bare basename, so fall back to a bounded basename search under
    the tree. Caches file contents and basename lookups -- a run has hundreds of findings over a
    handful of files."""

    def __init__(self, root):
        self.root = Path(root) if root else None
        self._lines: dict = {}            # resolved Path -> list[str]
        self._byname: dict = {}           # basename -> Path | None

    def _find_path(self, fp: str):
        if self.root is None:
            return None
        p = self.root / fp
        if p.is_file():
            return p
        base = os.path.basename(fp)
        if base in self._byname:
            return self._byname[base]
        hit = None
        n = 0
        for cand in self.root.rglob(base):
            if cand.is_file():
                hit = cand
                break
            n += 1
            if n > 64:
                break
        self._byname[base] = hit
        return hit

    def enclosing(self, fp: str, line: int):
        if not fp or not line:
            return None
        p = self._find_path(fp)
        if p is None:
            return None
        lines = self._lines.get(p)
        if lines is None:
            try:
                lines = p.read_text(errors="ignore").splitlines()
            except OSError:
                lines = []
            self._lines[p] = lines
        if not lines or line - 1 >= len(lines):
            return None
        try:
            return srctaint.enclosing_name(lines, line - 1)
        except Exception:                 # noqa: BLE001 -- a malformed span is just "unknown fn"
            return None


def canonical_key(cwe, fn, fp):
    """The distinct-bug key. (CWE, enclosing function) when the function resolves -- the prover's
    granularity; otherwise (CWE, file basename), a coarser but still correct fallback that never
    merges across files."""
    cwe = cwe or "CWE-unknown"
    if fn:
        return (cwe, "fn:" + fn)
    return (cwe, "file:" + (os.path.basename(fp) if fp else "unknown"))


def _rep_rank(f, fp, line):
    """Representative preference (higher first): a finding WITH a resolved site beats one without,
    then higher confidence, then the earliest line (stable, reproducible pick)."""
    return (1 if (fp and line) else 0, float(getattr(f, "confidence", 0.0) or 0.0),
            -(line or 10 ** 9))


def cluster(findings, resolver) -> dict:
    """Group raw candidate findings by canonical bug key. Returns {key: [findings]} where each list
    is sorted representative-first. Non-candidate findings are skipped (already advanced)."""
    groups: dict = {}
    for f in findings:
        if (getattr(f, "state", "candidate") or "candidate") != "candidate":
            continue
        fp, line = parse_loc(getattr(f, "evidence", None))
        fn = resolver.enclosing(fp, line) if resolver else None
        groups.setdefault(canonical_key(f.cwe, fn, fp), []).append((f, fp, line))
    out: dict = {}
    for key, items in groups.items():
        items.sort(key=lambda t: _rep_rank(*t), reverse=True)
        out[key] = [t[0] for t in items]
    return out


def dedup_findings(ctx, target, src_root) -> dict:
    """Collapse the target's raw candidates into distinct bugs. The representative of each cluster
    stays `candidate` (annotated with the co-located-site count); the rest are set to `merged` with
    a pointer to the representative. Returns {raw, clusters, merged}. Idempotent: a re-run re-picks
    the same representative and leaves an already-merged finding merged."""
    fd = FindingDAO(ctx.conn)
    findings = [f for f in fd.list_by_target(target.id)
                if (f.state or "candidate") == "candidate"]
    if not findings:
        return {"raw": 0, "clusters": 0, "merged": 0}
    resolver = _FnResolver(src_root)
    groups = cluster(findings, resolver)
    merged = 0
    for key, members in groups.items():
        if len(members) < 2:
            continue
        rep, dups = members[0], members[1:]
        rep_fp, rep_line = parse_loc(rep.evidence)
        rep_site = f"{rep_fp}:{rep_line}" if rep_fp else (rep.dedup_key or rep.id)
        # Annotate the representative with how many sites it stands for (additive evidence, safe
        # through upsert -- it only unions evidence, never downgrades).
        fd.upsert(target.id, target.case_id, {
            "cwe": rep.cwe, "title": rep.title, "severity": rep.severity or "medium",
            "detector": rep.detector, "dedup_key": rep.dedup_key, "state": rep.state,
            "confidence": rep.confidence or 0.0, "channel": "dedup",
            "evidence": [{"channel": "dedup",
                          "detail": (f"representative of {len(members)} co-located sites of this "
                                     f"({key[0]}, {key[1]}) bug; the others are merged into this one")}]})
        for d in dups:
            d_fp, d_line = parse_loc(d.evidence)
            ev = list(d.evidence or [])
            ev.append({"channel": "dedup",
                       "detail": (f"merged into {rep_site} -- the same ({key[0]}, {key[1]}) bug "
                                  f"(one of {len(members)} co-located sites)")})
            # Direct state write: dedup is structural bookkeeping, not a verdict, so it must bypass
            # the verdict-recompute merge (which only ever raises state) to set `merged`.
            _set_merged(ctx.conn, d.id, ev)
            merged += 1
    return {"raw": len(findings), "clusters": len(groups), "merged": merged}


def _set_merged(conn, finding_id, evidence) -> None:
    import json
    import time
    conn.execute("UPDATE finding SET state='merged', evidence_json=?, updated_at=? WHERE id=?",
                 (json.dumps(evidence), int(time.time()), finding_id))
