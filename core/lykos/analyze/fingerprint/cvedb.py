"""Offline CVE data access — the runtime side of the OSV snapshot + the optional reference pack.

Two independent, read-only, stdlib-based data sources, each used when present and skipped cleanly
when absent (so the tool runs identically offline with or without them):

  * MATCH INDEX -- `cvedb.sqlite`, built by tools/build_cvedb.py from OSV. One row per
    (ecosystem, package, CVE): severity, CWE, and affected version ranges. This is what answers
    "which CVEs affect package X version Y". It carries NO descriptions (kept small).

  * REFERENCE PACK -- `cve.sqlite`, the full NVD corpus (id -> cvss/severity/cwe/description).
    Large, optional; enriches a matched CVE with authoritative CVSS + prose. Schema-compatible
    with recce's data pack, so the same file serves both tools.

Neither is committed to git (they travel with the packaged tool). The small curated JSON subset
in data/osv_cvedb.json and the hand-curated C-library banner ranges in db.py always work.
"""
from __future__ import annotations

import functools
import json
import logging
import os
import sqlite3
import zlib
from pathlib import Path

_log = logging.getLogger(__name__)
_DATA = Path(__file__).with_name("data")


# ------------------------------------------------------------------- the OSV match index
@functools.lru_cache(maxsize=1)
def index_path() -> "Path | None":
    env = os.environ.get("LYKOS_CVEDB_SQLITE")
    if env and Path(env).is_file():
        return Path(env)
    cand = _DATA / "cvedb.sqlite"
    return cand if cand.is_file() else None


def index_available() -> bool:
    return index_path() is not None


def _ro(path: "Path | None") -> "sqlite3.Connection | None":
    if path is None:
        return None
    try:
        return sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error:
        return None


def cves_for(eco: str, name: str) -> list:
    """Candidate CVEs for one (ecosystem-key, package) from the match index:
    [{id, severity, cwe, ranges:[...]}]. Empty when no index or no match."""
    conn = _ro(index_path())
    if conn is None:
        return []
    try:
        rows = conn.execute(
            "SELECT cve, severity, cwe, ranges FROM cve WHERE eco=? AND name=?",
            (eco.lower(), name.lower())).fetchall()
    except sqlite3.Error:
        _log.debug("cve index query failed for %s/%s", eco, name, exc_info=True)
        return []
    finally:
        conn.close()
    out = []
    for cve, severity, cwe, ranges in rows:
        try:
            rngs = json.loads(ranges)
        except (ValueError, TypeError):
            continue
        out.append({"id": cve, "severity": severity or "medium",
                    "cwe": cwe or "CWE-1395", "ranges": rngs})
    return out


# ------------------------------------------------------------- the optional reference pack
@functools.lru_cache(maxsize=1)
def reference_path() -> "Path | None":
    """Resolve the full-corpus reference pack (recce-compatible schema). First match wins:
    $LYKOS_CVE_REF, data/cve.sqlite, ~/.local/share/lykos/cve.sqlite, then $RECCE_CVE_DB (the
    same pack recce ships -- reused rather than duplicated)."""
    env = os.environ.get("LYKOS_CVE_REF")
    if env and Path(env).is_file():
        return Path(env)
    for cand in (_DATA / "cve.sqlite",
                 Path.home() / ".local" / "share" / "lykos" / "cve.sqlite"):
        if cand.is_file():
            return cand
    recce = os.environ.get("RECCE_CVE_DB")
    if recce and Path(recce).is_file():
        return Path(recce)
    return None


def reference_available() -> bool:
    return reference_path() is not None


def reference_detail(cve: str) -> "dict | None":
    """Authoritative detail for one CVE id from the reference pack: {cvss, severity, cwe, desc}.
    None when there is no pack or the id is absent."""
    cid = (cve or "").strip().upper()
    if not cid.startswith("CVE-"):
        return None
    conn = _ro(reference_path())
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT cvss, severity, cwe, descr FROM cve WHERE id=?", (cid,)).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if not row:
        return None
    cvss, severity, cwe, descr = row
    desc = ""
    if descr:
        try:
            desc = zlib.decompress(descr).decode("utf-8", "replace")
        except (zlib.error, TypeError):
            desc = ""
    return {"cvss": cvss, "severity": (severity or "").lower(),
            "cwe": cwe or "", "desc": desc}
