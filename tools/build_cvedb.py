#!/usr/bin/env python3
"""Build lykos's offline CVE database from OSV (dev-time tool, NOT shipped-at-runtime).

lykos is air-gapped at runtime: it ships a STATIC snapshot of OSV and never touches the network
itself. This script regenerates that snapshot on a connected machine, in two artifacts:

  1. core/lykos/analyze/fingerprint/data/cvedb.sqlite   -- the FULL offline mirror. One indexed
     row per (ecosystem, package, CVE) with its affected version ranges. Queried lazily per
     detected package, so the whole DB never loads into RAM. This is the "whole CVE DB offline"
     reference. It is large, so it is git-ignored and travels with the packaged tool, not git.

  2. core/lykos/analyze/fingerprint/data/osv_cvedb.json -- a SMALL curated subset (committed) so
     the tool still matches common ecosystem packages when the big sqlite is absent.

Both share the shape the fingerprint loader + the $LYKOS_CVEDB override use. C-library BANNER
patterns (for stripped binaries) stay hand-curated in fingerprint/db.py -- OSV cannot supply a
byte-banner regex, only version ranges.

Usage:
  python tools/build_cvedb.py --sqlite               # full mirror, default ecosystem set
  python tools/build_cvedb.py --sqlite --all         # every OSV ecosystem (large; includes npm)
  python tools/build_cvedb.py --sqlite --ecosystems PyPI,Go,Alpine
  python tools/build_cvedb.py --json                 # refresh the small committed JSON subset
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "core/lykos/analyze/fingerprint/data"
SQLITE_OUT = DATA / "cvedb.sqlite"
JSON_OUT = DATA / "osv_cvedb.json"
CLIB_OUT = DATA / "clib_cvedb.json"
DUMP_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
ECOSYSTEMS_URL = "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# C / embedded libraries matched by a BINARY banner or a vendored HEADER (not a language
# ecosystem). OSV's data for these is distro-versioned and noisy, so their CVEs come from NVD's
# CPE match ranges (upstream versions) instead -- keyed by our bare library name -> the NVD CPE
# product token(s) to collect ranges for. Banner/header DETECTION for each lives in
# fingerprint/db.py (patterns) and fingerprint/source_scan.py (header version macros).
# lib -> {kw: NVD full-text keyword to search, cpe: CPE product token(s) to keep ranges for}.
# The keyword must be a term NVD's text matches (a CPE token like "mbed_tls" matches nothing);
# the cpe tokens filter the results to the right product.
CLIB_PRODUCTS = {
    "freertos": {"kw": "freertos", "cpe": ["freertos"]},
    "mbedtls": {"kw": "mbedtls", "cpe": ["mbed_tls", "mbedtls"]},
    "wolfssl": {"kw": "wolfssl", "cpe": ["wolfssl"]},
    "lwip": {"kw": "lwip", "cpe": ["lwip"]},
    "zlib": {"kw": "zlib", "cpe": ["zlib"]},
    "openssl": {"kw": "openssl", "cpe": ["openssl"]},
    "libpng": {"kw": "libpng", "cpe": ["libpng"]},
    "expat": {"kw": "libexpat", "cpe": ["libexpat", "expat"]},
    "sqlite": {"kw": "sqlite", "cpe": ["sqlite"]},
    "busybox": {"kw": "busybox", "cpe": ["busybox"]},
    "dropbear": {"kw": "dropbear", "cpe": ["dropbear_ssh", "dropbear"]},
}

# The default is the LANGUAGE ecosystems a source project's dependency manifests point at --
# the only packages lykos can actually detect-and-match from an upload. The Linux distro/OS +
# container feeds (Ubuntu, Debian, Red Hat, SUSE, Wolfi, Chainguard, ...) are intentionally
# EXCLUDED: they are keyed by distro-package name + distro version, which nothing an upload
# yields can be matched against, and they are enormous (the full set is ~2 GB vs. ~tens of MB
# here). C-library CVEs come from the hand-curated upstream ranges in db.py, matched off a
# binary's version banner. `--all` pulls every ecosystem for anyone who wants the full mirror.
DEFAULT_ECOSYSTEMS = [
    "PyPI", "npm", "Go", "crates.io", "Maven", "RubyGems", "Packagist", "NuGet", "Hex", "Pub",
]

# The small committed JSON subset (used when cvedb.sqlite is absent).
JSON_TARGETS = [
    ("PyPI", "jinja2"), ("PyPI", "flask"), ("PyPI", "requests"), ("PyPI", "pyyaml"),
    ("PyPI", "django"), ("PyPI", "urllib3"), ("PyPI", "cryptography"), ("PyPI", "werkzeug"),
    ("npm", "lodash"), ("npm", "minimist"), ("npm", "axios"), ("npm", "express"),
    ("Go", "golang.org/x/text"), ("Go", "golang.org/x/net"),
    ("crates.io", "openssl"), ("crates.io", "time"),
]

_SEV_MAP = {"low": "low", "moderate": "medium", "medium": "medium", "high": "high",
            "critical": "critical"}


def eco_key(ecosystem: str) -> str:
    """OSV ecosystem name -> the short prefix we key detected packages by (e.g. 'PyPI'->'pypi',
    'crates.io'->'crates', 'Red Hat'->'redhat'). Distro/OS feeds collapse to their own prefixes."""
    base = ecosystem.split(":")[0].strip().lower()        # OSV appends ':version' to some distros
    return base.replace(".io", "").replace(" ", "")


def _cve_id(vuln: dict) -> str:
    for a in vuln.get("aliases", []):
        if a.startswith("CVE-"):
            return a
    for u in vuln.get("upstream", []):
        if u.startswith("CVE-"):
            return u
    return vuln.get("id", "")


def _ranges_for(aff: dict) -> list:
    """One affected entry's version ranges -> [{ge?,lt?,le?}]. Version-typed only (no GIT)."""
    out = []
    for rng in aff.get("ranges", []):
        if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        events = rng.get("events", [])
        has_last = any("last_affected" in e for e in events)
        lo = hi = None
        for ev in events:
            if ev.get("introduced") not in (None, "0", ""):
                lo = ev["introduced"]
            elif "fixed" in ev:
                hi = ev["fixed"]
            elif "last_affected" in ev:
                hi = ev["last_affected"]
        r = {}
        if lo is not None:
            r["ge"] = lo
        if hi is not None:
            r["le" if has_last else "lt"] = hi
        if r:
            out.append(r)
    # Fall back to an explicit versions list as exact-match ranges when no range events exist.
    if not out and aff.get("versions"):
        out = [{"eq": v} for v in aff["versions"][:50]]
    return out


def _severity(vuln: dict) -> str:
    sev = (vuln.get("database_specific", {}) or {}).get("severity")
    return _SEV_MAP.get(sev.lower(), "medium") if isinstance(sev, str) else "medium"


def _cwe(vuln: dict) -> str:
    cwes = (vuln.get("database_specific", {}) or {}).get("cwe_ids") or []
    return cwes[0] if cwes else "CWE-1395"


def _download(ecosystem: str, retries: int = 3) -> bytes:
    url = DUMP_URL.format(eco=urllib.parse.quote(ecosystem))
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=120) as r:
                return r.read()
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if attempt == retries - 1:
                print(f"  ! download failed for {ecosystem}: {e}", file=sys.stderr)
                return b""
            time.sleep(2 * (attempt + 1))
    return b""


def build_sqlite(ecosystems: list, out: Path = SQLITE_OUT) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    # Build into a staging file and os.replace() at the end: an interrupted or concurrent build
    # never corrupts the live DB, and the swap into place is atomic.
    staging = out.with_name(out.name + ".building")
    if staging.exists():
        staging.unlink()
    conn = sqlite3.connect(staging)
    # The MATCH index only: no description text (that is the bulk, and the optional reference
    # pack already holds it per CVE id). severity/cwe are kept so the index is self-sufficient
    # for a finding when no reference pack is installed.
    conn.execute("""CREATE TABLE cve(
        eco TEXT, name TEXT, cve TEXT, severity TEXT, cwe TEXT, ranges TEXT,
        PRIMARY KEY(eco, name, cve))""")
    conn.execute("CREATE INDEX idx_lookup ON cve(eco, name)")
    total = 0
    for ecosystem in ecosystems:
        blob = _download(ecosystem)
        if not blob:
            continue
        key = eco_key(ecosystem)
        n = 0
        try:
            zf = zipfile.ZipFile(io.BytesIO(blob))
        except zipfile.BadZipFile:
            print(f"  ! bad zip for {ecosystem}", file=sys.stderr)
            continue
        rows = []
        for member in zf.namelist():
            if not member.endswith(".json"):
                continue
            try:
                v = json.loads(zf.read(member))
            except (ValueError, KeyError):
                continue
            cid = _cve_id(v)
            if not cid:
                continue
            sev, cwe = _severity(v), _cwe(v)
            seen_pkg = set()
            for aff in v.get("affected", []):
                pkg = aff.get("package", {})
                nm = (pkg.get("name") or "").lower()
                if not nm or (nm, cid) in seen_pkg:
                    continue
                ranges = _ranges_for(aff)
                if not ranges:
                    continue
                seen_pkg.add((nm, cid))
                rows.append((key, nm, cid, sev, cwe, json.dumps(ranges)))
                n += 1
        conn.executemany("INSERT OR IGNORE INTO cve VALUES(?,?,?,?,?,?)", rows)
        conn.commit()
        total += n
        print(f"[{ecosystem:>14}] key={key:<10} {n} package-CVE rows")
    conn.execute("ANALYZE")
    conn.commit()
    conn.close()
    os.replace(staging, out)            # atomic swap into place
    mb = out.stat().st_size / 1048576
    print(f"\nwrote {out}  ({total} rows, {mb:.1f} MB)")


def build_json(out: Path = JSON_OUT) -> None:
    """The small committed fallback: query OSV for a curated set of ecosystem packages."""
    db: dict = {}
    for ecosystem, name in JSON_TARGETS:
        key = f"{eco_key(ecosystem)}:{name.lower()}"
        data = json.dumps({"package": {"name": name, "ecosystem": ecosystem}}).encode()
        try:
            req = urllib.request.Request("https://api.osv.dev/v1/query", data=data,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                resp = json.loads(r.read().decode())
        except Exception as e:
            print(f"  ! {key}: {e}", file=sys.stderr)
            continue
        cves, seen = [], set()
        for v in resp.get("vulns", []):
            cid = _cve_id(v)
            ranges = [r for aff in v.get("affected", [])
                      if (aff.get("package", {}).get("ecosystem") == ecosystem
                          and aff.get("package", {}).get("name", "").lower() == name.lower())
                      for r in _ranges_for(aff)]
            if cid and ranges and cid not in seen:
                seen.add(cid)
                cves.append({"id": cid, "severity": _severity(v), "cwe": _cwe(v),
                             "summary": (v.get("summary") or v.get("details") or "")[:200],
                             "ranges": ranges})
        if cves:
            db[key] = {"patterns": [], "cves": cves}
            print(f"[json] {key}: {len(cves)} CVEs")
        time.sleep(0.3)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(db, indent=1, sort_keys=True) + "\n")
    print(f"wrote {out}")


def _nvd_get(params: dict, retries: int = 4) -> dict:
    url = NVD_API + "?" + urllib.parse.urlencode(params)
    key = os.environ.get("NVD_API_KEY")
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"apiKey": key} if key else {})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode())
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            # NVD rate-limits hard (5 req/30s without a key); back off generously.
            wait = (8 if not key else 2) * (attempt + 1)
            if attempt == retries - 1:
                print(f"  ! NVD query failed ({e}); giving up on this page", file=sys.stderr)
                return {}
            time.sleep(wait)
    return {}


def _cpe_ranges(cve: dict, tokens: list) -> list:
    """NVD CPE match rows for the target product -> our {ge?,gt?,le?,lt?} ranges. A match with
    only an exact CPE version (no range bounds) becomes an {eq} range."""
    out = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                crit = m.get("criteria", "")
                # cpe:2.3:a:<vendor>:<product>:<version>:...
                parts = crit.split(":")
                product = parts[4] if len(parts) > 4 else ""
                if product not in tokens:
                    continue
                r = {}
                if m.get("versionStartIncluding"):
                    r["ge"] = m["versionStartIncluding"]
                if m.get("versionStartExcluding"):
                    r["gt"] = m["versionStartExcluding"]
                if m.get("versionEndIncluding"):
                    r["le"] = m["versionEndIncluding"]
                if m.get("versionEndExcluding"):
                    r["lt"] = m["versionEndExcluding"]
                if not r and len(parts) > 5 and parts[5] not in ("*", "-"):
                    r = {"eq": parts[5]}
                # Drop an open-ended-UPWARD range (a lower bound but no upper bound and no exact
                # version): NVD sometimes lists only versionStartIncluding for a bug that was
                # since fixed, and such a range would match every future version forever -- a
                # false positive. A bounded range or an exact version is kept.
                if r and not ({"le", "lt", "eq"} & set(r)):
                    continue
                if r:
                    out.append(r)
    # dedupe identical ranges
    uniq = []
    for r in out:
        if r not in uniq:
            uniq.append(r)
    return uniq


def build_clibs(out: Path = CLIB_OUT) -> None:
    """Pull C/embedded-library CVEs from NVD by CPE product, with upstream version ranges, into
    the committed clib_cvedb.json (keyed by our bare library name). Banner/header detection for
    each is defined in the code, not here."""
    db: dict = {}
    for lib, spec in CLIB_PRODUCTS.items():
        kw, tokens = spec["kw"], spec["cpe"]
        print(f"[nvd] {lib}  (keyword: {kw}; cpe products: {', '.join(tokens)})")
        cves, seen = [], set()
        start, total = 0, None
        while total is None or start < total:
            resp = _nvd_get({"keywordSearch": kw, "resultsPerPage": 2000,
                             "startIndex": start})
            total = resp.get("totalResults", 0)
            vulns = resp.get("vulnerabilities", [])
            if not vulns:
                break
            for item in vulns:
                c = item["cve"]
                cid = c["id"]
                ranges = _cpe_ranges(c, tokens)
                if not ranges or cid in seen:
                    continue
                seen.add(cid)
                sev, cvss = "medium", None
                for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    mm = c.get("metrics", {}).get(mk)
                    if mm:
                        cd = mm[0]["cvssData"]
                        cvss = cd.get("baseScore")
                        sev = (cd.get("baseSeverity") or mm[0].get("baseSeverity")
                               or "medium").lower()
                        break
                cwes = [w["value"] for d in c.get("weaknesses", [])
                        for w in d.get("description", []) if w["value"].startswith("CWE-")]
                desc = next((t["value"] for t in c["descriptions"] if t["lang"] == "en"), "")
                cves.append({"id": cid, "severity": _SEV_MAP.get(sev, "medium"),
                             "cvss": cvss, "cwe": cwes[0] if cwes else "CWE-1395",
                             "summary": desc[:200], "ranges": ranges})
            start += len(vulns)
            time.sleep(8 if not os.environ.get("NVD_API_KEY") else 0.8)
        if cves:
            db[lib] = {"patterns": [], "cves": cves}
            print(f"       {len(cves)} CVE(s) with version ranges")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(db, indent=1, sort_keys=True) + "\n")
    total = sum(len(v["cves"]) for v in db.values())
    print(f"\nwrote {out}  ({len(db)} libraries, {total} CVEs)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqlite", action="store_true", help="build the full offline mirror")
    ap.add_argument("--json", action="store_true", help="refresh the small committed subset")
    ap.add_argument("--clibs", action="store_true",
                    help="refresh the committed C/embedded-library CVEs from NVD CPE")
    ap.add_argument("--all", action="store_true", help="every OSV ecosystem (with --sqlite)")
    ap.add_argument("--ecosystems", help="comma-separated ecosystem names (with --sqlite)")
    args = ap.parse_args()
    if args.clibs:
        build_clibs()
    if args.json:
        build_json()
    if args.sqlite:
        if args.ecosystems:
            ecos = [e.strip() for e in args.ecosystems.split(",") if e.strip()]
        elif args.all:
            with urllib.request.urlopen(ECOSYSTEMS_URL, timeout=60) as r:
                ecos = [ln.strip() for ln in r.read().decode().splitlines() if ln.strip()]
        else:
            ecos = DEFAULT_ECOSYSTEMS
        build_sqlite(ecos)
    if not (args.json or args.sqlite or args.clibs):
        ap.error("pass --sqlite, --json and/or --clibs")
