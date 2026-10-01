"""Fingerprint embedded library versions in a binary and match the offline CVE database.

Pure byte scanning + rule matching -- no execution, no network. The component/CVE seed lives in
db.COMPONENTS; an operator can extend it by pointing $LYKOS_CVEDB at a JSON file of the same
shape (merged per library: patterns concatenated, CVEs appended).
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

from . import cvedb, db

_log = logging.getLogger(__name__)

_MAX = 64 * 1024 * 1024        # cap the scan for huge firmware blobs

# Vendored snapshots shipped with the tool (built offline by tools/build_cvedb.py):
#   osv_cvedb.json  -- language-ecosystem packages (pypi:/npm:/go:/crates:) for source manifests
#   clib_cvedb.json -- C/embedded-library CVEs from NVD CPE (keyed by bare name: freertos, zlib,
#                      mbedtls, ...), matched off a binary banner or a vendored header
# Banner/header detection patterns live in db.COMPONENTS / source_scan; these files add the CVEs.
_DATA = Path(__file__).with_name("data")
_BUNDLED_DBS = [_DATA / "osv_cvedb.json", _DATA / "clib_cvedb.json"]


def _merge(comps: dict, ext: dict) -> None:
    """Merge an external DB (same shape) into comps: patterns concatenated, CVEs appended."""
    for lib, v in ext.items():
        tgt = comps.setdefault(lib, {"patterns": [], "cves": []})
        tgt["patterns"] += list(v.get("patterns", []))
        tgt["cves"] += list(v.get("cves", []))


def _components():
    """The seed C-library DB (banner patterns + curated CVEs), merged with the vendored OSV +
    NVD-CPE snapshots and any operator-supplied $LYKOS_CVEDB JSON. A malformed or missing file
    never breaks the scan. CVEs are deduped per library by id (first source wins: the curated
    db.COMPONENTS entry takes precedence over a snapshot's copy of the same CVE)."""
    comps = {k: {"patterns": list(v["patterns"]), "cves": list(v["cves"])}
             for k, v in db.COMPONENTS.items()}
    sources = list(_BUNDLED_DBS)
    override = os.environ.get("LYKOS_CVEDB")
    if override:
        sources.append(Path(override))
    for src in sources:
        if not src.exists():
            continue
        try:
            _merge(comps, json.loads(src.read_text(encoding="utf-8")))
        except Exception:
            _log.debug("failed to load/merge CVE DB %s", src, exc_info=True)
            continue            # a malformed source never breaks the scan
    for spec in comps.values():
        seen, uniq = set(), []
        for cve in spec["cves"]:
            cid = cve.get("id")
            if not cid or cid in seen:
                continue
            # Drop open-ended-UPWARD ranges ({ge}/{gt} with no le/lt/eq): they match every
            # future version forever (a version-matcher false-positive factory, e.g. an NVD CPE
            # that lists only a start bound for an already-fixed bug). A CVE left with no usable
            # range is dropped -- it could only ever match everything or nothing.
            ranges = [r for r in cve.get("ranges", []) if {"le", "lt", "eq"} & set(r)]
            if not ranges:
                continue
            seen.add(cid)
            uniq.append({**cve, "ranges": ranges})
        spec["cves"] = uniq
    return comps


def scan(blob: bytes, comps=None):
    """Detect (library, version) pairs from version banners in the blob. Returns a list of
    {library, version, evidence, offset}, deduped by (library, version)."""
    comps = comps or _components()
    text = blob[:_MAX].decode("latin-1", "ignore")
    found, seen = [], set()
    for lib, spec in comps.items():
        for pat in spec["patterns"]:
            try:
                matches = list(re.finditer(pat, text))
            except re.error:
                # An operator-supplied $LYKOS_CVEDB pattern can be malformed; a raw re.error here
                # aborts the whole cve scan for the target. Skip the bad pattern instead -- the
                # module's documented guarantee is that a malformed override never breaks the scan.
                _log.debug("skipping malformed CVE pattern %r for %s", pat, lib)
                continue
            for m in matches:
                if not m.groups():
                    continue
                ver = m.group(1)
                key = (lib, ver)
                if key in seen:
                    continue
                seen.add(key)
                ev = m.group(0)
                found.append({"library": lib, "version": ver,
                              "evidence": ev[:80], "offset": m.start()})
    return found


def _candidates(library: str, comps: dict) -> list:
    """Candidate CVE dicts for a detected library, from the in-memory DB (curated C-lib seed +
    committed JSON subset) AND the large OSV match index on disk. An 'ecosystem:name' key (a
    source-manifest dependency) is also looked up in the index; a bare C-lib key relies on the
    curated upstream ranges (the index's distro-versioned rows don't match upstream versions).
    Curated entries win over index entries on the same CVE id."""
    cves = list((comps.get(library) or {}).get("cves", []))
    seen = {c["id"] for c in cves}
    if ":" in library:
        eco, name = library.split(":", 1)
        for c in cvedb.cves_for(eco, name):
            if c["id"] not in seen:
                seen.add(c["id"])
                cves.append(c)
    return cves


def match(detected, comps=None):
    """For each detected component, the CVEs whose ranges include its version.
    Returns a list of {library, version, cve, name, cvss, severity, cwe, summary, evidence}."""
    comps = comps or _components()
    out = []
    for d in detected:
        for cve in _candidates(d["library"], comps):
            try:
                if not db.affected(d["version"], cve):
                    continue
            except Exception:
                _log.debug("CVE range match failed for %s / %s", d.get("library"),
                           cve.get("id"), exc_info=True)
                continue        # a bad range entry skips, never crashes the scan
            severity = cve.get("severity", "medium")
            cvss = cve.get("cvss")
            summary = cve.get("summary", "")
            # Enrich from the optional full-corpus reference pack: authoritative CVSS + prose,
            # and a severity when the match index had none.
            ref = cvedb.reference_detail(cve["id"])
            if ref:
                cvss = ref.get("cvss") or cvss
                severity = ref.get("severity") or severity
                summary = summary or ref.get("desc", "")[:200]
            out.append({"library": d["library"], "version": d["version"],
                        "cve": cve["id"], "name": cve.get("name"),
                        "cvss": cvss, "severity": severity,
                        "cwe": cve.get("cwe", "CWE-1395"), "summary": summary,
                        "evidence": d["evidence"]})
    return out


def exploit_evidence(cwe: str) -> list:
    """An 'exploit' evidence channel for a CVE finding: the exploit class its CWE implies, with
    the honest caveat that weaponising it needs a reproducer/trigger in this target. Empty when
    the CWE maps to no class. This is a routing HINT, never a claim that a PoC was built."""
    hint = db.exploit_hint(cwe)
    if not hint:
        return []
    desc, strategy = hint
    tail = (f" (exploit strategy: {strategy}; a reproducer/trigger in this target is still "
            f"required to weaponise)" if strategy
            else " (a trigger in this target is still required to exploit)")
    return [{"channel": "exploit", "detail": desc + tail}]


def scan_and_match(blob: bytes):
    comps = _components()
    detected = scan(blob, comps)
    return detected, match(detected, comps)
