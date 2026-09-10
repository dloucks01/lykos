"""Fingerprint embedded library versions in a binary and match the offline CVE database.

Pure byte scanning + rule matching -- no execution, no network. The component/CVE seed lives in
db.COMPONENTS; an operator can extend it by pointing $LYKOS_CVEDB at a JSON file of the same
shape (merged per library: patterns concatenated, CVEs appended).
"""
from __future__ import annotations

import json
import os
import re

from . import db

_MAX = 64 * 1024 * 1024        # cap the scan for huge firmware blobs


def _components():
    """The seed DB, merged with an operator-supplied $LYKOS_CVEDB JSON if present."""
    comps = {k: {"patterns": list(v["patterns"]), "cves": list(v["cves"])}
             for k, v in db.COMPONENTS.items()}
    path = os.environ.get("LYKOS_CVEDB")
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                ext = json.load(f)
            for lib, v in ext.items():
                tgt = comps.setdefault(lib, {"patterns": [], "cves": []})
                tgt["patterns"] += list(v.get("patterns", []))
                tgt["cves"] += list(v.get("cves", []))
        except Exception:
            pass                # a malformed override never breaks the scan
    return comps


def scan(blob: bytes, comps=None):
    """Detect (library, version) pairs from version banners in the blob. Returns a list of
    {library, version, evidence, offset}, deduped by (library, version)."""
    comps = comps or _components()
    text = blob[:_MAX].decode("latin-1", "ignore")
    found, seen = [], set()
    for lib, spec in comps.items():
        for pat in spec["patterns"]:
            for m in re.finditer(pat, text):
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


def match(detected, comps=None):
    """For each detected component, the CVEs whose ranges include its version.
    Returns a list of {library, version, cve, name, cvss, severity, cwe, summary, evidence}."""
    comps = comps or _components()
    out = []
    for d in detected:
        spec = comps.get(d["library"])
        if not spec:
            continue
        for cve in spec["cves"]:
            try:
                if db.affected(d["version"], cve):
                    out.append({"library": d["library"], "version": d["version"],
                                "cve": cve["id"], "name": cve.get("name"),
                                "cvss": cve.get("cvss"), "severity": cve.get("severity", "medium"),
                                "cwe": cve.get("cwe", "CWE-1395"),
                                "summary": cve.get("summary", ""),
                                "evidence": d["evidence"]})
            except Exception:
                continue        # a bad range entry skips, never crashes the scan
    return out


def scan_and_match(blob: bytes):
    comps = _components()
    detected = scan(blob, comps)
    return detected, match(detected, comps)
