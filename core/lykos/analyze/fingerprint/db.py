"""Offline component-CVE database + version matching (deterministic, no network).

`COMPONENTS` maps a library to the byte patterns that reveal its version in a binary and a
curated list of well-known CVEs with affected version ranges. This is a *seed* set (high-profile
CVEs, ranges best-effort) meant to be extended -- an operator can drop a JSON file at
$LYKOS_CVEDB (same shape) and it is merged in at scan time, so a fuller offline NVD-derived
feed can be vendored without code changes. Everything here is offline and rule-based.
"""
from __future__ import annotations

import re

# library -> {patterns: [regex with one version group], cves: [ {id,name,cvss,severity,cwe,
#             ranges:[{ge?,gt?,le?,lt?,eq?}], summary} ]}
COMPONENTS = {
    "openssl": {
        "patterns": [r"OpenSSL (\d+\.\d+\.\d+[a-z]{0,2})"],
        "cves": [
            {"id": "CVE-2014-0160", "name": "Heartbleed", "cvss": 7.5, "severity": "high",
             "cwe": "CWE-125", "ranges": [{"ge": "1.0.1", "lt": "1.0.1g"}],
             "summary": "TLS heartbeat out-of-bounds read leaks memory (Heartbleed)"},
            {"id": "CVE-2016-2107", "cvss": 5.9, "severity": "medium", "cwe": "CWE-203",
             "ranges": [{"ge": "1.0.1", "lt": "1.0.1t"}, {"ge": "1.0.2", "lt": "1.0.2h"}],
             "summary": "Padding-oracle in AES-NI CBC MAC check"},
            {"id": "CVE-2022-3602", "name": "punycode overflow", "cvss": 7.5,
             "severity": "high", "cwe": "CWE-787",
             "ranges": [{"ge": "3.0.0", "lt": "3.0.7"}],
             "summary": "X.509 email-address punycode 4-byte stack buffer overflow"},
        ],
    },
    "zlib": {
        "patterns": [r"(?:in|de)flate (\d+\.\d+\.\d+) Copyright",
                     r"\bzlib version (\d+\.\d+\.\d+)"],
        "cves": [
            {"id": "CVE-2018-25032", "cvss": 7.5, "severity": "high", "cwe": "CWE-787",
             "ranges": [{"ge": "1.2.0", "lt": "1.2.12"}],
             "summary": "Memory corruption on deflate with certain memLevel/window settings"},
            {"id": "CVE-2022-37434", "cvss": 9.8, "severity": "critical", "cwe": "CWE-787",
             "ranges": [{"lt": "1.2.12"}],
             "summary": "Heap over-read/overflow in inflate() via a large gzip header extra field"},
        ],
    },
    "libpng": {
        "patterns": [r"libpng version (\d+\.\d+\.\d+)"],
        "cves": [
            {"id": "CVE-2015-8126", "cvss": 9.8, "severity": "critical", "cwe": "CWE-120",
             "ranges": [{"lt": "1.6.20"}],
             "summary": "Multiple buffer overflows in png_set_PLTE/png_get_PLTE"},
            {"id": "CVE-2018-13785", "cvss": 5.3, "severity": "medium", "cwe": "CWE-190",
             "ranges": [{"lt": "1.6.35"}],
             "summary": "Integer overflow / divide-by-zero in png_check_chunk_length"},
        ],
    },
    "busybox": {
        "patterns": [r"BusyBox v(\d+\.\d+\.\d+)"],
        "cves": [
            {"id": "CVE-2021-42374", "cvss": 5.3, "severity": "medium", "cwe": "CWE-125",
             "ranges": [{"lt": "1.34.0"}],
             "summary": "Out-of-bounds read in the unlzma decompressor"},
            {"id": "CVE-2021-42378", "cvss": 7.2, "severity": "high", "cwe": "CWE-416",
             "ranges": [{"lt": "1.34.0"}],
             "summary": "Use-after-free in awk (getvar_i)"},
        ],
    },
    "sqlite": {
        # The sourceid banner needs its CAPTURE GROUP: `scan` skips any pattern that
        # matches without one, so this contributed nothing at all and SQLite CVEs only
        # ever fired on the rarer literal "SQLite version" text.
        "patterns": [r"(3\.\d+\.\d+) [0-9a-f]{40}", r"SQLite version (\d+\.\d+\.\d+)"],
        "cves": [
            {"id": "CVE-2019-5018", "cvss": 8.1, "severity": "high", "cwe": "CWE-416",
             "ranges": [{"lt": "3.28.0"}],
             "summary": "Use-after-free in window-function handling"},
            {"id": "CVE-2020-13631", "cvss": 5.5, "severity": "medium", "cwe": "CWE-476",
             "ranges": [{"lt": "3.32.0"}],
             "summary": "Virtual table can be renamed into itself (crash)"},
        ],
    },
    "curl": {
        "patterns": [r"libcurl/(\d+\.\d+\.\d+)", r"curl (\d+\.\d+\.\d+)"],
        "cves": [
            {"id": "CVE-2023-38545", "name": "SOCKS5 overflow", "cvss": 9.8,
             "severity": "critical", "cwe": "CWE-787",
             "ranges": [{"ge": "7.69.0", "lt": "8.4.0"}],
             "summary": "SOCKS5 proxy hostname heap buffer overflow"},
        ],
    },
    "expat": {
        "patterns": [r"expat_(\d+\.\d+\.\d+)", r"libexpat.*?(\d+\.\d+\.\d+)"],
        "cves": [
            {"id": "CVE-2022-25235", "cvss": 9.8, "severity": "critical", "cwe": "CWE-116",
             "ranges": [{"lt": "2.4.5"}],
             "summary": "Malformed UTF-8 / encoding handling enables injection"},
        ],
    },
    "dropbear": {
        "patterns": [r"[Dd]ropbear[ _](\d+\.\d+)"],
        "cves": [
            {"id": "CVE-2018-15599", "cvss": 5.3, "severity": "medium", "cwe": "CWE-200",
             "ranges": [{"lt": "2018.76"}],
             "summary": "recv_msg_userauth_request username enumeration"},
        ],
    },
    # Embedded / RTOS C stacks. BANNER patterns here let the binary scan recover the version from
    # a compiled image; their CVE ranges come from NVD CPE (data/clib_cvedb.json, built by
    # tools/build_cvedb.py --clibs) and from a source project's vendored header
    # (fingerprint/source_scan.py). Empty `cves` -- the loader merges the NVD set in.
    "freertos": {
        "patterns": [r"FreeRTOS(?: Kernel)? V(\d+\.\d+\.\d+)"],
        "cves": [],
    },
    "mbedtls": {
        "patterns": [r"[Mm]bed ?TLS (\d+\.\d+\.\d+)"],
        "cves": [],
    },
    "wolfssl": {
        "patterns": [r"wolfSSL(?:/| )(\d+\.\d+\.\d+)"],
        "cves": [],
    },
    "lwip": {
        "patterns": [r"lwIP (\d+\.\d+\.\d+)"],
        "cves": [],
    },
    # Common C libraries shipped in firmware / stripped binaries. BANNER patterns (low-FP,
    # anchored on the library's own version-string text); CVEs merged from clib_cvedb.json.
    "openssh": {"patterns": [r"OpenSSH_(\d+\.\d+)"], "cves": []},
    "nginx": {"patterns": [r"nginx/(\d+\.\d+\.\d+)"], "cves": []},
    "libssh": {"patterns": [r"libssh[-_ /](\d+\.\d+\.\d+)"], "cves": []},
    "lua": {"patterns": [r"Lua (\d+\.\d+\.\d+)"], "cves": []},
    "mosquitto": {"patterns": [r"mosquitto version (\d+\.\d+\.\d+)"], "cves": []},
    "nghttp2": {"patterns": [r"nghttp2/(\d+\.\d+\.\d+)"], "cves": []},
    "libtiff": {"patterns": [r"LIBTIFF, Version (\d+\.\d+\.\d+)"], "cves": []},
    "c-ares": {"patterns": [r"c-ares(?:/| version )(\d+\.\d+\.\d+)"], "cves": []},
    "u-boot": {"patterns": [r"U-Boot (\d+\.\d+)"], "cves": []},
    "ncurses": {"patterns": [r"ncurses (\d+\.\d+\.\d+)"], "cves": []},
    "pcre2": {"patterns": [r"PCRE2 (\d+\.\d+)"], "cves": []},
    "libxml2": {"patterns": [], "cves": []},          # detected from a vendored header (no banner)
    "freetype": {"patterns": [], "cves": []},
    "libwebp": {"patterns": [], "cves": []},          # detected from WEBP_DECODER_ABI_VERSION (no banner)
    "mongoose": {"patterns": [r"Mongoose/(\d+\.\d+)"], "cves": []},
}


# --------------------------------------------------------------- exploit-class hinting
# A matched CVE names a KNOWN bug but carries no reproducer for the specific target, so this is
# a HINT -- the exploit family its CWE implies -- not a claim that a weaponised PoC exists. It
# tells an analyst (and can seed an exploit strategy) what class of attack the flaw is, with the
# honest caveat that a trigger/reproducer in this target is still required. `strategy` lines up
# with exploit_stage's strategy names when one applies, else None (web/logic/DoS classes).
_EXPLOIT_CLASS = {
    "CWE-121": ("stack buffer overflow — overwrite the saved return address (ret2* family)", "rop"),
    "CWE-787": ("out-of-bounds write — corrupt control data (ret2* / overwrite)", "rop"),
    "CWE-120": ("classic buffer overflow — overwrite adjacent control data (ret2* family)", "rop"),
    "CWE-122": ("heap buffer overflow — corrupt heap metadata / adjacent object", "heap"),
    "CWE-416": ("use-after-free — reclaim the freed object (tcache/fastbin)", "heap"),
    "CWE-415": ("double free — tcache/fastbin poisoning to an arbitrary write", "heap"),
    "CWE-134": ("format string — %n write / memory leak via a tainted format", "format"),
    "CWE-190": ("integer overflow — a miscomputed size usually yields a heap/stack overflow", "rop"),
    "CWE-476": ("null-pointer dereference — denial of service (crash)", None),
    "CWE-78":  ("OS command injection — inject shell metacharacters into a command", None),
    "CWE-77":  ("command injection — inject into a constructed command", None),
    "CWE-89":  ("SQL injection — break out of the query", None),
    "CWE-22":  ("path traversal — escape the intended directory", None),
    "CWE-79":  ("cross-site scripting — inject script into rendered output", None),
    "CWE-400": ("uncontrolled resource consumption — denial of service", None),
    "CWE-770": ("allocation without limits — denial of service", None),
    "CWE-125": ("out-of-bounds read — information disclosure / crash", None),
    "CWE-200": ("information exposure — leak sensitive data", None),
}


def exploit_hint(cwe: str) -> "tuple[str, str | None] | None":
    """(human exploit-class description, exploit_stage strategy or None) for a CWE, or None when
    the CWE is not a class we map. The strategy is a SUGGESTION, gated on a real reproducer."""
    return _EXPLOIT_CLASS.get((cwe or "").strip().upper())


# ------------------------------------------------------------------ version comparison
def vkey(v: str):
    """Sortable key for versions like 1.2.11 / 1.0.2k / 2018.76: each dotted part -> (int, str)
    so numeric ordering dominates and a letter suffix (openssl) tie-breaks."""
    out = []
    for part in str(v).split("."):
        m = re.match(r"(\d*)([a-zA-Z]*)", part)
        num = int(m.group(1)) if m.group(1) else 0
        out.append((num, m.group(2)))
    return out


def vcmp(a: str, b: str) -> int:
    ka, kb = vkey(a), vkey(b)
    n = max(len(ka), len(kb))
    ka += [(0, "")] * (n - len(ka))
    kb += [(0, "")] * (n - len(kb))
    return -1 if ka < kb else (1 if ka > kb else 0)


def in_range(v: str, r: dict) -> bool:
    """All bounds in a range dict must hold (AND)."""
    ok = True
    if "eq" in r:
        ok = ok and vcmp(v, r["eq"]) == 0
    if "lt" in r:
        ok = ok and vcmp(v, r["lt"]) < 0
    if "le" in r:
        ok = ok and vcmp(v, r["le"]) <= 0
    if "gt" in r:
        ok = ok and vcmp(v, r["gt"]) > 0
    if "ge" in r:
        ok = ok and vcmp(v, r["ge"]) >= 0
    return ok


def affected(version: str, cve: dict) -> bool:
    """A CVE hits if the version falls in ANY of its ranges (OR)."""
    return any(in_range(version, r) for r in cve.get("ranges", []))
