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


def traversal_payloads():
    return [b"../../../../../../../../etc/passwd", b"..%2f..%2f..%2f..%2fetc/passwd",
            b"....//....//....//....//etc/passwd", b"/etc/passwd"]


def traversal_confirm(out: bytes, payload: bytes, marker: str) -> bool:
    return re.search(rb"root:.?:0:0:", out) is not None or b"root:x:0:" in out


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
}
