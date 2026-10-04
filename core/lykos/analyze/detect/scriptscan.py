"""Vulnerability detection for interpreted-script SOURCE (PHP / Python / JavaScript-Node / Ruby).

These substrates have no machine code, so the native taint/bounds channels do not apply; detection
is pattern-based over the source text, the same shape as the Go/Rust `lang_sinks` detector. A
dangerous SINK (command exec, code eval, SQL query, file open, deserialize) is a *candidate* on its
own; it is promoted to *corroborated* when an untrusted SOURCE (a request/superglobal/argv/stdin
value) reaches it -- either directly in the sink's statement, or through a variable that was
assigned from a source earlier (one-hop taint). Pure stdlib, line/statement oriented: best-effort,
never an error. Confirmed exploitation of scripts (running the interpreter with a malicious input)
is a separate concern; this is the detection channel.
"""
from __future__ import annotations

import re

# A physical line longer than this is treated as minified (a whole module collapsed onto one line):
# line-scoped corroboration cannot hold on it, so it yields candidates only.
_MINIFIED_LINE = 2000

# interpreted language -> the regex that matches an untrusted-input SOURCE token.
_SOURCES = {
    "php": re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)\b|php://input|"
                      r"\bfile_get_contents\s*\(\s*['\"]php://input|\$argv\b|\bgetenv\s*\("),
    "python": re.compile(r"\binput\s*\(|\bsys\.argv\b|\bos\.environ\b|\.get_json\s*\(|"
                         r"\brequest\.(?:args|form|values|json|data|cookies|files|GET|POST|"
                         r"headers|get_json)\b|\bflask\.request\b|\.recv\s*\("),
    "javascript": re.compile(r"\breq(?:uest)?\.(?:query|body|params|cookies|headers)\b|"
                             r"\bprocess\.argv\b|\bprocess\.env\b|\blocation\.(?:hash|search|href)\b|"
                             r"\bdocument\.(?:URL|location|cookie)\b|\.on\s*\(\s*['\"]data['\"]"),
    "ruby": re.compile(r"\bparams\s*\[|\bARGV\b|\bgets\b|\bENV\s*\[|\brequest\.(?:params|body|GET|POST)\b"),
}

# interpreted language -> [(sink regex, cwe, title, severity)].
_SINKS = {
    "php": [
        (re.compile(r"\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\("),
         "CWE-78", "OS command injection", "critical"),
        (re.compile(r"\beval\s*\(|\bassert\s*\(|\bcreate_function\s*\(|"
                    r"preg_replace\s*\(\s*['\"][^'\"]*/e"), "CWE-95", "Code injection (eval)", "critical"),
        (re.compile(r"\b(?:mysqli?_query|pg_query|->\s*query|->\s*exec|sqlite_query)\s*\("),
         "CWE-89", "SQL injection", "critical"),
        (re.compile(r"\bunserialize\s*\("), "CWE-502", "Insecure deserialization", "high"),
        (re.compile(r"\b(?:include|include_once|require|require_once)\b\s*\(?"),
         "CWE-98", "Remote/local file inclusion", "high"),
        (re.compile(r"\b(?:fopen|file_get_contents|readfile|file|unlink|fwrite)\s*\("),
         "CWE-22", "Path traversal", "high"),
        (re.compile(r"\b(?:echo|print|printf)\b"), "CWE-79", "Reflected XSS", "medium"),
    ],
    "python": [
        (re.compile(r"\bos\.system\s*\(|\bos\.popen\s*\(|\bsubprocess\.(?:call|run|Popen|"
                    r"check_output|check_call)\s*\((?=[^)]*shell\s*=\s*True)|\bos\.exec[lv]\w*\s*\("),
         "CWE-78", "OS command injection", "critical"),
        (re.compile(r"(?<!\.)\beval\s*\(|(?<!\.)\bexec\s*\(|\b__import__\s*\("),
         "CWE-95", "Code injection (eval/exec)", "critical"),
        (re.compile(r"\bpickle\.loads?\s*\(|\byaml\.load\s*\((?![^)]*Safe)|\bmarshal\.loads?\s*\(|"
                    r"\bcPickle\.loads?\s*\("), "CWE-502", "Insecure deserialization", "high"),
        (re.compile(r"\.execute(?:many)?\s*\(\s*(?:f['\"]|['\"][^'\"]*%|['\"][^'\"]*\"\s*\+|"
                    r"[^,)]*%\s|[^,)]*\+)"), "CWE-89", "SQL injection", "critical"),
        (re.compile(r"\bopen\s*\(|\bos\.open\s*\(|\bos\.remove\s*\(|\bshutil\.(?:copy|move)\s*\("),
         "CWE-22", "Path traversal", "high"),
    ],
    "javascript": [
        # OS command injection. The receiver matters: `RegExp.prototype.exec` is by far the most
        # common `.exec(` in JavaScript, so a BARE `.exec(` is NOT taken as a shell call (that flags
        # every file that uses a regex -- e.g. all of jQuery). Fire on child_process's own calls,
        # the `require('child_process')` form, and the *Sync / execFile / spawn variants that RegExp
        # has no equivalent of. (A `cp.exec(x)` aliased off child_process is intentionally missed
        # rather than flag every regex `.exec` -- recall traded for a FP that destroyed trust.)
        (re.compile(r"\bchild_process\.(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(|"
                    r"\brequire\s*\(\s*['\"]child_process['\"]\s*\)\s*\.\s*"
                    r"(?:exec|execSync|execFile|spawn|spawnSync)\s*\(|"
                    r"\b(?:execSync|execFileSync|spawnSync)\s*\(|"
                    r"(?<![.\w$])(?:exec|execFile|spawn)\s*\("), "CWE-78", "OS command injection",
         "critical"),
        (re.compile(r"(?<!\.)\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.runIn\w*\s*\(|"
                    r"\bsetTimeout\s*\(\s*['\"]"), "CWE-95", "Code injection (eval)", "critical"),
        (re.compile(r"\.(?:query|execute)\s*\(\s*(?:`[^`]*\$\{|['\"][^'\"]*\"\s*\+|[^,)]*\+)"),
         "CWE-89", "SQL injection", "critical"),
        (re.compile(r"\bfs\.(?:readFile|readFileSync|writeFile|writeFileSync|unlink|createReadStream)\s*\("),
         "CWE-22", "Path traversal", "high"),
        (re.compile(r"\.innerHTML\s*=|\bdocument\.write\s*\(|\bres\.send\s*\("),
         "CWE-79", "Reflected/DOM XSS", "medium"),
    ],
    "ruby": [
        (re.compile(r"\bsystem\s*\(|`[^`]*#\{|\bexec\s*\(|\bIO\.popen\s*\(|%x\{|\bOpen3\."),
         "CWE-78", "OS command injection", "critical"),
        (re.compile(r"(?<!\.)\beval\s*\(|\binstance_eval\b|\bclass_eval\b|\bsend\s*\("),
         "CWE-95", "Code injection (eval)", "critical"),
        (re.compile(r"\.execute\s*\(|\bwhere\s*\(\s*['\"][^'\"]*#\{|\bfind_by_sql\s*\("),
         "CWE-89", "SQL injection", "high"),
        (re.compile(r"\b(?:Marshal\.load|YAML\.load\s*\((?![^)]*safe)|Oj\.load)\b"),
         "CWE-502", "Insecure deserialization", "high"),
        (re.compile(r"\b(?:File\.(?:open|read|new|write)|IO\.read|open)\s*\("),
         "CWE-22", "Path traversal", "high"),
    ],
}

_EXT_LANG = {
    ".php": "php", ".phtml": "php", ".php3": "php", ".php4": "php", ".php5": "php", ".phps": "php",
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
    ".rb": "ruby", ".rake": "ruby", ".erb": "ruby",
}
_SHEBANG_LANG = {"php": "php", "python": "python", "python2": "python", "python3": "python",
                 "node": "javascript", "nodejs": "javascript", "ruby": "ruby"}

# a bare assignment of a source to a variable, per language, so a later sink using that variable is
# corroborated (one-hop taint). Group 1 is the assigned variable name.
_ASSIGN = {
    "php": re.compile(r"(\$\w+)\s*=\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b"),
    "python": re.compile(r"(\w+)\s*=\s*[^#\n]*(?:\binput\s*\(|\bsys\.argv\b|\brequest\.(?:args|form|"
                         r"values|json|data|GET|POST)\b)"),
    "javascript": re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*[^;\n]*(?:req(?:uest)?\.(?:query|body|"
                             r"params)\b|process\.argv|location\.(?:hash|search))"),
    "ruby": re.compile(r"(\w+)\s*=\s*[^#\n]*(?:\bparams\s*\[|\bARGV\b|\bgets\b)"),
}


def language_for(filename: str, data: bytes) -> str | None:
    """The interpreted language of a script target, from its extension or shebang, or None."""
    from pathlib import Path
    ext = Path(filename or "").suffix.lower()
    if ext in _EXT_LANG:
        return _EXT_LANG[ext]
    if data[:2] == b"#!":
        line = data[:256].split(b"\n", 1)[0].decode("latin-1", "ignore")
        for tok in line[2:].replace("/", " ").split():
            base = re.sub(r"[0-9.]+$", "", tok)
            if base in _SHEBANG_LANG:
                return _SHEBANG_LANG[base]
    return None


def _tainted_vars(text: str, lang: str) -> set:
    rx = _ASSIGN.get(lang)
    return {m.group(1) for m in rx.finditer(text)} if rx else set()


def scan(data: bytes, lang: str) -> list[dict]:
    """Findings for a script source. Each is {cwe, title, severity, state, line, snippet, evidence}.
    `state` is 'corroborated' when an untrusted source reaches the sink (directly or via a tainted
    variable), else 'candidate'."""
    text = data.decode("utf-8", "replace")
    sinks = _SINKS.get(lang)
    if not sinks:
        return []
    src_rx = _SOURCES.get(lang)
    tainted = _tainted_vars(text, lang)
    # Match a tainted variable only as a whole token, never as a substring -- a 1-char var like `u`
    # must not match inside "exec*u*te". `$`-sigil (PHP) vars carry their own left boundary.
    taint_rx = (re.compile(r"(?<![\w$])(?:" + "|".join(re.escape(v) for v in tainted) + r")\b")
                if tainted else None)
    lines = text.splitlines()
    out, seen = [], set()
    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "*", "/*")):     # skip obvious comments
            continue
        # A MINIFIED line is a whole file collapsed onto one physical line; line-scoped corroboration
        # ("source and sink in the same statement") is meaningless there -- every source co-occurs
        # with every sink -- so such a line yields candidates only, never corroboration.
        minified = len(line) > _MINIFIED_LINE
        for rx, cwe, title, sev in sinks:
            if not rx.search(line):
                continue
            # Corroborate ONLY when the untrusted input is in the SINK'S OWN statement -- a source
            # elsewhere in the file must not promote a hardcoded `system("ls")`. Directly: a source
            # token on this line. Via a one-hop tainted variable used on this line.
            direct_src = bool(src_rx and src_rx.search(line)) and not minified
            via_var = bool(taint_rx and taint_rx.search(line)) and not minified
            state = "corroborated" if (direct_src or via_var) else "candidate"
            key = (cwe, i)
            if key in seen:
                continue
            seen.add(key)
            out.append({"cwe": cwe, "title": title, "severity": sev, "state": state,
                        "line": i, "snippet": stripped[:160],
                        "tainted": direct_src or via_var})
            break                                           # one finding per line (highest sink)
    return out
