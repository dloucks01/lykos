"""Source variant analysis via weggli (AST pattern matching for C/C++).

weggli (github.com/weggli-rs/weggli, Apache-2.0) is a fast tree-sitter AST matcher: a query looks
like a C/C++ snippet with metavariables (``$name``), wildcards (``_``) and regex, matched to the
AST of a source tree -- so it finds a *shape* of code regardless of formatting or variable names.
Its canonical use is turning a 1-day into 0-days: start from a near-exact copy of a known-vulnerable
pattern, then generalize until every variant surfaces (Project Zero's workflow; ~half of in-the-wild
0-days are variants of a prior bug).

This is the SOURCE-side complement to lykos's binary ``variant-scan``: run a curated pack of
vulnerable-pattern queries over an ingested source tree, map each hit to a CWE, and support the
"generalize-from-a-patch" workflow (build a query from a known-bad snippet, then loosen it). Once
single static weggli binary is vendored it is fully offline and non-AI; lykos degrades gracefully
(declines with an install hint) when weggli is absent, exactly like the other optional engines.

weggli emits no machine-readable format and prints each match as the file path followed by the
matching function snippet, so the result parser is deliberately format-tolerant: it recovers the set
the matched FILES by path existence under the scan root (robust to color / context settings) and
keeps each match's snippet for the analyst, rather than depending on an exact textual layout.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------- query pack

# Curated vulnerable-pattern queries. Each: (name, cwe, severity, cpp_only, query, why). The queries
# are intentionally HIGH-SIGNAL shapes (a dangerous sink, or a sink on a fixed-size stack buffer);
# the analyst generalizes from a specific patched bug with `variant_query` for wider hunts.
QUERY_PACK = [
    ("unbounded_strcpy", "CWE-120", "high", False,
     "{ strcpy(_, _); }",
     "strcpy has no bound; if the source is attacker-influenced this overflows the destination"),
    ("unbounded_strcat", "CWE-120", "high", False,
     "{ strcat(_, _); }",
     "strcat appends without a bound on the destination's remaining space"),
    ("sprintf_no_bound", "CWE-120", "high", False,
     "{ sprintf(_, _); }",
     "sprintf writes an unbounded amount into a fixed buffer; snprintf is the bounded form"),
    ("gets_call", "CWE-242", "critical", False,
     "{ gets(_); }",
     "gets() cannot be used safely -- there is no way to bound its read"),
    ("scanf_percent_s", "CWE-120", "high", False,
     "{ scanf(_, _); }",
     "an unbounded %s in scanf/sscanf overflows its destination"),
    ("stack_buf_memcpy", "CWE-787", "high", False,
     "_ $fn(_) { _ $buf[_]; memcpy($buf, _, _); }",
     "a memcpy into a fixed-size stack buffer whose length is not visibly the buffer's size"),
    ("stack_buf_index_write", "CWE-787", "medium", False,
     "_ $fn(_ $n) { _ $buf[_]; for (_; _ < $n; _) { $buf[_] = _; } }",
     "a loop writes into a fixed stack buffer bounded by a parameter, not by the buffer size"),
    ("printf_variable_fmt", "CWE-134", "high", False,
     "{ printf($fmt); }",
     "printf whose format string is a variable is a format-string bug if that variable is tainted"),
    ("fprintf_variable_fmt", "CWE-134", "high", False,
     "{ fprintf(_, $fmt); }",
     "fprintf with a variable format string -- format-string write/leak if the format is tainted"),
    ("system_variable_arg", "CWE-78", "high", False,
     "{ system($cmd); }",
     "system() with a non-literal argument is command injection if the argument is attacker-built"),
    ("popen_variable_arg", "CWE-78", "high", False,
     "{ popen($cmd, _); }",
     "popen() with a non-literal command is command injection when the command is tainted"),
    ("malloc_mul_size", "CWE-190", "medium", False,
     "{ $p = malloc(_ * _); }",
     "a multiplication in malloc can integer-overflow to a small allocation, then be overflowed"),
    ("use_after_free", "CWE-416", "high", False,
     "{ free($p); _($p); }",
     "$p is used after being freed -- a use-after-free (confirm the use dereferences it)"),
    ("memcpy_after_free", "CWE-416", "high", False,
     "{ free($p); memcpy($p, _, _); }",
     "a memcpy through a pointer after it was freed"),
]


def query_pack(*, include_cpp: bool = True) -> list:
    """The built-in query pack as dicts. ``include_cpp`` keeps C++-only queries (there are none by
    default, but analyst packs may add them)."""
    return [{"name": n, "cwe": c, "severity": s, "cpp_only": cpp, "query": q, "why": w}
            for (n, c, s, cpp, q, w) in QUERY_PACK if include_cpp or not cpp]


# ---------------------------------------------------------------- tool + runner

def weggli_bin() -> Optional[str]:
    """Locate the weggli binary: LYKOS_WEGGLI, then PATH."""
    return os.environ.get("LYKOS_WEGGLI") or shutil.which("weggli")


def _matched_files(output: str, root: Path) -> list:
    """Recover the set of files a weggli run matched, format-tolerantly.

    weggli prints the (relative) path of each matching file as a header before its snippet. Rather
    than depend on the exact layout (color codes, context lines), we take every token in the output
    that resolves to an existing file under ``root`` -- weggli only ever prints real paths of the
    files it searched, so this is robust. Returns paths in first-seen order.
    """
    seen = []
    seen_set = set()
    # strip ANSI color so a path is not split by escape codes
    plain = re.sub(r"\x1b\[[0-9;]*m", "", output)
    for tok in re.split(r"[\s:]+", plain):
        if not tok or tok in seen_set:
            continue
        # weggli prints paths relative to cwd; try as-is and under root
        for cand in (Path(tok), root / tok):
            try:
                if cand.is_file():
                    rp = str(cand.resolve())
                    if rp not in seen_set:
                        seen.append(rp)
                        seen_set.add(rp)
                    break
            except OSError:
                pass
    return seen


def run_query(query: str, path, *, cpp: bool = False, timeout: float = 120.0,
              context: int = 0, unique: bool = True) -> dict:
    """Run one weggli query over ``path``. Returns ``{ok, files, count, raw, error}``.

    ``ok`` is False (with ``error``) when weggli is absent or the run failed. ``files`` is the list
    of source files that matched; ``count`` is the number of matched files; ``raw`` is a bounded
    prefix of weggli's output (for the analyst / snippet context).
    """
    wb = weggli_bin()
    if wb is None:
        return {"ok": False, "files": [], "count": 0, "raw": "", "error": "weggli not found"}
    root = Path(path)
    cmd = [wb, "-A", str(context), "-B", str(context)]
    if cpp:
        cmd.append("--cpp")
    if unique:
        cmd.append("--unique")
    cmd += [query, str(root)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "NO_COLOR": "1"})
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "files": [], "count": 0, "raw": "", "error": str(e)}
    out = r.stdout or ""
    files = _matched_files(out, root)
    return {"ok": True, "files": files, "count": len(files), "raw": out[:4000], "error": None}


def scan(path, *, queries=None, cpp: bool = False, timeout: float = 120.0) -> dict:
    """Run the query pack (or ``queries``) over a source tree. Returns ``{supported, findings}``.

    Each finding: ``{name, cwe, severity, query, why, files, count}``. ``supported`` is False with a
    note when weggli is absent, so the caller reports an honest decline rather than "no bugs".
    """
    if weggli_bin() is None:
        return {"supported": False, "findings": [],
                "note": "weggli not found; install it (cargo install weggli) or set LYKOS_WEGGLI"}
    pack = queries if queries is not None else query_pack(include_cpp=cpp)
    findings = []
    for q in pack:
        if q.get("cpp_only") and not cpp:
            continue
        res = run_query(q["query"], path, cpp=cpp, timeout=timeout)
        if res["ok"] and res["count"] > 0:
            findings.append({"name": q["name"], "cwe": q["cwe"], "severity": q["severity"],
                             "query": q["query"], "why": q["why"],
                             "files": res["files"], "count": res["count"]})
    # rank: severity then breadth
    _sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (_sev.get(f["severity"], 9), -f["count"]))
    return {"supported": True, "findings": findings,
            "queries_run": len(pack), "note": None}


# ---------------------------------------------------------------- variant workflow

_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def variant_query(snippet: str, *, level: int = 1) -> str:
    """Build a weggli query from a known-vulnerable code SNIPPET, generalized to ``level``.

    The 1-day -> 0-day workflow: level 0 is (almost) the literal snippet; each higher level replaces
    more concrete identifiers with metavariables/wildcards so more variants match:
      * level 0: the snippet as-is, wrapped as a statement pattern.
      * level 1: replace local identifiers with ``$v0..$vn`` metavariables (name-independent match).
      * level 2: also replace numeric literals with ``_`` (size-independent).
    Returns a query string to hand to ``run_query`` / weggli.
    """
    q = snippet.strip().rstrip(";")
    if level <= 0:
        return "{ " + q + "; }"
    # map identifiers that are not obvious keywords/known functions to metavariables
    keywords = {"if", "for", "while", "return", "sizeof", "int", "char", "void", "unsigned",
                "long", "short", "struct", "const", "static", "else", "do", "switch"}
    sinks = {"strcpy", "strcat", "sprintf", "memcpy", "memmove", "malloc", "free", "printf",
             "fprintf", "system", "popen", "scanf", "sscanf", "gets", "read", "recv"}
    counter = {"n": 0}
    mapping = {}

    def repl(m):
        w = m.group(0)
        if w in keywords or w in sinks or w.isupper():
            return w
        if w not in mapping:
            mapping[w] = f"$v{counter['n']}"
            counter["n"] += 1
        return mapping[w]

    q = _ID.sub(repl, q)
    if level >= 2:
        q = re.sub(r"\b\d+\b", "_", q)
    return "{ " + q + "; }"
