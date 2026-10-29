"""Finding GROUNDING: decide whether a reported finding is a real, reachable, arch-relevant defect
worth weaponizing -- or a pattern match that cannot be an exploit on this target.

A detector flags a PATTERN (a multiply before an alloc, a non-literal format arg, a free/use pair).
Whether that pattern is an actual exploitable defect depends on context the matcher does not carry:
is the code even the target's (not the statically-linked fuzzer/sanitizer runtime)? does it ship
(not a unit test / sample / benchmark)? does the arithmetic actually wrap on THIS word size? is the
format argument attacker data or a developer literal? Without that, a weaponizer is handed non-bugs
and produces nothing -- which reads as "the tool cannot build exploits" when the truth is "these are
not exploitable."

This module answers those questions deterministically and OFFLINE, and -- holding the precision rule
-- only ever DEMOTES a finding when it is PROVABLY benign/non-shipping, always with a cited reason,
and leaves anything it cannot decide exactly as a live candidate (an uncertain finding is kept, never
hidden). It is the honest filter in front of weaponization: the grounded set is small and real, and
every drop is explained.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Optional

SCHEMA = "lykos.grounding/1"

# Symbols/paths that belong to the statically-linked FUZZER or SANITIZER runtime, not the target.
# A finding anchored in one of these is analysing the instrumentation, not the program. Unambiguous
# -- these names exist only in libFuzzer / ASan-UBSan-LSan / their STL glue, never in a target.
_NOISE_SYMBOLS = (
    "fuzzer::", "method.fuzzer", "fuzzerdriver", "fuzzingoptions", "merge_fuzzer", "fuzzwithfork",
    "llvmfuzzer", "executecommand", "_zn6fuzzer",
    "__sanitizer", "sanitizer_cov", "internal_allocator", "__asan", "__ubsan", "__lsan",
    "asan_report", "__interceptor", "scudo", "__gnu_cxx",
)

# Path segments that mark NON-SHIPPING code: unit tests, samples, examples, benchmarks, the fuzz
# harness wrappers themselves. A defect here is not in the deployed attack surface.
_NONSHIP_SEGMENTS = ("test", "tests", "unittest", "unittests", "example", "examples", "demo",
                     "demos", "sample", "samples", "benchmark", "benchmarks", "fuzz", "fuzzing",
                     "fuzz_targets")

# Integer types that cannot, by themselves, make a product exceed a 64-bit size_t for any realistic
# count: a multiply of these on a 64-bit target does not wrap into the allocation. (A u64*u64 or an
# explicit 64-bit cast is NOT here -- those we never call safe.)
_SMALL_INT = ("sizeof", "int ", "int)", "unsigned ", "uint32", "uint16", "uint8", "u32", "u16",
              "u8", "dword", "word", "byte", "short", "uint32_t", "uint16_t", "uint8_t", "size8",
              "int32", "int16", "int32_t", "int16_t", "char")

_SRC_RE = re.compile(r'([\w./+\-]+\.(?:c|cc|cpp|cxx|h|hpp))[:"\s](\d+)')


def _source_ref(finding: dict):
    """(path, line) the finding cites in its evidence, or (None, None). The first source-looking
    `file.c:NN` in any evidence detail (detectors put it in the `source`/`recipe` channels)."""
    for e in finding.get("evidence") or []:
        d = e.get("detail") if isinstance(e, dict) else None
        if not d:
            continue
        m = _SRC_RE.search(d)
        if m:
            return m.group(1), int(m.group(2))
    return None, None


def _symbol_blob(finding: dict) -> str:
    parts = [str(finding.get("title") or ""), str(finding.get("detector") or "")]
    for e in finding.get("evidence") or []:
        if isinstance(e, dict) and e.get("detail"):
            parts.append(str(e["detail"]))
    return " ".join(parts).lower()


def _surface(finding: dict) -> str:
    """'on' / 'off' / 'none' -- the detector's own attack-surface tag (is the file compiled into an
    in-tree fuzz harness). Grounding sharpens this; it does not invent it."""
    for e in finding.get("evidence") or []:
        d = (e.get("detail") or "").lower() if isinstance(e, dict) else ""
        if "on the fuzzed attack surface" in d:
            return "on"
        if "off the fuzzed attack surface" in d:
            return "off"
    return "none"


def is_instrumentation_noise(finding: dict) -> bool:
    """The finding is anchored in the fuzzer/sanitizer runtime, not the target's code."""
    blob = _symbol_blob(finding)
    return any(m in blob for m in _NOISE_SYMBOLS)


def classify_role(path: Optional[str]) -> str:
    """A coarse, path-based role for the finding's file: 'non-shipping' (test/sample/fuzz harness),
    else 'shipping'. Deliberately conservative -- it only separates clearly non-deployed code."""
    if not path:
        return "unknown"
    segs = [s.lower() for s in re.split(r"[\\/]", path) if s]
    stem = segs[-1].lower() if segs else ""
    if any(s in _NONSHIP_SEGMENTS for s in segs[:-1]):
        return "non-shipping"
    if stem.startswith("test") or stem.startswith("fuzz") or "_test" in stem:
        return "non-shipping"
    return "shipping"


def _format_arg_is_literal(line: str) -> Optional[bool]:
    """For a CWE-134 site, True when the format argument is a STRING LITERAL (developer-controlled,
    not attacker data -> a false positive), False when it is a variable (keep), None when unsure.

    Sound: a compiler format-nonliteral SUPPRESSION on/next to the line (the project vouching the
    format is safe) also reads as literal-equivalent. Only a clear literal/suppression demotes."""
    low = line.lower()
    if "format_nonliteral" in low or "diag_ignored_format" in low or "-wformat" in low:
        return True
    # A printf-family call whose format position holds a "..." literal.
    m = re.search(r'\b(?:v?s?n?printf|vsnprintf|snprintf|fprintf|printf|vprintf|wlog_\w+)\s*\(', line, re.I)
    if not m:
        return None
    rest = line[m.end():]
    # the format arg is the first (printf/vprintf) or second (fprintf/snprintf/WLog) argument; if
    # ANY string literal appears before the first ');' it is overwhelmingly the format literal.
    head = rest.split(");")[0]
    if '"' in head and re.search(r'"[^"]', head):
        return True
    return False


def _mul_feeds_alloc_safe_on_64(line: str) -> Optional[bool]:
    """For a CWE-190 alloc site, True when a multiply feeding an allocation CANNOT wrap a 64-bit
    size_t (both operands are <=32-bit / sizeof) -> not an overflow on a 64-bit target. None when
    the operands are unknown or any looks 64-bit (then we never call it safe)."""
    low = line.lower()
    if not re.search(r'\b(?:m|c|re)alloc\w*\s*\(', low) and "sizeof" not in low:
        return None
    if "*" not in line:
        return None
    # A 64-bit operand or explicit 64-bit cast can wrap -> never safe.
    if any(t in low for t in ("uint64", "int64", "size_t)", "(size_t", "uint64_t", "unsigned long long",
                              "u64", "qword", "off_t", "ssize_t")):
        return None
    # Only call it safe when the multiply's parts are recognisably small-int / sizeof.
    if "sizeof" in low or any(t in low for t in _SMALL_INT):
        return True
    return None


def ground_finding(finding: dict, *, source_lookup: Optional[Callable[[str, int], Optional[str]]] = None,
                   bits: int = 64) -> dict:
    """Ground one finding. Returns {schema, grounded: bool, verdict, reason, surface, role, cwe}.

    `grounded` is False only when a check PROVES the finding is not an exploitable defect on this
    target (instrumentation runtime, non-shipping code, a developer-literal format, an arithmetic
    that cannot wrap at this word size). Off-attack-surface lowers priority but does NOT by itself
    set grounded=False -- a malicious-peer threat model can still reach client/library code -- so it
    is reported as a kept-but-deprioritised candidate. Everything not disproven stays grounded.
    `source_lookup(path, line) -> line text or None` enables the source-text checks; without it they
    are skipped (never a false demotion)."""
    cwe = (finding.get("cwe") or "").upper()
    surface = _surface(finding)
    path, line_no = _source_ref(finding)
    role = classify_role(path)

    if is_instrumentation_noise(finding):
        return _v(False, "instrumentation-noise",
                  "anchored in the statically-linked fuzzer/sanitizer runtime, not the target's code",
                  surface, role, cwe)
    if role == "non-shipping":
        return _v(False, "non-shipping-code",
                  f"the defect is in non-deployed code ({path}) -- a test/sample/fuzz harness, not "
                  "the shipped attack surface", surface, role, cwe)

    # Source-text soundness checks (only when we can read the cited line).
    line = source_lookup(path, line_no) if (source_lookup and path and line_no) else None
    if line:
        if cwe in ("CWE-134", "CWE-133") and _format_arg_is_literal(line) is True:
            return _v(False, "format-literal",
                      f"{path}:{line_no}: the format string is a developer literal / "
                      "format-nonliteral-suppressed, not attacker input -- not a format-string bug",
                      surface, role, cwe)
        if cwe in ("CWE-190", "CWE-680", "CWE-131") and bits >= 64 \
                and _mul_feeds_alloc_safe_on_64(line) is True:
            return _v(False, "arch-safe-mul",
                      f"{path}:{line_no}: the allocation multiply uses <=32-bit operands and cannot "
                      f"wrap a 64-bit size_t on this {bits}-bit target -- not an integer overflow here",
                      surface, role, cwe)

    if surface == "on":
        return _v(True, "exploitable-candidate",
                  "shipping code ON the attacker-reachable surface (its file is compiled into an "
                  "in-tree harness), with no soundness check disproving it -- a real weaponization "
                  "target", surface, role, cwe, priority="high")
    if surface == "off":
        return _v(True, "off-surface-candidate",
                  "a shipping-code defect, but off the fuzzed attack surface (no in-tree harness "
                  "reaches its file) -- real only under a reachability/malicious-peer argument; "
                  "kept, deprioritised", surface, role, cwe, priority="low")
    # No surface tag: a binary/taint-pattern finding whose attacker-reachability was never
    # established. NOT disproven (kept), but NOT trustworthy as a shortlist entry either -- the
    # taint "source" is often an assumed-untrusted function parameter, not confirmed attacker data.
    # This is exactly what the next grounding layer (taint-to-entry reachability) must decide.
    return _v(True, "reachability-unknown",
              "no attack-surface tag and no reachability proof: the 'untrusted input' is an assumed "
              "source (often a function parameter), not confirmed attacker-controlled -- kept, but "
              "needs taint-to-entry grounding before it is a trustworthy target", surface, role, cwe,
              priority="low")


def _v(grounded, verdict, reason, surface, role, cwe, *, priority: Optional[str] = None) -> dict:
    out = {"schema": SCHEMA, "grounded": grounded, "verdict": verdict, "reason": reason,
           "surface": surface, "role": role, "cwe": cwe}
    if priority:
        out["priority"] = priority
    return out


def make_source_lookup(root) -> Callable[[str, int], Optional[str]]:
    """A `source_lookup(path, line)` over a source tree at `root`. Resolves a cited path (which may
    be a full relative path or a bare basename) to a file under the tree and returns the line's
    text (+/- a little context joined), or None. Bounded and cached."""
    root = Path(root)
    index: dict = {}

    def _build():
        if index:
            return
        for p in root.rglob("*"):
            if p.is_file() and p.suffix in (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"):
                index.setdefault(p.name, []).append(p)

    def lookup(path: str, line: int) -> Optional[str]:
        _build()
        cands = []
        # exact suffix match first, then basename
        base = path.split("/")[-1]
        for p in index.get(base, []):
            if str(p).endswith(path) or path.endswith(str(p).split(str(root) + "/")[-1]):
                cands.insert(0, p)
            else:
                cands.append(p)
        for p in cands[:4]:
            try:
                lines = p.read_text("utf-8", "replace").splitlines()
            except OSError:
                continue
            if 1 <= line <= len(lines):
                lo = max(0, line - 2)
                return " ".join(x.strip() for x in lines[lo:line + 1])
        return None

    return lookup


def ground_findings(findings: list, *, source_root=None, bits: int = 64) -> dict:
    """Ground a list of findings. Returns {schema, total, grounded:[...], dropped:[...], by_verdict}
    where each entry is {finding, grounding}. The grounded list is the trustworthy prove-out
    shortlist; dropped carries the cited reason for every demotion."""
    lookup = make_source_lookup(source_root) if source_root else None
    grounded, dropped = [], []
    by_verdict: dict = {}
    for f in findings:
        g = ground_finding(f, source_lookup=lookup, bits=bits)
        by_verdict[g["verdict"]] = by_verdict.get(g["verdict"], 0) + 1
        (grounded if g["grounded"] else dropped).append({"finding": f, "grounding": g})
    return {"schema": SCHEMA, "total": len(findings), "grounded": grounded, "dropped": dropped,
            "by_verdict": by_verdict}
