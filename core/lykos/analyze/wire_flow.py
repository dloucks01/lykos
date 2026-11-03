"""Wire-value → dangerous-use flow detector (depth add) — the pattern behind every confirmed bug.

All five confirmed FreeRDP 3.20.0 bugs share one shape: a value read off the wire (a Stream_Read_*)
reaches a DANGEROUS use with no bound check in between —
  * ClearCodec: wire dims → allocation size (integer overflow → OOB write)
  * planar:     (missing SrcSize check) → read past the source
  * rdpgfx:     wire length → Stream_Seek (reachable assert)
  * DSP:        wire nBlockAlign/nChannels → a DIVISOR (divide-by-zero)
The generic detectors miss these because they flag the sink shape OR the untrusted source, not the
FLOW with the absent guard. This detector keys on exactly that flow, intraprocedurally, so it finds
the same class across the whole tree at high precision:

  1. a wire-tainted var: `Stream_Read_U?INT*(s, var)` (and one assignment hop `v2 = <expr with var>`);
  2. a dangerous use of that var with NO intervening bound:
       divisor  `/ var` or `% var`                       -> CWE-369
       index    `arr[var]`                               -> CWE-129 (read/write OOB)
       seek     `Stream_Seek(s, var)`                    -> CWE-125/617
       size     `malloc|calloc|realloc|alloca(... var)`  -> CWE-789/190
       length   `memcpy|memmove|Stream_Read(..., var)`   -> CWE-120/787
  3. a BOUND between read and use suppresses it: `CheckAndLogRequiredLength(..., var)`, or a
     `if (var <op> ...) return|goto|break`, or a `var <op> const` guard, or a modulo/mask that bounds it.

Pure source analysis (deterministic, testable); recall-first within the function, precision-first on
the flow (requires both the wire read AND the unguarded dangerous use). Emits candidate findings for
the confirmation ladder, not confirmed bugs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .dispatcher_harness import _functions
from . import value_range

_READ = re.compile(r"\bStream_Read_U?INT(?:8|16|32|64)\s*\(\s*\w+\s*,\s*([A-Za-z_][\w.\->]*)")
_ASSIGN = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*([^;]+);")


@dataclass
class WireFlow:
    function: str
    var: str
    use: str                       # divisor | index | seek | size | length
    cwe: str
    line_hint: str


_USES = [
    ("divisor", "CWE-369", lambda v: re.compile(r"[/%]\s*" + re.escape(v) + r"\b")),
    ("seek",    "CWE-125", lambda v: re.compile(r"\bStream_Seek\s*\(\s*\w+\s*,\s*" + re.escape(v) + r"\b")),
    ("index",   "CWE-129", lambda v: re.compile(r"\[\s*" + re.escape(v) + r"\s*\]")),
    ("size",    "CWE-190", lambda v: re.compile(r"\b(?:malloc|realloc|alloca)\s*\([^;]*\b" + re.escape(v) + r"\b")),
    ("length",  "CWE-120", lambda v: re.compile(r"\b(?:memcpy|memmove)\s*\([^;]*,\s*" + re.escape(v) + r"\s*\)")),
]


def _bounded(body: str, var: str, use_pos: int) -> bool:
    """A bound on `var` appearing BEFORE the dangerous use at `use_pos` suppresses the flow."""
    base = var.split(".")[-1].split("->")[-1]
    pre = body[:use_pos]
    # the standard length guard, OR any custom helper whose name says it checks a length/bound and
    # names this var (e.g. license_check_stream_length(.., cbScope, ..)) -- parsers wrap their checks.
    if re.search(r"(?:CheckAndLogRequiredLength\\w*|_check_\w*length|check_stream_length|"
                 r"RequiredLength|_ensure_\w*|_validate_\w*)\s*\([^;]*\b" + re.escape(base) + r"\b", pre):
        return True
    # an explicit comparison guard on the var that returns/breaks/gotos (incl. `>= CONST`)
    if re.search(r"\b" + re.escape(base) + r"\s*(?:<|<=|>|>=|==|!=)\s*[\w()]+[^;{]*\)\s*\n?\s*\{?\s*"
                 r"(?:return|goto|break|continue|WLog)", pre):
        return True
    if re.search(r"if\s*\(\s*!?\s*" + re.escape(base) + r"\s*\)", pre):     # `if (!var) ...` null/zero guard
        return True
    # a bound of the form `if (var < ARRAYSIZE(...)|COUNT|<CONST>) <use>` (index guards)
    if re.search(r"\b" + re.escape(base) + r"\s*(?:<|<=)\s*(?:ARRAYSIZE|ARRAY_SIZE|[A-Z_]+_COUNT|[A-Z_]*MAX[A-Z_]*|\w*[Cc]ount|sizeof|\d+)", pre):
        return True
    # `var % N` / `var & MASK` immediately bounds an index use
    if re.search(r"\b" + re.escape(base) + r"\s*[%&]\s*\w+", body[:use_pos + 40]):
        return True
    # bounded by a modulo/mask on the same var right at the use (e.g. arr[idx % N])
    return False


def _strip_comments(s: str) -> str:
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)         # block comments
    s = re.sub(r"//[^\n]*", " ", s)                      # line comments
    s = re.sub(r'"(?:\\.|[^"\\])*"', '""', s)            # string literals (kill `/` in log fmts)
    s = re.sub(r"'(?:\\.|[^'\\])'", "''", s)             # char literals
    return s


def find_wire_flows(src: str) -> list:
    """Unguarded wire-value→dangerous-use flows in every function of `src`."""
    out = []
    for name, _s, _p, raw in _functions(src):
        body = _strip_comments(raw)
        # wire-tainted vars (direct reads) + one assignment hop
        tainted = {m.group(1) for m in _READ.finditer(body)}
        tbases = {v.split(".")[-1].split("->")[-1] for v in tainted}
        for m in _ASSIGN.finditer(body):
            lhs, rhs = m.group(1), m.group(2)
            if any(re.search(r"\b" + re.escape(b) + r"\b", rhs) for b in tbases):
                tainted.add(lhs)
        for var in sorted(tainted):
            base = var.split(".")[-1].split("->")[-1]
            for use, cwe, mk in _USES:
                mm = mk(base).search(body)
                if not mm:
                    continue
                # the dangerous use must come AFTER a read of the var (flow order)
                rd = None
                for r in list(_READ.finditer(body)):
                    if r.group(1).split(".")[-1].split("->")[-1] == base and r.start() < mm.start():
                        rd = r.start(); break
                if rd is None and var not in {m2.group(1) for m2 in _ASSIGN.finditer(body)}:
                    continue
                if _bounded(body, var, mm.start()):
                    continue
                if use == "divisor" and not value_range.can_be_zero(base, body):
                    continue                         # interval engine proves the divisor is non-zero
                ln = body[:mm.start()].count("\n")
                out.append(WireFlow(function=name, var=base, use=use, cwe=cwe,
                                    line_hint=body.splitlines()[ln].strip()[:90] if ln < len(body.splitlines()) else ""))
                break   # one finding per (var) — the first dangerous use
    return out
