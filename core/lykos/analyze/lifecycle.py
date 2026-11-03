"""Type-state lifecycle analysis (static gap 3) — use-after-free / double-free (CWE-416/415).

The confirmed-bug hunt could not harness UAF single-shot (it needs an alloc->free->use sequence).
A static type-state walk finds them directly: track each pointer's state (freed after free(p) /
*_free(p)), and flag a USE (deref p->x / *p / p[i] / passing p to a call) or a SECOND free while the
pointer is in the freed state, with no intervening reassignment (p = ... / p = NULL) that revives it.

Intraprocedural and conservative: a reassignment, a `p = NULL`, or leaving the function clears the
state, so a freed-then-reassigned pointer is not reported. Pure/testable; recall-first (a genuine
UAF is not hidden), precision comes from the reassignment/NULL kills.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .dispatcher_harness import _functions
from .wire_flow import _strip_comments

_FREE = re.compile(r"\b(?:free|_aligned_free|winpr_aligned_free|\w+_free|\w+_Free|Stream_Free|"
                   r"freerdp_\w*_free)\s*\(\s*&?\s*([A-Za-z_][\w.\->]*)\s*[,)]")
_ASSIGN = re.compile(r"\b([A-Za-z_][\w.\->]*)\s*=\s*")


@dataclass
class LifecycleBug:
    function: str
    ptr: str
    kind: str                      # "use-after-free" | "double-free"
    free_line: int
    bad_line: int
    hint: str


def _uses(ptr: str, line: str) -> bool:
    p = re.escape(ptr)
    # p->field, p.field, *p, p[i], or passing p as an argument to some call fn(..., p, ...)
    if re.search(p + r"\s*(?:->|\[)", line):
        return True
    if re.search(r"\*\s*" + p + r"\b", line):
        return True
    if re.search(r"\b[a-z_]\w*\s*\([^;]*\b" + p + r"\b", line) and not _FREE.search(line):
        return True
    return False


def find_lifecycle_bugs(src: str) -> list:
    out = []
    for name, _s, _p, raw in _functions(src):
        body = _strip_comments(raw)
        lines = body.splitlines()
        freed: dict = {}                                 # ptr base -> line index of the free
        for i, line in enumerate(lines):
            # a reassignment (incl. `p = NULL`) revives the pointer -> clear freed state.
            for am in _ASSIGN.finditer(line):
                b = am.group(1).split(".")[-1].split("->")[-1]
                if b in freed and not _FREE.search(line):
                    del freed[b]
            # a use or second-free of a freed pointer
            for fm in _FREE.finditer(line):
                base = fm.group(1).split(".")[-1].split("->")[-1]
                if base in freed:
                    out.append(LifecycleBug(name, base, "double-free", freed[base], i, line.strip()[:80]))
                freed[base] = i
            for base in list(freed):
                if freed[base] != i and _uses(base, line):
                    out.append(LifecycleBug(name, base, "use-after-free", freed[base], i, line.strip()[:80]))
                    del freed[base]                      # report once
    return out
