"""Double-fetch / TOCTOU (CWE-367) and uninitialized-pointer-deref (CWE-824/457) detectors.

Two discovery classes lykos accounts for in the CWE catalog but did not yet detect. Both are static
and PRECISION-FIRST (the lifecycle detector's lesson: a recall-first pattern over a big tree drowns
the ledger). Each requires several corroborating signals before it fires.

Double-fetch: the SAME untrusted/shared source field is read TWICE in one function -- once feeding a
bounds/validation check, once feeding a dangerous use (copy length / index / allocation) -- so the
value can change between the check and the use (a classic kernel copy_from_user double-read, and the
userland shared-memory / mmap analogue). We require (1) the field read >= 2x, (2) one read inside an
`if(...)` condition, (3) another read in a size/index/copy context, (4) the base pointer reads as
untrusted (user/peer/shared/mmap/request/param) -- all four, or it does not fire.

Uninitialized pointer: a local pointer declared with NO initializer and dereferenced (`*p`, `p->`,
`p[`) before any assignment `p = ...` on the straight-line path -- stale/garbage memory read.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .dispatcher_harness import _functions
from .wire_flow import _strip_comments

#: a base pointer that reads as attacker/shared-controlled (so a re-fetch can change under us).
_UNTRUSTED_BASE = re.compile(r"(?:^|[^A-Za-z_])(user|usr|u|peer|remote|req|request|msg|packet|pkt|"
                             r"shared|shm|mmap|mapped|client|input|wire|hdr|header)(?:[^A-Za-z]|$)", re.I)
#: a dangerous USE context for the second fetch.
_USE_CTX = re.compile(r"(memcpy|memmove|memset|copy_from_user|copy_to_user|alloc|malloc|realloc|"
                      r"\[\s*$|,\s*$)", re.I)


@dataclass
class DoubleFetch:
    function: str
    field: str
    check_line: int
    use_line: int
    hint: str


def _field_reads(body: str):
    """Yield (field_expr, line_index) for each `base->field` / `base.field` read."""
    for m in re.finditer(r"\b([A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*)", body):
        yield m.group(1), body[:m.start()].count("\n")


def find_double_fetch(src: str) -> list:
    out = []
    for name, _s, _p, raw in _functions(src):
        body = _strip_comments(raw)
        lines = body.splitlines()
        # group reads of each field by line
        reads: dict = {}
        for fld, ln in _field_reads(body):
            reads.setdefault(fld, []).append(ln)
        for fld, lns in reads.items():
            if len(lns) < 2:
                continue
            base = fld.split("->")[0].split(".")[0]
            if not _UNTRUSTED_BASE.search(base) and not _UNTRUSTED_BASE.search(fld):
                continue
            check_ln = use_ln = None
            for ln in lns:
                line = lines[ln] if ln < len(lines) else ""
                if check_ln is None and re.search(r"\bif\s*\(", line) and fld in line:
                    check_ln = ln
                # a USE read on a DIFFERENT line than the check
                if _USE_CTX.search(line) and fld in line:
                    use_ln = ln
            if check_ln is not None and use_ln is not None and check_ln != use_ln:
                out.append(DoubleFetch(name, fld, check_ln, use_ln,
                                       (lines[use_ln].strip()[:80] if use_ln < len(lines) else "")))
    return out


@dataclass
class UninitPtr:
    function: str
    ptr: str
    decl_line: int
    use_line: int
    hint: str


_PTR_DECL = re.compile(r"^\s*(?:const\s+)?[A-Za-z_]\w*(?:\s+\w+)?\s*\*\s*([A-Za-z_]\w*)\s*;")


def find_uninit_ptr(src: str) -> list:
    """A local pointer declared with no initializer and dereferenced before any assignment."""
    out = []
    for name, _s, _p, raw in _functions(src):
        body = _strip_comments(raw)
        lines = body.splitlines()
        for i, line in enumerate(lines):
            m = _PTR_DECL.match(line)
            if not m:
                continue
            p = m.group(1)
            assigned = False
            for j in range(i + 1, len(lines)):
                lj = lines[j]
                # an assignment to p (p = ... , or &p passed to an initializer) clears it
                if re.search(r"\b" + re.escape(p) + r"\s*=(?!=)", lj) or \
                   re.search(r"&\s*" + re.escape(p) + r"\b", lj):
                    assigned = True
                    break
                # a dereference of p before any assignment -> uninitialized use
                if re.search(r"(?:\*\s*" + re.escape(p) + r"\b|\b" + re.escape(p) + r"\s*(?:->|\[))", lj):
                    out.append(UninitPtr(name, p, i, j, lj.strip()[:80]))
                    break
    return out
