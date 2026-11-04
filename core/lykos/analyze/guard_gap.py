"""Guard-gap detector -- an attacker-controlled stream length used as a size/seek/copy bound with NO
bounds guard on that value (CWE-125 over-read / CWE-787 over-write). This is the dominant real-bug
shape in stream-parsing protocol code (e.g. FreeRDP), and the mechanism that finds it is *precision
about the project's own guard idiom*: the existing length detectors over-fire because they do not
model the many ways the code DOES bound a value, so their output is a false-positive flood and the
genuine missing-guard bugs are buried.

Two ideas make this precise:

1. GUARD-WRAPPER DISCOVERY. A project wraps its bounds checks in helpers -- FreeRDP has
   `Stream_CheckAndLogRequiredLength`, `Stream_CheckAndLogRequiredLengthWLog`, and project-local
   wrappers like `license_check_stream_length`, `tpkt_ensure_stream_consumed`. We discover them: any
   function that consults a primitive stream-length primitive and gates a `return FALSE/0` on it is a
   guard. A value mentioned by ANY guard call (primitive or discovered wrapper), or clamped by a
   plain `if (v > ...) return/goto/break` or a mask/min, is treated as guarded -- conservatively, to
   favour precision over recall.

2. VARIANT CROSS-CHECK. When a sibling handler in the same family guards the very field this one
   reads but does not (the classic copy-paste-variant bug), that is forgery-proof evidence the
   omission is a defect, not an intentional unbounded read. Such a finding is marked high-confidence.

Pure string/AST analysis (the body brace-matcher is shared with dispatcher_harness). No execution.
The stage wrapper lives in guard_gap_stage.py.
"""
from __future__ import annotations

import re
from .dispatcher_harness import _functions

#: stream-length primitives -- the irreducible checks a guard (or guard wrapper) is built on.
_PRIM = (r'Stream_CheckAndLogRequiredLength|Stream_CheckAndLogRequiredCapacity|'
         r'Stream_GetRemainingLength|Stream_GetRemainingCapacity|Stream_SafeSeek|'
         r'Stream_EnsureRemainingCapacity|Stream_EnsureCapacity')
_PRIM_RE = re.compile(_PRIM)

#: an attacker value coming off the wire: Stream_Read_UINTn(s, VAR) / Stream_Read_INTn(s, VAR).
_READ_RE = re.compile(r'Stream_Read_U?INT(?:8|16|32|64)\s*\(\s*\w+\s*,\s*([A-Za-z_][\w.>\[\]-]*)')

#: uses of a value as a size/seek/copy bound (the sink), with the CWE each implies.
_SINKS = (
    (re.compile(r'Stream_Seek\s*\(\s*\w+\s*,\s*([A-Za-z_][\w.>\[\]-]*)\s*\)'), "seek", "CWE-125"),
    (re.compile(r'Stream_Read\s*\(\s*\w+\s*,[^,;]+,\s*([A-Za-z_][\w.>\[\]-]*)\s*\)'), "stream-read", "CWE-125"),
    (re.compile(r'\b(?:memcpy|memmove)\s*\([^;]*?,\s*([A-Za-z_][\w.>\[\]-]*)\s*\)'), "memcpy", "CWE-787"),
)

#: project-local guard wrappers that the discovery heuristic can miss (they gate via an inner call
#: or a macro). Seeded so a known-good wrapper is never mistaken for a gap.
_SEED_GUARDS = {"license_check_stream_length", "license_check_stream_capacity",
                "tpkt_ensure_stream_consumed"}


def _base(var: str) -> str:
    """The trailing identifier of a possibly-qualified lvalue: `pdu.bitmapDataLength` -> the token
    `bitmapDataLength`, `ticket->ServiceTicketLength` -> `ServiceTicketLength`."""
    return re.split(r'[.>\[\]-]+', var.strip())[-1] or var


def discover_guards(sources) -> set:
    """Guard-wrapper function names: a function that consults a stream-length primitive and gates a
    `return FALSE/0` on it. `sources` maps path -> text (only the texts are read)."""
    guards = set(_SEED_GUARDS)
    for text in sources.values():
        if "Stream_" not in text:
            continue
        for name, _static, _params, body in _functions(text):
            # a guard RETURNS BOOL on a failed check (FreeRDP convention); `return 0` is too common
            # as a success value to be a guard signal and would mislabel ordinary parsers.
            if _PRIM_RE.search(body) and re.search(r'return\s+(FALSE|false)\b', body):
                guards.add(name)
    return guards


def _guard_text(body: str, guard_re) -> str:
    """The whitespace-collapsed ARGUMENTS of every guard call in `body`. Collapsing first lets a
    guard call wrapped across physical lines still match the value it protects (the dominant false
    positive when matching line-by-line); extracting only up to the call's balanced close-paren
    keeps the following code -- including the very sink we are judging -- out of the guard text (the
    opposite failure: a fixed window swallows the sink and everything looks guarded)."""
    flat = re.sub(r'\s+', ' ', body)
    out = []
    for m in guard_re.finditer(flat):
        i = flat.find("(", m.end() - 1)
        if i < 0:
            continue
        depth, j, n = 0, i, len(flat)
        while j < n:
            if flat[j] == "(":
                depth += 1
            elif flat[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append(flat[i:j + 1])                          # just the guard's own arguments
    return " ".join(out)


def _clamped(body: str, base: str) -> bool:
    """A value is also 'guarded' if a plain branch clamps it: `if (v > N) return/goto/break`, a mask
    `v & ~3`, a `v = MIN(...)`, or a modulus/range reject. Conservative -- favours precision."""
    b = re.escape(base)
    pats = (rf'if\s*\([^)]*\b{b}\b[^)]*\)\s*\{{?\s*(return|goto|break)',
            rf'\b{b}\b\s*(&|%|>|<|>=|<=)',
            rf'\b{b}\b\s*=\s*(MIN|min|MAX|max)\b',
            rf'(MIN|min)\s*\([^;]*\b{b}\b')
    return any(re.search(p, body) for p in pats)


def find_guard_gaps(text: str, guards: set) -> list:
    """Every read-then-used-as-size value in `text` with no guard (wrapper, primitive, or branch
    clamp) on it. Returns finding dicts {fn, var, base, kind, cwe, line} -- line is 1-based within
    the file, at the sink use."""
    if "Stream_Read_" not in text:
        return []
    guard_re = re.compile(_PRIM + "|" + "|".join(re.escape(g) for g in guards)) if guards \
        else _PRIM_RE
    out = []
    search_from = 0
    for name, _static, _params, body in _functions(text):
        # body offset in the file, so a sink's line is THIS function's line, not a sibling's with an
        # identical call fragment. _functions yields in source order, so advance the search cursor.
        boff = text.find(body, search_from)
        if boff < 0:
            boff = text.find(body)
        search_from = boff + len(body) if boff >= 0 else search_from
        reads = {m.group(1) for m in _READ_RE.finditer(body)}
        if not reads:
            continue
        gtext = _guard_text(body, guard_re)
        guarded = set()
        for v in reads:
            base = _base(v)
            if re.search(r'\b' + re.escape(base) + r'\b', gtext) or _clamped(body, base):
                guarded.add(v)
        for sink_re, kind, cwe in _SINKS:
            for m in sink_re.finditer(body):
                v = m.group(1)
                if v in reads and v not in guarded:
                    ln = text.count("\n", 0, boff + m.start()) + 1 if boff >= 0 else 0
                    out.append({"fn": name, "var": v, "base": _base(v), "kind": kind,
                                "cwe": cwe, "line": ln})
    return out


def _family(fn: str) -> str:
    """The sibling-family key of a handler name: drop a trailing _<n>_ / version token so
    `rdpgfx_recv_wire_to_surface_1_pdu` and `..._2_pdu` share a family."""
    return re.sub(r'_(?:\d+|v\d+)(?=_|$)', '_N', fn)


def variant_confirmed(text: str, gap: dict, guards: set) -> bool:
    """True when a sibling function in the same family GUARDS the same field this gap reads unguarded
    -- forgery-proof evidence the omission is a defect (the copy-paste-variant bug)."""
    fam = _family(gap["fn"])
    base = gap["base"]
    guard_re = re.compile(_PRIM + "|" + "|".join(re.escape(g) for g in guards)) if guards else _PRIM_RE
    for name, _static, _params, body in _functions(text):
        if name == gap["fn"] or _family(name) != fam:
            continue
        gtext = _guard_text(body, guard_re)
        if re.search(r'\b' + re.escape(base) + r'\b', gtext):
            return True
    return False
