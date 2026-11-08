"""Statically enumerate reachable-DoS sites -- the harvest DENOMINATOR a fuzzer cannot give.

A coverage-guided fuzzer re-finds the SHALLOWEST reachable assert over and over (on FreeRDP's
rdpgfx it produced 83 crashes that all collapsed to one site), so it cannot answer "have we found
every DoS firing site of this class?" -- it only ever shows the easiest one. This module answers it
directly from the source: it enumerates the sites of a precise, mechanically-checkable DoS class so
the consuming stage can drive a targeted trigger to EACH one, instead of hoping the fuzzer stumbles
into them. The result is a real count (1/1, 3/5, ...), not a guess.

Class modelled here (the exact FreeRDP `rdpgfx_recv_wire_to_surface_2_pdu` defect): a
`Stream_Seek(s, VAR)` whose VAR was read off the wire, with NO `Stream_CheckAndLogRequiredLength`
(or ...OfSize) on that same VAR between the read and the seek. The seek then asserts inside WinPR
when VAR exceeds the remaining capacity -> a reachable `WINPR_ASSERT` -> CWE-617 process abort.
Guarded siblings (`wire_to_surface_1`, `reset_graphics`) check the variable before seeking and are
correctly NOT reported -- the detector keys on the guard being on THE SAME variable and BEFORE the
seek, not merely present somewhere in the body.

Pure source analysis (no build, no execution): deterministic, air-gap-safe, unit-testable. It emits
the site, the trigger field, and enough to hand `protocol_grammar.generate` an override that drives
that field oversized. It is a reach/enumeration aid for the DoS lane (capability #1), not a spec.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .dispatcher_harness import _functions

#: `Stream_Read_U?INT<w>(s, var)` -- the wire read that fills a field.
_READ = re.compile(r"Stream_Read_U?INT(?:8|16|32|64)\s*\(\s*\w+\s*,\s*([A-Za-z_][\w.\->]*)")
#: `Stream_Seek(s, var)` with a NON-constant amount (a bare constant seek is always bounded by the
#: fixed-size guard, so it is not this class).
_SEEKV = re.compile(r"Stream_Seek\s*\(\s*\w+\s*,\s*([A-Za-z_][\w.\->]*)\s*\)")
#: `Stream_CheckAndLogRequiredLength[OfSize](TAG, s, var ...)` -- the guard, keyed on its variable.
_GUARDV = re.compile(r"CheckAndLogRequiredLength(?:OfSize)?\s*\(\s*\w+\s*,\s*\w+\s*,\s*([A-Za-z_][\w.\->]*)")


@dataclass
class DosSite:
    """One statically-reachable DoS firing site."""
    function: str                  # the enclosing parser
    trigger_field: str             # the wire field to drive oversized (the seek amount)
    cwe: str = "CWE-617"           # reachable assertion -> abort
    mechanism: str = "unguarded-wire-seek"


def find_unguarded_seeks(src: str) -> list:
    """Every function in `src` that does a `Stream_Seek(s, VAR)` where VAR was read off the wire and
    is NOT covered by a `CheckAndLogRequiredLength*(..., VAR)` appearing BEFORE the seek. Each is a
    reachable `WINPR_ASSERT` (CWE-617) a short/oversized message trips -- the harvest denominator for
    this class."""
    sites = []
    for name, _is_static, _params, body in _functions(src):
        reads = [(m.group(1), m.start()) for m in _READ.finditer(body)]
        guards = [(m.group(1), m.start()) for m in _GUARDV.finditer(body)]
        for sm in _SEEKV.finditer(body):
            var, pos = sm.group(1), sm.start()
            read_before = any(v == var and p < pos for v, p in reads)
            if not read_before:
                continue                                 # seek amount isn't wire-controlled
            guarded_before = any(v == var and p < pos for v, p in guards)
            if guarded_before:
                continue                                 # properly bounded (the safe siblings)
            sites.append(DosSite(function=name, trigger_field=var))
    return sites
