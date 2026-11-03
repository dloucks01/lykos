"""Enumerate-then-target DoS harvest driver -- makes "every firing -> a PoC" true by construction.

A coverage fuzzer re-finds the shallowest reachable assert and never enumerates the rest (rdpgfx: 83
crashes, one site). This driver inverts that: it ENUMERATES the DoS sites statically
(`reachable_dos`), builds a cmdId-TARGETED trigger for each one (`protocol_grammar`) so the
dispatcher routes to that exact sub-parser with the trigger field driven oversized, replays each
through the harness, and CONFIRMS it through the same 0-FP DoS lane gate used everywhere else
(`directed_confirm._dos_class` / `_memory_fault`, with an empty-input negative control). The result
is one confirmed PoC per site, with a real denominator -- not whatever the fuzzer happened to hit.

Pure construction (site enumeration + trigger bytes) is deterministic and unit-testable; the only
impure part is `replay`, injected by the consuming stage (a closure over the built ASan harness), so
the whole flow is testable with a stub oracle and no build.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import protocol_grammar as pg
from .dispatcher_harness import _functions
from .reachable_dos import find_unguarded_seeks, DosSite
from .symbolic.directed_confirm import _dos_class, _memory_fault

#: `#define NAME <num>` or an enum entry `NAME = <num>` -- the wire-tag constants a dispatcher cases on.
_DEFINE = re.compile(r"#define\s+([A-Za-z_]\w*)\s+(0[xX][0-9A-Fa-f]+|\d+)")
_ENUMV = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*(0[xX][0-9A-Fa-f]+|\d+)")
_CASE_CALL = re.compile(r"\bcase\s+([A-Za-z_]\w*)\s*:(.*?)([a-z_]\w*_pdu|[a-z_]\w*_recv\w*)\s*\(", re.S)

#: the rdpgfx-style channel PDU header the dispatcher consumes before routing: cmdId(u16),
#: flags(u16), pduLength(u32). Override `header_spec` for a channel with a different envelope.
RDPGFX_HEADER = [pg.Field("int", 2, name="cmdId"), pg.Field("int", 2, name="flags"),
                 pg.Field("int", 4, name="pduLength")]


def resolve_constants(*srcs: str) -> dict:
    """Map wire-tag constant names to their integer values, from `#define`s and enum entries across
    the given sources (header + channel .c)."""
    out: dict = {}
    for src in srcs:
        for m in _DEFINE.finditer(src):
            out[m.group(1)] = int(m.group(2), 0)
        for m in _ENUMV.finditer(src):
            out.setdefault(m.group(1), int(m.group(2), 0))
    return out


def case_subparser_map(dispatcher_body: str) -> dict:
    """{sub-parser name -> the `case` constant that routes to it}, mined from the dispatcher's own
    `switch`. This is how a site (a sub-parser) is turned into the wire tag that reaches it."""
    out = {}
    for m in _CASE_CALL.finditer(dispatcher_body):
        const, callee = m.group(1), m.group(3)
        out.setdefault(callee, const)
    return out


@dataclass
class DosFinding:
    function: str
    cwe: str
    trigger_field: str
    cmdid: "int | None"
    trigger: bytes
    confirmed: bool
    report: str = ""


def build_dos_trigger(subparser_body: str, trigger_field: str, cmdid: "int | None", *,
                      header_spec: list = RDPGFX_HEADER, cmdid_field: str = "cmdId",
                      pdulen_field: str = "pduLength", oversize: int = 0xFFFFFFFF) -> bytes:
    """A message that routes to `subparser_body`'s sub-parser (via `cmdid`) and drives `trigger_field`
    oversized so a wire-controlled `Stream_Seek` over-runs -> the reachable assert fires. The body is
    the sub-parser's own fields (grammar-exact so the reads before the seek succeed) with the trigger
    field set to `oversize`; the header's length field is set to the actual body length so the
    dispatcher routes into the sub-parser rather than bailing on its envelope check."""
    fields = pg.extract_fields(subparser_body)
    body = pg.generate(fields, overrides={trigger_field: oversize}, blob_len=0)
    hdr_over = {pdulen_field: len(body)}
    if cmdid is not None:
        hdr_over[cmdid_field] = cmdid
    header = pg.generate(header_spec, overrides=hdr_over)
    return header + body


def harvest_dos(dispatcher_src: str, constants: dict, replay, *,
                header_spec: list = RDPGFX_HEADER, negative_control: bytes = b"",
                oversize: int = 0xFFFFFFFF) -> list:
    """Enumerate every unguarded-wire-seek DoS site in `dispatcher_src`, build a targeted trigger for
    each, replay it through `replay` (a `bytes -> report str` oracle over the built harness), and
    confirm it as a DoS. `constants` maps cmdId names to values (`resolve_constants`). A site is
    confirmed only when its trigger faults as a DoS AND the negative control does NOT also fault (the
    0-FP gate). Memory-safety faults are reported as such (the stronger finding), not as DoS."""
    sites = find_unguarded_seeks(dispatcher_src)
    if not sites:
        return []
    bodies = {name: body for name, _s, _p, body in _functions(dispatcher_src)}
    casemap = {}
    for _n, _s, _p, body in _functions(dispatcher_src):
        casemap.update(case_subparser_map(body))

    neg_report = replay(negative_control) if negative_control is not None else ""
    neg_faults = bool(_dos_class(neg_report) or _memory_fault(neg_report, None))

    out = []
    for site in sites:
        body = bodies.get(site.function, "")
        const = casemap.get(site.function)
        cmdid = constants.get(const) if const else None
        trig = build_dos_trigger(body, site.trigger_field, cmdid,
                                 header_spec=header_spec, oversize=oversize)
        report = replay(trig)
        mem = _memory_fault(report, None)
        cwe = "memory-safety" if mem else _dos_class(report)
        confirmed = bool(cwe) and not neg_faults
        out.append(DosFinding(function=site.function, cwe=(cwe or "none"),
                              trigger_field=site.trigger_field, cmdid=cmdid,
                              trigger=trig, confirmed=confirmed, report=report))
    return out
