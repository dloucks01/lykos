"""Interprocedural param-sink analysis (static-depth add) — the cross-function bug class.

The intraprocedural wire_flow detector cannot see a flow that crosses a call: a value read off the
wire in one function, stored in a struct, and used dangerously in a CALLEE. The confirmed DSP
divide-by-zero is exactly that — freerdp_dsp_context_reset divides by a term built from its
`targetFormat` PARAMETER's fields, with no self-check, and the audin/rdpsnd callers pass a wire-read
format. No single-function detector finds it.

This module finds the other half of such flows: a function that uses one of its PARAMETERS (or a
field of it) as a divisor / array index / Stream_Seek amount / allocation size / memcpy length
WITHOUT validating it in the function body. That is a "param sink": safe only if every caller
validates the argument first. Combined with the call graph (which callers pass a wire-derived
argument) and reachability, it surfaces the interprocedural wire->sink bugs. On its own it is a
contract finding ("this function trusts its caller to bound <param>"), ranked by attacker
reachability of the function.

Pure source analysis (deterministic, testable). Recognises the same guard forms wire_flow does, so a
parameter the function DOES validate is not reported.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .dispatcher_harness import _functions, _split_params
from .wire_flow import _strip_comments, _bounded, _USES
from . import value_range


#: divisor operand names that are never-zero container/crypto invariants (not attacker-zeroable),
#: so a modulo/division by them is not a real divide-by-zero. The confirmed DSP divisor
#: (data_per_block) is NOT in this set, so it is kept.
_INVARIANT_DIVISOR = re.compile(r"(capacity|numOfBuckets|keylength|blockSize|arraySize|"
                                r"->size\b|\.size\b|bucketCount|tableSize|nmemb)$", re.I)
#: guard-helper functions are not sinks themselves.
_GUARD_FN = re.compile(r"CheckAndLog|RequiredLength|RequiredCapacity|EnsureCapacity")


@dataclass
class ParamSink:
    function: str
    param: str                     # the parameter (or param->field) used dangerously
    use: str
    cwe: str
    line_hint: str


def _param_names(params: list) -> list:
    """The identifier of each parameter declaration (last word before any array/default)."""
    out = []
    for p in params:
        p = p.strip().rstrip(")")
        m = re.search(r"([A-Za-z_]\w*)\s*(?:\[\s*\d*\s*\])?$", p.replace("*", " "))
        if m and m.group(1) not in ("void", "const", "unsigned", "signed"):
            out.append(m.group(1))
    return out


def find_param_sinks(src: str) -> list:
    """Dangerous uses of an unvalidated parameter (or param->field / param.field) in each function."""
    out = []
    for name, _s, params, raw in _functions(src):
        if _GUARD_FN.search(name):
            continue                                     # a guard helper is not a sink
        body = _strip_comments(raw)
        pnames = _param_names(_split_params(params) if isinstance(params, str) else params)
        for p in pnames:
            # the parameter itself, its fields (p->field / p.field), AND locals computed from either
            # one assignment hop (e.g. `data_per_block = (fmt->nBlockAlign - 4*fmt->nChannels)*8;`
            # then `x / data_per_block` -- the confirmed DSP divide-by-zero shape).
            field_bases = set(re.findall(re.escape(p) + r"\s*(?:->|\.)\s*([A-Za-z_]\w*)", body))
            derived = set()
            for am in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*([^;]+);", body):
                lhs, rhs = am.group(1), am.group(2)
                if re.search(r"\b" + re.escape(p) + r"\b", rhs) or \
                   any(re.search(r"\b" + re.escape(fb) + r"\b", rhs) for fb in field_bases):
                    derived.add(lhs)
            operands = [p] + sorted(field_bases) + sorted(derived)
            for operand in operands:
                for use, cwe, mk in _USES:
                    mm = mk(operand).search(body)
                    if not mm:
                        continue
                    if _bounded(body, operand, mm.start()):
                        continue
                    if use == "divisor" and _INVARIANT_DIVISOR.search(operand):
                        continue                         # container/crypto invariant, never zero
                    if use == "divisor" and not value_range.can_be_zero(operand, body):
                        continue                         # interval engine proves non-zero
                    # ignore the operand being a mere pointer passed through (not arithmetic/index):
                    # the _USES regexes already require a divisor/index/seek/size/len context.
                    ln = body[:mm.start()].count("\n")
                    lines = body.splitlines()
                    hint = lines[ln].strip()[:90] if ln < len(lines) else ""
                    out.append(ParamSink(function=name, param=(p if operand == p else f"{p}->{operand}"),
                                         use=use, cwe=cwe, line_hint=hint))
                    break
    return out


# a caller fills a variable with attacker bytes via a stream read or a reader wrapper.
_WIRE_READER = re.compile(r"(?:Stream_Read_U?INT\d*|audio_format_read|\w+_read)\s*\(\s*\w+\s*,\s*&?\s*([A-Za-z_][\w.\->]*)")
_CALL_ARGS = re.compile(r"\b([a-z_]\w+)\s*\(([^;]*)\)")


def _param_index(params, pname: str) -> int:
    names = _param_names(_split_params(params) if isinstance(params, str) else params)
    return names.index(pname) if pname in names else -1


def confirmed_flows(files: dict) -> list:
    """Interprocedural wire→param-sink flows across a {relpath: source_text} map: a param-sink whose
    dangerous parameter is passed a WIRE-DERIVED argument by at least one caller. Filters the
    container-invariant param-sinks (a queue/hashtable passed an internal object, not wire data).
    Returns [(ParamSink, caller_fn, caller_file)]."""
    # index every function's param-sinks with the parameter position.
    sinks = {}                                           # fn_name -> [(ParamSink, idx)]
    func_cache = {}
    for rel, src in files.items():
        for name, _s, params, _b in _functions(src):
            func_cache.setdefault(name, (rel, params))
        for ps in find_param_sinks(src):
            idx = -1
            for n2, _s2, p2, _b2 in _functions(src):
                if n2 == ps.function:
                    idx = _param_index(p2, ps.param.split("->")[0]); break
            if idx >= 0:
                sinks.setdefault(ps.function, []).append((ps, idx))
    if not sinks:
        return []
    out = []
    seen = set()
    for rel, src in files.items():
        for cname, _s, _p, body in _functions(src):
            body = _strip_comments(body)
            # wire-tainted locals in this caller: record BOTH the root struct and the leaf field of
            # each wire-read lvalue (Stream_Read(s, fmt.blk) taints struct `fmt` AND field `blk`, so
            # a caller passing `&fmt` to a sink is matched).
            wire = set()
            for m in _WIRE_READER.finditer(body):
                lv = m.group(1)
                wire.add(re.split(r"[.\->]", lv)[0])         # root (fmt)
                wire.add(lv.split(".")[-1].split("->")[-1])  # leaf (blk)
            for cm in _CALL_ARGS.finditer(body):
                callee = cm.group(1)
                if callee not in sinks:
                    continue
                args = [a.strip() for a in _split_params(cm.group(2))]
                for ps, idx in sinks[callee]:
                    if idx >= len(args):
                        continue
                    argbase = re.sub(r"^[&*]+", "", args[idx]).split(".")[-1].split("->")[-1].split("[")[0]
                    if argbase in wire and (ps.function, ps.param, ps.use) not in seen:
                        seen.add((ps.function, ps.param, ps.use))
                        out.append((ps, cname, rel))
    return out
