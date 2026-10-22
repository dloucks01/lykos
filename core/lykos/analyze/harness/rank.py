"""T1 (doc 46) -- fuzz-worthiness ranking.

A real binary has thousands of functions; a daemon's bugs live in a handful of input-handling
parsers, not in `main()`. This scores every recovered function by the attack-surface signal we
ALREADY have in the DB -- which functions INGEST input, which touch DANGEROUS sinks, which look
harnessable (a pointer+length prototype), which are loopy (parsers loop over bytes), and which
already carry a taint/bounds finding -- so the harness/fuzzer (T2) can drive the worth-driving
units directly. Pure static, read-only; no execution, no new capture.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from ...db.dao import CallEdgeDAO, FindingDAO, FunctionDAO
from ..detect.catalog import DANGEROUS, SOURCES, normalize


def _to_int(x) -> Optional[int]:
    if x is None:
        return None
    if isinstance(x, int):
        return x
    try:
        s = str(x).strip()
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except (TypeError, ValueError):
        return None


#: Type/name fragments that read as a POINTER-to-bytes parameter, and as a LENGTH parameter. Used
#: to spot an `f(buf, len)` prototype -- the shape an in-process harness can drive directly. Best
#: effort: decompiler types on a stripped binary are noisy, so a hit is a bonus, never required.
_PTR_HINTS = ("*", "char", "uchar", "uint8", "u8", "byte", "void", "buf", "data", "ptr", "msg",
              "pkt", "packet", "payload", "str")
_LEN_HINTS = ("size", "len", "count", "nbyte", "nbytes", "size_t", "ssize_t", "n_", "_n")


def _param_types(frame_json: Optional[str], signature: Optional[str]) -> list:
    """Best-effort parameter type/name strings, from the decompiler frame blob or the signature."""
    out: list = []
    try:
        blob = json.loads(frame_json) if frame_json else None
    except Exception:                                    # noqa: BLE001
        blob = None
    for p in ((blob or {}).get("params") or []):
        if isinstance(p, dict):
            out.append(((p.get("type") or "") + " " + (p.get("name") or "")).strip().lower())
        elif p:
            out.append(str(p).strip().lower())
    if not out and signature and "(" in signature:
        inside = signature[signature.find("(") + 1:signature.rfind(")")]
        out = [a.strip().lower() for a in inside.split(",") if a.strip() and a.strip() != "void"]
    return out


def _ptr_len_confidence(param_types: list) -> int:
    """0 (no harnessable shape), 1 (a pointer arg), 2 (a pointer AND a length arg)."""
    has_ptr = any(("*" in t) or any(h in t for h in _PTR_HINTS) for t in param_types)
    has_len = any(any(h in t for h in _LEN_HINTS) or t in ("int", "long", "unsigned", "size_t")
                  for t in param_types)
    return (2 if (has_ptr and has_len) else 1 if has_ptr else 0)


def _ptr_param_indices(param_types: list) -> list:
    """Indices of the pointer-to-bytes parameters -- the buffer(s) a parser reads. Used by the
    taint channel's buffer-pointer seeding (doc 46 (b)): a parser reached only through a
    callback/dispatch gets no source->sink flow, so its buffer param is seeded as attacker-controlled."""
    return [i for i, t in enumerate(param_types)
            if ("*" in t) or any(h in t for h in _PTR_HINTS)]


@dataclass
class RankedFn:
    addr: int
    name: Optional[str]
    size: int
    score: int
    reasons: list = field(default_factory=list)
    sources: list = field(default_factory=list)      # input-reading callees (recv/read/fgets/...)
    sinks: list = field(default_factory=list)         # dangerous callees (strcpy/memcpy/system/...)
    ptr_len: int = 0                                  # harnessable-shape confidence (0..2)
    ptr_params: list = field(default_factory=list)    # indices of the pointer (buffer) parameters

    def as_dict(self) -> dict[str, Any]:
        return {"addr": hex(self.addr), "name": self.name, "size": self.size, "score": self.score,
                "reasons": self.reasons, "sources": sorted(set(self.sources)),
                "sinks": sorted(set(self.sinks)), "ptr_len": self.ptr_len,
                "ptr_params": list(self.ptr_params)}


# Score weights. Ingesting input is the strongest signal (that is where attacker bytes ENTER, the
# natural harness entry); a dangerous sink is where they go WRONG; a harnessable prototype makes it
# drivable; looping is what a parser does; an existing taint/bounds finding is corroboration.
_W_SOURCE = 4
_W_SINK = 2
_W_PTRLEN = 2            # scaled by confidence (0..2) -> up to 4
_W_LOOPY = 1
_W_TAINT = 3
_W_REACHABLE = 1         # on a call path from an input-source caller (not just a direct caller)

#: finding kinds that mean "input already shown to reach a pointer/index here" -- strong corroboration.
_TAINT_CWES = {"CWE-125", "CWE-787", "CWE-129", "CWE-822", "CWE-120", "CWE-121", "CWE-122"}
_TAINT_DETECTORS = {"tainted_deref", "oob_index", "stack_frame", "chain_primitive"}


def rank_functions(conn, target_id: str, *, top: int = 40) -> list[RankedFn]:
    """Rank a target's functions by fuzz-worthiness, most promising first.

    Reads functions (addr/size/signature/params), the call graph (who calls which SOURCE/sink),
    and the existing findings (taint/bounds sites). Returns the top `top` RankedFn. Read-only.
    """
    funcs = _load_functions(conn, target_id)
    if not funcs:
        return []
    ranges = sorted(((f["lo"], f["hi"], f) for f in funcs), key=lambda t: t[0])

    def _owner(addr: Optional[int]) -> Optional[dict]:
        a = _to_int(addr)
        if a is None:
            return None
        # linear-ish scan is fine for one-shot ranking; ranges are addr-sorted
        for lo, hi, f in ranges:
            if lo <= a < hi:
                return f
        return None

    # 1) attribute each call edge's SOURCE/sink to the function it fires from.
    src_callers: set = set()
    for e in CallEdgeDAO(conn).list_by_target(target_id):
        dn = normalize(getattr(e, "dst_name", None))
        if not dn:
            continue
        owner = _owner(getattr(e, "src_addr", None))
        if owner is None:
            continue
        if dn in SOURCES:
            owner["sources"].add(dn)
            src_callers.add(owner["lo"])
        if dn in DANGEROUS:
            owner["sinks"].add(dn)

    # 2) a taint/bounds finding sited in a function is corroboration.
    for fnd in FindingDAO(conn).list_by_target(target_id):
        if (getattr(fnd, "detector", "") in _TAINT_DETECTORS
                or getattr(fnd, "cwe", "") in _TAINT_CWES):
            owner = _owner(getattr(fnd, "site_addr", None) or getattr(fnd, "function_addr", None))
            if owner is not None:
                owner["taint"] = True

    # 3) score.
    ranked: list[RankedFn] = []
    for f in funcs:
        reasons: list = []
        score = 0
        if f["sources"]:
            score += _W_SOURCE
            reasons.append(f"reads input ({', '.join(sorted(f['sources']))})")
        if f["sinks"]:
            score += _W_SINK
            reasons.append(f"calls a dangerous sink ({', '.join(sorted(f['sinks']))})")
        if f["ptr_len"]:
            score += _W_PTRLEN * f["ptr_len"]
            reasons.append("harnessable prototype (pointer%s)" % ("+length" if f["ptr_len"] == 2 else ""))
        if f["loopy"]:
            score += _W_LOOPY
            reasons.append("loops over its input (back-edges)")
        if f["taint"]:
            score += _W_TAINT
            reasons.append("an input-reaches-a-pointer/index finding is sited here")
        ranked.append(RankedFn(addr=f["lo"], name=f["name"], size=f["size"], score=score,
                               reasons=reasons, sources=sorted(f["sources"]),
                               sinks=sorted(f["sinks"]), ptr_len=f["ptr_len"],
                               ptr_params=list(f.get("ptr_params") or [])))
    # A function only worth ranking if it has ANY signal; a scoreless function is noise.
    ranked = [r for r in ranked if r.score > 0]
    ranked.sort(key=lambda r: (-r.score, -r.size))
    return ranked[:top]


def _load_functions(conn, target_id: str) -> list[dict]:
    """Function rows + their frame params, as mutable scoring records keyed by address range."""
    rows = conn.execute(
        "SELECT addr,name,size,blocks,edges,signature,frame_json FROM function WHERE target_id=?",
        (target_id,)).fetchall()
    out: list[dict] = []
    for r in rows:
        lo = _to_int(r["addr"])
        if lo is None:
            continue
        size = int(r["size"] or 0)
        blocks = int(r["blocks"] or 0)
        edges = int(r["edges"] or 0)
        ptypes = _param_types(r["frame_json"], r["signature"])
        out.append({
            "lo": lo, "hi": lo + max(size, 1), "name": r["name"], "size": size,
            # more edges than blocks means at least one back-edge: the function loops.
            "loopy": edges > blocks and blocks > 0,
            "ptr_len": _ptr_len_confidence(ptypes),
            "ptr_params": _ptr_param_indices(ptypes),
            "sources": set(), "sinks": set(), "taint": False,
        })
    return out
