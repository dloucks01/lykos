"""Out-of-bounds write by INDEX (CWE-787), source-level.

Distinct from a copy-length desync (which needs interprocedural buffer-size tracking and is not
soundly catchable from text): this flags the two same-function index-write shapes that ARE sound to
recognise, and that the real CWE-787 CVEs include:

  1. MONOTONIC WRITE-INDEX, NEVER BOUNDED -- an index written into an array (`arr[k] = ...`,
     `&arr[k]`, `arr[k]++`) that is only ever incremented (`k++`, `k += ...`) and NEVER compared to
     anything in the function. A counter that grows without a capacity check and indexes a write is
     the classic "append past the fixed array" (a key-enumeration loop writing past a fixed entry table).
  2. ATTACKER-CONTROLLED INDEX, UNCHECKED -- `arr[idx] = ...` where `idx` is attacker-derived (a
     parameter, a reader/parser output, a parsed field) and no real branch bounds it before the
     write.

Precision is paramount, so it UNDER-reports: ANY comparison of the index (a loop condition, an
`if`, a clamp/min) silences it; a constant index is silent; a non-attacker, bounded, or
loop-counter index is silent. It does not reason about the array's capacity (that is cross-info),
so it never claims the overflow SIZE -- only that an index write runs with no bound. Shares the
lexer and guard logic with assert_guard; pure stdlib parsing.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..source_lookup import source_project_for
from . import srctaint
from .assert_guard import _call_args, _guard_kind, _idents, discover_assert_macros, functions, strip_code
from .srcwalk import source_files

_log = logging.getLogger(__name__)

OOB_WRITE_STAGE = "oob_write_scan"
TOOL = "oob_write"
TOOL_VERSION = "oob_write-1"

_IDENT = r"[A-Za-z_]\w*"
#: a wire-read call -- a function that reads from a peer stream IS a parser, so its parameters and
#: their fields carry attacker-controlled data (FreeRDP's Stream_Read*/Stream_Get*, plus generic
#: recv/read-into). A precise, body-based parser signal that does not depend on the function's name.
_WIRE_READ = re.compile(r"\b(?:Stream_(?:Read|Get|Peek|Check)\w*|recv|recvfrom)\s*\(")
# an indexed WRITE: arr[idx] =/+=/-=/++/-- , or &arr[idx] (address taken to write through). The
# array base may be a member chain (state->keys, x.buf). Captures (base, index-expr).
_IDX_WRITE = re.compile(
    rf"&\s*((?:{_IDENT}\s*(?:->|\.)\s*)*{_IDENT})\s*\[\s*([^\]]+?)\s*\]"
    rf"|((?:{_IDENT}\s*(?:->|\.)\s*)*{_IDENT})\s*\[\s*([^\]]+?)\s*\]\s*(?:\+\+|--|[-+*/|&^]?=(?!=))")
# attacker-origin of an index (parameter / reader-output / parsed field).
_READER = re.compile(
    r"(?i)\b([a-z0-9_]*read[a-z0-9_]*|recv|recvfrom|fread|parse\w*|decode\w*|unpack\w*|ntoh[ls]|"
    r"Stream_Read\w*|get[a-z0-9_]*(?:len|size|count|idx|index|num|u?int))\s*\(")


def _base_leaf(base: str) -> str:
    return re.split(r"->|\.", base)[-1].strip()


#: a capacity-ensuring helper -- a call that grows/reserves/reallocs the array before the write, so
#: the index that follows is bounded by it (Queue_EnsureCapacity(q,..), Stream_EnsureCapacity(s,..),
#: *_resize(buf,..), realloc(arr,..)). The write after such a call is not an unbounded append.
_ENSURE = re.compile(r"(?i)\b(\w*(?:ensure|reserve|resize|realloc|expand|reallocarray)\w*)\s*\(")


def _capacity_ensured(blines, upto: int, base: str) -> bool:
    """True when a capacity-ensuring helper for the array's base OBJECT is called before the write."""
    obj = re.split(r"->|\.", base)[0].strip()
    if not obj:
        return False
    pre = "\n".join(blines[:upto])
    oe = re.escape(obj)
    for m in _ENSURE.finditer(pre):
        got = _call_args(pre, m.end() - 1)
        if got and any(re.search(rf"\b{oe}\b", a) for a in got[0]):
            return True
    return False


def _external_index(blines, upto: int, idx_expr: str, params: set, parser: bool) -> bool:
    """True when the index is attacker-influenced. A reader/parser-filled index counts anywhere; a
    bare PARAMETER or a field of one counts only when the enclosing function is itself a wire/peer
    parser (or main) -- otherwise a parameter is just an internal value a caller passed (the queue,
    the pool, the pixel count), not attacker-controlled. Conservative."""
    ids = _idents(idx_expr)
    mb = re.match(rf"\s*[&*]?\s*({_IDENT})\s*(?:->|\.)", idx_expr)
    if mb:
        ids.add(mb.group(1))
    if parser and (ids & params):
        return True
    pre = "\n".join(blines[:upto])
    for b in ids:
        be = re.escape(b)
        for am in re.finditer(rf"\b{be}\s*=\s*([^;]+)", pre):
            if _READER.search(am.group(1)):
                return True
        for m in _READER.finditer(pre):
            got = _call_args(pre, m.end() - 1)
            if got and any(re.search(rf"(^|[^\w])&?{be}($|[^\w])", a) for a in got[0][1:]):
                return True
    return False


def _fixed_arrays(code: str) -> set:
    """Base names declared as a fixed-size array `T name[CAP]` (so an index write into one is into a
    bounded region). Member arrays are not seen here but are still flagged via the monotonic shape."""
    out = set()
    for m in re.finditer(rf"\b({_IDENT})\s*\[\s*([A-Za-z0-9_]+)\s*\]\s*(?:=|;|\{{)", code):
        out.add(m.group(1))
    return out


def _scan_function(lbl, name, b0, body, params, asserts) -> list:
    blines = body.split("\n")
    fixed = _fixed_arrays(body)
    parser = srctaint.is_parser_name(name) or name == "main" or bool(_WIRE_READ.search(body))
    findings, seen = [], set()
    for li, line in enumerate(blines):
        for m in _IDX_WRITE.finditer(line):
            base = (m.group(1) or m.group(3) or "").strip()
            idx = (m.group(2) or m.group(4) or "").strip()
            if not base or not idx:
                continue
            idx_ids = _idents(idx)
            if not idx_ids:                               # constant index -> safe
                continue
            # a REAL bound on the index anywhere before the write (loop cond / if / clamp) -> safe.
            if any(_guard_kind(gl, idx_ids, asserts) == "real" for gl in blines[:li]):
                continue
            # also safe if the index is compared ANYWHERE in the function (we are conservative:
            # a single comparison of the index is taken as a bound).
            if _index_compared(body, idx_ids):
                continue
            # a capacity-ensuring helper for this array before the write bounds the index (the safe
            # dynamic-container pattern: Queue_EnsureCapacity(q,1); q->array[q->tail] = ...).
            if _capacity_ensured(blines, li, base):
                continue
            leaf = _base_leaf(base)
            monotonic = _is_monotonic(body, idx)
            # PRECISION FLOOR: the index must be attacker-influenced -- a reader/parser output, or a
            # parameter/field WHEN the enclosing function is a wire parser (not a generic helper
            # whose parameter is just an internal object a caller passed). A purely-local counter, a
            # static-table walk, or an internal container index is NOT flagged.
            attacker = _external_index(blines, li, idx, params, parser)
            if not attacker:
                continue
            key = (lbl, b0 + li + 1, base, idx[:24])
            if key in seen:
                continue
            seen.add(key)
            kind = "monotonic-unbounded-index" if monotonic else "attacker-index"
            why = ("the write index only ever increments and is never compared to a capacity -- it "
                   "runs past the array (an unbounded append)" if monotonic else
                   "the write index is attacker-derived and no branch bounds it before the write")
            fixedn = " (into a fixed-size array)" if leaf in fixed else ""
            findings.append({
                "cwe": "CWE-787", "severity": "high" if (monotonic and leaf in fixed) else "medium",
                "title": f"Out-of-bounds write: unbounded index '{idx[:30]}' into '{base}'",
                "dedup_key": f"oobwrite:{lbl}:{b0 + li + 1}:{leaf}",
                "file": lbl, "line": b0 + li + 1, "kind": kind,
                "evidence": [{"channel": "source",
                              "detail": f"{lbl}:{b0 + li + 1}: write to '{base}[{idx}]'{fixedn} in "
                                        f"{name}() -- {why} (CWE-787)"}]})
    return findings


def _index_compared(body: str, idx_ids: set) -> bool:
    """True when any id of the index appears in a comparison anywhere in the function body."""
    for x in idx_ids:
        xe = re.escape(x)
        # the index on the LEFT of a comparison, or on the RIGHT -- but NOT the `>` of a `->`
        # member arrow (`state->nKeys` is an access, not `> nKeys`).
        if re.search(rf"\b{xe}\b\s*(?:<=?|>=?|==|!=)", body) or \
                re.search(rf"(?<!-)(?:<=?|>=?|==|!=)\s*\b{xe}\b", body):
            return True
    return False


def _is_monotonic(body: str, idx_expr: str) -> bool:
    """True when the index (its base identifier) is incremented in the function and never otherwise
    reassigned to a bounded value -- a growing counter."""
    if re.search(rf"{re.escape(idx_expr.strip())}\s*(?:\+\+|\+=)", body):   # state->nKeys++ / x += 1
        return True
    for b in _idents(idx_expr):                                            # bare counter: n++ / n +=
        if re.search(rf"\b{re.escape(b)}\b\s*(?:\+\+|\+=)", body):
            return True
    return False


def scan_texts(files) -> list:
    stripped = [(lbl, strip_code(t)) for lbl, t in files]
    asserts = discover_assert_macros(t for _, t in stripped)
    out = []
    for lbl, code in stripped:
        for name, params, b0, _b1, body in functions(code):
            out.extend(_scan_function(lbl, name, b0, body, set(params), asserts))
    return out


def scan_source(root: Path) -> list:
    return scan_texts((lbl, text) for lbl, _p, text in source_files(root))


def oob_write_stage(ctx) -> dict:
    import io
    import tarfile

    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("oob_write_scan requires a target_id")
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        ctx.emit("oob_write.done", payload={"applicable": False,
                 "note": "no archived source tree (this detector reads C/C++ source)"})
        return {}
    root = ctx.scratch() / "oob_write"
    root.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                          mode="r:gz") as tf:
            for mem in tf.getmembers():
                if mem.isfile() and not mem.name.startswith("/") and ".." not in mem.name:
                    tf.extract(mem, root)
    except Exception:                                    # noqa: BLE001
        ctx.emit("oob_write.done", payload={"applicable": False,
                 "note": "could not unpack the archived source tree"})
        return {}
    ctx.progress(msg="scanning for unbounded index writes (out-of-bounds write)")
    findings = scan_source(root)
    fd = FindingDAO(ctx.conn)
    for f in findings:
        fd.upsert(target.id, target.case_id, {
            "cwe": f["cwe"], "severity": f["severity"], "detector": "oob_write",
            "title": f["title"], "evidence": f["evidence"], "function_addr": None,
            "site_addr": None, "dedup_key": f["dedup_key"],
            "site_detail": f"{f['file']}:{f['line']}", "state": "candidate",
            "confidence": 0.55 if f["kind"] == "monotonic-unbounded-index" else 0.45})
    ctx.emit("oob_write.done", payload={"applicable": True, "findings": len(findings)})
    ctx.progress(pct=100, msg=f"{len(findings)} out-of-bounds-write candidate(s)")
    return {"metrics": {"findings": len(findings)}}


def register() -> None:
    register_stage(OOB_WRITE_STAGE, oob_write_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_oob_write_scan(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, OOB_WRITE_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="quick", force=force)
