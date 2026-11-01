"""Per-CWE source/sink/sanitizer queries with intraprocedural taint -- the discovery layer for
weakness classes the dedicated regex detectors (command/format sinks, int-overflow, use-after-free)
do not cover. This is the operational core of a code-property-graph query engine (source -> sink,
minus a sanitizer) done rule-based and offline: a declarative query table + the shared srctaint
intraprocedural link. It is INTRAPROCEDURAL (not a full interprocedural CPG yet), and deterministic
-- no LLM.

v1 classes, both taint-gated so a finding is never a bare pattern match:
  * CWE-120 -- unbounded copy into a buffer: strcpy/strcat/stpcpy/wcscpy/... of attacker-controlled
    data (the bounded variants strncpy/strlcpy/snprintf are the FIX and are never flagged); plus
    gets(), which is unsafe UNIVERSALLY (it reads unbounded stdin into a fixed buffer) and is flagged
    without a taint gate.
  * CWE-22 -- path traversal: a filesystem open/unlink/... whose path flows from untrusted input with
    no normalising guard (realpath / a `..` reject) in the enclosing function.

Findings are `candidate`; a taint-linked one earns the non-fuzzing weaponization floor (an overflow /
traversal recipe). Pure parsing, stdlib based; an unreadable file is skipped.
"""
from __future__ import annotations

import io
import re
import tarfile
from pathlib import Path

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..source_lookup import source_project_for
from . import srctaint
from .source_sinks import _balanced_arg, _is_declaration, _is_literal, _split_args, _strip_comments
from .srcwalk import source_files

CPG_STAGE = "cpg_scan"
TOOL, TOOL_VERSION = "cpg", "cpg-1"
_MAX_RECIPES = 64

# sink -> (cwe, arg position to check, mode). mode: "copy"/"path" taint-check the arg; "gets" is a
# universal defect (no taint gate). The bounded copy variants are deliberately ABSENT -- they are the
# fix, not the bug.
_COPY = {"strcpy": 1, "strcat": 1, "stpcpy": 1, "wcscpy": 1, "wcscat": 1, "lstrcpy": 1, "lstrcat": 1}
_PATH = {"fopen": 0, "freopen": 0, "open": 0, "open64": 0, "openat": 1, "opendir": 0, "creat": 0,
         "unlink": 0, "remove": 0, "rmdir": 0}
#: sized copy/read sinks -> the LENGTH argument position. The bug is an attacker-controlled SIZE
#: driving a fixed-destination copy/read with no bound check -- the dominant protocol-parser class
#: (CWE-787 OOB write / CWE-125 OOB read), e.g. `len = Stream_Read_UINT32(s); memcpy(dst, p, len)` or
#: `Stream_Read(s, dst, len)`. memset is included (a wild length clears out of bounds). The length,
#: not the data pointer, is what the attacker controls, so the taint gate runs on THIS argument.
_LEN = {"memcpy": 2, "memmove": 2, "bcopy": 2, "wmemcpy": 2, "wmemmove": 2, "memset": 2,
        "CopyMemory": 2, "MoveMemory": 2, "RtlCopyMemory": 2, "RtlMoveMemory": 2, "Stream_Read": 2}
#: the DESTINATION argument of each length sink, to recognise the SAFE idiom `dst = malloc(len);
#: copy(dst, src, len)` -- when the destination was allocated to the SAME length there is no
#: out-of-bounds WRITE, so it must not be flagged (0-false-positive). bcopy(src,dst,n) has dst 2nd.
_LEN_DST = {"memcpy": 0, "memmove": 0, "wmemcpy": 0, "wmemmove": 0, "memset": 0, "bcopy": 1,
            "CopyMemory": 0, "MoveMemory": 0, "RtlCopyMemory": 0, "RtlMoveMemory": 0, "Stream_Read": 1}
_SINKS = {**{k: ("CWE-120", v, "copy") for k, v in _COPY.items()},
          "gets": ("CWE-120", 0, "gets"),
          **{k: ("CWE-787", v, "length") for k, v in _LEN.items()},
          **{k: ("CWE-22", v, "path") for k, v in _PATH.items()}}
_CALL = re.compile(rf"\b({'|'.join(sorted(_SINKS, key=len, reverse=True))})\s*\(")
#: a length is BOUNDED when it is compared / clamped / checked against a limit before the sink, or a
#: stream-bounds guard covers it. Suppresses the common safe pattern so an untrusted-length copy is
#: flagged only when nothing constrains the size. FreeRDP's own guards (Stream_CheckAndLogRequired
#: Length, Stream_GetRemainingLength, Stream_SafeSeek, Stream_EnsureRemainingCapacity) count.
_LEN_GUARDS = ("Stream_CheckAndLogRequiredLength", "Stream_CheckAndLogRequiredCapacity",
               "Stream_GetRemainingLength", "Stream_GetRemainingCapacity", "Stream_SafeSeek",
               "Stream_EnsureRemainingCapacity", "Stream_EnsureCapacity", "Stream_Length",
               "check_stream_length", "CheckAndLogRequiredLength")
#: tokens that mean the path was normalised / traversal-checked in the enclosing function.
_PATH_SANITIZERS = ("realpath", "canonicaliz", "PathCanon", "basename", '".."', "'..'", "secure_path")
#: an allowlist / prefix check compares the path against a string LITERAL (e.g.
#: `strncmp(deviceId, "/dev/video", 10)`, `if (path == "...")`) -- the caller restricts the path to a
#: known-safe set, so an open() guarded by one is not an uncontrolled traversal.
_ALLOWLIST_CMP = re.compile(
    r'\b(?:strncmp|strncasecmp|strcmp|strcasecmp|memcmp|_strnicmp|_stricmp|wcscmp|wcsncmp|'
    r'CompareString\w*)\s*\([^;]*"')


def _sanitized(lines: list, idx: int, base: str | None = None) -> bool:
    start, _ = srctaint.enclosing(lines, idx)
    body = "\n".join(lines[start:idx + 1])
    if any(s in body for s in _PATH_SANITIZERS):
        return True
    # an allowlist comparison of the path base against a string literal anywhere before the sink
    for m in _ALLOWLIST_CMP.finditer(body):
        if base is None or re.search(rf"\b{re.escape(base)}\b", body[m.start():m.start() + 120]):
            return True
    return False


def _bounded(lines: list, idx: int, lenvar: str | None) -> bool:
    """True when the length `lenvar` is constrained before the sink at `idx`: a stream-bounds guard
    anywhere in the enclosing function, or a comparison / clamp of the length (`len < N`, `N >= len`,
    `len = MIN(len, ...)`, a `len > cap` reject). Intraprocedural and deliberately permissive -- a
    length with ANY visible bound is not flagged, keeping the untrusted-length finding to the cases
    where nothing checks the size."""
    start, _ = srctaint.enclosing(lines, idx)
    body = "\n".join(lines[start:idx + 1])
    if any(g in body for g in _LEN_GUARDS):
        return True
    if not lenvar:
        return False
    b = re.escape(lenvar)
    # a comparison of the length against anything (both operand orders), or a min/clamp of it
    if re.search(rf"\b{b}\s*(?:<|<=|>|>=)\s*\w", body) or re.search(rf"\w\s*(?:<|<=|>|>=)\s*{b}\b", body):
        return True
    if re.search(rf"\b(?:MIN|min|fmin|MIN3)\s*\([^;]*\b{b}\b", body) or re.search(rf"\b{b}\s*=\s*[^;]*\b(?:MIN|min)\b", body):
        return True
    return False


def _fixed_dst_cap(lines: list, idx: int, dstvar: str | None):
    """The capacity string of a FIXED-SIZE destination `dstvar`, or None. A destination is fixed when
    it is declared as an array `T dstvar[N]` (a stack buffer or struct field) in the enclosing
    function -- the dangerous target for an untrusted-length copy. A pointer (`T* dstvar`), an
    allocator result, or a parameter is NOT fixed (its size is dynamic or external) and returns None,
    which keeps the detector off the safe malloc-to-len idiom. `N` must be a constant or constant-like
    token, not another variable (a VLA is itself dynamic)."""
    if not dstvar:
        return None
    start, _ = srctaint.enclosing(lines, idx)
    d = re.escape(dstvar)
    # `TYPE dstvar [ CAP ] ;` -- a declaration (not an indexed USE): the token before dstvar is a
    # type/qualifier word, and CAP is a number, sizeof, or an UPPER_CASE/const-looking macro.
    decl = re.compile(rf"\b[A-Za-z_]\w*\s+(?:\*\s*)?{d}\s*\[\s*([^\];]*?)\s*\]")
    for j in range(start, min(idx + 1, len(lines))):
        m = decl.search(lines[j])
        if not m:
            continue
        cap = m.group(1).strip()
        if cap == "":                                        # `T dst[]` -- a flexible/param array, not fixed
            continue
        if re.fullmatch(r"\d+", cap) or cap.startswith("sizeof") or re.fullmatch(r"[A-Z_][A-Z0-9_]+", cap) \
                or re.fullmatch(r"0[xX][0-9a-fA-F]+", cap):
            return cap
    return None


def _mk(name, line, fn, arg, cwe, label, taint) -> dict:
    ev = [{"channel": "source", "detail": f"{name}:{line + 1}: {label}"}]
    if taint:
        ev.append({"channel": "source-flow",
                   "detail": f"the argument flows from {taint['source']} ({taint['via']})"})
    return {"cwe": cwe, "severity": "high", "title": f"{label} ({cwe})",
            "dedup_key": f"cpg:{cwe}:{name}:{line + 1}:{fn}", "fn": fn, "arg": arg,
            "file": name, "line": line + 1, "taint": taint, "evidence": ev}


def scan_source(root: Path) -> list:
    findings: list = []
    # PHASE A (interprocedural): pre-index struct fields the project fills from the wire, so a length
    # read as `obj->field` here is tainted even when the field was filled in another function. Built
    # once over the comment-stripped tree, then passed to every taint query below.
    files = [(label, _strip_comments(text)) for label, _p, text in source_files(root)]
    wire_fields = srctaint.scan_wire_fields(files)
    # PHASE B: functions whose return value is wire-derived, so `len = f(s)` here is tainted.
    ret_funcs = srctaint.scan_return_taint(files, wire_fields=wire_fields)
    for label, text in files:
        lines = text.splitlines()
        for i, ln in enumerate(lines):
            if ln.lstrip().startswith("#"):
                continue
            for m in _CALL.finditer(ln):
                fn = m.group(1)
                if _is_declaration(ln[:m.start()]) or ln[:m.start()].rstrip().endswith((".", "->")):
                    continue
                cwe, pos, mode = _SINKS[fn]
                try:
                    args = _split_args(_balanced_arg(ln, ln.index("(", m.end() - 1)))
                except ValueError:
                    continue
                if mode == "gets":
                    # gets() is unsafe universally -- unbounded stdin read into a fixed buffer.
                    dst = args[0] if args else "buffer"
                    findings.append(_mk(label, i, fn, dst, "CWE-120",
                                        f"gets() reads unbounded stdin into '{dst}' (buffer overflow)",
                                        {"via": "input-reader", "source": "stdin via gets()"}))
                    continue
                if pos >= len(args):
                    continue
                arg = args[pos]
                if _is_literal(arg) or re.fullmatch(r"(?:NULL|0|nullptr)", arg.strip()):
                    continue
                # PRECISION: require a STRONG untrusted source (input reader / argv / a parser's or
                # main's parameter), not a generic parameter -- a path/buffer arg that is merely a
                # forwarded parameter of a helper is not established attacker-controlled.
                strength, taint = srctaint.untrusted_strength(lines, i, arg, wire_fields=wire_fields,
                                                              ret_funcs=ret_funcs)
                if strength != "strong":
                    continue
                if mode == "path":
                    if _sanitized(lines, i, srctaint.base_ident(arg)):
                        continue
                    findings.append(_mk(label, i, fn, arg, "CWE-22",
                                        f"{fn}() opens a path from untrusted input ('{arg}') with "
                                        f"no traversal sanitisation", taint))
                elif mode == "length":                           # untrusted SIZE drives the copy/read
                    # bound-check against the FULL length expression (`h->len`, not just `h`), so a
                    # `if (h->len > sizeof dst)` guard on a struct-field length is recognised.
                    if _bounded(lines, i, arg.strip()):          # the length is checked/clamped
                        continue
                    dpos = _LEN_DST.get(fn)
                    dst = args[dpos] if (dpos is not None and dpos < len(args)) else None
                    dstbase = srctaint.base_ident(dst) if dst else None
                    # PRECISION (0-FP on well-guarded code): flag ONLY when the destination is a
                    # FIXED-SIZE buffer -- a declared stack/struct array `T buf[N]`. The common safe
                    # idiom `dst = malloc(len); copy(dst, src, len)` sizes the heap dst to the length
                    # (no OOB write), and a buffer handed back by an allocator (MF/Lock) is likewise
                    # not fixed -- both are excluded. A fixed array copied with an untrusted length is
                    # the classic wire-length stack/struct overflow.
                    cap = _fixed_dst_cap(lines, i, dstbase)
                    if cap is None:
                        continue
                    findings.append(_mk(label, i, fn, arg, "CWE-787",
                                        f"{fn}() writes an untrusted, unbounded length ('{arg}') into a "
                                        f"fixed-size buffer ('{dst}'[{cap}]) with no bound check "
                                        f"(stack/struct out-of-bounds write)", taint))
                else:                                            # copy
                    findings.append(_mk(label, i, fn, arg, "CWE-120",
                                        f"{fn}() copies untrusted data ('{arg}') into a buffer with "
                                        f"no length bound", taint))
    return findings


def _file_findings(ctx, target, findings) -> int:
    from ..poc.source_recipe import file_source_recipe
    fd = FindingDAO(ctx.conn)
    recipes = 0
    for f in findings:
        linked = bool(f.get("taint"))
        fd.upsert(target.id, target.case_id, {
            "cwe": f["cwe"], "severity": f["severity"], "detector": "cpg", "title": f["title"],
            "evidence": f["evidence"], "site_detail": f"{f['file']}:{f['line']}",
            "function_addr": None, "site_addr": None, "dedup_key": f["dedup_key"],
            "state": "candidate", "confidence": 0.6 if linked else 0.4})
        if linked and recipes < _MAX_RECIPES:
            if file_source_recipe(ctx, target, cwe=f["cwe"], fn=f["fn"], arg=f["arg"],
                                  file=f["file"], line=f["line"], taint=f["taint"]) is not None:
                recipes += 1
    return recipes


def cpg_scan_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("cpg_scan requires a target_id")
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        ctx.emit("cpg_scan.done", payload={"applicable": False,
                 "note": "no archived source tree (this detector reads C/C++ source)"})
        return {}
    root = ctx.scratch() / "cpg"
    root.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                          mode="r:gz") as tf:
            for mem in tf.getmembers():
                if mem.isfile() and not mem.name.startswith("/") and ".." not in mem.name:
                    tf.extract(mem, root)
    except Exception:
        ctx.emit("cpg_scan.done", payload={"applicable": False,
                 "note": "could not unpack the archived source tree"})
        return {}
    ctx.progress(msg="per-CWE source/sink queries (buffer-copy, path-traversal)")
    findings = scan_source(root)
    recipes = _file_findings(ctx, target, findings)
    ctx.emit("cpg_scan.done", payload={"applicable": True, "findings": len(findings),
             "recipes": recipes})
    ctx.progress(pct=100, msg=f"{len(findings)} per-CWE candidate(s), {recipes} recipe(s)")
    return {"metrics": {"findings": len(findings), "recipes": recipes}}


def register() -> None:
    register_stage(CPG_STAGE, cpg_scan_stage, resource_class="quick", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=180)


def enqueue_cpg_scan(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, CPG_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
