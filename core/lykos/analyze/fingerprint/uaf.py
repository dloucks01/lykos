"""Use-after-free / double-free detector (CWE-416 / CWE-415), source-level.

The dynamic channel (heap_trace) finds a UAF only when the fuzzer actually drives the program down
the freeing path; a guarded or hard-to-reach cleanup path stays invisible to it. This flags the
STATIC shape -- a pointer is `free()`d, then used (dereferenced, indexed, passed to a call) or
`free()`d again, with no reassignment in between -- so the bug is reported even on a path the fuzzer
never reaches. Scoped to one function body (brace depth): a `free` at the end of one function and a
same-named variable in the next is not conflated.

A source heuristic, so findings are `candidate`: reassignment (`p = ...`, including the safe
`p = NULL;` idiom) clears the pointer and suppresses the flag, which keeps patched code quiet,
but it cannot prove the freeing branch and the use branch are the same dynamic path.

Pure parsing, stdlib based; a file it cannot read is skipped, never fatal.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..source_lookup import source_project_for
from . import srctaint
from .srcwalk import source_files

_log = logging.getLogger(__name__)

UAF_STAGE = "uaf_scan"
TOOL = "uaf"
TOOL_VERSION = "uaf-1"
#: cap on corroborated recipes filed per scan.
_MAX_SOURCE_RECIPES = 64


_IDENT = r"[A-Za-z_]\w*"
# the deallocators, across libc / kernel / FreeRTOS / glib / C++ (`delete p;`). The captured group
# is the pointer expression being freed.
_FREE_NAMES = (r"free|cfree|kfree|kvfree|vfree|vPortFree|pvPortFree|g_free|OPENSSL_free|CRYPTO_free")
_FREE = re.compile(rf"\b(?:{_FREE_NAMES})\s*\(\s*({_IDENT})\s*\)")
_DELETE = re.compile(rf"\bdelete\s*(?:\[\s*\])?\s+({_IDENT})\s*;")
# CWE-761: free of a pointer that is NOT the allocation start. Two syntactically distinctive, very
# low-FP shapes -- you can only free the exact value malloc returned:
#   * pointer ARITHMETIC: free(p + n), free(buf - 1), free(s->data + k)  (a base, member/index
#     access, THEN a + or - and more) -- NOT free(p), free(p->next), free(arr[i]) (no trailing +/-).
#   * ADDRESS-OF: free(&x), free(&arr[i])  -- you never free the address of an object.
# Both reach the invalid/mismatched-free substrate (routed as CWE-590's sibling by chain_primitive).
_BASE = rf"{_IDENT}(?:\s*(?:->|\.)\s*{_IDENT}|\s*\[[^\]]*\])*"
# the arithmetic operator is a `+` or a `-` that is NOT the `-` of a `->` member access (so
# free(p->next) / free(list->head) are NOT mistaken for `p` minus `>next`).
_ARITH_OP = r"(?:\+|-(?!>))"
_FREE_ARITH = re.compile(rf"\b(?:{_FREE_NAMES})\s*\(\s*({_BASE}\s*{_ARITH_OP}\s*[^;)]+?)\s*\)")
_FREE_ADDROF = re.compile(rf"\b(?:{_FREE_NAMES})\s*\(\s*(&\s*{_BASE}[^;)]*?)\s*\)")
def _assigns(line: str, var: str) -> bool:
    return re.search(rf"(?<![=!<>])\b{re.escape(var)}\s*=(?!=)", line) is not None


def _uses(line: str, var: str) -> "str | None":
    """How `var` is used on this line as a freed pointer (deref / index / member / call arg), or
    None. A bare `&var` (taking its address) or a reassignment LHS is not a use-after-free."""
    v = re.escape(var)
    for rx, kind in ((rf"\*\s*{v}\b", "deref *p"), (rf"\b{v}\s*->", "member p->"),
                     (rf"\b{v}\s*\[", "index p[]")):
        if re.search(rx, line):
            return kind
    # passed to a call: `foo(.. p ..)` where p is not immediately preceded by & (address-of). The
    # parenthesis that encloses it must be a CALL's: `if (p)`, `while (p != NULL)`, `sizeof(p)`
    # read the pointer's VALUE (or nothing at all) and never touch the freed memory -- counting
    # them made `free(p); if (p == NULL) ...` a use-after-free.
    for m in re.finditer(rf"(?<![&\w]){v}\b", line):
        lhs = line[:m.start()]
        fn = _enclosing_call(lhs)
        if fn and fn not in _NOT_CALLS and not re.search(rf"\b{v}\s*=(?!=)", line):
            return "call arg"
    return None


# keywords / operators that take a parenthesised expression without calling anything
_NOT_CALLS = {"if", "while", "for", "switch", "return", "sizeof", "alignof", "_Alignof",
              "typeof", "__typeof__", "decltype", "assert"}


def _enclosing_call(lhs: str) -> "str | None":
    """The name before the innermost still-open `(` at the end of `lhs` (the callee whose argument
    list the next token sits in), or None when there is no open parenthesis or no name before it
    (a cast or grouping)."""
    depth = 0
    for k in range(len(lhs) - 1, -1, -1):
        c = lhs[k]
        if c == ")":
            depth += 1
        elif c == "(":
            if depth == 0:
                m = re.search(r"([A-Za-z_]\w*)\s*$", lhs[:k])
                return m.group(1) if m else None
            depth -= 1
    return None


_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def _strip_comments(text: str) -> str:
    """Blank out C/C++ comments, preserving line structure (so line numbers stay correct) -- a
    `free(p)` written in a comment is not a deallocation."""
    return _COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def _scan_text(name: str, lines: list) -> list:
    findings: list = []
    freed: dict = {}          # var -> (line_index, dealloc_name)
    depth = 0
    for i, ln in enumerate(lines):
        # 1) record a use / double-free of anything freed and still live
        for var in list(freed):
            if _assigns(ln, var):
                freed.pop(var, None)                       # reassigned -> no longer a dangling ptr
                continue
            fi, dealloc = freed[var]
            if i == fi:
                continue
            ref = _FREE.search(ln) or _DELETE.search(ln)
            if ref and ref.group(1) == var:
                findings.append(_mk(name, fi, i, var, dealloc, "CWE-415", "Double-free",
                                    f"freed by {dealloc}() at line {fi + 1}, freed again", lines))
                freed.pop(var, None)
                continue
            how = _uses(ln, var)
            if how:
                findings.append(_mk(name, fi, i, var, dealloc, "CWE-416", "Use-after-free",
                                    f"freed by {dealloc}() at line {fi + 1}, then used ({how})",
                                    lines))
                freed.pop(var, None)
        # 2) record new frees on this line -- unless the free's own block RETURNS on the same line
        # (`if (err) { free(p); return -1; }`): that path never reaches the code below, so a later
        # `use(p)` on the fall-through is not a use-after-free. The multi-line form of this is
        # handled by the exit rule in 4); this is its one-line twin.
        fm = _FREE.search(ln)
        if fm and not _returns_after(ln, fm.end()):
            freed[fm.group(1)] = (i, fm.group(0).split("(")[0].strip())
        dm = _DELETE.search(ln)
        if dm and not _returns_after(ln, dm.end()):
            freed[dm.group(1)] = (i, "delete")
        # 3) track function scope: on leaving the function body (brace depth back to 0), dangling
        # state does not carry into the next function -- a free in `void a(p){free(p);}` must not
        # flag a same-named `p` in the next function.
        depth += ln.count("{") - ln.count("}")
        if depth <= 0:
            depth = 0
            freed = {}
        # 4) an UNCONDITIONAL control-flow exit ends the branch the free was on: `if(err){ free(p);
        # return; } use(p);` is NOT a use-after-free (the free's path returned). Clear the dangling
        # set on a bare return/goto/break/continue (statement at line start). A CONDITIONAL exit
        # (`if(x) return;`) is NOT treated this way -- the free may still reach the fall-through, so
        # a real `free(a); if(x) return; use(a);` is kept. A `return p;` was scored as a use above.
        elif _EXIT.match(ln.lstrip()):
            freed = {}
    return findings


_EXIT = re.compile(r"(return|goto|break|continue)\b")


def _returns_after(line: str, pos: int) -> bool:
    """True when, after `pos` on this line, an UNCONDITIONAL `return` statement follows in the SAME
    brace block as the code at `pos`: `free(p); return;` / `{ free(p); return -1; }`. Not when the
    block closes first (`{ free(p); } else { return; }`), when the return is nested in a deeper
    block (`free(p); if (e) { return; }`), or when it is the body of a braceless conditional
    (`free(p); if (e) return;` -- the `return` follows `)`, not a statement boundary). Only `return`
    counts: a `break`/`goto` on the same line may land on a later use (a loop exit, a cleanup label
    that frees again), so it is not treated as leaving the path."""
    rest = line[pos:]
    depth = 0
    for m in re.finditer(r"[{}]|\breturn\b", rest):
        tok = m.group(0)
        if tok == "{":
            depth += 1
        elif tok == "}":
            depth -= 1
            if depth < 0:
                return False
        elif depth == 0:
            before = rest[:m.start()].rstrip()
            if before and before[-1] in ";{}":
                return True
    return False


def _mk(name, free_line, use_line, var, dealloc, cwe, label, detail_tail, lines) -> dict:
    detail = f"{name}:{use_line + 1}: pointer '{var}' {detail_tail}"
    # TAINT-LITE: is the freed pointer derived from an untrusted source in its function? That link
    # (not proof of reachability) is what earns the corroborated weaponization recipe.
    taint = srctaint.untrusted_link(lines, use_line, var)
    ev = [{"channel": "source", "detail": detail}]
    if taint:
        ev.append({"channel": "source-flow",
                   "detail": f"the pointer '{var}' flows from {taint['source']} ({taint['via']})"})
    return {
        "cwe": cwe, "severity": "high",
        "title": f"{label} of '{var}' ({cwe})",
        "dedup_key": f"uaf:{name}:{free_line + 1}:{use_line + 1}:{var}",
        "fn": f"{dealloc}()", "arg": var, "file": name, "line": use_line + 1, "taint": taint,
        "evidence": ev}


def _scan_bad_free(name: str, lines: list) -> list:
    """CWE-761: free of a pointer that is not the allocation start (pointer arithmetic or an
    address-of). One finding per site; the freed expression is the subject."""
    out: list = []
    for i, ln in enumerate(lines):
        for rx, kind in ((_FREE_ARITH, "pointer arithmetic (base + offset)"),
                         (_FREE_ADDROF, "the address of an object")):
            m = rx.search(ln)
            if not m:
                continue
            expr = " ".join(m.group(1).split())
            base = base_ident_safe(expr)
            # TAINT-LITE: if the offset / base flows from input, the free target is attacker-steered.
            taint = srctaint.untrusted_link(lines, i, base) if base else None
            ev = [{"channel": "source",
                   "detail": f"{name}:{i + 1}: free() is passed {kind}: '{expr}' -- not the pointer "
                             "a matching allocation returned (free of a non-start pointer)"}]
            if taint:
                ev.append({"channel": "source-flow",
                           "detail": f"the freed expression's base '{base}' flows from "
                                     f"{taint['source']} ({taint['via']})"})
            out.append({
                "cwe": "CWE-761", "severity": "high",
                "title": f"Free of a pointer not at the start of a buffer ('{expr}') (CWE-761)",
                "dedup_key": f"badfree:{name}:{i + 1}:{expr}",
                "fn": "free()", "arg": expr, "file": name, "line": i + 1, "taint": taint,
                "evidence": ev})
            break                                        # one finding per line is enough
    return out


def base_ident_safe(expr: str):
    """The leading identifier of a freed expression ('&buf[i]' -> 'buf', 'p + n' -> 'p'), or None."""
    m = re.search(_IDENT, expr.lstrip("&* "))
    return m.group(0) if m else None


def scan_source(root: Path) -> list:
    """Every freed-then-used / freed-twice pointer (CWE-415/416) and every free of a non-start
    pointer (CWE-761) across the source tree. Returns finding dicts (minus target/case ids)."""
    findings: list = []
    for label, _p, text in source_files(root):
        lines = _strip_comments(text).splitlines()
        findings.extend(_scan_text(label, lines))
        findings.extend(_scan_bad_free(label, lines))
    return findings


def uaf_stage(ctx) -> dict:
    import io
    import tarfile

    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("uaf_scan requires a target_id")
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        ctx.emit("uaf.done", payload={"applicable": False,
                 "note": "no archived source tree (this detector reads C/C++ source)"})
        return {}
    root = ctx.scratch() / "uaf"
    root.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                          mode="r:gz") as tf:
            for mem in tf.getmembers():
                if mem.isfile() and not mem.name.startswith("/") and ".." not in mem.name:
                    tf.extract(mem, root)
    except Exception:
        ctx.emit("uaf.done", payload={"applicable": False,
                 "note": "could not unpack the archived source tree"})
        return {}

    ctx.progress(msg="scanning for use-after-free / double-free")
    findings = scan_source(root)
    fd = FindingDAO(ctx.conn)
    recipes = 0
    for f in findings:
        # A freed pointer proven to flow from input raises the row and earns the non-fuzzing
        # weaponization FLOOR (a corroborated UAF/double-free recipe).
        linked = bool(f.get("taint"))
        fd.upsert(target.id, target.case_id, {
            "cwe": f["cwe"], "severity": f["severity"], "detector": "uaf",
            "title": f["title"], "evidence": f["evidence"],
            "function_addr": None, "site_addr": None, "dedup_key": f["dedup_key"],
            "site_detail": f"{f['file']}:{f['line']}",
            "state": "candidate", "confidence": 0.6 if linked else 0.45})
        if linked and recipes < _MAX_SOURCE_RECIPES:
            from ..poc.source_recipe import file_source_recipe
            if file_source_recipe(ctx, target, cwe=f["cwe"], fn=f["fn"], arg=f["arg"],
                                  file=f["file"], line=f["line"], taint=f["taint"]) is not None:
                recipes += 1
    ctx.emit("uaf.done", payload={"applicable": True, "findings": len(findings), "recipes": recipes})
    ctx.progress(pct=100, msg=f"{len(findings)} use-after-free / double-free candidate(s), "
                             f"{recipes} recipe(s)")
    return {"metrics": {"findings": len(findings), "recipes": recipes}}


def register() -> None:
    register_stage(UAF_STAGE, uaf_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_uaf_scan(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, UAF_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="quick", force=force)
