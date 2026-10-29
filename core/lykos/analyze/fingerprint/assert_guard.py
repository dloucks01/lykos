"""Assert-only bounds checks (CWE-617 / CWE-787 / CWE-125), source-level.

A bounds check written as an ASSERTION is only a check in the builds that keep the assertion:

  * where the assertion is compiled out (`-DNDEBUG` release/distro builds, or a project macro that
    expands to plain `assert()` when its verbose mode is off) the copy it was meant to guard runs
    unchecked -- an out-of-bounds write or read with attacker-chosen length;
  * where the assertion is kept, an attacker who can make the condition false aborts the process
    -- a reachable assertion (CWE-617), a remote denial of service.

Either way the length was never really validated. The usual shape is a small copy helper
(`static inline void buf_write(buf* b, const void* p, size_t n) { ASSERT(remaining(b) >= n);
memcpy(b->cur, p, n); }`) whose callers trust it, while the one guard inside it vanishes in release.
This detector finds those helpers by their shape (a copy whose length is a parameter guarded only by
an assertion), then the CALL SITES that pass a length the caller never checked with a real branch.
It also flags assertions whose condition tests a value just read from input (the abort half).

Assert-like macros are discovered from the tree itself (`assert`, plus every `#define` that is
named like an assertion or expands to one), so nothing here is project-specific. A source heuristic:
findings are `candidate`; any real `if`/`while` guard on the length in the caller suppresses the
call site, which keeps fixed code quiet. Pure parsing, stdlib based; an unreadable file is skipped.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..source_lookup import source_project_for
from .srcwalk import source_files

_log = logging.getLogger(__name__)

ASSERT_GUARD_STAGE = "assert_guard_scan"
TOOL = "assert_guard"
TOOL_VERSION = "assert_guard-1"

_IDENT = r"[A-Za-z_]\w*"
_COPIES = {"memcpy": 2, "memmove": 2, "CopyMemory": 2, "MoveMemory": 2, "bcopy": 2,
           "strncpy": 2, "memccpy": 3}
_COPY_RE = re.compile(r"\b(" + "|".join(_COPIES) + r")\s*\(")
_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "else", "do", "case", "goto",
             "defined", "typeof", "__typeof__", "alignof", "offsetof"}
_NOT_ASSERTS = {"static_assert", "_Static_assert"}
_ASSERTISH = re.compile(r"(?i)(?:^|_)assert(?:$|_|[A-Z0-9])|^BUG_ON$|^DCHECK\w*$|^g_assert\w*$")
_READER = re.compile(r"(?i)(?:read|recv|parse|decode|fetch|get_?u?int|unpack)")
_DEF_HEAD = re.compile(rf"^\s*(?!#)[A-Za-z_][\w\s\*&]*?\b({_IDENT})\s*\(")


# ---- lexing helpers --------------------------------------------------------------------------

def strip_code(text: str) -> str:
    """Blank out comments and string/char literal CONTENTS, preserving line structure, so braces and
    parentheses inside them never confuse the structural scan."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j])); i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(c + " " * (min(j, n) - i - 1) + (c if j < n and text[j] == c else ""))
            i = j + 1 if j < n and text[j] == c else j
        else:
            out.append(c); i += 1
    return "".join(out)


def _call_args(text: str, open_paren: int):
    """(args list, end index) for the call whose '(' is at `open_paren`; None if unbalanced."""
    depth, start, args = 0, open_paren + 1, []
    for k in range(open_paren, min(len(text), open_paren + 4000)):
        ch = text[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                args.append(text[start:k].strip())
                return args, k
        elif ch == "," and depth == 1:
            args.append(text[start:k].strip()); start = k + 1
    return None


def _idents(expr: str) -> set:
    """Identifiers that carry a RUNTIME value in an expression. `sizeof(...)`, keywords, ALL_CAPS
    constants and called function NAMES are dropped. In a member chain (`a->len`, `a.b.len`) only
    the LEAF is kept: the length is `len`, not the pointer `a` it hangs off -- treating the base as
    the value would mistake a field of a parameter for the parameter, and let any unrelated
    `if (!a)` pass for a bounds check."""
    e = re.sub(r"\bsizeof\s*\([^()]*\)", " ", expr or "")
    out = set()
    for m in re.finditer(_IDENT, e):
        tok, rest = m.group(0), e[m.end():]
        if tok in _KEYWORDS or re.fullmatch(r"[A-Z0-9_]+", tok):
            continue
        if re.match(r"\s*(?:->|\.(?!\d))\s*[A-Za-z_]", rest):   # a base of a member access
            continue
        if re.match(r"\s*\(", rest):                           # a called function's name
            continue
        out.add(tok)
    return out


def _is_constant(expr: str) -> bool:
    return not _idents(expr)


# ---- structure: macros and function bodies -------------------------------------------------

def discover_assert_macros(texts) -> set:
    """Names that behave as assertions in this tree: `assert`, every `#define` named like an
    assertion, and (to a fixpoint) every `#define` whose expansion invokes one of those."""
    defines = {}
    for text in texts:
        lines = text.split("\n")
        i = 0
        while i < len(lines):
            m = re.match(rf"\s*#\s*define\s+({_IDENT})\s*\(([^)]*)\)(.*)", lines[i])
            if m:
                body = m.group(3)
                while body.rstrip().endswith("\\") and i + 1 < len(lines):
                    i += 1
                    body = body.rstrip()[:-1] + " " + lines[i]
                defines[m.group(1)] = body
            i += 1
    asserts = {"assert"} | {n for n in defines if _ASSERTISH.search(n)
                            and not re.search(r"(?i)assert(?:ing|ed)_", n)}
    asserts -= _NOT_ASSERTS
    # A macro is an assertion only if its body IS one: it forwards its first argument into an
    # assertion (`X(c) Y((c), ...)`), or it is `if (!(c)) abort_like(...)`. A macro that merely
    # CONTAINS an assertion among other work (a typed write helper, an event definition) is not.
    changed = True
    while changed:
        changed = False
        for name, body in defines.items():
            if name in asserts or name in _NOT_ASSERTS:
                continue
            b = re.sub(r"\bdo\s*\{|\}\s*while\s*\(\s*0\s*\)", " ", body).strip().rstrip(";").strip()
            b = b.strip("()").strip() if b.startswith("(") and b.endswith(")") else b
            m = re.match(rf"^({_IDENT})\s*\(", b)
            if m and m.group(1) in asserts and b.rstrip(" ;").endswith(")") \
                    and b.count(";") <= 1:
                asserts.add(name); changed = True
                continue
            m = re.match(rf"^if\s*\(\s*!\s*\(?.*?\)?\s*\)\s*({_IDENT})\s*\(", b)
            if m and re.search(r"(?i)abort|assert|fatal|panic|die|bug", m.group(1)) \
                    and b.count(";") <= 1:
                asserts.add(name); changed = True
    return asserts


def functions(code: str):
    """Yield (name, params:list, body_start_line, body_end_line, body_text) for each function
    DEFINITION in stripped code (header may span lines; `static inline` helpers in headers too)."""
    lines = code.split("\n")
    i = 0
    while i < len(lines):
        m = _DEF_HEAD.match(lines[i])
        if not m or m.group(1) in _KEYWORDS:
            i += 1
            continue
        # gather the header until its parenthesis closes
        head, j = lines[i], i
        while head.count("(") > head.count(")") and j + 1 < len(lines) and j - i < 8:
            j += 1
            head += " " + lines[j]
        tail = head[head.rfind(")") + 1:].strip() if ")" in head else ";"
        nxt = lines[j + 1].strip() if j + 1 < len(lines) else ""
        if tail.startswith("{") or (tail == "" and nxt.startswith("{")):
            pm = re.search(rf"\b{re.escape(m.group(1))}\s*\((.*)\)", head)
            params = []
            for part in (pm.group(1) if pm else "").split(","):
                toks = re.findall(_IDENT, part)
                if toks and part.strip() not in ("void", "..."):
                    params.append(toks[-1])
            # body: brace-match from the first '{' after the header
            bl = j if tail.startswith("{") else j + 1
            depth, k, end = 0, bl, None
            while k < len(lines):
                for ch in lines[k]:
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            end = k
                            break
                if end is not None:
                    break
                k += 1
            if end is None:
                return
            yield m.group(1), params, bl, end, "\n".join(lines[bl:end + 1])
            i = end + 1
            continue
        i = j + 1


_CMP = r"(<=|>=|<|>|==|!=)"


def _bounds_in(cond: str, ids: set) -> bool:
    """True when `cond` really BOUNDS one of `ids`: a comparison against anything other than a
    literal 0 (an emptiness test `n > 0` / `!n` bounds nothing), or the value passed to a
    validating call inside the condition (`if (!check_len(s, n))`)."""
    for x in ids:
        xe = re.escape(x)
        for m in re.finditer(rf"\b{xe}\b\s*{_CMP}\s*([^&|?:;,)]+)", cond):
            if not re.fullmatch(r"\s*\(?\s*(?:\(\w+\)\s*)?0[uUlL]*\s*\)?\s*", m.group(2)):
                return True
        for m in re.finditer(rf"([^&|?:;,(]+?)\s*{_CMP}\s*\b{xe}\b", cond):
            if not re.fullmatch(r"\s*\(?\s*(?:\(\w+\)\s*)?0[uUlL]*\s*\)?\s*", m.group(1)):
                return True
        for m in re.finditer(rf"\b({_IDENT})\s*\(", cond):
            if m.group(1) in _KEYWORDS:
                continue
            got = _call_args(cond, m.end() - 1)
            if got and any(re.search(rf"\b{xe}\b", a) for a in got[0]):
                return True
    return False


def _guard_kind(line: str, ids: set, asserts: set):
    """'assert' when `line` is an assertion STATEMENT whose condition mentions one of `ids`; 'real'
    when a branch condition (if/while/for/ternary) actually bounds one, or a min/clamp assigns it;
    else None."""
    if not ids or not any(re.search(rf"\b{re.escape(x)}\b", line) for x in ids):
        return None
    sm = re.match(rf"\s*({_IDENT})\s*\(", line)
    if sm and sm.group(1) in asserts:
        got = _call_args(line, sm.end() - 1)
        cond = " ".join(got[0]) if got else line[sm.end():]
        if any(re.search(rf"\b{re.escape(x)}\b", cond) for x in ids):
            return "assert"
    # A capacity-ensuring call on a growable buffer IS the real bound (grow-then-write is the
    # stream API's contract): Stream_EnsureRemainingCapacity(s, n) / Stream_EnsureCapacity(s, n),
    # and realloc/resize helpers, whose length argument shares an ident with what we write.
    for m in re.finditer(rf"\b({_IDENT})\s*\(", line):
        nm = m.group(1)
        if nm in _KEYWORDS:
            continue
        if re.search(r"(?i)ensure.*capacity|_grow|_resize|_reserve|realloc", nm):
            got = _call_args(line, m.end() - 1)
            if got and any(re.search(rf"\b{re.escape(x)}\b", a) for x in ids for a in got[0]):
                return "real"
    bm = re.search(r"\b(?:if|while|for)\s*\(", line)
    if bm:
        got = _call_args(line, bm.end() - 1)
        cond = " ".join(got[0]) if got else line[bm.end():]
        if _bounds_in(cond, ids):
            return "real"
    if "?" in line and _bounds_in(line.split("?")[0], ids):
        return "real"
    if re.search(r"(?i)\b\w*(?:min|clamp)\w*\s*\(", line):
        return "real"
    return None


# ---- the scan ----------------------------------------------------------------------------------

def scan_texts(files) -> list:
    """`files`: iterable of (label, text). Returns finding dicts."""
    files = [(lbl, strip_code(t)) for lbl, t in files]
    asserts = discover_assert_macros(t for _, t in files)
    funcs = []
    for lbl, code in files:
        for name, params, b0, b1, body in functions(code):
            funcs.append((lbl, name, params, b0, b1, body))

    # pass 1: assert-guarded copy WRAPPERS -- length is a parameter guarded only by an assertion
    wrappers = {}                                        # name -> (param index, where, guard line)
    for lbl, name, params, b0, _b1, body in funcs:
        blines = body.split("\n")
        for li, line in enumerate(blines):
            for m in _COPY_RE.finditer(line):
                got = _call_args(line + "\n" + "\n".join(blines[li + 1:li + 6]), m.end() - 1)
                if not got:
                    continue
                args = got[0]
                pos = _COPIES[m.group(1)]
                if len(args) <= pos:
                    continue
                pids = _idents(args[pos]) & set(params)
                if not pids:
                    continue
                kinds = [(_guard_kind(blines[g], pids, asserts), g) for g in range(li)]
                if any(k == "real" for k, _ in kinds):
                    continue
                ag = [g for k, g in kinds if k == "assert"]
                if ag:
                    p = sorted(pids)[0]
                    wrappers[name] = (params.index(p), f"{lbl}:{b0 + ag[-1] + 1}",
                                      blines[ag[-1]].strip()[:160])
    # transitive: a function that forwards an unchecked parameter into a wrapper is a wrapper too
    for _ in range(3):
        added = False
        for lbl, name, params, b0, _b1, body in funcs:
            if name in wrappers:
                continue
            for w, (pi, where, gl) in list(wrappers.items()):
                for m in re.finditer(rf"\b{re.escape(w)}\s*\(", body):
                    got = _call_args(body, m.end() - 1)
                    if not got or len(got[0]) <= pi:
                        continue
                    pids = _idents(got[0][pi]) & set(params)
                    if not pids:
                        continue
                    pre = body[:m.start()].split("\n")
                    if any(_guard_kind(ln, pids, asserts) == "real" for ln in pre):
                        continue
                    wrappers[name] = (params.index(sorted(pids)[0]), where, gl)
                    added = True
                    break
                if name in wrappers:
                    break
        if not added:
            break

    findings: list = []
    seen = set()
    # pass 2: CALL SITES passing a length the caller never checked with a real branch
    for lbl, name, params, b0, _b1, body in funcs:
        for w, (pi, where, gl) in wrappers.items():
            if w == name:
                continue
            for m in re.finditer(rf"\b{re.escape(w)}\s*\(", body):
                got = _call_args(body, m.end() - 1)
                if not got or len(got[0]) <= pi:
                    continue
                arg = got[0][pi]
                ids = _idents(arg)
                if not ids or _is_constant(arg):
                    continue
                if ids & set(params):                    # the obligation passes to OUR callers
                    continue
                # The "length" must not be the destination buffer/stream itself: a wrapper whose
                # buffer and length arguments share a base (`rdg_write_packet(ctx, s)` where `s` is
                # the wStream, mis-propagated as a length) is not a length-controlled copy.
                buf0 = _idents((got[0][0] if got[0] else ""))
                if ids & buf0:
                    continue
                pre_lines = body[:m.start()].split("\n")
                if any(_guard_kind(ln, ids, asserts) == "real" for ln in pre_lines):
                    continue
                line_no = b0 + len(pre_lines)
                key = (lbl, line_no, w)
                if key in seen:
                    continue
                buf = (got[0][0] if got[0] else "").strip()
                fixed = _fixed_capacity(body[:m.start()], buf)
                # A GROWABLE-buffer wrapper (the Stream_* API, whose destination auto-grows) is only
                # a real out-of-bounds write when the destination is FIXED-size (Stream_New with a
                # literal, or a stack buffer). Without that, grow-then-write makes the copy safe and
                # the assert is just the API's last-line check -- not a bug. Non-stream custom copy
                # helpers (no auto-grow) still fire without a fixed-cap proof.
                if w.startswith("Stream_") and fixed is None:
                    continue
                seen.add(key)
                findings.append(_mk(lbl, line_no, name, w, arg, where, gl, fixed))
    # pass 3: direct assert-then-copy inside one function (length not a parameter)
    for lbl, name, params, b0, _b1, body in funcs:
        blines = body.split("\n")
        for li, line in enumerate(blines):
            for m in _COPY_RE.finditer(line):
                got = _call_args(line + "\n" + "\n".join(blines[li + 1:li + 6]), m.end() - 1)
                if not got or len(got[0]) <= _COPIES[m.group(1)]:
                    continue
                arg = got[0][_COPIES[m.group(1)]]
                ids = _idents(arg) - set(params)
                if not ids:
                    continue
                kinds = [(_guard_kind(blines[g], ids, asserts), g) for g in range(li)]
                if any(k == "real" for k, _ in kinds):
                    continue
                ag = [g for k, g in kinds if k == "assert"]
                if not ag:
                    continue
                line_no = b0 + li + 1
                key = (lbl, line_no, m.group(1))
                if key not in seen:
                    seen.add(key)
                    findings.append(_mk(lbl, line_no, name, m.group(1), arg,
                                        f"{lbl}:{b0 + ag[-1] + 1}", blines[ag[-1]].strip()[:160],
                                        _fixed_capacity("\n".join(blines[:li]),
                                                        (got[0][0] or "").strip())))
    # pass 4: reachable assertion on a value just read from input (the abort half)
    for lbl, name, params, b0, _b1, body in funcs:
        blines = body.split("\n")
        read_into = {}                                   # var -> line index it was read at
        for li, line in enumerate(blines):
            for m in re.finditer(rf"\b({_IDENT})\s*\(", line):
                if not _READER.search(m.group(1)) or m.group(1) in asserts:
                    continue
                got = _call_args(line, m.end() - 1)
                outs = set()
                if got:
                    for a in got[0][1:]:
                        a = a.strip()
                        if a.startswith("&"):
                            outs |= _idents(a)
                        elif re.fullmatch(_IDENT, a):
                            outs.add(a)         # macro-style reader taking the target by name
                lhs = re.match(rf"\s*(?:[\w\s\*]+\s)?({_IDENT})\s*=\s*{re.escape(m.group(1))}\s*\(",
                               line)
                if lhs:
                    outs.add(lhs.group(1))
                for v in outs - set(params):
                    read_into.setdefault(v, li)
            if not read_into:
                continue
            for a in asserts:
                am = re.search(rf"\b{re.escape(a)}\s*\(", line)
                if not am:
                    continue
                got = _call_args(line, am.end() - 1)
                cond = " ".join(got[0]) if got else ""
                hit = [v for v, ri in read_into.items()
                       if ri < li and re.search(rf"\b{re.escape(v)}\b", cond)]
                if not hit:
                    continue
                v = hit[0]
                if any(_guard_kind(blines[g], {v}, asserts) == "real"
                       for g in range(read_into[v] + 1, li)):
                    continue
                line_no = b0 + li + 1
                key = (lbl, line_no, "assert")
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "cwe": "CWE-617", "severity": "medium",
                    "title": f"Reachable assertion on input-derived '{v}' in {name}() (CWE-617)",
                    "dedup_key": f"assertguard:reach:{lbl}:{line_no}:{v}",
                    "file": lbl, "line": line_no,
                    "evidence": [{"channel": "source",
                                  "detail": f"{lbl}:{line_no}: {a}() tests '{v}', read from input "
                                            f"at line {b0 + read_into[v] + 1} with no real check in "
                                            "between -- the process aborts when the input violates "
                                            "it (where the assertion is compiled in)"}]})
                break
    return findings


def _fixed_capacity(prefix: str, buf_expr: str):
    """Evidence that the destination buffer has a FIXED size in this function: `T buf[N]` or
    `buf = Something_New(..., N)` / `malloc(N)` with a literal N. Returns N or None."""
    base = re.match(rf"\s*&?\s*({_IDENT})", buf_expr or "")
    if not base:
        return None
    b = re.escape(base.group(1))
    m = re.search(rf"\b{b}\s*\[\s*(\d+)\s*\]", prefix) or \
        re.search(rf"\b{b}\s*=\s*\w+\s*\([^;]*?\b(\d{{2,}})\s*\)\s*;", prefix)
    return int(m.group(1)) if m else None


def _mk(lbl, line_no, func, sink, arg, guard_where, guard_line, fixed) -> dict:
    cap = f" into a fixed {fixed}-byte buffer" if fixed else ""
    detail = (f"{lbl}:{line_no}: {func}() passes length '{arg}' to {sink}(){cap}; the only bound "
              f"on it is an assertion ({guard_where}: `{guard_line}`) -- compiled out in release "
              "builds (unchecked copy), an abort where kept (CWE-617)")
    return {"cwe": "CWE-787", "severity": "high" if fixed else "medium",
            "title": f"Assert-only bounds check: {func}() -> {sink}() length '{arg[:40]}'",
            "dedup_key": f"assertguard:{lbl}:{line_no}:{sink}",
            "file": lbl, "line": line_no, "fixed": fixed,
            "evidence": [{"channel": "source", "detail": detail}]}


def scan_source(root: Path) -> list:
    return scan_texts((lbl, text) for lbl, _p, text in source_files(root))


# ---- stage -------------------------------------------------------------------------------------

def assert_guard_stage(ctx) -> dict:
    import io
    import tarfile

    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("assert_guard_scan requires a target_id")
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        ctx.emit("assert_guard.done", payload={"applicable": False,
                 "note": "no archived source tree (this detector reads C/C++ source)"})
        return {}
    root = ctx.scratch() / "assert_guard"
    root.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                          mode="r:gz") as tf:
            for mem in tf.getmembers():
                if mem.isfile() and not mem.name.startswith("/") and ".." not in mem.name:
                    tf.extract(mem, root)
    except Exception:                                    # noqa: BLE001
        ctx.emit("assert_guard.done", payload={"applicable": False,
                 "note": "could not unpack the archived source tree"})
        return {}
    ctx.progress(msg="scanning for assertion-only bounds checks")
    findings = scan_source(root)
    fd = FindingDAO(ctx.conn)
    for f in findings:
        fd.upsert(target.id, target.case_id, {
            "cwe": f["cwe"], "severity": f["severity"], "detector": "assert_guard",
            "title": f["title"], "evidence": f["evidence"], "function_addr": None,
            "site_addr": None, "dedup_key": f["dedup_key"],
            "site_detail": f"{f['file']}:{f['line']}", "state": "candidate",
            "confidence": 0.55 if f.get("fixed") else 0.45})
    ctx.emit("assert_guard.done", payload={"applicable": True, "findings": len(findings)})
    ctx.progress(pct=100, msg=f"{len(findings)} assertion-only bounds candidate(s)")
    return {"metrics": {"findings": len(findings)}}


def register() -> None:
    register_stage(ASSERT_GUARD_STAGE, assert_guard_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_assert_guard_scan(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, ASSERT_GUARD_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="quick", force=force)
