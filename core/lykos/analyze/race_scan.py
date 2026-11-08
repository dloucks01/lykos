"""Double-fetch / TOCTOU (CWE-367) and uninitialized-pointer-deref (CWE-824/457) detectors.

Two discovery classes lykos accounts for in the CWE catalog. Both are static and PRECISION-FIRST:
they flag only universal-contract violations (wrong in ANY correct program), never a shape that a
correct program also has. All reported line numbers are 1-based FILE lines.

Double-fetch: a TOCTOU between two reads of the same memory exists ONLY when that memory is
concurrently mutable by the attacker while we run -- user-space memory read from a kernel, a
MAP_SHARED / shm mapping, or a `volatile` / `__user` buffer. Re-reading an ordinary struct field
(`if (req->len > 64) return; memcpy(dst, req->data, req->len);`) is the canonical CORRECT
validate-then-use and is never flagged, whatever the variable is named. Two shapes fire:
  (a) a field of a shared-provenance base is read in an `if (...)` check and re-read, on another
      line, in a size/copy/index use;
  (b) the kernel double-copy (Wang et al.): the same user pointer is fetched twice with the
      copy_from_user / get_user family and the first fetch's result is checked or sizes the second.

Uninitialized pointer: a bare local pointer declared with NO initializer (not `static`, not an
aggregate member) whose FIRST mention in its own scope is a dereference (`*p`, `p->`, `p[`) of the
whole identifier -- `x.p->y` / `x->p[0]` are member accesses of a different object and do not count.
Any other first mention (`p = ...`, `&p`, `p` passed to a call or macro, `if (p)`) ends the scan
without a finding; derefs inside a loop that also assigns p later are not flagged (back edge).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .dispatcher_harness import _functions

#: a dangerous USE context for the second fetch.
_USE_CTX = re.compile(r"(memcpy|memmove|memset|copy_from_user|copy_to_user|alloc|malloc|realloc|"
                      r"\[\s*$|,\s*$)", re.I)
#: user-memory fetch primitives (kernel); the SOURCE argument index for each.
_USER_FETCH = re.compile(r"\b(copy_from_user|__copy_from_user|__copy_from_user_inatomic|"
                         r"raw_copy_from_user|strncpy_from_user|get_user|__get_user)\s*\(")
#: shared-mapping producers: the assigned pointer is concurrently mutable memory.
_SHARED_MAP = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*(?:\([^;()]*\)\s*)?"
                         r"(mmap|mmap64|shmat|MapViewOfFile|MapViewOfFileEx)\s*\(")
_QUAL_DECL = re.compile(r"\b(?:volatile|__user)\b[^;=(){}]*?\*\s*(?:const\s+)?([A-Za-z_]\w*)")


def _strip(s: str) -> str:
    """Comments/strings neutralised, one branch per `#if` kept -- newline count preserved."""
    s = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n") + " ", s, flags=re.S)
    s = re.sub(r"//[^\n]*", " ", s)
    s = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', s)
    s = re.sub(r"'(?:\\.|[^'\\\n])'", "''", s)
    # preprocessor: keep ONE branch of every conditional (the first; for `#if 0` the `#else`) so
    # alternative branches cannot unbalance braces or double-declare locals.
    out, stack = [], []                                  # stack of [taking_now, taken_already]
    for ln in s.split("\n"):
        t = ln.strip()
        live = all(e[0] for e in stack)
        if re.match(r"#\s*if", t):
            zero = bool(re.match(r"#\s*if\s+0\b", t))
            stack.append([not zero, not zero])
            out.append("")
            continue
        if re.match(r"#\s*(else|elif)\b", t) and stack:
            e = stack[-1]
            e[0] = not e[1]
            e[1] = True
            out.append("")
            continue
        if re.match(r"#\s*endif", t) and stack:
            stack.pop()
            out.append("")
            continue
        out.append(ln if live else "")
    return "\n".join(out)


def _functions_at(src: str):
    """(name, params, body, first_file_line) -- first_file_line is the 1-based line of body[0]."""
    cur = 0
    for name, _s, params, raw in _functions(src):
        off = src.find(raw, cur)
        if off < 0:
            off = src.find(raw)
        if off >= 0:
            cur = off + len(raw)
        body = _strip(raw)
        depth = 0                                        # truncate at the real closing brace
        for k, ch in enumerate(body):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    body = body[:k + 1]
                    break
        yield name, params, body, src[:max(off, 0)].count("\n") + 1


def _ref(expr: str) -> re.Pattern:
    """`expr` as a whole expression -- not a suffix of `x.expr` / `x->expr` / `foo_expr`."""
    return re.compile(r"(?<![\w.])(?<!->)" + re.escape(expr) + r"(?!\w)")


@dataclass
class DoubleFetch:
    function: str
    field: str
    check_line: int     # 1-based file line
    use_line: int       # 1-based file line
    hint: str


def _call_args(text: str, open_paren: int) -> list:
    """Top-level comma-split args of the call whose '(' is at `open_paren`."""
    depth, cur, args = 0, "", []
    for ch in text[open_paren:open_paren + 600]:
        if ch == "(":
            depth += 1
            if depth == 1:
                continue
        elif ch == ")":
            depth -= 1
            if depth == 0:
                args.append(cur.strip())
                return args
        if ch == "," and depth == 1:
            args.append(cur.strip()); cur = ""
        else:
            cur += ch
    return args


def _base_ident(expr: str) -> str:
    e = re.sub(r"^\s*(?:\([^()]*\)\s*)*", "", expr).lstrip("&* (")
    m = re.match(r"[A-Za-z_]\w*", e)
    return m.group(0) if m else ""


def _shared_bases(params: list, body: str) -> set:
    """Pointers whose provenance makes them concurrently mutable: volatile/__user qualified
    (params or locals), or assigned from a MAP_SHARED mmap / shmat / MapViewOfFile."""
    bases = set()
    for p in params:
        if re.search(r"\b(volatile|__user)\b", p):
            m = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", p)
            if m:
                bases.add(m.group(1))
    for m in _QUAL_DECL.finditer(body):
        bases.add(m.group(1))
    for m in _SHARED_MAP.finditer(body):
        args = _call_args(body, m.end() - 1)
        if m.group(2).startswith("mmap") and not any("MAP_SHARED" in a for a in args):
            continue
        bases.add(m.group(1))
    return bases


def _double_copy(name: str, body: str, lines: list, base_line: int) -> list:
    """Kernel double-fetch: same user pointer fetched twice, first result checked/sizes the second."""
    fetches = []                                         # (line_idx, src_base, dst_ident, args)
    for m in _USER_FETCH.finditer(body):
        args = _call_args(body, m.end() - 1)
        if len(args) < 2:
            continue
        fn = m.group(1)
        dst, src = (args[0], args[1])
        sb = _base_ident(src)
        if not sb:
            continue
        fetches.append((body[:m.start()].count("\n"), sb, _base_ident(dst), args, fn))
    out, seen = [], set()
    for i, (l1, b1, d1, _a1, _f1) in enumerate(fetches):
        for l2, b2, _d2, a2, _f2 in fetches[i + 1:]:
            if b2 != b1 or l2 == l1 or not d1 or (b1, l2) in seen:
                continue
            between = "\n".join(lines[l1 + 1:l2 + 1])
            checked = re.search(r"\bif\s*\([^;{]*" + _ref(d1).pattern, between)
            sizes = len(a2) >= 3 and _ref(d1).search(a2[2])
            if checked or sizes:
                seen.add((b1, l2))
                ck = next((k for k in range(l1 + 1, l2 + 1)
                           if re.search(r"\bif\s*\(", lines[k]) and _ref(d1).search(lines[k])), l1)
                out.append(DoubleFetch(name, b1, base_line + ck, base_line + l2,
                                       lines[l2].strip()[:80]))
    return out


def find_double_fetch(src: str) -> list:
    out = []
    for name, params, body, base_line in _functions_at(src):
        lines = body.splitlines()
        out.extend(_double_copy(name, body, lines, base_line))
        shared = _shared_bases(params, body)
        if not shared:
            continue
        reads: dict = {}
        for m in re.finditer(r"(?<![\w.])(?<!->)([A-Za-z_]\w*)(->|\.)([A-Za-z_]\w*)", body):
            if m.group(1) in shared:
                reads.setdefault(m.group(0), []).append(body[:m.start()].count("\n"))
        for fld, lns in reads.items():
            if len(lns) < 2:
                continue
            rx = _ref(fld)
            check_ln = use_ln = None
            for ln in lns:
                line = lines[ln] if ln < len(lines) else ""
                if check_ln is None and re.search(r"\bif\s*\(", line) and rx.search(line):
                    check_ln = ln
                elif check_ln is not None and ln != check_ln and _USE_CTX.search(line) \
                        and rx.search(line):
                    use_ln = ln
            if check_ln is not None and use_ln is not None:
                out.append(DoubleFetch(name, fld, base_line + check_ln, base_line + use_ln,
                                       lines[use_ln].strip()[:80]))
    return out


@dataclass
class UninitPtr:
    function: str
    ptr: str
    decl_line: int      # 1-based file line
    use_line: int       # 1-based file line
    hint: str


_NOT_TYPE = r"(?!(?:return|goto|case|else|sizeof|static|extern|typedef|do)\b)"
_PTR_DECL = re.compile(r"^\s*" + _NOT_TYPE + r"(?:(?:const|volatile|register|struct|union|enum|"
                       r"unsigned|signed)\s+)*" + _NOT_TYPE +
                       r"[A-Za-z_]\w*(?:\s+(?:const\b|\w+))?\s*\*+\s*(?:const\s+)?([A-Za-z_]\w*)\s*;")
_LOOP = re.compile(r"\b(for|while|do)\b")


def _aggregate_lines(lines: list) -> set:
    """Line indexes inside a local struct/union/enum body or a brace initializer (members, not
    locals)."""
    agg, stack, prev = set(), [], ""
    for i, ln in enumerate(lines):
        if any(stack):
            agg.add(i)
        for k, ch in enumerate(ln):
            if ch == "{":
                head = (prev + " " + ln[:k]).rstrip()
                tail = re.split(r"[;{}]", head)[-1]
                stack.append(bool(re.search(r"\b(struct|union|enum)\b", tail)) or tail.endswith("=")
                             or (stack[-1] if stack else False))
            elif ch == "}" and stack:
                stack.pop()
        prev = ln
    return agg


def _is_deref(line: str, hit) -> bool:
    """Is the identifier mention `hit` a dereference: `p->`, `p[`, or unary `*p` / `(*p)`?"""
    if re.match(r"\s*(?:->|\[)", line[hit.end():]):
        return True
    k = hit.start() - 1
    while k >= 0 and line[k] in " \t":
        k -= 1
    if k < 0 or line[k] != "*":
        return False
    k -= 1
    while k >= 0 and line[k] in " \t":
        k -= 1
    return k < 0 or not (line[k].isalnum() or line[k] in "_)]")   # binary `a * p` is not a deref


def find_uninit_ptr(src: str) -> list:
    """A bare local pointer declared with no initializer whose first mention is a dereference."""
    out = []
    for name, _params, body, base_line in _functions_at(src):
        body = re.sub(r"\bsizeof\s*\((?:[^()]|\([^()]*\))*\)", "sizeof()", body)   # unevaluated
        lines = body.splitlines()
        agg = _aggregate_lines(lines)
        for i, line in enumerate(lines):
            m = _PTR_DECL.match(line)
            if not m or i in agg:
                continue
            p = m.group(1)
            mention = _ref(p)
            depth, opened_loop = 0, False
            for j in range(i + 1, len(lines)):
                lj = lines[j]
                d = _PTR_DECL.match(lj)
                if d and d.group(1) == p:
                    break                                        # shadowing redeclaration
                if _LOOP.search(lj):
                    opened_loop = True
                hit = mention.search(lj)
                if hit:                                          # the first mention decides
                    if _is_deref(lj, hit):
                        if opened_loop and re.search(mention.pattern + r"\s*=(?!=)|&\s*"
                                                     + re.escape(p) + r"(?!\w)",
                                                     "\n".join(lines[j:])):
                            break                                # assigned on a loop back edge
                        out.append(UninitPtr(name, p, base_line + i, base_line + j,
                                             lj.strip()[:80]))
                    break
                depth += lj.count("{") - lj.count("}")
                if depth < 0:
                    break                                        # left the declaring scope
    return out
