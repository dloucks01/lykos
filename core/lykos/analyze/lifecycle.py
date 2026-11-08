"""Type-state lifecycle analysis (static gap 3) — use-after-free / double-free (CWE-416/415).

The confirmed-bug hunt could not harness UAF single-shot (it needs an alloc->free->use sequence).
A static type-state walk finds them directly: track each pointer's state (freed after free(p) /
*_free(p)), and flag a USE (deref p->x / *p / p[i] / passing p to a call) or a SECOND free while the
pointer is in the freed state, with no intervening reassignment (p = ... / p = NULL) that revives it.

Precision (the earlier version over-fired ~740 on FreeRDP, all false): the freed set is keyed by the
WHOLE pointer expression (`ctx->buffer`, not a bare `buffer`), so freeing `a->buf` never implicates
an unrelated `b->buf`; a use must name that same whole expression; reassigning the expression OR its
container pointer revives it; and a `free`-like call only arms a UAF for operands that are plain
pointer lvalues (not a freed sub-object the container still owns). Intraprocedural and conservative:
leaving the function clears all state. Pure/testable; recall-first, precision from the kills above.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .dispatcher_harness import _functions
from .wire_flow import _strip_comments

#: a deallocation call: function name + the full argument list (parsed by _free_targets, which
#: applies the context-handle and address-of heuristics). The `\w+_free`/`\w+_Free` breadth stays
#: for recall.
_FREE_CALL = re.compile(r"\b(free|_aligned_free|winpr_aligned_free|\w+_free|\w+_Free|Stream_Free|"
                        r"freerdp_\w*_free)\s*\(")
#: used only as a cheap "is there any free on this line" guard.
_FREE = _FREE_CALL
_ASSIGN = re.compile(r"(?<![=!<>])\b([A-Za-z_][\w.\[\]\->]*)\s*=(?!=)")
#: a second-arg literal that means the first arg really IS the freed object (Stream_Free(s, TRUE)),
#: as opposed to a pointer second arg that marks the first as an allocator/context (png_free(ctx,p)).
_BOOL_LIT = re.compile(r"^(?:TRUE|FALSE|true|false|NULL|0|1|-?\d+|sizeof\b)")
_CAST = re.compile(r"^\(\s*[A-Za-z_][\w ]*\**\s*\)\s*")   # a leading (type*) cast on an argument


def _args(s: str) -> list:
    """Split a call's argument text on top-level commas."""
    out, depth, cur = [], 0, []
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur)); cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur))
    return [a.strip() for a in out]


#: bare, unambiguous single-object deallocators — these dangle their pointer argument even inside a
#: destructor. A `\w+_free` WRAPPER inside a destructor is usually a sub-destructor (frees members of
#: the argument, not the argument), so it does not dangle the arg there.
_BARE_FREE = re.compile(r"^(?:free|_aligned_free|winpr_aligned_free|Stream_Free)$")


def _free_targets(line: str):
    """Yields (expr, revived, wrapper) pointer operands freed on `line`. `revived` is True for a
    free-through-address wrapper (`free_and_null(&p)`) which nulls the pointer rather than dangling
    it; `wrapper` is True for a `\\w+_free`/`\\w+_Free` call (vs a bare free). Applies: a leading cast
    is stripped; for a multi-arg `\\w+_free` wrapper whose first arg is a pointer and whose next arg
    is ALSO a pointer (not a bool/size literal), the first arg is an allocator/context handle
    (png_free(ctx, obj)), so the OBJECT (a later pointer arg) is freed, not the context."""
    for m in _FREE_CALL.finditer(line):
        wrapper = not bool(_BARE_FREE.match(m.group(1)))
        # grab the balanced argument list after the '('
        i = m.end() - 1
        depth, j, n = 0, i, len(line)
        while j < n:
            if line[j] == "(":
                depth += 1
            elif line[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        args = _args(line[i + 1:j])
        if not args:
            continue

        def clean(a):
            a = _CAST.sub("", a).strip()
            rev = a.startswith("&")
            a = a.lstrip("& ")
            mm = re.match(r"[A-Za-z_][\w.\[\]\->]*", a)
            return (mm.group(0) if mm else None, rev)

        first, rev = clean(args[0])
        if first is None:
            continue
        # context-handle: name ends in _free/_Free, >1 arg, and the 2nd arg is itself a pointer
        # expression (not a bool/size literal) -> first is the pool/context, the object is a later
        # pointer arg. We then free the LAST pointer-looking arg instead.
        if len(args) > 1 and not _BOOL_LIT.match(args[1].lstrip("(")):
            obj = None
            for a in args[1:]:
                c, r = clean(a)
                if c:
                    obj = (c, r)
            if obj:
                yield (obj[0], obj[1], wrapper)
                continue
            # no clean object operand -> skip (don't blame the context handle)
            continue
        yield (first, rev, wrapper)


@dataclass
class LifecycleBug:
    function: str
    ptr: str
    kind: str                      # "use-after-free" | "double-free"
    free_line: int
    bad_line: int
    hint: str


def _norm(expr: str) -> str:
    """Canonical form of a pointer lvalue for matching: drop whitespace and a trailing array index
    so `p [i]` and `p[i]` and `p[0]` compare on the base element expression `p`."""
    e = re.sub(r"\s+", "", expr)
    e = re.sub(r"\[[^\]]*\]$", "", e)        # p[i] -> p (freeing/using the pointer itself)
    return e


def _container(expr: str) -> str:
    """The root pointer a member expression hangs off: `ctx->fmt->buf` -> `ctx`. Reassigning the
    root invalidates every freed-member fact under it."""
    return re.split(r"->|\.|\[", expr, maxsplit=1)[0]


def _uses(expr: str, line: str) -> bool:
    """`line` dereferences / passes the exact freed expression `expr`."""
    p = re.escape(expr)
    # expr->field, expr.field, expr[i]
    if re.search(p + r"\s*(?:->|\.|\[)", line):
        return True
    # *expr
    if re.search(r"\*\s*" + p + r"\b", line):
        return True
    # expr passed as an argument to a (non-free) call: fn(..., expr, ...)
    if re.search(r"\b[a-z_]\w*\s*\([^;]*\b" + p + r"\b", line) and not _FREE.search(line):
        return True
    return False


#: a preprocessor conditional boundary; a free on each side of one is branch-exclusive, not a
#: double-free (the #if/#else platform frees like winpr_*_backtrace_free).
_CPP_COND = re.compile(r"^\s*#\s*(?:if|ifdef|ifndef|elif|else|endif)\b")
#: an UNCONDITIONAL control-flow sever (not an inline `if (e) return;`, which is conditional) or a
#: switch case/label. Anything freed before such a line, at the same-or-shallower brace depth, is on
#: a different path from code after it -- the switch-case and early-return exclusive-free patterns.
_SEVER = re.compile(r"^\s*(?:break|return|continue|goto)\b")
_LABEL = re.compile(r"^\s*(?:case\b|default\s*:)")


def _depths(lines):
    """Brace depth at the START of each line (string/char braces are rare in comment-stripped C
    bodies and ignored)."""
    out = []
    d = 0
    for ln in lines:
        out.append(d)
        d += ln.count("{") - ln.count("}")
    return out


#: a destructor: a function whose job is to tear down the object passed to it. A `*_free` wrapper
#: call inside one is a sub-destructor of a member, not a dangle of the destructor's own argument.
#: The teardown verb may appear anywhere as a word (freerdp_settings_free_internal, *_free_keys,
#: *_clear, *_uninit), not only as the suffix.
_DESTRUCTOR = re.compile(r"(?:^|_)(?:free|destroy|clear|uninit|dispose|cleanup|release|fini)(?:_|$)",
                         re.I)


def _norm_free(expr: str) -> str:
    """Free-operand key: whitespace-stripped but KEEPS the array subscript, so freeing an element
    `arr[i]` is a different object from freeing the array `arr` (the destructor loop pattern)."""
    return re.sub(r"\s+", "", expr)


def find_lifecycle_bugs(src: str) -> list:
    out = []
    for name, _s, _p, raw in _functions(src):
        is_destructor = bool(_DESTRUCTOR.search(name or ""))
        body = _strip_comments(raw)
        lines = body.splitlines()
        cpp = [bool(_CPP_COND.match(ln)) for ln in lines]
        depth = _depths(lines)
        sever = [bool(_SEVER.match(ln)) or bool(_LABEL.match(ln)) for ln in lines]
        label = [bool(_LABEL.match(ln)) for ln in lines]
        # a break/return/continue/goto anywhere on the line (handles `case X: free(p); break;`).
        tail = [bool(re.search(r"\b(?:break|return|continue|goto)\b", ln)) for ln in lines]
        freed: dict = {}                                 # normalized expr -> line index of the free

        def _severed(a, b):                              # control cannot flow straight-line a -> b
            if tail[a] or label[b]:
                return True                              # free's own line ends control / b is a new case
            for k in range(a + 1, b):
                if cpp[k]:
                    return True                          # a #if/#else arm boundary
                if sever[k] and depth[k] <= depth[a]:
                    return True                          # unconditional break/return/case at <= depth
            return False

        # kept as the old name so both checks below read naturally.
        _cpp_between = _severed

        for i, line in enumerate(lines):
            # A reassignment of a freed expr, or of its container pointer, revives it (p = NULL,
            # p = realloc(...), etc.). free(&p) is handled as a revive in _free_targets.
            if not _FREE.search(line):
                for am in _ASSIGN.finditer(line):
                    lv = _norm(am.group(1))
                    for key in list(freed):
                        if key == lv or _container(key) == lv:
                            del freed[key]
            # Deallocations on this line.
            for operand, revived, wrapper in _free_targets(line):
                operand = _norm_free(operand)
                if revived:                              # free_and_null(&p): nulls p -> not dangling
                    freed.pop(operand, None)
                    continue
                if wrapper and is_destructor:
                    # a sub-destructor inside a destructor frees a MEMBER, not this function's own
                    # argument -- do not mark the operand dangling (the member-teardown FP).
                    continue
                if operand in freed and not _cpp_between(freed[operand], i):
                    out.append(LifecycleBug(name, operand, "double-free", freed[operand], i,
                                            line.strip()[:80]))
                freed[operand] = i
            # Uses of a still-freed expr (not the free line itself, and not across a #if arm).
            for key in list(freed):
                if freed[key] != i and _uses(key, line) and not _cpp_between(freed[key], i):
                    out.append(LifecycleBug(name, key, "use-after-free", freed[key], i,
                                            line.strip()[:80]))
                    del freed[key]                       # report once
    return out
