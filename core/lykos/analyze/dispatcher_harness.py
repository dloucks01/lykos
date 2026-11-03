"""Reach internal parsers behind a dispatcher -- capability #2 (the structural unlock).

A protocol/codec library's bugs live in `static` sub-parsers reached only through a DISPATCHER: one
function that reads a tag off the wire and `switch`es to ~N sub-parsers (FreeRDP's
`rdpgfx_recv_pdu` -> wire_to_surface / cache / solidfill / ...; the audin / cliprdr channel recv
loops). lykos's `driver_synth` needs an EXPORTED `(buf,size)`/stream entry, which these are not, so
the whole channel surface was unreachable. Getting there by hand this engagement took three steps,
which this module makes mechanical:

  1. DETECT the dispatcher (a `switch` on a wire-read tag fanning out to sub-parser calls) -- the
     ideal single harness entry, because one driver then reaches every sub-parser.
  2. EXPOSE it: a `static` dispatcher hidden by `-fvisibility=hidden` is rewritten to carry
     `__attribute__((visibility("default")))` so a rebuilt library exports it (linkage only -- the
     bug is unchanged).
  3. SCAFFOLD the context the dispatcher dereferences (the plugin/`context` structs, a logger, a
     hash table, a settings object via the project's own exported constructor), mined into a recipe,
     and emit a libFuzzer driver that builds a stream from the fuzz bytes and calls the dispatcher.

Pure string/AST work here (detection, the source rewrite, and the emitted C); the rebuild + link +
fuzz is done by the stage that consumes this, exactly as proven on FreeRDP's rdpgfx dispatcher.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

#: a C `switch (<expr>)`; we care about the switched expression (often `header.cmdId` / `msgType`).
_SWITCH = re.compile(r"\bswitch\s*\(\s*([A-Za-z_][\w.\->]*)\s*\)")
#: a `case <CONST>:` label.
_CASE = re.compile(r"\bcase\s+([A-Za-z_]\w*)\s*:")
#: a call `fn(args)` inside a case -- the sub-parser; we take the callee name.
_CALL = re.compile(r"\b([a-z_]\w*(?:_recv|_process|_read|_pdu|_decode|_parse)\w*)\s*\(")
#: an optional run of leading specifiers before the return type: __attribute__((...)), an ALLCAPS
#: export macro (FREERDP_API, WINPR_API), or `static`/`inline`.
_SPECIFIERS = r"(?:__attribute__\s*\(\(.*?\)\)\s*|[A-Z][A-Z0-9_]*_API\s+|static\s+|inline\s+)*"
#: a function definition header: `[specifiers] <ret...> name(<params>)` just before a `{`.
_FUNC_HDR = re.compile(r"(^|\n)([ \t]*)(" + _SPECIFIERS + r"[A-Za-z_][\w \t\*]*?)\b([A-Za-z_]\w*)\s*\(([^;{]*)\)\s*\{",
                       re.S)


@dataclass
class Dispatcher:
    name: str
    tag: str                       # the switched expression (the wire tag)
    subparsers: list               # distinct sub-parser callee names reached from the cases
    is_static: bool
    params: list = field(default_factory=list)


def _split_params(s: str) -> list:
    s = s.strip()
    if not s or s == "void":
        return []
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "(<":
            depth += 1
        elif ch in ")>":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip()); cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _functions(src: str) -> list:
    """(name, is_static, params, body) for each C function definition in `src` (brace-matched)."""
    out = []
    for m in _FUNC_HDR.finditer(src):
        ret, name, params = m.group(3), m.group(4), m.group(5)
        if name in ("if", "for", "while", "switch", "sizeof", "return", "do"):
            continue
        # brace-match the body from the opening '{'
        i = m.end() - 1
        depth, j = 0, i
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body = src[i:j + 1]
        out.append((name, "static" in ret.split(), _split_params(params), body))
    return out


def find_dispatchers(src: str, *, min_cases: int = 3) -> list:
    """Dispatchers in `src`: a function with a `switch` on a tag whose cases call >= `min_cases`
    distinct sub-parsers. The switched expression is the wire tag the harness drives to select a
    sub-parser; the callee list is the surface one driver reaches."""
    out = []
    for name, is_static, params, body in _functions(src):
        sw = _SWITCH.search(body)
        if not sw:
            continue
        subs = []
        for cm in _CASE.finditer(body):
            seg = body[cm.end():cm.end() + 400]          # the case's leading statements
            call = _CALL.search(seg)
            if call and call.group(1) != name and call.group(1) not in subs:
                subs.append(call.group(1))
        if len(subs) >= min_cases:
            out.append(Dispatcher(name=name, tag=sw.group(1), subparsers=subs,
                                   is_static=is_static, params=params))
    return out


_STATIC_DECL = re.compile(r"(^|\n)([ \t]*)static\s+(?=[A-Za-z_][\w \t\*]*\b%s\s*\()")


def expose_static(src: str, fn: str) -> str:
    """Rewrite `fn`'s definition so a rebuilt shared library EXPORTS it: drop `static` and prepend
    `__attribute__((visibility("default")))`, defeating the project's `-fvisibility=hidden`. Linkage
    only -- the function body (and the bug) is untouched. Idempotent. This is the exact transform
    done by hand to reach FreeRDP's `rdpgfx_recv_pdu`."""
    attr = '__attribute__((visibility("default"))) '
    pat = re.compile(r"(^|\n)([ \t]*)static\s+([A-Za-z_][\w \t\*]*?\b" + re.escape(fn) + r"\s*\()")
    if attr + fn not in src:
        new, n = pat.subn(lambda m: f"{m.group(1)}{m.group(2)}{attr}{m.group(3)}", src, count=1)
        if n:
            return new
    # already non-static: still ensure it is exported
    if attr not in src:
        pat2 = re.compile(r"(^|\n)([ \t]*)([A-Za-z_][\w \t\*]*?\b" + re.escape(fn) + r"\s*\()")
        new, n = pat2.subn(lambda m: f"{m.group(1)}{m.group(2)}{attr}{m.group(3)}", src, count=1)
        if n:
            return new
    return src


@dataclass
class ContextRecipe:
    """How to build the opaque context a dispatcher dereferences, mined from the project (or given).
    `includes` are headers the harness needs; `setup_c` is the C that constructs the context and
    assigns the callback/plugin pointers the dispatcher reads; `call_c` invokes the dispatcher with
    the built stream. `stream_param_index` is which dispatcher parameter takes the wStream."""
    includes: list
    setup_c: str
    call_expr: str                 # e.g. "rdpgfx_recv_pdu(&cb, s)"


def synth_dispatcher_harness(recipe: ContextRecipe) -> str:
    """A libFuzzer driver that builds a WinPR stream from the fuzz bytes, constructs the context via
    `recipe.setup_c`, and calls the dispatcher via `recipe.call_expr`. The stage that consumes this
    rebuilds the library with the dispatcher exposed and links the driver against it."""
    inc = "\n".join(f"#include {h}" for h in recipe.includes)
    return (f"""#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <winpr/stream.h>
{inc}

{recipe.setup_c}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < 1) return 0;
    wStream* s = Stream_New(NULL, size);
    if (!s) return 0;
    Stream_Write(s, data, size);
    Stream_SealLength(s);
    Stream_SetPosition(s, 0);
    {recipe.call_expr};
    Stream_Free(s, TRUE);
    return 0;
}}
""")
