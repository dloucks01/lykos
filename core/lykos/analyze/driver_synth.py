"""Context-aware fuzz-driver synthesis -- reach a parser the ladder cannot (doc: non-fuzzing-first).

`synth_confirm` / `libfuzzer` synthesize a driver only for a function whose every parameter is a
plain `(buf,size)`/string/number (`_opaque_param` rejects the rest). A real parser in a protocol or
format library does not look like that: it reads attacker bytes THROUGH a project stream object and
writes into a context/out struct -- e.g. FreeRDP's `recv_*(rdpContext*, wStream* s, RGNDATA* out)`,
which `Stream_Read_UINT*`s the input out of `s`. A zeroed struct cannot stand in for `s` (the parser
dereferences the stream's internal pointers), so those functions were skipped and their candidate
bugs never reached -- which is why a whole-library fuzz of the few shipped harnesses confirms nothing.

This module models the missing piece: classify each parameter (data / size / stream / context / out /
string / scalar), detect the project's STREAM idiom (the bytes carrier + its header + wrap API), and
emit a driver that builds a REAL stream from the fuzz bytes, `calloc`s the opaque context/out
structs, and calls the function. The concolic rung can then solve an input that satisfies the
stream's length guards and reaches the defect -- a confirmation WITHOUT fuzzing. Pure string/AST
work here; building + the 0-FP from-entry reachability gate live in the stage that consumes this.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StreamIdiom:
    """A project's 'bytes carrier': the pointer type a parser reads input through, the header that
    declares it, and the statements that build one from a (data,size) pair + name it `var`."""
    name: str
    type_token: str          # the pointer type as it appears in a signature, e.g. "wStream *"
    header: str              # the #include that declares the carrier + its API
    #: a callable (var, data, size) -> C statements that construct the carrier into `var`.
    wrap: "callable"
    #: substrings in a function body that mark it as reading through THIS carrier (detection signal).
    read_markers: tuple


def _wstream_wrap(var: str, data: str, size: str) -> str:
    # a real WinPR stream over the fuzz bytes, positioned at the start for reading.
    return (f"    wStream* {var} = Stream_New(NULL, {size} ? {size} : 1);\n"
            f"    if (!{var}) return 0;\n"
            f"    Stream_Write({var}, {data}, {size});\n"
            f"    Stream_SealLength({var});\n"
            f"    Stream_SetPosition({var}, 0);\n")


#: Known project stream idioms, matched by the carrier type in a signature. A project with none of
#: these but a `(const uint8_t*, size_t)` parse entry is handled by the plain (data,size) path.
STREAM_IDIOMS = (
    StreamIdiom("winpr-wStream", "wStream *", "winpr/stream.h", _wstream_wrap,
                ("Stream_Read_", "Stream_Get", "Stream_CheckAndLogRequiredLength",
                 "Stream_GetRemainingLength")),
)

_SIZE_RE = re.compile(r"\b(size_t|ssize_t|u?int\d+_t|unsigned|int|long|size|len|count|n|cb\w*)\b", re.I)
# a raw byte buffer: unsigned char / uint8_t / byte / void pointer. A bare `char *` is treated as a
# STRING (a path/mode), not a byte buffer -- `(const char *path, int flags)` is not (data,size).
_DATA_RE = re.compile(r"(const\s+)?(unsigned\s+char|u?int8_t|byte|void)\s*\*", re.I)


def _is_size(param: str) -> bool:
    low = param.lower()
    return "*" not in low and bool(_SIZE_RE.search(low))


def classify_params(params: list, idiom: "StreamIdiom | None") -> list:
    """Role of each parameter: 'stream' (the project bytes carrier), 'data'/'size' (a raw buf+len
    pair), 'string' (a char* path/mode), 'context' (an opaque struct pointer to scaffold), 'out'
    (a trailing non-const pointer the parser writes), or 'scalar'. Order-sensitive: a size is only a
    'size' when it follows a 'data'."""
    roles: list = []
    n = len(params)
    for i, a in enumerate(params):
        a = a.strip()
        low = a.lower()
        if a in ("", "void"):
            continue
        if idiom and idiom.type_token.replace(" ", "") in a.replace(" ", ""):
            roles.append("stream")
        elif "*" in low and _DATA_RE.search(low) and i + 1 < n and _is_size(params[i + 1]):
            roles.append("data")                         # a (buf, size) pair: the raw fuzz bytes
        elif _is_size(a) and roles and roles[-1] == "data":
            roles.append("size")
        elif "char" in low and "*" in low:
            roles.append("string")
        elif "*" in low:
            # an opaque pointer: an out-struct the parser WRITES (only meaningful as the trailing
            # param AFTER an input carrier), otherwise a context it reads. Both are calloc'd, so the
            # distinction is only for the recipe's prose.
            trailing_out = i == n - 1 and ("stream" in roles or "data" in roles)
            roles.append("out" if trailing_out else "context")
        else:
            roles.append("scalar")
    return roles


def synthesisable(params: list, idiom: "StreamIdiom | None") -> bool:
    """True when a driver can be synthesized: there is a way to deliver the fuzz bytes (a stream
    carrier or a (data,size) pair), and every other parameter is one we can supply (a context/out
    pointer we calloc, a string, or a scalar) -- never a bare callback."""
    roles = classify_params(params, idiom)
    if not ("stream" in roles or "data" in roles):
        return False
    return all("(" not in p for p in params)             # no function-pointer / callback parameters


def synth_stream_harness(fn: str, params: list, idiom: StreamIdiom, *, ctx_size: int = 8192,
                         header: "str | None" = None) -> str:
    """A libFuzzer driver that builds a real `idiom` stream from the fuzz bytes, calloc's each
    opaque context/out struct, and calls `fn`. Includes the project header that declares the stream
    and `fn` (so the real types/signature are used -- a parser's signature is not fillable with the
    forward-declared `void*` shape the plain synthesizer uses). `header` names the project header
    that declares `fn` (the carrier header is added from the idiom)."""
    roles = classify_params(params, idiom)
    includes = ["#include <stdint.h>", "#include <stddef.h>", "#include <stdlib.h>",
                "#include <string.h>", f'#include <{idiom.header}>']
    if header:
        includes.append(f'#include "{header}"')
    pre, args, k = [], [], 0
    for role in roles:
        k += 1
        v = f"a{k}"
        if role == "stream":
            pre.append(idiom.wrap(v, "data", "size"))
            args.append(v)
        elif role == "data":
            args.append("data")
        elif role == "size":
            args.append("size")
        elif role == "string":
            args.append('"r"')
        elif role == "context":
            pre.append(f"    void* {v} = calloc(1, {ctx_size});\n    if (!{v}) return 0;\n")
            args.append(f"({v})")
        elif role == "out":
            pre.append(f"    void* {v} = calloc(1, {ctx_size});\n")
            args.append(f"({v})")
        else:                                            # scalar: a value taken from the fuzz bytes
            pre.append(f"    long {v} = size >= 8 ? (long)(*(const long*)data) : 0;\n")
            args.append(v)
    body = "".join(pre)
    return ("\n".join(includes) + "\n\n"
            + "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            + body
            + f"    {fn}({', '.join(args)});\n"
            + "    return 0;\n}\n")


def detect_stream_idiom(root) -> "StreamIdiom | None":
    """The project's bytes-carrier idiom, by the read markers its sources use the most. Scans a
    bounded sample of C sources; returns the idiom whose markers dominate, or None (a project that
    parses raw (data,size) needs no carrier)."""
    root = Path(root)
    counts = {idi.name: 0 for idi in STREAM_IDIOMS}
    seen = 0
    for p in root.rglob("*.c"):
        if seen >= 400:
            break
        try:
            txt = p.read_text(errors="ignore")
        except OSError:
            continue
        seen += 1
        for idi in STREAM_IDIOMS:
            counts[idi.name] += sum(txt.count(m) for m in idi.read_markers)
    best = max(STREAM_IDIOMS, key=lambda i: counts[i.name], default=None)
    return best if best and counts[best.name] >= 20 else None
