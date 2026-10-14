"""Coverage-guided in-process fuzzing of C/C++ SOURCE via libFuzzer.

The built-in engine is blind havoc with bolt-on breakpoint coverage; libFuzzer is a real
coverage-guided, in-process fuzzer that clang provides for free with `-fsanitize=fuzzer`. Real
source -- especially libraries with no `main` -- is the case it fits: build an
`LLVMFuzzerTestOneInput` harness (one the project already ships, as OSS-Fuzz projects do, or one
synthesized for a named entry function) with ASan+UBSan, let libFuzzer drive coverage, and harvest
each crash with its sanitizer report -- a confirmed finding with a source file:line and no oracle.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

_C_EXT = {".c"}
_CXX_EXT = {".cc", ".cpp", ".cxx", ".c++", ".C"}
_SRC_EXT = _C_EXT | _CXX_EXT
_HARNESS_SYM = "LLVMFuzzerTestOneInput"
# `int main(` misses the K&R spelling `main(argc, argv)`, which libtiff's contrib still
# uses -- and a missed main collides with libFuzzer's own ("multiple definition of `main'").
_MAIN_RE = re.compile(r"^(?:[A-Za-z_][\w \t*]*[ \t*]+)?main[ \t]*\(", re.M)
_HARNESS_RE = re.compile(_HARNESS_SYM)
# `nonnull-attribute` RECOVERS, everything else is fatal. Measured on libtiff 4.0.3: the very
# first interesting input reaches `TIFFFetchStripThing`, where a strip array with count 0 does
# `memcpy(dst, NULL, 0)` -- technically undefined, practically harmless, and it ABORTED the
# campaign after 36 executions. Letting it recover hides nothing: a copy from NULL with a
# NON-zero length faults, and ASan reports that as SEGV. Trading a zero-length UB report for the
# rest of the campaign is the right trade; without it the engine stops at the first benign
# defect in the directory parser and never reaches a codec.
_SAN = ["-g", "-O1", "-fno-omit-frame-pointer", "-fsanitize=fuzzer,address,undefined",
        "-fno-sanitize-recover=all", "-fsanitize-recover=nonnull-attribute",
        "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", "-w",
        "-Wno-error=implicit-function-declaration", "-Wno-error=implicit-int",
        "-Wno-error=int-conversion", "-D_GNU_SOURCE"]


def _clang(cxx: bool):
    return shutil.which("clang++" if cxx else "clang")


def find_harness(root) -> Path | None:
    """A source file defining LLVMFuzzerTestOneInput, if the project ships one."""
    for p in Path(root).rglob("*"):
        if p.is_file() and p.suffix in _SRC_EXT:
            try:
                if _HARNESS_RE.search(p.read_text(errors="ignore")):
                    return p
            except OSError:
                pass
    return None


# A function DEFINITION: optionally a return type, a name, a parameter list, then `{`. Two
# things it must tolerate, because libtiff does both and neither was matched before -- so the
# library's actual entry point was invisible and only single-line helpers were candidates:
#   * the return type on its OWN line (`TIFF*\nTIFFOpen(const char* name, const char* mode)`);
#   * any parameter list, not just "pointer, optional number" (`TIFFOpen` takes two strings).
# The parameter list is captured and filtered in Python, where it can be read.
_FN_DEF = re.compile(
    r"(?:^|\n)[ \t]*(?!static\b|typedef\b|return\b|else\b|switch\b|case\b)"
    r"(?:[A-Za-z_][\w \t*]*?[ \t*]+)?"
    r"([A-Za-z_]\w*)[ \t]*\(([^;{}()]*)\)[ \t]*(?:\r?\n[ \t]*)?\{",
    re.M)
# The first parameter has to be something fuzz bytes (or a path to them) can be delivered as.
_PTR_FIRST = re.compile(r"^(?:const\s+)?(?:unsigned\s+)?(?:char|void|uint8_t|u_char)\s*\*", re.I)
# A length beside a pointer: the (buf, len) shape libFuzzer hands over directly.
_LEN_PARAM = re.compile(r"\b(size_t|ssize_t|int|long|unsigned|uint\d+_t|tmsize_t)\b", re.I)


# A parameter the harness can supply honestly: a string (a path or a mode), a number, or a
# plain pointer it can pass NULL for. Anything else (a callback, a struct by value, a typedef
# we cannot see through) means the call would be fabricated.
# NB the word boundary applies only to the BARE types: after `char *` the next character is a
# space, and `\b` cannot match between `*` and a space, so a trailing `\b` made every POINTER
# parameter read as unfillable -- which scored `TIFFOpen(const char*, const char*)` as if its
# mode string were a callback and dropped the pick to `_TIFFfree`.
_FILLABLE = re.compile(r"^(?:const\s+)?(?:unsigned\s+|signed\s+)?"
                       r"(?:(?:char|void)\s*\*"
                       r"|(?:int|long|short|size_t|ssize_t|unsigned|uint\d+_t|int\d+_t"
                       r"|float|double|tmsize_t)\b)", re.I)


def _opaque_param(param: str) -> bool:
    """Is this parameter one the harness cannot supply an honest value for?"""
    return not _FILLABLE.match(param.strip())


def fn_params(root, fn: str) -> list:
    """`fn`'s parameter type spellings, or [] when it is not found / takes none."""
    for p in sorted(Path(root).rglob("*")):
        if not (p.is_file() and p.suffix in _SRC_EXT):
            continue
        try:
            txt = p.read_text(errors="ignore")
        except OSError:
            continue
        for m in _FN_DEF.finditer(txt):
            if m.group(1) != fn:
                continue
            raw = (m.group(2) or "").strip()
            if not raw or raw == "void":
                return []
            return [a.strip() for a in raw.split(",") if a.strip()]
    return []


# An opener's matching closer, by name. Without one the harness leaks a handle per iteration
# and the process runs out of file descriptors part-way through the campaign; `TIFFOpen` then
# starts returning NULL and every remaining execution tests the failure path instead of the
# parser. The campaign would still report "ran 40,000 inputs" while testing nothing.
_CLOSER_PAIRS = (("Open", "Close"), ("open", "close"), ("New", "Free"), ("new", "free"),
                 ("Load", "Free"), ("load", "free"), ("Create", "Destroy"),
                 ("create", "destroy"), ("Alloc", "Free"), ("alloc", "free"))


def fn_closer(root, fn: str):
    """The function that releases what `fn` returns, if one is named for it."""
    for a, b in _CLOSER_PAIRS:
        if a in fn:
            cand = fn.replace(a, b)
            if cand != fn and (_declared_in_header(root, cand) or fn_params(root, cand)):
                return cand
    return None


def harness_kind_for(root, fn: str) -> str:
    """Which harness shape fits `fn`: `buflen` for (pointer, length), `file` for a FILENAME,
    else `cstring`.

    The caller used to pass `cstring` always, which hands the fuzz bytes to the function AS a
    string. For a file-format library's entry point that is nonsense -- `TIFFOpen` would be
    asked to open a file whose NAME is a TIFF image, fail at once, and every execution would
    test the failure path. The bytes have to be written to a file and the PATH passed instead.
    """
    params = fn_params(root, fn)
    if not params:
        return "cstring"
    first = params[0]
    if not _PTR_FIRST.match(first):
        return "cstring"
    if len(params) >= 2 and _LEN_PARAM.search(params[1]) and "*" not in params[1]:
        return "buflen"
    if "char" in first.lower() and _PARSERISH.search(fn):
        return "file"
    return "cstring"


_KEYWORDS = ("main", "if", "for", "while", "switch", "return", "sizeof", "do", "else")
# Names that say "I consume an input". A memory-safety bug in a format library is in the code
# that reads the format, not in a helper that happens to take a char*.
_PARSERISH = re.compile(r"(open|parse|load|read|decode|import|scan|unpack|inflate|new)", re.I)
# Directories that are not the library: a tool's private helper is reachable only through that
# tool's own argv handling, so fuzzing it proves nothing about the library's API.
_NOT_LIBRARY = ("test", "tests", "tools", "contrib", "examples", "example", "build-aux", "port")
#: Directories holding a PLATFORM PORT's headers rather than the library's API. Their
#: declarations are real -- they are just not the surface an application on this machine reaches,
#: and a harness that includes one does not compile.
_PORT_DIRS = ("amiga", "win32", "windows", "msvc", "vms", "os2", "macos", "watcom", "borland",
              "mingw", "darwin", "aix", "hpux", "solaris", "android", "ios", "bcb5", "nt")


def _declared_in_header(root, fn: str):
    """The header that declares `fn`, if any. A function in the PUBLIC header is the library's
    API -- the surface an application reaches, so a bug behind it is a bug anyone can reach."""
    # `NAME(` is not the only spelling of a declaration: bzip2 wraps every name in a calling
    # convention macro -- `BZ_EXTERN int BZ_API(BZ2_bzBuffToBuffDecompress) (...)` -- so the name
    # is followed by `)`. Accepting the punctuation that can follow a declared name matches both
    # without matching prose that merely mentions the function.
    pat = re.compile(r"\b" + re.escape(fn) + r"\s*[(),;]")
    hits = []
    for h in sorted(Path(root).rglob("*.h")):
        rel = h.relative_to(Path(root)).parts
        if any(seg in _SKIP_DIRS for seg in rel):
            continue
        # A PORT's header is not the library's API. expat ships four headers declaring
        # `XML_ParserCreate` and `sorted()` returned `amiga/include/inline4/expat.h` first -- an
        # Amiga inline-macro wrapper. The name was found, so every caller believed the function
        # was public, while a harness that INCLUDED that header would not compile here at all.
        if any(seg in _PORT_DIRS for seg in rel[:-1]):
            continue
        try:
            if pat.search(h.read_text(errors="ignore")):
                hits.append(h)
        except OSError:
            continue
    if not hits:
        return None
    # The shallowest path wins, then the shortest: a library's own public header sits beside its
    # sources (`lib/expat.h`), while a platform or bundled copy is nested deeper.
    hits.sort(key=lambda h: (len(h.relative_to(Path(root)).parts), len(str(h))))
    return hits[0]


def pick_harness_fn(root) -> str | None:
    """Auto-select an entry function to fuzz in a LIBRARY with no in-tree harness.

    This returned the FIRST non-static function taking a `char*` in alphabetical file order,
    which on libtiff 4.0.3 meant `convertHTMLcodes` -- an HTML-entity helper inside a command
    line tool. In-process fuzzing then exercised a string unescaper while libtiff's own decoders
    (where its CVEs are) were never called. The candidate set is unchanged; what is new is that
    they are RANKED: the library's public, input-consuming API first.
    """
    root = Path(root)
    best, best_score = None, -(10 ** 6)
    for p in sorted(root.rglob("*")):
        if not (p.is_file() and p.suffix in _SRC_EXT):
            continue
        rel = p.relative_to(root).parts
        if any(seg in _SKIP_DIRS for seg in rel):
            continue
        # EXCLUDED, not penalised. A score penalty still let a sample program win when nothing in
        # the library itself was a candidate: zlib's `gzlog_open` (from `examples/`) was picked and
        # the link failed on `gzlog_close`, which is not compiled at all. A function outside the
        # library is not a worse choice, it is not a choice.
        if any(seg in _NOT_LIBRARY for seg in rel[:-1]):
            continue
        try:
            txt = p.read_text(errors="ignore")
        except OSError:
            continue
        for m in _FN_DEF.finditer(txt):
            name = m.group(1)
            if name in _KEYWORDS:
                continue
            raw = [a.strip() for a in (m.group(2) or "").split(",") if a.strip()]
            first = raw[0] if raw else ""
            if not _PTR_FIRST.match(first):
                continue                                 # nothing to deliver the bytes through
            # Every argument past the first has to be INVENTED by the harness, and an invented
            # one is a lie the library may crash on -- `TIFFClientOpen` is the public, perfectly
            # parser-ish entry point of libtiff and it takes eight callbacks, so a synthesized
            # call passes NULL function pointers and faults inside our own harness. Prefer the
            # narrow door: `TIFFOpen(name, mode)` is the same parser reached honestly.
            score = -2 * max(0, len(raw) - 2)
            if any(_opaque_param(a) for a in raw[1:]):
                score -= 6
            if _PARSERISH.search(name):
                score += 4
            if _declared_in_header(root, name) is not None:
                score += 3
            if score > best_score:
                best, best_score = name, score
    return best


def fn_first_arg_type(root, fn: str):
    """The spelling of `fn`'s FIRST parameter type in the source (e.g. "const char *", "char *"),
    or "" when it takes no args, or None if not found. Needed to forward-declare `fn` in the harness
    so C++ name mangling matches -- `extern void fn()` mangles differently than `fn(const char*)` and
    fails to link. C is lenient, but the exact declaration is correct for both."""
    pat = re.compile(r"\b" + re.escape(fn) + r"\s*\(([^)]*)\)\s*(?:const\s*)?\{", re.M)
    for p in sorted(Path(root).rglob("*")):
        if not (p.is_file() and p.suffix in _SRC_EXT):
            continue
        try:
            m = pat.search(p.read_text(errors="ignore"))
        except OSError:
            continue
        if not m:
            continue
        params = m.group(1).strip()
        if not params or params == "void":
            return ""
        first = params.split(",")[0].strip()
        first = re.sub(r"\b[A-Za-z_]\w*\s*$", "", first).strip() or first   # drop the param NAME
        return first
    return None


def fn_def_file(root, fn) -> Path | None:
    """The source file that DEFINES `fn` (for its language: .c -> a C symbol, .cc/.cpp -> a mangled
    C++ symbol -- which decides whether the harness declares it `extern "C"`)."""
    pat = re.compile(r"\b" + re.escape(fn) + r"\s*\([^)]*\)\s*(?:const\s*)?\{", re.M)
    for p in sorted(Path(root).rglob("*")):
        if p.is_file() and p.suffix in _SRC_EXT:
            try:
                if pat.search(p.read_text(errors="ignore")):
                    return p
            except OSError:
                pass
    return None


def _arg_values(params: list) -> list:                   # noqa: D401
    """Plausible values for an opener's arguments AFTER the path: a mode string for a `char *`,
    NULL for any other pointer, 0 for a number. Only ever called for signatures whose every
    parameter `_FILLABLE` accepted, so none of these is a fabricated callback."""
    out = []
    for a in params:
        low = a.lower()
        if "char" in low and "*" in low:
            out.append('(void*)"r"')                     # declared void *, so cast explicitly
        elif "*" in low:
            out.append("(void*)0")
        else:
            out.append("0")
    return out


_SCALARS = re.compile(r"\b(void|char|short|int|long|unsigned|signed|float|double|size_t|"
                      r"ssize_t|u?int\d+_t)\b")


def _types_only(params: list) -> str:
    """A parameter list as TYPES the HARNESS can name, for a forward declaration.

    A declaration may not use the project's own typedefs: the harness is a separate translation
    unit that includes none of the project's headers, so `FILE* fopen_output_safely(Char* name,
    const char* mode)` declared with `Char*` does not compile -- and because a translation unit
    that fails to compile is skipped, the HARNESS itself was dropped and the link failed with
    "undefined reference to `LLVMFuzzerTestOneInput'". Measured on bzip2 1.0.6.

    So every pointer becomes `void *` and every unrecognised scalar becomes `long`. Linkage is
    unaffected (C does not encode parameter types, and a C symbol reached from C++ is declared
    `extern "C"`), and the call site casts to match.
    """
    out = []
    for a in params:
        a = a.strip()
        m = re.match(r"^(.*?[\*\s])[A-Za-z_]\w*(\s*\[\s*\])?$", a)
        t = (m.group(1) if m else a).strip()
        if "*" in t or "[" in a:
            out.append("void *")
        elif _SCALARS.search(t):
            out.append(t)
        else:
            out.append("long")                           # an opaque scalar typedef
    return ", ".join(out) or "void"


def synth_file_harness(fn: str, params: list, *, closer: str | None = None,
                       cxx: bool = False, c_linkage: bool = False) -> str:
    """A harness that writes the fuzz bytes to a FILE and passes its PATH to `fn`.

    This is the shape a file-format library needs and the one that was missing: the `cstring`
    harness hands the bytes to the function as a string, so `TIFFOpen` was asked to open a file
    whose NAME was a TIFF image. It failed immediately, every single execution, and in-process
    fuzzing of the library reported runs without ever reaching a decoder.
    """
    fuzz_qual = 'extern "C" ' if cxx else ""
    fn_qual = 'extern "C" ' if (cxx and c_linkage) else "extern "
    args = ", ".join(["(void*)path"] + _arg_values(params[1:]))
    decl = f'{fn_qual}void *{fn}({_types_only(params)});\n'
    close_decl = f'{fn_qual}void {closer}(void *);\n' if closer else ""
    close_call = f"        if (h) {closer}(h);\n" if closer else ""
    return ("#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n"
            "#include <string.h>\n#include <unistd.h>\n"
            + decl + close_decl
            + f"{fuzz_qual}int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n"
            '    char path[] = "/tmp/lykos-lfXXXXXX";\n'
            "    int fd = mkstemp(path);\n"
            "    if (fd < 0) return 0;\n"
            "    long w = (long)write(fd, data, size);\n"
            "    close(fd);\n"                        # close BEFORE the call: the library opens
            "    if (w == (long)size) {\n"            # the path itself and needs the bytes flushed
            f"        void *h = {fn}({args});\n"
            + close_call
            + "    }\n"
            "    unlink(path);\n"
            "    return 0;\n}\n")


#: Names that RELEASE a handle. A harness that never releases leaks one per execution; libFuzzer
#: runs tens of thousands of iterations in one process, so the library stops being able to
#: allocate and the rest of the campaign tests the out-of-memory path instead of the parser.
_DTOR_WORDS = re.compile(r"(free|destroy|close|delete|release|fini|cleanup|end|reset)", re.I)
#: Names that CREATE one.
_CTOR_WORDS = re.compile(r"(create|new|alloc|init|open|make|begin)", re.I)


def _handle_type(param: str) -> str:
    """The TYPE spelling of a parameter, with the variable name removed.

    `"XML_Parser parser"` -> `"XML_Parser"`; `"struct foo *f"` -> `"struct foo *"`.
    """
    t = " ".join((param or "").split())
    if not t:
        return ""
    if t.endswith("*"):
        return t
    parts = t.split(" ")
    if len(parts) == 1:
        return parts[0]                                  # an unnamed parameter: all type
    last = parts[-1]
    if last.startswith("*"):                             # `struct foo *f`
        return " ".join(parts[:-1]) + " *"
    return " ".join(parts[:-1])


def _buf_len_at(params: list) -> int:
    """Index of the first (pointer, length) PAIR in `params`, or -1.

    This is the shape libFuzzer hands over directly, and finding it is what tells a
    handle-threading consumer (`XML_Parse(XML_Parser, const char *s, int len, int isFinal)`) from
    a function that merely happens to take a handle.
    """
    for i in range(len(params) - 1):
        if _PTR_FIRST.match(params[i].strip()) and _LEN_PARAM.search(params[i + 1]):
            return i
    return -1


def find_handle_triple(root):
    """A create -> consume -> destroy triple, or None.

    THE REACH GAP. `pick_harness_fn` requires a pointer-spelled first parameter, so it can only
    reach a library whose entry point takes the bytes directly. The dominant shape in a C library
    is not that: you make a handle, feed it, and free it --

        XML_Parser XML_ParserCreate(const XML_Char *encoding);
        enum XML_Status XML_Parse(XML_Parser parser, const char *s, int len, int isFinal);
        void XML_ParserFree(XML_Parser parser);

    `XML_Parser` is a typedef with no `*` in its spelling, so the ranked pick excluded expat's
    real parser outright and the library was reachable only through a HAND-WRITTEN harness. The
    same holds for libpng (`png_create_read_struct`/`png_read_png`/`png_destroy_read_struct`),
    libxml2, sqlite3 and openssl: a hand-written harness per library does not generalise, and
    this does.

    Returns `{"header", "handle", "ctor", "ctor_params", "consume", "consume_params", "dtor",
    "buf_at"}`. The header matters: the handle type is OPAQUE, so the harness cannot
    forward-declare its way around it and has to `#include` the library's own public header --
    which is what a real harness does anyway, and brings every prototype with it.
    """
    root = Path(root)
    # 1. a CONSUMER: an opaque first parameter followed by a (pointer, length) pair.
    cands = []
    for p in sorted(root.rglob("*")):
        if not (p.is_file() and p.suffix in _SRC_EXT):
            continue
        rel = p.relative_to(root).parts
        if any(seg in _SKIP_DIRS for seg in rel) or any(seg in _NOT_LIBRARY for seg in rel[:-1]):
            continue
        try:
            txt = p.read_text(errors="ignore")
        except OSError:
            continue
        for m in _FN_DEF.finditer(txt):
            name = m.group(1)
            if name in _KEYWORDS or _DTOR_WORDS.search(name):
                continue
            params = [a.strip() for a in (m.group(2) or "").split(",") if a.strip()]
            if len(params) < 3 or not _opaque_param(params[0]):
                continue                                 # no handle to thread
            at = _buf_len_at(params[1:])
            if at < 0:
                continue
            htype = _handle_type(params[0])
            if not htype or htype in ("void *", "void*"):
                continue                                 # `void *` is not a named handle type
            hdr = _declared_in_header(root, name)
            score = (4 if hdr is not None else 0) + (3 if _PARSERISH.search(name) else 0)
            cands.append((score, name, params, at + 1, htype, hdr))
    if not cands:
        return None
    cands.sort(key=lambda c: (-c[0], c[1]))
    for _score, name, params, buf_at, htype, hdr in cands:
        if hdr is None:
            continue                                     # a private function is not an API
        ctor = _find_by_return(root, hdr, htype, _CTOR_WORDS, exclude={name})
        if not ctor:
            continue
        dtor = _find_taking_only(root, htype, _DTOR_WORDS, exclude={name, ctor[0]})
        return {"header": hdr, "handle": htype, "ctor": ctor[0], "ctor_params": ctor[1],
                "consume": name, "consume_params": params, "dtor": dtor, "buf_at": buf_at}
    return None


def _find_by_return(root, header, htype: str, words, exclude=()):
    """(name, params) of a function in `header` whose RETURN type is `htype`, or None.

    The return type is matched in the text BEFORE the name rather than by parsing a declaration,
    because a public header usually wraps it in an export macro -- expat writes
    `XMLPARSEAPI(XML_Parser)` on the line above `XML_ParserCreate(...)` -- and no reasonable
    regex for "a C declaration" survives that. Being loose here is safe: the candidate still has
    to be named like a constructor, take only parameters we can supply, and link.
    """
    try:
        txt = Path(header).read_text(errors="ignore")
    except OSError:
        return None
    bare = htype.replace("*", "").strip()
    for m in re.finditer(r"\b" + re.escape(bare) + r"\b([^;{}]{0,160}?)"
                         r"([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*;", txt):
        name, raw = m.group(2), m.group(3)
        if name in exclude or name in _KEYWORDS or not words.search(name):
            continue
        params = [a.strip() for a in raw.split(",") if a.strip() and a.strip() != "void"]
        # Every argument has to be one we can supply honestly. A pointer gets NULL, which is what
        # an optional argument of this kind almost always means (expat: the encoding).
        if any(a for a in params if _opaque_param(a) and "*" not in a):
            continue
        return (name, params)
    return None


def _find_taking_only(root, htype: str, words, exclude=()):
    """The name of a function taking exactly one `htype`, named like a releaser, or None."""
    bare = htype.replace("*", "").strip()
    for p in sorted(Path(root).rglob("*")):
        if not (p.is_file() and p.suffix in _SRC_EXT):
            continue
        try:
            txt = p.read_text(errors="ignore")
        except OSError:
            continue
        for m in _FN_DEF.finditer(txt):
            name = m.group(1)
            if name in exclude or not words.search(name):
                continue
            params = [a.strip() for a in (m.group(2) or "").split(",") if a.strip()]
            if len(params) == 1 and bare and bare in params[0]:
                return name
    return None


def _ctor_arg_values(params: list) -> list:
    """Arguments for a CONSTRUCTOR. A pointer gets NULL and a scalar gets 0.

    `_arg_values` exists for an opener and hands a pointer `(void*)"r"` -- a file MODE, which is
    right for `TIFFOpen(path, "r")` and wrong here. Passing "r" as expat's encoding name made
    `XML_ParserCreate` fail, so the harness returned at `if (!h)` on EVERY execution: a campaign
    that runs forty thousand inputs and tests nothing. NULL is what an optional argument of this
    kind means -- for expat, "use the encoding the document declares".
    """
    out = []
    for a in params:
        out.append("NULL" if "*" in a else "0")
    return out


def synth_handle_harness(triple: dict, *, cxx: bool = False) -> str:
    """A harness that makes a handle, feeds the fuzz bytes through it, and frees it.

    It INCLUDES the library's public header instead of forward-declaring: the handle type is
    opaque, so there is nothing to forward-declare, and including the header is both what a real
    harness does and what makes every prototype and typedef correct by construction.
    """
    hdr = Path(triple["header"]).name
    h, ctor, consume, dtor = (triple["handle"], triple["ctor"], triple["consume"],
                              triple.get("dtor"))
    params, buf_at = triple["consume_params"], triple["buf_at"]
    ctor_args = ", ".join(_ctor_arg_values(triple.get("ctor_params") or []))
    # the call: handle, then the buffer and its length in the slots they occupy, then whatever
    # trailing scalars the API takes. A trailing int is passed 1, not 0: in this shape it is
    # almost always a "last chunk" / "finish now" flag (expat's `isFinal`), and 0 asks the
    # library to wait for more data that a one-shot harness will never send.
    args = ["h"]
    i = 1
    while i < len(params):
        if i == buf_at:
            args.append(f"({_handle_type(params[i])})data")
            args.append("(int)size" if _LEN_PARAM.search(params[i + 1]) else "size")
            i += 2
            continue
        args.append("1" if _LEN_PARAM.search(params[i]) else "0")
        i += 1
    fuzz_qual = 'extern "C" ' if cxx else ""
    free_call = f"    {dtor}(h);\n" if dtor else ""
    return ("#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n"
            f'#include "{hdr}"\n'
            f"{fuzz_qual}int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n"
            f"    {h} h = {ctor}({ctor_args});\n"
            "    if (!h) return 0;\n"
            f"    {consume}({', '.join(args)});\n"
            + free_call
            + "    return 0;\n}\n")


def synth_harness(fn: str, *, kind: str = "cstring", arg_type: str | None = None,
                  cxx: bool = False, c_linkage: bool = False) -> str:
    """A libFuzzer harness calling `fn` with the fuzz bytes. `cstring`: fn(char*) on a
    NUL-terminated copy; `buflen`: fn(const uint8_t*, size_t). `arg_type` is `fn`'s real first
    parameter spelling from the source so the forward declaration links (C++ mangles the signature).
    `cxx` emits a C++ harness (the fuzzer entry then needs `extern "C"`); `c_linkage` declares `fn`
    itself `extern "C"` when it is a C symbol reached from a C++ harness."""
    fuzz_qual = 'extern "C" ' if cxx else ""
    fn_qual = 'extern "C" ' if (cxx and c_linkage) else "extern "
    if kind == "buflen":
        decl = arg_type or "const unsigned char *, unsigned long"
        pre, call = "", f"    {fn}(data, size);\n"
    else:
        at = arg_type if arg_type not in (None, "") else "char *"
        decl = at
        pre = ("    char *s = (char*)malloc(size + 1);\n    if (!s) return 0;\n"
               "    memcpy(s, data, size); s[size] = 0;\n")
        call = f"    {fn}(({at})s);\n    free(s);\n"
    return ("#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>\n"
            f"{fn_qual}void {fn}({decl});\n"
            f"{fuzz_qual}int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n"
            f"{pre}{call}    return 0;\n}}\n")


def _sources(root: Path, exclude_main: bool):
    out = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix not in _SRC_EXT:
            continue
        parts = p.relative_to(root).parts
        if any(seg in _SKIP_DIRS for seg in parts):
            continue
        # `contrib`/`examples` are sample programs, not the library: they are unmaintained often
        # enough that they are the first thing to break a whole-project build (see build_libfuzzer).
        if any(seg in ("contrib", "examples", "example") for seg in parts[:-1]):
            continue
        try:
            txt = p.read_text(errors="ignore")
        except OSError:
            continue
        if exclude_main and _MAIN_RE.search(txt) and not _HARNESS_RE.search(txt):
            continue                                     # its own main clashes with libFuzzer's
        out.append(p)
    return out


_SKIP_DIRS = (".git", "_lykos_build", "node_modules", ".deps", ".libs")


def include_dirs(root, cap: int = 32) -> list:
    """Every directory that holds a header, shallowest first.

    `-I <root>` alone is not enough for any project that keeps its public header beside its
    sources: libtiff declares `tiffio.h` in `libtiff/`, so the harness failed to compile with
    "fatal error: 'tiffio.h' file not found" and in-process fuzzing -- the one engine built for
    a library with no main -- was unavailable on exactly the targets it exists for. Shallowest
    first because a project's real include dir is near the top and a vendored copy is deep.
    """
    root = Path(root)
    dirs = {root}
    for h in root.rglob("*.h"):
        parts = h.relative_to(root).parts
        if any(seg in _SKIP_DIRS for seg in parts):
            continue
        dirs.add(h.parent)
    return sorted(dirs, key=lambda d: (len(d.relative_to(root).parts), str(d)))[:cap]


# ---------------------------------------------------------------------------------------------
# KNOWN LIBRARY HARNESSES.
#
# A synthesized harness can only call what it can honestly supply arguments for, which for a
# file-format library means the OPEN function and nothing past it. Measured on libtiff 4.0.3:
# `TIFFOpen`/`TIFFClose` at 3,780 exec/s for 714,465 executions found two real UB defects and
# ZERO memory-corruption ones, because opening parses the directory and stops at the decoder's
# door -- and that is where the CVEs are.
#
# Reaching a decoder needs the library's own read call, with a buffer sized the way the library
# documents. That cannot be inferred, so it is written down per library and GATED on the symbols
# actually being present in this source tree: if they are absent the entry does not apply and the
# synthesized harness is used instead. This is the OSS-Fuzz shape -- a small amount of per-library
# knowledge, stated openly -- not a heuristic pretending to be general.
#
# The honesty rule for anything added here: every buffer must be sized from the library's OWN
# documented contract. `TIFFReadRGBAImage` documents a raster of width*height uint32 and
# width/height come from `TIFFGetField`, so an ASan report against that buffer is a libtiff
# defect. A harness that guesses a size manufactures findings instead of discovering them.
_KNOWN_HARNESSES: dict = {
    # expat: the parser is a HANDLE, so no synthesized harness can reach it -- `XML_Parse`'s first
    # parameter is an `XML_Parser`, which is why the ranking rejected it and picked
    # `_68k_endelementhandler` (a function from an unused platform file) instead.
    "expat": {
        "symbols": ("XML_ParserCreate", "XML_Parse", "XML_ParserFree"),
        "source": r"""
#include <stdint.h>
#include <stddef.h>
#include "expat.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    XML_Parser p = XML_ParserCreate(NULL);
    if (!p) return 0;
    /* isFinal=1: parse the whole buffer as one document, which is the documented one-shot use. */
    XML_Parse(p, (const char *)data, (int)size, 1);
    XML_ParserFree(p);
    return 0;
}
""",
    },
    # zlib: `uncompress` documents destLen as in/out -- we say how big the buffer is and zlib
    # must not exceed it, so an ASan report against it is zlib's defect. `inflate` itself takes a
    # z_stream, another handle a synthesized harness cannot build.
    "zlib": {
        "symbols": ("uncompress", "compress2", "inflateInit_"),
        "source": r"""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uLongf out_len = 1 << 18;
    Bytef *out = (Bytef *)malloc(out_len);
    if (!out) return 0;
    /* destLen is the contract: zlib is told the capacity and may not write past it. */
    uncompress(out, &out_len, (const Bytef *)data, (uLong)size);
    free(out);
    return 0;
}
""",
    },
    # bzip2: same shape -- BZ2_bzBuffToBuffDecompress takes the destination capacity in/out.
    "bzip2": {
        "symbols": ("BZ2_bzBuffToBuffDecompress", "BZ2_bzDecompress"),
        "source": r"""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "bzlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned int out_len = 1 << 18;
    char *out = (char *)malloc(out_len);
    if (!out) return 0;
    BZ2_bzBuffToBuffDecompress(out, &out_len, (char *)(void *)data,
                               (unsigned int)size, 0, 0);
    free(out);
    return 0;
}
""",
    },
    "tiff": {
        "symbols": ("TIFFOpen", "TIFFClose", "TIFFGetField", "TIFFReadRGBAImage",
                    "TIFFReadDirectory", "TIFFSetErrorHandler"),
        "source": r"""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include "tiffio.h"

/* libtiff reports a malformed file by CALLING these; printing is noise, not a finding. */
static void lykos_quiet(const char *m, const char *f, va_list a) { (void)m; (void)f; (void)a; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char path[] = "/tmp/lykos-lfXXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    long wrote = (long)write(fd, data, size);
    close(fd);
    if (wrote == (long)size) {
        TIFFSetErrorHandler(lykos_quiet);
        TIFFSetWarningHandler(lykos_quiet);
        TIFF *tif = TIFFOpen(path, "r");
        if (tif) {
            uint32 iw = 0, ih = 0;
            TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &iw);
            TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &ih);
            /* w*h uint32 is exactly what TIFFReadRGBAImage documents, and w/h are the library's
               own answer -- so an overflow here is libtiff's, not ours. The cap only bounds the
               allocation so a crafted size is not reported as out-of-memory. */
            if (iw && ih && (uint64_t)iw * (uint64_t)ih <= (1u << 22)) {
                uint32 *raster = (uint32 *)_TIFFmalloc((tmsize_t)(iw * ih * sizeof(uint32)));
                if (raster) {
                    TIFFReadRGBAImage(tif, iw, ih, raster, 0);
                    _TIFFfree(raster);
                }
            }
            /* EVERY directory, not just the first: multi-IFD parsing is its own bug surface.
               Bounded, because 4.0.3 does not reliably detect an IFD loop and an unbounded walk
               would be reported as a libFuzzer timeout rather than as the hang it is. */
            for (int i = 0; i < 64 && TIFFReadDirectory(tif); i++) { }
            TIFFClose(tif);
        }
    }
    unlink(path);
    return 0;
}
""",
    },
}


def _configure_if_needed(root, *, timeout: int = 300) -> bool:
    """Run the project's own `configure` when a header it generates is missing.

    Detected from the templates the tree ships (`*.h.in`): if a template's generated header is
    absent, the tree has not been configured. Best-effort and quiet -- a project with no
    `configure`, or one whose configure fails, is simply built as-is and the compiler reports
    whatever is actually wrong.
    """
    root = Path(root)
    conf = root / "configure"
    if not conf.is_file():
        return False
    try:
        missing = False
        for tpl in list(root.rglob("*.h.in"))[:40]:
            if not tpl.with_suffix("").exists():         # `tiffconf.h.in` -> `tiffconf.h`
                missing = True
                break
        if not missing:
            return False
        subprocess.run(["sh", "./configure", "--disable-shared"], cwd=str(root),
                       capture_output=True, text=True, timeout=timeout)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def config_defines(root) -> list:
    """`-D` flags for the config headers this tree GENERATES, which autoconf would have supplied.

    A configured autotools project compiles with `-DHAVE_CONFIG_H` (or a project-specific
    spelling) and the sources are written to require it. We compile each translation unit
    ourselves and never read the generated Makefile, so the define was missing -- and expat's
    `xmlparse.c` does not merely lose a feature without it, it refuses to compile at all:

        lib/xmlparse.c:83:2: error: memmove does not exist on this platform, nor is a
                                    substitute available

    That TU was then skipped like any other failing one, the link resolved `XML_ParserCreate`
    from the SYSTEM libexpat via the undefined-symbol fallback, and the build reported ok. The
    campaign ran twenty-one million executions against Debian's copy of the library instead of
    the source tree it was pointed at, and nothing said so.

    The mapping is the autoconf convention: `config.h` -> `HAVE_CONFIG_H`,
    `expat_config.h` -> `HAVE_EXPAT_CONFIG_H`.
    """
    root = Path(root)
    out = []
    for tpl in sorted(root.rglob("*config.h.in"))[:20]:
        gen = tpl.with_suffix("")                        # `expat_config.h.in` -> `expat_config.h`
        if not gen.exists():
            continue
        flag = "-DHAVE_" + gen.name.replace(".h", "").upper() + "_H"
        if flag not in out:
            out.append(flag)
    return out


def known_harness(root):
    """(name, source) for a library this tree matches, or None.

    Matched on SYMBOLS, not on a directory name: a vendored or renamed copy still matches, and a
    tree that merely mentions the library in a comment does not.
    """
    for name, entry in _KNOWN_HARNESSES.items():
        if all(_declared_in_header(root, sym) is not None for sym in entry["symbols"]):
            return name, entry["source"]
    return None


def build_libfuzzer(root, out: Path, *, harness_fn: str | None = None,
                    harness_kind: str | None = None, timeout: int = 300) -> dict:
    """Build a libFuzzer target from the project at `root`. Uses an in-tree LLVMFuzzerTestOneInput
    if present, else synthesizes one for `harness_fn`. Returns {ok, binary, harness, log}."""
    root = Path(root).resolve()
    existing = find_harness(root)
    # PREFERENCE ORDER: the project's own harness (it knows its API best), then a known-library
    # harness that reaches the decode path, then a synthesized one that can only open the file.
    known = None if existing else known_harness(root)
    # A CREATE -> CONSUME -> DESTROY triple, which is the dominant shape in a C library and the
    # one the single-function pick cannot reach: it requires a pointer-spelled first parameter,
    # and a handle type is a typedef (`XML_Parser`), so expat's real parser was excluded outright
    # and the library was reachable only through a hand-written harness. Preferred over the
    # single-function pick because threading the handle reaches the PARSER, where the pick's
    # fallback reaches whatever function happened to take a buffer.
    triple = None
    if not existing and not known and not harness_fn:
        triple = find_handle_triple(root)
    if not existing and not known and not harness_fn and not triple:
        harness_fn = pick_harness_fn(root)               # auto-harness a library's parser entry
    cxx = any(p.suffix in _CXX_EXT for p in _sources(root, exclude_main=False))
    cc = _clang(cxx)
    if not cc:
        return {"ok": False, "binary": None, "harness": None, "log": "clang not found (libFuzzer needs clang)"}
    # A tree whose config header is GENERATED has none until it is configured: libtiff's sources
    # include `tiffconf.h`/`tif_config.h`, which `configure` writes from a `.in` template, so a
    # pristine checkout cannot compile at all ("fatal error: 'tiffconf.h' file not found"). In the
    # pipeline the archived tree is post-build and has them; a tree handed over directly does not,
    # and that difference is exactly the kind of "works on the machine we tested" gap that only
    # shows up on someone else's target.
    _configure_if_needed(root, timeout=timeout)
    tmp = Path(tempfile.mkdtemp(prefix="lykos-lf-"))
    srcs = _sources(root, exclude_main=True)
    # Compile THE LIBRARY the entry point belongs to, not the whole repository. Building every
    # source in a real project drags in `contrib/` and `test/`, which reference symbols that do
    # not exist (`XTIFFOpen`), include headers for other platforms (`pixrect/pixrect_hs.h`), and
    # carry their own `main`. None of it is on the path to the parser, and any one of those stops
    # the build -- so in-process fuzzing was unavailable on a project merely for having a contrib
    # directory. The entry point's own directory IS the library by construction: it is where the
    # function we are about to call is defined.
    if (harness_fn or known or triple) and not existing:
        # For a known harness, scope by the OPEN symbol it is built around: the directory that
        # defines the library's entry point is the library.
        anchor_fn = (harness_fn or (triple or {}).get("consume")
                     or _KNOWN_HARNESSES[known[0]]["symbols"][0])
        home = fn_def_file(root, anchor_fn)
        if home is not None and home.parent != root:
            lib_srcs = [x for x in srcs if home.parent in x.parents or x.parent == home.parent]
            if lib_srcs:
                srcs = lib_srcs
    harness_desc = None
    if existing:
        harness_desc = f"in-tree {existing.relative_to(root)}"
    elif known:
        name, src_text = known
        h = tmp / "harness.c"
        h.write_text(src_text)
        srcs = srcs + [h]
        harness_desc = f"known-library harness for {name} (reaches the decode path)"
    elif triple:
        h = tmp / ("harness.cc" if cxx else "harness.c")
        h.write_text(synth_handle_harness(triple, cxx=cxx))
        srcs = srcs + [h]
        harness_desc = (f"synthesized handle harness: {triple['ctor']}() -> "
                        f"{triple['consume']}() -> {triple.get('dtor') or '(no free)'}"
                        f" [reaches the parser through the library's own API]")
    elif harness_fn:
        h = tmp / ("harness.cc" if cxx else "harness.c")
        # match the target function's real signature and linkage so a C++ symbol (mangled) or a C
        # symbol reached from a C++ harness both resolve at link time.
        def_file = fn_def_file(root, harness_fn)
        c_linkage = bool(def_file and def_file.suffix in _C_EXT)
        # The SHAPE is inferred from the signature unless the caller names one. It defaulted to
        # `cstring` for everything, which delivers the fuzz bytes as a string -- wrong for every
        # entry point that takes a FILENAME, i.e. every file-format library.
        kind = harness_kind or harness_kind_for(root, harness_fn)
        if kind == "file":
            params = fn_params(root, harness_fn)
            h.write_text(synth_file_harness(harness_fn, params,
                                            closer=fn_closer(root, harness_fn),
                                            cxx=cxx, c_linkage=c_linkage))
        else:
            h.write_text(synth_harness(harness_fn, kind=kind,
                                       arg_type=fn_first_arg_type(root, harness_fn),
                                       cxx=cxx, c_linkage=c_linkage))
        srcs = srcs + [h]
        harness_desc = f"synthesized for {harness_fn}() [{kind}]"
    else:
        return {"ok": False, "binary": None, "harness": None,
                "log": "no LLVMFuzzerTestOneInput in the source and no harness_fn to synthesize one"}
    # What a configured autotools build would have on its command line. Without it expat's
    # xmlparse.c does not compile at all (see `config_defines`).
    incs = list(config_defines(root))
    for d in include_dirs(root):
        incs += ["-I", str(d)]
    # The harness is REQUIRED: skipping a translation unit is right for a platform shim or a test,
    # and wrong for the one file that defines the entry point. Silently skipping it produced a link
    # error about `LLVMFuzzerTestOneInput` instead of the compile error that caused it.
    res = _compile_and_link(srcs, incs, out, tmp, timeout,
                            required=(h if (known or harness_fn) and not existing else None))
    shutil.rmtree(tmp, ignore_errors=True)
    res["harness"] = harness_desc
    return res


def _compile_and_link(srcs, incs, out: Path, tmp: Path, timeout: int, *, required=None) -> dict:
    """Compile each translation unit with the driver for ITS language, then link what compiled.

    One source file decided the language for the whole project, and `any(.cxx)` is true for
    libtiff -- it ships a single optional C++ stream wrapper (`tif_stream.cxx`). So eighty C
    files were handed to clang++ and the build died on ISO C++ rules that have nothing to do
    with the library: "ISO C++17 does not allow 'register'", "assigning to 'char *' from 'const
    char *' discards qualifiers", "'strcasecmp' is missing exception specification".

    A TU that will not compile is SKIPPED rather than failing the build: in a real project some
    translation units are tests, or platform shims for another platform, and they are not on the
    path to the library's parser. The link is the arbiter -- if something the harness actually
    needs was skipped, it fails there with an undefined symbol, which is a true error and is
    reported. The count of skipped units is in the log either way, so a build that quietly
    dropped half the project is visible rather than silently thinner than it looks.
    """
    from concurrent.futures import ThreadPoolExecutor
    objs, failed, logs = [], [], []

    failed_paths = []

    def _one(i_src):
        i, src = i_src
        obj = tmp / f"o{i}.o"
        drv = _clang(src.suffix in _CXX_EXT)
        if not drv:
            return None, f"{src.name}: no clang driver"
        argv = [drv] + _SAN + ["-c", str(src), "-o", str(obj)] + incs
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as e:
            return None, f"{src.name}: {e}"
        if r.returncode or not obj.exists():
            return None, ((r.stderr or "") + (r.stdout or ""))[-400:]
        return obj, None

    with ThreadPoolExecutor(max_workers=min(8, (os.cpu_count() or 2))) as ex:
        for src, (obj, err) in zip(srcs, ex.map(_one, enumerate(srcs))):
            if obj is not None:
                objs.append(obj)
            else:
                failed.append(err or "")
                failed_paths.append(Path(src))
    if required is not None and Path(required) in failed_paths:
        i = failed_paths.index(Path(required))
        return {"ok": False, "binary": None,
                "log": ("the HARNESS did not compile:\n" + failed[i])[-4000:]}
    skipped_srcs = list(failed_paths)
    if failed:
        logs.append(f"{len(failed)}/{len(srcs)} translation units skipped (did not compile)")
        logs += failed[:5]
    if not objs:
        return {"ok": False, "binary": None, "log": "\n".join(logs)[-4000:]}
    # Link with the C++ driver when any C++ object is present, so libstdc++ comes along.
    link_cxx = any(Path(s).suffix in _CXX_EXT for s in srcs)
    drv = _clang(link_cxx) or _clang(False)
    argv = [drv] + _SAN + [str(o) for o in objs] + ["-o", str(out)]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "binary": None, "log": ("\n".join(logs) + f"\nlink: {e}")[-4000:]}
    err = (r.stderr or "") + (r.stdout or "")
    if r.returncode and not out.exists():
        # The project's EXTERNAL libraries. A library project links against others -- libtiff
        # needs zlib for its Deflate and PixarLog codecs, liblzma, libjpeg -- and nothing told
        # the linker, so the build died on `undefined reference to 'inflateEnd'` with every
        # translation unit compiled. Read the undefined symbols and ask for the libraries that
        # define them, then retry ONCE. Linking a library nothing needs is harmless; guessing
        # from the project's configure output is not available here, and the symbols are.
        # THE TARGET'S OWN SYMBOLS MAY NOT COME FROM A SYSTEM LIBRARY. The fallback below exists
        # for a project's external dependencies (libtiff needs zlib for its Deflate codec), and
        # it happily resolved the library UNDER TEST as well: expat's `xmlparse.c` failed to
        # compile for want of a config define, was skipped like any other failing unit, and
        # `XML_ParserCreate` was then satisfied by `-lexpat`. The build reported ok and the
        # campaign ran twenty-one million executions against Debian's uninstrumented copy of
        # expat instead of the tree it was pointed at. A fuzzer that is not fuzzing the target
        # has to fail loudly; a quiet success here is worse than no build at all.
        _own = symbols_defined_in(skipped_srcs)
        _borrowed = sorted(set(_UNDEF_RE.findall(err or "")) & _own)
        if _borrowed:
            return {"ok": False, "binary": None, "log": ("\n".join(logs) + "\n" + (
                "refusing to link: " + ", ".join(_borrowed[:6]) + " is defined by this project's "
                "own source, in a translation unit that did not compile. Resolving it from a "
                "system library would fuzz the installed copy instead of this tree. Fix the "
                "skipped unit (its error is above) -- the usual cause is a generated config "
                "header or a missing -D."))[-4000:]}
        libs = _libs_for_undefined(err)
        if libs:
            retry = [drv] + _SAN + [str(o) for o in objs] + libs + ["-o", str(out)]
            try:
                r2 = subprocess.run(retry, capture_output=True, text=True, timeout=timeout)
                logs.append("relinked with " + " ".join(libs))
                err = (r2.stderr or "") + (r2.stdout or "")
                r = r2
            except (OSError, subprocess.SubprocessError) as e:
                logs.append(f"relink: {e}")
    logs.append(err)
    ok = r.returncode == 0 and out.exists()
    return {"ok": ok, "binary": out if ok else None, "log": "\n".join(logs)[-4000:]}


# Undefined-symbol prefix -> the library that defines it. Only libraries a build machine
# plausibly has; one that is absent simply fails to link and is reported as such.
_SYM_LIBS = (
    (re.compile(r"\b(inflate|deflate|compress2?|uncompress|crc32|adler32|zlib)"), "-lz"),
    (re.compile(r"\blzma_"), "-llzma"),
    (re.compile(r"\b(jpeg_|jinit_|jdiv_|jzero_|jcopy_)"), "-ljpeg"),
    (re.compile(r"\bpng_"), "-lpng"),
    (re.compile(r"\bBZ2_"), "-lbz2"),
    (re.compile(r"\bXML_"), "-lexpat"),
    (re.compile(r"\b(xmlParse|xmlFree|xmlRead)"), "-lxml2"),
    (re.compile(r"\bzstd"), "-lzstd"),
    (re.compile(r"\b(WebP|webp)"), "-lwebp"),
    (re.compile(r"\biconv"), "-liconv"),
    (re.compile(r"\bpthread_"), "-lpthread"),
    (re.compile(r"\bdl(open|sym|close)\b"), "-ldl"),
    (re.compile(r"^(sin|cos|tan|pow|log|exp|floor|ceil|sqrt|fabs|atan2?|round)$"), "-lm"),
)
_UNDEF_RE = re.compile(r"undefined (?:reference to|symbol:?) [`'\"]?([A-Za-z_][\w]*)")


def symbols_defined_in(srcs) -> set:
    """The function names DEFINED by these translation units, by their definitions in the text.

    Used to answer one question before borrowing a system library: is this undefined symbol one
    of the TARGET's own? If it is, a `-l` flag does not fix the build -- it replaces the thing
    under test with the distribution's copy, uninstrumented, and the campaign then measures
    nothing while reporting millions of executions.
    """
    names: set = set()
    for src in srcs or ():
        try:
            txt = Path(src).read_text(errors="ignore")
        except OSError:
            continue
        for m in _FN_DEF.finditer(txt):
            names.add(m.group(1))
    return names


def _libs_for_undefined(log: str) -> list:
    """The `-l` flags for the symbols this link could not resolve, in a stable order."""
    syms = set(_UNDEF_RE.findall(log or ""))
    out = []
    for pat, lib in _SYM_LIBS:
        if lib in out:
            continue
        if any(pat.search(sym) for sym in syms):
            out.append(lib)
    if syms and "-lm" not in out:
        out.append("-lm")                                # cheap, and a codec usually wants it
    return out


_ASAN_HDR = re.compile(r"(==\d+==ERROR: (?:AddressSanitizer|UndefinedBehaviorSanitizer).*)", re.S)


def run_libfuzzer(binary, workdir, *, seconds: int = 30, max_len: int = 4096,
                  corpus: list | None = None) -> dict:
    """Run the libFuzzer `binary` for `seconds`. Returns {crashes:[{input, report}], runs, log}.
    Each crash is the reproducing input (bytes) plus the sanitizer report libFuzzer printed."""
    workdir = Path(workdir)
    art = workdir / "lf-artifacts"
    art.mkdir(parents=True, exist_ok=True)
    corpus_dir = workdir / "lf-corpus"
    corpus_dir.mkdir(exist_ok=True)
    for i, seed in enumerate(corpus or []):
        try:
            (corpus_dir / f"seed{i}").write_bytes(seed if isinstance(seed, (bytes, bytearray)) else bytes(seed))
        except OSError:
            pass
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0:" + env.get("ASAN_OPTIONS", "")
    argv = [str(binary), str(corpus_dir), f"-max_total_time={seconds}", f"-max_len={max_len}",
            f"-artifact_prefix={art}/", "-print_final_stats=1", "-rss_limit_mb=2048"]
    crashes = []
    before = set(art.iterdir())
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=seconds + 30, env=env,
                           cwd=str(workdir))
        out = (r.stderr or "") + (r.stdout or "")
    except subprocess.TimeoutExpired as e:
        out = (e.stderr or b"").decode("latin-1", "ignore") if isinstance(e.stderr, bytes) else (e.stderr or "")
    m = _ASAN_HDR.search(out)
    report = m.group(1)[:4000] if m else None
    for f in sorted(set(art.iterdir()) - before):
        if f.name.startswith(("crash-", "oom-", "timeout-", "leak-")):
            try:
                crashes.append({"input": f.read_bytes(), "report": report})
            except OSError:
                pass
    # THE CORPUS IS THE PRODUCT, not a by-product. libFuzzer writes every input that reached new
    # coverage into this directory -- 1,208 of them in one 420 s run on libtiff -- and it lived in
    # the stage's scratch directory, so every run started from nothing and re-derived the same
    # coverage. Coverage-guided fuzzing is the one engine whose work COMPOUNDS; discarding the
    # corpus discards the compounding. Handing it back lets the caller keep it.
    return {"crashes": crashes, "log": out[-4000:], "corpus": _harvest(corpus_dir)}


#: Bounds on a kept corpus: enough to matter, small enough to load every run. libFuzzer prefers
#: short inputs, so smallest-first keeps the units that are cheapest to execute.
CORPUS_MAX_UNITS = 2000
CORPUS_MAX_BYTES = 8 << 20


def _harvest(corpus_dir: Path) -> list:
    """The corpus after a run: seeds plus every unit that reached new coverage, smallest first."""
    units = []
    try:
        for f in corpus_dir.iterdir():
            if not f.is_file():
                continue
            try:
                units.append(f.read_bytes())
            except OSError:
                continue
    except OSError:
        return []
    units.sort(key=len)
    out, total = [], 0
    for u in units:
        if len(out) >= CORPUS_MAX_UNITS or total + len(u) > CORPUS_MAX_BYTES:
            break
        out.append(u)
        total += len(u)
    return out
