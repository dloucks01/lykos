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


def _declared_in_header(root, fn: str):
    """The header that declares `fn`, if any. A function in the PUBLIC header is the library's
    API -- the surface an application reaches, so a bug behind it is a bug anyone can reach."""
    # `NAME(` is not the only spelling of a declaration: bzip2 wraps every name in a calling
    # convention macro -- `BZ_EXTERN int BZ_API(BZ2_bzBuffToBuffDecompress) (...)` -- so the name
    # is followed by `)`. Accepting the punctuation that can follow a declared name matches both
    # without matching prose that merely mentions the function.
    pat = re.compile(r"\b" + re.escape(fn) + r"\s*[(),;]")
    for h in sorted(Path(root).rglob("*.h")):
        if any(seg in _SKIP_DIRS for seg in h.relative_to(Path(root)).parts):
            continue
        try:
            if pat.search(h.read_text(errors="ignore")):
                return h
        except OSError:
            continue
    return None


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
    if not existing and not known and not harness_fn:
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
    if (harness_fn or known) and not existing:
        # For a known harness, scope by the OPEN symbol it is built around: the directory that
        # defines the library's entry point is the library.
        anchor_fn = harness_fn or _KNOWN_HARNESSES[known[0]]["symbols"][0]
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
    incs = []
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
