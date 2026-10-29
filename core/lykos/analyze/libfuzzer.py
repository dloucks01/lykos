"""Coverage-guided in-process fuzzing of C/C++ SOURCE via libFuzzer.

The built-in engine is blind havoc with bolt-on breakpoint coverage; libFuzzer is a real
coverage-guided, in-process fuzzer that clang provides for free with `-fsanitize=fuzzer`. Real
source -- especially libraries with no `main` -- is the case it fits: build an
`LLVMFuzzerTestOneInput` harness (one the project already ships, as OSS-Fuzz projects do, or one
synthesized for a named entry function) with ASan+UBSan, let libFuzzer drive coverage, and harvest
each crash with its sanitizer report -- a confirmed finding with a source file:line and no oracle.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_log = logging.getLogger(__name__)

_C_EXT = {".c"}
_CXX_EXT = {".cc", ".cpp", ".cxx", ".c++", ".C"}
_SRC_EXT = _C_EXT | _CXX_EXT
_HARNESS_SYM = "LLVMFuzzerTestOneInput"
# `int main(` misses the K&R spelling `main(argc, argv)`, which libtiff's contrib still
# uses -- and a missed main collides with libFuzzer's own ("multiple definition of `main'").
_MAIN_RE = re.compile(r"^(?:[A-Za-z_][\w \t*]*[ \t*]+)?main[ \t]*\(", re.M)
_HARNESS_RE = re.compile(_HARNESS_SYM)
#: A harness DEFINES the entry point. openjpeg ships `tests/fuzzers/fuzzingengine.c`, which
#: declares `LLVMFuzzerTestOneInput` and defines `main` -- it is OSS-Fuzz's standalone driver,
#: the thing you link INSTEAD of libFuzzer. Mentioning the symbol was the whole test, so that
#: driver was openjpeg's top-ranked door: it would have linked a second `main` against
#: libFuzzer's own and left the entry point undefined, and a first door that cannot build is
#: the whole engine failing on the target.
_HARNESS_DEF = re.compile(_HARNESS_SYM + r"\s*\([^;{]*\)\s*\{", re.S)
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


def find_harnesses(root, *, limit: int = 8) -> list:
    """Every source file defining LLVMFuzzerTestOneInput, shallowest first.

    A project that ships harnesses usually ships SEVERAL -- an OSS-Fuzz tree has one per entry
    point, which is the very breadth we synthesize for a tree that has none -- and taking the
    first one `rglob` happened to yield threw the rest away. They cannot be linked together (two
    definitions of the same symbol), so each is its own build.
    """
    out = []
    for p in sorted(Path(root).rglob("*")):
        if not (p.is_file() and p.suffix in _SRC_EXT):
            continue
        rel = p.relative_to(Path(root)).parts
        if any(seg in _SKIP_DIRS for seg in rel):
            continue
        # A VENDORED PROJECT'S HARNESS IS NOT THIS PROJECT'S. mupdf bundles harfbuzz and
        # freetype, each of which ships its own libFuzzer harness, and they are shallower than
        # anything mupdf writes -- so the plan for mupdf was five harnesses fuzzing harfbuzz and
        # freetype, with every finding filed against mupdf. The bundled code is reachable the
        # honest way, through mupdf's own entry points.
        if any(seg.lower() in _VENDOR_DIRS for seg in rel[:-1]):
            continue
        try:
            if _HARNESS_DEF.search(p.read_text(errors="ignore")):
                out.append(p)
        except OSError:
            pass
    out.sort(key=lambda p: (len(p.relative_to(Path(root)).parts), str(p)))
    return out[:max(0, limit)]


def find_harness(root) -> Path | None:
    """The project's own harness, if it ships one. See `find_harnesses`."""
    found = find_harnesses(root, limit=1)
    return found[0] if found else None


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


_DEFS_CACHE: dict = {}


def defs_index(root) -> dict:
    """{name: (file, params)} for every function the library DEFINES, by one scanner.

    `fn_params`, `fn_def_file` and `fn_first_arg_type` each carried their own ANSI-only pattern,
    and that is how a correct plan produced a harness that crashes on its first input: zlib is
    written in K&R style, the PLANNER learned to read it, and `fn_params("gzopen")` still
    answered `[]`. The shape was then inferred as `cstring`, so the harness declared
    `void gzopen(char *)` and called the real two-parameter `gzopen(path, mode)` with one
    argument -- `mode` was whatever happened to be in the register, zlib dereferenced it, and the
    campaign reported an ASan SEGV in zlib on execution one. A fabricated crash in a real library
    is the worst output this tool can produce, and three copies of one regex is how it got there.
    """
    key = str(root)
    if key in _DEFS_CACHE:
        return _DEFS_CACHE[key]
    idx: dict = {}
    sa = static_aliases(root)
    for path, txt in _library_srcs(root):
        for name, params in _fn_defs(txt, sa):
            if name in _KEYWORDS:
                continue
            idx.setdefault(name, (path, params))
    return _cache_put(_DEFS_CACHE, key, idx)


def fn_params(root, fn: str) -> list:
    """`fn`'s parameter type spellings, or [] when it is not found / takes none."""
    params = defs_index(root).get(fn, (None, []))[1]
    return [] if params == ["void"] else list(params)


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
#: Directories holding ANOTHER PROJECT, bundled. openjpeg vendors zlib, libtiff and lcms2 under
#: `thirdparty/`, so the plan for openjpeg was `known zlib`, `TIFFOpen()`, `gzopen()` and
#: `cmsOpenProfileFromFile()` -- four doors into four other libraries, each finding filed against
#: openjpeg. A vendored library's API is not this target's API, the same way a platform port's is
#: not; its code is still compiled and still reachable THROUGH openjpeg's own entry points.
_VENDOR_DIRS = ("thirdparty", "third_party", "3rdparty", "external", "externals", "vendor",
                "subprojects", "deps", "dependencies")


#: A declaration whose parameter list is wrapped in a macro: `gzopen OF((const char *path, const
#: char *mode))`. zlib and libpng (`PNGARG((...))`) both do it, as does every library that still
#: supports a pre-ANSI compiler. The name the reader sees is then the MACRO's -- the constructor
#: search read `gzopen OF((...))` as a function called `OF`, found no name that looked like a
#: constructor, and zlib's `gzopen` -> `gzread` -> `gzclose` triple did not exist as far as the
#: synthesizer was concerned. `#define OF(args) args`, so unwrapping it is what the preprocessor
#: would do.
#: Bounded on purpose: with an unlimited `.*?` an unbalanced `((` would match the next `))`
#: hundreds of lines away and the substitution would mangle every declaration in between. A
#: parameter list is never that long.
_MACRO_ARGS = re.compile(r"\b[A-Z_]\w*\(\((.{0,400}?)\)\)", re.S)


def _unwrap_macro_args(text: str) -> str:
    return _MACRO_ARGS.sub(lambda m: "(" + m.group(1) + ")", text or "")


#: An install rule names the headers a project SHIPS, which is the definition of its API.
#: `include_HEADERS`, `pkginclude_HEADERS`, `nobase_include_HEADERS`, `libtiffinclude_HEADERS`
#: and libsndfile's `nodist_include_HEADERS` are all the same automake rule under a prefix.
_INSTALL_AUTOMAKE = re.compile(r"^[ \t]*\w*include_HEADERS[ \t]*\+?=((?:[^\n\\]|\\\n)*)", re.M)
_INSTALL_CMAKE = re.compile(r"\binstall\s*\(\s*FILES\b(.{0,2000}?)\)", re.S | re.I)
_INSTALL_MESON = re.compile(r"\binstall_headers\s*\((.{0,2000}?)\)", re.S)
#: `set(ZLIB_PUBLIC_HDRS ... zlib.h)` -- zlib installs its headers through a variable, so the
#: install rule itself names no file at all.
_CMAKE_SET = re.compile(r"\bset\s*\(\s*([A-Za-z_]\w*)(.{0,2000}?)\)", re.S | re.I)
_HDR_NAME = re.compile(r"[\w.+-]+\.h(?:h|pp|xx)?\b")
_BUILD_FILES = ("Makefile.am", "CMakeLists.txt", "meson.build")
_INSTALLED_CACHE: dict = {}


def _strip_comments(text: str) -> str:
    """`#install(FILES mj2.h ...)` is openjpeg declining to install that header, not installing it."""
    return re.sub(r"(?m)^[ \t]*#.*$", "", text or "")


#: A directory that builds PROGRAMS and no library is not the library, whatever it is called.
#: `_NOT_LIBRARY` is a list of names, and the names keep being different: libsndfile's regression
#: PROGRAM lives in `regtest/`, so `db_open` and `db_close` -- a sqlite wrapper from a test
#: driver -- were ranked as libsndfile entry points, and openjpeg's command line tools live in
#: `src/bin/`. The project's own build file says which it is.
_AM_PROGRAMS = re.compile(r"^[ \t]*\w*_PROGRAMS[ \t]*\+?=", re.M)
_AM_LIBRARIES = re.compile(r"^[ \t]*\w*_(?:LTLIBRARIES|LIBRARIES)[ \t]*\+?=", re.M)
_CMAKE_EXE = re.compile(r"\badd_executable\s*\(", re.I)
_CMAKE_LIB = re.compile(r"\badd_library\s*\(", re.I)
_MESON_EXE = re.compile(r"\bexecutable\s*\(")
_MESON_LIB = re.compile(r"\b(?:static_|shared_)?library\s*\(")
_PROGRAM_CACHE: dict = {}


def program_dirs(root) -> frozenset:
    """Directories this project builds PROGRAMS in and no library, relative to `root`.

    Read from the build files, not from a list of directory names: a program's helper function
    is not an entry point into the library -- it cannot be reached by any caller of the library
    and, with `main` excluded from the build, it usually cannot even link. The root is never
    reported, because a project that builds one program at its top level still has to offer
    those sources as candidates or there is nothing left to fuzz.
    """
    key = str(root)
    if key in _PROGRAM_CACHE:
        return _PROGRAM_CACHE[key]
    root = Path(root)
    out: set = set()
    pairs = (("Makefile.am", _AM_PROGRAMS, _AM_LIBRARIES),
             ("CMakeLists.txt", _CMAKE_EXE, _CMAKE_LIB),
             ("meson.build", _MESON_EXE, _MESON_LIB))
    for name, exe, lib in pairs:
        for bf in sorted(root.rglob(name))[:200]:
            rel = bf.relative_to(root).parts
            if any(seg in _SKIP_DIRS for seg in rel) or len(rel) == 1:
                continue                                 # never the root: see above
            try:
                txt = _strip_comments(bf.read_text(errors="ignore"))
            except OSError:
                continue
            if exe.search(txt) and not lib.search(txt):
                out.add(Path(*rel[:-1]))
    return _cache_put(_PROGRAM_CACHE, key, frozenset(out))


def installed_headers(root) -> frozenset:
    """The BASENAMES of the headers this project installs, from its own build files.

    A function declared in a header the project ships is reachable by an application; one
    declared only in an internal header is not. Nothing distinguished them, so libsndfile's
    strongest triple came out of `src/common.h` -- `psf_allocate()` -> `psf_fopen()` -> a
    `SF_PRIVATE` the library builds for itself. That harness did not even compile
    ("use of undeclared identifier 'psf_allocate'"), and had it compiled it would have fuzzed
    an API no caller can reach while `sf_open` -> `sf_read_*` -> `sf_close`, the door every
    application uses, went untested. The project already says which headers are its API; this
    reads the statement instead of guessing from a path.

    Basenames, not paths, because an install rule is written relative to its own build file and
    may name a header this build has yet to generate (`nodist_include_HEADERS = sndfile.h`).
    Empty when the tree states nothing -- bzip2 installs with a shell script -- and every caller
    treats an empty answer as "unknown", never as "nothing is public".
    """
    key = str(root)
    if key in _INSTALLED_CACHE:
        return _INSTALLED_CACHE[key]
    root = Path(root)
    names: set = set()
    for name in _BUILD_FILES:
        for bf in sorted(root.rglob(name))[:64]:
            rel = bf.relative_to(root).parts
            if any(seg in _SKIP_DIRS for seg in rel):
                continue
            # A BUNDLED PROJECT'S install rule is not this library's. zlib ships
            # `contrib/minizip`, whose `minizip_include_HEADERS` names `zip.h` and `unzip.h` --
            # taking it would have made zlib's own `zlib.h` "not installed" and excluded
            # `gzopen` from the candidates it has always been found through.
            if any(seg.lower() in _NOT_LIBRARY or seg.lower() in _PORT_DIRS
                   or seg.lower() in _VENDOR_DIRS for seg in rel[:-1]):
                continue
            try:
                txt = _strip_comments(bf.read_text(errors="ignore"))
            except OSError:
                continue
            found = []
            for pat in (_INSTALL_AUTOMAKE, _INSTALL_CMAKE, _INSTALL_MESON):
                found += [m.group(1) for m in pat.finditer(txt)]
            if not found:
                continue
            setvars = {m.group(1): m.group(2) for m in _CMAKE_SET.finditer(txt)}
            for blob in found:
                for var in set(re.findall(r"\$[{(]([A-Za-z_]\w*)[})]", blob)):
                    blob += " " + setvars.get(var, "")
                names.update(_HDR_NAME.findall(blob))
    # A STATEMENT WE CANNOT CHECK IS NOT EVIDENCE. On a tree nobody has configured, the public
    # header may not exist yet -- libsndfile's `sndfile.h` is generated from `sndfile.h.in` --
    # and acting on the rule then excludes every candidate the tree really has while the API it
    # names is unreachable. If not one installed header is on disk, the honest answer is the
    # same as having found no rule at all: unknown.
    try:
        on_disk = {h.name for h in list(root.rglob("*.h"))[:4000]}
    except OSError:
        on_disk = set()
    if names and not (names & on_disk):
        names = set()
    return _cache_put(_INSTALLED_CACHE, key, frozenset(names))


def header_is_installed(root, header) -> bool:
    """Does this project ship `header`? False only when it ships a DIFFERENT set -- an unknown
    answer (a tree with no install rule) is not evidence that a header is private."""
    installed = installed_headers(root)
    return (not installed) or Path(header).name in installed


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
        if any(seg in _PORT_DIRS or seg in _VENDOR_DIRS for seg in rel[:-1]):
            continue
        try:
            # UNWRAPPED FIRST. A declaration whose parameter list is wrapped in a macro
            # (`gzread OF((gzFile, voidp, unsigned))`) has no punctuation after the name, so the
            # function read as undeclared and a public entry point was treated as private.
            # zlib's `gzread` matched anyway, from an unrelated second mention in the header --
            # i.e. by luck, which is the sort of thing that works until the next library.
            if pat.search(_unwrap_macro_args(h.read_text(errors="ignore"))):
                hits.append(h)
        except OSError:
            continue
    if not hits:
        return None
    # A header the project INSTALLS wins outright: libsndfile declares `sf_close` in both the
    # shipped `sndfile.h` and the internal `common.h` (same directory, same depth), and the
    # tie-break below picked `common.h` for being the shorter name -- so a public entry point
    # was reported through a header no application includes. Then the shallowest path, then the
    # shortest: a library's own public header sits beside its sources (`lib/expat.h`), while a
    # platform or bundled copy is nested deeper.
    _ins = installed_headers(root)
    hits.sort(key=lambda h: (0 if h.name in _ins else 1,
                             len(h.relative_to(Path(root)).parts), len(str(h))))
    return hits[0]


#: The per-tree scans below are cached because every scanner asks for them, and BOUNDED because
#: the API server is long-lived: each analyzed target materializes its source into a fresh scratch
#: path, so the key is never reused and an unbounded cache would hold every tree the process ever
#: saw (libtiff alone indexes some two thousand names).
_CACHE_ROOTS = 8


def _cache_put(cache: dict, key, value):
    if len(cache) >= _CACHE_ROOTS:
        cache.clear()
    cache[key] = value
    return value


_ALIAS_CACHE: dict = {}
_DEFINE_STATIC = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+static\b", re.M)


def static_aliases(root) -> frozenset:
    """The project's own spellings of `static`, from its own `#define`s.

    zlib writes `#define local static` in `zutil.h` and then `local int gz_load(...)` for every
    internal function, so nothing in the tree is spelled `static` at all and half of `gzread.c`
    read as public API. The project says what its keyword is; this reads it rather than carrying
    a list of idioms (`local`, `PRIVATE`, `STATIC`) that is wrong for the next project.
    """
    key = str(root)
    if key in _ALIAS_CACHE:
        return _ALIAS_CACHE[key]
    found = set()
    try:
        for h in sorted(Path(root).rglob("*")):
            if not (h.is_file() and (h.suffix == ".h" or h.suffix in _SRC_EXT)):
                continue
            rel = h.relative_to(Path(root)).parts
            if any(seg in _SKIP_DIRS for seg in rel):
                continue
            for m in _DEFINE_STATIC.finditer(h.read_text(errors="ignore")):
                found.add(m.group(1))
    except OSError:
        pass
    return _cache_put(_ALIAS_CACHE, key, frozenset(found))


def _static_before(txt: str, start: int, statics=()) -> bool:
    """Is the definition at `start` declared `static` (under any of the project's spellings)?

    `_FN_DEF` refuses a definition whose line BEGINS with `static`, which is most of them and not
    all: expat writes the storage class and the return type on the line above the name --

        static int FASTCALL
        attcmp(const void *p1, const void *p2)

    -- so `attcmp` was ranked as one of the library's entry points. A static function is not
    callable from another translation unit at all, so the harness synthesized for it cannot link:
    the cost is not a weak candidate, it is a build that fails after paying for the library's
    whole compile. Read the declaration back to its last boundary and look for the keyword.
    """
    head = txt[max(0, start - 240):start]
    cut = max(head.rfind(";"), head.rfind("}"), head.rfind("{"), head.rfind("*/"))
    words = "|".join(re.escape(w) for w in ("static", *statics))
    return re.search(r"\b(?:" + words + r")\b", head[cut + 1:]) is not None


#: A K&R (pre-ANSI) function DEFINITION: the parameter list is bare NAMES and the types follow it
#: as declarations before the body. zlib 1.2.11 is written this way throughout --
#:
#:     int ZEXPORT uncompress (dest, destLen, source, sourceLen)
#:         Bytef *dest;
#:         uLongf *destLen;
#:         const Bytef *source;
#:         uLong sourceLen;
#:     {
#:
#: -- so the ANSI pattern above matched NOTHING in the whole library: `_fn_defs` found zero
#: functions in `uncompr.c`, `gzlib.c` and `gzread.c`, and zlib was reachable only through its
#: `_KNOWN_HARNESSES` entry. The style is not a curiosity: it is what a lot of old, bug-rich C
#: looks like, which is the code most worth fuzzing.
_KR_DEF = re.compile(
    r"(?:^|\n)[ \t]*(?!static\b|typedef\b|return\b|else\b|switch\b|case\b|while\b|if\b|for\b)"
    r"(?:[A-Za-z_][\w \t*]*?[ \t*]+)?"
    r"([A-Za-z_]\w*)[ \t]*\(([ \t]*[A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*[ \t]*)\)[ \t]*\r?\n"
    r"((?:[ \t]*[A-Za-z_][^;{}()]*;[ \t]*\r?\n)+)"
    r"[ \t]*\{",
    re.M)


def _kr_params(names: str, decls: str) -> list:
    """Parameter spellings for a K&R definition, in the order the parameter list names them.

    A declaration may name several (`int a, b;`), and the type belongs to all of them. A name the
    declarations never mention defaults to `int`, which is what C89 says it is.
    """
    order = [n.strip() for n in names.split(",") if n.strip()]
    typed: dict = {}
    for line in decls.splitlines():
        line = line.strip().rstrip(";").strip()
        if not line:
            continue
        head, _, tail = line.rpartition(" ")
        if not head:
            continue
        # `Bytef *dest` -> type `Bytef *`; `int a, b` -> type `int` for both
        parts = [x.strip() for x in line.split(",")]
        first = parts[0]
        m = re.match(r"^(.*?)([A-Za-z_]\w*)$", first)
        if not m:
            continue
        base = m.group(1).strip()
        typed[m.group(2)] = f"{base} {m.group(2)}".strip()
        for extra in parts[1:]:
            stars = "*" * extra.count("*")
            nm = extra.replace("*", "").strip()
            root_t = base.replace("*", "").strip()
            if nm:
                typed[nm] = f"{root_t} {stars}{nm}".strip()
    return [typed.get(n, f"int {n}") for n in order]


def _fn_defs(txt: str, statics=()):
    """(name, params) for every NON-static function defined in `txt`, in either C style.

    The storage class is looked for up to the NAME, not up to the start of the match: the return
    type is part of the match (`local int \ngz_load(...)`), so a keyword sitting in front of the
    type is inside it.
    """
    for m in _FN_DEF.finditer(txt):
        if _static_before(txt, m.start(1), statics):
            continue
        yield m.group(1), [a.strip() for a in (m.group(2) or "").split(",") if a.strip()]
    for m in _KR_DEF.finditer(txt):
        if _static_before(txt, m.start(1), statics):
            continue
        params = _kr_params(m.group(2), m.group(3))
        if params:
            yield m.group(1), params


def _library_srcs(root):
    """The translation units a harness may call INTO, with their text: the files this tree's build
    will actually compile, minus the ones that are not the library.

    The two scanners below used to walk every `*.c` in the tree, which produced candidates that
    could not be reached even in principle:

      * a file with its OWN `main` is a PROGRAM, and `_sources(exclude_main=True)` drops it from
        the build -- so bzip2's `fopen_output_safely` and expat's `getXMLCharset` (both in a tool's
        translation unit, beside its `main`) were ranked as library entry points that could never
        link, and the top five candidates for bzip2 were all bzip2.c's own helpers;
      * a PLATFORM PORT's file is real code for another machine. expat ships `amiga/`, so
        `_68k_commenthandler` ranked above every function in the library.

    Reading each file once here also stops the scanners reading the whole tree twice.
    """
    out = []
    _progs = program_dirs(root)
    for p in _sources(Path(root), exclude_main=True):
        rel = p.relative_to(Path(root)).parts
        if any(seg.lower() in _PORT_DIRS or seg.lower() in _VENDOR_DIRS
               for seg in rel[:-1]):
            continue
        if any(seg in _NOT_LIBRARY for seg in rel[:-1]):
            continue
        # The project's own answer, for the directories whose names we would never guess.
        if any(Path(*rel[:i]) in _progs for i in range(1, len(rel))):
            continue
        try:
            txt = p.read_text(errors="ignore")
        except OSError:
            continue
        # A FUZZ HARNESS IS NOT THE LIBRARY. `_sources` keeps a harness file on purpose (it is
        # the one `main`-like unit the build wants), and it is a plain source file with a
        # non-static function in it -- so on a tree that ships its own harnesses,
        # `LLVMFuzzerTestOneInput` was itself ranked as one of the library's entry points and a
        # harness was synthesized to call it.
        if _HARNESS_RE.search(txt):
            continue
        out.append((p, txt))
    return out


#: Named like something the library calls rather than something a caller calls.
_CALLBACKISH = re.compile(r"(?:^|_)(?:callback|cb|handler|hook)$|^on_", re.I)


def rank_harness_fns(root, *, limit: int = 8) -> list:
    """Entry functions worth fuzzing in a LIBRARY with no in-tree harness, strongest first.

    This returned the FIRST non-static function taking a `char*` in alphabetical file order,
    which on libtiff 4.0.3 meant `convertHTMLcodes` -- an HTML-entity helper inside a command
    line tool. In-process fuzzing then exercised a string unescaper while libtiff's own decoders
    (where its CVEs are) were never called. The candidate set is unchanged; what is new is that
    they are RANKED: the library's public, input-consuming API first.

    It also returned ONLY the winner, and a library is not one function. libtiff declares some
    two hundred public entry points and we fuzzed one of them, so "we fuzzed libtiff" meant "we
    fuzzed `TIFFOpen`" -- every decoder reached only if that one door happened to lead there.
    Ranking already produced the whole ordered list; throwing all but its head away was the
    waste. `plan_harnesses` takes as many as the budget can run.
    """
    root = Path(root)
    best: dict = {}
    # EXCLUSION, not a penalty. A score penalty still let a sample program win when nothing in
    # the library itself was a candidate: zlib's `gzlog_open` (from `examples/`) was picked and
    # the link failed on `gzlog_close`, which is not compiled at all. A function outside the
    # library is not a worse choice, it is not a choice -- see `_library_srcs`.
    _sa = static_aliases(root)
    for _p, txt in _library_srcs(root):
        for name, raw in _fn_defs(txt, _sa):
            if name in _KEYWORDS:
                continue
            first = raw[0] if raw else ""
            if not _PTR_FIRST.match(first):
                continue                                 # nothing to deliver the bytes through
            # IT HAS TO BE AN INPUT. A `void *` with no `const` is an OUT parameter or an opaque
            # context, and handing it the fuzz bytes is a misuse that faults inside the library:
            # expat's `XmlInitUnknownEncoding(void *mem, ...)` WRITES an encoding table into
            # `mem`, so a harness passing libFuzzer's buffer there earns a heap-buffer-overflow
            # write in expat's own code -- a finding that would be filed against expat and caused
            # entirely by us. `const` is the library telling us it only reads.
            _const = first.lower().lstrip().startswith("const")
            if not _const and re.match(r"^\s*(void|unsigned\s+char|uint8_t|u_char)\s*\*",
                                       first, re.I):
                continue
            # Every argument past the first has to be INVENTED by the harness, and an invented
            # one is a lie the library may crash on -- `TIFFClientOpen` is the public, perfectly
            # parser-ish entry point of libtiff and it takes eight callbacks, so a synthesized
            # call passes NULL function pointers and faults inside our own harness. Prefer the
            # narrow door: `TIFFOpen(name, mode)` is the same parser reached honestly.
            score = -2 * max(0, len(raw) - 2)
            if any(_opaque_param(a) for a in raw[1:]):
                score -= 6
            if not _const:
                score -= 3                               # plausibly input, but it does not say so
            if _PARSERISH.search(name):
                score += 4
            # A CALLBACK IS CALLED BY THE LIBRARY, so it is not a way IN: openjpeg's ranked tail
            # held `error_callback()` and `info_callback()`, which take the message the library
            # has already built and print it. Fuzzing one spends a door's share of the slice and
            # reports a clean campaign, which reads as breadth. A penalty and not an exclusion,
            # because the name is a convention and not a contract -- a tree whose only
            # candidates are callbacks still offers them, last.
            if _CALLBACKISH.search(name):
                score -= 6
            _hdr = _declared_in_header(root, name)
            if _hdr is not None:
                score += 3
                # The project SHIPS this header, so an application can reach the function --
                # the difference between libsndfile's `sf_open` and its internal `psf_fopen`.
                # A bonus and not an exclusion here: a single function is called through its own
                # forward declaration, so an internal one still compiles, still runs, and is
                # worth fuzzing once the public doors are taken.
                if header_is_installed(root, _hdr) and installed_headers(root):
                    score += 4
            if score > best.get(name, -(10 ** 6)):
                best[name] = score
    # Ties broken by NAME, so a plan is reproducible: two runs of the same tree have to build the
    # same harnesses, or a finding cannot be attributed to the entry point that found it.
    ranked = sorted(best.items(), key=lambda kv: (-kv[1], kv[0]))
    return [name for name, _ in ranked[:max(0, limit)]]


def pick_harness_fn(root) -> str | None:
    """The single best entry function to fuzz, or None. See `rank_harness_fns`."""
    ranked = rank_harness_fns(root, limit=1)
    return ranked[0] if ranked else None


def fn_first_arg_type(root, fn: str):
    """The spelling of `fn`'s FIRST parameter type in the source (e.g. "const char *", "char *"),
    or "" when it takes no args, or None if not found. Needed to forward-declare `fn` in the harness
    so C++ name mangling matches -- `extern void fn()` mangles differently than `fn(const char*)` and
    fails to link. C is lenient, but the exact declaration is correct for both."""
    hit = defs_index(root).get(fn)
    if hit is None:
        return None
    params = hit[1]
    if not params or params == ["void"]:
        return ""
    first = params[0].strip()
    # drop the parameter NAME, keeping the type spelling
    return re.sub(r"\b[A-Za-z_]\w*\s*$", "", first).strip() or first


def fn_def_file(root, fn) -> Path | None:
    """The source file that DEFINES `fn` (for its language: .c -> a C symbol, .cc/.cpp -> a mangled
    C++ symbol -- which decides whether the harness declares it `extern "C"`)."""
    return defs_index(root).get(fn, (None, None))[0]


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
    # A C++ SYMBOL IS MANGLED FROM ITS PARAMETER TYPES, so the declaration has to name the real
    # ones. `_types_only` rewrites every pointer to `void *` -- which is what lets a C project's
    # own typedefs be declared at all (see its docstring) and, for a C++ function, produces a
    # declaration of a DIFFERENT function: `load(void*)` where the project defines
    # `load(const char*)`, so the harness compiled and the link failed on an undefined symbol.
    # C is unaffected either way: its symbol names carry no types.
    mangled = cxx and not c_linkage
    types = [_handle_type(a) for a in params] if mangled else []
    if mangled:
        args = ", ".join([f"({types[0]})path"]
                         + [f"({ty}){v}" for ty, v in zip(types[1:], _arg_values(params[1:]))])
        decl = f'{fn_qual}void *{fn}({", ".join(types) or "void"});\n'
    else:
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
#: Names that MANAGE MEMORY for the handle rather than consume input through it. `(void *ptr,
#: size_t size)` is exactly the shape of a (buffer, length) pair, so expat's `XML_MemRealloc`
#: ranked as the library's second-best consumer -- a reallocator fed fuzz bytes as a POINTER.
_ALLOC_WORDS = re.compile(r"(malloc|realloc|calloc|_mem|mem_|memory)", re.I)


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


_TYPEDEF_PTR = re.compile(
    r"typedef\s+(?:const\s+)?(?:unsigned\s+|signed\s+)?"
    r"(?:void|char|uint8_t|u_char)\s+(?:[A-Z_]\w*\s+)?\*\s*([A-Za-z_]\w*)\s*;")
_PTR_TYPEDEF_CACHE: dict = {}


def byte_ptr_typedefs(root) -> frozenset:
    """Names the project typedefs to a byte-or-void POINTER (`typedef void *voidp;`).

    A buffer parameter does not have to be spelled with a `*`. zlib's reader is
    `gzread(gzFile file, voidp buf, unsigned len)` -- a textbook (pointer, length) pair that
    `_PTR_FIRST` could not see, so the library's one synthesizable door was `gzopen` followed by
    `gzclose`: a harness that opens the fuzz file, reads its header and closes it again without
    ever inflating a byte.
    """
    key = str(root)
    if key in _PTR_TYPEDEF_CACHE:
        return _PTR_TYPEDEF_CACHE[key]
    found = set()
    try:
        for h in sorted(Path(root).rglob("*.h")):
            rel = h.relative_to(Path(root)).parts
            if any(seg in _SKIP_DIRS for seg in rel):
                continue
            for m in _TYPEDEF_PTR.finditer(h.read_text(errors="ignore")):
                found.add(m.group(1))
    except OSError:
        pass
    return _cache_put(_PTR_TYPEDEF_CACHE, key, frozenset(found))


def is_byte_ptr(param: str, ptrs=()) -> bool:
    """Can the fuzz bytes (or a buffer) be delivered through this parameter?"""
    if _PTR_FIRST.match((param or "").strip()):
        return True
    ty = _handle_type(param or "").replace("const", "").strip()
    return ty.rstrip("*").strip() in set(ptrs)


def _buf_len_at(params: list, ptrs=()) -> int:
    """Index of the first (pointer, length) PAIR in `params`, or -1.

    This is the shape libFuzzer hands over directly, and finding it is what tells a
    handle-threading consumer (`XML_Parse(XML_Parser, const char *s, int len, int isFinal)`) from
    a function that merely happens to take a handle.
    """
    for i in range(len(params) - 1):
        if is_byte_ptr(params[i], ptrs) and _LEN_PARAM.search(params[i + 1]):
            return i
    return -1


def find_handle_triples(root, *, limit: int = 6) -> list:
    """Every create -> consume -> destroy triple this tree offers, strongest first.

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

    A handle usually has SEVERAL consumers -- expat takes bytes through both `XML_Parse` and
    `XML_ParseBuffer`, and a decoder library feeds the same handle from a file, a buffer and a
    callback -- so one triple per handle type is a fraction of the library's input surface. The
    constructor and destructor are resolved ONCE PER HANDLE TYPE and shared by its consumers:
    finding them walks the tree, and doing that per consumer was the reason this only ever
    returned one.

    Each triple is `{"header", "handle", "ctor", "ctor_params", "consume", "consume_params",
    "dtor", "buf_at"}`. The header matters: the handle type is OPAQUE, so the harness cannot
    forward-declare its way around it and has to `#include` the library's own public header --
    which is what a real harness does anyway, and brings every prototype with it.
    """
    root = Path(root)
    # 1. a CONSUMER: an opaque first parameter followed by a (pointer, length) pair.
    cands = []
    _sa, _ptrs = static_aliases(root), byte_ptr_typedefs(root)
    for _p, txt in _library_srcs(root):
        for name, params in _fn_defs(txt, _sa):
            if name in _KEYWORDS or _DTOR_WORDS.search(name) or _ALLOC_WORDS.search(name):
                continue
            if len(params) < 3 or not _opaque_param(params[0]):
                continue                                 # no handle to thread
            at = _buf_len_at(params[1:], _ptrs)
            if at < 0:
                continue
            htype = _handle_type(params[0])
            if not htype or htype in ("void *", "void*"):
                continue                                 # `void *` is not a named handle type
            hdr = _declared_in_header(root, name)
            if hdr is None:
                continue                                 # a private function is not an API
            # NOR IS AN INTERNAL ONE. Being declared in *some* header was the whole test, and
            # libsndfile's `src/common.h` -- the struct definitions the library keeps to itself
            # -- passed it, so the strongest triple in the tree was `psf_allocate` ->
            # `psf_fopen`: a door no application has, on a handle the harness cannot honestly
            # build. Excluded rather than penalised, because a penalty still wins when the
            # internal API is the only candidate, and a triple through it cannot be a finding.
            if not header_is_installed(root, hdr):
                continue
            score = 4 + (3 if _PARSERISH.search(name) else 0)
            cands.append((score, name, params, at + 1, htype, hdr))
    cands.sort(key=lambda c: (-c[0], c[1]))
    out, resolved = [], {}
    for _score, name, params, buf_at, htype, hdr in cands:
        if len(out) >= max(0, limit):
            break
        if htype not in resolved:
            ctor = _find_by_return(root, hdr, htype, _CTOR_WORDS, exclude={name})
            dtor = (_find_taking_only(root, htype, _DTOR_WORDS, exclude={name, ctor[0]},
                                      kin=ctor[0]) if ctor else None)
            resolved[htype] = (ctor, dtor)
        ctor, dtor = resolved[htype]
        if not ctor:
            continue
        if name in (ctor[0], dtor):
            continue
        out.append({"header": hdr, "handle": htype, "ctor": ctor[0], "ctor_params": ctor[1],
                    "consume": name, "consume_params": params, "dtor": dtor, "buf_at": buf_at,
                    "ctor_file": ctor_opens_a_file(ctor[0], ctor[1])})
    return out


def find_handle_triple(root):
    """The strongest create -> consume -> destroy triple, or None. See `find_handle_triples`."""
    triples = find_handle_triples(root, limit=1)
    return triples[0] if triples else None


def _find_by_return(root, header, htype: str, words, exclude=()):
    """(name, params) of a function in `header` whose RETURN type is `htype`, or None.

    The return type is matched in the text BEFORE the name rather than by parsing a declaration,
    because a public header usually wraps it in an export macro -- expat writes
    `XMLPARSEAPI(XML_Parser)` on the line above `XML_ParserCreate(...)` -- and no reasonable
    regex for "a C declaration" survives that. Being loose here is safe: the candidate still has
    to be named like a constructor, take only parameters we can supply, and link.
    """
    try:
        txt = _unwrap_macro_args(Path(header).read_text(errors="ignore"))
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


#: Words that RELEASE a handle for good, as against ones that merely end a phase of using it.
#: Both match `_DTOR_WORDS`, and taking whichever the tree yielded first was wrong: libtiff's
#: `TIFFImageIterEnd` matches "end" and sorts before `TIFFClose`, so the synthesized harness
#: ended the iteration and never closed the file -- a leaked TIFF handle and an open descriptor
#: on EVERY execution, which over a hundred thousand of them stops being a fuzzing campaign and
#: becomes a test of the allocator.
_DTOR_STRONG = re.compile(r"(free|destroy|close|delete|release|dispose)", re.I)


def _find_taking_only(root, htype: str, words, exclude=(), kin: str | None = None):
    """The name of the function that takes exactly one `htype` and releases it, or None.

    Ranked, not first-found, on three pieces of evidence in order:

      * it belongs to the SAME API as `kin` (the constructor), by shared name prefix. Without
        this, libtiff's handle was released by `Fax3Close` -- a codec's private teardown that
        takes a `TIFF*`, sorts before `TIFFClose`, and run against a non-fax image tears down
        state that was never set up. A fault inside it is OUR bug, filed against the library;
      * it RELEASES rather than ending a phase of use (`close` over `end`);
      * among equals, the shortest name is the library's canonical one.
    """
    bare = htype.replace("*", "").strip()
    found = []
    _sa = static_aliases(root)
    for _p, txt in _library_srcs(root):
        for name, params in _fn_defs(txt, _sa):
            if name in exclude or not words.search(name):
                continue
            if len(params) == 1 and bare and bare in params[0]:
                found.append(name)
    if not found:
        return None
    found.sort(key=lambda n: (-_shared_prefix(n, kin or ""),
                              0 if _DTOR_STRONG.search(n) else 1, len(n), n))
    return found[0]


def _shared_prefix(a: str, b: str) -> int:
    """How many leading characters two names share, case-insensitively."""
    a, b = (a or "").lower(), (b or "").lower()
    n = 0
    while n < min(len(a), len(b)) and a[n] == b[n]:
        n += 1
    return n


#: A constructor that OPENS something named, as against one that creates an empty object. The
#: distinction decides where the fuzz bytes go, and getting it wrong costs the whole campaign:
#: `TIFFOpen(const char *name, const char *mode)` and `XML_ParserCreate(const XML_Char *encoding)`
#: have the same SHAPE -- a constructor taking a string -- and NULL is the right argument for
#: exactly one of them. Passing NULL to the opener makes every execution return at `if (!h)`;
#: passing a path to the creator makes expat reject the encoding and do the same.
_OPENER_WORDS = re.compile(r"(open|load|read|from_?file|infile)", re.I)
#: Parameter names that say "this is a file". Corroborates the function name above.
_PATH_PARAM = re.compile(r"\b(path|file|filename|fname|fn|name)\b", re.I)


def _is_string_param(param: str) -> bool:
    low = (param or "").lower()
    return "*" in low and ("char" in low or "wchar" in low)


def ctor_opens_a_file(name: str, params: list) -> bool:
    """Does this constructor want the NAME of something to open?

    Evidence, not a guess: the function is named like an opener AND it takes a string. A creator
    that happens to take a string (an encoding, a mode, a label) is not named `*Open`/`*Load`,
    and an opener that takes no string has nothing to open.
    """
    if not any(_is_string_param(a) for a in params or ()):
        return False
    return bool(_OPENER_WORDS.search(name or "")
                or any(_PATH_PARAM.search(a) for a in params or ()))


def _opener_arg_values(params: list) -> list:
    """Arguments for an opener: the fuzz FILE's path, then a mode string, then nothing invented.

    The path goes in the first string parameter, which is where a C API puts it. A SECOND string
    is the mode (`TIFFOpen(name, "r")`), and anything else gets NULL or 0 -- the same discipline
    as `_ctor_arg_values`, since an argument we have to invent is a value the library may be
    entitled to trust.
    """
    out, used_path = [], False
    for a in params or ():
        if _is_string_param(a):
            if not used_path:
                out.append("path")
                used_path = True
            else:
                out.append('"r"')
        elif "*" in a:
            out.append("NULL")
        else:
            out.append("0")
    return out


#: A constructor parameter that is a CAPACITY, not a flag. Zero is a legal value for a mode or
#: an option bitmask and a MISUSE for a table size, a bucket count or an initial length.
_CAPACITY_WORDS = frozenset({"size", "sz", "len", "length", "count", "cnt", "capacity", "cap",
                             "entries", "slots", "buckets", "nmemb", "nitems", "nelem", "n"})
#: Identifiers in a parameter declaration, so the NAME can be read without the type. `size_t
#: opt` is an option that happens to be declared with a size type, and treating its type as the
#: signal would hand 16 to a flag; `int initial_capacity` is a capacity whose word sits behind
#: an underscore, where a `\b`-anchored pattern does not match at all.
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _is_capacity_param(decl: str) -> bool:
    names = _IDENT.findall(decl or "")
    if not names:
        return False
    return bool(_CAPACITY_WORDS & set(re.split(r"[^a-z0-9]+", names[-1].lower())))
#: What a sane caller passes. json-c's own code calls `lh_table_new` with
#: JSON_OBJECT_DEF_HASH_ENTRIES == 16, which is the kind of number every container picks.
_CAPACITY_DEFAULT = "16"


def _ctor_arg_values(params: list) -> list:
    """Arguments for a CONSTRUCTOR. A pointer gets NULL, a capacity gets 16, anything else 0.

    `_arg_values` exists for an opener and hands a pointer `(void*)"r"` -- a file MODE, which is
    right for `TIFFOpen(path, "r")` and wrong here. Passing "r" as expat's encoding name made
    `XML_ParserCreate` fail, so the harness returned at `if (!h)` on EVERY execution: a campaign
    that runs forty thousand inputs and tests nothing. NULL is what an optional argument of this
    kind means -- for expat, "use the encoding the document declares".

    THE CAPACITY RULE IS THE SAME LESSON, MEASURED ON json-c 0.13.1. Every scalar got 0, so the
    synthesized door was
        lh_table_new(0, NULL, NULL, NULL); lh_table_insert_w_hash(t, data, size, ...)
    and `linkhash.c` does `n = h % t->size` -- a divide by zero, reported as two confirmed
    CWE-369 findings plus a poc-backed "control-flow hijack (potential)" in a library whose own
    code calls that constructor with 16 (`JSON_OBJECT_DEF_HASH_ENTRIES`) and whose header
    documents the argument as "initial table size". A hash table of size zero is MISUSE BY THE
    CALLER, and a crash we caused by misusing the API is not a defect in the API. Meanwhile the
    library's real parser, fuzzed through its in-tree harness in the same run, took 5,508,986
    executions without a single crash.

    A fabricated crash in a real library is the worst thing this tool can emit.
    """
    out = []
    for a in params:
        if "*" in a:
            out.append("NULL")
        elif _is_capacity_param(a):
            out.append(_CAPACITY_DEFAULT)
        else:
            out.append("0")
    return out


#: Bytes the harness offers a reader for its OUTPUT. Big enough for a real decoded strip or
#: tile, small enough that a library writing past what it was told is a fault rather than a
#: quietly-absorbed overrun. Heap, not stack: ASan then reports the overflow with the library's
#: own write as the faulting frame and the harness only as the allocation site.
_OUT_BUF = 1 << 16


def synth_file_handle_harness(triple: dict, *, cxx: bool = False) -> str:
    """A harness that writes the fuzz bytes to a FILE, opens a handle ON that file, and calls one
    reader through the handle.

    THE DOMINANT SHAPE IN A FILE-FORMAT LIBRARY, and the one neither synthesizer could reach.
    `synth_handle_harness` threads the bytes through the consume call, which is right for a
    streaming parser (`XML_Parse(p, data, len, 1)`) and wrong for a reader whose bytes come from
    the file its handle was opened on: libtiff's decoders are reached as
    `TIFFOpen(path, "r")` -> `TIFFReadEncodedStrip(tif, strip, buf, size)`, where `buf` is where
    the decoded image is written TO. Synthesized the other way round, the constructor was handed
    NULL for the filename, returned NULL, and the campaign tested the `if (!h)` branch a few
    hundred thousand times -- which is how "we fuzzed libtiff's strip decoder" would have been
    reported with no strip ever decoded.

    So the (pointer, length) pair in the consumer is an OUTPUT buffer here, not the input. The
    difference is decided by the constructor (`ctor_opens_a_file`), because that is where the
    evidence is.
    """
    hdr = Path(triple["header"]).name
    h, ctor, consume, dtor = (triple["handle"], triple["ctor"], triple["consume"],
                              triple.get("dtor"))
    params, buf_at = triple["consume_params"], triple["buf_at"]
    ctor_args = ", ".join(_opener_arg_values(triple.get("ctor_params") or []))
    args = ["h"]
    i = 1
    while i < len(params):
        if i == buf_at:
            args.append(f"({_handle_type(params[i])})out")
            args.append(f"({_handle_type(params[i + 1])}){_OUT_BUF}")
            i += 2
            continue
        args.append("0")
        i += 1
    fuzz_qual = 'extern "C" ' if cxx else ""
    free_call = f"            {dtor}(h);\n" if dtor else ""
    # THE HANDLE IS RELEASED BEFORE THE OUTPUT BUFFER. A reader may KEEP the buffer it was
    # handed -- `TIFFReadBufferSetup` stores it as the handle's raw-data buffer -- so freeing
    # ours first and closing afterwards would be a use-after-free committed by the harness and
    # reported against the library. Freeing last cannot be wrong: nothing holds the pointer once
    # the handle is gone.
    return ("#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n"
            "#include <string.h>\n#include <unistd.h>\n"
            f'#include "{hdr}"\n'
            f"{fuzz_qual}int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n"
            '    char path[] = "/tmp/lykos-lfXXXXXX";\n'
            "    int fd = mkstemp(path);\n"
            "    if (fd < 0) return 0;\n"
            "    long w = (long)write(fd, data, size);\n"
            "    close(fd);\n"
            "    if (w == (long)size) {\n"
            f"        {h} h = {ctor}({ctor_args});\n"
            "        if (h) {\n"
            f"            void *out = malloc({_OUT_BUF});\n"
            "            if (out) {\n"
            f"                {consume}({', '.join(args)});\n"
            "            }\n"
            + free_call
            + "            free(out);\n"
            "        }\n"
            "    }\n"
            "    unlink(path);\n"
            "    return 0;\n}\n")


def synth_handle_harness(triple: dict, *, cxx: bool = False) -> str:
    """A harness that makes a handle, feeds the fuzz bytes through it, and frees it.

    It INCLUDES the library's public header instead of forward-declaring: the handle type is
    opaque, so there is nothing to forward-declare, and including the header is both what a real
    harness does and what makes every prototype and typedef correct by construction.

    When the constructor OPENS A FILE the bytes belong in that file instead, which is a different
    harness entirely -- see `synth_file_handle_harness`.
    """
    if triple.get("ctor_file"):
        return synth_file_handle_harness(triple, cxx=cxx)
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
                  cxx: bool = False, c_linkage: bool = False, params: list | None = None) -> str:
    """A libFuzzer harness calling `fn` with the fuzz bytes. `cstring`: fn(char*) on a
    NUL-terminated copy; `buflen`: fn(const uint8_t*, size_t). `arg_type` is `fn`'s real first
    parameter spelling from the source so the forward declaration links (C++ mangles the signature).
    `cxx` emits a C++ harness (the fuzzer entry then needs `extern "C"`); `c_linkage` declares `fn`
    itself `extern "C"` when it is a C symbol reached from a C++ harness.

    `params` is the function's full parameter list, which `buflen` needs: it declared only the
    FIRST parameter's type and then called the function with two arguments, so every harness of
    that shape failed to compile ("too many arguments to function call, expected 1, have 2").
    The shape is chosen for a (pointer, length) signature, so this was every candidate whose
    signature is the one libFuzzer hands over directly.
    """
    fuzz_qual = 'extern "C" ' if cxx else ""
    fn_qual = 'extern "C" ' if (cxx and c_linkage) else "extern "
    if kind == "buflen":
        pre = ""
        if params and len(params) >= 2:
            mangled = cxx and not c_linkage
            types = ([_handle_type(a) for a in params] if mangled
                     else _types_only(params).split(", "))
            args = [f"({types[0]})data", f"({types[1]})size"]
            args += [f"({ty}){v}" for ty, v in zip(types[2:], _arg_values(params[2:]))]
            decl = ", ".join(types)
            call = f"    {fn}({', '.join(args)});\n"
        else:
            decl = arg_type or "const unsigned char *, unsigned long"
            call = f"    {fn}(data, size);\n"
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
    # libsndfile: every decoder sits behind an open, and `sf_open` wants a PATH -- so the only
    # door a synthesized harness could reach was a function taking the bytes directly, of which
    # libsndfile has none. `sf_open_virtual` is the library's own documented answer: the caller
    # supplies the four I/O callbacks, which is how the bytes get in without a file at all.
    "sndfile": {
        "symbols": ("sf_open_virtual", "sf_readf_short", "sf_close"),
        "source": r"""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "sndfile.h"

typedef struct { const uint8_t *data; sf_count_t size, pos; } lykos_vio;

static sf_count_t vio_len(void *u) { return ((lykos_vio *)u)->size; }
static sf_count_t vio_tell(void *u) { return ((lykos_vio *)u)->pos; }

static sf_count_t vio_seek(sf_count_t off, int whence, void *u) {
    lykos_vio *d = (lykos_vio *)u;
    sf_count_t at = d->pos;
    if (whence == SEEK_SET) at = off;
    else if (whence == SEEK_CUR) at = d->pos + off;
    else if (whence == SEEK_END) at = d->size + off;
    /* CLAMPED. The callbacks are ours, so an out-of-range seek that we honoured would be our
       out-of-bounds read reported against libsndfile. A real file refuses it the same way. */
    if (at < 0) at = 0;
    if (at > d->size) at = d->size;
    d->pos = at;
    return at;
}

static sf_count_t vio_read(void *ptr, sf_count_t count, void *u) {
    lykos_vio *d = (lykos_vio *)u;
    sf_count_t left = d->size - d->pos;
    if (count > left) count = left;                 /* a short read at EOF, like read(2) */
    if (count <= 0) return 0;
    memcpy(ptr, d->data + d->pos, (size_t)count);
    d->pos += count;
    return count;
}

static sf_count_t vio_write(const void *ptr, sf_count_t count, void *u) {
    (void)ptr; (void)u;                             /* SFM_READ never writes */
    return count;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    SF_VIRTUAL_IO vio;
    lykos_vio d;
    SF_INFO info;
    SNDFILE *snd;

    vio.get_filelen = vio_len;
    vio.seek = vio_seek;
    vio.read = vio_read;
    vio.write = vio_write;
    vio.tell = vio_tell;
    d.data = data; d.size = (sf_count_t)size; d.pos = 0;
    memset(&info, 0, sizeof info);

    snd = sf_open_virtual(&vio, SFM_READ, &info, &d);
    if (!snd) return 0;
    /* sf_readf_short documents the buffer as frames * channels shorts, and `channels` is
       libsndfile's own answer about this file -- so an overrun of it is libsndfile's defect.
       The frame count only bounds the allocation; the loop decodes the whole file. */
    if (info.channels > 0 && info.channels <= 64) {
        const sf_count_t frames = 2048;
        short *buf = (short *)malloc((size_t)frames * (size_t)info.channels * sizeof *buf);
        if (buf) {
            while (sf_readf_short(snd, buf, frames) > 0) { }
            free(buf);
        }
    }
    sf_close(snd);
    return 0;
}
""",
    },
}


def _run_group(argv, *, timeout: float, cwd=None, env=None):
    """subprocess.run(capture_output=True, text=True) whose timeout takes the WHOLE process tree.

    `subprocess.run` kills only the direct child on timeout. A project's `./configure` (the
    project's own, untrusted shell script) forks compilers and test programs, and an ASan replay
    forks llvm-symbolizer; those grandchildren survived the kill and kept running unbounded after
    the stage had moved on. Here the child leads its own session and the group is SIGKILLed.
    Raises subprocess.TimeoutExpired (with whatever output was captured) like run() does."""
    import signal as _signal
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         stdin=subprocess.DEVNULL, cwd=cwd, env=env, start_new_session=True,
                         errors="replace")
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as e:
        try:
            os.killpg(p.pid, _signal.SIGKILL)
        except OSError:
            p.kill()
        try:
            out, err = p.communicate(timeout=5)
        except Exception:                                # noqa: BLE001 -- pipes held open
            out, err = "", ""
        raise subprocess.TimeoutExpired(argv, timeout, output=out, stderr=err) from e
    finally:
        if p.poll() is None:
            from .dynamic.sandbox import kill_quietly
            kill_quietly(p)                  # pipes closed first, then the whole group
    # the leader is done; anything it left behind in its group goes too
    try:
        os.killpg(p.pid, _signal.SIGKILL)
    except OSError:
        pass
    return subprocess.CompletedProcess(argv, p.returncode, out, err)


def _configure_confinement(root: Path) -> list:
    """bwrap prefix for running the project's `configure`, or [] when bwrap is unusable.

    `configure` is the project's OWN shell script -- untrusted code -- and it ran on this host
    with the server's full privileges while the build step beside it (source_project) was
    confined. Same confinement as that build step: read-only root with the secret dirs masked,
    no network, a fresh /tmp, and only the project tree writable (configure writes its generated
    headers, config.status and config.log there and nowhere else). Opt out with
    LYKOS_BUILD_UNCONFINED=1, as for the build."""
    if os.environ.get("LYKOS_BUILD_UNCONFINED") == "1":
        return []
    try:
        from .dynamic import sandbox
        return sandbox.isolate_prefix(str(root), net=False, rw_binds=[str(root)],
                                      chdir=str(root))
    except Exception:                                     # noqa: BLE001 -- best-effort containment
        return []


def ensure_configured(root, *, timeout: int = 300, report: dict | None = None) -> bool:
    """Run the project's own `configure` when a header it generates is missing.

    Detected from the templates the tree ships (`*.h.in`): if a template's generated header is
    absent, the tree has not been configured. Best-effort and quiet -- a project with no
    `configure`, or one whose configure fails, is simply built as-is and the compiler reports
    whatever is actually wrong.

    CONFINED like the build step (see `_configure_confinement`) and run in its own process
    group, so a timeout takes every test program it forked. `report`, when given, is filled with
    {"ran", "confined", "rc"} so the caller can say when it ran UNCONFINED (bwrap unusable) --
    degradation is reported, never silent.
    """
    root = Path(root).resolve()
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
        confine = _configure_confinement(root)
        env = dict(os.environ)
        if confine:
            env["CCACHE_DISABLE"] = "1"  # a ccache'd compiler would fail writing ~/.ccache (ro)
        else:
            _log.warning("libfuzzer: running %s/configure UNCONFINED (bwrap unusable)", root)
        if report is not None:
            report.update({"ran": True, "confined": bool(confine), "rc": None})
        r = _run_group(confine + ["sh", "./configure", "--disable-shared"], cwd=str(root),
                       timeout=timeout, env=env)
        if report is not None:
            report["rc"] = r.returncode
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _is_elf_exec(p: Path) -> bool:
    """True for an ELF executable (ET_EXEC or ET_DYN) -- a harness binary, not a shell wrapper or a
    library we matched by name. Reads the 18-byte ELF header only."""
    try:
        with open(p, "rb") as f:
            hdr = f.read(18)
        return len(hdr) >= 18 and hdr[:4] == b"\x7fELF" and hdr[16] in (2, 3)   # ET_EXEC / ET_DYN
    except OSError:
        return False


#: A cmake cache-preload (`cmake -C <file>`) a project ships for a minimal, fuzzer-oriented build --
#: how OSS-Fuzz / ClusterFuzzLite onboarded projects pin the knobs (disable heavy optional deps,
#: BUILD_FUZZERS ON). Recognised by name so it is the project's OWN authoritative config, not a guess.
_FUZZ_PRELOAD_DIRS = ("ci", "cmake", ".clusterfuzzlite", "tools", "")
_RE_CMAKE_NOTFOUND = re.compile(r"Could NOT find (\w+)")
_RE_CMAKE_PROVIDED = re.compile(r'provided by "([\w\-]+)"')


def _find_fuzz_preload(root: Path):
    """A cmake cache-preload the project ships for a minimal+fuzzers build, or None."""
    for d in _FUZZ_PRELOAD_DIRS:
        base = root / d if d else root
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.cmake"))[:400]:
            n = p.name.lower()
            if "fuzz" in n and any(k in n for k in ("oss", "preload", "preset", "config", "clusterfuzz")):
                return p
    return None


def _cmake_disable_flags(pkg: str) -> list:
    """Best-effort `-D` flags to turn OFF the feature that pulls in a missing package. The option
    name is not mechanical (PulseAudio -> WITH_PULSE), so try the common conventions; a flag the
    project does not define is harmlessly ignored by cmake."""
    P = re.sub(r"[^A-Za-z0-9]", "", pkg).upper()
    return [f"-DWITH_{P}=OFF", f"-DENABLE_{P}=OFF", f"-DUSE_{P}=OFF", f"-DWITH_{P}=0"]


def _collect_cmake_harnesses(bd, intree, names):
    """The harness ELFs produced under build dir `bd` (match by stem, exclude libraries) plus the
    shared-lib dirs. Returns (harnesses, lib_dirs)."""
    bd = Path(bd)
    if not bd.is_dir():
        return [], []
    found: dict = {}
    for p in bd.rglob("*"):
        if p.is_file() and p.stem in names and p.suffix == "" and os.access(p, os.X_OK) and _is_elf_exec(p):
            found.setdefault(p.stem, p)
    harnesses = [{"name": s.stem, "source": str(s), "binary": str(found[s.stem])}
                 for s in intree if s.stem in found]
    lib_dirs = sorted({str(p.parent) for p in bd.rglob("*.so*") if p.is_file()})
    return harnesses, lib_dirs


#: Core shared libraries to register as analysis targets from a harness build. Bounded because a
#: large project builds dozens of plugin .so's and each target costs a full per-target budget; the
#: biggest few are the core libs that hold the code (the rest are thin channel/codec plugins).
_LIB_TARGET_MAX = 4


def _collect_cmake_libraries(bd):
    """The largest few distinct SHARED LIBRARIES built under `bd` -- the core libs that hold the
    project's code, not the many small plugins. Real ELF .so files only (no symlinks, no sanitizer
    runtimes), deduped by version-stripped name, largest first, bounded by `_LIB_TARGET_MAX`. These
    are not runnable, but the binary static detectors / CVE fingerprint / symbolic execution read a
    .so, so registering them reaches the library code the harnesses only link."""
    import re as _re
    bd = Path(bd)
    if not bd.is_dir():
        return []
    best: dict = {}
    for p in bd.rglob("*.so*"):
        try:
            if not p.is_file() or p.is_symlink():
                continue
            n = p.name
            if not (n.endswith(".so") or ".so." in n):
                continue
            if any(x in n for x in ("libasan", "libubsan", "liblsan", "libclang_rt")):
                continue
            with open(p, "rb") as fh:
                if fh.read(4) != b"\x7fELF":
                    continue
            sz = p.stat().st_size
        except OSError:
            continue
        stem = _re.sub(r"\.so.*$", "", n)                 # libcore3.so.3.20 -> libcore3
        if stem not in best or sz > best[stem][0]:
            best[stem] = (sz, str(p))
    return [path for _sz, path in sorted(best.values(), key=lambda t: -t[0])][:_LIB_TARGET_MAX]


def _cmake_fresh(bd, root) -> bool:
    """True when the build under `bd` is newer than the project's CMakeLists.txt -- a cheap staleness
    guard. The materialized source tree is immutable after ingest, so this is conservative; it only
    protects against a stale dir left by an earlier, different checkout."""
    try:
        cml = (Path(root) / "CMakeLists.txt").stat().st_mtime
        newest = max((p.stat().st_mtime for p in Path(bd).rglob("*")
                      if p.is_file() and p.suffix == "" and os.access(p, os.X_OK)), default=0.0)
        return newest >= cml
    except OSError:
        return False


def cmake_build_harnesses(root, *, timeout: int = 600, deadline: float | None = None,
                          want=None, shared: bool = True, sanitize: bool = True,
                          build_name: str | None = None) -> dict:
    """Build a CMake project's IN-TREE libFuzzer harnesses (files defining LLVMFuzzerTestOneInput)
    with the project's OWN cmake -- which generates its config headers and resolves its include/link
    graph, neither of which a per-translation-unit compile can do for a large project (FreeRDP's
    `winpr/config.h` is generated at configure time, so `build_libfuzzer`'s own compile fails
    "winpr/config.h: No such file or directory" on every file).

    A harness is the bytes->parser DRIVER the directed/concolic confirmation runs a candidate input
    through; fuzzing merely reuses it. clang + ASan + standalone libFuzzer (`-fsanitize=fuzzer`, so
    no OSS-Fuzz `LIB_FUZZING_ENGINE` is needed), and BUILD_SHARED_LIBS=ON so a project's transitive
    system deps resolve through shared libraries without the static `-dev` packages.

    Configure uses the project's own fuzz cache-preload when it ships one (the authoritative minimal
    knob set); on a configure failure from a missing REQUIRED `find_package`, the offending feature
    is disabled and configure retried (bounded), so a project that hard-requires an absent optional
    dependency still reaches a buildable core.

    Returns {ok, harnesses:[{name, source, binary}], lib_dirs:[str], log, system:"cmake"}. `lib_dirs`
    is where the shared libraries landed -- a runner must put them on LD_LIBRARY_PATH. `want` (harness
    basenames) narrows which harnesses to collect; None collects all."""
    import time as _time
    root = Path(root).resolve()
    res = {"ok": False, "harnesses": [], "lib_dirs": [], "log": "", "system": "cmake"}
    if not (root / "CMakeLists.txt").is_file():
        res["log"] = "not a cmake project"
        return res
    intree = find_harnesses(root, limit=64)
    if not intree:
        res["log"] = "no in-tree LLVMFuzzerTestOneInput harness"
        return res
    cc, cxx = _clang(False), _clang(True)
    if not cc:
        res["log"] = "clang not found (standalone libFuzzer needs clang -fsanitize=fuzzer)"
        return res
    if deadline is None:
        deadline = _time.time() + timeout * 4
    # A CONFIG-KEYED build dir (default): the same (shared, sanitize) config lands in the same dir, so
    # the shared-ASan harness that source_confirm and libfuzzer_stage BOTH want is built once and
    # shared, instead of twice into two dirs (each configure pass rmtrees its dir, so distinct names
    # meant a full rebuild). Distinct configs (static-clean explore, static-ASan replay) still get
    # distinct dirs and coexist.
    if build_name is None:
        build_name = f"_lykos_cmake_{'sh' if shared else 'st'}_{'asan' if sanitize else 'clean'}"
    names = {p.stem for p in intree}
    if want:
        names &= set(want)
    bd = root / build_name
    # REUSE: if this exact config was already built this run, skip reconfigure+rebuild and re-collect
    # the ELFs (fresh = newer than CMakeLists.txt). This is what makes the shared build shared.
    _pre_h, _pre_l = _collect_cmake_harnesses(bd, intree, names)
    if _pre_h and _cmake_fresh(bd, root):
        res["harnesses"], res["lib_dirs"], res["ok"] = _pre_h, _pre_l, True
        res["libraries"] = _collect_cmake_libraries(bd)
        res["log"], res["reused"] = f"reused existing cmake build {build_name}", True
        return res
    confine = _configure_confinement(root)
    env = dict(os.environ)
    if confine:
        env["CCACHE_DISABLE"] = "1"

    def _run(argv):
        slice_s = min(float(timeout), max(1.0, deadline - _time.time()))
        try:
            return _run_group(confine + list(argv), cwd=str(root), timeout=slice_s, env=env)
        except subprocess.TimeoutExpired as e:
            return subprocess.CompletedProcess(argv, 124, e.output or "", e.stderr or "")

    base = ["cmake", "-S", str(root), "-B", str(bd),
            f"-DCMAKE_C_COMPILER={cc}", f"-DCMAKE_CXX_COMPILER={cxx or cc}",
            "-DBUILD_FUZZERS=ON", "-DOSS_FUZZ=OFF",
            # ASan for the fuzz/replay build (faults are the proof); OFF for the concolic EXPLORE build
            # -- angr gets confused by ASan's shadow-memory accesses, so it explores clean code and the
            # solved input is replayed through the ASan build to confirm.
            f"-DWITH_SANITIZE_ADDRESS={'ON' if sanitize else 'OFF'}",
            # SHARED resolves a project's transitive system deps without the static -dev packages (the
            # default, for the fuzz/replay harness). STATIC links the project's parser INTO the harness
            # ELF, which the concolic rung needs -- angr loads the harness with auto_load_libs=False, so
            # a parser left in a .so would never be explored.
            f"-DBUILD_SHARED_LIBS={'ON' if shared else 'OFF'}", "-DCMAKE_BUILD_TYPE=Debug"]
    preload = _find_fuzz_preload(root)
    if preload:
        base += ["-C", str(preload)]
    flags: list = []
    disabled: set = set()
    log = ""
    rc = None
    for _ in range(12):                                   # configure, disabling a missing dep each pass
        shutil.rmtree(bd, ignore_errors=True)             # a cached REQUIRED-find failure sticks; fresh
        r = _run(base + flags)
        log = (log + (r.stdout or "") + (r.stderr or ""))[-20000:]
        rc = r.returncode
        if rc == 0 or _time.time() >= deadline:
            break
        out = (r.stdout or "") + (r.stderr or "")
        pkgs = (set(_RE_CMAKE_NOTFOUND.findall(out)) | set(_RE_CMAKE_PROVIDED.findall(out))) - disabled
        if not pkgs:
            break
        for pk in pkgs:
            flags += _cmake_disable_flags(pk)
            disabled.add(pk)
    res["log"] = log
    if rc != 0:
        return res
    # Prefer the project's `fuzzers` aggregate target; fall back to building each harness by name.
    br = _run(["cmake", "--build", str(bd), "-j", "--target", "fuzzers"])
    res["log"] = (log + (br.stdout or "") + (br.stderr or ""))[-20000:]
    if br.returncode != 0:
        for n in sorted(names):
            if _time.time() >= deadline:
                break
            _run(["cmake", "--build", str(bd), "-j", "--target", n])
    harnesses, lib_dirs = _collect_cmake_harnesses(bd, intree, names)
    res["harnesses"], res["lib_dirs"], res["ok"] = harnesses, lib_dirs, bool(harnesses)
    res["libraries"] = _collect_cmake_libraries(bd)
    return res


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


#: How many harnesses one plan may hold. The ceiling is about what a time budget can honestly
#: run -- each harness is a separate build and a separate campaign -- not about what the tree
#: offers: libtiff declares some two hundred public entry points.
MAX_HARNESSES = 6


def _slug(text) -> str:
    """A short filesystem-safe name for a harness. It keys the corpus cache and names the
    harness in a finding, so it has to be stable across runs of the same tree."""
    keep = "".join(c if (c.isalnum() or c in "-_") else "-" for c in str(text))
    while "--" in keep:
        keep = keep.replace("--", "-")
    return keep.strip("-")[:48] or "harness"


def fn_spec(root, fn: str, kind=None) -> dict:
    """A spec for synthesizing a harness around a single function."""
    return {"kind": "function", "id": "fn-" + _slug(fn), "entry": f"{fn}()",
            "fn": fn, "fn_kind": kind, "anchor": fn}


def plan_harnesses(root, *, limit: int = MAX_HARNESSES) -> list:
    """The harnesses worth building for this tree, strongest first.

    ONE HARNESS WAS THE CEILING ON REACH. The builder resolved a single entry point and the
    campaign fuzzed that one door: "we fuzzed expat" meant "we fuzzed `XML_Parse`", and every
    other way bytes enter the library -- `XML_ParseBuffer`, a second handle type, a second
    in-tree harness the project itself ships -- was unreachable at any budget. Nothing was wrong
    with the choice; it was that there was only one.

    The PREFERENCE ORDER is unchanged, and the first spec is exactly what the builder used to
    resolve on its own: the project's own harnesses (they know its API best), then a
    known-library harness that reaches the decode path, then handle triples through the public
    API, then synthesized single-function calls. What is new is that the rest of the list
    survives, for a caller with budget for it.

    Each spec is `{kind, id, entry, ...}`; `build_libfuzzer(spec=...)` builds one.
    """
    root = Path(root)
    limit = max(0, limit)
    plan: list = []
    for p in find_harnesses(root, limit=limit or 1):
        rel = p.relative_to(root)
        plan.append({"kind": "in-tree", "id": "tree-" + _slug(rel.as_posix()), "entry": str(rel),
                     "path": p, "anchor": None})
    known = known_harness(root)
    if known:
        plan.append({"kind": "known", "id": "known-" + _slug(known[0]), "entry": known[0],
                     "name": known[0], "source": known[1],
                     "anchor": _KNOWN_HARNESSES[known[0]]["symbols"][0]})
    if len(plan) < limit:
        # A triple the KNOWN harness already drives is not a second entry point: expat's
        # known harness is `XML_ParserCreate`/`XML_Parse`/`XML_ParserFree`, which is also the
        # strongest triple in the tree, and building both would spend half the slice fuzzing
        # the same code twice.
        covered = (known[1] if known else "")
        for tri in find_handle_triples(root, limit=limit):
            if re.search(r"\b" + re.escape(tri["consume"]) + r"\s*\(", covered):
                continue
            plan.append({"kind": "triple", "id": "tri-" + _slug(tri["consume"]),
                         "entry": f"{tri['consume']}()", "triple": tri,
                         "anchor": tri["consume"]})
    if len(plan) < limit:
        taken = {s.get("entry") for s in plan}
        for fn in rank_harness_fns(root, limit=limit + 4):
            if f"{fn}()" in taken:
                continue
            plan.append(fn_spec(root, fn))
    # Deduplicated by id, because two kinds can name the same door (a triple's consumer is also
    # a ranked function when its handle is pointer-spelled).
    seen, out = set(), []
    for s in plan:
        if s["id"] in seen:
            continue
        seen.add(s["id"])
        out.append(s)
    return out[:limit]


class BuildCache:
    """Compiled library objects, reused across the harnesses built from one tree.

    Each harness is a separate link of the SAME library objects, and compiling them is nearly
    all of the clock: libtiff is eighty translation units under ASan+UBSan, tens of seconds,
    against about one to compile a harness and link it against objects that already exist.
    Without this, fuzzing four entry points would have spent its budget compiling the same
    library four times over -- so breadth would have cost depth for no reason.
    """

    def __init__(self, directory):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.objs: dict = {}                             # (src, incs) -> (obj|None, err|None)
        self.compiled = 0
        self.reused = 0


def build_libfuzzer(root, out: Path, *, harness_fn: str | None = None,
                    harness_kind: str | None = None, timeout: int = 300,
                    spec: dict | None = None, cache: BuildCache | None = None) -> dict:
    """Build a libFuzzer target from the project at `root`. Uses an in-tree LLVMFuzzerTestOneInput
    if present, else synthesizes one. Returns {ok, binary, harness, log}.

    `spec` names WHICH harness to build (see `plan_harnesses`); without one this resolves the
    strongest, which is what it has always done. `cache` carries the library's compiled objects
    between calls so building a second harness does not recompile the library.
    """
    root = Path(root).resolve()
    if spec is None:
        if harness_fn:
            spec = fn_spec(root, harness_fn, harness_kind)
        else:
            plan = plan_harnesses(root, limit=1)
            spec = plan[0] if plan else None
    if spec is None:
        return {"ok": False, "binary": None, "harness": None,
                "log": "no LLVMFuzzerTestOneInput in the source and no harness_fn to synthesize one"}
    kind = spec["kind"]
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
    ensure_configured(root, timeout=timeout)
    tmp = Path(tempfile.mkdtemp(prefix="lykos-lf-"))
    try:
        res = _build_in(root, out, tmp, spec, kind, cxx, timeout, cache)
    finally:
        # any raise between mkdtemp and the old trailing rmtree (a synth helper, a path outside
        # the tree, a compile-pool error) leaked one lykos-lf-* directory per call
        shutil.rmtree(tmp, ignore_errors=True)
    # FALLBACK for a cmake project's IN-TREE harness: the per-TU compile above cannot generate the
    # project's config headers (FreeRDP's `winpr/config.h`) or resolve its include/link graph, so it
    # fails on every such tree. Build the harness through the project's OWN cmake instead (additive --
    # only when the per-TU build failed for an in-tree harness of a cmake project, so a project that
    # builds per-TU today is unaffected). The cmake build is cached across the plan's specs.
    if (not res.get("ok") and kind == "in-tree" and (root / "CMakeLists.txt").is_file()
            and spec.get("path")):
        cres = _cmake_cached(cache, root, timeout)
        if cres and cres.get("ok"):
            want = Path(spec["path"]).stem
            h = next((x for x in cres["harnesses"] if x["name"] == want), None)
            if h:
                rel = Path(spec["path"]).resolve()
                try:
                    rel = rel.relative_to(root)
                except ValueError:
                    pass
                return {"ok": True, "binary": h["binary"], "lib_dirs": cres.get("lib_dirs", []),
                        "harness": f"in-tree (cmake) {rel}",
                        "log": (res.get("log") or "") + "\n-- per-TU build failed; built via the "
                               "project's cmake --\n" + (cres.get("log") or "")[-1500:]}
    return res


def _cmake_cached(cache, root, timeout):
    """cmake_build_harnesses(root), cached on the BuildCache so the plan's several in-tree specs share
    one project build (it builds all harness targets at once). `cache` may be None (one-off build)."""
    root = str(Path(root).resolve())
    if cache is not None and getattr(cache, "_cmake", None) is not None:
        prev_root, prev = cache._cmake
        if prev_root == root:
            return prev
    res = cmake_build_harnesses(root, timeout=timeout)
    if cache is not None:
        cache._cmake = (root, res)
    return res


def _build_in(root, out, tmp, spec, kind, cxx, timeout, cache) -> dict:
    srcs = _sources(root, exclude_main=True)
    # Compile THE LIBRARY the entry point belongs to, not the whole repository. Building every
    # source in a real project drags in `contrib/` and `test/`, which reference symbols that do
    # not exist (`XTIFFOpen`), include headers for other platforms (`pixrect/pixrect_hs.h`), and
    # carry their own `main`. None of it is on the path to the parser, and any one of those stops
    # the build -- so in-process fuzzing was unavailable on a project merely for having a contrib
    # directory. The entry point's own directory IS the library by construction: it is where the
    # function we are about to call is defined.
    if spec.get("anchor"):
        home = fn_def_file(root, spec["anchor"])
        if home is not None and home.parent != root:
            lib_srcs = [x for x in srcs if home.parent in x.parents or x.parent == home.parent]
            if lib_srcs:
                srcs = lib_srcs
    h = None
    # EVERY harness in the tree but the one being built has to go. Each defines
    # `LLVMFuzzerTestOneInput`, so linking two of them fails on a duplicate symbol -- and this
    # matters for the SYNTHESIZED kinds too, which can now be planned for a tree that also ships
    # its own harnesses. Before the plan, a synthesized harness was only ever built for a tree
    # with none, so the collision could not arise.
    own = spec.get("path")
    others = [x for x in find_harnesses(root, limit=MAX_HARNESSES) if x != own]
    srcs = [x for x in srcs if x not in others]
    if kind == "in-tree":
        harness_desc = f"in-tree {spec['path'].relative_to(root)}"
    elif kind == "known":
        h = tmp / "harness.c"
        h.write_text(spec["source"])
        srcs = srcs + [h]
        harness_desc = f"known-library harness for {spec['name']} (reaches the decode path)"
    elif kind == "triple":
        tri = spec["triple"]
        h = tmp / ("harness.cc" if cxx else "harness.c")
        h.write_text(synth_handle_harness(tri, cxx=cxx))
        srcs = srcs + [h]
        _in = "(fuzz file)" if tri.get("ctor_file") else "()"
        harness_desc = (f"synthesized handle harness: {tri['ctor']}{_in} -> "
                        f"{tri['consume']}() -> {tri.get('dtor') or '(no free)'}"
                        f" [reaches the parser through the library's own API]")
    else:
        fn = spec["fn"]
        h = tmp / ("harness.cc" if cxx else "harness.c")
        # match the target function's real signature and linkage so a C++ symbol (mangled) or a C
        # symbol reached from a C++ harness both resolve at link time.
        def_file = fn_def_file(root, fn)
        c_linkage = bool(def_file and def_file.suffix in _C_EXT)
        # The SHAPE is inferred from the signature unless the caller names one. It defaulted to
        # `cstring` for everything, which delivers the fuzz bytes as a string -- wrong for every
        # entry point that takes a FILENAME, i.e. every file-format library.
        fk = spec.get("fn_kind") or harness_kind_for(root, fn)
        if fk == "file":
            params = fn_params(root, fn)
            h.write_text(synth_file_harness(fn, params, closer=fn_closer(root, fn),
                                            cxx=cxx, c_linkage=c_linkage))
        else:
            h.write_text(synth_harness(fn, kind=fk, arg_type=fn_first_arg_type(root, fn),
                                       cxx=cxx, c_linkage=c_linkage,
                                       params=fn_params(root, fn)))
        srcs = srcs + [h]
        harness_desc = f"synthesized for {fn}() [{fk}]"
    # What a configured autotools build would have on its command line. Without it expat's
    # xmlparse.c does not compile at all (see `config_defines`).
    incs = list(config_defines(root))
    for d in include_dirs(root):
        incs += ["-I", str(d)]
    # The harness is REQUIRED: skipping a translation unit is right for a platform shim or a test,
    # and wrong for the one file that defines the entry point. Silently skipping it produced a link
    # error about `LLVMFuzzerTestOneInput` instead of the compile error that caused it.
    res = _compile_and_link(srcs, incs, out, tmp, timeout, required=h, cache=cache)
    res["harness"] = harness_desc
    res["harness_id"] = spec["id"]
    res["entry"] = spec.get("entry")
    return res


def _obj_name(src, incs) -> str:
    """A stable object-file name for one translation unit: content-addressed by what decides its
    contents (the path and the flags), so a cached object is only reused for the same compile."""
    key = str(src) + "\x00" + "\x00".join(incs)
    return hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:20] + ".o"


def _compile_objs(srcs, incs, tmp: Path, timeout: int, cache=None) -> list:
    """Compile each translation unit with the driver for ITS language. Returns [(src, obj, err)].

    `cache` makes the library's objects outlive one build, which is what lets several harnesses
    share one compile of the library (see `BuildCache`).
    """
    out_dir = cache.dir if cache is not None else tmp
    todo = [s for s in srcs if cache is None or (str(s), tuple(incs)) not in cache.objs]

    def _one(src):
        src = Path(src)
        obj = out_dir / _obj_name(src, incs)
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

    fresh = {}
    if todo:
        with ThreadPoolExecutor(max_workers=min(8, (os.cpu_count() or 2))) as ex:
            for src, got in zip(todo, ex.map(_one, todo)):
                fresh[str(src)] = got
    results = []
    for src in srcs:
        k = (str(src), tuple(incs))
        if str(src) in fresh:
            got = fresh[str(src)]
            if cache is not None:
                cache.objs[k] = got
                cache.compiled += 1
        else:
            got = cache.objs[k]
            cache.reused += 1
        results.append((Path(src), got[0], got[1]))
    return results


def _compile_and_link(srcs, incs, out: Path, tmp: Path, timeout: int, *, required=None,
                      cache=None) -> dict:
    """Compile every translation unit, then link what compiled.

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
    objs, failed, logs = [], [], []
    failed_paths = []
    for src, obj, err in _compile_objs(srcs, incs, tmp, timeout, cache=cache):
        if obj is not None:
            objs.append(obj)
        else:
            failed.append(err or "")
            failed_paths.append(src)
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


_ASAN_HDR = re.compile(r"(==\d+==\s?ERROR: (?:AddressSanitizer|UndefinedBehaviorSanitizer).*)", re.S)
#: UBSan's own wording, which carries NO `ERROR:` header -- `tif_read.c:545:8: runtime error:
#: load of null pointer of type 'uint64'`, followed by libFuzzer's `deadly signal` stack. Three
#: of libtiff's five synthesized harnesses fault exactly this way, and with only the header form
#: above the report came back EMPTY: a real null dereference inside `TIFFFillStrip` was filed as
#: "crash under libFuzzer, CWE-787" with no source line, because the text that said what it was
#: never left this function.
_UBSAN_HDR = re.compile(r"(^\S+:\d+:\d+: runtime error: .*)", re.S | re.M)
#: A fault with no sanitizer verdict at all (a plain SIGSEGV). Worth capturing for its stack:
#: the classification falls back to "a crash", but the frames still name the faulting function.
_SIGNAL_HDR = re.compile(r"(==\d+==\s?ERROR: libFuzzer: .*)", re.S)


def fault_report(out: str):
    """The sanitizer's own account of the fault, or None.

    Whichever form appears EARLIEST wins, because the sanitizer prints its verdict before
    libFuzzer prints the stack it died on: starting at the later text would drop the one line
    that says what the bug is.
    """
    best = None
    for pat in (_ASAN_HDR, _UBSAN_HDR, _SIGNAL_HDR):
        m = pat.search(out or "")
        if m and (best is None or m.start(1) < best.start(1)):
            best = m
    return best.group(1)[:4000] if best else None


#: libFuzzer's artifact prefixes, and what each one is EVIDENCE OF. They are not all crashes:
#: `oom-` is libFuzzer's RSS limit, which a library hits by believing a size field in the input
#: -- a real resource-exhaustion defect, and not memory corruption. Filed as the same
#: "crash under libFuzzer, CWE-787" as a heap overflow, it would overstate a denial of service as
#: a write primitive, which is the kind of claim this pipeline exists not to make.
ARTIFACT_KINDS = {"crash-": "crash", "oom-": "oom", "timeout-": "timeout", "leak-": "leak"}
#: libFuzzer's own execution counter, from `-print_final_stats=1`.
_UNITS_RE = re.compile(r"stat::number_of_executed_units:\s*(\d+)")
#: Every progress line is prefixed with the execution count (`#4096\tpulse  cov: 211 ...`). The
#: final-stats block does not print when the run ends in a crash, which is precisely the run whose
#: count matters, so the counter is read from the log as well.
_TICK_RE = re.compile(r"^#(\d+)\s", re.M)


def executions(log: str) -> int:
    """How many inputs libFuzzer executed, from its own output.

    THE IN-PROCESS ENGINE WAS INVISIBLE. `run_libfuzzer` never reported a count and the stage
    never emitted one, so the scorecard's executions came only from the out-of-process campaigns:
    a library run that found its bug in-process reported the executions of the engines that found
    nothing. The number was not wrong, it was absent -- and "20,618 executions" on a target whose
    only real work was in-process said the opposite of what happened.
    """
    best = 0
    for m in _UNITS_RE.finditer(log or ""):
        best = max(best, int(m.group(1)))
    for m in _TICK_RE.finditer(log or ""):
        best = max(best, int(m.group(1)))
    return best


#: How many candidate inputs the deterministic replay pass will re-run when the fuzzing loop left
#: no crash with a usable source. Harvested crash inputs are always replayed (there are few); this
#: caps the SEED replay so a clean target carrying a big kept corpus (up to CORPUS_MAX_UNITS) is not
#: re-executed one unit per process. Largest seeds first, because size is what drives an overflow.
_REPLAY_SEED_CAP = 24


def _report_has_source(report: str | None) -> bool:
    """Whether a sanitizer report pins the defect to a source file:line. This is the property the
    libfuzzer_stage confirmation turns on, so it is also the signal for whether a replay is needed."""
    try:
        from .debug.rootcause import parse_asan_report
        cls = parse_asan_report(report or "")
        return bool(cls and cls.get("source"))
    except Exception:
        # Best-effort predicate: if the report cannot be classified, treat it as sourceless so the
        # replay pass still runs (it loses nothing -- a replay that also yields no source is a no-op).
        return False


def _replay_report(binary, workdir: Path, data: bytes) -> str:
    """Replay ONE input through the harness directly (`binary <file>`, no fuzzing loop) and return
    the sanitizer report, or "".

    The fuzzing loop runs with abort_on_error=1 so that a CORPUS-SEED crash (execs 0-1) can abort()
    before llvm-symbolizer finishes walking the stack -- the `parse.c:3` frame then prints as a bare
    address and the source line is lost -- and a run that ends in TimeoutExpired can have its stderr
    truncated so no report is captured at all. A lone-file replay is a single, deterministic exec
    outside the loop and its timeout, with halt_on_error + abort_on_error off so the symbolizer
    finishes. This is what makes a seed-triggered crash and its source line reproducible run to run."""
    try:
        f = Path(workdir) / "lf-replay.in"
        f.write_bytes(bytes(data))
    except OSError:
        return ""
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = ("abort_on_error=0:detect_leaks=0:symbolize=1:halt_on_error=1:"
                           + env.get("ASAN_OPTIONS", ""))
    # The crash itself is instant; the cost is llvm-symbolizer parsing the statically-linked ASan
    # binary's DWARF, measured at ~9 s idle and several times that with a cold symbolizer or under a
    # loaded box. 120 s keeps a slow-but-succeeding symbolization from being cut to an empty report
    # (which was the replay's own flake). Only the ONE reproducing replay pays this -- the pass
    # breaks on the first sourced report, and a non-crashing candidate exits fast with no symbolizer.
    try:
        r = _run_group([str(binary), str(f)], timeout=120, env=env, cwd=str(workdir))
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return fault_report((r.stderr or "") + (r.stdout or "")) or ""


def run_libfuzzer(binary, workdir, *, seconds: int = 30, max_len: int = 4096,
                  corpus: list | None = None, lib_dirs: list | None = None) -> dict:
    """Run the libFuzzer `binary` for `seconds`. Returns {crashes, corpus, execs, log}.
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
    if lib_dirs:                                          # a cmake-built (shared) harness needs its
        env["LD_LIBRARY_PATH"] = os.pathsep.join(        # project's .so dirs to load
            [str(d) for d in lib_dirs] + ([env["LD_LIBRARY_PATH"]] if env.get("LD_LIBRARY_PATH") else []))
    argv = [str(binary), str(corpus_dir), f"-max_total_time={seconds}", f"-max_len={max_len}",
            f"-artifact_prefix={art}/", "-print_final_stats=1", "-rss_limit_mb=2048"]
    crashes = []
    before = set(art.iterdir())
    try:
        r = _run_group(argv, timeout=seconds + 30, env=env, cwd=str(workdir))
        out = (r.stderr or "") + (r.stdout or "")
    except subprocess.TimeoutExpired as e:
        out = (e.stderr or b"").decode("latin-1", "ignore") if isinstance(e.stderr, bytes) else (e.stderr or "")
    except OSError as e:
        return {"crashes": [], "log": f"libFuzzer binary could not be run: {e!r}", "corpus": [],
                "execs": 0}
    report = fault_report(out)
    for f in sorted(set(art.iterdir()) - before):
        kind = next((k for pre, k in ARTIFACT_KINDS.items() if f.name.startswith(pre)), None)
        if kind:
            try:
                crashes.append({"input": f.read_bytes(), "report": report, "kind": kind,
                                "artifact": f.name})
            except OSError:
                pass
    # A sanitizer fired but NO artifact was harvested: the crash is real (the report proves it), the
    # artifact write just lost the race with the sanitizer's abort() -- which is the common case when
    # a CORPUS SEED crashes on the initial replay (execs 0-1), before libFuzzer flushes `crash-*`.
    # Treating that as "no crash" made seed-triggered overflows undetectable and the crash reporting
    # nondeterministic. Recover the crashing input from libFuzzer's "Running: <file>" line (the unit
    # it was executing), else the largest seed, and record it so the crash is never lost.
    if report and not crashes:
        import re as _re
        crash_input = b""
        m = _re.search(r"Running:\s*(\S+)", out)
        if m:
            try:
                crash_input = Path(m.group(1)).read_bytes()
            except OSError:
                crash_input = b""
        guessed = False
        if not crash_input and corpus:
            crash_input = max((bytes(s) for s in corpus), key=len, default=b"")
            guessed = True                               # a stand-in until a replay proves it
        crashes.append({"input": crash_input, "report": report, "kind": "crash", "artifact": None,
                        "reproduced": not guessed})
    # DETERMINISTIC REPLAY. The report the fuzzing loop captured can be incomplete under CPU
    # contention -- a corpus-seed crash can abort() before the symbolizer finishes (source line
    # lost), and a timed-out run's stderr can be truncated so no report is captured at all -- which
    # made a SEEDED overflow report nondeterministically and its source line flaky. When no crash
    # yet carries a usable source, replay the candidate inputs ONE AT A TIME through the harness
    # directly (see `_replay_report`) and take the first that reproduces with a source. Harvested
    # crash inputs are always tried; seeds are tried largest-first but capped, so a clean target
    # carrying a big kept corpus is not re-executed one unit per process.
    if not any(_report_has_source(c.get("report")) for c in crashes):
        seen_inputs, candidates = set(), []
        for c in crashes:                                # harvested crash inputs first (always few)
            ci = c.get("input")
            if ci and bytes(ci) not in seen_inputs:
                seen_inputs.add(bytes(ci)); candidates.append(bytes(ci))
        for s in sorted((bytes(x) for x in (corpus or [])), key=len, reverse=True)[:_REPLAY_SEED_CAP]:
            if s not in seen_inputs:
                seen_inputs.add(s); candidates.append(s)
        best_rep, best_input = "", b""
        reproduced_inputs: set = set()
        for data in candidates:
            rep = _replay_report(binary, workdir, data)
            if not rep:
                continue
            reproduced_inputs.add(data)
            if not best_rep:
                best_rep, best_input = rep, data         # keep any reproduction as a floor
            if _report_has_source(rep):
                best_rep, best_input = rep, data          # a sourced one wins outright
                break
        if best_rep:
            # The replayed report belongs to the input that PRODUCED it. Pasting it onto
            # crashes[0] regardless filed one input's file:line against another input -- and
            # when crashes[0] was the largest-seed stand-in, the saved reproducer did not
            # reproduce at all while the finding claimed it did.
            same = next((c for c in crashes if bytes(c.get("input") or b"") == best_input), None)
            # A stand-in is an entry whose input is NOT a verified reproducer: the largest-seed
            # guess, or an artifact with no report that did not reproduce on replay (libFuzzer
            # lost the race and wrote the EMPTY unit, crash-da39a3ee..., for a seed crash).
            stand_in = next((c for c in crashes
                             if c.get("reproduced") is False
                             or (not c.get("report")
                                 and bytes(c.get("input") or b"") not in reproduced_inputs)),
                            None)
            if same is not None:
                same["report"] = best_rep
                same["reproduced"] = True
            elif stand_in is not None:
                if stand_in.get("artifact"):
                    stand_in["note"] = (f"libFuzzer artifact {stand_in['artifact']} did not "
                                        "reproduce; replaced by the input that did")
                stand_in.update(input=best_input, report=best_rep, reproduced=True)
            else:
                crashes.append({"input": best_input, "report": best_rep, "kind": "crash",
                                "artifact": None, "reproduced": True})  # one the loop missed
    # THE CORPUS IS THE PRODUCT, not a by-product. libFuzzer writes every input that reached new
    # coverage into this directory -- 1,208 of them in one 420 s run on libtiff -- and it lived in
    # the stage's scratch directory, so every run started from nothing and re-derived the same
    # coverage. Coverage-guided fuzzing is the one engine whose work COMPOUNDS; discarding the
    # corpus discards the compounding. Handing it back lets the caller keep it.
    return {"crashes": crashes, "log": out[-4000:], "corpus": _harvest(corpus_dir),
            "execs": executions(out)}


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
