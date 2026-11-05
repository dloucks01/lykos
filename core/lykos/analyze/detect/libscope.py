"""Static-binary scoping: which recovered functions are the LINKED-IN LIBRARY, not the program.

A statically linked binary carries its libc, and the decompiler recovers every body of it. jhead-3.04
(static, symbols present) is 1,429 functions, ~1,370 of them glibc -- and the static detectors
analysed all of them: of 6,218 filed sites, about 5,800 sat inside `_dl_relocate_object`,
`__vfscanf_internal`, `_int_malloc`, `_nl_load_domain`... None of those is the target's bug; they
are noise that buries the program's own findings and cost most of the stage's time.

On a DYNAMIC binary the same calls go to imports: the analysis sees `memcpy` as a named external
whose name drives the sink/source semantics, and never walks its body. This module makes a static
binary look like that: it names the library bodies so the detect stage can drop them from the
analysed set, while call edges INTO them (which carry `dst_name`) still reach the detectors and
the taint channel as named sinks/sources -- exactly an import's treatment.

Bases, strongest first. Each one is conservative: when the evidence is not clear the function
STAYS in scope -- an extra library function analysed is noise, a program function hidden is a
missed bug.

  symbol-file  The symbol table groups LOCAL symbols under the STT_FILE naming their object.
               A glibc archive member is `iofclose.o`; the program's own file is `jhead.c`. A local
               symbol's file is exact. A GLOBAL symbol carries no file, so it is attributed only
               when the local marks on BOTH sides of it name library files -- a global sitting at
               the boundary between the program and libc is left to the name test.
  flirt        Stripped static: the bodies FLIRT matched against the reference libc.a
               (`flirt.identified`), plus the IFUNC thunks that resolve to them.
  name         No usable file attribution: glibc-internal spellings (`_IO_`, `_dl_`, `_nl_`, `__`),
               the C runtime glue (`_start`, `frame_dummy`, ...), and libc API names DEFINED in the
               binary (a static `memcpy` body is libc's).

A function attributed to a program source file is never excluded, `main` is never excluded, and
nothing is ever excluded on a dynamically linked binary.
"""
from __future__ import annotations

import bisect
import logging
import re

from ... import observe
from .catalog import ADVISORY, DANGEROUS, OUT_PARAM_SOURCES, SOURCES, normalize

_log = logging.getLogger(__name__)

# STT_FILE names that are a library/archive member rather than a program source. glibc's libc.a
# members are named for the object (`iofclose.o`, `memcpy-avx-unaligned-erms.o`); libtool objects
# are `.lo`. A program's own STT_FILE is its source name (`exif.c`). crtstuff.c is the compiler's
# glue, linked into every program (elf._LIB_FILE).
_LIB_FILE_EXT = (".o", ".lo", ".os", ".oS")
_CRT_FILES = {"crtstuff.c"}

# The C runtime / compiler glue every gcc-linked program carries.
_CRT_NAMES = {"_start", "_init", "_fini", "frame_dummy", "register_tm_clones",
              "deregister_tm_clones", "__do_global_dtors_aux", "__libc_csu_init",
              "__libc_csu_fini", "_dl_relocate_static_pie", "call_weak_fn"}
# glibc-internal spellings. `__` covers the reserved namespace (C11 7.1.3: identifiers starting
# with two underscores are reserved for the implementation), which is where glibc's internals live.
_INTERNAL_PREFIXES = ("_IO_", "_dl_", "_nl_", "__", "_itoa", "_fitoa", "_Unwind_", "_obstack",
                      "_fxstat")
# libc API names (normalized) whose body, DEFINED in a static binary, is the library's. The sink/
# source catalogs plus the common stdio/string/memory/process surface. Deliberately named API
# functions only -- no generic words a program might use for its own function.
_LIBC_API = (set(DANGEROUS) | set(SOURCES) | set(OUT_PARAM_SOURCES) | set(ADVISORY) | {
    "malloc", "calloc", "realloc", "free", "reallocarray", "posix_memalign", "aligned_alloc",
    "memalign", "valloc", "pvalloc", "memset", "memcmp", "memchr", "memrchr", "mempcpy", "bzero",
    "strlen", "strnlen", "strcmp", "strncmp", "strcasecmp", "strncasecmp", "strchr", "strrchr",
    "strstr", "strdup", "strndup", "strtok", "strtok_r", "strspn", "strcspn", "strpbrk", "stpcpy",
    "stpncpy", "strerror", "strerror_r", "strsep", "strcoll", "strxfrm", "strncat", "strftime",
    "strtol", "strtoul", "strtoll", "strtoull", "strtod", "strtof", "strtold", "atoi", "atol",
    "atoll", "atof", "printf", "vprintf", "vfprintf", "vsnprintf", "dprintf", "vdprintf",
    "asprintf", "vasprintf", "puts", "fputs", "putchar", "fputc", "putc", "fwrite", "fflush",
    "fclose", "fopen64", "fdopen", "fseek", "fseeko", "fseeko64", "ftell", "ftello", "ftello64",
    "rewind", "fileno", "feof", "ferror", "clearerr", "setvbuf", "setbuf", "ungetc", "getc",
    "vfscanf", "vsscanf", "vscanf", "perror", "exit", "abort", "atexit", "qsort", "bsearch",
    "getopt", "getopt_long", "time", "localtime", "localtime_r", "gmtime", "gmtime_r", "mktime",
    "ctime", "asctime", "difftime", "close", "write", "lseek", "lseek64", "stat", "fstat",
    "lstat", "stat64", "fstat64", "lstat64", "access", "chmod", "fchmod", "chown", "utime",
    "utimes", "mkdir", "rmdir", "rename", "getcwd", "chdir", "isatty", "dup", "dup2", "pipe",
    "fork", "vfork", "waitpid", "wait", "kill", "signal", "sigaction", "raise", "setjmp",
    "longjmp", "sleep", "usleep", "nanosleep", "getpid", "getuid", "geteuid", "getgid",
    "getegid", "setuid", "setgid", "seteuid", "setegid", "socket", "connect", "bind", "listen",
    "accept", "send", "sendto", "sendmsg", "setsockopt", "getsockopt", "mmap", "munmap",
    "mprotect", "ioctl", "fcntl", "readdir", "closedir", "tolower", "toupper", "isalpha",
    "isdigit", "isspace", "isprint", "isalnum", "isxdigit", "ctype_b_loc", "ctype_tolower_loc",
    "ctype_toupper_loc", "errno_location", "setlocale", "dcgettext", "gettext", "iconv",
    "iconv_open", "iconv_close", "pthread_create", "pthread_join", "pthread_mutex_lock",
    "pthread_mutex_unlock", "pthread_once", "dlopen", "dlsym", "dlclose", "syscall",
    "libc_start_main", "stack_chk_fail", "assert_fail", "fortify_fail", "chk_fail",
})
# GCC/LTO clone suffixes (`foo.part.0`, `foo.isra.0.constprop.1`, `foo.cold`) and the backend's
# de-duplication suffix (`foo_0x46e2f0`): a clone belongs to whatever its base function does.
_CLONE_RE = re.compile(r"(?:\.(?:part|isra|constprop|cold|lto_priv|localalias|clone|llvm)"
                       r"(?:\.\d+)?)+$")
_DEDUP_RE = re.compile(r"_0x[0-9a-fA-F]+$")
_GENERIC = ("fcn.", "loc.", "sub_", "func.", "unk.", "FUN_", "entry")


def _base_name(name: str) -> str:
    n = (name or "").strip()
    n = _DEDUP_RE.sub("", n)
    n = _CLONE_RE.sub("", n)
    return n


def _to_int(a):
    try:
        return int(a, 16) if isinstance(a, str) else int(a)
    except (TypeError, ValueError):
        return None


def is_library_file(owner) -> bool:
    """True for an STT_FILE that names a library/archive member or the compiler's crt glue."""
    o = str(owner or "")
    return bool(o) and (o in _CRT_FILES or o.endswith(_LIB_FILE_EXT))


def is_library_name(name) -> bool:
    """The name test: a glibc-internal spelling, the C runtime glue, or a libc API name. Never
    true for `main` or for a generic (unnamed) recovery label."""
    base = _base_name(name)
    if not base or base == "main" or base.startswith(_GENERIC):
        return False
    if base in _CRT_NAMES or base.startswith(_INTERNAL_PREFIXES):
        return True
    return normalize(base) in _LIBC_API


def _symbol_marks(blob, info):
    """(sorted mark addrs, owners) -- the LOCAL symbols' owning files -- or ([], []) when the
    symbol table cannot attribute (none, or PowerPC64 ELFv1 whose symbol values are OPD
    descriptors, not code)."""
    from .. import elf as elfmod
    if any(sec.get("name") == ".opd" for sec in (info.sections or [])):
        return [], []
    try:
        marks, _funcs, _end = elfmod._symbol_owners(blob, info)
    except Exception:                                    # noqa: BLE001
        observe.absorbed(_log, "no symbol-file attribution")
        return [], []
    return [a for a, _ in marks], [o for _, o in marks]


def library_scope(blob, functions, *, flirt_named=None) -> dict:
    """Classify `functions` (objects with `.addr`/`.name`) of the ELF image `blob`.

    Returns {"linking", "excluded": {addr: basis}, "basis": {basis: count}, "total", "kept",
    "sample": [names]}. `excluded` is empty -- nothing scoped -- unless the image is statically
    linked. `flirt_named` ({hex_va: name}) overrides the FLIRT pass (tests); default computes it.
    """
    from .. import elf as elfmod
    out = {"linking": None, "excluded": {}, "basis": {}, "total": len(functions or []),
           "kept": len(functions or []), "sample": []}
    try:
        info = elfmod.parse(blob)
    except Exception:                                    # noqa: BLE001
        observe.absorbed(_log, "not an ELF we can scope")
        return out
    out["linking"] = info.linking
    if info.linking not in ("static", "static-pie") or not functions:
        return out                                       # dynamic / unknown: never exclude

    addrs, owners = _symbol_marks(blob, info)
    # Decompiler addresses vs link VAs: a static-pie image is rebased by the recovery backend.
    base = 0
    if info.elf_type and "DYN" in str(info.elf_type).upper():
        from ..debug import rootcause
        base = rootcause.image_base(functions, info.entry)
        if base is None:
            addrs, owners = [], []                       # cannot place symbols: no file basis
    if flirt_named is None:
        flirt_named = {}
        if info.stripped:
            try:
                from .. import flirt
                flirt_named = flirt.identified(blob)
            except Exception:                            # noqa: BLE001
                observe.absorbed(_log, "no FLIRT identification")
    flirt_ints = {_to_int(k) for k in (flirt_named or {})}
    flirt_ints.discard(None)

    def file_verdict(a):
        """'lib' / 'prog' / None from the symbol-file marks around link VA `a`."""
        if not addrs or a is None:
            return None
        i = bisect.bisect_right(addrs, a) - 1
        if i >= 0 and addrs[i] == a:                     # its own LOCAL symbol: exact
            return "lib" if is_library_file(owners[i]) else "prog"
        prev = owners[i] if i >= 0 else None
        j = bisect.bisect_right(addrs, a)
        nxt = owners[j] if j < len(addrs) else None
        if prev is None or nxt is None:
            return None
        lp, ln = is_library_file(prev), is_library_file(nxt)
        if lp and ln:
            return "lib"
        if not lp and not ln:
            return "prog"
        return None                                      # a program/library boundary: unsure

    excluded: dict = {}
    for f in functions:
        name = getattr(f, "name", None) or ""
        if _base_name(name) == "main":
            continue
        a = _to_int(getattr(f, "addr", None))
        link = (a - base) if a is not None else None
        v = file_verdict(link)
        if v == "prog":
            continue
        if v == "lib":
            excluded[f.addr] = "symbol-file"
        elif a is not None and a in flirt_ints:
            excluded[f.addr] = "flirt"
        elif is_library_name(name):
            excluded[f.addr] = "name"
    kept = sum(1 for f in functions if f.addr not in excluded)
    # Never blind the stage: if scoping would leave nothing, the attribution is wrong.
    if not kept:
        return out
    basis: dict = {}
    for b in excluded.values():
        basis[b] = basis.get(b, 0) + 1
    names = {f.addr: f.name for f in functions}
    out.update(excluded=excluded, basis=basis, kept=kept,
               sample=sorted(str(names.get(a) or a) for a in excluded)[:12])
    return out
