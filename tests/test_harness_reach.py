"""REACH: getting the fuzzer inside a library, not just at its front door.

`pick_harness_fn` requires a pointer-spelled FIRST parameter, so it can only reach a library
whose entry point takes the bytes directly. The dominant shape in a C library is not that --
you make a handle, feed it, and free it:

    XML_Parser XML_ParserCreate(const XML_Char *encoding);
    enum XML_Status XML_Parse(XML_Parser parser, const char *s, int len, int isFinal);
    void XML_ParserFree(XML_Parser parser);

`XML_Parser` is a typedef with no `*` in its spelling, so expat's real parser was excluded
outright and the library was reachable only through a HAND-WRITTEN harness. A hand-written
harness per library does not generalise; the same create/consume/destroy triple is libpng's
(`png_create_read_struct`/`png_read_png`/`png_destroy_read_struct`), libxml2's, sqlite3's.
"""
import os
import pathlib
import subprocess

import pytest
from lykos.analyze import libfuzzer as L

_LIBSRC = """#include <stdlib.h>
#include <string.h>
#include "mylib.h"
struct my_parser_s { int n; char buf[16]; };
my_parser my_parser_create(const char *opts) {
    my_parser p = (my_parser)calloc(1, sizeof(struct my_parser_s));
    (void)opts;
    return p;
}
int my_parse(my_parser p, const char *s, int len, int isfinal) {
    if (!p) return 0;
    (void)isfinal;
    if (len > 0 && s[0] == 'X') { memcpy(p->buf, s, (size_t)len); }   /* the bug */
    return 1;
}
void my_parser_free(my_parser p) { free(p); }
"""
_LIBHDR = """#ifndef MYLIB_H
#define MYLIB_H
typedef struct my_parser_s *my_parser;
my_parser my_parser_create(const char *opts);
int my_parse(my_parser p, const char *s, int len, int isfinal);
void my_parser_free(my_parser p);
#endif
"""


@pytest.fixture
def lib(tmp_path):
    d = tmp_path / "mylib"
    (d / "lib").mkdir(parents=True)
    (d / "lib" / "mylib.c").write_text(_LIBSRC)
    (d / "lib" / "mylib.h").write_text(_LIBHDR)
    return d


def test_a_handle_first_api_is_found(lib):
    t = L.find_handle_triple(lib)
    assert t, "a create/consume/destroy triple was not recognised"
    assert (t["ctor"], t["consume"], t["dtor"]) == ("my_parser_create", "my_parse",
                                                    "my_parser_free")
    assert t["handle"] == "my_parser"
    assert t["buf_at"] == 1, "the (buffer, length) pair was not located in the parameter list"
    assert pathlib.Path(t["header"]).name == "mylib.h"


def test_the_harness_includes_the_header_rather_than_guessing_the_type(lib):
    src = L.synth_handle_harness(L.find_handle_triple(lib))
    assert '#include "mylib.h"' in src, \
        "an opaque handle type cannot be forward-declared, so the header has to be included"
    assert "my_parser h = my_parser_create(" in src
    assert "my_parser_free(h);" in src, "a harness that never frees leaks a handle per execution"
    assert "if (!h) return 0;" in src


def test_a_constructors_pointer_argument_is_NULL_not_a_file_mode(lib):
    """`_arg_values` exists for an opener and hands a pointer `(void*)"r"` -- a file MODE, right
    for `TIFFOpen(path, "r")` and wrong here. Passing "r" as expat's encoding name made
    `XML_ParserCreate` fail, so the harness returned at `if (!h)` on EVERY execution: a campaign
    that runs forty thousand inputs and tests nothing."""
    assert L._ctor_arg_values(["const char *opts"]) == ["NULL"]
    assert L._ctor_arg_values(["int flags"]) == ["0"]
    src = L.synth_handle_harness(L.find_handle_triple(lib))
    assert "my_parser_create(NULL)" in src
    assert '"r"' not in src


def test_a_trailing_flag_is_passed_one_not_zero(lib):
    """In this shape a trailing int is almost always a "last chunk" flag (expat's `isFinal`), and
    0 asks the library to wait for more data a one-shot harness will never send."""
    src = L.synth_handle_harness(L.find_handle_triple(lib))
    assert "my_parse(h, (const char *)data, (int)size, 1);" in src, src


def test_a_ports_header_is_not_the_librarys_api(tmp_path):
    """expat ships four headers declaring `XML_ParserCreate` and `sorted()` returned
    `amiga/include/inline4/expat.h` -- an Amiga inline-macro wrapper. The name was found, so
    every caller believed the function was public, while a harness INCLUDING that header would
    not compile here at all."""
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "api.h").write_text("int thing_parse(void *h, const char *s, int n);\n")
    (tmp_path / "amiga" / "include" / "inline4").mkdir(parents=True)
    (tmp_path / "amiga" / "include" / "inline4" / "api.h").write_text(
        "int thing_parse(void *h, const char *s, int n);\n")
    got = L._declared_in_header(tmp_path, "thing_parse")
    assert got is not None
    assert "amiga" not in str(got), f"a platform port's header was chosen: {got}"


# --------------------------------------------------------------- the build has to be the target
def test_the_generated_config_define_is_supplied(tmp_path):
    """A configured autotools project compiles with `-DHAVE_CONFIG_H` (or a project-specific
    spelling) and its sources are written to REQUIRE it. We compile each unit ourselves and never
    read the generated Makefile, so the define was missing -- and expat's xmlparse.c does not
    merely lose a feature without it, it refuses to compile:

        lib/xmlparse.c:83:2: error: memmove does not exist on this platform
    """
    (tmp_path / "expat_config.h.in").write_text("#define X 1\n")
    assert L.config_defines(tmp_path) == [], "a template with no generated header is not configured"
    (tmp_path / "expat_config.h").write_text("#define X 1\n")
    assert L.config_defines(tmp_path) == ["-DHAVE_EXPAT_CONFIG_H"]
    (tmp_path / "config.h.in").write_text("")
    (tmp_path / "config.h").write_text("")
    assert "-DHAVE_CONFIG_H" in L.config_defines(tmp_path)


def test_symbols_defined_in_reads_the_projects_own_definitions(tmp_path):
    f = tmp_path / "a.c"
    f.write_text("static int priv(void){return 0;}\n"
                 "int my_parse(void *p, int n) {\n return 0;\n}\n")
    got = L.symbols_defined_in([f])
    assert "my_parse" in got


@pytest.mark.skipif(not L._clang(False), reason="needs clang")
def test_a_build_refuses_to_resolve_the_target_from_a_system_library(tmp_path):
    """The undefined-symbol fallback exists for a project's EXTERNAL dependencies -- libtiff needs
    zlib for its Deflate codec -- and it happily resolved the library UNDER TEST as well. expat's
    xmlparse.c failed to compile for want of a config define, was skipped like any other failing
    unit, and `XML_ParserCreate` was then satisfied by `-lexpat`: the build reported ok and the
    campaign ran twenty-one million executions against Debian's uninstrumented copy of expat
    instead of the tree it was pointed at.

    Here the project defines `crc32` itself, in a unit that cannot compile. `-lz` would resolve
    it, and must not."""
    bad = tmp_path / "own.c"
    bad.write_text("#ifndef LYKOS_OK\n#error this unit needs a define\n#endif\n"
                   "unsigned long crc32(unsigned long a, const unsigned char *b, unsigned c)\n"
                   "{ (void)b; (void)c; return a; }\n")
    h = tmp_path / "harness.c"
    h.write_text("#include <stdint.h>\n#include <stddef.h>\n"
                 "extern unsigned long crc32(unsigned long, const unsigned char *, unsigned);\n"
                 "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {\n"
                 "  crc32(0, d, (unsigned)n); return 0; }\n")
    out = tmp_path / "h.bin"
    tmp = tmp_path / "t"
    tmp.mkdir()
    res = L._compile_and_link([bad, h], [], out, tmp, timeout=120, required=h)
    assert not res["ok"], "the build 'succeeded' by linking the system copy of the target"
    assert "refusing to link" in (res["log"] or ""), res["log"][-300:]
    assert "crc32" in (res["log"] or "")
    assert not out.exists()


@pytest.mark.skipif(not L._clang(False), reason="needs clang")
def test_the_synthesized_handle_harness_builds_and_reaches_the_bug(tmp_path, lib):
    """End to end on a library whose only entry point is handle-first: the harness must build and
    the planted overflow must be reachable through it."""
    out = tmp_path / "h.bin"
    saved = dict(L._KNOWN_HARNESSES)
    L._KNOWN_HARNESSES.clear()
    try:
        res = L.build_libfuzzer(lib, out, timeout=240)
    finally:
        L._KNOWN_HARNESSES.update(saved)
    assert res["ok"], (res.get("log") or "")[-600:]
    assert "handle harness" in (res.get("harness") or "")
    # 40,000 runs and a PINNED libFuzzer seed. The planted bug needs an input that starts with
    # 'X' and is longer than 16 bytes, which is ~1/256 of random inputs: at 4,000 runs with a
    # fresh RNG every time this assertion failed about one run in six (measured), and a gate that
    # fails one time in six teaches everyone to re-run it. With the seed fixed the campaign is
    # the same every time, so the test is deterministic in BOTH directions -- if the harness ever
    # stops reaching the bug, it fails every time instead of sometimes.
    r = subprocess.run([str(out), "-runs=40000", "-max_len=64", "-seed=1"],
                       capture_output=True, text=True, timeout=180,
                       cwd=str(tmp_path), env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"})
    both = (r.stdout or "") + (r.stderr or "")
    assert "stack-buffer-overflow" in both or "AddressSanitizer" in both, both[-700:]


# ------------------------------------------- a sanitizer fault is a reproduction, not a near-miss
def test_the_delivery_sweep_stops_on_a_sanitizer_fault():
    """`build_poc` sweeps the delivery channels and broke only on `res.crashed` -- "was it killed
    by a signal". A libFuzzer harness installs its own handlers and _Exit()s, so a real defect
    comes back as exit 77 with the report on stderr. The sweep walked straight past the channel
    that DID reproduce, `res` ended up being the last channel tried (argv, which the harness
    ignores), and the sanitizer check after the loop had nothing to read.

    Measured on expat 2.1.0, through the whole pipeline: `libfuzzer` recorded a crash,
    `poc_primitive` reproduced it as SIGABRT, and the gate said "1 crash(es) recorded but NO
    verified PoC"."""
    from lykos.analyze.poc.stage import _san_report

    class _R:
        def __init__(self, crashed, stderr):
            self.crashed, self.stderr, self.isolation = crashed, stderr, "bwrap"

    ub = (b"/src/lib/xmltok_impl.c:694:3: runtime error: left shift of 1 by 31 places cannot be "
          b"represented in type 'int'\nSUMMARY: UndefinedBehaviorSanitizer: undefined-behavior\n")
    got = _san_report(_R(False, ub))
    assert got and got["class"] == "undefined-behavior", got
    # a signal crash is handled by the existing path, not this one
    assert _san_report(_R(True, ub)) is None
    assert _san_report(_R(False, b"")) is None
    assert _san_report(None) is None
    # a sanitizer SETUP failure is not a finding
    assert _san_report(_R(False, b"AddressSanitizer failed to allocate 0x1000 bytes\n")) is None


def test_the_sweep_breaks_on_it_in_the_loop_not_after():
    """A source-level check, because the defect was entirely about WHERE the test happened: the
    verdict was correct and applied to the wrong run."""
    import pathlib as _p

    import lykos.analyze.poc.stage as S
    src = _p.Path(S.__file__).read_text()
    body = src[src.index("for pre in (prefixes if"):src.index("verified = res.crashed")]
    assert "_san = _san_report(res)" in body, "the sweep no longer asks inside the loop"
    assert "if res.crashed or _san:" in body, "the sweep still breaks on a signal alone"


# ------------------------------------------------- a crash WE caused is not a finding
def test_a_constructors_capacity_is_not_zero():
    """Measured on json-c 0.13.1, and it fabricated three findings.

    Every scalar constructor argument used to be 0, so the synthesized door was

        lh_table_new(0, NULL, NULL, NULL);  lh_table_insert_w_hash(t, data, size, ...)

    and `linkhash.c` does `n = h % t->size`. The run reported two confirmed CWE-369
    divide-by-zeros and a poc-backed "control-flow hijack (potential)" against a library whose
    own code calls that constructor with `JSON_OBJECT_DEF_HASH_ENTRIES` == 16 and whose header
    documents the argument as "initial table size" -- while json-c's real parser, fuzzed through
    its in-tree harness in the same run, took 5,508,986 executions and crashed zero times.

    A hash table of size zero is misuse by the caller. A crash we caused by misusing an API is
    not a defect in that API, and emitting one is the worst thing this tool can do.
    """
    assert L._ctor_arg_values(["int size"]) == ["16"]
    assert L._ctor_arg_values(["size_t nmemb", "unsigned buckets"]) == ["16", "16"]
    assert L._ctor_arg_values(["int initial_capacity"]) == ["16"]
    # a pointer still means "the optional thing you did not ask for"
    assert L._ctor_arg_values(["const char *encoding"]) == ["NULL"]
    # and a flag or a mode is legitimately zero -- "no options"
    assert L._ctor_arg_values(["int flags", "unsigned mode", "int opt"]) == ["0", "0", "0"]
    # The NAME decides, not the type: `size_t opt` is an option declared with a size type, and
    # reading the type as the signal would hand 16 to a flag. An unnamed parameter stays 0.
    assert L._ctor_arg_values(["size_t opt"]) == ["0"]
    assert L._ctor_arg_values(["int"]) == ["0"]
    assert L._ctor_arg_values(["unsigned num_buckets"]) == ["16"]
    # the real json-c signature, end to end
    assert L._ctor_arg_values(["int size", "lh_entry_free_fn *free_fn", "lh_hash_fn *hash_fn",
                               "lh_equal_fn *equal_fn"]) == ["16", "NULL", "NULL", "NULL"]


# ------------------------------------------------------------------ the PUBLIC door, not any door
#
# Being declared in *some* header was the whole test for "this is the library's API", and
# libsndfile's `src/common.h` -- the internal structs -- passed it. The strongest triple in the
# tree was therefore `psf_allocate()` -> `psf_fopen()`: a door no application has, on a handle a
# harness cannot honestly build. It did not even compile ("use of undeclared identifier
# 'psf_allocate'"), so the library fuzzed at 34 exec/s through nothing while `sf_open` ->
# `sf_read_*` -> `sf_close` went untouched.
_INTERNAL_HDR = """#ifndef MYLIB_PRIV_H
#define MYLIB_PRIV_H
#include "mylib.h"
typedef struct my_inner_s *my_inner;
my_inner my_inner_alloc(void);
int my_inner_feed(my_inner p, const char *s, int len, int flags);
void my_inner_free(my_inner p);
#endif
"""
_INTERNAL_SRC = """#include <stdlib.h>
#include <string.h>
#include "mylib_priv.h"
struct my_inner_s { int n; char buf[16]; };
my_inner my_inner_alloc(void) { return (my_inner)calloc(1, sizeof(struct my_inner_s)); }
int my_inner_feed(my_inner p, const char *s, int len, int flags) {
    (void)flags;
    if (p && len > 0) { memcpy(p->buf, s, (size_t)len); }
    return 1;
}
void my_inner_free(my_inner p) { free(p); }
"""


@pytest.fixture
def lib_with_internals(lib):
    (lib / "lib" / "mylib_priv.h").write_text(_INTERNAL_HDR)
    (lib / "lib" / "inner.c").write_text(_INTERNAL_SRC)
    return lib


def test_an_install_rule_names_the_api(lib_with_internals):
    """The project states which headers it ships; both automake and cmake spellings are read."""
    (lib_with_internals / "Makefile.am").write_text(
        "lib_LTLIBRARIES = libmylib.la\n"
        "nodist_include_HEADERS = mylib.h\n")
    assert L.installed_headers(lib_with_internals) == frozenset({"mylib.h"})
    assert L.header_is_installed(lib_with_internals, "lib/mylib.h")
    assert not L.header_is_installed(lib_with_internals, "lib/mylib_priv.h")


def test_a_variable_in_an_install_rule_is_expanded(lib_with_internals):
    """zlib installs through `install(FILES ${ZLIB_PUBLIC_HDRS})`, so the rule names no file."""
    (lib_with_internals / "CMakeLists.txt").write_text(
        "set(MYLIB_PUBLIC_HDRS\n    lib/mylib.h\n)\n"
        "set(MYLIB_PRIVATE_HDRS lib/mylib_priv.h)\n"
        "install(FILES ${MYLIB_PUBLIC_HDRS} DESTINATION include)\n")
    assert L.installed_headers(lib_with_internals) == frozenset({"mylib.h"})


def test_a_commented_out_install_rule_installs_nothing(lib_with_internals):
    """openjpeg ships `#install(FILES mj2.h` -- a header it decided NOT to install."""
    (lib_with_internals / "CMakeLists.txt").write_text(
        "install(FILES lib/mylib.h DESTINATION include)\n"
        "#install(FILES lib/mylib_priv.h DESTINATION include)\n")
    assert L.installed_headers(lib_with_internals) == frozenset({"mylib.h"})


def test_a_bundled_projects_install_rule_is_not_this_librarys(lib_with_internals):
    """zlib ships `contrib/minizip`, whose `minizip_include_HEADERS` names zip.h and unzip.h.
    Reading it would make zlib's own `zlib.h` private and lose `gzopen` -- the door that works."""
    (lib_with_internals / "Makefile.am").write_text("nodist_include_HEADERS = mylib.h\n")
    (lib_with_internals / "contrib" / "minilib").mkdir(parents=True)
    (lib_with_internals / "contrib" / "minilib" / "Makefile.am").write_text(
        "minilib_include_HEADERS = zip.h unzip.h\n")
    assert L.installed_headers(lib_with_internals) == frozenset({"mylib.h"})


def test_a_tree_that_states_nothing_keeps_every_candidate(lib_with_internals):
    """bzip2 installs with a shell script. An unknown answer is not "nothing is public": the
    triple through the internal header is still the only door there is, and it still works."""
    assert L.installed_headers(lib_with_internals) == frozenset()
    doors = [t["consume"] for t in L.find_handle_triples(lib_with_internals, limit=4)]
    assert "my_inner_feed" in doors


def test_the_internal_api_is_not_planned_as_a_door(lib_with_internals):
    """With the API stated, the internal triple is EXCLUDED -- not merely outranked, because a
    penalty still wins when the internal door is the only candidate left in the window."""
    (lib_with_internals / "Makefile.am").write_text("nodist_include_HEADERS = mylib.h\n")
    doors = [t["consume"] for t in L.find_handle_triples(lib_with_internals, limit=4)]
    assert "my_parse" in doors
    assert "my_inner_feed" not in doors
    entries = [s.get("entry") for s in L.plan_harnesses(lib_with_internals)]
    assert "my_parse()" in entries
    assert "my_inner_feed()" not in entries


def test_a_public_header_wins_the_tie_over_an_internal_one(lib_with_internals):
    """libsndfile declares `sf_close` in both the shipped `sndfile.h` and the internal
    `common.h`, same directory and same depth, and the shorter NAME used to win."""
    (lib_with_internals / "Makefile.am").write_text("nodist_include_HEADERS = mylib.h\n")
    (lib_with_internals / "lib" / "ml.h").write_text("int my_parse(my_parser, const char *, int, int);\n")
    assert L._declared_in_header(lib_with_internals, "my_parse").name == "mylib.h"
