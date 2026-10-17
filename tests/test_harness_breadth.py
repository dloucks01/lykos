"""BREADTH: a library is not one function.

`build_libfuzzer` resolved ONE entry point and the campaign went through that one door. Nothing
was wrong with the choice -- the ranking picks the library's strongest public, input-consuming
API -- but "we fuzzed libtiff" meant "we fuzzed `TIFFOpen`", and every other way bytes enter the
library was unreachable at any budget. Measured on libtiff 4.0.3: six doors the synthesizer can
reach, five of them never opened, and three distinct UBSan faults behind them
(`tif_read.c:460`, `tif_read.c:545`, `tif_dirread.c:3766`) that the one harness never saw.

The library here has two readers behind one handle. The bug is behind the SECOND, which is the
whole point: with one harness per library it cannot be found at all.
"""
import os
import pathlib
import re
import subprocess

import pytest
from lykos.analyze import libfuzzer as L

_HDR = """#ifndef MH_H
#define MH_H
#include <stddef.h>
typedef struct mh_s *mh;
mh mh_open(const char *path, const char *mode);
int mh_read_index(mh h, void *out, int n);
int mh_read_tile(mh h, void *out, int n);
void mh_close(mh h);
void mh_iter_end(mh h);
#endif
"""

_SRC = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mh.h"

struct mh_s { FILE *f; };

mh mh_open(const char *path, const char *mode) {
    mh h = (mh)calloc(1, sizeof(struct mh_s));
    if (!h) return 0;
    h->f = fopen(path, mode);
    if (!h->f) { free(h); return 0; }
    return h;
}

/* door one: bounded, and correct. */
int mh_read_index(mh h, void *out, int n) {
    unsigned char b[8];
    size_t got;
    if (!h || !h->f || n <= 0) return 0;
    got = fread(b, 1, sizeof(b), h->f);
    if (got > (size_t)n) got = (size_t)n;
    memcpy(out, b, got);
    return (int)got;
}

/* door two: believes a length out of the file. */
int mh_read_tile(mh h, void *out, int n) {
    unsigned char hdr[4], buf[256];
    size_t len, got;
    unsigned char *tile;
    (void)n;
    if (!h || !h->f) return 0;
    if (fread(hdr, 1, 4, h->f) != 4) return 0;
    if (hdr[0] != 'T') return 0;
    len = (size_t)hdr[1] * 256u + (size_t)hdr[2];
    if (len > sizeof(buf)) len = sizeof(buf);
    got = fread(buf, 1, len, h->f);
    tile = (unsigned char *)malloc(16);
    if (!tile) return 0;
    memcpy(tile, buf, got);                 /* the bug: got can be 256, tile holds 16 */
    memcpy(out, tile, 16);
    free(tile);
    return 1;
}

void mh_close(mh h) { if (h) { if (h->f) fclose(h->f); free(h); } }

/* a WEAK closer: it matches "end" and must not be preferred to mh_close. */
void mh_iter_end(mh h) { (void)h; }
"""

#: A static helper whose storage class is on the line ABOVE the name, which is how expat writes
#: them -- and which `_FN_DEF`'s line-anchored refusal does not catch.
_STATIC = """#include <stddef.h>
static int FASTCALL_PLACEHOLDER
mh_private_cmp(const char *a, const char *b) { return a && b && a[0] == b[0]; }
""".replace("FASTCALL_PLACEHOLDER", "")


@pytest.fixture
def lib(tmp_path):
    d = tmp_path / "mh"
    (d / "lib").mkdir(parents=True)
    (d / "lib" / "mh.h").write_text(_HDR)
    (d / "lib" / "mh.c").write_text(_SRC)
    (d / "lib" / "mh_private.c").write_text(_STATIC)
    # a program in the tree: its helpers are not the library's API
    (d / "tool").mkdir()
    (d / "tool" / "mhdump.c").write_text(
        '#include <stdio.h>\n#include "../lib/mh.h"\n'
        "char *tool_helper(const char *s) { return (char *)s; }\n"
        "int main(int argc, char **argv) { (void)argc; (void)argv; return 0; }\n")
    return d


# ---------------------------------------------------------------- the plan

def test_both_doors_into_the_library_are_planned(lib):
    """One harness per library was the ceiling on reach. The plan holds every door."""
    plan = L.plan_harnesses(lib, limit=6)
    entries = [s.get("entry") for s in plan]
    assert "mh_read_tile()" in entries, f"the second reader is unreachable: {entries}"
    assert "mh_read_index()" in entries, f"the first reader is unreachable: {entries}"
    assert len({s["id"] for s in plan}) == len(plan), "the plan repeats a harness"


def test_the_plan_leads_with_what_the_builder_used_to_resolve_alone(lib):
    """Breadth must not change the choice that was already being made: the strongest harness is
    still first, so the first campaign is the one that used to run."""
    plan = L.plan_harnesses(lib, limit=6)
    alone = L.plan_harnesses(lib, limit=1)
    assert alone == plan[:1]


def test_the_projects_own_harnesses_all_count(tmp_path):
    """An OSS-Fuzz tree ships one harness per entry point; `find_harness` took whichever `rglob`
    yielded first and the others were invisible."""
    d = tmp_path / "proj"
    (d / "fuzz").mkdir(parents=True)
    (d / "lib").mkdir()
    (d / "lib" / "x.c").write_text("int x(const char *s){ return s ? s[0] : 0; }\n")
    for name in ("a_fuzzer.c", "b_fuzzer.c"):
        (d / "fuzz" / name).write_text(
            "#include <stdint.h>\n#include <stddef.h>\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)\n"
            "{ (void)d; (void)n; return 0; }\n")
    assert len(L.find_harnesses(d)) == 2
    plan = L.plan_harnesses(d, limit=4)
    kinds = [s["kind"] for s in plan]
    assert kinds[:2] == ["in-tree", "in-tree"], kinds


def test_a_static_helper_is_not_an_entry_point(lib):
    """A static function cannot be called from another translation unit, so a harness synthesized
    for one cannot link -- after paying for the library's whole compile. expat's `attcmp` ranked
    as an entry point because its `static` sits on the line above the name."""
    assert "mh_private_cmp" not in L.rank_harness_fns(lib, limit=20)
    assert L._static_before("static int FASTCALL\nattcmp(const void *p)", 21) is True
    assert L._static_before("int;\nattcmp(const void *p)", 5) is False


def test_a_tools_helper_is_not_an_entry_point(lib):
    """Its translation unit carries `main`, so the build excludes it and a harness calling into it
    could never link."""
    assert "tool_helper" not in L.rank_harness_fns(lib, limit=20)


# ------------------------------------------------- where the bytes belong

def test_an_opener_is_told_from_a_creator(lib):
    """The same SHAPE, and NULL is right for exactly one of them: `TIFFOpen(name, mode)` needs a
    path, `XML_ParserCreate(encoding)` needs NULL. Guessing either way wrong costs every
    execution -- the handle comes back NULL and the campaign tests `if (!h)`."""
    assert L.ctor_opens_a_file("mh_open", ["const char *path", "const char *mode"]) is True
    assert L.ctor_opens_a_file("TIFFOpen", ["const char* name", "const char* mode"]) is True
    assert L.ctor_opens_a_file("XML_ParserCreate", ["const XML_Char *encoding"]) is False
    assert L.ctor_opens_a_file("my_parser_create", []) is False


def test_the_file_backed_harness_puts_the_bytes_in_the_file(lib):
    """And NOT in the consumer's buffer, which is where the decoded output goes."""
    tri = next(t for t in L.find_handle_triples(lib, limit=6) if t["consume"] == "mh_read_tile")
    assert tri["ctor_file"] is True
    src = L.synth_handle_harness(tri)
    assert "mkstemp(path)" in src and "write(fd, data, size)" in src
    assert 'mh_open(path, "r")' in src
    # the output buffer is the harness's own allocation, not libFuzzer's input
    assert re.search(r"mh_read_tile\(h, \(void \*\)out, \(int\)\d+\)", src), src
    assert "data" not in src.split("mh_read_tile")[1], "the fuzz bytes are passed as the output"


def test_the_handle_is_released_by_the_librarys_own_closer(lib):
    """`mh_iter_end` matches "end" and sorts first; it is not the closer. libtiff's handle was
    released by `Fax3Close` -- a codec's private teardown -- and before that by
    `TIFFImageIterEnd`, which leaks the file on every one of a hundred thousand executions."""
    assert L._find_taking_only(lib, "mh", L._DTOR_WORDS, kin="mh_open") == "mh_close"


# -------------------------------------------------------------- the build

@pytest.fixture(scope="module")
def clang():
    import shutil
    if not shutil.which("clang"):
        pytest.skip("clang is required for libFuzzer")
    return "clang"


def _run(binary, work, seconds=15):
    work.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, ASAN_OPTIONS="abort_on_error=1:detect_leaks=0")
    p = subprocess.run([str(binary), str(work), f"-max_total_time={seconds}", "-max_len=512",
                        f"-artifact_prefix={work}/"], capture_output=True, text=True,
                       timeout=seconds + 60, env=env, cwd=str(work))
    return (p.stderr or "") + (p.stdout or "")


def test_the_bug_behind_the_second_door_is_found_only_by_the_second_harness(lib, clang, tmp_path):
    """THE WHOLE POINT. The planted overflow is behind `mh_read_tile`, and the harness the builder
    resolves on its own calls `mh_read_index`. One harness per library cannot reach it."""
    plan = L.plan_harnesses(lib, limit=6)
    # the premise: the harness the builder resolves ON ITS OWN is the other door
    assert plan[0]["entry"] == "mh_read_index()", [s["entry"] for s in plan]
    cache = L.BuildCache(tmp_path / "objs")
    built = {}
    for spec in plan:
        if spec["kind"] != "triple":
            continue
        out = tmp_path / f"{spec['id']}.bin"
        res = L.build_libfuzzer(lib, out, spec=spec, cache=cache)
        assert res["ok"], f"{spec['id']} did not build: {res['log'][-800:]}"
        built[spec["triple"]["consume"]] = res["binary"]
    assert set(built) == {"mh_read_index", "mh_read_tile"}

    log_tile = _run(built["mh_read_tile"], tmp_path / "w-tile")
    assert "heap-buffer-overflow" in log_tile, log_tile[-2000:]
    log_index = _run(built["mh_read_index"], tmp_path / "w-index", seconds=10)
    assert "ERROR: AddressSanitizer" not in log_index, "door one was supposed to be correct"


def test_the_library_is_compiled_once_for_all_its_harnesses(lib, clang, tmp_path):
    """Breadth is only affordable because each harness LINKS objects the first build compiled:
    measured on libtiff 4.0.3, 13.4 s for the first harness and 0.5 s for each of the next five.
    Without the shared cache, fuzzing six doors would compile the library six times."""
    cache = L.BuildCache(tmp_path / "objs")
    specs = [s for s in L.plan_harnesses(lib, limit=6) if s["kind"] == "triple"][:2]
    assert len(specs) == 2
    for i, spec in enumerate(specs):
        assert L.build_libfuzzer(lib, tmp_path / f"b{i}.bin", spec=spec, cache=cache)["ok"]
    assert cache.reused > 0, "the second harness recompiled the library"
    # the harness itself is never reused: it is a different translation unit each time
    assert cache.compiled >= 2


# ------------------------------------------------------- reading the engine

def test_the_execution_count_comes_back(lib):
    """The in-process engine reported no count at all, so a library run whose only real work was
    in-process showed the executions of the engines that found nothing."""
    assert L.executions("stat::number_of_executed_units: 123456\n") == 123456
    assert L.executions("#4096\tpulse  cov: 211 ft: 212\n#8192\tDONE   cov: 211\n") == 8192
    assert L.executions("") == 0


def test_a_ubsan_fault_is_reported_in_its_own_wording():
    """UBSan prints no `ERROR:` header, so three of libtiff's five synthesized harnesses faulted
    and the report came back EMPTY -- a null dereference in `TIFFFillStrip` filed as
    "crash under libFuzzer" with no source line."""
    out = ("#2 INITED cov: 1\n"
           "/x/libtiff/tif_read.c:545:8: runtime error: load of null pointer of type 'uint64'\n"
           "==674067== ERROR: libFuzzer: deadly signal\n"
           "    #10 0x1 in TIFFFillStrip /x/libtiff/tif_read.c:545:8\n")
    rep = L.fault_report(out)
    assert rep.startswith("/x/libtiff/tif_read.c:545:8: runtime error:"), rep
    from lykos.analyze.debug.rootcause import parse_asan_report
    cls = parse_asan_report(rep)
    assert cls["cwe"] == "CWE-476" and cls["source"] == "tif_read.c:545"


def test_the_sanitizers_verdict_wins_over_the_libfuzzer_stack():
    """libFuzzer's `deadly signal` says a signal arrived; the sanitizer's line says what the bug
    is. Capturing from the later text drops the only line that classifies it."""
    out = ("==1== ERROR: libFuzzer: deadly signal\n"
           "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n")
    assert "AddressSanitizer: heap-buffer-overflow" in L.fault_report(out)


def test_an_oom_is_not_filed_as_memory_corruption():
    """libFuzzer's `oom-` artifact means the library believed a size field, which is a real
    resource-exhaustion defect and not a write primitive. Filed as CWE-787 "crash under
    libFuzzer", a denial of service would be reported as memory corruption."""
    from lykos.analyze.libfuzzer_stage import _KIND_CLAIM
    assert _KIND_CLAIM["oom"][0] == "CWE-400"
    assert _KIND_CLAIM["oom"][3] == "corroborated"
    assert "crash" not in L.ARTIFACT_KINDS or L.ARTIFACT_KINDS["crash-"] == "crash"
    assert L.ARTIFACT_KINDS["oom-"] == "oom"


def test_the_corpus_is_pooled_across_the_doors(tmp_path):
    """Every entry point into one library consumes the same formats, so a unit that reached new
    coverage through one door is a strong seed for the next."""
    from lykos.analyze.libfuzzer_stage import _load_corpus
    root = tmp_path / "corpus-cache"
    (root / "tri-a").mkdir(parents=True)
    (root / "tri-b").mkdir(parents=True)
    (root / "tri-a" / "u1").write_bytes(b"AAAA")
    (root / "tri-b" / "u2").write_bytes(b"BBBB")
    (root / "legacy").write_bytes(b"CCCC")               # kept before harnesses had directories
    units = _load_corpus(root / "tri-a", pool=root)
    assert units[0] == b"AAAA", "the harness's own corpus does not lead"
    assert set(units) == {b"AAAA", b"BBBB", b"CCCC"}


# ------------------------------------------------ what the operator is told

def test_the_second_pass_is_scheduled_from_what_the_stage_reported(lib):
    """Only the stage has the source tree, so only it can say how many doors exist. The
    orchestrator asks it rather than guessing."""
    src = pathlib.Path(L.__file__).parents[0].joinpath("orchestrate.py").read_text()
    assert '_lf.get("more_entry_points")' in src
    assert '"harness_from": int(_lf.get("next_entry_point") or 1)' in src


def test_both_passes_are_counted(lib):
    """A stage that runs twice reports twice. `max` over the two reported the better half of the
    work; the plan line showed only the second pass."""
    src = pathlib.Path(L.__file__).parents[0].joinpath("orchestrate.py").read_text()
    assert "_done_execs[key] = _done_execs.get(key, 0) + n" in src, "per-run counts are not summed"
    assert "_all_done_payloads(store, target, \"libfuzzer\")" in src, "the plan shows one pass"


def test_a_second_pass_with_nothing_left_is_not_a_decline(lib):
    """`supported: false` would overwrite the first pass's record and the scorecard would call the
    whole engine inapplicable to a target it had just fuzzed."""
    src = pathlib.Path(
        L.__file__).parents[0].joinpath("libfuzzer_stage.py").read_text()
    body = src.split("if not window:")[1].split("return")[0]
    assert '"supported": True' in body, body[:400]


def test_a_pass_whose_doors_were_all_starved_is_not_a_decline(lib):
    """The second pass is scheduled to open the doors the first had no room for, and the first
    had already spent the stage's slice -- so every door in the window was starved and the stage
    reported `supported: false, "no budget left in this stage's slice"`. The real-corpus gate
    then FAILED libsndfile for an unclassifiable decline on a run where this same capability had
    just fuzzed 11,545 inputs through door 1 and found a real UBSan defect in `common.c:174`.
    Out of time is not a refusal."""
    src = pathlib.Path(
        L.__file__).parents[0].joinpath("libfuzzer_stage.py").read_text()
    body = src.split('all("no budget" in (r.get("why") or "") for r in rows)')[1].split(
        "if not built:")[0]
    assert '"supported": True' in body, body[:400]
    # ...and the doors it never attempted are still offered, so the pass is repeatable rather
    # than consumed.
    assert '"next_entry_point": first' in body
    assert '"more_entry_points": True' in body


# ------------------------------- a tree that ships a harness AND has doors

_ZH = "int zparse(const char *s, int n);\n"
_ZC = ('#include <string.h>\n#include "z.h"\n'
       "int zparse(const char *s, int n) { char b[8];\n"
       "    if (n > 0 && s[0] == 0x41) { memcpy(b, s, (size_t)n); return b[0]; }\n"
       "    return 0; }\n")
_ZF = ('#include <stdint.h>\n#include <stddef.h>\n#include "../lib/z.h"\n'
       "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)\n"
       "{ return zparse((const char *)d, (int)n) ? 0 : 0; }\n")


@pytest.fixture
def mixed(tmp_path):
    d = tmp_path / "zz"
    (d / "lib").mkdir(parents=True)
    (d / "lib" / "z.h").write_text(_ZH)
    (d / "lib" / "z.c").write_text(_ZC)
    (d / "fuzz").mkdir()
    (d / "fuzz" / "f.c").write_text(_ZF)
    return d


def test_a_harness_is_not_one_of_the_librarys_entry_points(mixed):
    """`_sources` keeps a harness file on purpose, and it is an ordinary source file with a
    non-static function in it -- so on a tree that ships its own harness,
    `LLVMFuzzerTestOneInput` was ranked as a door into the library and a harness was synthesized
    to call the harness."""
    assert "LLVMFuzzerTestOneInput" not in L.rank_harness_fns(mixed, limit=10)
    assert [s["entry"] for s in L.plan_harnesses(mixed, limit=4)] == ["fuzz/f.c", "zparse()"]


def test_two_harnesses_are_never_linked_together(mixed, clang, tmp_path):
    """Each defines the same symbol. Before the plan a synthesized harness was only ever built
    for a tree with none of its own, so this collision could not arise."""
    cache = L.BuildCache(tmp_path / "objs")
    for i, spec in enumerate(L.plan_harnesses(mixed, limit=4)):
        res = L.build_libfuzzer(mixed, tmp_path / f"b{i}.bin", spec=spec, cache=cache)
        assert res["ok"], f"{spec['id']}: {res['log'][-600:]}"
        assert "multiple definition" not in (res["log"] or "")


def test_a_pointer_and_length_signature_compiles(mixed, clang, tmp_path):
    """The shape libFuzzer hands over directly, and it declared only the FIRST parameter while
    calling with two: "too many arguments to function call, expected 1, have 2" for every
    candidate of the one signature that needs no invention at all."""
    assert L.harness_kind_for(mixed, "zparse") == "buflen"
    params = ["const char *s", "int n"]
    # C: every pointer is declared `void *` so a project's own typedefs need not be nameable --
    # what matters is that the declaration takes as many arguments as the call passes.
    src = L.synth_harness("zparse", kind="buflen", arg_type="const char *", params=params)
    assert "zparse(void *, int)" in src, src
    assert "zparse((void *)data, (int)size)" in src, src
    # C++: the symbol is mangled from its parameter types, so those have to be the real ones.
    cpp = L.synth_harness("zparse", kind="buflen", arg_type="const char *", params=params,
                          cxx=True, c_linkage=False)
    assert "zparse(const char *, int)" in cpp, cpp
    res = L.build_libfuzzer(mixed, tmp_path / "bl.bin", spec=L.fn_spec(mixed, "zparse"))
    assert res["ok"], res["log"][-600:]


# ------------------------------------- C that is not written the way we read it

#: zlib 1.2.11 in miniature: K&R definitions, `#define local static`, a pointer typedef for the
#: buffer parameter, and a header that wraps every parameter list in a macro. Each of those on its
#: own made the whole library invisible to the definition scanner -- `_fn_defs` found ZERO
#: functions in `uncompr.c`, `gzlib.c` and `gzread.c` -- so zlib was reachable only through its
#: known harness, at any budget.
_KR_H = """#ifndef KR_H
#define KR_H
#define OF(args) args
typedef void *voidp;
typedef struct kr_s *krFile;
extern krFile krOpen OF((const char *path, const char *mode));
extern int krRead OF((krFile f, voidp buf, unsigned len));
extern void krClose OF((krFile f));
#endif
"""

_KR_C = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kr.h"
#define local static

struct kr_s { FILE *f; };

local int kr_helper(n)
    int n;
{
    return n + 1;
}

krFile krOpen(path, mode)
    const char *path;
    const char *mode;
{
    krFile h = (krFile)calloc(1, sizeof(struct kr_s));
    if (!h) return 0;
    h->f = fopen(path, mode);
    if (!h->f) { free(h); return 0; }
    return h;
}

int krRead(f, buf, len)
    krFile f;
    voidp buf;
    unsigned len;
{
    unsigned char hdr[4];
    unsigned char tmp[256];
    size_t want, got;
    unsigned char *small;
    if (!f || !f->f) return 0;
    if (fread(hdr, 1, 4, f->f) != 4) return 0;
    if (hdr[0] != 'K') return 0;
    want = (size_t)hdr[1] * 256u + (size_t)hdr[2];
    if (want > sizeof(tmp)) want = sizeof(tmp);
    got = fread(tmp, 1, want, f->f);
    small = (unsigned char *)malloc(16);
    if (!small) return 0;
    memcpy(small, tmp, got);                  /* the bug */
    memcpy(buf, small, 16 < len ? 16 : len);
    free(small);
    return (int)got;
}

void krClose(f)
    krFile f;
{
    if (f) { if (f->f) fclose(f->f); free(f); }
}
"""


@pytest.fixture
def krlib(tmp_path):
    d = tmp_path / "kr"
    (d / "lib").mkdir(parents=True)
    (d / "lib" / "kr.h").write_text(_KR_H)
    (d / "lib" / "kr.c").write_text(_KR_C)
    return d


def test_a_kr_definition_is_read(krlib):
    """The parameter list is bare NAMES and the types follow it. zlib is written this way
    throughout, so the scanner found nothing at all in the library."""
    idx = L.defs_index(krlib)
    assert "krOpen" in idx, sorted(idx)
    assert L.fn_params(krlib, "krOpen") == ["const char * path", "const char * mode"]
    assert L.fn_params(krlib, "krRead")[1] == "voidp buf"


def test_the_projects_own_spelling_of_static_counts(krlib):
    """zlib writes `#define local static` and then `local int gz_load(...)`, so nothing in the
    tree is spelled `static` and half of `gzread.c` read as public API."""
    assert L.static_aliases(krlib) == frozenset({"local"})
    assert "kr_helper" not in L.rank_harness_fns(krlib, limit=20)


def test_a_typedefd_pointer_is_still_a_buffer(krlib):
    """`krRead(krFile f, voidp buf, unsigned len)` is a textbook (pointer, length) pair that a
    `*`-shaped test cannot see -- which is why zlib's `gzread` was not a door."""
    assert "voidp" in L.byte_ptr_typedefs(krlib)
    assert L.is_byte_ptr("voidp buf", {"voidp"}) is True
    assert L.is_byte_ptr("int n", {"voidp"}) is False
    assert L._buf_len_at(["voidp buf", "unsigned len"], {"voidp"}) == 0


def test_a_macro_wrapped_parameter_list_is_unwrapped(krlib):
    """`gzopen OF((const char *, const char *))` read as a function called `OF`, so the
    constructor search found nothing and zlib's open -> read -> close triple did not exist."""
    tri = L.find_handle_triples(krlib, limit=4)
    assert tri, "no triple through a macro-wrapped header"
    assert (tri[0]["ctor"], tri[0]["consume"], tri[0]["dtor"]) == ("krOpen", "krRead", "krClose")
    assert tri[0]["ctor_file"] is True


def test_one_scanner_decides_both_the_plan_and_the_call(krlib):
    """THE FABRICATED CRASH. The planner learned to read K&R and `fn_params` did not, so the
    shape was inferred from an empty parameter list: the harness declared `void gzopen(char *)`
    and called the real two-parameter `gzopen(path, mode)` with one argument. `mode` was whatever
    was in the register, zlib dereferenced it, and the campaign reported an ASan SEGV *in zlib* on
    execution one -- a crash that was entirely ours, in a real library, from three copies of one
    regex."""
    assert L.harness_kind_for(krlib, "krOpen") == "file"
    src = L.synth_file_harness("krOpen", L.fn_params(krlib, "krOpen"),
                               closer=L.fn_closer(krlib, "krOpen"))
    assert src.count(",") >= 1, src
    assert 'krOpen((void*)path, (void*)"r")' in src, src


def test_the_kr_library_builds_and_the_bug_is_found(krlib, clang, tmp_path):
    cache = L.BuildCache(tmp_path / "objs")
    tri = next(s for s in L.plan_harnesses(krlib, limit=6) if s["kind"] == "triple")
    res = L.build_libfuzzer(krlib, tmp_path / "kr.bin", spec=tri, cache=cache)
    assert res["ok"], res["log"][-800:]
    log = _run(res["binary"], tmp_path / "w-kr", seconds=20)
    assert "heap-buffer-overflow" in log, log[-1500:]


def test_the_first_pass_says_there_are_more_doors(krlib):
    """THE GATE CAUGHT THIS ONE. The stage planned only as far as its window reached
    (`limit=first+width`), so `more_entry_points` compared the plan's length against the end of
    the window -- equal by construction -- and the second pass was never scheduled: libtiff
    reported DOOR 1/1 with six doors in the tree, on the real pipeline, while every planner test
    passed because they ask for `limit=6` directly."""
    src = pathlib.Path(L.__file__).parents[0].joinpath("libfuzzer_stage.py").read_text()
    assert "limit=max(first + width, LF.MAX_HARNESSES)" in src, \
        "the stage plans only as far as its own window again"
    # the shape the stage relies on: a full plan is longer than a one-door window
    full = L.plan_harnesses(krlib, limit=L.MAX_HARNESSES)
    assert len(full) > 1, [s["entry"] for s in full]
    assert len(full) > len(full[0:1]), "a one-door window cannot be the whole plan"
