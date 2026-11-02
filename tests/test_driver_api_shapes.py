"""Driver synthesis for library APIs spelled with typedefs and output callbacks.

Measured on md4c 0.4.4: the library's real entry point `md_html(const MD_CHAR*, MD_SIZE,
void (*)(const MD_CHAR*, MD_SIZE, void*), void*, unsigned, unsigned)` was invisible (the definition
regex could not read a function-pointer parameter, and MD_CHAR/MD_SIZE hid the buffer/length shape),
so 117M executions went to `entity_lookup` and a heap overflow a 4-minute hand driver finds was
missed. Fixing that must not open the opposite hole: a synthesized call whose invented argument
(NULL for a struct, a temp PATH) crashes the library is OUR crash and must never be filed.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from lykos.analyze import libfuzzer as L

_MDLIKE_H = """
typedef char MD_CHAR;
typedef unsigned MD_SIZE;
typedef struct MD_PARSER { int abi_version; void (*cb)(void); } MD_PARSER;
int md_parse(const MD_CHAR* text, MD_SIZE size, const MD_PARSER* parser, void* userdata);
int md_html(const MD_CHAR* input, MD_SIZE input_size,
            void (*process_output)(const MD_CHAR*, MD_SIZE, void*),
            void* userdata, unsigned parser_flags, unsigned renderer_flags);
"""
_MDLIKE_C = r"""
#include <string.h>
#include "md.h"
int md_parse(const MD_CHAR* text, MD_SIZE size, const MD_PARSER* parser, void* userdata) {
    if (parser->abi_version != 0) return -1;          /* dereferences the parser first */
    return (int)size + (text ? 0 : 1) + (userdata ? 1 : 0);
}
int md_html(const MD_CHAR* input, MD_SIZE input_size,
            void (*process_output)(const MD_CHAR*, MD_SIZE, void*),
            void* userdata, unsigned parser_flags, unsigned renderer_flags) {
    char out[8];
    MD_SIZE n = input_size < 8 ? input_size : 8;
    memcpy(out, input, n);
    process_output(out, n, userdata);                   /* calls the output sink */
    if (input_size > 3 && input[0] == 'B' && input[1] == 'U' && input[2] == 'G')
        out[input_size] = 0;                            /* the real bug: attacker-indexed write */
    return (int)(parser_flags + renderer_flags);
}
"""
_CMAKE = """cmake_minimum_required(VERSION 3.5)
project(md C)
add_library(md md.c md.h)
set_target_properties(md PROPERTIES PUBLIC_HEADER md.h)
install(TARGETS md PUBLIC_HEADER DESTINATION include)
"""


@pytest.fixture
def mdlike(tmp_path):
    (tmp_path / "md.h").write_text(_MDLIKE_H)
    (tmp_path / "md.c").write_text(_MDLIKE_C)
    (tmp_path / "CMakeLists.txt").write_text(_CMAKE)
    # helper with a plain (buf, len) signature in an INTERNAL header -- the old winner
    (tmp_path / "entity.h").write_text("int entity_lookup(const char* name, unsigned long n);\n")
    (tmp_path / "entity.c").write_text(
        '#include "entity.h"\nint entity_lookup(const char* name, unsigned long n)'
        '{ return n ? name[0] : 0; }\n')
    return tmp_path


def test_typedefs_and_function_pointer_params_are_read(mdlike):
    tm = L.typedef_map(mdlike)
    assert tm["MD_CHAR"] == "char" and tm["MD_SIZE"] == "unsigned"
    p = L.fn_params(mdlike, "md_html")
    assert len(p) == 6 and p[0].startswith("const char")
    assert L.is_void_callback(p[2])
    assert L.harness_kind_for(mdlike, "md_html") == "buflen"
    assert L.installed_headers(mdlike) == frozenset({"md.h"})


def test_the_public_one_call_api_outranks_an_internal_helper(mdlike):
    ranked = L.rank_harness_fns(mdlike, limit=8)
    assert ranked[0] == "md_html", ranked


def test_a_callback_stub_has_the_callbacks_exact_signature():
    n = L.callback_stub("void (*cb)(const char* text, unsigned size, void* ud)")
    assert L._CB_DEFS[n].startswith(f"static void {n}(const char* a0, unsigned a1, void* a2)")
    # a callback the harness cannot spell, or one whose result the library uses, is not faked
    assert L.callback_stub("void (*cb)(MD_BLOCK* b)") is None
    assert L.callback_stub("int (*cb)(void)") is None
    assert L._opaque_param("int (*cb)(void)")


def _clang():
    if not shutil.which("clang"):
        pytest.skip("no clang")
    r = subprocess.run(["clang", "-fsanitize=fuzzer", "-x", "c", "-", "-o", "/dev/null"],
                       input=b"#include <stdint.h>\n#include <stddef.h>\nint LLVMFuzzerTestOneInput"
                             b"(const uint8_t*d,size_t n){return 0;}\n", capture_output=True)
    if r.returncode:
        pytest.skip("clang cannot build a libFuzzer target here")


def test_md_html_driver_passes_the_gate_and_finds_the_real_bug(mdlike, tmp_path):
    _clang()
    b = L.build_libfuzzer(mdlike, tmp_path / "html.bin", spec=L.fn_spec(mdlike, "md_html"))
    assert b["ok"], b.get("log", "")[-800:]
    # the generated output callback is called with the library's own arguments -- UBSan's
    # function-type check would abort a mismatched stub on the first input
    assert L.trivial_input_crash(b["binary"], tmp_path / "triv") is None
    r = L.run_libfuzzer(b["binary"], tmp_path / "run", seconds=20, corpus=[b"BUG", b"hello"])
    reports = " ".join(c.get("report") or "" for c in r["crashes"])
    # the attacker-indexed write at md.c:16 -- UBSan's bounds check or ASan, whichever fires first
    assert "md.c:16" in reports and ("out of bounds" in reports
                                     or "stack-buffer-overflow" in reports)


def test_a_call_with_an_invented_null_struct_is_never_fuzzed(mdlike, tmp_path):
    _clang()
    b = L.build_libfuzzer(mdlike, tmp_path / "parse.bin", spec=L.fn_spec(mdlike, "md_parse"))
    assert b["ok"], b.get("log", "")[-800:]
    bad = L.trivial_input_crash(b["binary"], tmp_path / "triv")
    assert bad and "0-byte input" in bad
