"""The hypothesis loop's pure parts: sanitizer-report attribution, the evidence model, PoC replay
scripts. (The solver itself is measured end to end by `make bench-tier0`.)"""
from lykos.hypo.model import Hypothesis, Solution, Verdict
from lykos.hypo.store import _replay_script
from lykos.hypo.validate import parse_sanitizer

_UAF = """==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x502 at pc 0x4 bp 0x7 sp 0x7
READ of size 1 at 0x502000000010 thread T0
    #0 0x401b2c in cmd_show /tmp/lykos-hunt-build-x/asan/main.c:46
    #1 0x402000 in main /tmp/lykos-hunt-build-x/asan/main.c:70
    #2 0x7f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #3 0x7f in __libc_start_main_impl ../csu/libc-start.c:360
"""

_MEMCPY = """==9==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd at pc 0x7f bp 0x7 sp 0x7
WRITE of size 300 at 0x7ffd thread T0
    #0 0x7f1 in __interceptor_memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:827
    #1 0x401234 in handle_name /src/prog.c:20
    #2 0x401300 in main /src/prog.c:51
"""

_WRAP = """==3==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60 at pc 0x4 bp 0x7 sp 0x7
WRITE of size 4 at 0x60 thread T0
    #0 0x401111 in load_table /src/prog.c:31
    #1 0x401222 in main /src/prog.c:60
0x60 is located 0 bytes after 8-byte region
allocated by thread T0 here:
    #0 0x7f in malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x4010aa in load_table /src/prog.c:27
"""

_UBSAN = """prog.c:12:21: runtime error: index -4 out of bounds for type 'uint32_t [16]'
    #0 0x401265 in set_reg /src/prog.c:12
"""


def test_program_frame_skips_runtime_but_not_a_dir_named_asan():
    kind, func, path, line, _ = parse_sanitizer(_UAF)
    assert (kind, func, line) == ("heap-use-after-free", "cmd_show", 46)
    assert path.endswith("asan/main.c")


def test_interceptor_report_attributes_to_the_call_site():
    kind, func, _path, line, _ = parse_sanitizer(_MEMCPY)
    assert (kind, func, line) == ("stack-buffer-overflow", "handle_name", 20)


def test_alloc_frame_is_reported_for_size_wrap_matching():
    kind, _f, _p, line, alloc = parse_sanitizer(_WRAP)
    assert kind == "heap-buffer-overflow" and line == 31 and alloc == 27


def test_ubsan_report():
    kind, func, _p, line, _ = parse_sanitizer(_UBSAN)
    assert kind.startswith("ubsan:") and func == "set_reg" and line == 12


def test_no_report():
    assert parse_sanitizer("all good\n") is None


def test_only_a_verdict_confirms_and_roundtrip():
    h = Hypothesis("stack-write@0x4012c9", "stack-write", "CWE-121", 0x4012C9, "handle_name",
                   0x4012A0, 80, "/src/prog.c:20", reached=1)
    h.solutions.append(Solution(b"TLV1\x01\xff", "overwrites the saved return address", 0.5))
    h.settle()
    assert h.status == "solved"            # the solver's claim alone is not a finding
    h.solutions[0].verdict = Verdict(False, "asan", "no sanitizer report")
    h.settle()
    assert h.status == "unconfirmed"
    h.solutions.append(Solution(b"x", "", 1.0, Verdict(True, "asan", "ok", 20, 3)))
    h.settle()
    assert h.status == "confirmed" and h.line == 20
    back = Hypothesis.from_dict(h.to_dict())
    assert back.to_dict() == h.to_dict()
    assert back.confirmed_solution().data == b"x"


def test_replay_script_delivers_input_per_mode():
    assert '"$HERE/input.bin"' in _replay_script("/b/prog", ["-c", "@@"], "file")
    assert '< "$HERE/input.bin"' in _replay_script("/b/prog", [], "stdin")
    assert '"$(cat "$HERE/input.bin")"' in _replay_script("/b/prog", ["@@"], "arg")
    assert "ASAN_OPTIONS" in _replay_script("/b/prog_asan", ["@@"], "file", sanitizer=True)
