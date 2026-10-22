"""Harness candidate selection: drive the program's own parsers, never an imported-libc PLT thunk,
and do not drop a real parser just because the decompiler recovered no parameter types (-O0 /
stripped). Regression for a live finding: on a tiny -O0 binary the harness drove the `memcpy`/`puts`
PLT thunks (perfect libc prototype -> top harnessable score) and skipped the actual `parse_record`
parser (ptr_len=0), returning zero findings on a binary with an obvious overflow."""
from lykos.analyze.harness.harness_stage import _drivable, _drive_shape, _is_import_thunk
from lykos.analyze.harness.rank import RankedFn


def _rf(name, *, ptr_len=0, sinks=(), sources=()):
    return RankedFn(addr=0x401000, name=name, size=32, score=2, sinks=list(sinks),
                    sources=list(sources), ptr_len=ptr_len)


def test_import_thunks_are_excluded():
    assert _is_import_thunk(_rf("memcpy", ptr_len=2))
    assert _is_import_thunk(_rf("puts", ptr_len=2))
    assert _is_import_thunk(_rf("strcpy"))
    assert not _is_import_thunk(_rf("parse_record", sinks=["memcpy"]))
    assert not _is_import_thunk(_rf("main"))


def test_real_parser_without_param_types_is_drivable():
    # the live bug: parse_record has a memcpy sink but ptr_len=0 (no recovered param types)
    assert _drivable(_rf("parse_record", ptr_len=0, sinks=["memcpy"]))
    assert _drivable(_rf("handle", ptr_len=0, sources=["recv"]))
    assert _drivable(_rf("decode", ptr_len=1))


def test_thunks_and_signalless_functions_not_drivable():
    assert not _drivable(_rf("memcpy", ptr_len=2))        # a thunk, however good its prototype looks
    assert not _drivable(_rf("helper", ptr_len=0))        # no pointer, no sink, no source = nothing


def test_drive_shape_guesses_buf_len_when_unknown():
    assert _drive_shape(_rf("f", ptr_len=2)) == "ptr_len"   # pointer+length recovered
    assert _drive_shape(_rf("f", ptr_len=1)) == "ptr"       # a lone pointer, no length
    # ptr_len=0 (nothing recovered) -> guess f(buf,len) so a `if(len<N) return;` guard does not
    # early-return on an uninitialised length and hide the bug
    assert _drive_shape(_rf("f", ptr_len=0, sinks=["memcpy"])) == "ptr_len"
