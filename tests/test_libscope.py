"""Static-binary scoping (detect/libscope.py, doc 62 §4 item 6).

A statically linked binary carries its libc and the decompiler recovers all of it: jhead-3.04 is
1,429 functions of which 56 are jhead's, and detect_cwe filed ~5,800 of its 6,218 sites inside
glibc internals (`_dl_relocate_object`, `__vfscanf_internal`, `_int_malloc`...) -- noise that
buries the program's own findings. The detect stage now scopes the detectors and taint to the
program's own functions; calls INTO the library keep their names, so they are still sinks/sources
(as imports are on a dynamic binary). Nothing is excluded on a dynamically linked binary.
"""
import pathlib
from types import SimpleNamespace

import pytest
from lykos.analyze.detect import libscope, taint
from lykos.analyze.poc.exploit import _elf_symbols

_BIN = pathlib.Path(__file__).resolve().parent.parent / "examples" / "vuln-targets" / "bin"
# jhead's own functions (its four .c files), as the dynamically linked build names them
_JHEAD_OWN = {"main", "ProcessFile", "ReadJpegSections", "ReadJpegFile", "ProcessExifDir",
              "ProcessGpsInfo", "ProcessMakerNote", "ConvertAnyFormat", "Get16u", "Get32u",
              "process_EXIF", "process_SOFn", "process_COM", "show_IPTC", "ShowImageInfo",
              "DoCommand", "WriteJpegFile", "shellescape"}


def _functions(path):
    blob = path.read_bytes()
    syms = _elf_symbols(blob, 2)                         # STT_FUNC name -> addr
    by_addr: dict = {}                                   # one row per address, as recovery has
    for n, a in sorted(syms.items()):
        if a:
            by_addr.setdefault(a, n)
    return blob, [SimpleNamespace(addr=hex(a), name=n) for a, n in sorted(by_addr.items())]


def _need(name):
    p = _BIN / name
    if not p.is_file():
        pytest.skip(f"{name} not present")
    return p


# ------------------------------------------------------------------------------ name / file tests
def test_library_file_names():
    assert libscope.is_library_file("iofclose.o")
    assert libscope.is_library_file("memcpy-avx-unaligned-erms.o")
    assert libscope.is_library_file("crtstuff.c")
    assert not libscope.is_library_file("exif.c")
    assert not libscope.is_library_file("main.cpp")
    assert not libscope.is_library_file(None)


def test_library_name_recognition_is_conservative():
    for n in ("_IO_fwrite", "_dl_relocate_object", "_nl_find_msg", "__vfscanf_internal",
              "__printf_fp_buffer_1.isra.0", "_start", "frame_dummy", "memcpy", "malloc",
              "__isoc23_sscanf", "__str_to_mpn.part.0.constprop.0_0x46e2f0"):
        assert libscope.is_library_name(n), n
    # never main, never an unnamed recovery label, never a plausible program name
    for n in ("main", "main.cold", "fcn.00401088", "sub_401000", "FUN_00401000", "ProcessFile",
              "process_EXIF", "show_IPTC", "parse_header", ""):
        assert not libscope.is_library_name(n), n


# ------------------------------------------------------------------------- whole-binary scoping
def test_symbolized_static_binary_scopes_to_program_functions():
    blob, fns = _functions(_need("jhead_x86-64"))
    sc = libscope.library_scope(blob, fns, flirt_named={})
    assert sc["linking"] == "static"
    excluded_names = {f.name for f in fns if f.addr in sc["excluded"]}
    kept_names = {f.name for f in fns if f.addr not in sc["excluded"]}
    # jhead's own code: every function stays in scope
    assert _JHEAD_OWN <= kept_names, _JHEAD_OWN - kept_names
    # glibc internals leave it
    for n in ("_IO_fwrite", "_int_malloc", "__vfscanf_internal", "_nl_find_msg",
              "_dl_relocate_object", "_IO_fclose", "save_for_backup"):
        assert n in excluded_names, n
    # most of the image is library, attributed by the symbol table's STT_FILE groups
    assert sc["basis"].get("symbol-file", 0) > 1000
    assert sc["kept"] < 150


def test_dynamic_binary_is_never_scoped():
    blob, fns = _functions(_need("gif2rgb_x86-64"))
    sc = libscope.library_scope(blob, fns, flirt_named={})
    assert sc["linking"] == "dynamic"
    assert sc["excluded"] == {}


def test_stripped_static_uses_flirt_identified_bodies(monkeypatch):
    """No symbol table: the bodies FLIRT matched are the library; unnamed code stays in scope."""
    blob = _need("jhead_x86-64").read_bytes()
    monkeypatch.setattr(libscope, "_symbol_marks", lambda b, i: ([], []))
    fns = [SimpleNamespace(addr="0x401000", name="fcn.00401000"),
           SimpleNamespace(addr="0x402000", name="fcn.00402000"),
           SimpleNamespace(addr="0x403000", name="main")]
    sc = libscope.library_scope(blob, fns, flirt_named={"0x402000": "strcpy", "0x403000": "x"})
    assert sc["excluded"] == {"0x402000": "flirt"}        # main is never excluded


def test_nothing_excluded_when_everything_would_be():
    blob = _need("jhead_x86-64").read_bytes()
    fns = [SimpleNamespace(addr="0x9990000", name="_IO_x"), SimpleNamespace(addr="0x9990010",
                                                                               name="__y")]
    assert libscope.library_scope(blob, fns, flirt_named={})["excluded"] == {}


# --------------------------------------------------------------- the stage wiring (_library_scoped)
class _Ctx:
    def __init__(self, path):
        self.events = []
        self.content = SimpleNamespace(path=lambda sha: path)

    def emit(self, type, level="info", payload=None):
        self.events.append((type, payload))


def test_stage_drops_library_bodies_but_keeps_named_edges_into_them():
    from lykos.analyze.detect.stage import _library_scoped
    path = _need("jhead_x86-64")
    blob, fns = _functions(path)
    by = {n: hex(a) for n, a in _elf_symbols(blob, 2).items() if a}   # every alias
    E = lambda s, d, n: SimpleNamespace(src_addr=s, site_addr=hex(int(s, 16) + 5), dst_addr=d,
                                        dst_name=n, external=False)
    edges = [E(by["ProcessFile"], by["malloc"], "malloc"),           # program -> libc: kept
             E(by["malloc"], by["_int_malloc"], "_int_malloc"),      # libc -> libc: dropped
             E(by["main"], by["ProcessFile"], "ProcessFile")]
    ctx = _Ctx(path)
    tgt = SimpleNamespace(file_type="elf", sha256="x")
    kept, kedges, n, (summ, summ_edges) = _library_scoped(ctx, tgt, fns, edges)
    assert n > 1000 and len(kept) == len(fns) - n
    assert {e.dst_name for e in kedges} == {"malloc", "ProcessFile"}
    # the directly-called library function is a taint SUMMARY, not a detector input
    assert [f.addr for f in summ] == [by["malloc"]]
    assert [e.dst_name for e in summ_edges] == ["_int_malloc"]
    ev = dict(ctx.events)["detect.library_scoped"]
    assert ev["excluded"] == n and ev["applied"] and ev["basis"]["symbol-file"] > 1000
    # opting out keeps everything and still says what it would have scoped
    ctx2 = _Ctx(path)
    kept2, kedges2, n2, _ = _library_scoped(ctx2, tgt, fns, edges, off=True)
    assert n2 == 0 and len(kept2) == len(fns) and len(kedges2) == 3
    assert dict(ctx2.events)["detect.library_scoped"]["applied"] is False


def test_stage_leaves_a_dynamic_binary_alone():
    from lykos.analyze.detect.stage import _library_scoped
    path = _need("gif2rgb_x86-64")
    blob, fns = _functions(path)
    ctx = _Ctx(path)
    kept, kedges, n, _ = _library_scoped(ctx, SimpleNamespace(file_type="elf", sha256="x"),
                                         fns, [])
    assert n == 0 and kept is fns and ctx.events == []


# ------------------------------------------- a call into an excluded body is a NAMED sink (import)
def test_call_into_an_unanalysed_library_body_is_still_a_named_sink():
    """The excluded `system` body is not in func_irs, but the INTERNAL edge to it carries its name:
    taint flags the call exactly as it would an import."""
    main = "0x1000"
    ir = {"blocks": [{"addr": main, "succ": [], "instructions": [
        {"addr": "0x1000", "text": "", "pcode": ["COPY reg:RSI:8 -> reg:RDI:8"]},
        {"addr": "0x1008", "text": "", "pcode": ["CALL ram:0x9000:8"]}]}]}
    edge = SimpleNamespace(src_addr=main, site_addr="0x1008", dst_addr="0x9000",
                           dst_name="system", external=False)
    flagged = taint.analyze_program({main: ir}, [edge], "x86-64", entry_seeds={main: {1}})
    assert "0x1008" in flagged
