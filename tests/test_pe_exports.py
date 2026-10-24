"""PE export directory + TLS callbacks (analyze/pe.py).

Triage used to report exports=0 for every DLL: the field existed but nothing filled it, so the
cross-binary linker (link/resolve.py) could never resolve a PE import against a sibling DLL.
"""
import random
import shutil
import struct
import subprocess

import pytest
from lykos.analyze import pe


def _mingw(tmp_path, src: str, out: str, extra=()):
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if not cc:
        pytest.skip("no mingw cross compiler")
    c = tmp_path / "t.c"
    c.write_text(src)
    o = tmp_path / out
    r = subprocess.run([cc, "-O0", "-w", str(c), "-o", str(o), *extra],
                       capture_output=True, timeout=180)
    if r.returncode != 0:
        pytest.skip("mingw cannot link here: " + r.stderr.decode(errors="replace")[:200])
    return o


def test_dll_named_ordinal_and_forwarded_exports(tmp_path):
    (tmp_path / "x.def").write_text(
        "LIBRARY mylib\nEXPORTS\n  parse_blob\n  helper_two\n  hidden_one @7 NONAME\n"
        "  fwd_sleep = kernel32.Sleep\n")
    dll = _mingw(tmp_path,
                 "__declspec(dllexport) int parse_blob(const char*p){return p[0];}\n"
                 "int helper_two(void){return 2;}\nint hidden_one(void){return 1;}\n",
                 "mylib.dll", ["-shared", str(tmp_path / "x.def")])
    info = pe.parse(dll.read_bytes())
    assert info.ok, info.errors
    assert "parse_blob" in info.exported_symbols
    assert "helper_two" in info.exported_symbols
    assert "hidden_one" not in info.exported_symbols        # NONAME: counted, not named
    assert info.exports_count >= len(info.exported_symbols) + 1
    assert info.export_dll_name and info.export_dll_name.lower().startswith("mylib")
    assert info.export_forwarders.get("fwd_sleep", "").lower() == "kernel32.sleep"
    assert not [e for e in info.errors if e.startswith("exports")]
    fd = pe.to_format_details(info)
    assert fd["export_forwarders"]


def test_an_exe_without_exports_is_zero_not_an_error(tmp_path):
    exe = _mingw(tmp_path, "int main(void){return 0;}\n", "a.exe")
    info = pe.parse(exe.read_bytes())
    assert info.ok
    assert not [e for e in info.errors if e.startswith("exports")]


def test_tls_callback_is_listed(tmp_path):
    exe = _mingw(tmp_path,
                 "#include <windows.h>\n"
                 "static void NTAPI cb(PVOID h, DWORD r, PVOID p){(void)h;(void)r;(void)p;}\n"
                 "__attribute__((section(\".CRT$XLB\"), used)) "
                 "PIMAGE_TLS_CALLBACK p_cb = cb;\n"
                 "int main(void){return 0;}\n", "tls.exe")
    info = pe.parse(exe.read_bytes())
    assert info.tls_callbacks, info.errors
    lo = info.image_base
    assert all(v > lo for v in info.tls_callbacks)


def _synthetic_dll(n_names=2, n_funcs=2, funcs_rva=None, names_rva=None, ords_rva=None):
    """A minimal PE32+ with one section holding a hand-built export directory."""
    data = bytearray(0x600)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    opt_size = 240
    struct.pack_into("<HHIIIHH", data, coff, 0x8664, 1, 0, 0, 0, opt_size, 0x2022)
    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<Q", data, opt + 24, 0x180000000)
    struct.pack_into("<I", data, opt + 108, 16)
    struct.pack_into("<II", data, opt + 112, 0x1000, 0x200)       # EXPORT dir
    sh = opt + opt_size
    data[sh:sh + 8] = b".edata\0\0"
    struct.pack_into("<IIII", data, sh + 8, 0x200, 0x1000, 0x200, 0x400)
    struct.pack_into("<I", data, sh + 36, 0x40000040)
    e = 0x400
    struct.pack_into("<IIHHIIIIIII", data, e, 0, 0, 0, 0, 0x1100, 1, n_funcs, n_names,
                     funcs_rva if funcs_rva is not None else 0x1040,
                     names_rva if names_rva is not None else 0x1060,
                     ords_rva if ords_rva is not None else 0x1080)
    struct.pack_into("<II", data, 0x440, 0x2000, 0x1120)           # [1] is a forwarder
    struct.pack_into("<II", data, 0x460, 0x10A0, 0x10B0)
    struct.pack_into("<HH", data, 0x480, 0, 1)
    data[0x4A0:0x4A6] = b"alpha\0"
    data[0x4B0:0x4B5] = b"beta\0"
    data[0x500:0x508] = b"my.dll\0\0"
    data[0x520:0x530] = b"OTHER.Function\0\0"
    return bytes(data)


def test_synthetic_export_directory():
    info = pe.parse(_synthetic_dll())
    assert info.exported_symbols == ["alpha", "beta"]
    assert info.exports_count == 2
    assert info.export_dll_name == "my.dll"
    assert info.export_forwarders == {"beta": "OTHER.Function"}


def test_hostile_counts_are_bounded_not_a_hang():
    info = pe.parse(_synthetic_dll(n_names=0xFFFFFFFF, n_funcs=0xFFFFFFFF))
    assert info.ok
    assert info.exports_count < 100000


def test_pointers_outside_the_file_do_not_raise():
    info = pe.parse(_synthetic_dll(funcs_rva=0xFFFFFFF0, names_rva=0x7FFFFFFF, ords_rva=0x1))
    assert info.ok
    assert info.exported_symbols == []


def test_random_mutations_never_raise():
    base = bytearray(_synthetic_dll())
    rng = random.Random(1234)
    for _ in range(400):
        d = bytearray(base)
        for _ in range(rng.randint(1, 12)):
            d[rng.randrange(len(d))] = rng.randrange(256)
        pe.parse(bytes(d))                       # never raises
        pe.parse(bytes(d[:rng.randrange(len(d))]))
