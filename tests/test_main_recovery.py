"""Recovering `main` on aarch64 by decoding the _start / __libc_start_main idiom (doc 04).

On aarch64, main is passed to __libc_start_main only as a data pointer in x0 -- never called --
so a static/stripped target gets no named function there. elf.main_from_start decodes _start
(adrp+add for static, adrp+ldr + R_AARCH64_RELATIVE for PIE, following a __wrap_main trampoline)
to recover it, independently of any external tool. Validated against the symbol table's `main`."""
from __future__ import annotations

import re
import shutil
import subprocess

import pytest
from lykos.analyze.elf import main_from_start

_SRC = (
    "#include <stdio.h>\n"
    "int main(void){ unsigned long s; if(scanf(\"%lu\",&s)!=1) return 1;\n"
    "  puts(((s ^ 0x1337UL) + 0x1000UL) == 0xDEADBEEFUL ? \"ok\" : \"no\"); return 0; }\n"
)


def _cross():
    cc = shutil.which("aarch64-linux-gnu-gcc")
    if not cc:
        pytest.skip("no aarch64-linux-gnu-gcc")
    nm = shutil.which("aarch64-linux-gnu-nm") or shutil.which("nm")
    if not nm:
        pytest.skip("no nm to read the ground-truth main")
    return cc, nm


def _build_and_main(tmp_path, cc, nm, *flags):
    src = tmp_path / "cm.c"
    src.write_text(_SRC)
    exe = tmp_path / ("cm" + "".join(flags).replace("-", ""))
    if subprocess.run([cc, "-O2", *flags, str(src), "-o", str(exe)],
                      capture_output=True).returncode != 0:
        pytest.skip("aarch64 build failed")
    out = subprocess.run([nm, str(exe)], capture_output=True, text=True).stdout
    m = re.search(r"^([0-9a-fA-F]+)\s+[Tt]\s+main$", out, re.M)
    if not m:
        pytest.skip("could not read main from the symbol table")
    return exe.read_bytes(), int(m.group(1), 16)


@pytest.mark.parametrize("flags", [("-static",), (), ("-static-pie",)],
                         ids=["static", "dynamic-pie", "static-pie"])
def test_recovers_main_matches_symbol(tmp_path, flags):
    cc, nm = _cross()
    data, real_main = _build_and_main(tmp_path, cc, nm, *flags)
    assert main_from_start(data) == real_main


def test_none_on_non_aarch64(tmp_path):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("no gcc")
    src = tmp_path / "x.c"
    src.write_text("int main(void){return 0;}\n")
    exe = tmp_path / "x"
    if subprocess.run([gcc, str(src), "-o", str(exe)], capture_output=True).returncode != 0:
        pytest.skip("gcc build failed")
    # x86-64 (or any non-aarch64 host) is not handled -> None, never a wrong guess
    from lykos.analyze.elf import parse
    if parse(exe.read_bytes()).arch == "aarch64":
        pytest.skip("host is aarch64")
    assert main_from_start(exe.read_bytes()) is None


def test_never_raises_on_garbage():
    assert main_from_start(b"") is None
    assert main_from_start(b"\x7fELF" + b"\x00" * 8) is None
    assert main_from_start(b"not an elf at all") is None
    assert main_from_start(b"\x7fELF\x02\x01" + b"\xff" * 200) is None
