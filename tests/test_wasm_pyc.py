"""WebAssembly (.wasm) and CPython bytecode (.pyc) front-ends: magic detection, a structural parse
that yields the imports/exports/strings the detectors consume, and the triage route that turns each
from unrecognized into an analyzable, precisely-described target. Neither has native machine code, so
both advisories say the exploit ladder does not apply."""
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from lykos.analyze import filetype, pyc, wasm

_WAT2WASM = __import__("shutil").which("wat2wasm")


# ------------------------------------------------------------------- WebAssembly
def test_wasm_detect_and_minimal_header():
    blob = b"\x00asm\x01\x00\x00\x00"                    # bare valid module: magic + version 1
    assert filetype.detect(blob) == "wasm"
    i = wasm.parse(blob)
    assert not i.errors and i.version == 1 and i.arch == "wasm"
    assert i.mitigations["nx"] == "n/a"                  # the sandbox model, not NX


def test_wasm_rejects_non_module():
    assert wasm.parse(b"\x7fELF" + b"\x00" * 8).errors


@pytest.mark.skipif(not _WAT2WASM, reason="needs wat2wasm to assemble a .wasm")
def test_wasm_parse_imports_exports(tmp_path):
    wat = tmp_path / "m.wat"
    wat.write_text(
        '(module\n'
        '  (import "env" "host_log" (func $log (param i32)))\n'
        '  (memory (export "memory") 2 16)\n'
        '  (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add)\n'
        '  (start $w) (func $w i32.const 42 call $log))\n')
    out = tmp_path / "m.wasm"
    if subprocess.run([_WAT2WASM, str(wat), "-o", str(out)], capture_output=True).returncode:
        pytest.skip("wat2wasm failed")
    i = wasm.parse(out.read_bytes())
    assert not i.errors and i.version == 1
    assert "env.host_log" in i.imported_symbols[0] and "env" in i.imports["libraries"]
    assert any(s.startswith("add ") for s in i.exported_symbols)
    assert i.mem_pages == 2 and i.has_start and i.func_count == 2


def test_wasm_triage_route(tmp_path):
    from lykos.analyze import triage
    p = tmp_path / "x.wasm"
    p.write_bytes(b"\x00asm\x01\x00\x00\x00")
    rec = triage.build_triage(p, {"sha256": "0" * 64, "size": 8}, "x.wasm")
    assert rec["file_type"] == "wasm" and rec["analyzable"] is True
    assert rec["arch"] == "wasm" and "WebAssembly analysed" in (rec.get("advisory") or "")


# ------------------------------------------------------------------- CPython .pyc
_SRC = ("import os, subprocess\n"
        "def run(cmd):\n"
        "    return subprocess.check_output(['echo', cmd])\n"
        "SECRET = 'a-unique-literal-xyzzy'\n"
        "os.system('id')\n")


def _compile_pyc(tmp_path) -> Path:
    src = tmp_path / "s.py"
    src.write_text(_SRC)
    out = tmp_path / "s.pyc"
    import py_compile
    py_compile.compile(str(src), cfile=str(out), doraise=True)
    return out


def test_pyc_detect_and_parse(tmp_path):
    p = _compile_pyc(tmp_path)
    data = p.read_bytes()
    assert filetype.detect(data[:64]) == "pyc"
    i = pyc.parse(data)
    assert not i.errors
    assert i.python_version.startswith("3.") and i.magic
    assert set(i.imported_symbols) >= {"os", "subprocess", "run"}          # harvested co_names
    assert any("xyzzy" in s for s in i.strings)                            # harvested literal const


def test_pyc_version_magic_matches_runtime(tmp_path):
    import importlib.util
    i = pyc.parse(_compile_pyc(tmp_path).read_bytes())
    runtime_magic = importlib.util.MAGIC_NUMBER[0] | (importlib.util.MAGIC_NUMBER[1] << 8)
    assert i.magic == runtime_magic
    assert i.python_version.startswith("%d.%d" % sys.version_info[:2]) or "magic" in i.python_version


def test_pyc_rejects_non_pyc():
    assert pyc.parse(b"not a pyc file at all" + b"\x00" * 8).errors


def test_pyc_triage_route(tmp_path):
    from lykos.analyze import triage
    p = _compile_pyc(tmp_path)
    rec = triage.build_triage(p, {"sha256": "0" * 64, "size": p.stat().st_size}, "s.pyc")
    assert rec["file_type"] == "pyc" and rec["analyzable"] is True
    assert rec["arch"] == "cpython-bytecode"
    assert "bytecode analysed" in (rec.get("advisory") or "")
