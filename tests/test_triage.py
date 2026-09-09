"""IT-19/21/22/23 — triage builder: real ELF mitigations, cross-arch detection,
determinism, robustness."""
import struct
import subprocess

import pytest
from lykos.analyze.triage import build_triage, validate
from lykos.hashing import canonical_json, hash_all_file

_C = ("#include <stdio.h>\n#include <string.h>\n"
      "int main(int c,char**v){char b[64];if(c>1)strcpy(b,v[1]);printf(\"%s\",b);return 0;}\n")


def _triage(path):
    return build_triage(path, hash_all_file(path), path.name if hasattr(path, "name") else "f")


@pytest.fixture(scope="module")
def variants(gcc, tmp_path_factory):
    d = tmp_path_factory.mktemp("variants")
    src = d / "m.c"; src.write_text(_C)
    made = {}

    def build(name, args):
        out = d / name
        r = subprocess.run([gcc, str(src), "-o", str(out), *args], capture_output=True)
        if r.returncode == 0:
            made[name] = out

    build("default", ["-O2"])
    build("hardened", ["-O2", "-fstack-protector-all", "-fPIE", "-pie",
                       "-Wl,-z,relro,-z,now"])
    build("weak", ["-O0", "-no-pie", "-fno-stack-protector", "-Wl,-z,norelro"])
    if "default" in made:
        stripped = d / "stripped"
        stripped.write_bytes(made["default"].read_bytes())
        if subprocess.run(["strip", str(stripped)], capture_output=True).returncode == 0:
            made["stripped"] = stripped
    return made


def test_default_x86_64(variants):
    if "default" not in variants:
        pytest.skip("build failed")
    rec = _triage(variants["default"])
    assert rec["file_type"] == "elf"
    assert rec["arch"] == "x86-64" and rec["bits"] == 64 and rec["endianness"] == "little"
    assert rec["entry_point"] and rec["sections"]
    assert any("c" in lib for lib in rec["imports"]["libraries"])  # libc.so.6
    assert rec["linking"] == "dynamic"
    assert validate(rec) == []


def test_hardened_mitigations(variants):
    if "hardened" not in variants:
        pytest.skip("build failed")
    m = _triage(variants["hardened"])["mitigations"]
    assert m["pie"] == "on"
    assert m["relro"] == "on"      # full RELRO (relro + now)
    assert m["canary"] == "on"
    assert m["nx"] == "on"


def test_weak_mitigations(variants):
    if "weak" not in variants:
        pytest.skip("build failed")
    m = _triage(variants["weak"])["mitigations"]
    assert m["pie"] == "off"       # -no-pie => ET_EXEC
    assert m["canary"] == "off"    # -fno-stack-protector
    assert m["relro"] == "off"     # -z norelro


def test_stripped_flag(variants):
    if "stripped" not in variants or "default" not in variants:
        pytest.skip("build failed")
    assert _triage(variants["stripped"])["stripped"] is True
    assert _triage(variants["default"])["stripped"] is False


# --- crafted minimal headers for cross-arch detection (no cross compilers needed) ---
def _elf_header(bits=64, big=False, machine=0xB7, etype=2):
    ei = bytearray(16)
    ei[0:4] = b"\x7fELF"
    ei[4] = 2 if bits == 64 else 1
    ei[5] = 2 if big else 1
    ei[6] = 1
    endc = ">" if big else "<"
    if bits == 64:
        rest = struct.pack(endc + "HHIQQQIHHHHHH",
                           etype, machine, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    else:
        rest = struct.pack(endc + "HHIIIIIHHHHHH",
                           etype, machine, 1, 0, 0, 0, 0, 52, 32, 0, 40, 0, 0)
    return bytes(ei) + rest


@pytest.mark.parametrize("bits,big,machine,arch", [
    (64, False, 0xB7, "aarch64"),
    (32, True, 0x14, "ppc"),
    (32, True, 0x08, "mips"),
    (64, False, 0x3E, "x86-64"),
    (64, True, 0x15, "ppc64"),
])
def test_arch_detection_crafted(tmp_path, bits, big, machine, arch):
    p = tmp_path / "hdr.bin"
    p.write_bytes(_elf_header(bits, big, machine))
    rec = build_triage(p, {"sha256": "x", "size": p.stat().st_size}, "hdr.bin")
    assert rec["file_type"] == "elf"
    assert rec["arch"] == arch
    assert rec["bits"] == bits
    assert rec["endianness"] == ("big" if big else "little")


def test_determinism(variants):
    if "default" not in variants:
        pytest.skip("build failed")
    a = canonical_json(_triage(variants["default"]))
    b = canonical_json(_triage(variants["default"]))
    assert a == b


def test_robustness(tmp_path):
    # zero-byte
    z = tmp_path / "z"; z.write_bytes(b"")
    rz = build_triage(z, {"sha256": "0", "size": 0}, "z")
    assert rz["file_type"] == "raw" and validate(rz) == []
    # truncated ELF (magic only)
    t = tmp_path / "t"; t.write_bytes(b"\x7fELF\x02\x01\x01")
    rt = build_triage(t, {"sha256": "1", "size": 7}, "t")
    assert rt["file_type"] == "elf" and rt["parse_errors"]        # partial, noted
    assert validate(rt) == []                                    # still schema-valid
    # non-executable text
    x = tmp_path / "x.txt"; x.write_text("hello world\n")
    rx = build_triage(x, {"sha256": "2", "size": 12}, "x.txt")
    assert rx["file_type"] in ("other", "raw") and validate(rx) == []


def test_validate_catches_bad(variants):
    if "default" not in variants:
        pytest.skip("build failed")
    rec = _triage(variants["default"])
    rec["mitigations"]["nx"] = "MAYBE"
    assert any("mitigation" in e for e in validate(rec))


def test_cross_check_readelf(variants):
    if "default" not in variants:
        pytest.skip("build failed")
    r = subprocess.run(["readelf", "-h", str(variants["default"])], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("readelf failed")
    out = r.stdout
    rec = _triage(variants["default"])
    assert ("ELF64" in out) == (rec["bits"] == 64)
    assert ("little endian" in out) == (rec["endianness"] == "little")
    assert "X86-64" in out.upper() and rec["arch"] == "x86-64"


# ---------------------------------------------------------- non-binary upload flag (UX)
def test_non_binary_is_flagged_not_denied(tmp_path):
    """A shell script is imported and hashed, but clearly flagged as not analyzable."""
    s = tmp_path / "pdfman"
    s.write_text("#!/bin/bash\nman -Tpdf \"$@\" >/tmp/x; xdg-open /tmp/x\n")
    rec = _triage(s)
    assert rec["file_type"] == "other"
    assert rec["analyzable"] is False
    assert rec["advisory"] and "not a supported executable binary" in rec["advisory"]
    assert "shell script" in rec["detected"].lower()
    assert validate(rec) == []                       # still a valid, complete record
    assert "_data_head" not in rec                   # transient field is stripped


def test_content_classification_variants(tmp_path):
    def det(name, data):
        p = tmp_path / name
        p.write_bytes(data)
        return _triage(p)["detected"]
    assert "Python script" in det("a.py", b"#!/usr/bin/env python3\nprint(1)\n")
    assert "Perl script" in det("a.pl", b"#!/usr/bin/perl\nprint 1;\n")
    assert "ZIP archive" in det("a.zip", b"PK\x03\x04rest")
    assert "text" in det("a.txt", b"just some ascii text here\n" * 4).lower()


def test_elf_is_analyzable(variants):
    if "default" not in variants:
        pytest.skip("no gcc build")
    rec = _triage(variants["default"])
    assert rec["analyzable"] is True and rec["advisory"] is None
