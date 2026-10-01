"""Per-CVE weaponization triggers + detonation (CVE->exploit, tier 3).

The trigger must be a well-formed input that exercises the specific CVE, and the detonation path
must record a reproduction ONLY on a real fault. (That the zlib trigger drives real zlib 1.2.11
to an ASan abort at inflate.c:764 is verified out-of-band; here we check the payload shape and
that the detonation machinery reports a crash when the target actually faults.)
"""
from __future__ import annotations

import shutil
import struct
import subprocess

import pytest

from lykos.analyze.poc import cve_poc_stage, cve_triggers

_HAS_CC = shutil.which("gcc") or shutil.which("cc")


def test_zlib_trigger_is_a_gzip_with_an_oversized_extra_field():
    t = cve_triggers.for_cve("CVE-2022-37434")
    assert t is not None and t.cve == "CVE-2022-37434"
    assert t.data[:3] == b"\x1f\x8b\x08"            # gzip magic + deflate method
    assert t.data[3] & 0x04                          # FEXTRA flag set
    xlen = struct.unpack_from("<H", t.data, 10)[0]   # XLEN right after the 10-byte base header
    assert xlen >= 0x1000                            # far larger than any sane extra_max
    assert "zlib" in t.libraries and t.cwe == "CWE-787"


def test_unknown_cve_has_no_trigger():
    assert cve_triggers.for_cve("CVE-1999-0001") is None
    assert "CVE-2022-37434" in cve_triggers.available()


@pytest.mark.skipif(not _HAS_CC, reason="no C compiler")
def test_detonation_reports_a_crash_when_the_target_faults(tmp_path):
    """A target that overflows on the trigger bytes must come back as a crashed RunResult; a
    benign target must not."""
    cc = shutil.which("gcc") or shutil.which("cc")
    vuln = tmp_path / "vuln.c"
    vuln.write_text("#include <unistd.h>\nint main(){char b[16];int n=read(0,b,4096);"
                    "return b[n%16];}\n")
    vexe = tmp_path / "vuln"
    subprocess.run([cc, "-O0", "-fno-stack-protector", str(vuln), "-o", str(vexe)], check=True)
    benign = tmp_path / "benign.c"
    benign.write_text("#include <unistd.h>\nint main(){char b[65536];"
                      "while(read(0,b,sizeof b)>0); return 0;}\n")
    bexe = tmp_path / "benign"
    subprocess.run([cc, "-O0", str(benign), "-o", str(bexe)], check=True)

    trig = cve_triggers.for_cve("CVE-2022-37434")
    assert cve_poc_stage._detonate(str(vexe), trig, "x86-64") is not None   # faults
    assert cve_poc_stage._detonate(str(bexe), trig, "x86-64") is None       # safe


def test_class_triggers_cover_the_main_weaponizable_cwes():
    assert cve_triggers.class_triggers("CWE-787"), "overflow class has no triggers"
    assert cve_triggers.class_triggers("CWE-134"), "format-string class has no triggers"
    assert cve_triggers.class_triggers("CWE-78"), "command-injection class has no triggers"
    assert cve_triggers.class_triggers("CWE-9999") == []     # unknown class -> nothing
    # overflow class escalates length and spans channels
    ov = cve_triggers.class_triggers("CWE-787")
    assert {t.channel for t in ov} >= {"stdin", "file", "arg"}
    assert max(len(t.data) for t in ov) >= 16384


def test_library_triggers_map_zlib_and_xml_to_dos_payloads():
    zt = cve_triggers.library_triggers("zlib")
    assert zt and zt[0].cwe == "CWE-409"                 # decompression bomb
    import zlib
    # decompress up to 512 MiB; the bomb expands ~1000:1, so it fills the cap from a few MB in.
    expanded = zlib.decompressobj(15 + 16).decompress(zt[0].data, 512 << 20)
    assert len(expanded) > 32 * len(zt[0].data)          # expands far beyond its own size
    xt = cve_triggers.library_triggers("expat")
    assert xt and xt[0].cwe == "CWE-776"                 # billion laughs
    assert xt[0].data.count(b"<!ENTITY") >= 5            # nested entities present
    assert cve_triggers.library_triggers("not-a-lib") == []


def test_dos_trigger_counts_a_timeout_as_a_fault():
    from lykos.analyze.poc import cve_poc_stage

    class _R:
        crashed = False
        timed_out = True
    bomb = cve_triggers.library_triggers("zlib")[0]
    overflow = cve_triggers.class_triggers("CWE-787")[0]
    assert cve_poc_stage._fault(bomb, _R()) is True       # DoS: timeout is the fault
    assert cve_poc_stage._fault(overflow, _R()) is False  # non-DoS: a timeout is not a crash


@pytest.mark.skipif(not _HAS_CC, reason="no C compiler")
def test_generic_overflow_class_trigger_faults_a_vulnerable_target(tmp_path):
    cc = shutil.which("gcc") or shutil.which("cc")
    src = tmp_path / "v.c"
    # realistic overflow: read a bounded amount, strcpy into a small buffer in a function that
    # RETURNS (so the smashed return address is used). The generic 256B+ cyclic payload overflows.
    src.write_text("#include <unistd.h>\n#include <string.h>\n"
                   "static void vuln(char*in){char b[32]; strcpy(b,in);}\n"
                   "int main(){char line[2048]; int n=read(0,line,sizeof line-1);"
                   "line[n>0?n-1:0]=0; vuln(line); return 0;}\n")
    exe = tmp_path / "v"
    subprocess.run([cc, "-O0", "-fno-stack-protector", str(src), "-o", str(exe)], check=True)
    # at least one overflow-class stdin trigger must fault it
    faulted = any(cve_poc_stage._detonate(str(exe), t, "x86-64") is not None
                  for t in cve_triggers.class_triggers("CWE-787") if t.channel == "stdin")
    assert faulted
