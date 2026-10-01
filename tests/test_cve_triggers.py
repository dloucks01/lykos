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
