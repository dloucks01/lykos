"""Phase 6 -- dynamic taint confirmation: feed a marker as input and confirm it reaches a sink."""
import os
import subprocess

import pytest
from lykos.analyze.debug import monitor, qemu_gdb
from lykos.analyze.debug import taint_stage as ts
from lykos.analyze.dynamic import sandbox

_CORPUS = os.path.join(os.path.dirname(__file__), "..", "examples", "re-corpus", "bin")
_AARCH64 = os.path.join(_CORPUS, "vuln_aarch64")

_CMDI = ("#include <stdlib.h>\n#include <string.h>\n"
         "int main(int c,char**v){char cmd[256];if(c>1){strcpy(cmd,v[1]);system(cmd);}return 0;}\n")


def test_marker_is_ascii_and_unique():
    a, b = ts._marker(), ts._marker()
    assert a != b and a.isalnum() and a.startswith("LYKOSTAINT")


@pytest.mark.skipif(not monitor._locate_gdb() or sandbox.host_arch() != "x86-64",
                    reason="needs gdb on x86-64")
def test_native_taint_confirms_input_to_system(gcc, tmp_path):
    """Input flows argv -> strcpy -> system(); the marker fed as argv is observed in BOTH the
    strcpy source and the system() command -> confirmed input->sink flows."""
    c = tmp_path / "c.c"; c.write_text(_CMDI)
    b = tmp_path / "cmdi"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-w", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    marker = ts._marker()
    flows, note = ts._flows_from_native(str(b), ["system", "strcpy", "strcat"], "x86-64",
                                        [marker], b"", marker, 20)
    assert note is None, note
    sinks = {f["sink"] for f in flows}
    assert "system" in sinks and "strcpy" in sinks           # input reaches both


@pytest.mark.skipif(not os.path.exists(_AARCH64) or not sandbox._qemu_for("aarch64")
                    or not qemu_gdb.breakpoints_supported("aarch64"),
                    reason="needs the aarch64 corpus binary and qemu-aarch64")
def test_cross_arch_taint_confirms_copy():
    """The marker argv reaches the string-copy sinks on aarch64 (cross-arch monitor argstrs)."""
    from lykos.analyze.debug import elfsyms
    info = elfsyms.read(_AARCH64)
    funcs = sorted(set(info["symbols"]) & set(monitor.CATALOG))
    marker = ts._marker()

    class _T:
        endianness, bits = "little", 64

    flows, note = ts._flows_from_qemu(_AARCH64, "aarch64", info, funcs, _T(), [marker], b"",
                                      marker, 30)
    assert note is None, note
    assert any(f["sink"] == "strcpy" and marker in f["arg"] for f in flows)


def test_taint_cwe_mapping():
    assert ts._CWE["exec"][0] == "CWE-78" and ts._CWE["format"][0] == "CWE-134"
    assert ts._CWE["copy"][0] == "CWE-120"
    assert ts._kind("system") == "exec" and ts._kind("strcpy") == "copy"
