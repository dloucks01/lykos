"""Phase 6 — instrumented dangerous-call monitor: capture concrete sink arguments at runtime
(command strings, copy lengths) and turn them into findings without a crash."""
import subprocess

import pytest
from lykos.analyze.debug import monitor
from lykos.analyze.dynamic import sandbox

_VULN = ("#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n"
         "void handle(const char*s){char b[64];strcpy(b,s);"
         "  if(!strcmp(b,\"open\")) system(\"echo unlocked\");}\n"
         "int main(void){char in[256]; if(fgets(in,sizeof in,stdin)) handle(in); return 0;}\n")


@pytest.mark.skipif(not monitor._locate_gdb() or sandbox.host_arch() != "x86-64",
                    reason="needs gdb on x86-64")
def test_monitor_captures_command_and_copy_length(gcc, tmp_path):
    c = tmp_path / "v.c"; c.write_text(_VULN)
    b = tmp_path / "v"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    funcs = ["strcpy", "system", "fgets", "strcmp"]

    # PIN-passing input -> we watch system("echo unlocked") execute
    r = monitor.run_monitor(str(b), funcs, "x86-64", stdin=b"open", timeout=20)
    assert r["ok"]
    execs = [h for h in r["hits"] if h["kind"] == "exec"]
    assert execs and execs[0]["func"] == "system" and "echo unlocked" in execs[0]["cmd"]

    # oversized input -> strcpy copies more than the 64-byte buffer, caller resolved by name
    r2 = monitor.run_monitor(str(b), funcs, "x86-64", stdin=b"A" * 200, timeout=20)
    scpy = [h for h in r2["hits"] if h["func"] == "strcpy" and h.get("caller_name") == "handle"]
    assert scpy and scpy[0]["length"] > 64


def test_monitor_unsupported_arch():
    assert not monitor.supported("mips")
    r = monitor.run_monitor("/bin/true", ["system"], "mips")
    assert r["ok"] is False and "native-arch" in r["note"]


# --- cross-arch (qemu-user gdbstub) ----------------------------------------------------------
import os

from lykos.analyze.debug import elfsyms, monitor_stage, qemu_gdb

_CORPUS = os.path.join(os.path.dirname(__file__), "..", "examples", "re-corpus", "bin")
_AARCH64 = os.path.join(_CORPUS, "vuln_aarch64")


@pytest.mark.skipif(not os.path.exists(_AARCH64) or not sandbox._qemu_for("aarch64")
                    or not qemu_gdb.breakpoints_supported("aarch64"),
                    reason="needs the aarch64 corpus binary and qemu-aarch64")
def test_cross_arch_monitor_captures_system_and_copy():
    info = elfsyms.read(_AARCH64)
    assert info["pie"] and "system" in info["symbols"]
    r = qemu_gdb.monitor_calls(_AARCH64, "aarch64", symbols=info["symbols"], entry=info["entry"],
                               pie=info["pie"], sink_names={"strcpy", "strcat", "system"},
                               argv=["4242"], timeout=30)
    assert r["ok"], r.get("note")
    execs = [h for h in r["hits"] if h["func"] == "system"]
    assert execs and execs[0]["argstrs"][0] == "echo unlocked"
    copies = [h for h in r["hits"] if h["func"] == "strcpy"]
    assert copies and any("4242" in (s or "") for h in copies for s in h["argstrs"])


def test_decode_xarch_maps_hits_to_native_shape():
    raw = [
        {"func": "system", "argints": [0x1000], "argstrs": ["id"]},
        {"func": "strcpy", "argints": [0x2000, 0x3000], "argstrs": ["", "A" * 200]},
        {"func": "sprintf", "argints": [0x4000, 0x5000], "argstrs": ["", "%s%n"]},
    ]
    out = {h["func"]: h for h in monitor_stage._decode_xarch(raw)}
    assert out["system"]["kind"] == "exec" and out["system"]["cmd"] == "id"
    assert out["strcpy"]["kind"] == "copy" and out["strcpy"]["length"] == 200
    assert out["strcpy"]["caller_name"] is None
    assert out["sprintf"]["kind"] == "format" and out["sprintf"]["fmt"] == "%s%n"
