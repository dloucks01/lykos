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
