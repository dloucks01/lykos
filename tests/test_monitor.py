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


_ARGV_VULN = ("#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
              "int main(int argc,char**argv){char in[64];\n"
              "  if(argc>1 && !strcmp(argv[1],\"go\")) system(\"echo unlocked\");\n"
              "  if(fgets(in,sizeof in,stdin)){}\n  return 0;}\n")


@pytest.mark.skipif(not monitor._locate_gdb() or sandbox.host_arch() != "x86-64",
                    reason="needs gdb on x86-64")
def test_monitor_delivers_argv_even_with_stdin(gcc, tmp_path):
    """Regression: `set args X` then `run < file` makes gdb reset args to empty, silently
    dropping argv when a stdin file is also supplied. The monitor must still deliver argv."""
    c = tmp_path / "a.c"; c.write_text(_ARGV_VULN)
    b = tmp_path / "a"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    # argv reaches system() AND a stdin file is present at the same time
    r = monitor.run_monitor(str(b), ["system", "fgets"], "x86-64",
                            argv=["go"], stdin=b"A" * 64, timeout=20)
    assert r["ok"], r.get("note")
    execs = [h for h in r["hits"] if h["kind"] == "exec"]
    assert execs and "echo unlocked" in execs[0]["cmd"]


# --- analyst sink_addrs escape hatch (stripped / no-symbol binaries) --------------------------
import shutil

from lykos.analyze.debug import monitor_stage as _mstage


def test_parse_sink_addrs_forms_and_filtering():
    got = _mstage._parse_sink_addrs(
        {"system": "0xc5c", "strcpy": 12880, "printf": "0x10",   # printf: not in CATALOG -> drop
         "strcat": "bogus", "gets": None})                        # unparseable -> dropped
    assert got == {"system": 0xc5c, "strcpy": 12880}


@pytest.mark.skipif(not os.path.exists(_AARCH64) or not sandbox._qemu_for("aarch64")
                    or not qemu_gdb.breakpoints_supported("aarch64")
                    or not (shutil.which("llvm-strip") or shutil.which("aarch64-linux-gnu-strip")),
                    reason="needs the aarch64 corpus binary, qemu-aarch64, and a cross strip")
def test_cross_arch_sink_addrs_on_stripped(tmp_path):
    """The escape hatch: a stripped static-pie aarch64 binary has no .symtab, so name-based sink
    resolution finds nothing; analyst-supplied sink_addrs breakpoint them by address anyway."""
    exe = tmp_path / "stripped"
    exe.write_bytes(open(_AARCH64, "rb").read())
    os.chmod(exe, 0o755)                                  # qemu-user needs the execute bit
    strip = shutil.which("llvm-strip") or shutil.which("aarch64-linux-gnu-strip")
    if subprocess.run([strip, "--strip-all", str(exe)], capture_output=True).returncode:
        pytest.skip("strip failed")
    info = elfsyms.read(exe)
    if info["symbols"]:
        pytest.skip("symbols survived strip")            # need a truly symbol-less binary
    # addresses recovered from the (named) twin -- the analyst-in-the-loop input
    twin = elfsyms.read(_AARCH64)["symbols"]
    sink_addrs = {n: twin[n] for n in ("system", "strcpy", "strcat") if n in twin}
    assert sink_addrs, "twin lacks the expected sinks"
    r = qemu_gdb.monitor_calls(str(exe), "aarch64", symbols=sink_addrs, entry=info["entry"],
                               pie=info["pie"], sink_names=set(sink_addrs), argv=["4242"],
                               timeout=30)
    assert r["ok"], r.get("note")
    execs = [h for h in r["hits"] if h["func"] == "system"]
    assert execs and execs[0]["argstrs"][0] == "echo unlocked"


_ADDR_C = ("#include <stdlib.h>\n"
           "void run_cmd(const char*c){ volatile const char*x=c; (void)x; }\n"
           "int main(int argc,char**argv){ if(argc>1) run_cmd(argv[1]); return 0; }\n")


@pytest.mark.skipif(not monitor._locate_gdb() or sandbox.host_arch() != "x86-64"
                    or not shutil.which("nm"),
                    reason="needs gdb + nm on x86-64")
def test_native_addr_sinks_breakpoints_by_address(gcc, tmp_path):
    """Native path: addr_sinks breakpoints a sink by address (stripped: no symbol to name).
    We point the 'system' spec at a local function whose arg0 is a string and confirm the
    address breakpoint fires and decodes arg0 as the command."""
    c = tmp_path / "d.c"; c.write_text(_ADDR_C)
    b = tmp_path / "d"
    if subprocess.run([gcc, "-O0", "-no-pie", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    nm = subprocess.run(["nm", str(b)], capture_output=True, text=True)
    addr = next((int(line.split()[0], 16) for line in nm.stdout.splitlines()
                 if line.split()[-1] == "run_cmd"), None)
    if addr is None:
        pytest.skip("could not find run_cmd address")
    subprocess.run(["strip", str(b)], capture_output=True)     # prove it works without symbols
    r = monitor.run_monitor(str(b), [], "x86-64", argv=["echo hi"], stdin=b"",
                            addr_sinks={"system": addr}, timeout=20)
    assert r["ok"], r.get("note")
    execs = [h for h in r["hits"] if h["kind"] == "exec"]
    assert execs and execs[0]["cmd"] == "echo hi"
