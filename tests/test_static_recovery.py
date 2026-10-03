"""Static-pipeline recovery for architectures the structural backend (Kali's rizin) handles poorly:
RISC-V 64, which rizin has NO disassembler plugin for (it silently decodes RISC-V as x86 garbage) --
recovered instead by SLEIGH/pypcode, which owns the function bodies, P-Code and call edges; and
s390x, which rizin disassembles correctly but leaves its xref DB empty -- call edges harvested from
the instruction stream. Unit tests pin the pure helpers; E2E tests build a fixture and assert the
call graph and disassembly are now real."""
import shutil
import subprocess

import pytest
from lykos.analyze import native_re

_RV_GCC = shutil.which("riscv64-linux-gnu-gcc")
_S390_GCC = shutil.which("s390x-linux-gnu-gcc")
_RIZIN = shutil.which("rizin") or shutil.which("r2") or shutil.which("radare2")
try:
    import pypcode  # noqa: F401
    _HAS_PYPCODE = True
except Exception:
    _HAS_PYPCODE = False

_SRC = ('#include <stdlib.h>\n#include <unistd.h>\n'
        'void never(int c,char**v){ if(c>99){ char*s="/bin/sh"; system(s); } }\n'
        'long sink(long x){ volatile long v=x; return v*2654435761UL+1; }\n'
        'void vuln(long s){ char b[64]; long a=sink(s),x=sink(s^1); read(0,b,512); sink(a); sink(x); }\n'
        'int main(int c,char**v){ never(c,v); vuln(c); write(1,"ok\\n",3); return 0; }\n')


def test_calls_from_ops_harvests_when_xref_db_empty():
    """When callrefs/afxj come back empty, call edges are recovered from the disassembly ops: an op
    whose type is a call variant, target from `jump` or the resolved `sym.`/`fcn.` token."""
    fn_by_addr = {0x2000: {"name": "read"}}
    ops = [
        {"offset": 0x1000, "type": "mov", "disasm": "lghi %r2, 0"},
        {"offset": 0x1004, "type": "call", "jump": 0x2000, "disasm": "brasl %r14, sym.read"},
        {"offset": 0x1008, "type": "call", "disasm": "brasl %r14, sym.imp.puts"},   # no numeric jump
    ]
    calls = native_re._calls_from_ops(ops, fn_by_addr)
    assert len(calls) == 2
    assert calls[0]["dst_name"] == "read" and calls[0]["dst_addr"] == "0x2000"
    assert calls[1]["dst_name"] == "puts"            # resolved from the sym.imp. token in the text


def test_ram_target_parses_pcode_call():
    assert native_re._ram_target("CALL ram:0x16cca:8") == 0x16cca
    assert native_re._ram_target("CALLIND register:0x20:8") is None     # indirect: no ram target
    assert native_re._ram_target("CALL const:0x0:4") is None


def _build(tmp_path, gcc, extra=()):
    src = tmp_path / "v.c"
    src.write_text(_SRC)
    exe = tmp_path / "v"
    if subprocess.run([gcc, "-O1", "-static", "-fno-stack-protector", "-no-pie", "-w",
                       *extra, str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build fixture")
    return exe


@pytest.mark.skipif(not (_RV_GCC and _RIZIN and _HAS_PYPCODE),
                    reason="needs riscv64-linux-gnu-gcc + rizin + pypcode")
def test_riscv64_recovered_via_sleigh(tmp_path):
    exe = _build(tmp_path, _RV_GCC, extra=["-march=rv64g", "-mabi=lp64d"])
    r = native_re.analyze(exe, timeout=240)
    assert (r["program"]["arch"] or "").startswith("riscv")
    assert r["program"]["language"] == "RISCV:LE:64:default"
    funcs = r["functions"]
    # call edges and P-Code must both be real now (rizin alone gave ~0 of each, as x86 garbage)
    edges = sum(len(fn.get("calls", [])) for fn in funcs)
    pcode = sum(1 for fn in funcs for b in fn["cfg"]["blocks"] for i in b["instructions"] if i["pcode"])
    assert edges > 100 and pcode > 500
    vuln = next((fn for fn in funcs if fn["name"] == "vuln"), None)
    assert vuln, "vuln not recovered"
    texts = [i["text"] for b in vuln["cfg"]["blocks"] for i in b["instructions"]]
    assert any("sp" in t and "addi" in t for t in texts)        # a real RISC-V prologue, not x86
    assert any(t.startswith("jal") for t in texts)              # the overflow read() call site
    main = next((fn for fn in funcs if fn["name"] == "main"), None)
    assert main and any(c.get("dst_name") == "vuln" for c in main["calls"])   # main -> vuln edge


@pytest.mark.skipif(not (_S390_GCC and _RIZIN), reason="needs s390x-linux-gnu-gcc + rizin")
def test_s390_call_edges_recovered(tmp_path):
    exe = _build(tmp_path, _S390_GCC)
    r = native_re.analyze(exe, timeout=240)
    funcs = r["functions"]
    edges = sum(len(fn.get("calls", [])) for fn in funcs)
    assert edges > 100, "s390 call edges not recovered from the instruction stream"
    vuln = next((fn for fn in funcs if fn["name"] == "vuln"), None)
    assert vuln and any((c.get("dst_name") or "").endswith("read") for c in vuln["calls"])
