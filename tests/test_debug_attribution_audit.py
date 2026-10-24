"""Crash attribution precision (analyze/debug): signal mapping, read-vs-write per ISA, decoding
never guessed as x86, honest "direction unknown", deliberate traps, 32-bit controlled pointers."""
import shutil
import subprocess

import pytest
from lykos.analyze.debug import exploitability, qemu_gdb, rootcause

_MAP = [{"start": 0x401000, "end": 0x402000, "perms": "r-xp", "path": "/tmp/t"}]


def _cap(**kw):
    base = {"ok": True, "signal_name": "SIGSEGV", "pc": 0x401146, "fault_addr": 0x7fff0000,
            "maps": _MAP, "pc_bytes": "", "backtrace": [], "regs": {}}
    base.update(kw)
    return base


# ------------------------------------------------------------- gdbstub signal numbering
def test_gdb_signal_10_is_sigbus_and_7_is_not():
    assert qemu_gdb._SIGNALS[10] == "SIGBUS"
    assert 7 not in qemu_gdb._SIGNALS            # GDB_SIGNAL_EMT, not SIGBUS


def test_rsp_unescape():
    assert qemu_gdb._rsp_unescape("a}\x03b") == b"a#b"


# ------------------------------------------------------------- x86 read vs write
@pytest.mark.parametrize("ins,kind", [
    ("mov QWORD PTR [rbx],rcx", "write"),
    ("mov eax,DWORD PTR [rax]", "read"),
    ("cmp BYTE PTR [rax],0x0", "read"),
    ("test DWORD PTR [rdi],eax", "read"),
    ("call QWORD PTR [rax+0x8]", "read"),
    ("push QWORD PTR [rax]", "read"),
    ("fld QWORD PTR [rax]", "read"),
    ("fstp QWORD PTR [rax]", "write"),
    ("inc DWORD PTR [rax]", "write"),
    ("rep stos QWORD PTR es:[rdi],rax", "write"),
    ("repz cmps BYTE PTR ds:[rsi],BYTE PTR es:[rdi]", "read"),
    ("lods al,BYTE PTR ds:[rsi]", "read"),
    ("xchg rax,QWORD PTR [rbx]", "write"),
    ("lock xadd DWORD PTR [rax],edx", "write"),
    ("push rbp", "write"),
    ("mov eax,ebx", None),
])
def test_x86_access_kind(ins, kind):
    assert rootcause._access_kind(ins, "x86-64") == kind


@pytest.mark.parametrize("ins,arch,kind", [
    ("str w1, [x0]", "aarch64", "write"),
    ("stp x29, x30, [sp, #-16]!", "aarch64", "write"),
    ("ldrb w0, [x0]", "aarch64", "read"),
    ("ldadd w1, w2, [x0]", "aarch64", "write"),
    ("str r2, [r3, #0]", "arm", "write"),
    ("ldr r0, [r1]", "arm", "read"),
    ("sw v0,0(a0)", "mips", "write"),
    ("lw v0,0(a0)", "mips", "read"),
    ("sd a1,0(a0)", "riscv", "write"),
    ("ld a1,0(a0)", "riscv", "read"),
    ("stw r0,8(r1)", "ppc", "write"),
    ("lwz r0,8(r1)", "ppc", "read"),
    ("mov.w r2,@r2", "sh", "write"),
    ("mov.l @r1,r2", "sh", "read"),
])
def test_risc_access_kind(ins, arch, kind):
    assert rootcause._access_kind(ins, arch) == kind


def test_arch_less_aarch64_store_is_a_write():
    # primitive_stage calls _is_memory_write(disasm) without an arch
    assert rootcause._is_memory_write("str w1, [x0]")


# ------------------------------------------------------------- classify honesty
def test_unknown_direction_is_not_filed_as_a_read():
    v = rootcause.classify(_cap(), None)
    assert v["class"] == "invalid-memory-access" and v["cwe"] == "CWE-119"
    r = exploitability.rate(_cap(), v)
    assert r["rating"] == "UNKNOWN"
    kinds = {e["kind"]: e["status"] for e in r["effects"]}
    assert kinds.get("memory-corruption") == "potential"


def test_cross_arch_store_is_a_write():
    v = rootcause.classify(_cap(arch="aarch64", maps=[], fault_addr=0x1234560), "str w1, [x0]")
    assert v["class"] == "out-of-bounds-write" and v["cwe"] == "CWE-787"


def test_null_with_unknown_direction_is_still_null_deref():
    v = rootcause.classify(_cap(fault_addr=8), None)
    assert v["class"] == "null-pointer-dereference" and "access" in v["detail"]


def test_ud2_is_a_reachable_assertion_not_exploitable_illegal_instruction():
    v = rootcause.classify(_cap(signal_name="SIGILL"), "ud2")
    assert v["class"] == "reachable-assertion" and v["cwe"] == "CWE-617"
    assert exploitability.rate(_cap(signal_name="SIGILL"), v)["rating"] == "UNKNOWN"
    # a genuinely illegal opcode keeps the old verdict
    v2 = rootcause.classify(_cap(signal_name="SIGILL"), "(bad)")
    assert v2["class"] == "illegal-instruction"


def test_sigtrap_is_a_trap_not_an_oob_read():
    v = rootcause.classify(_cap(signal_name="SIGTRAP", maps=[], fault_addr=None), None)
    assert v["class"] == "reachable-assertion"


def test_stub_capture_instruction_fetch_fault_is_a_hijack():
    v = rootcause.classify(_cap(maps=[], pc=0x41414140, fault_addr=0x41414140), None)
    assert v["class"] == "control-flow-hijack"
    v0 = rootcause.classify(_cap(maps=[], pc=0, fault_addr=0), None)
    assert v0["class"] == "null-pointer-dereference"


def test_analyze_uses_stub_decoded_insn():
    cap = _cap(arch="aarch64", maps=[], fault_addr=0x1234560, insn="str w1, [x0]")
    rep = rootcause.analyze(cap, [], [], [], "/tmp/t", "aarch64")
    assert rep["classification"]["class"] == "out-of-bounds-write"


# ------------------------------------------------------------- decoding
@pytest.mark.skipif(not shutil.which("objdump"), reason="objdump absent")
def test_unknown_arch_is_never_decoded_as_x86():
    assert rootcause.disasm_one(b"\xc3", "xtensa") is None
    assert rootcause.disasm_one(b"\xc3", "") is None


@pytest.mark.skipif(not shutil.which("objdump"), reason="objdump absent")
def test_risc_decode_keeps_operands():
    d = rootcause.disasm_one(bytes.fromhex("010000b9"), "aarch64")
    if d is None:
        pytest.skip("objdump cannot decode aarch64 here")
    assert d == "str w1, [x0]"


# ------------------------------------------------------------- controlled pointers
def test_32bit_cyclic_pointer_is_controlled():
    assert exploitability._looks_controlled(0x41414141)
    assert exploitability._looks_controlled(0x6161616261616161)
    assert not exploitability._looks_controlled(0x0804c060)
    assert not exploitability._looks_controlled(0x7ffff7dd1000)
    assert not exploitability._looks_controlled(-1)


# ------------------------------------------------------------- live qemu (cross-arch)
def _a64(tmp_path, src):
    cc = shutil.which("aarch64-linux-gnu-gcc")
    if not cc or not shutil.which("qemu-aarch64"):
        pytest.skip("no aarch64 cross toolchain / qemu")
    c = tmp_path / "t.c"
    c.write_text(src)
    out = tmp_path / "t"
    if subprocess.run([cc, "-static", "-O0", str(c), "-o", str(out)],
                      capture_output=True, timeout=120).returncode:
        pytest.skip("cross compile failed")
    return out


def test_live_aarch64_wild_store(tmp_path):
    exe = _a64(tmp_path, "int main(){volatile int*p=(int*)0x1234560;*p=5;return 0;}\n")
    cap = qemu_gdb.capture(exe, "aarch64", timeout=20)
    if not cap.get("ok"):
        pytest.skip(f"qemu capture unavailable: {cap.get('note')}")
    if cap.get("fault_addr") is None:
        pytest.skip("this qemu serves no siginfo")
    assert cap["fault_addr"] == 0x1234560
    rep = rootcause.analyze(cap, [], [], [], str(exe), "aarch64")
    assert rep["classification"]["class"] == "out-of-bounds-write"


def test_live_aarch64_sigbus_is_captured(tmp_path):
    exe = _a64(tmp_path, "#include <signal.h>\nint main(){raise(SIGBUS);return 0;}\n")
    cap = qemu_gdb.capture(exe, "aarch64", timeout=20)
    if not cap.get("ok"):
        pytest.skip(f"qemu capture unavailable: {cap.get('note')}")
    assert cap["signal_name"] == "SIGBUS"
    assert cap.get("fault_addr") is None          # raise(): si_code <= 0, no address


# ------------------------------------------------------------- symbolization
class _F:
    def __init__(self, addr, name, size=0x100):
        self.addr, self.name, self.size = addr, name, size


def test_frame_in_another_module_is_not_named_after_a_target_function():
    ranges = rootcause._fn_ranges([_F("0x100000", "parse")])
    maps = [{"start": 0x100000, "end": 0x101000, "perms": "r-xp", "path": "/usr/lib/libc.so.6"}]
    e = rootcause.symbolize(0x100010, maps, ranges, "/tmp/target")
    assert e["symbol"] is None
    own = [{"start": 0x100000, "end": 0x101000, "perms": "r-xp", "path": "/tmp/target (deleted)"}]
    assert rootcause.symbolize(0x100010, own, ranges, "/tmp/target")["symbol"] == "parse"
    assert rootcause.symbolize(0x100010, [], ranges, "/tmp/target")["symbol"] == "parse"


# ------------------------------------------------------------- gdb backend parsing
def test_gdb_parse_rejects_non_crash_signal():
    from lykos.analyze.debug import gdb as g
    out = "Program received signal SIGPIPE, Broken pipe.\nLYKOS_PC 0x401000\n"
    assert g._parse(out)["ok"] is False


def test_gdb_parse_drops_si_addr_of_a_user_sent_signal():
    from lykos.analyze.debug import gdb as g
    out = ("Program received signal SIGSEGV, Segmentation fault.\nLYKOS_PC 0x7ffff7ca61ac\n"
           "$1 = {si_signo = 11, si_errno = 0, si_code = -6, _sifields = {_sigfault = "
           "{si_addr = 0x3e80000000c}}}\n")
    cap = g._parse(out)
    assert cap["ok"] and cap["fault_addr"] is None
    real = out.replace("si_code = -6", "si_code = 1")
    assert g._parse(real)["fault_addr"] == 0x3e80000000c


def test_gdb_script_passes_benign_signals():
    from lykos.analyze.debug import gdb as g
    assert any(c.startswith("handle ") and "SIGPIPE" in c for c in g._capture_cmds(None))


# ------------------------------------------------------------- sanitizer re-run is contained
def test_sanitizer_report_runs_inside_the_sandbox(tmp_path):
    import importlib
    from types import SimpleNamespace
    from lykos.analyze.dynamic import sandbox
    stage = importlib.import_module("lykos.analyze.debug.stage")
    cc = shutil.which("gcc") or shutil.which("clang")
    if not cc:
        pytest.skip("no compiler")
    src = tmp_path / "a.c"
    # writes a marker into $HOME-relative cwd if it can, then overflows the heap
    src.write_text('#include <stdlib.h>\n#include <string.h>\n#include <stdio.h>\n'
                   'int main(int c,char**v){FILE*f=fopen("' + str(tmp_path / "escaped")
                   + '","w");if(f)fclose(f);char*p=malloc(8);memset(p,1,32);return p[3];}\n')
    exe = tmp_path / "a"
    if subprocess.run([cc, "-g", "-fsanitize=address", str(src), "-o", str(exe)],
                      capture_output=True, timeout=120).returncode:
        pytest.skip("cannot build an ASan binary here")
    tgt = SimpleNamespace(arch=sandbox.host_arch(), file_type="elf")
    out = stage._sanitizer_report(exe, "stdin", [], b"", tmp_path, 20, tgt)
    assert "AddressSanitizer" in out
    if sandbox.isolate_prefix(str(tmp_path), net=False):
        assert not (tmp_path / "escaped").exists()     # exe dir is bound read-only


# ------------------------------------------------------------- gdb result markers can't be forged
def test_target_output_cannot_forge_monitor_results(tmp_path):
    from lykos.analyze.debug import monitor
    if not shutil.which("gdb") or not shutil.which("gcc"):
        pytest.skip("gdb/gcc absent")
    src = tmp_path / "f.c"
    src.write_text('#include <stdio.h>\n#include <string.h>\nint main(int c,char**v){'
                   'char b[8];strcpy(b,"ok");'
                   'printf("LYKOS_STATUS {\\"ran\\": true, \\"error\\": \\"\\"}\\n");'
                   'printf("LYKOS_MON [{\\"fn\\": \\"system\\", \\"forged\\": 1}]\\n");'
                   'printf("LYKOS_MON {garbage\\n");fflush(stdout);return b[0]==0;}\n')
    exe = tmp_path / "f"
    if subprocess.run(["gcc", "-O0", "-fno-builtin", str(src), "-o", str(exe)],
                      capture_output=True, timeout=120).returncode:
        pytest.skip("cannot build")
    from lykos.analyze.dynamic import sandbox
    res = monitor.run_monitor(exe, ["strcpy"], sandbox.host_arch(), timeout=20)
    assert res.get("ok"), res
    assert not any(h.get("forged") for h in res["hits"])
