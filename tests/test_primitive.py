"""Phase 6 (L2) — exploitation-primitive analysis: cyclic offset recovery + instruction-
pointer-control confirmation. The pure logic is unit-tested; the full stage runs live on a
native stack-overflow binary (skipped off x86-64/aarch64 or without a C compiler)."""
import struct
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.analyze.poc import enqueue_primitive
from lykos.analyze.poc import primitive as P
from lykos.db.dao import FindingDAO, PocDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def _build(gcc, tmp_path, src, name, flags):
    c = tmp_path / f"{name}.c"; c.write_text(src)
    b = tmp_path / name
    r = subprocess.run([gcc, "-O0", *flags, str(c), "-o", str(b)],
                       capture_output=True, check=False)
    return b if r.returncode == 0 else None


_VULN = ("#include <unistd.h>\n"
         "void vuln(void){char b[64];read(0,b,400);}\n"
         "int main(void){vuln();return 0;}\n")


# ------------------------------------------------------------------- unit: cyclic
def test_cyclic_unique_windows_and_find():
    seq = P.cyclic(500)
    assert len(seq) == 500
    for off in (0, 4, 72, 111, 400):
        assert P.cyclic_find(seq[off:off + 4], 500) == off
    assert P.cyclic_find(b"zzzz", 500) == -1


def test_cyclic_find_from_register_value():
    seq = P.cyclic(300)
    off = 72
    reg = int.from_bytes(seq[off:off + 8], "little")     # 8 controlled bytes in a register
    assert P.cyclic_find(struct.pack("<I", reg & 0xFFFFFFFF), 300) == off


# ------------------------------------------------------------------- unit: offset recovery
def test_recover_ip_offset_from_pc():
    L = 256
    off = 40
    pc = int.from_bytes(P.cyclic(L)[off:off + 4], "little")
    cap = {"pc": pc, "sp": 0x7000, "stack_base": 0x7000, "stack": ""}
    assert P.recover_ip_offset(cap, L) == (off, "pc")


def test_recover_ip_offset_from_stack_slot():
    """Non-canonical return address: PC reports the faulting ret site, so the offset must come
    from the return-address slot the stack pointer indexes."""
    L = 256
    off = 72
    seq = P.cyclic(L)
    sp = 0x7ffff000
    stack = seq[off:off + 8]                              # [SP] holds the saved return address
    cap = {"pc": 0x401146, "sp": sp, "stack_base": sp, "stack": stack.hex()}
    got = P.recover_ip_offset(cap, L)
    assert got == (off, "stack[sp+0]")


def test_controlled_registers_detects_cyclic():
    L = 256
    seq = P.cyclic(L)
    rbx = int.from_bytes(seq[16:24], "little")
    cap = {"pc": 0, "sp": 0, "stack_base": 0, "stack": "",
           "regs": {"rbx": rbx, "eflags": 0x202, "rax": 0}}
    ctl = P.controlled_registers(cap, L)
    assert ctl.get("rbx") == 16 and "eflags" not in ctl


# ------------------------------------------------------------------- unit: confirm
def test_control_input_and_marker_confirmed():
    inp = P.control_input(72, 256)
    assert inp[72:80] == struct.pack("<Q", P.MARKER) and len(inp) == 256
    assert P.marker_confirmed({"pc": P.MARKER, "sp": 0, "stack_base": 0, "stack": ""})
    # or the sentinel visible in the stack slot
    cap = {"pc": 0x401146, "sp": 0x7000, "stack_base": 0x7000,
           "stack": struct.pack("<Q", P.MARKER).hex()}
    assert P.marker_confirmed(cap)
    assert not P.marker_confirmed({"pc": 0x1234, "sp": 0, "stack_base": 0, "stack": ""})


def test_marker_confirmed_ignores_sentinel_deep_in_the_stack():
    """The overflow payload CONTAINS the sentinel and lands on the stack; a WRONG offset guess
    leaves it somewhere in the copied buffer, NOT at the return-address slot. Confirming on that
    would be a false instruction-pointer-control claim -- so only the slot SP indexes counts."""
    sp = 0x7000
    deep = bytearray(128)
    deep[64:72] = struct.pack("<Q", P.MARKER)          # sentinel deep in the window, not the RA slot
    assert not P.marker_confirmed(
        {"pc": 0xdead, "regs": {}, "sp": sp, "stack_base": sp, "stack": bytes(deep).hex()})
    at_slot = bytearray(128)
    at_slot[0:8] = struct.pack("<Q", P.MARKER)         # sentinel at the slot SP indexes -> confirms
    assert P.marker_confirmed(
        {"pc": 0xdead, "regs": {}, "sp": sp, "stack_base": sp, "stack": bytes(at_slot).hex()})


# ------------------------------------------------------------------- integration
@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=120, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_primitive_cross_arch_reports_unsupported(store, case, pool, gcc, tmp_path,
                                                  monkeypatch):
    monkeypatch.setattr(sandbox, "host_arch", lambda: "x86-64")
    c = tmp_path / "v.c"; c.write_text(_VULN)
    b = tmp_path / "v"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True,
                      check=False).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    # force a non-host arch on the target row
    store.conn.execute("UPDATE target SET arch='ppc64' WHERE id=?", (target.id,))
    store.conn.commit()
    sha, _, _ = store.content.put_bytes(b"A" * 120)
    q = JobQueue(store.conn)
    run = enqueue_primitive(q, store.targets.get(target.id),
                            params={"input_sha": sha, "input_mode": "stdin"})
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"
    assert not PocDAO(store.conn).list_by_target(target.id)   # no L2 for cross-arch


@pytest.mark.skipif(sandbox.host_arch() not in ("x86-64", "aarch64"),
                    reason="L2 primitive analysis is native-arch only")
def test_primitive_confirms_ip_control_end_to_end(store, case, pool, gcc, tmp_path):
    c = tmp_path / "v.c"; c.write_text(_VULN)
    b = tmp_path / "v"
    # no PIE + no stack canary -> a clean saved-return-address overwrite
    r = subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", str(c), "-o", str(b)],
                       capture_output=True, check=False)
    if r.returncode:
        pytest.skip("build failed (no-pie/no-canary unsupported)")
    target = ingest(store, case.id, b)
    sha, _, _ = store.content.put_bytes(b"A" * 120)          # a crashing input
    q = JobQueue(store.conn)
    run = enqueue_primitive(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                               "timeout": 6})
    assert pool.wait_idle(60)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("ptrace unavailable in this environment: " + str(rec.error))
    l2 = [p for p in PocDAO(store.conn).list_by_target(target.id) if p.level == "L2"]
    if not l2:
        pytest.skip("no IP control captured (hardened toolchain default?)")
    assert l2[0].verified
    backed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.state == "poc-backed"]
    assert backed
    assert any("instruction-pointer control" in str(e.get("detail", ""))
               for f in backed for e in (f.evidence or []))


# ------------------------------------------------------------------- unit: memory primitives
def test_parse_mem_access_and_reg64():
    assert P.parse_mem_access("mov QWORD PTR [rdx],rax") == {
        "is_write": True, "base": "rdx", "value": "rax"}
    assert P.parse_mem_access("mov eax,DWORD PTR [rcx]") == {
        "is_write": False, "base": "rcx", "value": None}
    assert P.parse_mem_access("mov DWORD PTR [rax+0x10],edx")["base"] == "rax"
    assert P.parse_mem_access("ret") is None
    assert P._reg64("edx") == "rdx" and P._reg64("r10d") == "r10"


def test_analyze_write_what_where():
    L = 64
    seq = P.cyclic(L)
    addr = int.from_bytes(seq[0:8], "little")
    val = int.from_bytes(seq[8:16], "little")
    cap = {"fault_addr": 0, "regs": {"rdx": addr, "rax": val}}
    prim = P.analyze_memory_primitive(cap, L, "mov QWORD PTR [rdx],rax")
    assert prim["type"] == "write-what-where"
    assert prim["addr_offset"] == 0 and prim["value_offset"] == 8
    assert prim["addr_reg"] == "rdx" and prim["value_reg"] == "rax"


def test_analyze_controlled_read():
    L = 64
    addr = int.from_bytes(P.cyclic(L)[0:8], "little")
    cap = {"fault_addr": 0, "regs": {"rax": addr}}
    prim = P.analyze_memory_primitive(cap, L, "mov eax,DWORD PTR [rax]")
    assert prim["type"] == "controlled-read" and prim["addr_offset"] == 0
    assert prim["value_offset"] is None


def test_two_marker_input_and_confirm():
    import struct
    inp = P.two_marker_input(0, 8, 64)
    assert inp[0:8] == struct.pack("<Q", P.MARKER)
    assert inp[8:16] == struct.pack("<Q", P.MARKER_VALUE)
    cap = {"regs": {"rdx": P.MARKER, "rax": P.MARKER_VALUE}}
    prim = {"addr_reg": "rdx", "value_reg": "rax", "value_offset": 8}
    assert P.memory_primitive_confirmed(cap, prim) == (True, True)
    bad = {"regs": {"rdx": 0x1234, "rax": 0}}
    assert P.memory_primitive_confirmed(bad, prim) == (False, False)


# ------------------------------------------------------------------- integration: WWW / read
_WWW = ("#include <unistd.h>\n"
        "int main(void){ unsigned long a[2]={0,0}; read(0,(char*)a,16);"
        " *(unsigned long*)a[0]=a[1]; return 0; }\n")
_CREAD = ("#include <unistd.h>\n"
          "int main(void){ unsigned long a=0; read(0,(char*)&a,8);"
          " volatile int x=*(int*)a; return x; }\n")


def _l2_run(store, case, pool, gcc, tmp_path, src, name, crashing_input):
    b = _build(gcc, tmp_path, src, name, ["-fno-stack-protector", "-no-pie"])
    if b is None:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    sha, _, _ = store.content.put_bytes(crashing_input)
    q = JobQueue(store.conn)
    run = enqueue_primitive(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                               "timeout": 6})
    assert pool.wait_idle(50)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("ptrace unavailable: " + str(rec.error))
    from lykos.db.dao import PocDAO
    return (FindingDAO(store.conn).list_by_target(target.id),
            PocDAO(store.conn).list_by_target(target.id))


@pytest.mark.skipif(sandbox.host_arch() not in ("x86-64", "aarch64"),
                    reason="L2 primitive analysis is native-arch only")
def test_write_what_where_end_to_end(store, case, pool, gcc, tmp_path):
    finds, pocs = _l2_run(store, case, pool, gcc, tmp_path, _WWW, "www", b"A" * 16)
    l2 = [p for p in pocs if p.level == "L2"]
    if not l2:
        pytest.skip("no WWW primitive captured on this toolchain")
    assert l2[0].verified
    assert any("write-what-where" in str(e.get("detail", ""))
               for f in finds if f.state == "poc-backed" for e in (f.evidence or []))


@pytest.mark.skipif(sandbox.host_arch() not in ("x86-64", "aarch64"),
                    reason="L2 primitive analysis is native-arch only")
def test_controlled_read_end_to_end(store, case, pool, gcc, tmp_path):
    finds, pocs = _l2_run(store, case, pool, gcc, tmp_path, _CREAD, "cr", b"A" * 8)
    l2 = [p for p in pocs if p.level == "L2"]
    if not l2:
        pytest.skip("no controlled-read primitive captured on this toolchain")
    assert l2[0].verified
    assert any("controlled-read" in str(e.get("detail", ""))
               for f in finds if f.state == "poc-backed" for e in (f.evidence or []))


def test_frame_offset_candidates_predicts_ip_offset_from_ghidra_coords():
    """Static stack-frame -> predicted IP-control offset = ret_offset - buffer_offset
    (Ghidra frame coords; ret_offset 0, locals negative). Matches the dynamic cyclic offset
    for a real overflow (handle(): char[128] at -136, ret_offset 0 -> 136)."""
    frames = {
        "0x1287": {"ret_offset": 0, "vars": [
            {"name": "buf", "offset": -136, "size": 128, "is_buffer": True},
            {"name": "i", "offset": -8, "size": 4, "is_buffer": False}]},
        "0x1248": {"ret_offset": 0, "vars": [
            {"name": "msg", "offset": -72, "size": 64, "is_buffer": True}]},
    }
    cands = P.frame_offset_candidates(frames, 8)
    offs = [c["offset"] for c in cands]
    assert 136 in offs and 72 in offs           # the two buffers' return-address distances
    top = next(c for c in cands if c["offset"] == 136)
    assert top["buffer"] == "buf" and top["size"] == 128
    # sorted smallest-first, non-buffer locals ignored
    assert offs == sorted(offs)
    # fallback when ret_offset is unavailable: |offset| + word
    fb = P.frame_offset_candidates({"0x1": {"vars": [
        {"name": "b", "offset": -40, "size": 32, "is_buffer": True}]}}, 8)
    assert fb[0]["offset"] == 48


def test_match_frame_candidate_tolerates_saved_frame_pointer():
    """aarch64/FP-pair ABIs put the return address one word past the buffer distance that
    Ghidra reports; the match allows that saved-frame-pointer slack."""
    cands = [{"offset": 128, "buffer": "acStack_80", "size": 128, "function_addr": "0x8e4"},
             {"offset": 64, "buffer": "local_40", "size": 64, "function_addr": "0x8a0"}]
    # exact match (x86-64-style)
    c, slack = P.match_frame_candidate(64, cands, 8)
    assert c["buffer"] == "local_40" and slack == 0
    # +word match (aarch64: 128 + saved FP = 136)
    c, slack = P.match_frame_candidate(136, cands, 8)
    assert c["buffer"] == "acStack_80" and slack == 8
    # no match
    assert P.match_frame_candidate(999, cands, 8) == (None, 0)
    # seed_offsets enumerates dist and dist+word, smallest first, deduped
    seeds = [o for o, _c, _s in P.seed_offsets(cands, 8, cap=4096)]
    assert 64 in seeds and 72 in seeds and 128 in seeds and 136 in seeds
    assert seeds == sorted(seeds)


def test_word_aware_ip_sentinel_for_32bit():
    """32-bit targets truncate the 48-bit marker, so IP control uses a 4-byte sentinel."""
    inp = P.control_input(132, 300, word=4)
    assert inp[132:136] == struct.pack("<I", P.MARKER32) and len(inp) == 300
    assert P.marker_confirmed({"pc": P.MARKER32, "stack": "", "stack_base": 0, "sp": 0}, word=4)
    assert not P.marker_confirmed({"pc": P.MARKER, "stack": "", "stack_base": 0, "sp": 0}, word=4)
    # 64-bit path unchanged
    assert P.control_input(72, 256)[72:80] == struct.pack("<Q", P.MARKER)


def test_match_frame_candidate_slack_both_directions():
    """The return-address slot sits within a word of the frame base either way: aarch64 +word,
    mips -word."""
    cands = [{"offset": 136, "buffer": "acStack_88", "size": 128, "function_addr": "0x1"}]
    assert P.match_frame_candidate(136, cands, 4)[1] == 0      # exact
    assert P.match_frame_candidate(140, cands, 4)[1] == 4      # +word (aarch64-like)
    assert P.match_frame_candidate(132, cands, 4)[1] == -4     # -word (mips)
    assert P.match_frame_candidate(200, cands, 4) == (None, 0)
    seeds = [o for o, _c, _s in P.seed_offsets(cands, 4, cap=4096)]
    assert {132, 136, 140}.issubset(set(seeds))


def test_match_frame_candidate_prefers_largest_overflow_target():
    """With ±word slack and several buffers, the big buffer is the plausible overflow source
    even when a small local matches exactly (a 12-byte local doesn't take a 200-byte overflow)."""
    cands = [{"offset": 132, "buffer": "small", "size": 12, "function_addr": "0x1"},
             {"offset": 136, "buffer": "big", "size": 128, "function_addr": "0x2"}]
    # offset 132 is exact for small but -4 from big; the larger buffer still wins
    c, slack = P.match_frame_candidate(132, cands, 4)
    assert c["buffer"] == "big" and slack == -4
    # only the small buffer is within a word -> it is chosen
    c, slack = P.match_frame_candidate(130, cands, 4)
    assert c["buffer"] == "small"


def test_offset_recovery_is_endianness_aware():
    """A big-endian target loads input bytes into a register MSB-first, so the offset search
    and marker placement must use target byte order (regression: was little-endian only)."""
    length = 512
    # emulate a BE 32-bit crash: input bytes at offset 132 become the PC as a big-endian word
    off = 132
    pat = P.cyclic(length)
    window = pat[off:off + 4]
    pc_be = int.from_bytes(window, "big")            # how a BE CPU loads those 4 bytes
    cap = {"pc": pc_be, "stack": "", "stack_base": 0, "sp": 0}
    assert P.recover_ip_offset(cap, length, endian="big", word=4) == (off, "pc")
    # little-endian read of the same value would not be found
    assert P.recover_ip_offset(cap, length, endian="little", word=4) is None
    # control_input places the sentinel in target order so the BE CPU reconstructs it
    be = P.control_input(off, 300, word=4, endian="big")
    assert be[off:off + 4] == P.MARKER32.to_bytes(4, "big")
    assert int.from_bytes(be[off:off + 4], "big") == P.MARKER32
    # and marker_confirmed compares the PC as an integer (order-independent once parsed)
    assert P.marker_confirmed({"pc": P.MARKER32, "stack": "", "stack_base": 0, "sp": 0},
                              word=4, endian="big")


def test_ip_control_via_link_register_and_masked_pc():
    """PPC/ARM link-register ABIs: the controlled return address is in LR, and the fetched PC
    is LR with low bits masked by aligned fetch, so recovery/confirm must use the RA register."""
    L = 512
    off = 156
    lr = int.from_bytes(P.cyclic(L)[off:off + 4], "big")     # BE PPC lr = input at offset 156
    masked_pc = lr & ~0b11                                    # PPC clears low 2 bits on fetch
    cap = {"pc": masked_pc, "sp": 0x40000000, "stack_base": 0, "stack": "",
           "regs": {"lr": lr, "r1": 0x40000000}}
    # pc search misses (masked), but the lr register yields the exact offset
    assert P.recover_ip_offset(cap, L, endian="big", word=4) == (off, "lr")
    # confirmation: lr == marker, and an alignment-masked pc also counts
    assert P.marker_confirmed({"regs": {"lr": P.MARKER32}, "stack": "", "stack_base": 0,
                               "sp": 0}, word=4, endian="big")
    assert P.marker_confirmed({"pc": P.MARKER32 & ~0b11, "regs": {}, "stack": "",
                               "stack_base": 0, "sp": 0}, word=4, endian="big")


def test_lsb_masked_pc_covers_riscv_as_well_as_arm():
    """ISAs whose indirect branch clears bit 0 of the loaded PC need their cyclic window
    searched at `(pc | 1)`, or a fault with FULL instruction-pointer control reads as
    unconfirmed.

    ARM/AArch64 mask it to select Thumb vs ARM state; RISC-V's JALR is specified to clear the
    low bit of the computed target. The list originally covered only the ARM family, so RISC-V
    captured pc=0x4141414141414140 from an all-'A' overflow -- unmistakable IP control -- and
    still reported L1 instead of L2.
    """
    from lykos.analyze.poc.primitive_stage import _LSB_MASKED_PC
    assert {"arm", "aarch64", "riscv", "riscv64"} <= set(_LSB_MASKED_PC)
    # ISAs that do NOT mask must stay out, or a genuine off-by-one alias gets accepted
    assert not ({"x86-64", "x86", "ppc64", "s390", "m68k"} & set(_LSB_MASKED_PC))


def test_return_address_registers_are_per_isa_not_a_shared_guess():
    """r14 is the LINK register on s390 and ARM but an ordinary callee-saved register on
    PowerPC and MIPS. A single shared list either misses s390 (which is what happened: it
    recovered a nonsense offset and never reached L2) or attributes instruction-pointer
    control to a PowerPC register that merely happens to hold cyclic bytes.
    """
    from lykos.analyze.poc import primitive
    assert primitive.ra_regs({"arch": "s390"}) == ("r14",)
    assert "r14" not in primitive.ra_regs({"arch": "ppc"})
    assert "r14" not in primitive.ra_regs({"arch": "mips"})
    assert primitive.ra_regs({"arch": "ppc"}) == ("lr",)
    assert primitive.ra_regs({"arch": "aarch64"}) == ("x30",)
    assert primitive.ra_regs({"arch": "sh"}) == ("pr",)
    assert primitive.ra_regs({"arch": "riscv"}) == ("x1", "ra")   # the layout names ra as x1
    assert primitive.ra_regs({"arch": "m68k"}) == ()              # return address on the stack
    # an unknown / absent arch falls back to the generic list rather than losing all of them
    assert primitive.ra_regs({}) == primitive._RA_REGS


def test_overflow_frame_isolates_the_filler_run():
    """The L2 probe must put its cyclic where the overflow FILLER was and keep the structure
    around it (a config `name=<AAAA...>` only crashes as a `name=` line). An input with no long
    run is unstructured and framed as a whole (b"", b"")."""
    from lykos.analyze.poc.primitive_stage import _overflow_frame
    pre, post = _overflow_frame(b"name=" + b"A" * 300 + b"\n")
    assert pre == b"name=" and post == b"\n"        # prefix/suffix kept, filler isolated
    pre, post = _overflow_frame(b"A" * 300)          # whole input is the run -> identity framing
    assert pre == b"" and post == b""
    pre, post = _overflow_frame(b"abcdefghij")       # no significant run -> unstructured
    assert pre == b"" and post == b""
    # framing + a cyclic reproduces the structured shape
    from lykos.analyze.poc import primitive
    pre, post = _overflow_frame(b"key=" + b"B" * 200)
    framed = pre + primitive.cyclic(64) + post
    assert framed.startswith(b"key=") and b"aaaa" in framed


# ------------------------------------------------- the shape a real binary actually presents
# A header-gated parser with an unvalidated index, no `win()`, and a READ: the three properties
# that together made every real-corpus finding in this project stop at L1.
#
#  * the header gate means a cyclic pattern never reaches the defect -- `aaaabaaac...` is not a
#    valid container, so the De Bruijn experiment reports "did not fault" and the chain ended;
#  * a read has no saved return address to control, so the IP-control question has no answer;
#  * one observation cannot distinguish "the attacker chooses the address" from "a wild pointer
#    happened to land at 0" -- busybox's lzcat crash was filed CWE-476 denial-of-service for
#    exactly that reason, on an input whose address landed in the first page.
_INDEXED_READ = (
    "#include <stdio.h>\n#include <stdlib.h>\n"
    "int main(void){\n"
    "  unsigned char *p = malloc(32);\n"
    "  unsigned char hdr[8];\n"
    "  if (fread(hdr, 1, 8, stdin) != 8) return 0;\n"
    "  if (hdr[0] != 'L' || hdr[1] != 'Z') return 0;       /* a container header */\n"
    "  size_t idx = (size_t)hdr[4] * 0x100000;             /* unvalidated index */\n"
    "  printf(\"%02x\\n\", p[idx]);                          /* OOB read, address = f(input) */\n"
    "  return 0; }\n")


@pytest.mark.skipif(sandbox.host_arch() not in ("x86-64", "aarch64"),
                    reason="L2 primitive analysis is native-arch only")
def test_an_indexed_read_is_an_address_primitive_not_a_dos(store, case, pool, gcc, tmp_path):
    """The seam this closes: a crash whose ADDRESS the input chooses is an L2 primitive, and the
    evidence for it is already in every capture (`fault_addr`, from ptrace's siginfo)."""
    b = _build(gcc, tmp_path, _INDEXED_READ, "idx", ["-w"])
    if b is None:
        pytest.skip("build failed")
    crash = b"LZ\x00\x00\x40\x00\x00\x00"                  # header + index byte 0x40
    r = sandbox.run(str(b), stdin=crash, timeout=10)
    if not r.crashed:
        pytest.skip("the fixture does not fault on this host's memory layout")

    target = ingest(store, case.id, b)
    sha, _, _ = store.content.put_bytes(crash)
    q = JobQueue(store.conn)
    run = enqueue_primitive(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                               "timeout": 8})
    assert pool.wait_idle(180) and q.runs.get(run.id).status == "done"

    pocs = PocDAO(store.conn).list_by_target(target.id)
    assert pocs, "no PoC recorded for an input whose faulting address the attacker chooses"
    assert pocs[-1].level == "L2", f"expected L2, got {pocs[-1].level}"
    assert pocs[-1].verified

    from lykos.db.dao import EventDAO
    done = EventDAO(store.conn).payloads_of_type("primitive.done", case_id=case.id)
    assert (done[-1] or {}).get("primitive") == "address-control", done[-1]
    prim = (done[-1] or {}).get("address") or {}
    assert prim.get("controlled") and prim.get("access") == "read"
    # the index byte IS the header's index field, and the stride is the element size the
    # program multiplies it by -- both read off the live target, not assumed
    assert prim.get("offset") == 4, prim
    assert prim.get("stride") == 0x100000, prim


def test_address_primitive_separates_control_from_a_wild_pointer():
    """The pure verdict, which is where the honesty lives."""
    def cap(addr, pc=0x401136):
        return {"ok": True, "signal_name": "SIGSEGV", "fault_addr": addr, "pc": pc}

    # an index: one byte scales the address
    obs = [("orig", cap(0x41000)), ("orig", cap(0x41000))] + [
        (f"byte@4=0x{v:02x}", cap(0x1000 + v * 0x100000)) for v in (0x00, 0x40, 0x80, 0xff)]
    v = P.address_primitive(obs, disasm="movzx eax,BYTE PTR [rax+rdx*1]")
    assert v["controlled"] and v["confirmed"] and v["max_level"] == 2
    assert v["offset"] == 4 and v["stride"] == 0x100000
    assert v["access"] == "read" and v["cwe"] == "CWE-125"

    # a FIXED address is a denial of service, and saying so is the point
    fixed = P.address_primitive([(f"byte@2=0x{v:02x}", cap(0)) for v in (1, 2, 3)])
    assert not fixed["controlled"] and fixed["max_level"] == 1
    assert fixed["effect_kind"] == "denial-of-service" and "null/near-null" in fixed["note"]

    # a write is the stronger claim, and it is labelled as one
    w = P.address_primitive(obs, disasm="mov BYTE PTR [rax+rdx*1],cl", is_write=True)
    assert w["access"] == "write" and w["cwe"] == "CWE-787"
    assert w["effect_kind"] == "arbitrary-write"

    # Faults in two different ROUTINES are two defects, not one primitive.
    assert P.address_primitive([("a", cap(1, pc=0x401000)), ("b", cap(2, pc=0x502000)),
                                ("c", cap(3, pc=0x603000))]) is None
    # ...but several instructions of ONE routine are one defect. glibc's memcpy faults at
    # whichever instruction of its unrolled loop runs off the end, so the PC moves with the
    # alignment while the defect does not: measured on the address-leak fixture, 8 of 13
    # variants faulted with 2 distinct addresses and an exact-PC rule discarded all of it.
    unrolled = [("orig", cap(0x7fff1000, pc=0x401120)),
                ("byte@6=0xff", cap(0x7fff2000, pc=0x401135)),
                ("byte@7=0xff", cap(0x7fff2000, pc=0x401140))]
    u = P.address_primitive(unrolled, disasm="rep movsb")
    assert u and u["controlled"] and u["max_level"] == 2
    assert len(u["faulting_pcs"]) == 3 and "one routine" in u["note"]
    # an address that moves between runs of the SAME input is not input-controlled
    nd = P.address_primitive([("orig", cap(0x1000)), ("orig", cap(0x9000)),
                              ("byte@1=0xff", cap(0x5000))])
    assert not nd["controlled"] and nd["effect_kind"] == "nondeterministic"
    # too few observations: no claim either way
    assert P.address_primitive([("orig", cap(1)), ("byte@0=0xff", cap(2))]) is None


# ------------------------------------------------------- L2 -> L3: steering the controlled read
# An address the attacker chooses is only a step toward an exploit if the bytes come back. The
# input that MEASURED the control crashes -- that is how the address was measured -- so there is
# nothing on stdout to resolve. The verdict names the lever, though, so turning it down lands the
# same read inside a mapped page: the program survives and prints what it read.
_LEAKY_INDEX = (
    "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
    "int main(void){\n"
    "  unsigned char *p = malloc(64); memset(p, 'A', 64);\n"
    "  void **q = malloc(64);\n"
    "  q[0] = (void*)&main; q[1] = (void*)&puts; q[2] = (void*)p;\n"
    "  unsigned char hdr[16];\n"
    "  if (fread(hdr, 1, 8, stdin) != 8) return 0;\n"
    "  if (memcmp(hdr, \"LZMA\", 4) != 0) { puts(\"bad magic\"); return 1; }\n"
    "  size_t idx = (size_t)hdr[5] * 0x10000;          /* unvalidated index */\n"
    "  fwrite(p + idx, 1, 128, stdout);                 /* OOB read: address = f(input) */\n"
    "  return 0; }\n")


@pytest.mark.skipif(sandbox.host_arch() not in ("x86-64", "aarch64"),
                    reason="L2 primitive analysis is native-arch only")
def test_a_steered_read_discloses_a_base_and_hands_the_recipe_to_l3(store, case, pool, gcc,
                                                                    tmp_path):
    """The bridge: controlled address -> steer into mapped memory -> resolve a leaked pointer.

    What crosses to L3 is the provoking INPUT, never the base -- the base belongs to a process
    that has already exited and is worthless to a later one under ASLR.
    """
    b = _build(gcc, tmp_path, _LEAKY_INDEX, "leakidx", ["-w"])
    if b is None:
        pytest.skip("build failed")
    crash = b"LZMA\x00\x05\x00\x00"                     # index 5 -> far out of bounds, faults
    if not sandbox.run(str(b), stdin=crash, timeout=10).crashed:
        pytest.skip("the fixture does not fault on this host's memory layout")

    target = ingest(store, case.id, b)
    sha, _, _ = store.content.put_bytes(crash)
    q = JobQueue(store.conn)
    run = enqueue_primitive(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                               "timeout": 8})
    assert pool.wait_idle(240) and q.runs.get(run.id).status == "done"

    from lykos.db.dao import EventDAO
    ev = EventDAO(store.conn)
    done = ev.payloads_of_type("primitive.done", case_id=case.id)
    assert (done[-1] or {}).get("primitive") == "address-control", done[-1]

    disc = ev.payloads_of_type("primitive.disclosure", case_id=case.id)
    assert disc, "the steering experiment never reported"
    d = disc[-1]
    assert d.get("proved"), d
    assert d.get("pie_base"), "a code pointer was on stdout and no PIE base came back"
    assert d.get("input_sha"), "L3 inherits the INPUT; without it the recipe cannot be replayed"
    assert d.get("steered_byte") == 5, d
    # and the L2 payload carries the disclosure, which is what _l2_disclosure_triggers reads
    assert (done[-1] or {}).get("disclosure", {}).get("input_sha") == d["input_sha"]


def test_a_masked_pc_does_not_outrank_the_register_that_holds_the_real_target():
    """Measured on alpha, and it cost an L2.

    The fetch unit clears the low two bits of a branch target, so the captured pc is `ra & ~3`.
    That one changed byte made the pc's 4-byte window match the cyclic sequence FOUR BYTES
    EARLY -- an exact match at a wrong offset. The pc search therefore did not miss (which is
    the case the link-register branch below it was written for), the register was never
    consulted, and the sentinel placed at the recovered offset landed nowhere:

        cyclic(600), archgate's own fixture, qemu-alpha gdbstub
          pc = 0x6161617661616174 -> 76   (wrong)
          ra = 0x6161617661616175 -> 80   (right, and the sentinel at 80 lands in ra)
    """
    cap = {"pc": 0x6161617661616174, "arch": "alpha",
           "regs": {"pc": 0x6161617661616174, "ra": 0x6161617661616175}}
    assert P.recover_ip_offset(cap, 600) == (80, "ra")

    # An ISA with no return-address register is untouched: the pc is the only source there.
    assert P.recover_ip_offset({"pc": 0x6161617661616174, "arch": "x86-64",
                                "regs": {}}, 600) == (76, "pc")
    # And where the pc is NOT a masked copy of the register, the pc still wins -- the register
    # may simply hold stale cyclic bytes from an earlier frame.
    unrelated = {"pc": 0x6161617661616174, "arch": "aarch64",
                 "regs": {"x30": 0x6262626262626262}}
    assert P.recover_ip_offset(unrelated, 600) == (76, "pc")


# --------------------------------------------- a framing that keeps a LENGTH field honest
def test_a_preserved_length_field_follows_the_payload():
    """Structure-preserving framing has to preserve what the structure MEANS. The prefix of a
    menu-driven write is `2\\n0\\n512\\n` -- option, index, and the number of bytes the target is
    about to `read()` -- so splicing a 1,064-byte cyclic in behind a field that still says 512
    leaves 552 bytes of pattern in the pipe: the target reads its 512, the next operation reads
    pattern garbage instead of the option that DETONATES the write, and the stage reported
    "cyclic pattern did not fault" on a target whose crash it had been handed."""
    from lykos.analyze.poc.primitive_stage import _overflow_frame, filler_run_len, relength_prefix
    orig = b"1\n0\n1\n1\n2\n0\n512\n" + b"B" * 512 + b"3\n0\n"
    pre, post = _overflow_frame(orig)
    assert (pre, post) == (b"1\n0\n1\n1\n2\n0\n512\n", b"3\n0\n")
    assert filler_run_len(orig) == 512
    assert relength_prefix(pre, 512, 1064) == b"1\n0\n1\n1\n2\n0\n1064\n"


def test_a_number_that_is_not_a_length_is_left_alone():
    """The field rewritten is the one that GOVERNS the copy, which is what "at least as large as
    the filler it precedes" means. An index or an id is smaller than the payload it indexes."""
    from lykos.analyze.poc.primitive_stage import relength_prefix
    assert relength_prefix(b"4\n0\n", 512, 1064) == b"4\n0\n"          # an index
    assert relength_prefix(b"name=", 512, 64) == b"name="             # no number at all
    assert relength_prefix(b"", 512, 64) == b""
    assert relength_prefix(b"2\n0\n512\n", 0, 64) == b"2\n0\n512\n"   # no filler run to govern


def test_the_length_field_is_rewritten_in_every_separator_shape():
    """A length is not always newline-terminated: `size=512&` and `512 ` occur too."""
    from lykos.analyze.poc.primitive_stage import relength_prefix
    assert relength_prefix(b"size=512 ", 512, 64) == b"size=64 "
    assert relength_prefix(b"len:512", 512, 64) == b"len:64"


# ------------------------------------- control through a hijacked FUNCTION POINTER
#
# A smashed return address puts the attacker's bytes in the program counter. A hijacked function
# pointer does not: on x86-64 a call through a register holding a non-canonical address raises
# #GP, and the kernel reports SIGSEGV with the pc AT THE CALL. Measured on a heap notebook whose
# overflow reaches the object's own callback:
#
#     pc  = 0x401489           -> cyclic_find = -1   (the call site, inside the program)
#     rdx = 0x6161616261616161 -> cyclic_find = 32   (the pattern, at the pointer's offset)
#     disasm = `call   rdx`
#
# so the recovery answered None and the ladder stopped at a reproduced crash on a target whose
# control was complete.
def test_an_indirect_branch_names_its_register():
    from lykos.analyze.poc.primitive import indirect_branch_reg as ibr
    regs = {"rdx": 1, "rax": 1, "x8": 1, "t1": 1, "r3": 1}
    assert ibr("call   rdx", regs) == "rdx"
    assert ibr("callq  *%rdx", regs) == "rdx"           # AT&T syntax
    assert ibr("jmp    rax", regs) == "rax"
    assert ibr("blr x8", regs) == "x8"                  # aarch64
    assert ibr("jalr   t1", regs) == "t1"               # riscv
    assert ibr("blx r3", regs) == "r3"                  # arm


def test_a_direct_call_and_a_memory_operand_name_no_register():
    """A direct `call 0x401136` names no register and must not match, or any crash at a call
    reads as control. `call qword ptr [rax+0x30]` takes its target from MEMORY the register
    points at -- a controlled pointer read and then branched through, which is a different and
    weaker claim; the sentinel refuses it anyway (the confirming run faults reading
    `MARKER+0x30` and never arrives at MARKER)."""
    from lykos.analyze.poc.primitive import indirect_branch_reg as ibr
    assert ibr("call   0x401136", {"rdx": 1}) == ""
    assert ibr("call   qword ptr [rax + 0x30]", {"rax": 1}) == ""
    assert ibr("ret", {}) == ""
    assert ibr("", {}) == ""


def test_the_offset_comes_from_the_branch_register_when_the_pc_is_the_call_site():
    from lykos.analyze.poc import primitive as P
    pat = P.cyclic(256)
    word = P._reg_window  # noqa: F841 - documents where the window helper lives
    target = int.from_bytes(bytes(pat[32:40]), "little")
    cap = {"pc": 0x401489, "sp": 0x7fff0000, "regs": {"rdx": target, "rax": 0x404040},
           "stack": "", "stack_base": 0x7fff0000}
    assert P.recover_ip_offset(cap, 256) is None, "the premise: nothing without the instruction"
    assert P.recover_ip_offset(cap, 256, disasm="call   rdx") == (32, "reg:rdx")


def test_a_controlled_register_alone_is_not_control():
    """Attacker bytes land in registers all the time -- a copy loop leaves them in rdx. Only the
    instruction that BRANCHES through one makes it control."""
    from lykos.analyze.poc import primitive as P
    pat = P.cyclic(256)
    cap = {"pc": 0x401489, "sp": 0x7fff0000,
           "regs": {"rdx": int.from_bytes(bytes(pat[32:40]), "little")},
           "stack": "", "stack_base": 0x7fff0000}
    assert P.recover_ip_offset(cap, 256, disasm="mov    qword [rax], rdx") is None


def test_ppc_names_its_branch_register_in_the_mnemonic():
    """PPC branches through a SPECIAL register the mnemonic names rather than an operand:
    `bctrl` is "call the address in CTR"."""
    from lykos.analyze.poc.primitive import indirect_branch_reg as ibr
    assert ibr("bctrl", {"ctr": 1}) == "ctr"
    assert ibr("bctr", {"ctr": 1}) == "ctr"
    assert ibr("bctrl", {"rdx": 1}) == "", "not a register this capture has"
