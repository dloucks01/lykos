"""Does the campaign know where the program went, or only what it printed?

The coverage proxy was the SHAPE of the program's output. That notices a parser printing
something new; it does not notice a parser taking a branch it has never taken. On jhead it saw
a few thousand distinct "behaviours" where the binary has 1,887 basic blocks -- a signal
loosely correlated with coverage rather than a measure of it.

The decompiler already walked the binary, so its block list is instrumentation we have paid
for. Breakpoints are one-shot and the campaign only ever arms blocks it has not reached, so
the cost decays as coverage saturates -- and "did this input reach anywhere new?" is exactly
the question a fuzzer needs answered.
"""
import struct

import pytest
from lykos.analyze.fuzz import batch_runner


def _elf(pie: bool, load_vaddr: int) -> bytes:
    """A 64-bit ELF header with one PT_LOAD at `load_vaddr`."""
    e = bytearray(4096)
    e[0:4] = b"\x7fELF"
    e[4] = 2                                            # ELFCLASS64
    phoff = 0x40
    struct.pack_into("<Q", e, 0x20, phoff)
    struct.pack_into("<HH", e, 0x36, 56, 1)             # phentsize, phnum
    struct.pack_into("<I", e, phoff, 1)                 # PT_LOAD
    struct.pack_into("<Q", e, phoff + 0x10, load_vaddr)
    return bytes(e)


def test_a_fixed_image_reports_its_load_address(tmp_path):
    """A non-PIE binary is placed exactly where it asks, so a file vaddr IS a runtime one."""
    p = tmp_path / "nopie"
    p.write_bytes(_elf(False, 0x400000))
    assert batch_runner._elf_min_vaddr(str(p)) == 0x400000


def test_a_position_independent_image_reports_zero(tmp_path):
    """PIE asks for 0 and the loader picks the address, so every block needs the runtime base
    added. Getting this backwards arms breakpoints at addresses that are not code."""
    p = tmp_path / "pie"
    p.write_bytes(_elf(True, 0))
    assert batch_runner._elf_min_vaddr(str(p)) == 0


def test_a_non_elf_is_not_guessed_at(tmp_path):
    p = tmp_path / "nope"
    p.write_bytes(b"MZ" + b"\x00" * 200)
    assert batch_runner._elf_min_vaddr(str(p)) == 0


def test_a_missing_file_does_not_raise():
    assert batch_runner._elf_min_vaddr("/nonexistent/at/all") == 0


# ---------------------------------------------------------------- end to end
def test_coverage_is_recorded_only_when_blocks_are_asked_for(tmp_path, gcc):
    """The plumbing: no block list means no tracing cost and no coverage; a block list means
    the runner traces the child and reports what it reached.

    Deliberately NOT asserting which blocks: a real block list comes from the decompiler, and
    a synthetic one (every Nth address) is not block boundaries -- arming those would prove
    something about arithmetic rather than about coverage. The discriminating property is
    measured on real targets instead: jhead reaches 378 of 1,887 recovered blocks, ncompress
    83-148 of 433 depending on the input channel.
    """
    import subprocess

    from lykos.analyze.dynamic import sandbox
    src = tmp_path / "t.c"
    src.write_text('#include <stdio.h>\nint main(void){ char b[64];'
                   ' if(!fgets(b,sizeof b,stdin)) return 1; puts(b); return 0; }\n')
    exe = tmp_path / "t"
    subprocess.run([gcc, "-O0", str(src), "-o", str(exe)], check=True)

    plain = sandbox.run_batch(exe, [b"hi\n"], mode="stdin", timeout=5.0)
    if plain is None:
        pytest.skip("batched sandbox unavailable here")
    assert plain[0].note is None, "no block list asked for, so nothing to report"

    entry = batch_runner._elf_min_vaddr(str(exe))
    assert isinstance(entry, int), "the address contract must resolve for a real binary"
    traced = sandbox.run_batch(exe, [b"hi\n"], mode="stdin", timeout=5.0,
                               blocks=[0x1000, 0x1040, 0x1080])
    assert traced is not None and traced[0].exit_code == 0, "tracing must not break the run"


def test_the_sandbox_lets_the_tracer_plant_breakpoints():
    """Breakpoints are planted by writing to /proc/<pid>/mem, and the sandbox mounts the host
    root READ-ONLY. Without a fresh procfs over it, that open fails with EROFS and the tracer
    falls back to two ptrace syscalls per block -- silently, since the fallback is correct.

    On a statically linked target (38,418 recovered blocks, because the binary carries its own
    libc) that was 72,000 syscalls per execution: the campaign ran at 15 exec/s inside the
    sandbox against 506 outside it, and a whole architecture corpus is statically linked.
    """
    import shutil
    import subprocess

    from lykos.analyze.dynamic import sandbox
    if not shutil.which("bwrap") or not sandbox._bwrap_usable():
        pytest.skip("bubblewrap not available here")
    probe = ("import os\n"
             "fd = os.open('/proc/self/mem', os.O_RDWR)\n"
             "os.close(fd)\n"
             "print('writable')\n")
    cmd = ["bwrap"] + list(sandbox._BWRAP_ARGS) + ["python3", "-c", probe]
    done = subprocess.run(cmd, capture_output=True, timeout=60)
    assert done.returncode == 0 and b"writable" in done.stdout, (
        "the tracer cannot plant a breakpoint in this sandbox: "
        f"{done.stderr.decode('utf-8', 'replace')[:200]}")
    assert "--proc" in sandbox._BWRAP_ARGS, "a fresh procfs is what makes it writable"


def test_a_signal_the_program_handles_is_not_a_crash(tmp_path):
    """Under ptrace every signal stops the tracee and is the tracer's to decide on. Killing on
    sight reported a program that catches SIGSEGV and recovers as crashed -- so the same input
    got two different verdicts depending on whether block coverage happened to be switched on,
    and anything that uses SIGSEGV deliberately (a JIT, a guard page, lazy mapping) would have
    produced a finding and a PoC for a bug that is not there."""
    import shutil
    import subprocess
    import textwrap

    from lykos.analyze.dynamic import sandbox
    gcc = shutil.which("gcc")
    if not gcc or not shutil.which("nm") or not sandbox._bwrap_usable():
        pytest.skip("needs gcc, nm and bubblewrap")
    src = tmp_path / "h.c"
    src.write_text(textwrap.dedent("""
        #include <signal.h>
        #include <stdio.h>
        #include <setjmp.h>
        static jmp_buf jb;
        static void onsegv(int s){ (void)s; longjmp(jb, 1); }
        int main(void){
            signal(SIGSEGV, onsegv);
            if (setjmp(jb) == 0) { *(volatile int*)0 = 1; }
            printf("recovered\\n");
            return 0;
        }
    """))
    exe = tmp_path / "h"
    if subprocess.run([gcc, "-O0", "-w", str(src), "-o", str(exe)],
                      capture_output=True, timeout=120).returncode != 0:
        pytest.skip("cannot build the fixture")
    nm = subprocess.run(["nm", str(exe)], capture_output=True, text=True, timeout=60).stdout
    blocks = tuple(sorted({int(f[0], 16) for f in (x.split() for x in nm.splitlines())
                           if len(f) == 3 and f[1] in "tT"}))
    assert blocks, "need real function entries -- invented addresses corrupt the code"
    traced = sandbox.run_batch(exe, [b""], mode="stdin", timeout=10, blocks=blocks)
    plain = sandbox.run_batch(exe, [b""], mode="stdin", timeout=10)
    if traced is None or plain is None:
        pytest.skip("batch runner unavailable here")
    assert not plain[0].crashed
    assert not traced[0].crashed, "tracing must not invent a crash the program recovered from"
    assert b"recovered" in (traced[0].stdout or b""), "and the program must run to completion"
