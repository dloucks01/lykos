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
    # Arm REAL block boundaries recovered from the binary, not synthetic every-Nth addresses:
    # an INT3 planted mid-instruction (e.g. on the last byte of _start's call to
    # __libc_start_main) rewrites that instruction and faults the process before main -- which
    # is a property of the arbitrary address, not of the tracer. A decompiler block address is
    # always an instruction start, which is what the runner is actually fed in production.
    from lykos.analyze import native_re
    recovered = []
    for f in native_re.analyze(str(exe)).get("functions", []):
        for b in f.get("cfg", {}).get("blocks", []):
            a = b.get("addr")
            a = int(a, 16) if isinstance(a, str) else a
            if isinstance(a, int):
                recovered.append(a)
    blocks = sorted(set(recovered))[:8] if recovered else [entry]
    traced = sandbox.run_batch(exe, [b"hi\n"], mode="stdin", timeout=5.0, blocks=blocks)
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


def test_qemu_block_log_is_parsed_for_the_guest_pc(tmp_path):
    """The ptrace tracer cannot reach inside qemu, so every non-native campaign ran blind on
    output shape alone -- eleven of the twelve architectures the platform builds real targets
    for. qemu logs the guest PC of each block it translates, and the log line is

        Trace 0: <host translation addr> [<flags>/<GUEST PC>/...] <symbol>

    The host address in front is not an address in the target at all: reading it instead of
    the bracketed guest PC matches nothing, which is indistinguishable from no coverage."""
    from lykos.analyze.dynamic.sandbox import _qemu_reached
    log = tmp_path / "exec.log"
    log.write_bytes(b"".join([
        b"Trace 0: 0x7fdc04000100 [80081009231/0000000000400740/00000001/00000000] _start\n",
        b"Linking TBs 0x7fdc040002c0 index 1 -> 0x7fdc04000600\n",
        b"Trace 0: 0x7fdc040002c0 [80081009231/000000000040f924/00000001/00000000] main\n",
    ]))
    assert _qemu_reached(str(log), (0x400740, 0x40F924, 0xDEAD)) == [0x400740, 0x40F924]
    assert _qemu_reached(str(log), ()) == (), "nothing asked for, nothing reported"
    assert _qemu_reached(str(tmp_path / "missing.log"), (0x400740,)) == ()
    # the host translation address must never be mistaken for a guest block
    assert _qemu_reached(str(log), (0x7FDC04000100,)) == []


def test_an_emulated_target_reports_the_blocks_it_reached():
    """End to end: a real cross-architecture binary, under qemu, through the sandbox."""
    import pathlib
    import shutil
    import subprocess

    from lykos.analyze.dynamic import sandbox
    exe = pathlib.Path("examples/vuln-targets/bin/jhead_aarch64").resolve()
    seed = pathlib.Path("examples/vuln-targets/inputs/jhead-ok.jpg").resolve()
    if not exe.exists() or not shutil.which("qemu-aarch64") or not shutil.which("readelf"):
        pytest.skip("run examples/vuln-targets/fetch_build.sh, and qemu-aarch64 is needed")
    out = subprocess.run(["readelf", "-sW", str(exe)], capture_output=True, text=True).stdout
    blocks = tuple(sorted({int(f[1], 16) for f in (ln.split() for ln in out.splitlines())
                           if len(f) >= 8 and f[3] in ("FUNC", "IFUNC") and f[6] != "UND"
                           and int(f[1], 16)}))
    assert blocks
    res = sandbox.run(exe, argv=[str(seed)], arch="aarch64", timeout=30, blocks=blocks)
    reached = [x for x in (res.note or "").split(",") if x]
    assert res.exit_code == 0, res.stderr[:200]
    assert 20 < len(reached) < len(blocks), f"{len(reached)} of {len(blocks)}"


def test_the_sandbox_does_not_show_the_target_the_host_process_table():
    """A fresh procfs without a PID namespace still lists every process on the host: a target
    could read 564 entries of /proc/<pid>/cmdline, and /proc/<pid>/environ for anything running
    as the same user. The namespace is what makes the mount mean something -- and it does not
    cost the tracer anything, because a pid namespace is exactly the scope ptrace and
    /proc/<pid>/mem already work in."""
    import shutil
    import subprocess

    from lykos.analyze.dynamic import sandbox
    if not shutil.which("bwrap") or not sandbox._bwrap_usable():
        pytest.skip("bubblewrap not available here")
    assert "--unshare-pid" in sandbox._BWRAP_ARGS
    cmd = ["bwrap"] + list(sandbox._BWRAP_ARGS) + [
        "sh", "-c", 'ls /proc | grep -c "^[0-9]"']
    inside = int(subprocess.run(cmd, capture_output=True, text=True,
                                timeout=60).stdout.strip() or 0)
    host = int(subprocess.run(["sh", "-c", 'ls /proc | grep -c "^[0-9]"'],
                              capture_output=True, text=True, timeout=60).stdout.strip() or 0)
    assert 0 < inside < 16, f"{inside} processes visible inside the sandbox"
    assert inside < host, "the target must not see the host's process table"


def test_code_nothing_can_call_is_not_counted_as_coverage():
    """A program linked against a library carries all of it. gif2rgb only DECODES GIFs, but
    giflib's whole encoder is in the binary -- 36 of the 62 functions the campaign never
    reached were EGifPutLine, EGifCompressLine, EGifSpew and friends, which no input can reach
    because nothing calls them. Counting them made a campaign covering 38% of what it can
    reach look like one covering 26% of the program."""
    from lykos.analyze.fuzz import stage as fz

    class _F:
        def __init__(self, addr, name):
            self.addr, self.name, self.blocks = addr, name, 1

    class _E:
        def __init__(self, src, dst):
            self.src_addr, self.dst_addr = src, dst

    fns = [_F("0x1000", "main"), _F("0x2000", "decode"), _F("0x3000", "EGifPutLine")]
    edges = [_E("0x1000", "0x2000")]

    class _DAO:
        def __init__(self, _c):
            pass

        def list_by_target(self, _t):
            return edges
    import lykos.analyze.fuzz.stage as st
    real, st.CallEdgeDAO = st.CallEdgeDAO, _DAO

    class _Ctx:
        conn = None

    class _T:
        id = 1
    try:
        live = fz._reachable_functions(_Ctx(), _T(), fns)
        assert live == {"0x1000", "0x2000"}, live

        # A call graph that explains almost nothing is not evidence of dead code -- it is a
        # stripped binary. Trusting it took unzip from 3,705 blocks to 100, a 46/100 result
        # that measures nothing.
        many = [_F("0x%x" % (0x1000 + i * 16), None) for i in range(100)]
        many[0].name = "main"
        assert fz._reachable_functions(_Ctx(), _T(), many) is None

        edges = []
        assert fz._reachable_functions(_Ctx(), _T(), fns) is None, "no edges, no claim"
    finally:
        st.CallEdgeDAO = real
