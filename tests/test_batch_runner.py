"""The batched execution path: many inputs inside ONE sandbox, with block coverage.

This is the throughput path -- bubblewrap costs 3.18 ms of a 3.55 ms execution, so the
namespace is paid for once per batch instead of once per input -- and it is also where real
path coverage comes from. It runs as a subprocess by construction, so in-process coverage
never saw it and none of this was tested: the wire protocol between parent and runner, the
one-shot breakpoint semantics, and what a batch does when one of its inputs crashes or hangs.

A bug here is quiet in the worst way: `run_batch` returns None for "not available", and the
caller then silently falls back to per-exec. A protocol mistake therefore costs throughput and
coverage without ever producing an error.
"""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze.dynamic import sandbox
from lykos.analyze.fuzz import batch_runner

pytestmark = pytest.mark.skipif(not sandbox._bwrap_usable(),
                                reason="batched execution needs bubblewrap")

_ECHO_C = """
#include <stdio.h>
#include <string.h>
int main(void){ char b[64]; size_t n = fread(b,1,sizeof b,stdin);
  fwrite(b,1,n,stdout); if(n && b[0]=='X') fprintf(stderr,"saw X\\n"); return n ? 0 : 3; }
"""
_CRASH_C = """
#include <stdio.h>
#include <string.h>
int main(void){ char b[16]; char line[512];
  size_t n = fread(line,1,sizeof line,stdin); line[n?n-1:0]=0;
  if(n > 32) strcpy(b,line);            /* overflows only for a long input */
  printf("%zu\\n", n); return 0; }
"""
# A handler that returns from SIGSEGV without fixing the fault: the kernel re-runs the faulting
# instruction, which faults again, forever. Under ptrace this is a flood of back-to-back stops
# that the per-input deadline used to miss entirely (it was only checked while WAITING for a
# stop), so one such input could spin the runner without end.
_REFAULT_C = """
#include <signal.h>
static void h(int s){ (void)s; }
int main(void){ signal(SIGSEGV, h); volatile int *p = 0; *p = 1; return 0; }
"""
# two branches, so a block list can tell one input's path from another's
_BRANCH_C = """
#include <stdio.h>
int main(void){ int c = getchar();
  if (c == 'a') { puts("alpha"); return 0; }
  if (c == 'b') { puts("beta"); return 0; }
  puts("other"); return 0; }
"""


def _build(gcc, tmp_path, src, name, extra=()):
    c = tmp_path / f"{name}.c"
    c.write_text(src)
    exe = tmp_path / name
    if subprocess.run([gcc, "-O0", "-w", *extra, str(c), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip(f"cannot build {name}")
    return exe


# ---- the image-base helper the block addresses depend on ---------------------------------

def test_a_fixed_image_reports_the_vaddr_it_asks_to_be_loaded_at(gcc, tmp_path):
    exe = _build(gcc, tmp_path, _ECHO_C, "fixed", extra=["-no-pie"])
    assert batch_runner._elf_min_vaddr(str(exe)) > 0


def test_a_position_independent_image_reports_zero(gcc, tmp_path):
    """A PIE's file vaddrs are already relative, so the runtime base comes from /proc/maps
    instead. Getting this backwards shifts every breakpoint by the image base and arms
    addresses that are not code."""
    exe = _build(gcc, tmp_path, _ECHO_C, "pie", extra=["-fPIE", "-pie"])
    assert batch_runner._elf_min_vaddr(str(exe)) == 0


def test_a_non_elf_is_zero_rather_than_an_exception(tmp_path):
    p = tmp_path / "not.elf"
    p.write_bytes(b"MZ" + b"\x00" * 200)
    assert batch_runner._elf_min_vaddr(str(p)) == 0
    assert batch_runner._elf_min_vaddr(str(tmp_path / "missing")) == 0


# ---- the batch protocol ------------------------------------------------------------------

def test_every_input_gets_its_own_result_in_order(gcc, tmp_path):
    exe = _build(gcc, tmp_path, _ECHO_C, "echo")
    payloads = [b"one", b"two", b"three", b"Xfour"]
    res = sandbox.run_batch(exe, payloads, mode="stdin", timeout=5)
    if res is None:
        pytest.skip("batched execution unavailable here")
    assert len(res) == len(payloads)
    for d, r in zip(payloads, res):
        assert r.stdout == d, "a result was paired with the wrong input"
    assert res[3].stderr.strip() == b"saw X", "per-input stderr is not separated"


def test_an_empty_batch_is_declined_rather_than_run(gcc, tmp_path):
    exe = _build(gcc, tmp_path, _ECHO_C, "echo2")
    assert sandbox.run_batch(exe, [], mode="stdin", timeout=5) is None


def test_exit_codes_travel_per_input(gcc, tmp_path):
    exe = _build(gcc, tmp_path, _ECHO_C, "echo3")
    res = sandbox.run_batch(exe, [b"", b"data"], mode="stdin", timeout=5)
    if res is None:
        pytest.skip("batched execution unavailable here")
    assert res[0].exit_code == 3 and not res[0].crashed
    assert res[1].exit_code == 0


def test_a_crash_in_the_middle_does_not_lose_the_rest_of_the_batch(gcc, tmp_path):
    """The whole point of batching is amortising the namespace; one bad input must cost one
    result, not the other sixty-three."""
    exe = _build(gcc, tmp_path, _CRASH_C, "mid", extra=["-fno-stack-protector"])
    payloads = [b"short\n", b"A" * 400 + b"\n", b"also short\n", b"tiny\n"]
    res = sandbox.run_batch(exe, payloads, mode="stdin", timeout=5)
    if res is None:
        pytest.skip("batched execution unavailable here")
    assert len(res) == 4
    assert res[1].crashed, "the overflowing input did not crash"
    assert not res[0].crashed and not res[2].crashed and not res[3].crashed
    assert res[2].stdout, "the input after the crash produced no output"


def test_a_crashing_input_carries_its_fault_address(gcc, tmp_path):
    """Two crashes at different addresses are different defects; without a fault PC every
    SIGSEGV in the program buckets as one finding."""
    exe = _build(gcc, tmp_path, _CRASH_C, "fault", extra=["-fno-stack-protector"])
    res = sandbox.run_batch(exe, [b"B" * 400 + b"\n"], mode="stdin", timeout=5)
    if res is None:
        pytest.skip("batched execution unavailable here")
    if not res[0].crashed:
        pytest.skip("the fixture did not fault on this toolchain")
    assert res[0].isolation == "bwrap+netns+batch"


def _libc_for_trace():
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    return libc


def test_a_refaulting_handler_is_killed_at_the_deadline_not_spun_forever(gcc, tmp_path):
    """A program whose SIGSEGV handler returns without fixing the fault re-faults on every
    instruction retry, producing back-to-back ptrace stops. The deadline used to be consulted
    only inside the wait loop -- which never runs when a stop is always ready -- so `_trace_one`
    looped without end. It must now enforce the deadline at the top of every iteration and cap
    forwarded signals, terminating bounded and reporting a hang."""
    import time

    exe = _build(gcc, tmp_path, _REFAULT_C, "refault", extra=["-no-pie"])
    blocks = _blocks_of(exe)                              # force the traced path
    if not blocks:
        pytest.skip("no function entries recovered")
    libc = _libc_for_trace()
    start = time.time()
    rc, out, err, flags, reached, fault_pc = batch_runner._trace_one(
        libc, [str(exe)], b"", 2.0, blocks, str(exe), {})
    elapsed = time.time() - start
    # the regression: without the fix this never returns
    assert elapsed < 20, f"re-fault loop was not bounded ({elapsed:.1f}s); deadline not enforced"
    # when it did loop, it is a hang, not a single clean crash
    assert flags == 1 or elapsed < 1.0, "a bounded re-fault loop must be reported as a hang"


def test_isolation_is_not_traded_away_for_speed(gcc, tmp_path):
    """Batching buys throughput by amortising the namespace, never by giving one up."""
    exe = _build(gcc, tmp_path, _ECHO_C, "iso")
    res = sandbox.run_batch(exe, [b"x"], mode="stdin", timeout=5)
    if res is None:
        pytest.skip("batched execution unavailable here")
    assert "bwrap" in res[0].isolation and "netns" in res[0].isolation


# ---- substrates that must NOT be batched -------------------------------------------------

def test_a_jar_is_never_batched(tmp_path):
    """The runner execs the target directly and traces it. A jar is not executable and the JVM
    is not the target, so batching it would run the wrong program under someone else's
    breakpoints."""
    import zipfile
    jar = tmp_path / "x.jar"
    with zipfile.ZipFile(jar, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    assert sandbox.run_batch(jar, [b"x"], mode="stdin", timeout=5) is None


def test_a_cross_architecture_target_is_never_batched(gcc, tmp_path):
    exe = _build(gcc, tmp_path, _ECHO_C, "xarch")
    other = "aarch64" if sandbox.host_arch() != "aarch64" else "x86-64"
    assert sandbox.run_batch(exe, [b"x"], mode="stdin", timeout=5, arch=other) is None


def test_a_windows_pe_is_never_batched(tmp_path):
    pe = tmp_path / "x.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 0x3a + (0x80).to_bytes(4, "little")
                   + b"\x00" * 0x40 + b"PE\x00\x00" + b"\x00" * 200)
    assert sandbox.run_batch(pe, [b"x"], mode="stdin", timeout=5) is None


# ---- block coverage ----------------------------------------------------------------------

def _blocks_of(exe):
    """Basic-block-ish addresses: every function entry objdump reports, as FILE vaddrs."""
    out = subprocess.run(["objdump", "-d", str(exe)], capture_output=True, text=True)
    if out.returncode:
        pytest.skip("objdump unavailable")
    addrs = []
    for line in out.stdout.splitlines():
        if line.endswith(">:") and " <" in line:
            try:
                addrs.append(int(line.split()[0], 16))
            except ValueError:
                pass
    return addrs


def test_coverage_reports_only_the_blocks_an_input_reached(gcc, tmp_path):
    exe = _build(gcc, tmp_path, _BRANCH_C, "branch", extra=["-no-pie"])
    blocks = _blocks_of(exe)
    if not blocks:
        pytest.skip("no function entries recovered")
    res = sandbox.run_batch(exe, [b"a"], mode="stdin", timeout=5, blocks=blocks)
    if res is None:
        pytest.skip("batched execution unavailable here")
    assert res[0].blocks_hit is not None, "coverage was asked for and not answered"
    assert set(res[0].blocks_hit) <= set(blocks), "reported a block that was never armed"
    assert res[0].blocks_hit, "an executed program reached none of its own function entries"


def test_coverage_travels_on_both_channels(gcc, tmp_path):
    """`blocks_hit` is the explicit field and `note` the older comma-joined string. run() sets
    both; the batch path setting only one is exactly the drift that let coverage go missing
    on the channel runner."""
    exe = _build(gcc, tmp_path, _BRANCH_C, "chan", extra=["-no-pie"])
    blocks = _blocks_of(exe)
    if not blocks:
        pytest.skip("no function entries recovered")
    res = sandbox.run_batch(exe, [b"a"], mode="stdin", timeout=5, blocks=blocks)
    if res is None or not res[0].blocks_hit:
        pytest.skip("batched coverage unavailable here")
    from_note = {int(x) for x in (res[0].note or "").split(",") if x}
    assert from_note == set(res[0].blocks_hit)


def test_no_blocks_asked_for_means_no_coverage_claimed(gcc, tmp_path):
    """None and () are different answers: "we did not measure" is not "it reached nothing"."""
    exe = _build(gcc, tmp_path, _BRANCH_C, "nocov", extra=["-no-pie"])
    res = sandbox.run_batch(exe, [b"a"], mode="stdin", timeout=5)
    if res is None:
        pytest.skip("batched execution unavailable here")
    assert res[0].blocks_hit is None


def test_a_block_in_a_loop_is_reported_once_not_once_per_iteration(gcc, tmp_path):
    """"One-shot" is per EXECUTION: the trap is restored the first time it is hit so a hot loop
    does not pay a trap per iteration. That is also the signal a fuzzer wants -- "did this
    input reach anywhere new?" -- rather than a hit count it would have to diff."""
    src = """
#include <stdio.h>
static void hot(int i){ printf("%d", i & 1); }
int main(void){ int c = getchar(); for (int i = 0; i < 500; i++) hot(i);
  return c == 'a' ? 0 : 1; }
"""
    exe = _build(gcc, tmp_path, src, "loop", extra=["-no-pie", "-O0"])
    blocks = _blocks_of(exe)
    if not blocks:
        pytest.skip("no function entries recovered")
    res = sandbox.run_batch(exe, [b"a"], mode="stdin", timeout=10, blocks=blocks)
    if res is None or not res[0].blocks_hit:
        pytest.skip("batched coverage unavailable here")
    hit = res[0].blocks_hit
    assert len(hit) == len(set(hit)), "a block was reported more than once for one input"


def test_identical_inputs_in_one_batch_report_the_same_blocks(gcc, tmp_path):
    """Each input is its own process, so the arm list applies afresh to every one of them.
    The cost decay across a campaign is the CALLER's doing -- it passes only the blocks it has
    not seen yet -- not something the batch does behind its back. Asserting otherwise would
    bake in a decay that does not exist and hide it if the caller ever stopped shrinking."""
    exe = _build(gcc, tmp_path, _BRANCH_C, "same", extra=["-no-pie"])
    blocks = _blocks_of(exe)
    if not blocks:
        pytest.skip("no function entries recovered")
    res = sandbox.run_batch(exe, [b"a", b"a"], mode="stdin", timeout=5, blocks=blocks)
    if res is None or not res[0].blocks_hit:
        pytest.skip("batched coverage unavailable here")
    assert set(res[0].blocks_hit) == set(res[1].blocks_hit)


def test_arming_fewer_blocks_reports_fewer(gcc, tmp_path):
    """This is the decay the campaign actually relies on: as coverage saturates it arms less,
    and the per-input cost falls with it."""
    exe = _build(gcc, tmp_path, _BRANCH_C, "shrink", extra=["-no-pie"])
    blocks = _blocks_of(exe)
    if len(blocks) < 4:
        pytest.skip("too few function entries to shrink")
    full = sandbox.run_batch(exe, [b"a"], mode="stdin", timeout=5, blocks=blocks)
    if full is None or not full[0].blocks_hit:
        pytest.skip("batched coverage unavailable here")
    keep = list(full[0].blocks_hit)[:1]
    few = sandbox.run_batch(exe, [b"a"], mode="stdin", timeout=5, blocks=keep)
    assert few is not None
    assert set(few[0].blocks_hit or ()) == set(keep)


def test_is_sanitizer_distinguishes_builds(gcc, tmp_path):
    """The batch tracer decides once, from the ELF's bytes, whether a target is a sanitizer
    build -- it runs as a bare subprocess and cannot import the package, so this is a stdlib
    byte-scan for the ASan/UBSan runtime marker."""
    plain = _build(gcc, tmp_path, _ECHO_C, "plain_san")
    assert not batch_runner._is_sanitizer(str(plain))
    asan = _build(gcc, tmp_path, _ECHO_C, "asan_san", extra=["-fsanitize=address"])
    if not asan.exists():
        pytest.skip("no ASan runtime on this toolchain")
    assert batch_runner._is_sanitizer(str(asan)), "ASan marker scan missed an ASan build"
    assert not batch_runner._is_sanitizer(str(tmp_path / "missing"))


def test_a_sanitizer_build_is_not_as_capped_and_reaches_its_code(gcc, tmp_path):
    """Regression: the batch tracer capped every child's RLIMIT_AS to bound a memory bomb, but an
    ASan build reserves a ~20TB VIRTUAL shadow region at startup -- under an AS cap that mmap
    fails and the process ABORTS BEFORE main(). Every input then read as a spurious SIGABRT and
    no block was ever reached (block coverage came back 0/N on every source build, which is the
    whole ASan-source path). A sanitizer build must run WITHOUT the AS cap -- resident memory is
    bounded via ASAN_OPTIONS=hard_rss_limit_mb instead -- so it reaches its own code and coverage
    is real. This is the same exemption the sandbox already makes for the non-batched path."""
    exe = _build(gcc, tmp_path, _BRANCH_C, "asan_cov", extra=["-no-pie", "-fsanitize=address"])
    if not batch_runner._is_sanitizer(str(exe)):
        pytest.skip("no ASan runtime on this toolchain")
    blocks = _blocks_of(exe)
    if not blocks:
        pytest.skip("no function entries recovered")
    res = sandbox.run_batch(exe, [b"a"], mode="stdin", timeout=15, blocks=blocks)
    if res is None:
        pytest.skip("batched execution unavailable here")
    assert not res[0].crashed, "the ASan build spuriously aborted -- the AS cap starved its shadow"
    assert res[0].blocks_hit, "the ASan build reached none of its blocks -- it aborted before main()"


def test_a_large_stdin_payload_does_not_deadlock_the_traced_path(gcc, tmp_path):
    """Regression (H5): the tracee is stopped at execve and not yet reading fd 0, so writing a
    payload larger than the 64 KiB pipe buffer directly -- before continuing it -- deadlocked, and
    the per-input deadline (checked only inside the trace loop) never fired; the whole batch stalled
    to the outer budget and was discarded. stdin is now fed from a thread. A 256 KiB payload must
    complete promptly, not stall."""
    import time
    exe = _build(gcc, tmp_path, _ECHO_C, "bigstdin")
    blocks = _blocks_of(exe)
    if not blocks:
        pytest.skip("no function entries recovered")
    t = time.time()
    res = sandbox.run_batch(exe, [b"A" * (256 * 1024)], mode="stdin", timeout=5, blocks=blocks)
    elapsed = time.time() - t
    if res is None and elapsed < 3:
        pytest.skip("batched execution unavailable here")
    # without the fix this returns None only after the outer budget (~timeout+15 s) kills the batch
    assert elapsed < 15, f"large-stdin batch stalled ({elapsed:.1f}s) -- the H5 deadlock is back"
    assert res is not None and len(res) == 1


def test_different_inputs_take_different_paths(gcc, tmp_path):
    """The whole reason to collect this: an input that reaches somewhere new is worth keeping,
    and output shape alone could not tell the difference."""
    exe = _build(gcc, tmp_path, _BRANCH_C, "paths", extra=["-no-pie"])
    blocks = _blocks_of(exe)
    if not blocks:
        pytest.skip("no function entries recovered")
    res = sandbox.run_batch(exe, [b"a", b"z"], mode="stdin", timeout=5, blocks=blocks)
    if res is None or not res[0].blocks_hit:
        pytest.skip("batched coverage unavailable here")
    assert res[0].stdout != res[1].stdout, "the fixture did not actually branch"
