"""A defect that never crashes: reading uninitialised memory, and disclosing it.

Everything else in this pipeline is reached through a crash. An uninitialised read produces
none -- the read succeeds, the process exits 0, and the stale bytes leave with the output -- so
it was invisible end to end. Two things had to be true to close it, and the first one is why the
obvious design does not work.

A DIFFERENTIAL oracle (fill fresh memory with a pattern, run twice, diff the output) needs a
knob, and the common shape of this defect has none:

    static void fill(void){ char pad[64]; memset(pad,'S',sizeof pad); }
    static void leak(void){ char b[64]; printf("%.64s\\n", b); }
    int main(void){ fill(); leak(); }

`fill()` overwrites any pre-seeded pattern microseconds before `leak()` reads it, and the program
reads no input at all, so the output is identical under every pattern. Shadow memory has the
knob: memcheck tracks definedness per byte, so it sees the read itself.

The second thing is the distinction that decides what may be CLAIMED: undefined bytes reaching a
write syscall have LEFT THE PROCESS (CWE-200, an effect that actually happened), while a
conditional jump on an undefined value is real but internal (CWE-457, no effect to show).
"""
import shutil
import subprocess

import pytest
from lykos.analyze.dynamic import memoracle

_LEAK_SRC = """#include <stdio.h>
#include <string.h>
static void fill(void){ char pad[64]; memset(pad,'S',sizeof pad); }
static void leak(void){ char b[64]; printf("%.64s\\n", b); }   /* never initialised */
int main(void){ setvbuf(stdout,0,2,0); fill(); leak(); return 0; }
"""

_CLEAN_SRC = """#include <stdio.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  char b[64]; memset(b,'S',sizeof b); printf("%.64s\\n", b); return 0; }
"""

_BRANCH_SRC = """#include <stdio.h>
int main(void){ setvbuf(stdout,0,2,0);
  int x; if (x) puts("hi"); else puts("ho"); return 0; }
"""


@pytest.fixture(scope="module")
def cc():
    c = shutil.which("gcc") or shutil.which("cc")
    if not c:
        pytest.skip("no C compiler")
    if memoracle.valgrind_bin() is None:
        pytest.skip("valgrind not installed")
    return c


def _build(cc, tmp_path, name, src):
    s = tmp_path / f"{name}.c"
    s.write_text(src)
    exe = tmp_path / name
    r = subprocess.run([cc, "-no-pie", "-fno-stack-protector", "-O0", "-w", "-o", str(exe),
                        str(s)], capture_output=True)
    assert r.returncode == 0, r.stderr.decode()
    return exe


# ---- the oracle ---------------------------------------------------------------------------

def test_a_differential_on_the_output_could_never_have_seen_this(cc, tmp_path):
    """Stated as a test because it is the reason the design is what it is: the program is
    deterministic and reads nothing, so no black-box variation of input or environment moves its
    output. Anything that only compares outputs is blind here, however it fills memory."""
    exe = _build(cc, tmp_path, "leak", _LEAK_SRC)
    outs = {subprocess.run([str(exe)], capture_output=True, timeout=60,
                           env={"PATH": "/usr/bin:/bin", "LYKOS_X": "x" * n}).stdout
            for n in (0, 1, 500)}
    assert len(outs) == 1, "the output varied, so a differential WOULD have worked"
    assert b"S" * 64 in outs.pop()


def test_undefined_bytes_reaching_a_write_are_reported_as_a_disclosure(cc, tmp_path):
    exe = _build(cc, tmp_path, "leak", _LEAK_SRC)
    v = memoracle.valgrind_triage(exe, b"", mode="stdin", timeout=180.0)
    assert v, "memcheck saw nothing"
    assert v["kind"] == "uninit-disclosure"
    assert v["cwe"] == "CWE-200" and v["severity"] == "high"
    assert v.get("origin") == "stack", "the origin is what makes it a root cause"


def test_an_internal_uninitialised_read_is_not_claimed_as_a_disclosure(cc, tmp_path):
    """A branch on an undefined value is a real defect (CWE-457) and nothing left the process, so
    it must not be reported with the disclosure's CWE or its severity."""
    exe = _build(cc, tmp_path, "branch", _BRANCH_SRC)
    v = memoracle.valgrind_triage(exe, b"", mode="stdin", timeout=180.0)
    assert v, "memcheck saw nothing"
    assert v["kind"] == "uninitialised"
    assert v["cwe"] == "CWE-457"


def test_an_initialised_program_is_reported_clean(cc, tmp_path):
    """Precision: this stage runs on every native target, so a false positive here would land on
    every clean binary in the suite."""
    exe = _build(cc, tmp_path, "ok", _CLEAN_SRC)
    assert memoracle.valgrind_triage(exe, b"", mode="stdin", timeout=180.0) is None


def test_the_disclosure_outranks_the_internal_read_when_both_are_present(cc, tmp_path):
    """The leak program reports BOTH (a strnlen branch on undefined bytes, then the write). The
    verdict must be the one with the effect."""
    exe = _build(cc, tmp_path, "leak", _LEAK_SRC)
    assert memoracle.valgrind_triage(exe, b"", mode="stdin",
                                     timeout=180.0)["kind"] == "uninit-disclosure"


# ---- the parser, without needing valgrind -------------------------------------------------

_DISCLOSE = b"""==1== Syscall param write(buf) points to uninitialised byte(s)
==1==    at 0x49811B5: write (write.c:26)
==1==    by 0x401189: leak (in /t/x)
==1==  Address 0x1ffefffe00 is on thread 1's stack
==1==  Uninitialised value was created by a stack allocation
==1==    at 0x401167: leak (in /t/x)
"""


def test_the_parser_recognises_the_disclosure_without_running_anything():
    v = memoracle.parse_memcheck(_DISCLOSE)
    assert v["kind"] == "uninit-disclosure" and v["cwe"] == "CWE-200"
    assert v["origin"] == "stack"


@pytest.mark.parametrize("syscall", [b"write", b"pwrite64", b"writev", b"send", b"sendto"])
def test_every_syscall_that_sends_bytes_out_counts(syscall):
    msg = (b"==1== Syscall param " + syscall +
           b"(buf) points to uninitialised byte(s)\n==1==    at 0x1: f (x.c:1)\n")
    assert memoracle.parse_memcheck(msg)["kind"] == "uninit-disclosure"


def test_a_heap_error_still_outranks_an_uninitialised_one():
    """Ordering matters: a use-after-free is the worse finding and must stay the verdict."""
    both = (b"==1== Syscall param write(buf) points to uninitialised byte(s)\n"
            b"==1==    at 0x1: f (x.c:1)\n"
            b"==1== Invalid read of size 4\n"
            b"==1==    at 0x2: g (x.c:2)\n"
            b"==1==  Address 0x5 is 0 bytes inside a block of size 8 free'd\n")
    assert memoracle.parse_memcheck(both)["kind"] == "use-after-free"


def test_a_clean_memcheck_run_is_None():
    assert memoracle.parse_memcheck(b"") is None
    assert memoracle.parse_memcheck(b"==1== All heap blocks were freed -- no leaks\n") is None


# ---- the stage's own gates ----------------------------------------------------------------

@pytest.mark.parametrize("ftype", ["pyc", "wasm", "dotnet", "jar", "macho", "raw"])
def test_the_stage_declines_on_anything_it_cannot_natively_run(ftype):
    from lykos.analyze import capabilities
    from lykos.analyze.dynamic import uninit_stage

    class T:
        file_type, arch, linking = ftype, "x86-64", "dynamic"
    why = capabilities._why_unavailable("mem_oracle", T())
    assert why, f"{ftype} must not be offered a host-arch shadow-memory oracle"
    assert uninit_stage.MEM_ORACLE_STAGE == "mem_oracle"


def test_memcheck_uninit_lane_is_declined_on_go_and_rust_binaries():
    """A runtime-managed, bounds-checked language (Go, Rust) makes memcheck's uninitialised-read
    lane a false-positive generator -- its runtime legitimately reads slots memcheck has not seen
    written, so EVERY such binary yields a 'confirmed CWE-457' that is runtime noise (observed
    identically on kubectl/helm/terraform). The stage must gate on toolchain_hint and decline,
    not file a misleading finding. (Source-level guard: the behavioural path needs a built Go
    binary; this ensures the gate itself is not silently dropped.)"""
    import inspect

    from lykos.analyze.dynamic import uninit_stage
    src = inspect.getsource(uninit_stage.mem_oracle_stage)
    assert "toolchain_hint" in src, "the Go/Rust gate reads target.toolchain_hint"
    assert '"go"' in src or "'go'" in src or 'startswith("go")' in src, "must gate Go"
    assert "rust" in src, "must gate Rust"
    # and it must decline (not raise / not file) -- the gate uses _decline
    gate = src[src.index("toolchain_hint"):]
    assert "_decline" in gate, "the Go/Rust path must _decline, not file a finding"


def test_the_stage_is_scheduled_and_visible_to_the_operator():
    from lykos.analyze import capabilities
    from lykos.analyze.orchestrate import _PLAN_STAGES, _TARGET
    assert "mem_oracle" in _TARGET
    assert "mem_oracle" in {s for s, _ in _PLAN_STAGES}
    assert "mem_oracle" in capabilities.STAGES
