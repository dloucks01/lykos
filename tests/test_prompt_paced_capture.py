"""Prompt-paced delivery, the channel that capped a whole class of defect at L1.

A prompt-driven target reads each field with its own `read(0, buf, N)`. `read` returns whatever is
AVAILABLE, so a bulk feed hands the entire blob to field one -- which then holds the bytes meant
for field two, and field two reaches EOF. The campaign knew this (`fuzz.runner.run_input_prompted`)
and the shipped bundle knew it (`replay_prompt.py`), but the ptrace capture used by the L2 primitive
and the root-cause stage did NOT: its mode chain had no `prompt` branch and no `else`, so such an
input left stdin unset, the child ran with NO INPUT, and the helper honestly reported "no fatal
signal". The crash was real, the setup was wrong, and nothing said so.

These tests pin down three things: the split is shared with the campaign so the two cannot drift,
paced delivery captures a fault the bulk channels cannot, and an unrecognised mode is now an
explicit refusal rather than silence.
"""
import shutil
import subprocess
import sys

import pytest
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import capture as cap

#: Field one must end exactly at its newline, so a bulk feed is REJECTED and field two never
#: arrives. The copy lives in a function that returns, so the smash reaches a saved return address.
_PROMPT_SRC = r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static void use(const char *src){ char small[64]; strcpy(small, src); printf("ok %s\n", small); }
int main(void){ setvbuf(stdout,0,2,0);
  char first[128], second[512];
  printf("mode: ");
  ssize_t n = read(0, first, sizeof first - 1); if(n <= 0) return 0; first[n] = 0;
  if(memchr(first, '\n', n) != first + n - 1){ puts("one field per line, please"); return 1; }
  printf("data: ");
  n = read(0, second, sizeof second - 1); if(n <= 0) return 0; second[n] = 0;
  use(second);
  return 0; }
"""

_PAYLOAD = b"go\n" + b"A" * 400 + b"\n"


class _Ctx:
    """The one thing `make_capture` needs from a stage context."""

    def run_subprocess(self, argv, timeout=None):
        return subprocess.run(argv, capture_output=True, timeout=timeout)


@pytest.fixture(scope="module")
def prompt_exe(tmp_path_factory):
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc or sandbox.host_arch() != "x86-64":
        pytest.skip("native x86-64 build required")
    d = tmp_path_factory.mktemp("paced")
    (d / "t.c").write_text(_PROMPT_SRC)
    exe = d / "t"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-O0", "-w",
                       str(d / "t.c"), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("build failed")
    return exe


# ------------------------------------------------------------------------ the split, shared once
def test_paced_chunks_keeps_every_field_including_a_trailing_empty_one():
    """A blob that ends in a newline means a final bare "\\n" went in, which for a target reading
    with `read(0, ...)` is a field, not nothing -- so the split must not drop it."""
    assert cap.paced_chunks(b"go\nAAA\n") == [b"go\n", b"AAA\n", b"\n"]
    assert cap.paced_chunks(b"one") == [b"one\n"]
    assert cap.paced_chunks(b"") == [b"\n"]
    assert b"".join(cap.paced_chunks(b"a\nb")) == b"a\nb\n"


def test_the_campaign_and_the_capture_share_one_split():
    """Source-level, deliberately: a crash found with one split and replayed with another is a
    crash that does not reproduce, and that silent disagreement is the whole reason this channel
    exists. Behavioural equivalence is asserted separately, live, below."""
    import inspect

    from lykos.analyze.fuzz import runner
    src = inspect.getsource(runner.run_input_prompted)
    assert "paced_chunks" in src, "the campaign must not re-implement the pacing split"


def test_prompt_is_not_one_of_the_blanket_sweep_modes():
    """`prompt` is a PACING POLICY on stdin, not a channel. In MODES it would cost every target in
    the generic sweep an extra execution per input and would make `substrate.channels` claim a
    carrier that does not exist."""
    assert cap.PROMPT not in cap.MODES
    assert cap.MODES == ("stdin", "file", "arg")


def test_sweep_modes_adds_prompt_only_when_there_is_more_than_one_field():
    assert cap.sweep_modes("stdin", b"AAAA") == ["stdin", "file", "arg"]
    assert cap.sweep_modes("stdin", b"go\nAAAA\n")[-1] == cap.PROMPT
    # recorded as prompted -> it LEADS, because then it is not a guess
    assert cap.sweep_modes(cap.PROMPT, b"go\nAAAA\n")[0] == cap.PROMPT
    # and it is not added twice
    assert cap.sweep_modes(cap.PROMPT, b"go\nAAAA\n").count(cap.PROMPT) == 1
    # a substrate that cannot carry stdin cannot carry a prompt protocol either
    assert cap.PROMPT not in cap.sweep_modes("file", b"go\nAAAA\n", deliverable=["file", "arg"])


# ---------------------------------------------------------------------------- the capability, live
def test_only_paced_delivery_captures_the_fault(prompt_exe):
    """The measurement this whole change rests on: the bulk channels cannot deliver a prompt
    protocol, and before the `prompt` branch existed that read as "the input does not fault"."""
    helper = cap.materialize_helper()
    ctx = _Ctx()
    for mode in ("stdin", "file", "arg"):
        r = cap.make_capture(ctx, helper, prompt_exe, mode, [], 10, sys.executable)(_PAYLOAD)
        assert not (r.get("ok") and r.get("signal_name")), \
            f"{mode} delivered a prompt protocol, so this fixture does not isolate pacing"
    r = cap.make_capture(ctx, helper, prompt_exe, cap.PROMPT, [], 10, sys.executable)(_PAYLOAD)
    assert r.get("ok") and r.get("signal_name") == "SIGSEGV", r
    # and everything L2 needs out of it
    assert r.get("pc") and r.get("regs") and r.get("stack")
    assert r["fields_delivered"] >= 2, r
    assert r["fields_total"] == 3                         # go / filler / the trailing bare newline
    assert "data:" in (r.get("target_output") or ""), "the second prompt was never reached"


def test_the_campaign_reproduces_the_same_signal_as_the_capture(prompt_exe):
    """Behavioural equivalence between the two pacers, which is what the shared split is FOR."""
    from lykos.analyze.fuzz.runner import run_input_prompted
    _argv, res = run_input_prompted(str(prompt_exe), _PAYLOAD, timeout=10)
    assert res.crashed, "the campaign's own prompted runner did not reproduce it"
    helper = cap.materialize_helper()
    r = cap.make_capture(_Ctx(), helper, prompt_exe, cap.PROMPT, [], 10, sys.executable)(_PAYLOAD)
    assert r.get("signal_name") == (res.signal_name or "SIGSEGV")


def test_a_cyclic_pattern_faults_when_framed_and_paced(prompt_exe):
    """What makes L2 reachable: the bare cyclic has no field boundaries, but framed as the crash
    was framed (`b"go\\n" + cyclic + b"\\n"`) it has three, and the pc comes back."""
    from lykos.analyze.poc import primitive
    framed = b"go\n" + primitive.cyclic(300) + b"\n"
    assert len(cap.paced_chunks(framed)) == 3
    assert cap.sweep_modes("stdin", framed)[-1] == cap.PROMPT
    r = cap.make_capture(_Ctx(), cap.materialize_helper(), prompt_exe, cap.PROMPT, [], 10,
                         sys.executable)(framed)
    assert r.get("ok") and r.get("signal_name") == "SIGSEGV", r
    assert r.get("pc")


# -------------------------------------------------------------- the silence that caused all of it
def test_an_unknown_delivery_mode_is_refused_not_ignored(prompt_exe):
    """The regression guard. An unrecognised mode used to fall through the chain leaving stdin
    unset, so the child ran with no input and the helper reported "no fatal signal" -- a wrong
    setup wearing the clothes of a clean negative result."""
    r = cap.make_capture(_Ctx(), cap.materialize_helper(), prompt_exe, "bogus", [], 10,
                         sys.executable)(_PAYLOAD)
    assert not r.get("ok")
    assert "does not know how to deliver" in r.get("reason", ""), r
    # socket delivery has no exec-time carrier at all, and says so by name
    r = cap.make_capture(_Ctx(), cap.materialize_helper(), prompt_exe, "socket", [], 10,
                         sys.executable)(_PAYLOAD)
    assert not r.get("ok") and "no exec-time carrier" in r.get("reason", "")


def test_the_emulated_capture_declines_what_it_cannot_pace():
    """qemu's gdbstub takes one bulk stdin blob, so an emulated prompt-driven target is a real
    gap -- stated, rather than run with no input and reported as not faulting."""
    c = cap.make_qemu_capture("/nonexistent", "aarch64", cap.PROMPT, [], 5)
    r = c(_PAYLOAD)
    assert not r.get("ok")
    assert "cannot deliver" in r.get("reason", "")
