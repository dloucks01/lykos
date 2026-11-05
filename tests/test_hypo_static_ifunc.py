"""The hypothesis driver on a STATIC glibc binary: by-name models must not sit on IFUNC resolvers.

In a static binary `strlen` is the IFUNC resolver the startup calls once to fill a `.plt` GOT slot.
The driver hooked its lean strlen model there by name, so the startup stored the model's return
value (0) in the slot and every later strlen call jumped to 0x0 -- the reach collapse measured on
static jhead-3.04 (9,698 errored states from one `.plt` stub). This drives the real driver on a
small static program that calls strlen on its input and checks no path jumps to 0x0 and that the
hooks were moved onto the implementations."""
from __future__ import annotations

import shutil
import subprocess

import pytest
from lykos.hypo import engine

pytestmark = pytest.mark.skipif(engine.angr_python() is None, reason="angr interpreter not available")

_SRC = r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(void){
  char buf[64] = {0};
  if (read(0, buf, sizeof buf - 1) <= 0) return 1;
  size_t n = strlen(buf);
  if (n > 8 && buf[0] == 'Z') { char *p = 0; *p = (char)n; }
  printf("%zu\n", n);
  return 0;
}
"""


def test_static_binary_strlen_reaches_past_the_ifunc_slot(tmp_path):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("gcc not available")
    (tmp_path / "s.c").write_text(_SRC)
    exe = tmp_path / "s"
    if subprocess.run([gcc, "-static", "-no-pie", "-O0", "-w", str(tmp_path / "s.c"), "-o", str(exe)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot link a static binary here")
    slots = engine._ifunc_slots(exe)
    assert slots and any(r[2] == "strlen" for r in slots), "strlen should be an IFUNC slot"
    out = engine.run_driver(exe, argv=[], input_mode="stdin", budget=90, input_size=32,
                            mem_mb=4096)
    stats = out.get("stats") or {}
    assert stats.get("ifunc_slots") == len(slots), stats
    assert stats.get("ifunc_moved", 0) >= 1, stats              # the strlen model left its resolver
    errored = stats.get("errored") or {}
    assert not any(k.endswith("@0x0") for k in errored), errored
