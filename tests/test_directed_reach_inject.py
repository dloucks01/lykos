"""Directed multi-step reach to a DEEP command-injection sink (doc 58, reaching bridge).

Single-menu-nav can reach a sink behind ONE option, but not one behind MULTI-STEP state (e.g.
`system(buf)` reachable only after an earlier option sets `unlocked=1`). _bfs_reach breakpoints the
sink's call site and searches menu-option SEQUENCES until one drives execution to it; the injection
then confirms with its own forgery-proof marker (the injected `echo` must RUN, not echo back), so
the reach is only a search guide and a wrong reach never fabricates a finding.
"""
import re
import shutil
import subprocess

import pytest

from lykos.analyze.poc import inject_stage, injection
from lykos.analyze.dynamic import sandbox

# A non-PIE menu whose system() sink is gated by multi-step state: option 1 sets unlocked, option 2
# reads a line and (only if unlocked) runs system() on it. Option 2 alone hits the `locked` guard.
_FIXTURE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int unlocked = 0;
static void rdline(char *b, int n){ if (!fgets(b, n, stdin)) exit(0); b[strcspn(b, "\n")] = 0; }
int main(void){
    char cmd[64], buf[128];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    for (;;) {
        if (!fgets(cmd, sizeof cmd, stdin)) break;
        int c = atoi(cmd);
        if (c == 1) { unlocked = 1; puts("unlocked"); }
        else if (c == 2) { rdline(buf, sizeof buf);
            if (unlocked) system(buf);                 /* SINK behind multi-step state */
            else puts("locked"); }
        else if (c == 3) return 0;
    }
    return 0;
}
"""


def _build(tmp_path):
    src = tmp_path / "deep.c"
    src.write_text(_FIXTURE)
    exe = tmp_path / "deep"
    r = subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-O0", "-w", "-o", str(exe),
                        str(src)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"fixture build failed: {r.stderr[:200]}")
    exe.chmod(0o755)
    return exe


def _system_call_sites(exe):
    dis = subprocess.check_output(
        ["objdump", "-d", "--no-show-raw-insn", "-M", "intel", str(exe)], text=True)
    return [int(ln.split(":", 1)[0].strip(), 16) for ln in dis.splitlines()
            if "call" in ln and "<system@plt>" in ln]


@pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("objdump")), reason="needs gcc + objdump")
def test_bfs_reach_finds_multistep_prefix(tmp_path):
    exe = _build(tmp_path)
    sinks = _system_call_sites(exe)
    assert sinks, "no system@plt call site found"

    navs = inject_stage._bfs_reach(str(exe), [b"1", b"2", b"3"], sinks, depth=3, cap=120)
    assert navs, "directed BFS did not reach the multi-step-gated sink"
    # The reaching prefix must UNLOCK before selecting the sink option -- a single step cannot.
    assert any(b"1\n" in n and b"2\n" in n for n in navs), f"navs: {navs}"
    assert b"2\n" not in [n for n in navs if n == b"2\n"]      # not the bare single-step nav


@pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("objdump")), reason="needs gcc + objdump")
def test_directed_reach_injection_confirms(tmp_path):
    exe = _build(tmp_path)
    sinks = _system_call_sites(exe)
    nav = inject_stage._bfs_reach(str(exe), [b"1", b"2", b"3"], sinks, depth=3, cap=120)[0]

    marker = "MK" + re.sub(r"\D", "", str(abs(hash(str(exe)))))[:6]
    confirmed = False
    for payload in injection.cmdi_payloads(marker):
        pl = payload if isinstance(payload, bytes) else payload.encode()
        res = sandbox.run(str(exe), argv=[], stdin=nav + pl + b"\n", timeout=5)
        out = (res.stdout or b"") + b"\n" + (res.stderr or b"")
        if injection.cmdi_confirm(out, pl.decode("latin-1"), marker):
            confirmed = True
            break
    assert confirmed, "the injected command did not run at the deep sink (forgery-proof marker)"
