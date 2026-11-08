"""PIE deep-reach to a NON-INJECTION sink via the two-stage runtime oracle (doc 58, reaching bridge).

A non-injection sink (a dangerous call, a memory-corruption site) behind multi-step state in a PIE
has no side-effect marker to confirm a reach, and the non-PIE breakpoint needs a fixed address ASLR
denies. `inject_stage.directed_reach_pie` drives menu-option sequences through
`detonate.reaches_runtime_address`, which leaks the PIE base from a pointer the target discloses
(page-offset matched by `exploit.recover_pie_base`), plants an INT3 at base+sink_offset, and confirms
a SIGTRAP at that runtime address -- control actually arrived at the sink under that preamble. The
reach is a search guide; the test pins soundness with a negative control (the locked path must not
reach).
"""
import shutil
import subprocess

import pytest

from lykos.analyze.poc import inject_stage, detonate

# PIE: leaks a CODE pointer at startup (defeats ASLR via recover_pie_base), then a dangerous sink
# strcpy() sits behind multi-step state -- option 1 sets `unlocked`, option 2 reaches strcpy only if
# unlocked. Option 2 alone hits the `locked` guard and never reaches the sink.
_FIXTURE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int unlocked = 0;
int main(void){
    char cmd[64], buf[128], dst[128];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    printf("main @ %p\n", (void*)main);              /* startup code-pointer leak */
    for (;;) {
        if (!fgets(cmd, sizeof cmd, stdin)) break;
        int c = atoi(cmd);
        if (c == 1) { unlocked = 1; puts("unlocked"); }
        else if (c == 2) { if (!fgets(buf, sizeof buf, stdin)) break;
            if (unlocked) strcpy(dst, buf);          /* SINK (CWE-120) behind multi-step state */
            else puts("locked"); }
        else if (c == 3) return 0;
    }
    return 0;
}
"""


def _build_pie(tmp_path):
    src = tmp_path / "pr.c"
    src.write_text(_FIXTURE)
    exe = tmp_path / "pr"
    r = subprocess.run(["gcc", "-fPIE", "-pie", "-fno-stack-protector", "-O0", "-w", "-o", str(exe),
                        str(src)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"PIE fixture build failed: {r.stderr[:200]}")
    exe.chmod(0o755)
    return exe


@pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("objdump")), reason="needs gcc + objdump")
def test_directed_reach_pie_nonsink_confirms(tmp_path):
    exe = _build_pie(tmp_path)
    tb = exe.read_bytes()
    offs = inject_stage._image_sink_offsets(str(exe), ["strcpy@plt", "strcpy"])
    if not offs:
        pytest.skip("no strcpy@plt call-site offset (sink inlined?)")

    navs = inject_stage.directed_reach_pie(str(exe), [b"1", b"2", b"3"], offs, tb,
                                           depth=2, cap=24, want=1)
    assert navs, "two-stage runtime oracle did not reach the multi-step-gated PIE sink"
    # The reaching prefix must UNLOCK (option 1) before selecting the sink option (2).
    assert any(b"1\n" in n and b"2\n" in n for n in navs), f"navs: {navs}"


@pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("objdump")), reason="needs gcc + objdump")
def test_pie_sink_negative_control_does_not_reach(tmp_path):
    # Soundness: the locked path (option 2 with no prior unlock) must NOT trip the runtime
    # breakpoint -- otherwise the oracle would confirm a reach that never happens.
    exe = _build_pie(tmp_path)
    tb = exe.read_bytes()
    offs = inject_stage._image_sink_offsets(str(exe), ["strcpy@plt", "strcpy"])
    if not offs:
        pytest.skip("no strcpy@plt call-site offset (sink inlined?)")
    reached, base = detonate.reaches_runtime_address(
        str(exe), win_off=offs[0], target_bytes=tb, make_payload=lambda b, rt: b"2\nx\n")
    # The base is still recoverable (the leak fires regardless), but control must not reach the sink.
    assert reached is False, "locked path falsely confirmed reaching the PIE sink"
