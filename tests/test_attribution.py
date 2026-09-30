"""Attribution-graded proof oracle: a weaponized effect is credited only when the TARGET's own
process subtree emits it, and a shell/code-exec claim needs a forgery-proof marker an echoing
target cannot fake. Native x86-64 (the L3 confirm arch)."""
import shutil
import subprocess

import pytest
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import attribution as A
from lykos.analyze.poc import attribution_trace as T

pytestmark = pytest.mark.skipif(
    sandbox.host_arch() != "x86-64" or not shutil.which("gcc"),
    reason="attribution tracer + build are native x86-64 only")

_ECHOER = "#include <unistd.h>\nint main(){char b[256];ssize_t n;" \
          "while((n=read(0,b,sizeof b))>0)write(1,b,n);return 0;}\n"
_CMDINJ = "#include <stdlib.h>\n#include <unistd.h>\nint main(){char b[512];" \
          "ssize_t n=read(0,b,sizeof b-1);if(n>0){b[n]=0;system(b);}return 0;}\n"
_WIN = "#include <stdio.h>\n#include <string.h>\nint main(){char b[64];" \
       "if(fgets(b,sizeof b,stdin)){if(!strncmp(b,\"WIN\",3))puts(\"flag{ok}\");" \
       "else puts(\"nope\");}return 0;}\n"


def _build(tmp_path, src, name):
    c = tmp_path / f"{name}.c"; c.write_text(src)
    b = tmp_path / name
    if subprocess.run(["gcc", "-O0", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    return b


def _run(exe, data, tmp_path):
    f = tmp_path / "in.bin"; f.write_bytes(data)
    return T.trace(str(exe), [], str(f), 8)


def test_supported_is_x86_64():
    assert A.supported() is (sandbox.host_arch() == "x86-64")


def test_write_is_attributed_to_the_target_subtree(tmp_path):
    exe = _build(tmp_path, _ECHOER, "echoer")
    r = _run(exe, b"HELLO\n", tmp_path)
    assert r["ok"] and r["root"] > 0
    assert A.lineage_bytes(r) == b"HELLO\n"        # the target's own write
    assert not (r.get("foreign_writes"))           # nothing misattributed


def test_echo_cannot_forge_the_code_marker(tmp_path):
    """An input-reflecting target emits the RAW challenge, never its solved form -- so it tops
    out at output_attributed, never code_exec_proven."""
    exe = _build(tmp_path, _ECHOER, "echoer")
    m = A.make_code_markers()
    r = _run(exe, m.command + b"\n", tmp_path)
    assert m.raw in A.lineage_bytes(r) and m.solved not in A.lineage_bytes(r)
    g = A.grade(r, markers=m)
    assert g["level"] == "output_attributed"
    assert A.rank(g["level"]) < A.rank("code_exec_proven")


def test_command_execution_is_proven_and_attributed(tmp_path):
    """A shell that evaluates the marker (arithmetic + quote-strip) proves code exec; because the
    shell is an exec'd descendant of the target, it reaches shell_proven."""
    exe = _build(tmp_path, _CMDINJ, "cmdinj")
    m = A.make_code_markers()
    r = _run(exe, m.command + b"\n", tmp_path)
    assert m.solved in A.lineage_bytes(r)
    g = A.grade(r, markers=m)
    assert g["level"] in ("code_exec_proven", "shell_proven")
    assert A.rank(g["level"]) >= A.rank("code_exec_proven")


def test_win_token_needs_the_differential(tmp_path):
    """A win banner is credited only when it appears under the exploit input and NOT under a
    benign control -- so an unconditional printer is not mistaken for a hijack."""
    exe = _build(tmp_path, _WIN, "winbanner")
    hit = _run(exe, b"WIN\n", tmp_path)
    ctrl = _run(exe, b"xx\n", tmp_path)
    assert A.grade(hit, win_tokens=[b"flag{"], control=ctrl)["level"] == "win_attributed"
    # the control alone must NOT be credited as a win
    assert A.grade(ctrl, win_tokens=[b"flag{"], control=ctrl)["level"] == "output_attributed"


def test_a_win_printed_every_time_is_not_a_hijack(tmp_path):
    """If the banner shows for the control too, the differential withholds the win credit."""
    src = "#include <stdio.h>\nint main(){puts(\"flag{always}\");return 0;}\n"
    exe = _build(tmp_path, src, "always")
    hit = _run(exe, b"WIN\n", tmp_path)
    ctrl = _run(exe, b"xx\n", tmp_path)
    g = A.grade(hit, win_tokens=[b"flag{"], control=ctrl)
    assert g["level"] == "output_attributed"       # attributed, but not a differential win


def test_code_markers_reject_reflection():
    """The core anti-reflection property: a shell that evaluates the challenge is proven; a target
    that merely echoes the command (its raw form) is not -- closing the input-reflection cheat that
    a bare `marker in output` check falls for."""
    m = A.make_code_markers()
    assert m.proves(b"noise " + m.solved + b" more")        # a real shell evaluated it
    assert not m.proves(b"you sent: " + m.command)          # an echo reflects the raw command
    assert not m.proves(m.raw)                               # the unevaluated challenge alone
    assert not m.proves(b"")
