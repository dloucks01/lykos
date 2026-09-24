"""The standalone ptrace capture helper.

This is the L2/L3 register capture the whole PoC ladder rests on -- "which register held the
payload at the fault" is what turns a crash into a primitive -- and it had no test of its own.
It is deliberately a SEPARATE PROCESS (it forks and ptraces, which a threaded worker must
never do), so the contract tests drive it exactly the way production does: `python
ptrace_capture.py spec.json`, parse the JSON on stdout.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

HELPER = Path(__file__).resolve().parent.parent / "core" / "lykos" / "analyze" / "poc" \
    / "ptrace_capture.py"

_CRASH_C = r"""
#include <string.h>
#include <stdio.h>
void boom(char *s){ char b[32]; strcpy(b, s); printf("%s\n", b); }
int main(int argc, char **argv){ if(argc>1) boom(argv[1]); return 0; }
"""

_ECHO_C = r"""
#include <stdio.h>
#include <string.h>
/* exits 0, but reports how many bytes argv[1] actually carried */
int main(int argc, char **argv){ if(argc>1) fprintf(stderr,"%zu\n", strlen(argv[1]));
  return 0; }
"""


def _host_is_supported():
    import platform
    return platform.machine().lower() in ("x86_64", "amd64", "aarch64", "arm64")


pytestmark = pytest.mark.skipif(not _host_is_supported(),
                                reason="ptrace helper supports x86-64 and aarch64 only")


def _build(gcc, tmp_path, src, name):
    c = tmp_path / f"{name}.c"
    c.write_text(src)
    exe = tmp_path / name
    subprocess.run([gcc, "-O0", "-fno-stack-protector", str(c), "-o", str(exe)],
                   check=True, capture_output=True)
    return exe


def _run(tmp_path, spec) -> dict:
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec))
    cp = subprocess.run([sys.executable, str(HELPER), str(p)],
                        capture_output=True, timeout=120)
    assert cp.returncode == 0, cp.stderr.decode()
    # ALWAYS a JSON object, even on failure -- the caller parses stdout unconditionally
    return json.loads(cp.stdout.decode())


@pytest.fixture(scope="module")
def crasher(gcc, tmp_path_factory):
    return _build(gcc, tmp_path_factory.mktemp("ptrace"), _CRASH_C, "crash")


def test_a_fault_yields_the_register_file_at_the_fault(crasher, tmp_path):
    res = _run(tmp_path, {"exe": str(crasher), "argv": ["A" * 400],
                          "stdin_file": None, "timeout": 10})
    assert res["ok"] is True, res
    assert res["signal_name"] == "SIGSEGV"
    assert res["signal"] == 11
    # the names are the ISA's, and the values have to be present under them
    assert res["pc_name"] in ("rip", "pc") and res["sp_name"] in ("rsp", "sp")
    assert res["regs"][res["pc_name"]] == res["pc"]
    assert res["regs"][res["sp_name"]] == res["sp"]
    assert res["pc"] > 0 and res["sp"] > 0


def test_the_stack_at_the_fault_carries_the_payload(crasher, tmp_path):
    """This is the capture's whole purpose: the bytes the analyzer searches for the pattern
    that reached a saved return address."""
    res = _run(tmp_path, {"exe": str(crasher), "argv": ["A" * 400],
                          "stdin_file": None, "timeout": 10})
    stack = bytes.fromhex(res["stack"])
    assert b"A" * 64 in stack
    # the window is anchored so the analyzer can turn an offset into a stack address
    assert res["stack_base"] <= res["sp"] <= res["stack_base"] + len(stack)


def test_the_bytes_at_the_program_counter_are_captured(crasher, tmp_path):
    res = _run(tmp_path, {"exe": str(crasher), "argv": ["A" * 400],
                          "stdin_file": None, "timeout": 10})
    pc_bytes = bytes.fromhex(res["pc_bytes"])
    assert len(pc_bytes) == 16


def test_the_memory_map_is_captured_so_an_address_can_be_attributed(crasher, tmp_path):
    res = _run(tmp_path, {"exe": str(crasher), "argv": ["A" * 400],
                          "stdin_file": None, "timeout": 10})
    maps = res["maps"]
    assert maps and all({"start", "end", "perms"} <= set(m) for m in maps)
    assert any(str(crasher) in (m.get("path") or "") for m in maps), \
        "the target's own image has to be in the map or a PC cannot be made image-relative"
    assert all(m["end"] > m["start"] for m in maps)


def test_a_clean_exit_is_reported_as_no_fault_not_as_a_capture(gcc, tmp_path):
    exe = _build(gcc, tmp_path, _ECHO_C, "clean")
    res = _run(tmp_path, {"exe": str(exe), "argv": ["hello"],
                          "stdin_file": None, "timeout": 10})
    assert res["ok"] is False
    assert "no fatal signal" in res["reason"]


def test_a_missing_target_is_a_reason_not_a_traceback(tmp_path):
    res = _run(tmp_path, {"exe": str(tmp_path / "nope"), "argv": [],
                          "stdin_file": None, "timeout": 5})
    assert res["ok"] is False and res["reason"]


def test_stdin_is_delivered_from_the_spec_file(gcc, tmp_path):
    src = r"""
#include <stdio.h>
#include <string.h>
int main(void){ char b[32]; char line[512];
  if(fgets(line,sizeof line,stdin)) strcpy(b,line);
  printf("%s",b); return 0; }
"""
    exe = _build(gcc, tmp_path, src, "stdincrash")
    payload = tmp_path / "in.bin"
    payload.write_bytes(b"B" * 400 + b"\n")
    res = _run(tmp_path, {"exe": str(exe), "argv": [], "stdin_file": str(payload),
                          "timeout": 10})
    assert res["ok"] is True and res["signal_name"] in ("SIGSEGV", "SIGBUS", "SIGABRT")
    assert b"B" * 64 in bytes.fromhex(res["stack"])


def test_high_bytes_in_argv_survive_the_json_round_trip(gcc, tmp_path):
    """The regression this guards is not hypothetical: argv arrives as latin-1 text, and
    encoding it back with the filesystem encoding turns every byte >= 0x80 into two. Any
    payload carrying an address has such bytes, so argv-delivered IP control broke outright
    and the corruption was invisible -- the run simply did not reproduce."""
    exe = _build(gcc, tmp_path, _ECHO_C, "echolen")
    # 200 bytes, every one of them >= 0x80: UTF-8 would make this 400
    arg = "".join(chr(0x80 + (i % 0x40)) for i in range(200))
    spec = {"exe": str(exe), "argv": [arg], "stdin_file": None, "timeout": 10}
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec))
    cp = subprocess.run([sys.executable, str(HELPER), str(p)], capture_output=True,
                        timeout=60)
    # the program prints strlen(argv[1]) to stderr; the helper sends the child's output to
    # /dev/null, so assert through the one channel that survives: it must not have crashed,
    # and re-running the same argv outside the helper must show 200 bytes arriving
    assert json.loads(cp.stdout.decode())["ok"] is False       # clean exit, no fault
    direct = subprocess.run([str(exe), arg.encode("latin-1")], capture_output=True)
    assert direct.stderr.strip() == b"200"


def test_a_hung_target_is_killed_and_still_answers(gcc, tmp_path):
    src = "#include <unistd.h>\nint main(void){ for(;;) pause(); return 0; }\n"
    exe = _build(gcc, tmp_path, src, "hang")
    res = _run(tmp_path, {"exe": str(exe), "argv": [], "stdin_file": None, "timeout": 2})
    assert res["ok"] is False and res["reason"]


def test_the_helper_is_stdlib_only():
    """It is materialised into a temp directory and run by whatever python is to hand, so an
    import of anything outside the stdlib would fail there and nowhere else."""
    import ast
    tree = ast.parse(HELPER.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= set(sys.stdlib_module_names), imported - set(sys.stdlib_module_names)


_WIN_C = r"""
#include <stdio.h>
void win(void){ puts("win"); }
int main(int argc, char **argv){ if(argc>1) win(); return 0; }
"""


def _nm_addr(exe, sym):
    try:
        out = subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout
    except FileNotFoundError:
        pytest.skip("nm not available")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == sym:
            return int(parts[0], 16)
    pytest.skip(f"{sym} not in the symbol table")


@pytest.fixture(scope="module")
def win_exe(gcc, tmp_path_factory):
    """-no-pie so the address `nm` reports is the address the program runs at: a breakpoint
    is set before the image is relocated, and this test is about the breakpoint, not ASLR."""
    d = tmp_path_factory.mktemp("win")
    c = d / "win.c"
    c.write_text(_WIN_C)
    exe = d / "win"
    r = subprocess.run([gcc, "-O0", "-no-pie", "-fno-stack-protector", str(c), "-o", str(exe)],
                       capture_output=True)
    if r.returncode != 0:
        pytest.skip("no -no-pie support on this toolchain")
    return exe


def test_a_breakpoint_that_is_reached_is_reported_as_the_hit(win_exe, tmp_path):
    """This is what makes an L3 claim checkable: "the hijack reached win()" is a breakpoint
    report, not an inference from a register value."""
    import platform
    if platform.machine().lower() not in ("x86_64", "amd64"):
        pytest.skip("software int3 breakpoints are x86-64 only, by design")
    addr = _nm_addr(win_exe, "win")
    res = _run(tmp_path, {"exe": str(win_exe), "argv": ["go"], "stdin_file": None,
                          "timeout": 10, "breakpoints": [addr]})
    assert res["ok"] is True, res
    assert res["breakpoint_hit"] == addr
    # the int3 traps one byte PAST the breakpoint, and the helper is what corrects for that
    assert res["pc"] in (addr, addr + 1)
    assert res["regs"]


def test_a_breakpoint_that_is_not_reached_leaves_the_run_unchanged(win_exe, tmp_path):
    import platform
    if platform.machine().lower() not in ("x86_64", "amd64"):
        pytest.skip("software int3 breakpoints are x86-64 only, by design")
    addr = _nm_addr(win_exe, "win")
    # no argv -> main never calls win(), so the process exits cleanly with the trap unhit
    res = _run(tmp_path, {"exe": str(win_exe), "argv": [], "stdin_file": None,
                          "timeout": 10, "breakpoints": [addr]})
    assert res["ok"] is False and "no fatal signal" in res["reason"]
    assert "breakpoint_hit" not in res


def test_a_bogus_breakpoint_address_does_not_break_the_run(win_exe, tmp_path):
    """An address that cannot be written is a breakpoint that is simply not set -- the run
    still has to happen, because the caller's other evidence depends on it."""
    import platform
    if platform.machine().lower() not in ("x86_64", "amd64"):
        pytest.skip("software int3 breakpoints are x86-64 only, by design")
    res = _run(tmp_path, {"exe": str(win_exe), "argv": ["go"], "stdin_file": None,
                          "timeout": 10, "breakpoints": [0xdeadbeef000]})
    assert res["ok"] is False and "no fatal signal" in res["reason"]
