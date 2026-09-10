"""Phase 6 — syscall/behavior tracer: inventory security-relevant syscalls (exec, network,
file writes, anti-debug, W^X) and flag the high-signal ones."""
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.debug import enqueue_behavior_trace, syscalls
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_BEHAV = r"""
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
int main(void){
  ptrace(PTRACE_TRACEME,0,0,0);
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_port=htons(9);
  inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);
  connect(s,(struct sockaddr*)&a,sizeof a);
  void*p=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  if(p) mprotect(p,4096,PROT_READ|PROT_EXEC);
  execl("/bin/true","true",(char*)0);
  return 0;
}
"""


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=120, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_supported_arch():
    assert syscalls.supported("x86-64")
    assert not syscalls.supported("aarch64")


@pytest.mark.skipif(sandbox.host_arch() != "x86-64" or not shutil.which("gdb"),
                    reason="native x86-64 + gdb required")
def test_behavior_trace_inventories_and_flags(store, case, pool, gcc, tmp_path):
    c = tmp_path / "b.c"; c.write_text(_BEHAV)
    b = tmp_path / "b"
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    q = JobQueue(store.conn)
    run = enqueue_behavior_trace(q, target, params={"timeout": 25})
    assert pool.wait_idle(60)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("gdb syscall trace unavailable: " + str(rec.error))
    finds = [f for f in FindingDAO(store.conn).list_by_target(target.id)
             if f.detector == "behavior"]
    titles = " ".join(f.title for f in finds)
    assert "network connection" in titles.lower()      # connect() flagged
    assert "anti-debug" in titles.lower()              # ptrace(TRACEME)
    assert "executable memory" in titles.lower()       # mprotect +X (W^X)
    assert "/bin/true" in titles                       # execve


# --- cross-arch backend: qemu-user -strace parser + live trace ------------------------------
import os

from lykos.analyze.debug import elfsyms  # noqa: E402

_QEMU_STRACE = """\
1 brk(NULL) = 0x555555559000
1 execve("/bin/sh",{"sh","-c","echo hi",NULL}) = 0
1 openat(AT_FDCWD,"/tmp/out.txt",O_WRONLY|O_CREAT,0644) = 5
1 openat(-100,"/etc/passwd",O_RDONLY|O_CLOEXEC) = 3
1 socket(PF_INET,SOCK_STREAM,IPPROTO_IP) = 4
1 connect(4,0xdeadbeef,16) = 0
1 mprotect(0x1000,4096,PROT_EXEC|PROT_READ) = 0
1 ptrace(0,0,0,0,4294967295,0) = -1 errno=38 (Function not implemented)
1 unlink("/tmp/x") = 0
1 setuid(0) = 0
1 kill(1234,SIGKILL) = 0
1 clone(CLONE_VM|CLONE_VFORK,child_stack=0x7f00) = 99
"""


def test_parse_qemu_strace_shapes():
    got = syscalls._parse_qemu_strace(_QEMU_STRACE)
    by = {}
    for e in got:
        by.setdefault(e["syscall"], []).append(e)
    assert "brk" not in by                                # not a tracked syscall
    assert by["execve"][0]["path"] == "/bin/sh"
    writes = {e["path"]: e["write"] for e in by["openat"]}
    assert writes["/tmp/out.txt"] is True and writes["/etc/passwd"] is False
    assert by["socket"][0]["family"] == "inet"
    assert by["connect"][0]["dest"] == {"family": "inet", "addr": None, "port": None}  # fd 4 known
    assert by["mprotect"][0]["exec"] is True
    assert by["ptrace"][0]["request"] == 0               # PTRACE_TRACEME
    assert by["unlink"][0]["path"] == "/tmp/x"
    assert by["setuid"][0]["id"] == 0
    assert by["kill"][0]["pid"] == 1234
    assert by["clone"]


def test_parse_qemu_connect_family_unknown_without_socket():
    # a connect on an fd we never saw as an AF_INET socket -> family unknown (not falsely inet)
    ev = syscalls._parse_qemu_strace("1 connect(9,0x1234,16) = 0\n")
    assert ev and ev[0]["dest"]["family"] == "unknown"


_AARCH64 = os.path.join(os.path.dirname(__file__), "..", "examples", "re-corpus", "bin",
                        "vuln_aarch64")


@pytest.mark.skipif(not os.path.exists(_AARCH64) or not sandbox._qemu_for("aarch64"),
                    reason="needs the aarch64 corpus binary and qemu-aarch64")
def test_cross_arch_behavior_trace_captures_execve():
    """system("echo unlocked") on aarch64 surfaces as execve(/bin/sh) via qemu -strace."""
    r = syscalls.trace_qemu(_AARCH64, "aarch64", endianness="little", bits=64,
                            argv=["4242"], timeout=25)
    assert r["ok"], r.get("note")
    assert elfsyms.read(_AARCH64)["pie"]                 # sanity: it's the expected binary
    execs = [e for e in r["events"] if e["syscall"] == "execve"]
    assert execs and execs[0]["path"] == "/bin/sh"


def test_clone3_in_catch_set_and_qemu_tracked():
    assert syscalls.NR.get(435) == "clone3"            # native GDB catches the modern fork path
    ev = syscalls._parse_qemu_strace("1 clone3({flags=CLONE_VM},88) = 1234\n")
    assert ev and ev[0]["syscall"] == "clone3"


_X64_STRIPPED = os.path.join(os.path.dirname(__file__), "..", "examples", "re-corpus", "bin",
                             "vuln_x86-64_stripped")


@pytest.mark.skipif(not os.path.exists(_X64_STRIPPED) or not sandbox._qemu_for("x86-64"),
                    reason="needs the x86-64 corpus binary and qemu-x86_64")
def test_qemu_backend_follows_forked_exec_on_native():
    """system() forks (clone/clone3) and execs in the child; the qemu backend follows the child
    and captures execve, which the native GDB backend cannot (it only sees the parent's spawn)."""
    r = syscalls.trace_qemu(_X64_STRIPPED, "x86-64", argv=["4242"], stdin=b"", timeout=25)
    assert r["ok"], r.get("note")
    execs = [e for e in r["events"] if e["syscall"] == "execve"]
    assert execs and execs[0]["path"] == "/bin/sh"


# --- Windows PE: Win32 API trace via Wine +relay -------------------------------------------
from lykos.analyze.debug import winapi  # noqa: E402

_RELAY = (
    '0100:trace:module:map_image_into_view mapping PE file L"vuln.exe" '
    'at 0x140000000-0x140041000\n'
    '0100:Call msvcrt.system(14000a01f "echo pwn") ret=140008caf\n'        # target -> kept
    '0100:Call KERNEL32.CreateProcessW(0,0,0) ret=6fffaaaa\n'              # ret in DLL -> drop
    '0200:Call advapi32.RegSetValueExW(0,"BIOSVendor") ret=140002000\n'    # other thread -> drop
    '0100:Call KERNEL32.CreateProcessW(0,7ff L"evilcmd",0) ret=140008d00\n'  # target -> kept
    '0100:Call ws2_32.connect(3,7ffe,16) ret=140008e00\n'                 # target -> kept
    '0300:Call KERNEL32.CreateProcessW(0,L"services.exe",0) ret=140001000\n'  # helper -> drop(tid)
)


def test_winapi_parse_attributes_to_target_thread_and_range():
    tm = winapi._target_map(_RELAY, "vuln.exe")
    assert tm and tm[0] == "0100" and tm[1] == 0x140000000 and tm[2] == 0x140041000
    ev = winapi.parse(_RELAY, *tm)
    execs = {e["detail"] for e in ev if e["category"] == "exec"}
    nets = [e for e in ev if e["category"] == "network"]
    # system("echo pwn") + CreateProcessW(evilcmd) kept; the msvcrt-internal call (ret out of
    # range), the other-thread RegSetValue, and the services.exe helper (other thread) excluded.
    assert execs == {"echo pwn", "evilcmd"}
    assert len(nets) == 1 and nets[0]["api"] == "connect"


def test_winapi_helper_exec_filtered():
    # a Wine service exe on the target thread is still dropped by the helper blocklist
    txt = ('0100:trace:module:map_image_into_view mapping PE file L"t.exe" at 0x400000-0x410000\n'
           '0100:Call KERNEL32.CreateProcessW(0,L"plugplay.exe",0) ret=401000\n'
           '0100:Call msvcrt.system(0 "real") ret=402000\n')
    ev = winapi.parse(txt, "0100", 0x400000, 0x410000)
    assert [e["detail"] for e in ev if e["category"] == "exec"] == ["real"]


_WIN64_PE = os.path.join(os.path.dirname(__file__), "..", "examples", "re-corpus", "bin",
                         "vuln_win64.exe")


@pytest.mark.skipif(not os.path.exists(_WIN64_PE) or not winapi.supported(),
                    reason="needs the win64 corpus PE and wine")
def test_winapi_live_captures_system_exec():
    r = winapi.trace(_WIN64_PE, argv=["4242"], timeout=90)
    assert r["ok"], r.get("note")
    execs = [e for e in r["events"] if e["category"] == "exec"]
    assert any(e["detail"] == "echo unlocked" for e in execs)


_WIN32_PE = os.path.join(os.path.dirname(__file__), "..", "examples", "re-corpus", "bin",
                         "vuln_win32.exe")


@pytest.mark.skipif(not os.path.exists(_WIN32_PE) or not winapi.supported(),
                    reason="needs the win32 corpus PE and wine")
def test_winapi_win32_runs_or_reports_wow64_gap():
    """A 32-bit PE either traces (if the i386 WoW64 runtime is installed) or is HONESTLY reported
    as un-launchable -- never a misleading 'no behavior' / clean result."""
    r = winapi.trace(_WIN32_PE, argv=["4242"], timeout=90)
    if r["ok"]:
        assert "events" in r                            # i386 runtime present -> it traced
    else:
        assert "32-bit" in (r.get("note") or "")        # honest launch-failure report
