"""Network / socket fuzzing: detect a server, drive it over a socket, catch a crash.

The engine has to do three things right: recognise a server from its imports, discover the port
it ACTUALLY listens on (/proc/net is namespace-wide, so it filters by the process's own socket
inodes), and attribute a crash to the payload that preceded the server's death -- confirming it
reproduces before reporting.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

import pytest

from lykos.analyze.fuzz import netfuzz

_HAS_CC = shutil.which("gcc") or shutil.which("cc")


@dataclass
class _Edge:
    dst_name: str


def test_detect_tcp_server_from_listen():
    proto, ok = netfuzz.detect_server([_Edge("socket"), _Edge("bind"), _Edge("listen"),
                                       _Edge("accept")])
    assert ok and proto == "tcp"


def test_detect_udp_server_from_bind_recvfrom():
    proto, ok = netfuzz.detect_server([_Edge("socket"), _Edge("bind"), _Edge("recvfrom")])
    assert ok and proto == "udp"


def test_non_server_is_not_detected():
    _proto, ok = netfuzz.detect_server([_Edge("printf"), _Edge("malloc"), _Edge("read")])
    assert not ok


_VULN_SERVER = r"""
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
static void handle(int c){ char buf[32]; int n=read(c,buf,4096); if(n>0) write(c,"ok\n",3); }
int main(void){
    int s=socket(AF_INET,SOCK_STREAM,0); int one=1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(0);
    a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(s,(void*)&a,sizeof a); listen(s,4);
    for(;;){ int c=accept(s,0,0); if(c<0) continue; handle(c); close(c); }
}
"""


@pytest.mark.skipif(not _HAS_CC, reason="no C compiler to build the test server")
def test_fuzz_server_finds_and_confirms_a_tcp_crash(tmp_path):
    src = tmp_path / "srv.c"
    src.write_text(_VULN_SERVER)
    exe = tmp_path / "srv"
    cc = shutil.which("gcc") or shutil.which("cc")
    r = subprocess.run([cc, "-O0", "-g", "-fno-stack-protector", str(src), "-o", str(exe)],
                       capture_output=True)
    assert r.returncode == 0, r.stderr.decode()[:400]

    res = netfuzz.fuzz_server(str(exe), "tcp", max_execs=200, listen_timeout=5)
    assert res.crashed, f"did not crash the vulnerable server (note={res.note})"
    assert res.signal_name == "SIGSEGV"
    assert res.payload and len(res.payload) >= 32          # the overflowing payload
    assert res.port and res.port > 0                       # discovered the real listening port


@pytest.mark.skipif(not _HAS_CC, reason="no C compiler to build the test server")
def test_a_safe_echo_server_does_not_crash(tmp_path):
    src = tmp_path / "echo.c"
    src.write_text(r"""
#include <unistd.h>
#include <arpa/inet.h>
int main(void){
    int s=socket(AF_INET,SOCK_STREAM,0); int one=1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(0);
    a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(s,(void*)&a,sizeof a); listen(s,4);
    for(;;){ int c=accept(s,0,0); if(c<0) continue; char b[4096];
             int n=read(c,b,sizeof b); if(n>0) write(c,b,n); close(c); }
}
""")
    exe = tmp_path / "echo"
    cc = shutil.which("gcc") or shutil.which("cc")
    subprocess.run([cc, "-O0", str(src), "-o", str(exe)], capture_output=True, check=True)
    res = netfuzz.fuzz_server(str(exe), "tcp", max_execs=150, listen_timeout=5)
    assert not res.crashed
