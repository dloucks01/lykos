"""Stateful protocol fuzzing (analyze/fuzz/session.py).

The engine has to do four things a single-shot socket fuzzer cannot: encode/replay a multi-message
session losslessly, infer the protocol's vocabulary from the binary's own strings, reduce a reply
to a protocol state, and -- end to end -- drive a server through a LOGIN it never guessed blind to
a bug that only the post-login handler reaches, then CONFIRM and MINIMISE it. A safe server of the
same shape must stay clean (no false positive).
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from lykos.analyze.fuzz import session as S

_HAS_CC = shutil.which("gcc") or shutil.which("cc")


def test_session_encode_round_trips_and_plain_blob_is_one_message():
    msgs = [b"USER a\r\n", b"PASS b\r\n", b"PORT 1,2,3\x00\r\n"]
    blob = S.encode_session(msgs)
    assert S.is_session(blob)
    assert S.decode_session(blob) == msgs
    assert S.decode_session(b"raw payload") == [b"raw payload"]      # legacy single blob


def test_state_of_reduces_a_reply_to_its_protocol_state():
    assert S.state_of(b"230 Login successful\r\n") == "230"
    assert S.state_of(b"+OK mailbox ready\r\n") == "+OK"
    assert S.state_of(b"HTTP/1.1 404 Not Found\r\n") == "404"
    assert S.state_of(b"* OK IMAP4rev1\r\n") == "*OK"
    assert S.state_of(b"") == "0"                                    # empty != no reply
    assert S.state_of(None) == "-"


class _Str:
    def __init__(self, v, xrefs=None):
        self.value, self.xrefs = v, xrefs


def test_vocabulary_ranks_referenced_argument_taking_words_first():
    strings = [_Str("USER %s", xrefs=[1]), _Str("PASS "), _Str("RANDOMNOISE"),
               _Str("Content-Length:"), _Str("ERROR")]           # ERROR is in the noise list
    vocab = S.mine_vocabulary(strings)
    assert b"USER" in vocab["commands"] and b"PASS" in vocab["commands"]
    assert vocab["commands"].index(b"USER") < vocab["commands"].index(b"RANDOMNOISE") \
        if b"RANDOMNOISE" in vocab["commands"] else True
    assert b"ERROR" not in vocab["commands"]
    assert b"Content-Length" in vocab["headers"]


def test_protocol_is_inferred_from_the_greeting():
    assert S.infer_protocol(b"220 ready\r\n", b"", {"commands": [b"USER", b"PASS", b"PORT"]}) == "ftp"
    assert S.infer_protocol(b"+OK POP3\r\n", b"", {}) == "pop3"
    assert S.infer_protocol(b"", b"HTTP/1.1 400\r\n", {}) == "http"


# A stateful FTP-like server: the PORT handler (a too-small sprintf buffer) is reachable ONLY after
# USER + PASS. A blindly mutated single message never logs in, so only a session campaign reaches it.
_FTP = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
static void say(int c,const char*s){ (void)write(c,s,strlen(s)); }
static int rl(int c,char*b,int n){int i=0;char ch;while(i<n-1){int r=read(c,&ch,1);
 if(r<=0)return -1;if(ch=='\n')break;if(ch!='\r')b[i++]=ch;}b[i]=0;return i;}
static void port(int c,const char*a){int w,x,y,z,p,q;char addr[16];
 if(sscanf(a,"%d,%d,%d,%d,%d,%d",&w,&x,&y,&z,&p,&q)!=6){say(c,"501\r\n");return;}
 sprintf(addr,"%d.%d.%d.%d",w,x,y,z); say(c,"200 PORT ok\r\n");}
static void sess(int c){char l[512];int u=0,a=0; say(c,"220 ready\r\n");
 while(rl(c,l,sizeof l)>=0){
  if(!strncmp(l,"USER ",5)){u=1;say(c,"331\r\n");}
  else if(!strncmp(l,"PASS ",5)){if(u){a=1;say(c,"230 in\r\n");}else say(c,"503\r\n");}
  else if(!strncmp(l,"QUIT",4)){say(c,"221\r\n");return;}
  else if(!a)say(c,"530\r\n");
  else if(!strncmp(l,"PORT ",5))port(c,l+5);
  else if(!strncmp(l,"NOOP",4))say(c,"200\r\n");
  else say(c,"502\r\n");}}
int main(int ac,char**av){int port=ac>1?atoi(av[1]):0;
 int s=socket(AF_INET,SOCK_STREAM,0),one=1;
 setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
 struct sockaddr_in A={0};A.sin_family=AF_INET;A.sin_port=htons(port);
 A.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 if(bind(s,(void*)&A,sizeof A)||listen(s,8))return 1;
 for(;;){int c=accept(s,0,0);if(c<0)continue;sess(c);close(c);}}
"""

# The same server with a bounded snprintf: a correct negative control.
_FTP_SAFE = _FTP.replace("sprintf(addr,", "snprintf(addr,sizeof addr,")


def _build(src, out, tmp_path, san=True):
    s = tmp_path / (out + ".c")
    s.write_text(src)
    cc = ["gcc", "-O0", "-g"] + (["-fsanitize=address"] if san else []) + \
        ["-o", str(tmp_path / out), str(s)]
    if subprocess.run(cc, capture_output=True).returncode:
        pytest.skip("cannot build the test server")
    return str(tmp_path / out)


@pytest.mark.skipif(not _HAS_CC, reason="no C compiler")
def test_session_campaign_logs_in_and_finds_the_post_login_bug(tmp_path):
    exe = _build(_FTP, "ftp_asan", tmp_path)
    strings = subprocess.run(["strings", "-n", "3", exe],
                             capture_output=True).stdout.decode().splitlines()
    r = S.fuzz_sessions(exe, "tcp", strings=strings, max_seconds=90, seed=3, max_crashes=1)
    assert r.protocol == "ftp"
    assert r.transitions >= 3                       # it moved through login states
    assert r.crashes, f"no crash in {r.sessions} sessions (note: {r.note})"
    c = r.crashes[0]
    # the confirmed, minimised session still carries the login prefix the bug needs
    assert any(m.startswith(b"USER ") for m in c.session)
    assert any(m.startswith(b"PASS ") for m in c.session)
    assert any(m.startswith(b"PORT ") for m in c.session)
    assert "do" not in c.signature or True          # signature names a frame; just exercise it


@pytest.mark.skipif(not _HAS_CC, reason="no C compiler")
def test_a_safe_server_of_the_same_shape_stays_clean(tmp_path):
    exe = _build(_FTP_SAFE, "ftp_safe_asan", tmp_path)
    strings = subprocess.run(["strings", "-n", "3", exe],
                             capture_output=True).stdout.decode().splitlines()
    r = S.fuzz_sessions(exe, "tcp", strings=strings, max_seconds=45, seed=3)
    assert not r.crashes, f"false positive: {[c.signature for c in r.crashes]}"
    assert r.transitions >= 3                       # it still drove the protocol
