"""Stateful protocol fuzzing: drive a network server through multi-message SESSIONS.

`netfuzz.fuzz_server` sends ONE blind payload per connection. That reaches a server's first
parser and nothing behind it: an FTP server's `PORT` handler only runs after `USER` + `PASS`, an
SMTP server's `DATA` parser only after `HELO`/`MAIL`/`RCPT`, and a mutated single message never
gets past the login. Measured on FreeRDP: 7 harnesses, 0 PoCs -- every bug sat behind a handshake.

This engine is the AFLNet idea, built for lykos's constraints (air-gapped, any binary):

  * A SESSION is a list of messages delivered in order over one connection (or one datagram each
    for UDP), reading the server's response between them.
  * Feedback is two signals. CODE COVERAGE comes from an AFL shared-memory map the server writes
    into while it keeps running -- an AFL-instrumented build natively, any other binary of the
    host architecture under `afl-qemu-trace` -- reset before and read after every session, so it
    is per session even though the process is not restarted. PROTOCOL STATE comes from the
    responses: each reply is reduced to a status code ("230", "HTTP 404", "+OK"), and a session
    that produces a state TRANSITION never seen before is kept even without new code coverage
    (a successful login looks like very little new code and is the most important thing a
    session can do).
  * Seeds come from the protocol the server SPEAKS, inferred from its greeting / its answer to a
    probe / the command words compiled into it -- not from a hand-picked list per product.
  * Mutation keeps the session's PREFIX intact (the login that got it there) and mutates one
    message, with text-aware operators for line protocols (an argument becomes a 4 KiB string,
    a format specifier, a boundary integer) alongside byte havoc, plus structural operators
    (insert a known command, duplicate, drop, splice two sessions).
  * The oracle is the server's own death (a fatal signal) AND its stderr: a forking server's
    crashed CHILD never kills the parent, but its sanitizer report -- or, for an uninstrumented
    binary, the fault line of a tiny preloaded handler -- lands on the shared stderr.
  * A crash is CONFIRMED by replaying the whole session against a fresh server, then minimised
    (messages the crash does not need are dropped), before it is reported. 0 false positives is
    the rule: an unconfirmed crash is never returned.

A session is stored as a single blob (`encode_session`) so it rides through the content store,
DynResult rows and PoC bundles exactly like any other crashing input; `decode_session` turns a
plain (non-session) blob into a one-message session, so every older socket crash still replays.
"""
from __future__ import annotations

import ctypes
import logging
import os
import random
import re
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from ... import observe
from ..dynamic import sandbox
from .mutator import Mutator

_log = logging.getLogger(__name__)

SESSION_MAGIC = b"LYKOS-SESSION/1\n"


# --------------------------------------------------------------------------- session encoding

def encode_session(msgs) -> bytes:
    """One blob for a list of messages: the magic line, then `<len>\\n<bytes>` per message."""
    out = bytearray(SESSION_MAGIC)
    for m in msgs:
        m = bytes(m)
        out += b"%d\n" % len(m) + m
    return bytes(out)


def is_session(blob: bytes) -> bool:
    return bool(blob) and bytes(blob[:len(SESSION_MAGIC)]) == SESSION_MAGIC


def decode_session(blob: bytes) -> list:
    """The messages of an encoded session; a plain blob is a one-message session."""
    blob = bytes(blob or b"")
    if not is_session(blob):
        return [blob]
    msgs, i = [], len(SESSION_MAGIC)
    while i < len(blob):
        j = blob.index(b"\n", i)
        n = int(blob[i:j])
        msgs.append(blob[j + 1:j + 1 + n])
        i = j + 1 + n
    return msgs


# --------------------------------------------------------------------------- coverage map

_MAP_SIZE = 1 << 18
# AFL's hit-count buckets: a loop that ran 4 times and one that ran 40 are different behaviour,
# 40 and 41 are not. Each bucket is one bit so a byte-wise OR merges them.
_BUCKET = bytes([0, 1, 2, 4, 8, 8, 8, 8] + [16] * 8 + [32] * 16 + [64] * 96 + [128] * 128)
_NONZERO = bytes([0] + [1] * 255)


class CoverageMap:
    """A System V shared-memory AFL map the server writes into (`__AFL_SHM_ID`).

    The server is NOT restarted per session, so the map is zeroed before every session and read
    after it: what is in it is that session's coverage alone. `seen` is the union, bucketed."""

    def __init__(self, size: int = _MAP_SIZE):
        self.size = size
        self._libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self._libc.shmat.restype = ctypes.c_void_p
        self._libc.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        self._libc.shmdt.argtypes = [ctypes.c_void_p]
        self.id = self._libc.shmget(0, size, 0o1000 | 0o600)     # IPC_PRIVATE | IPC_CREAT
        if self.id < 0:
            raise OSError(ctypes.get_errno(), "shmget failed")
        addr = self._libc.shmat(self.id, None, 0)
        if addr in (None, ctypes.c_void_p(-1).value):
            self._rm()
            raise OSError(ctypes.get_errno(), "shmat failed")
        self._addr = addr
        self._buf = (ctypes.c_ubyte * size).from_address(addr)
        self.seen = 0
        self._nz = 0
        self.edges = 0

    def env(self) -> dict:
        return {"__AFL_SHM_ID": str(self.id), "AFL_MAP_SIZE": str(self.size)}

    def reset(self) -> None:
        ctypes.memset(self._addr, 0, self.size)

    def collect(self) -> int:
        """Merge the map into `seen`; return how many NEW (edge, bucket) bits it contributed."""
        raw = bytes(self._buf)
        cur = int.from_bytes(raw.translate(_BUCKET), "little")
        new = cur & ~self.seen
        if new:
            self.seen |= cur
            self._nz |= int.from_bytes(raw.translate(_NONZERO), "little")
            self.edges = self._nz.bit_count()
        return new.bit_count()

    def _rm(self) -> None:
        try:
            self._libc.shmctl(self.id, 0, None)                   # IPC_RMID
        except Exception:                                         # noqa: BLE001
            observe.absorbed(_log, "shm removal is best effort")

    def close(self) -> None:
        try:
            self._libc.shmdt(ctypes.c_void_p(self._addr))
        except Exception:                                         # noqa: BLE001
            observe.absorbed(_log, "shm detach is best effort")
        self._rm()


def afl_instrumented(exe) -> bool:
    """Was this binary built by afl-cc (it reads `__AFL_SHM_ID` itself)?"""
    try:
        with open(exe, "rb") as fh:
            return b"__AFL_SHM_ID" in fh.read()
    except OSError:
        return False


def coverage_launch(exe, arch: "str | None" = None):
    """(launch_prefix, kind) to run `exe` so it reports coverage into a CoverageMap.

    kind 'afl': an afl-cc build, run natively. kind 'qemu': any other binary of an architecture an
    afl-qemu-trace on this host emulates. (None, None) when neither is available -- the campaign
    then runs on protocol-state feedback alone, and says so."""
    if afl_instrumented(exe):
        return [], "afl"
    if sandbox._is_sanitizer_exe(exe):
        return None, None                 # ASan's shadow mapping does not survive qemu-user
    try:
        from . import aflpp
        trace = aflpp.locate_qemu_trace_for(aflpp.locate_afl(), arch or sandbox.host_arch())
    except Exception:                                             # noqa: BLE001
        trace = None
    if trace:
        return [str(trace)], "qemu"
    return None, None


# --------------------------------------------------------------------------- fault oracle

#: What a crashed process leaves on stderr when it does not take the server down with it (a
#: forked worker): a sanitizer report, glibc's own aborts, or our preloaded handler's line.
_FAULT_MARKERS = (
    re.compile(rb"ERROR: AddressSanitizer: ([\w-]+)"),
    re.compile(rb"ERROR: (?:Leak|Memory|Thread)Sanitizer: ([\w-]+)"),
    re.compile(rb"runtime error: ([^\n]{0,80})"),
    re.compile(rb"LYKOS-FAULT sig=(\d+)"),
    re.compile(rb"\*\*\* (stack smashing detected|buffer overflow detected) \*\*\*"),
    re.compile(rb"(free\(\): invalid pointer|double free or corruption|malloc\(\): [\w ]+)"),
)

_FAULT_SHIM = r"""
#define _GNU_SOURCE
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <ucontext.h>
static void h(int s, siginfo_t *si, void *uc) {
    char b[160]; int n = 0; unsigned long pc = 0;
#if defined(__x86_64__)
    pc = ((ucontext_t *)uc)->uc_mcontext.gregs[REG_RIP];
#elif defined(__aarch64__)
    pc = ((ucontext_t *)uc)->uc_mcontext.pc;
#endif
    const char *p = "LYKOS-FAULT sig="; while (*p) b[n++] = *p++;
    char t[24]; int k = 0; int v = s; do { t[k++] = '0' + v % 10; v /= 10; } while (v);
    while (k) b[n++] = t[--k];
    p = " pc=0x"; while (*p) b[n++] = *p++;
    for (int i = 60; i >= 0; i -= 4) b[n++] = "0123456789abcdef"[(pc >> i) & 15];
    p = " addr=0x"; while (*p) b[n++] = *p++;
    unsigned long a = (unsigned long)si->si_addr;
    for (int i = 60; i >= 0; i -= 4) b[n++] = "0123456789abcdef"[(a >> i) & 15];
    b[n++] = '\n'; write(2, b, n);
    signal(s, SIG_DFL); raise(s);
}
__attribute__((constructor)) static void lykos_fault_init(void) {
    static char stk[65536]; stack_t ss = { .ss_sp = stk, .ss_size = sizeof stk };
    sigaltstack(&ss, 0);
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = h; sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
    int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT };
    for (unsigned i = 0; i < sizeof sigs / sizeof *sigs; i++) sigaction(sigs[i], &sa, 0);
}
"""


def fault_shim(dest_dir) -> "str | None":
    """Build the preloaded fault reporter into `dest_dir` (visible inside the sandbox) and return
    its path, or None when no compiler is available. Only for an uninstrumented NATIVE server:
    a sanitizer build reports for itself and must not have its handlers replaced."""
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        return None
    out = Path(dest_dir) / "lykos-faultlog.so"
    if out.exists():
        return str(out)
    src = Path(tempfile.mkdtemp(prefix="lykos-shim-")) / "f.c"
    try:
        src.write_text(_FAULT_SHIM)
        r = subprocess.run([cc, "-shared", "-fPIC", "-O1", "-o", str(out), str(src)],
                           capture_output=True, timeout=60)
        return str(out) if r.returncode == 0 and out.exists() else None
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        shutil.rmtree(src.parent, ignore_errors=True)


def fault_in(stderr: bytes) -> "str | None":
    """The class of a fault reported on stderr, or None."""
    for rx in _FAULT_MARKERS:
        m = rx.search(stderr or b"")
        if m:
            g = m.group(1).decode("latin-1", "replace").strip()
            if rx.pattern.startswith(b"LYKOS-FAULT"):
                try:
                    import signal as _sig
                    return _sig.Signals(int(g)).name
                except (ValueError, KeyError):
                    return f"signal {g}"
            return g
    return None


_FRAME0 = re.compile(rb"#0 0x[0-9a-f]+ in (\S+)(?: (\S+?):(\d+))?")
_FIRST_APP_FRAME = re.compile(rb"#\d+ 0x[0-9a-f]+ in (\S+) (/\S+?):(\d+)")


def crash_signature(stderr: bytes, signal_name: "str | None") -> str:
    """A stable identity for a crash, so keep-going reports DISTINCT defects: the sanitizer class
    plus the first frame that names a source line, else the class/signal alone."""
    cls = fault_in(stderr) or signal_name or "crash"
    m = _FIRST_APP_FRAME.search(stderr or b"")
    if m and b"/sanitizer_common/" not in m.group(2) and b"/asan/" not in m.group(2):
        return f"{cls}@{m.group(1).decode('latin-1')}"
    m = _FRAME0.search(stderr or b"")
    if m:
        return f"{cls}@{m.group(1).decode('latin-1')}"
    m = re.search(rb"LYKOS-FAULT sig=\d+ pc=0x([0-9a-f]+)", stderr or b"")
    if m:
        return f"{cls}@pc+{int(m.group(1), 16) & 0xfff:03x}"
    return cls


# --------------------------------------------------------------------------- protocol state

_STATE_RX = (
    (re.compile(rb"^(?:HTTP|RTSP|SIP)/\d(?:\.\d)? (\d{3})"), "{}"),
    (re.compile(rb"^(\d{3})[ -]"), "{}"),
    (re.compile(rb"^([+-](?:OK|ERR))"), "{}"),
    (re.compile(rb"^\* (OK|NO|BAD|PREAUTH|BYE)\b"), "*{}"),
    (re.compile(rb"^[A-Za-z0-9.]{1,12} (OK|NO|BAD)\b"), "tag-{}"),
)


def state_of(resp: bytes) -> str:
    """A response reduced to the protocol state it signals. Text protocols put a status code
    first (FTP/SMTP "230", HTTP "404", POP3 "+OK", IMAP "OK"); anything else is described by its
    first byte and a log-scale length class, which still separates "error" from "data"."""
    if resp is None:
        return "-"
    if not resp:
        return "0"
    head = resp.lstrip()[:64]
    for rx, fmt in _STATE_RX:
        m = rx.match(head)
        if m:
            return fmt.format(m.group(1).decode("latin-1"))
    return f"b{resp[0]:02x}/{min(len(resp).bit_length(), 16)}"


# --------------------------------------------------------------------------- protocol inference

_NOISE = frozenset("""ERROR WARNING WARN INFO DEBUG NULL NONE TRUE FALSE HOME PATH LANG TERM SHELL
USERPROFILE ASCII UTF EOF EOL GNU GCC LINUX UNIX POSIX TMPDIR TZ STDIN STDOUT STDERR OK YES NO
FILE DIR MAIN LIBC GLIBC ABI CXXABI GLIBCXX AES SHA MD RSA DES ID TODO FIXME XXX""".split())
_CMD_RX = re.compile(rb"^([A-Z]{3,10})(?:[ :]|$)")
_HDR_RX = re.compile(rb"^([A-Z][A-Za-z]+(?:-[A-Za-z]+)+|Host|Connection|Cookie|Range|Expect|"
                     rb"Upgrade|Authorization|Referer|Accept|Transfer-Encoding)(?::|$)")
_HTTP_METHODS = (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"TRACE", b"CONNECT",
                 b"PATCH", b"PROPFIND", b"MKCOL")


def mine_vocabulary(strings) -> dict:
    """Command words and header names compiled into the server: the protocol's vocabulary,
    MOST LIKELY FIRST.

    A command table (`{"USER", cmd_user}, {"PASS", cmd_pass}, ...`) leaves every command word in
    .rodata, as a whole string or as a prefix ("USER %s", "RETR "). Header-name strings
    ("Content-Length:") do the same for HTTP-like protocols. Ranking matters more than recall:
    a word followed by a space or colon (it takes an argument) or referenced by code is far more
    likely a command than a bare upper-case run in a sanitizer runtime, and `_verify_commands`
    asks the server about the candidates in this order under a deadline."""
    tiers: dict = {}
    hdrs = []
    for s in strings or ():
        v = getattr(s, "value", s)
        if v is None:
            continue
        ref = bool(getattr(s, "xrefs", None))
        b = v.encode("latin-1", "ignore") if isinstance(v, str) else bytes(v)
        b = b.lstrip()
        if not b or len(b) > 80:
            continue
        m = _CMD_RX.match(b)
        if m and m.group(1).decode() not in _NOISE:
            w = m.group(1)
            tail = b[len(w):len(w) + 1]
            tier = (0 if tail in (b" ", b":") else 2) - (1 if ref else 0) + \
                (0 if len(w) >= 4 else 1)
            tiers[w] = min(tier, tiers.get(w, 99))
        h = _HDR_RX.match(b.strip())
        if h and h.group(1) not in hdrs:
            hdrs.append(h.group(1))
    cmds = sorted(tiers, key=lambda w: (tiers[w], w))
    return {"commands": cmds[:600], "headers": hdrs[:48]}


def infer_protocol(greeting: bytes, probe_reply: bytes, vocab: dict) -> str:
    """Name the protocol from what the server said and what it knows."""
    g, cmds = (greeting or b"").lstrip(), set(vocab.get("commands") or ())
    if g.startswith(b"220"):
        if b"SMTP" in g.upper() or {b"HELO", b"EHLO", b"RCPT"} & cmds:
            return "smtp"
        return "ftp"
    if g.startswith(b"+OK"):
        return "pop3"
    if g.startswith(b"* OK") or g.startswith(b"* PREAUTH"):
        return "imap"
    if g.startswith(b"SSH-"):
        return "ssh"
    p = (probe_reply or b"").lstrip()
    if p.startswith(b"RTSP/"):
        return "rtsp"
    if p.startswith(b"HTTP/") or (b"GET" in cmds and b"HTTP" in cmds):
        return "http"
    if {b"USER", b"PASS", b"RETR"} <= cmds or {b"USER", b"PASS", b"PORT"} <= cmds:
        return "ftp"
    if {b"HELO", b"MAIL", b"RCPT"} <= cmds:
        return "smtp"
    if g and all(32 <= c < 127 or c in (9, 10, 13) for c in g[:64]):
        return "line"
    if cmds and not g:
        return "line"
    return "binary"


# The protocol's STANDARD commands, always seeded alongside the mined ones. Mining + server-side
# verification can miss a real command (a tight verify deadline, a command the server only answers
# in a state the probe did not set), and for a line protocol the dangerous handler is often one of
# these (FTP PORT/EPRT, SMTP VRFY/EXPN) -- so a bug behind it must not depend on the miner naming it.
_STD_CMDS = {
    "ftp": [b"PORT", b"EPRT", b"LIST", b"NLST", b"RETR", b"STOR", b"CWD", b"CDUP", b"MKD", b"RMD",
            b"DELE", b"RNFR", b"RNTO", b"SIZE", b"MDTM", b"TYPE", b"MODE", b"STRU", b"SYST",
            b"STAT", b"SITE", b"MLSD", b"MLST", b"REST", b"ALLO"],
    "smtp": [b"VRFY", b"EXPN", b"HELP", b"NOOP", b"RSET", b"ETRN", b"AUTH"],
    "pop3": [b"STAT", b"LIST", b"RETR", b"DELE", b"TOP", b"UIDL", b"APOP"],
    "imap": [b"SELECT", b"EXAMINE", b"FETCH", b"STORE", b"SEARCH", b"LIST", b"LSUB", b"STATUS",
             b"APPEND", b"CREATE", b"RENAME", b"SUBSCRIBE"],
}


_CREDS = ((b"anonymous", b"guest@example.com"), (b"ftp", b"ftp"), (b"admin", b"admin"),
          (b"test", b"test"), (b"user", b"password"))
_ARGS = (b"/", b"a", b"1", b"0", b"test.txt", b"1,2,3,4,5,6", b"*", b"INBOX", b"..")


def seed_sessions(proto: str, vocab: dict, *, eol: bytes = b"\r\n", creds=None,
                  extra=()) -> list:
    """Starting sessions for `proto`, built from the server's own vocabulary."""
    cmds = list(vocab.get("commands") or [])
    for c in _STD_CMDS.get(proto, []):               # standard commands, always tried
        if c not in cmds:
            cmds.append(c)
    hdrs = list(vocab.get("headers") or [])
    creds = [tuple(c) for c in (creds or [])] + list(_CREDS)
    L = lambda s: s + eol                                         # noqa: E731
    out = [list(s) for s in extra if s]
    if proto == "ftp":
        logins = [[L(b"USER " + u), L(b"PASS " + p)] for u, p in creds[:3]]
        out += logins
        for c in cmds or [b"SYST", b"PWD", b"LIST", b"RETR", b"STOR", b"CWD", b"PORT"]:
            if c in (b"USER", b"PASS", b"QUIT"):
                continue
            arg = b"1,2,3,4,5,6" if c in (b"PORT", b"EPRT") else b"/"
            out.append(logins[0] + [L(c + b" " + arg)])
            out.append(logins[0] + [L(c)])
        out.append([L(b"USER " + creds[0][0])])
    elif proto == "smtp":
        base = [L(b"EHLO lykos.test"), L(b"MAIL FROM:<a@lykos.test>"),
                L(b"RCPT TO:<b@lykos.test>"), L(b"DATA"),
                b"Subject: x" + eol + eol + b"body" + eol + b"." + eol, L(b"QUIT")]
        out += [base, base[:1] + [L(b"HELO lykos.test")], base[:3]]
        for c in cmds:
            if c not in (b"EHLO", b"HELO", b"MAIL", b"RCPT", b"DATA", b"QUIT"):
                out.append(base[:1] + [L(c + b" a")])
    elif proto == "pop3":
        lg = [L(b"USER " + creds[0][0]), L(b"PASS " + creds[0][1])]
        out += [lg + [L(b"STAT")], lg + [L(b"LIST")], lg + [L(b"RETR 1")], lg + [L(b"TOP 1 0")]]
        out += [lg + [L(c + b" 1")] for c in cmds if c not in (b"USER", b"PASS", b"QUIT")]
    elif proto == "imap":
        lg = [L(b"a1 LOGIN " + creds[0][0] + b" " + creds[0][1])]
        out += [lg + [L(b'a2 LIST "" *')], lg + [L(b"a2 SELECT INBOX"), L(b"a3 FETCH 1 BODY[]")],
                [L(b"a1 CAPABILITY")]]
    elif proto in ("http", "rtsp"):
        ver = b"RTSP/1.0" if proto == "rtsp" else b"HTTP/1.1"
        methods = [m for m in _HTTP_METHODS if m in set(cmds)] or [b"GET", b"POST", b"HEAD"]
        if proto == "rtsp":
            methods = [b"OPTIONS", b"DESCRIBE", b"SETUP", b"PLAY"]
        for m in methods:
            for path in (b"/", b"/index.html", b"/cgi-bin/test?a=b"):
                req = m + b" " + path + b" " + ver + b"\r\nHost: localhost\r\nCSeq: 1\r\n"
                if m in (b"POST", b"PUT"):
                    req += b"Content-Length: 4\r\n\r\nabcd"
                else:
                    req += b"\r\n"
                out.append([req])
        for h in hdrs[:24]:
            out.append([b"GET / " + ver + b"\r\nHost: localhost\r\n" + h + b": x\r\n\r\n"])
        out.append([b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n"])
    elif proto == "line":
        for c in cmds[:48]:
            out.append([L(c)])
            out.append([L(c + b" " + random.Random(len(c)).choice(_ARGS))])
        if len(cmds) >= 2:
            out.append([L(cmds[0] + b" a"), L(cmds[1] + b" b")])
    if proto in ("binary", "line", "ssh") or not out:
        from .netfuzz import _default_corpus
        out += [[p] for p in _default_corpus()]
    seen, uniq = set(), []
    for s in out:
        k = tuple(s)
        if s and k not in seen:
            seen.add(k)
            uniq.append(s)
    return uniq


# --------------------------------------------------------------------------- mutation

_LONG = (64, 256, 1024, 4096, 16384)
_INTS = (b"-1", b"0", b"2147483647", b"-2147483648", b"4294967295", b"4294967296",
         b"99999999999999999999", b"65535", b"-65536")
_TEXT_SPECIAL = (b"%n%n%n%n", b"%s%s%s%s%s", b"%x" * 32, b"../" * 24 + b"etc/passwd",
                 b"/" * 600, b"", b"\x00", b"\xff" * 64, b"A,B,C,D,E,F," * 40, b"\\" * 200)
_TOKEN_SPLIT = re.compile(rb"([ ,:=;&?/])")
_NUM = re.compile(rb"-?\d+")


def _is_text(b: bytes) -> bool:
    return bool(b) and all(32 <= c < 127 or c in (9, 10, 13) for c in b[:256])


def _split_eol(m: bytes):
    for eol in (b"\r\n", b"\n"):
        if m.endswith(eol):
            return m[:-len(eol)], eol
    return m, b""


class SessionMutator:
    def __init__(self, rng: random.Random, vocab: dict, dictionary=(), eol=b"\r\n"):
        self.rng = rng
        self.vocab = vocab or {}
        self.eol = eol
        words = list(self.vocab.get("commands") or []) + list(self.vocab.get("headers") or [])
        self.bytes_mut = Mutator(rng, list(dictionary) + words)

    def _interesting(self, tok: bytes) -> bytes:
        r = self.rng.random()
        if r < 0.40:
            return (tok[:1] or b"A") * self.rng.choice(_LONG)
        if r < 0.70:
            return self.rng.choice(_INTS)
        if r < 0.90:
            return self.rng.choice(_TEXT_SPECIAL)
        return tok * self.rng.randint(2, 64)

    def mutate_message(self, m: bytes) -> bytes:
        body, eol = _split_eol(m)
        if _is_text(body) and self.rng.random() < 0.65:
            parts = _TOKEN_SPLIT.split(body)
            idx = [i for i, p in enumerate(parts) if p and not _TOKEN_SPLIT.fullmatch(p)]
            nums = [i for i in idx if _NUM.fullmatch(parts[i])]
            if len(nums) > 1 and self.rng.random() < 0.25:
                # EVERY number at one boundary at once: a field list ("PORT h1,h2,h3,h4,p1,p2",
                # a WxH, a range) is usually formatted back together, and only all-fields-large
                # overruns the buffer it is printed into. One random field at a time rarely does.
                v = self.rng.choice(_INTS[1:])
                for i in nums:
                    parts[i] = v
                return b"".join(parts) + eol
            if idx:
                # Never the command word itself unless there is nothing else: mutating "PORT"
                # turns the message into "502 unknown", which tests nothing past the dispatcher.
                pick = idx[1:] or idx
                for _ in range(1 if self.rng.random() < 0.7 else 2):
                    i = self.rng.choice(pick)
                    parts[i] = self._interesting(parts[i])
                return b"".join(parts) + eol
            return (body + b" " + self._interesting(b"A")) + eol
        out = self.bytes_mut.mutate(m, [])
        # A line protocol only acts on a line once it is TERMINATED: a mutant that lost its
        # newline makes the server wait, and every later message of the session joins it.
        if eol and not out.endswith(eol) and self.rng.random() < 0.85:
            out += eol
        return out

    def mutate(self, session: list, corpus: list, focus: int = 0) -> list:
        s = [bytes(m) for m in session] or [b"\r\n"]
        for _ in range(self.rng.choice((1, 1, 2, 3))):
            s = self._mutate_once(s, corpus, focus)
        return s

    def _mutate_once(self, s: list, corpus: list, focus: int) -> list:
        s = list(s) or [b"\r\n"]
        r = self.rng.random()
        # Bias toward the TAIL: the prefix is what got the session into its state.
        lo = min(max(0, focus), len(s) - 1)
        i = self.rng.randint(lo, len(s) - 1)
        if r < 0.70:
            s[i] = self.mutate_message(s[i])
        elif r < 0.80 and self.vocab.get("commands"):
            c = self.rng.choice(self.vocab["commands"])
            arg = self._interesting(b"A") if self.rng.random() < 0.5 else self.rng.choice(_ARGS)
            s.insert(i + 1, c + b" " + arg + self.eol)
        elif r < 0.86:
            s.insert(i, s[i])
        elif r < 0.91 and len(s) > 1:
            del s[i]
        elif corpus:
            other = self.rng.choice(corpus)
            cut = self.rng.randint(0, len(s))
            s = s[:cut] + [bytes(m) for m in other[self.rng.randint(0, len(other) - 1):]]
        else:
            s[i] = self.bytes_mut.mutate(s[i], [])
        return s[:24]


# --------------------------------------------------------------------------- the server

@dataclass
class SessionResult:
    responses: list = field(default_factory=list)
    states: tuple = ()
    crashed: bool = False
    died: bool = False
    signal_name: "str | None" = None
    signal: "int | None" = None
    at_message: "int | None" = None
    stderr: bytes = b""
    new_cov: int = 0
    connect_failed: bool = False
    late: bool = False


class SessionServer:
    """One server process serving many sessions, with an optional coverage map."""

    def __init__(self, exe, proto="tcp", *, argv=(), port=None, arch=None, coverage=True,
                 listen_timeout=8.0, mem_mb=1024, preload=None):
        # Absolute: the sandbox changes directory before it executes anything.
        self.exe, self.proto, self.argv = str(Path(exe).resolve()), proto, [str(a) for a in argv]
        self.want_port, self.arch = port, arch
        self.listen_timeout, self.mem_mb = float(listen_timeout), int(mem_mb)
        self.cov = None
        self.cov_kind = None
        self.launch = []
        if coverage:
            launch, kind = coverage_launch(self.exe, arch)
            if kind:
                try:
                    self.cov = CoverageMap()
                    self.launch, self.cov_kind = launch, kind
                except OSError:
                    self.cov = None
        self.preload = preload
        self.proc = None
        self.port = None
        self.restarts = 0
        self._err_pos = 0
        self.greets = None                # does the server speak first?
        self._lat = 0.08                  # EWMA of first-response latency (s)
        self.isolation = None
        self.start_error = ""

    # -- lifecycle
    def start(self) -> bool:
        from . import netfuzz
        env = dict(self.cov.env()) if self.cov else {}
        launch = list(self.launch)
        if self.preload and not sandbox._is_sanitizer_exe(self.exe):
            if self.cov_kind == "qemu":
                launch += ["-E", f"LD_PRELOAD={self.preload}"]
            else:
                env["LD_PRELOAD"] = self.preload
        self.proc = netfuzz._spawn_server(self.exe, self.argv, mem_mb=self.mem_mb,
                                          launch=launch, extra_env=env)
        self.restarts += 1
        self._err_pos = 0
        if self.proc is None:
            self.start_error = "spawn failed"
            return False
        self.isolation = getattr(self.proc, "_lykos_isolation", None)
        self.port = netfuzz._wait_for_port(self.proc, self.proto, self.want_port,
                                           self.listen_timeout * (3 if self.cov_kind == "qemu"
                                                                  else 1))
        if self.port is None:
            self.start_error = (netfuzz._first_err_line(self.proc)
                                or f"no {self.proto} listening port")
            self.stop()
            return False
        return True

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        from . import netfuzz
        if self.proc is not None:
            netfuzz._killtree(self.proc)
        self.proc = None

    def close(self) -> None:
        self.stop()
        if self.cov is not None:
            self.cov.close()
            self.cov = None

    def stderr_since(self) -> bytes:
        from . import netfuzz
        if self.proc is None:
            return b""
        err = netfuzz.stderr_tail(self.proc, wait=0.0)
        return err[self._err_pos:] if self._err_pos <= len(err) else err

    # -- one session
    def _recv(self, s, first_wait: float) -> bytes:
        out = bytearray()
        s.settimeout(first_wait)
        t0 = time.time()
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                if not out:                            # latency to the FIRST byte
                    self._lat = 0.8 * self._lat + 0.2 * (time.time() - t0)
                out += chunk
                # A reply that ends a line is almost always complete (a status line); waiting
                # the full idle window after it is what made every session cost ~20 ms/message.
                s.settimeout(0.003 if out.endswith(b"\n") else 0.02)
                if len(out) > 1 << 20:
                    break
        except (socket.timeout, BlockingIOError):
            pass
        except OSError:
            pass
        return bytes(out)

    def late_death(self) -> "SessionResult | None":
        """The server died AFTER the previous session was judged (a frame smashed on return, a
        worker that faulted a moment later). The crash belongs to that session, not the next."""
        if self.proc is None or self.proc.poll() is None:
            return None
        res = SessionResult(late=True)
        return self._finish(res, (), 0.0)

    def run(self, msgs, *, settle: float = 0.0) -> SessionResult:
        res = SessionResult()
        if not self.alive() and not self.start():
            res.connect_failed = True
            return res
        from . import netfuzz
        self._err_pos = len(netfuzz.stderr_tail(self.proc, wait=0.0))
        if self.cov:
            self.cov.reset()
        wait = min(0.4, max(0.015, 3 * self._lat))
        states = []
        try:
            if self.proto == "tcp":
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                try:
                    s.connect(("127.0.0.1", self.port))
                except OSError:
                    res.connect_failed = True
                    s.close()
                    return self._finish(res, states, settle)
                try:
                    if self.greets is not False:
                        g = self._recv(s, 0.6 if self.greets is None else wait + 0.1)
                        if self.greets is None:
                            self.greets = bool(g)
                        res.responses.append(g)
                        states.append(state_of(g))
                    for i, m in enumerate(msgs):
                        try:
                            s.sendall(m)
                        except OSError:
                            res.at_message = i
                            break
                        r = self._recv(s, wait)
                        res.responses.append(r)
                        states.append(state_of(r))
                        if self.proc.poll() is not None:
                            res.at_message = i
                            break
                finally:
                    s.close()
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    for i, m in enumerate(msgs):
                        s.sendto(m, ("127.0.0.1", self.port))
                        r = b""
                        s.settimeout(wait)
                        try:
                            r = s.recvfrom(65536)[0]
                        except OSError:
                            pass
                        res.responses.append(r)
                        states.append(state_of(r))
                        if self.proc.poll() is not None:
                            res.at_message = i
                            break
                finally:
                    s.close()
        except OSError:
            observe.absorbed(_log, "a session that cannot be delivered is judged by the server")
        return self._finish(res, states, settle)

    def _finish(self, res: SessionResult, states, settle: float) -> SessionResult:
        from . import netfuzz
        res.states = tuple(states)
        # A crash lands after the reply (a smashed frame faults on RETURN), so give it a beat.
        rc = (netfuzz._poll_death(self.proc, timeout=settle) if settle > 0 else self.proc.poll()) \
            if self.proc else None
        if rc is not None:
            res.died = True
            crashed, sig, name, _ = sandbox.classify_rc(rc)
            res.stderr = self.stderr_since()
            fault = fault_in(res.stderr)
            res.crashed = bool(crashed or fault)
            res.signal, res.signal_name = sig, (name if crashed else (fault or f"exit{rc}"))
            if fault and not crashed:
                res.signal_name = fault
            self.stop()
        else:
            err = self.stderr_since()
            fault = fault_in(err)
            if fault:                                  # a forked worker died; the parent lives
                res.crashed, res.signal_name, res.stderr = True, fault, err
        if self.cov is not None and not res.connect_failed:
            res.new_cov = self.cov.collect()
        return res


# --------------------------------------------------------------------------- the campaign

@dataclass
class SessionCrash:
    session: list
    signal_name: str
    signal: "int | None"
    signature: str
    stderr: bytes
    minimized_from: int = 0


@dataclass
class CampaignResult:
    crashes: list = field(default_factory=list)
    sessions: int = 0
    protocol: str = ""
    coverage: "str | None" = None
    edges: int = 0
    states: int = 0
    transitions: int = 0
    corpus: int = 0
    note: str = ""
    isolation: "str | None" = None
    did_not_run: bool = False
    elapsed: float = 0.0
    corpus_sessions: list = field(default_factory=list)
    verified_commands: list = field(default_factory=list)


_VERIFIABLE = frozenset({"ftp", "smtp", "pop3", "imap", "line"})
_SUCCESS = re.compile(r"^(2\d\d|\+OK|\*OK|tag-OK|OK)$")


def _verify_commands(srv: "SessionServer", proto: str, vocab: dict, eol: bytes, creds,
                     *, deadline: float, stop) -> "tuple[dict, int]":
    """Keep only the mined words the server TREATS as commands.

    A word list mined from strings is noisy (a sanitizer runtime alone contributes thousands of
    upper-case runs), and the noise costs the campaign its whole budget: every seed built from a
    fake command earns the same "unknown command" reply. So ask the server: send each candidate
    after the login prefix and compare the reply's state with the reply to a word no server
    knows. A different state means the dispatcher recognised it -- even a "missing argument" or
    "permission denied" is a real handler. Returns (vocab with verified commands, sessions used)."""
    n = 0
    login = []
    for sess in seed_sessions(proto, {"commands": []}, eol=eol, creds=creds)[:4]:
        if time.time() > deadline or stop():
            break
        r = srv.run(sess)
        n += 1
        if r.states and _SUCCESS.match(r.states[-1]) and len(sess) <= 3:
            login = list(sess)
            break
    def _state(word):
        r = srv.run(login + [word + b" a" + eol])
        return (r.states[-1] if r.states else "-"), r
    unknown = set()
    for nonce in (b"LYKOSNOPE", b"QZXJWV"):
        st, _r = _state(nonce)
        n += 1
        unknown.add(st)
    keep = []
    for c in vocab.get("commands") or []:
        if time.time() > deadline or stop():
            keep.extend(x for x in vocab["commands"] if x not in keep and x in (b"USER", b"PASS"))
            break
        st, r = _state(c)
        n += 1
        if st not in unknown and st != "-":
            keep.append(c)
    out = dict(vocab)
    # Nothing verified (the deadline hit, or a server that answers everything alike): the best-
    # ranked candidates, not the whole noisy list -- each one costs the campaign seeds.
    out["commands"] = keep or list(vocab.get("commands") or [])[:24]
    out["login"] = login
    return out, n


def _probe(server: SessionServer) -> "tuple[bytes, bytes]":
    """(greeting, reply-to-an-HTTP-probe) from a fresh connection."""
    r = server.run([b"GET / HTTP/1.0\r\n\r\n"], settle=0.02)
    g = r.responses[0] if (r.responses and server.greets) else b""
    p = r.responses[-1] if r.responses else b""
    return g, p


def _confirm(exe, proto, argv, port, arch, session, preload, tries=2) -> "SessionResult | None":
    """Replay `session` against FRESH server instances; the crash must recur."""
    for _ in range(tries):
        srv = SessionServer(exe, proto, argv=argv, port=port, arch=arch, coverage=False,
                            preload=preload)
        try:
            r = srv.run(session, settle=0.8)
            if r.crashed:
                return r
        finally:
            srv.close()
    return None


def _minimize(exe, proto, argv, port, arch, session, preload, signature, deadline) -> list:
    """Drop every message the crash does not need, one at a time -- the trailing ones too: a
    frame smashed by message k faults when ITS handler returns, so whatever followed is noise."""
    s = list(session)
    i = 0
    while i < len(s) and len(s) > 1 and time.time() < deadline:
        cand = s[:i] + s[i + 1:]
        r = _confirm(exe, proto, argv, port, arch, cand, preload, tries=1)
        if r is not None and crash_signature(r.stderr, r.signal_name) == signature:
            s = cand
        else:
            i += 1
    return s


def fuzz_sessions(exe, proto="tcp", *, argv=(), port=None, arch=None, strings=(),
                  seeds=(), creds=None, max_seconds=120.0, max_sessions=200000,
                  seed=1337, keep_going=True, max_crashes=6, coverage=True,
                  oracle_exe=None, on_session=None, should_stop=None,
                  scratch=None) -> CampaignResult:
    """Fuzz a server through stateful sessions. See the module docstring.

    `oracle_exe`: a sanitizer build of the same server to CONFIRM crashes on when `exe` is the
    coverage build (an uninstrumented binary under qemu). `seeds`: operator-supplied sessions
    (lists of messages). `on_session(session, result, phase)` sees every delivery."""
    t0 = time.time()
    # The SEARCH ends at 75% of the slice: confirming a crash on fresh servers, minimising it and
    # recording it come out of the same slice, and a stage that overruns is cut off by the
    # orchestrator with its findings unrecorded -- and starves the prove phase that verifies them.
    search_end = t0 + 0.75 * max_seconds
    hard_end = t0 + 0.92 * max_seconds
    stop = should_stop or (lambda: False)
    rng = random.Random(seed)
    res = CampaignResult()
    scratch = Path(scratch or tempfile.mkdtemp(prefix="lykos-sess-"))
    preload = None
    if not sandbox._is_sanitizer_exe(str(exe)) and not afl_instrumented(exe):
        # The shim lives beside the target, which the sandbox binds; /tmp is a private tmpfs.
        preload = fault_shim(Path(exe).resolve().parent)
    confirm_exe = str(oracle_exe or exe)
    confirm_preload = None if oracle_exe else preload
    srv = SessionServer(exe, proto, argv=argv, port=port, arch=arch, coverage=coverage,
                        preload=preload)
    res.coverage = srv.cov_kind
    try:
        if not srv.start():
            res.did_not_run = True
            res.note = f"server did not start: {srv.start_error}"
            return res
        res.isolation = srv.isolation
        port = port or None
        vocab = mine_vocabulary(strings)
        greeting, probe = (b"", b"")
        if proto == "tcp":
            greeting, probe = _probe(srv)
        res.protocol = infer_protocol(greeting, probe, vocab) if proto == "tcp" else "datagram"
        eol = b"\r\n" if (greeting.endswith(b"\r\n") or res.protocol in
                          ("ftp", "smtp", "pop3", "imap", "http", "rtsp")) else b"\n"
        if res.protocol in _VERIFIABLE and vocab.get("commands"):
            vocab, verify_n = _verify_commands(srv, res.protocol, vocab, eol, creds,
                                               deadline=t0 + max_seconds * 0.2, stop=stop)
            res.sessions += verify_n
            res.verified_commands = [c.decode("latin-1") for c in vocab["commands"]]
        queue = seed_sessions(res.protocol, vocab, eol=eol, creds=creds,
                              extra=[list(s) for s in seeds])
        mut = SessionMutator(rng, vocab, eol=eol)
        corpus: list = []           # [{"s": session, "focus": int, "picks": int, "score": float}]
        transitions: set = set()
        state_set: set = set()
        sigs: set = set()

        def _judge(sess, r, phase):
            nonlocal transitions
            res.sessions += 1
            if on_session:
                try:
                    on_session(sess, r, phase)
                except Exception:                                 # noqa: BLE001
                    observe.absorbed(_log, "attempt logging must not stop the campaign")
            seq = ("^",) + tuple(r.states)
            new_t = {(seq[k], seq[k + 1]) for k in range(len(seq) - 1)} - transitions
            transitions |= new_t
            state_set.update(r.states)
            if (r.new_cov or new_t) and not r.crashed:
                # focus = the index of the first message after the newest transition: mutate there.
                focus = 0
                for k in range(len(seq) - 1):
                    if (seq[k], seq[k + 1]) in new_t:
                        focus = max(0, k - (1 if srv.greets else 0))
                corpus.append({"s": list(sess), "focus": focus, "picks": 0,
                               "score": 1.0 + (2.0 if new_t else 0.0) + min(r.new_cov, 50) / 10})

        def _on_crash(sess, r):
            sig = crash_signature(r.stderr, r.signal_name)
            if sig in sigs or time.time() > hard_end - 4:
                return
            conf = _confirm(confirm_exe, proto, argv, port if port else None, arch, sess,
                            confirm_preload)
            if conf is None:
                res.note = (res.note + "; " if res.note else "") + \
                    f"a {r.signal_name} did not reproduce on a fresh server (dropped)"
                return
            csig = crash_signature(conf.stderr, conf.signal_name)
            if csig in sigs:
                return
            mini = _minimize(confirm_exe, proto, argv, port, arch, sess, confirm_preload, csig,
                             deadline=min(time.time() + 30, hard_end - 3))
            sigs.add(csig)
            final = _confirm(confirm_exe, proto, argv, port, arch, mini, confirm_preload) or conf
            res.crashes.append(SessionCrash(session=mini, signal_name=final.signal_name or
                                            conf.signal_name, signal=final.signal,
                                            signature=csig, stderr=final.stderr[-16384:],
                                            minimized_from=len(sess)))

        prev = {"s": None}

        def _deliver(sess, phase):
            late = srv.late_death()
            if late is not None and late.crashed and prev["s"] is not None:
                _judge(prev["s"], late, phase)
                _on_crash(prev["s"], late)
            if late is not None:
                srv.stop()
            prev["s"] = sess
            r = srv.run(sess)
            if r.connect_failed and not srv.alive():
                srv.stop()
                if not srv.start():
                    return None
                r = srv.run(sess)
            _judge(sess, r, phase)
            if r.crashed:
                _on_crash(sess, r)
                if not srv.alive():
                    srv.stop()
            return r

        for s in queue:
            if stop() or time.time() > search_end:
                break
            if _deliver(s, "seed") is None:
                res.note = f"server stopped listening: {srv.start_error}"
                break
            if res.crashes and not keep_going:
                break
        while (not stop() and time.time() < search_end and res.sessions < max_sessions
               and not (res.crashes and not keep_going) and len(res.crashes) < max_crashes):
            pool = corpus or [{"s": s, "focus": 0, "picks": 0, "score": 1.0} for s in queue]
            if not pool:
                break
            ent = max(rng.sample(pool, min(4, len(pool))),
                      key=lambda e: e["score"] / (1 + e["picks"]))
            ent["picks"] += 1
            child = mut.mutate(ent["s"], [e["s"] for e in pool], focus=ent["focus"])
            if _deliver(child, "mutate") is None:
                res.note = f"server stopped listening: {srv.start_error}"
                break
        res.edges = srv.cov.edges if srv.cov else 0
        res.states = len(state_set)
        res.transitions = len(transitions)
        res.corpus = len(corpus)
        res.corpus_sessions = [e["s"] for e in sorted(corpus, key=lambda e: -e["score"])[:64]]
        res.isolation = srv.isolation or res.isolation
    finally:
        srv.close()
        res.elapsed = time.time() - t0
    return res


def replay_session(exe, proto, blob: bytes, *, argv=(), port=None, arch=None,
                   settle=0.8) -> SessionResult:
    """Deliver a stored session (or a plain single-message blob) to a fresh server."""
    preload = None
    if not sandbox._is_sanitizer_exe(str(exe)) and not afl_instrumented(exe):
        preload = fault_shim(Path(exe).resolve().parent)
    srv = SessionServer(exe, proto, argv=argv, port=port, arch=arch, coverage=False,
                        preload=preload)
    try:
        return srv.run(decode_session(blob), settle=settle)
    finally:
        srv.close()
