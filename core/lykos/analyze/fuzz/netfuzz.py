"""Network / socket fuzzing: the input channel for a server that reads from a socket.

Every other channel (stdin / file / argv / menu / command) feeds a program that runs once and
exits. A network server is different: it binds a port, loops, and reads from connections -- so to
reach its parser you must SPAWN it, wait for it to listen, connect, and send. That attack surface
(FreeRTOS+TCP, any daemon) was unreachable before.

This spawns the target, discovers the port it listens on from /proc (no guessing), then drives a
mutation loop over a real socket, attributing a crash to the payload that preceded the server's
death. Single-process servers are handled directly; a forking server whose PARENT survives a
child crash is a documented limitation (the parent-death signal is what we observe).

The server runs under bubblewrap with the SAME containment as every other execution path --
read-only root, tmpfs /tmp, host secrets masked, pid namespace, die-with-parent -- EXCEPT the
network namespace, which it keeps (`sandbox.isolate_prefix(..., net=True)`): an unshared netns
would isolate the server from our connect(). Traffic is localhost-only (we dial 127.0.0.1). Where
bubblewrap is unusable the server runs rlimits-only and the result SAYS so (`isolation`), never
silently. Pure stdlib.
"""
from __future__ import annotations

import logging
import os
import random
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from ... import observe
from ..detect.catalog import normalize
from ..dynamic import sandbox
from .mutator import Mutator

_log = logging.getLogger(__name__)

# Imports that mark a socket server. A TCP server binds+listens (or accepts); a UDP server binds
# and recvfrom's without listen.
_TCP_SERVER = {"listen", "accept", "accept4"}
_BIND = {"bind"}
_UDP_RECV = {"recvfrom", "recvmsg"}


def detect_server(call_edges) -> "tuple[str, bool]":
    """(proto, is_server): 'tcp'/'udp'/'' from the target's imports. A listen/accept => tcp; a
    bind with recvfrom but no listen => udp."""
    names = {normalize(e.dst_name) for e in call_edges if e.dst_name}
    if names & _TCP_SERVER:
        return "tcp", True
    if names & _BIND and names & _UDP_RECV:
        return "udp", True
    if names & _BIND:                       # bind alone: most likely a server, assume tcp
        return "tcp", True
    return "", False


def _descendants(pid: int) -> list:
    """`pid` and every process below it. Under bubblewrap the Popen pid is the bwrap MONITOR, and
    the server is its grandchild (bwrap -> bwrap-as-init -> [setarch ->] server), so the sockets
    to look for are owned by a descendant, not by the pid we spawned."""
    children: dict = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return [pid]
    for e in entries:
        if not e.isdigit():
            continue
        try:
            with open(f"/proc/{e}/stat", "rb") as fh:
                st = fh.read()
            ppid = int(st.rsplit(b")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        children.setdefault(ppid, []).append(int(e))
    out, i = [pid], 0
    while i < len(out) and len(out) < 4096:
        out.extend(c for c in children.get(out[i], ()) if c not in out)
        i += 1
    return out


def _proc_socket_inodes(pid: int) -> set:
    """The socket inodes the process TREE actually owns (each /proc/<pid>/fd/* -> socket:[inode]),
    so a server under a sandbox monitor (or one that forks a listener) is still found."""
    inodes = set()
    for p in _descendants(pid):
        try:
            fds = os.listdir(f"/proc/{p}/fd")
        except OSError:
            continue
        for fd in fds:
            try:
                tgt = os.readlink(f"/proc/{p}/fd/{fd}")
            except OSError:
                continue
            if tgt.startswith("socket:["):
                inodes.add(tgt[len("socket:["):-1])
    return inodes


def _listening_ports(pid: int, proto: str) -> list:
    """Ports the process is listening on. /proc/<pid>/net/{tcp,udp}[6] is NETWORK-NAMESPACE-wide
    (it lists every listener on the host), so results are filtered to sockets this process owns
    by matching the inode (field 9) against its own fds. TCP LISTEN is state 0A; a bound UDP
    socket is state 07."""
    want_state = "0A" if proto == "tcp" else "07"
    inodes = _proc_socket_inodes(pid)
    ports, seen = [], set()
    for fam in (proto, proto + "6"):
        try:
            with open(f"/proc/{pid}/net/{fam}") as f:
                next(f, None)                        # header
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    local, st, inode = parts[1], parts[3], parts[9]
                    if st != want_state or inode not in inodes:
                        continue
                    port = int(local.rsplit(":", 1)[-1], 16)
                    if port and port not in seen:
                        seen.add(port)
                        ports.append(port)
        except (OSError, ValueError, StopIteration):
            continue
    return ports


_PR_SET_PDEATHSIG = 1
_ERR_TAIL = 65536                    # bytes of the server's stderr kept (an ASan report fits)


def isolation_tier() -> str:
    """The containment a spawned server gets on this host: `bwrap+loopback` (everything but the
    network namespace) or `rlimits-only` (bubblewrap unusable -- the run still happens, and the
    result says it was less contained)."""
    return "bwrap+loopback" if sandbox._bwrap_usable() else "rlimits-only"


def _drain_stderr(proc) -> None:
    """Read the server's stderr for as long as it is open, keeping only the last `_ERR_TAIL` bytes.

    The server used to get `stderr=PIPE` that nothing ever read: a server that LOGS (most do)
    fills the 64 KiB pipe, blocks in write(), and stops answering -- a live, wedged target that
    every later payload then reported as "survived". Draining keeps it running, and the tail is
    what explains a server that died before listening (a missing library, a bad config)."""
    buf = bytearray()
    proc._lykos_err = buf
    stream = proc.stderr

    def _pump():
        try:
            while True:
                chunk = stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536)
                if not chunk:
                    break
                buf.extend(chunk)
                if len(buf) > _ERR_TAIL:
                    del buf[:len(buf) - _ERR_TAIL]
        except (OSError, ValueError):
            pass

    t = threading.Thread(target=_pump, name="netfuzz-stderr", daemon=True)
    t.start()
    proc._lykos_err_thread = t


def stderr_tail(proc, wait: float = 0.3) -> bytes:
    """What the server last wrote to stderr (bounded). Waits briefly for the drain to catch up
    with a server that just exited."""
    t = getattr(proc, "_lykos_err_thread", None)
    if t is not None and proc.poll() is not None:
        t.join(timeout=wait)
    return bytes(getattr(proc, "_lykos_err", b"") or b"")


def _first_err_line(proc) -> str:
    for ln in stderr_tail(proc).decode("latin-1", "replace").splitlines():
        if ln.strip():
            return ln.strip()[:160]
    return ""


def _spawn_server(exe: str, argv: list, mem_mb: int = 1024) -> "subprocess.Popen | None":
    # A shared object has no entry point: spawning it as a server faults in the loader rather than
    # binding a port. Refuse it like a spawn failure (the campaign then reports "no-listen", which
    # is honest) rather than execute a library as a program -- the same guard sandbox.run has.
    if sandbox._is_elf_shared_object(exe):
        return None
    # A sanitizer build reserves a ~20 TB virtual shadow at startup: under an RLIMIT_AS cap that
    # mmap fails and the server aborts before main() -- every spawn "no-listen". And without
    # abort_on_error ASan reports a memory error by EXITING 1, which reads as an ordinary exit,
    # not a crash. Same treatment as sandbox.run: no AS cap, resident memory bounded by ASan
    # itself, and a detected error aborts (SIGABRT) so it is classified as the crash it is.
    san = sandbox._is_sanitizer_exe(exe)
    env = None
    if san:
        env = dict(os.environ)
        _prior = env.get("ASAN_OPTIONS", "")
        env["ASAN_OPTIONS"] = ((_prior + ":") if _prior else "") + \
            f"abort_on_error=1:hard_rss_limit_mb={max(256, int(mem_mb))}:detect_leaks=0"
    rlimits = sandbox._rlimits(mem_mb, 60, set_as=not san, nproc=sandbox._nproc_cap(san))

    def preexec():
        rlimits()
        # Tie the server's life to ours in the KERNEL. _killtree is the normal cleanup, but it only
        # runs if this process unwinds: a campaign cancelled at its budget (or an interpreter exit
        # with the worker thread still mid-fuzz) never reaches that `finally`, and because
        # start_new_session puts the server in its own process group, nothing else reaps it. A
        # leaked instance keeps its listening port, so every later spawn of the same server fails to
        # bind and the whole campaign reports "no-listen" -- a live bug that reads as "no crash".
        try:
            import ctypes
            ctypes.CDLL("libc.so.6", use_errno=True).prctl(_PR_SET_PDEATHSIG, signal.SIGKILL,
                                                           0, 0, 0)
        except Exception:                                # noqa: BLE001 -- best effort; _killtree remains
            pass

    # Contain it like every other execution of an untrusted target: read-only root, tmpfs /tmp,
    # host secrets masked, pid namespace, die-with-parent. The NETWORK namespace is kept
    # (net=True) -- that is the one thing this channel needs, since we connect() to it over
    # loopback. A target with a RELATIVE ELF interpreter (a staged glibc bundle) only loads with
    # its own dir as cwd, so that dir is bound writable and chdir'd into, as sandbox.run does.
    exedir = str(Path(exe).resolve().parent)
    rel = sandbox._relative_interp(exe)
    prefix = sandbox.isolate_prefix(exedir, net=True, rw_binds=([exedir] if rel else ()),
                                    chdir=(exedir if rel else ""))
    # Unwrapped (no bubblewrap): never inherit the worker's cwd, which a server writing relative
    # files (logs, pid files) would litter.
    cwd = None
    if not prefix:
        cwd = exedir if rel else tempfile.mkdtemp(prefix="lykos-netfuzz-")
        # the wrapped tier gets the confirmed runtime environment from isolate_prefix; unwrapped,
        # only its variables and cwd-relative files can be supplied (never a host path)
        renv = sandbox._runtime_env(exe)
        if renv is not None:
            env = {**(env if env is not None else os.environ), **renv.env}
            try:
                renv.populate_cwd(cwd)
            except OSError:
                pass
    try:
        proc = subprocess.Popen(prefix + [exe] + [str(a) for a in argv],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, preexec_fn=preexec,
                                start_new_session=True, env=env, cwd=cwd)
    except OSError:
        _log.debug("failed to spawn server %s", exe, exc_info=True)
        if cwd and not rel:
            shutil.rmtree(cwd, ignore_errors=True)
        return None
    proc._lykos_isolation = "bwrap+loopback" if prefix else "rlimits-only"
    proc._lykos_cwd = cwd if (cwd and not rel) else None
    _drain_stderr(proc)
    return proc


def _wait_for_port(proc, proto: str, want_port: "int | None", timeout: float) -> "int | None":
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:                 # died before listening
            return None
        ports = _listening_ports(proc.pid, proto)
        if ports:
            return want_port if (want_port and want_port in ports) else ports[0]
        time.sleep(0.05)
    return None


def _send_once(proto: str, port: int, payload: bytes, timeout: float = 1.0) -> None:
    fam = socket.AF_INET
    if proto == "tcp":
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(("127.0.0.1", port))
            s.sendall(payload)
            try:
                s.recv(256)                          # let the server process it
            except socket.timeout:
                pass
        finally:
            s.close()
    else:
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(payload, ("127.0.0.1", port))
            try:
                s.recvfrom(256)
            except socket.timeout:
                pass
        finally:
            s.close()


def _poll_death(proc, timeout: float = 0.6) -> "int | None":
    """Return the process's exit code if it dies within `timeout`, else None. A crash happens
    just AFTER the payload is delivered, so a single poll right after send races the kernel;
    give it a short window."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc = proc.poll()
        if rc is not None:
            return rc
        time.sleep(0.02)
    return None


def _killtree(proc) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait(timeout=2)
    except Exception:
        observe.absorbed(_log, "continuing")
    t = getattr(proc, "_lykos_err_thread", None)
    if t is not None:
        t.join(timeout=1)
    # Close only once the drain has seen EOF: closing a buffered reader another thread is blocked
    # in would wait on that read (a daemonised grandchild of an UNWRAPPED server can hold the
    # write end open past the group kill). The daemon thread then just ends with the process.
    if t is None or not t.is_alive():
        try:
            if proc.stderr is not None:
                proc.stderr.close()
        except (OSError, ValueError):
            pass
    d = getattr(proc, "_lykos_cwd", None)
    if d:
        shutil.rmtree(d, ignore_errors=True)


def _default_corpus() -> list:
    """Protocol-shaped seeds for a network parser. Beyond raw overflows, these target the bug
    classes that dominate embedded network stacks (FreeRTOS+TCP, lwIP): a length/size field that
    lies about the body (header says huge, body is short -> over-read), oversized option/TLV and
    extension fields, and format specifiers reaching a logging printf."""
    import struct
    out = [
        b"GET / HTTP/1.0\r\n\r\n",                     # a benign request to pass a protocol gate
        b"A" * 64, b"A" * 1024, b"A" * 8192,           # escalating overflow
        b"\x00" * 16,
        b"%s%s%s%s%n", b"%p" * 32,                     # format string into a log line
    ]
    # length-prefixed: a 2- and 4-byte length header that claims far more than follows.
    for lam in (struct.pack(">H", 0xFFFF), struct.pack("<H", 0xFFFF),
                struct.pack(">I", 0x7FFFFFFF), struct.pack("<I", 0x0FFFFFFF)):
        out.append(lam + b"A" * 8)                     # header lies: says huge, body tiny
        out.append(lam + b"A" * 2048)
    # TLV / option storms: many type-length-value records, and one with an oversized length.
    out.append(b"".join(bytes([1, 4]) + b"opt" + b"\x00" for _ in range(64)))
    out.append(bytes([3, 0xFF]) + b"B" * 16)           # TLV length 255, 16 bytes present
    # an IPv6-RA-ish prefix/option length field (the CVE-2026-7426 class): oversized length byte.
    out.append(b"\x86\x00" + b"\x00" * 6 + bytes([0x03, 0xFF]) + b"C" * 8)
    return out


class NetFuzzResult:
    def __init__(self, crashed, payload=None, signal_name=None, signal_num=None,
                 execs=0, port=None, note=None, isolation=None, stderr=b""):
        self.crashed = crashed
        self.payload = payload
        self.signal_name = signal_name
        self.signal = signal_num
        self.execs = execs
        self.port = port
        self.note = note
        # The containment the server actually ran under (`bwrap+loopback` / `rlimits-only`), so a
        # degraded run is visible instead of silent.
        self.isolation = isolation
        # The server's last stderr (bounded) -- a sanitizer report on a crash, the loader/config
        # error on a server that never listened.
        self.stderr = stderr


def replay_once(exe: str, proto: str, payload: bytes, *, argv=(), port: "int | None" = None,
                listen_timeout: float = 5.0, settle: float = 0.6) -> "tuple":
    """Deliver ONE payload to a freshly spawned server and report whether it died:
    (crashed, signal_name, signal_num, port).

    A socket is not an exec-time channel like stdin/argv/a file/an env var -- the input only exists
    after the server is up and listening -- so a crash found this way could not be replayed by the
    PoC path at all, and was filed as an unverified L0. This is the same spawn -> wait-for-port ->
    send -> poll sequence fuzz_server already uses for its confirm pass, exposed so the PoC and
    bundle paths can reproduce a socket crash instead of guessing a channel that cannot carry it."""
    proc = _spawn_server(exe, list(argv))
    if proc is None:
        return False, "spawn-failed", None, None
    try:
        p = _wait_for_port(proc, proto, port, listen_timeout)
        if p is None:
            _log.debug("replay: server did not listen (%s): %s",
                       getattr(proc, "_lykos_isolation", "?"), _first_err_line(proc))
            return False, "no-listen", None, None
        try:
            _send_once(proto, p, payload)
        except OSError:
            pass                                         # refused/reset: it may have just died
        rc = _poll_death(proc, timeout=settle)
        if rc is None:
            return False, "survived", None, p
        crashed, sig, sig_name, _ = sandbox.classify_rc(rc)
        return bool(crashed), (sig_name if crashed else f"exit{rc}"), \
            (sig if crashed else None), p
    finally:
        _killtree(proc)


def fuzz_server(exe: str, proto: str, *, argv=(), seeds=(), port: "int | None" = None,
                max_execs: int = 1500, seed: int = 1337,
                listen_timeout: float = 5.0, on_attempt=None, should_stop=None) -> NetFuzzResult:
    """Spawn `exe`, find its listening port, and fuzz it over a socket until a payload crashes it
    or the budget runs out. On a crash, respawn to CONFIRM the same payload reproduces before
    reporting it (kills one-off flakes). Returns a NetFuzzResult.

    `should_stop() -> bool` is polled before every delivery. `max_execs` alone does not bound the
    wall clock: a server that accepts but never answers costs the full 1 s receive timeout per
    payload, so 1,500 payloads outlive the stage and the run is reaped as an ERROR instead of
    reporting the executions it did make (the same reason `envfuzz.fuzz_env` polls its clock)."""
    stop = should_stop if should_stop is not None else (lambda: False)
    rng = random.Random(seed)
    mut = Mutator(rng)
    corpus = [s for s in seeds if s] or _default_corpus()
    found = {"port": port, "isolation": None, "stderr": b""}
    # `on_attempt(data, detail, phase)` sees every delivery (the attempt log). detail: {outcome,
    # rc, note}. A server that is still up after a payload "handled" it (clean); one that died
    # is classified by its exit status; a refused connection means the payload never arrived.
    _att = on_attempt or (lambda *_a, **_k: None)

    def _payloads(confirm_payload):
        if confirm_payload:
            yield confirm_payload
            return
        yield from corpus
        while True:
            for _ in range(32):
                yield mut.mutate(rng.choice(corpus), corpus)

    def _start(ph, confirm_payload, n):
        """Spawn the server and wait for it to listen: (proc, port, failure-note)."""
        proc = _spawn_server(exe, list(argv))
        if proc is None:
            _att(confirm_payload or b"", {"outcome": "no_start", "rc": None,
                                          "note": "server process could not be spawned"}, ph)
            return None, None, "spawn-failed"
        found["isolation"] = getattr(proc, "_lykos_isolation", None)
        p = _wait_for_port(proc, proto, port, listen_timeout)
        if p is None:
            rc0 = proc.poll()
            why = _first_err_line(proc)
            found["stderr"] = stderr_tail(proc)
            _att(confirm_payload or b"", {"outcome": "no_start", "rc": rc0,
                 "note": ((f"server exited ({rc0}) before listening" if rc0 is not None
                           else f"no {proto} listening port within {listen_timeout:g}s")
                          + (f": {why}" if why else ""))}, ph)
            _killtree(proc)
            # Only the FIRST start failing means nothing ran; a respawn that fails after
            # deliveries were made is a campaign that ran and then lost its target.
            return None, None, ("no-listen" if n == 0 else
                                f"server stopped listening after {n} delivery(ies)")
        found["port"] = p
        return proc, p, None

    def _run_campaign(confirm_payload=None):
        ph = "confirm" if confirm_payload else "mutate"
        n, proc, p = 0, None, None
        try:
            for data in _payloads(confirm_payload):
                if not confirm_payload and (n >= max_execs or stop()):
                    if n >= max_execs:
                        return None, None, "no-crash", n
                    return None, None, (f"stopped after {n} delivery(ies): out of budget or "
                                        f"cancelled"), n
                if proc is None:
                    proc, p, why = _start(ph, confirm_payload, n)
                    if proc is None:
                        return None, None, why, n
                n += 1
                refused = None
                try:
                    _send_once(proto, p, data)
                except OSError as e:
                    # connection refused/reset -> the server may have just died; check below
                    refused = str(e)[:120]
                # a crash lands just after delivery; wait a beat so we don't race the kernel.
                rc = _poll_death(proc, timeout=(0.6 if confirm_payload else 0.15))
                if rc is None:
                    _att(data, {"outcome": "no_start" if refused else "clean_exit",
                                "rc": None, "note": (f"send failed: {refused}" if refused
                                                     else "server alive after payload")},
                         ph if confirm_payload or n > len(corpus) else "seed")
                    if confirm_payload:
                        return None, None, "survived", n   # confirm pass: it did NOT re-crash
                    continue
                crashed, sig, sig_name, _ = sandbox.classify_rc(rc)
                found["stderr"] = stderr_tail(proc)
                _att(data, {"outcome": "crash" if crashed else "error_exit", "rc": rc,
                            "sig": sig_name if crashed else None,
                            "note": f"server died ({sig_name if crashed else f'exit {rc}'})"},
                     ph)
                if crashed or confirm_payload:
                    # `sig` from classify_rc: under bubblewrap the status is 128+signum, which
                    # the old `-rc if rc < 0` turned into "no signal" for every real crash.
                    return (data if crashed else None), (sig if crashed else None), \
                        (sig_name if crashed else f"exit{rc}"), n
                # It EXITED without a fault -- a one-shot server (handles one connection and
                # quits) or a payload it rejects by exiting. That ended the whole campaign after
                # a single delivery and reported "no crash"; respawn and keep fuzzing instead.
                _killtree(proc)
                proc = None
            return None, None, "no-crash", n
        finally:
            if proc is not None:
                _killtree(proc)

    crash_payload, signum, sig_name, execs = _run_campaign()
    if crash_payload is None:
        return NetFuzzResult(False, execs=execs, port=found["port"], note=sig_name,
                             isolation=found["isolation"], stderr=found["stderr"])
    # Confirm the crash reproduces on a fresh server instance.
    conf_payload, csig, cname, _ = _run_campaign(confirm_payload=crash_payload)
    if conf_payload is None:
        return NetFuzzResult(False, execs=execs, port=found["port"],
                             note=f"crash on {sig_name} did not reproduce (flaky)",
                             isolation=found["isolation"], stderr=found["stderr"])
    return NetFuzzResult(True, payload=crash_payload, signal_name=cname or sig_name,
                         signal_num=csig or signum, execs=execs, port=found["port"],
                         isolation=found["isolation"], stderr=found["stderr"])
