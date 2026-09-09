"""Cross-architecture fault capture via qemu-user's gdbstub (pure stdlib, air-gap safe).

Native L2/root-cause use ptrace/gdb, which only work on the host ISA. For an emulated target
we instead launch `qemu-<arch> -g <port>` (the guest starts paused, speaking the GDB Remote
Serial Protocol), drive it with a minimal RSP client over a loopback socket, continue, and on
the guest's fatal signal read the guest register file -- so we recover the exact fault-time PC
(including a hijacked/controlled value) and the general registers, on any ISA qemu supports.

No gdb / gdb-multiarch needed: the RSP client is ~a page of socket code, matching the project's
stdlib-only stance (cf. ptrace_capture.py). The register file layout is per-ISA (the g-packet
concatenates registers target-endian); layouts below are verified for aarch64/riscv64 and
best-effort elsewhere. Returns a capture dict compatible with rootcause.classify and
primitive.recover_ip_offset: {pc, sp, regs, signal, signal_name, arch, isolation}.
"""
from __future__ import annotations

import os
import signal as _signal
import socket
import subprocess
import time

from ..dynamic import sandbox

_SIGNALS = {4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
            11: "SIGSEGV"}

# g-packet register layout per ISA: ordered (name, byte_width). The gdbstub returns every
# register concatenated as target-endian hex in this order; we slice pc/sp/GP-regs out of it.
_LAYOUTS = {
    "aarch64": [(f"x{i}", 8) for i in range(31)] + [("sp", 8), ("pc", 8), ("cpsr", 4)],
    "riscv":   [(f"x{i}", 8) for i in range(32)] + [("pc", 8)],
    "riscv64": [(f"x{i}", 8) for i in range(32)] + [("pc", 8)],
    "arm":     [(f"r{i}", 4) for i in range(13)] + [("sp", 4), ("lr", 4), ("pc", 4),
                                                    ("cpsr", 4)],
    "ppc64":   [(f"r{i}", 8) for i in range(32)] + [("pc", 8), ("msr", 8)],
    "s390":    [("pswm", 8), ("pc", 8)] + [(f"r{i}", 8) for i in range(16)],
}
# which register name is the stack pointer / return-address register per ISA
_SP = {"aarch64": "sp", "riscv": "x2", "riscv64": "x2", "arm": "sp", "ppc64": "r1"}


def supported(arch: str) -> bool:
    return arch in _LAYOUTS


def _pkt(data: str) -> bytes:
    return f"${data}#{sum(data.encode()) & 0xff:02x}".encode()


def _txn(sock, data: str, timeout=5.0) -> str:
    """Send one RSP packet, ack the reply, return its body."""
    sock.sendall(_pkt(data))
    sock.settimeout(timeout)
    buf = b""
    while True:
        c = sock.recv(65536)
        if not c:
            return ""
        buf += c
        h = buf.find(b"#")
        if h != -1 and len(buf) >= h + 3:
            sock.sendall(b"+")                       # ack the packet
            st = buf.find(b"$")
            return buf[st + 1:h].decode("latin-1", "ignore")


def _parse_regs(g_hex: str, arch: str) -> dict:
    layout = _LAYOUTS.get(arch)
    if not layout:
        return {}
    regs, pos = {}, 0
    for name, width in layout:
        h = g_hex[pos:pos + width * 2]
        pos += width * 2
        if len(h) == width * 2:
            regs[name] = int.from_bytes(bytes.fromhex(h), "little")
    return regs


def capture(exe, arch, *, argv=(), stdin: bytes = b"", timeout: float = 8.0,
            endianness=None, bits=None, port: int = 0) -> dict:
    """Run `exe` under qemu-<arch>'s gdbstub and capture the register state at its fatal signal.

    Returns {} with a `note` when qemu for the arch is unavailable or the ISA layout is unknown.
    """
    qemu = sandbox._qemu_for(arch, endianness, bits)
    if not qemu:
        return {"note": f"no qemu-user for {arch}", "arch": arch}
    if arch not in _LAYOUTS:
        return {"note": f"no gdbstub register layout for {arch}", "arch": arch}
    port = port or _free_port()
    proc = subprocess.Popen(
        [qemu, "-g", str(port), str(exe), *[str(a) for a in argv]],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True)
    try:
        if proc.stdin:                               # deliver input; the guest reads it once run
            try:
                proc.stdin.write(stdin)
                proc.stdin.close()
            except BrokenPipeError:
                pass
        sock = _connect(port, deadline=time.time() + 5)
        if not sock:
            return {"note": "gdbstub did not accept a connection", "arch": arch}
        try:
            stop = _txn(sock, "c", timeout=timeout)  # continue until the guest stops
            sig = int(stop[1:3], 16) if stop[:1] in ("T", "S") else None
            if sig is None:
                return {"note": f"target exited without a fault (reply {stop[:8]!r})",
                        "arch": arch}
            regs = _parse_regs(_txn(sock, "g", timeout=timeout), arch)
        finally:
            sock.close()
    finally:
        _kill(proc)
    pc = regs.get("pc")
    sp = regs.get(_SP.get(arch, "sp"))
    return {
        "ok": True, "arch": arch, "isolation": "qemu-gdbstub", "signal": sig,
        "signal_name": _SIGNALS.get(sig), "pc": pc, "sp": sp,
        "regs": {k: v for k, v in regs.items() if k not in ("cpsr", "msr", "pswm")},
        "fault_addr": None, "maps": [], "backtrace": [],   # not available over the stub
    }


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _connect(port, deadline):
    while time.time() < deadline:
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=1)
        except OSError:
            time.sleep(0.05)
    return None


def _kill(proc):
    try:
        os.killpg(os.getpgid(proc.pid), _signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
