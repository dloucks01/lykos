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
import re
import signal as _signal
import socket
import subprocess
import time
from pathlib import Path

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
    # PowerPC: 32 GPRs then nip(pc), msr, cr, lr, ctr, xer. On PPC the controllable return
    # address is the Link Register (lr); the fetched pc is lr with the low 2 bits masked.
    "ppc":     [(f"r{i}", 4) for i in range(32)]
               + [("pc", 4), ("msr", 4), ("cr", 4), ("lr", 4), ("ctr", 4), ("xer", 4)],
    "ppc64":   [(f"r{i}", 8) for i in range(32)]
               + [("pc", 8), ("msr", 8), ("cr", 8), ("lr", 8), ("ctr", 8), ("xer", 8)],
    "s390":    [("pswm", 8), ("pc", 8)] + [(f"r{i}", 8) for i in range(16)],
    # MIPS32 o32: 32 GPRs then CP0 status/lo/hi/badvaddr/cause and pc (QEMU gdbstub order).
    # $sp is r29, return address is r31 ($ra). Works big- or little-endian (see `endianness`).
    "mips":    [(f"r{i}", 4) for i in range(32)]
               + [("status", 4), ("lo", 4), ("hi", 4), ("badvaddr", 4), ("cause", 4), ("pc", 4)],
    # SuperH is the one ISA here that must stay hand-written: qemu-sh4's stub serves NO target
    # description, so nothing can be derived from it. Transcribed from qemu's SH4 gdbstub and
    # then verified against a live g-packet -- 59 32-bit registers (236 bytes), with an
    # all-'A' overflow landing at indices 14, 16 and 17, i.e. exactly r14 (frame pointer), pc
    # and pr (link register). $sp is r15 and the return address is pr.
    "sh":      [(f"r{i}", 4) for i in range(16)]
               + [("pc", 4), ("pr", 4), ("gbr", 4), ("vbr", 4), ("mach", 4), ("macl", 4),
                  ("sr", 4), ("fpul", 4), ("fpscr", 4)]
               + [(f"fr{i}", 4) for i in range(16)]
               + [("ssr", 4), ("spc", 4)]
               + [(f"r{i}_bank0", 4) for i in range(8)]
               + [(f"r{i}_bank1", 4) for i in range(8)],
}
# which register name is the stack pointer per ISA
# The stack pointer's name in each ISA's own g-packet layout. A name the layout does not have
# is not an error: `capture` does regs.get(_sp_name(arch)), so it comes back None and the
# capture reports no stack pointer at all. s390 was exactly that -- its SP is r15, the default
# "sp" matched nothing, and every s390 capture returned sp=None while the value sat unread in
# regs["r15"]. The arch gate did not catch it because s390's PoC path goes through r14, its
# link register, and never asks for the stack.
_SP = {"aarch64": "sp", "riscv": "x2", "riscv64": "x2", "arm": "sp", "ppc64": "r1",
       "ppc": "r1", "mips": "r29", "sh": "r15", "s390": "r15"}
# integer argument registers per ISA calling convention (in order), named as in _LAYOUTS
_ARG_REGS = {
    "aarch64": [f"x{i}" for i in range(8)],
    "arm": [f"r{i}" for i in range(4)],
    "mips": ["r4", "r5", "r6", "r7"],
    "ppc": [f"r{i}" for i in range(3, 11)],
    "ppc64": [f"r{i}" for i in range(3, 11)],
    "riscv": [f"x{i}" for i in range(10, 18)],
    "riscv64": [f"x{i}" for i in range(10, 18)],
    "s390": [f"r{i}" for i in range(2, 7)],
    "loongarch": [f"r{i}" for i in range(4, 12)],     # a0-a7
    "sparcv9": [f"o{i}" for i in range(6)],           # caller side; the callee sees i0-i5
    "sh": [f"r{i}" for i in range(4, 8)],             # SuperH passes r4-r7
}
_BP_KIND = {"arm": 4, "aarch64": 4, "mips": 4, "ppc": 4, "ppc64": 4,
            "riscv": 4, "riscv64": 4, "s390": 2,     # software-breakpoint length hint
            "loongarch": 4, "sparcv9": 4, "m68k": 2, "sh": 2, "x86": 1}

# ---------------------------------------------------------------- derived layouts
# Every _LAYOUTS entry above is hand-written, which is how the register order gets subtly
# wrong. But the emulator that answers the `g` packet will also DESCRIBE it: the GDB remote
# protocol serves a target description over qXfer:features:read:target.xml listing every
# register, in regnum order, with its bit width. Deriving the layout from that is strictly
# better than transcribing it -- so architectures below are fetched at connect time instead.
#
# Only the pieces the description does NOT carry stay hard-coded: which register is the stack
# pointer and which is the program counter (the names vary -- i386 calls them esp/eip,
# LoongArch has no "sp" at all, its stack pointer is r3), plus the argument registers, which
# are a calling-convention fact rather than a hardware one.
#
# A wrong layout cannot silently produce a false L2: primitive_stage CONFIRMS a recovered
# offset by re-running with a marker, so a bad slice fails confirmation and is reported
# unconfirmed rather than believed.
#
# qemu-sh4 is deliberately absent: its stub serves no target description at all (verified),
# so SuperH stays honestly unsupported rather than guessed at.
# ISAs whose indirect branch masks bit 0 of the target. Two consequences here: a captured
# fault PC is `value & ~1`, and a FUNCTION SYMBOL may carry bit 0 set to mean "Thumb" -- so a
# breakpoint must be placed at the even code address even though the payload must keep the bit
# (it selects the instruction set). Placing it at the odd address simply never fires.
LSB_MASKED_PC = ("arm", "aarch64", "riscv", "riscv64")

_STUB_ABI = {
    "loongarch": {"sp": "r3", "pc": "pc"},            # a0-a7 are r4-r11
    "m68k": {"sp": "sp", "pc": "pc"},                 # SysV m68k passes arguments on the stack
    "sparcv9": {"sp": "sp", "pc": "pc"},              # sp is o6; caller args o0-o5
    "x86": {"sp": "esp", "pc": "eip"},                # cdecl passes arguments on the stack
}
_DERIVED: dict = {}                                   # arch -> layout, fetched once per process
_REG_RE = re.compile(r'<reg\s+name="([^"]+)"[^>]*?bitsize="(\d+)"')
_INCLUDE_RE = re.compile(r'<xi:include\s+href="([^"]+)"')


def _pc_name(arch: str) -> str:
    return _STUB_ABI.get(arch, {}).get("pc", "pc")


def _sp_name(arch: str) -> str:
    if arch in _SP:
        return _SP[arch]
    return _STUB_ABI.get(arch, {}).get("sp", "sp")


def _layout_for(arch: str):
    return _LAYOUTS.get(arch) or _DERIVED.get(arch)


def _fetch_layout(sock) -> list:
    """Read the stub's own target description and return [(register, width_bytes)] in g-packet
    order. Returns [] when the stub serves no description (qemu-sh4)."""
    docs, todo, seen = [], ["target.xml"], set()
    while todo:
        name = todo.pop(0)
        if name in seen:
            continue
        seen.add(name)
        body, off = "", 0
        while True:                                   # qXfer replies are chunked: m=more, l=last
            r = _txn(sock, f"qXfer:features:read:{name}:{off:x},7ff")
            if not r or r[0] not in "ml":
                break
            body += r[1:]
            if r[0] == "l":
                break
            off += len(r) - 1
        docs.append(body)
        todo += _INCLUDE_RE.findall(body)
    out = []
    for body in docs:
        for m in _REG_RE.finditer(body):
            out.append((m.group(1), (int(m.group(2)) + 7) // 8))
    return out


def _ensure_layout(arch: str, sock) -> list:
    """Layout for `arch`, fetching it from the live stub the first time it is needed."""
    have = _layout_for(arch)
    if have:
        return have
    lay = _fetch_layout(sock)
    if lay:
        _DERIVED[arch] = lay
    return lay


def supported(arch: str) -> bool:
    return arch in _LAYOUTS or arch in _STUB_ABI


def breakpoints_supported(arch: str) -> bool:
    return supported(arch) and arch in _ARG_REGS


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


def _parse_regs(g_hex: str, arch: str, endianness=None) -> dict:
    """Slice pc/sp/GP registers out of the g-packet. Each register's bytes are in target byte
    order, so a big-endian target (mips BE, ppc64) must be read big-endian."""
    layout = _layout_for(arch)
    if not layout:
        return {}
    byteorder = "big" if endianness == "big" else "little"
    regs, pos = {}, 0
    for name, width in layout:
        h = g_hex[pos:pos + width * 2]
        pos += width * 2
        if len(h) == width * 2:
            regs[name] = int.from_bytes(bytes.fromhex(h), byteorder)
    return regs


def _argv_bytes(a):
    """See sandbox.argv_bytes: a payload must not be re-encoded on its way to execve."""
    from ..dynamic.sandbox import argv_bytes
    return argv_bytes(a)


def capture(exe, arch, *, argv=(), stdin: bytes = b"", timeout: float = 8.0,
            endianness=None, bits=None, port: int = 0, breakpoints=None) -> dict:
    """Run `exe` under qemu-<arch>'s gdbstub and capture the register state at its fatal signal.

    Returns {} with a `note` when qemu for the arch is unavailable or the ISA layout is unknown.
    """
    qemu = sandbox._qemu_for(arch, endianness, bits)
    if not qemu:
        return {"note": f"no qemu-user for {arch}", "arch": arch}
    if not supported(arch):
        return {"note": f"no gdbstub register layout for {arch}", "arch": arch}
    port = port or _free_port()
    exedir = str(Path(exe).resolve().parent)
    # Detonating a hostile guest: contain the filesystem and cap resources. The network
    # namespace is KEPT (net=True) so the loopback gdb stub is still reachable; on an air-gapped
    # host loopback is not egress. rlimits bound memory-adjacent abuse (forks, file size, CPU)
    # without RLIMIT_AS, which qemu-user needs generously.
    cmd = sandbox.isolate_prefix(exedir, net=True) + \
        [qemu, "-g", str(port), str(exe), *[_argv_bytes(a) for a in argv]]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,
        preexec_fn=sandbox._rlimits(4096, int(timeout) + 30, set_as=False,
                                    nproc=sandbox._nproc_cap(True)))
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
            bp_alias = {}
            if breakpoints:
                # Confirming a control-flow hijack means proving execution REACHED a chosen
                # address, which a fault alone cannot show. Software breakpoints do that on
                # any ISA the stub speaks for.
                kind = _BP_KIND.get(arch, 4)
                for a in breakpoints:
                    a = int(a)
                    placed = a & ~1 if arch in LSB_MASKED_PC else a
                    bp_alias[placed] = a          # report back what the CALLER asked for
                    _txn(sock, f"Z0,{placed:x},{kind}")
            stop = _txn(sock, "c", timeout=timeout)  # continue until the guest stops
            sig = int(stop[1:3], 16) if stop[:1] in ("T", "S") else None
            if sig is None:
                return {"note": f"target exited without a fault (reply {stop[:8]!r})",
                        "arch": arch}
            if not _ensure_layout(arch, sock):
                return {"note": f"gdbstub for {arch} serves no target description",
                        "arch": arch}
            regs = _parse_regs(_txn(sock, "g", timeout=timeout), arch, endianness)
        except socket.timeout:
            # The guest never reached a stop within the budget (hang / long loop). A raised
            # exception here is not a clean capture -- report it as "could not run", honestly.
            return {"note": "guest did not stop within timeout", "arch": arch}
        finally:
            sock.close()
    finally:
        _kill(proc)
    pc = regs.get(_pc_name(arch))
    sp = regs.get(_sp_name(arch))
    hit = None
    if breakpoints and pc is not None:
        for cand in (pc, pc & ~1, pc | 1):
            if cand in bp_alias:
                hit = bp_alias[cand]              # the caller's address, bit 0 and all
                break
    return {
        "ok": True, "arch": arch, "isolation": "qemu-gdbstub", "signal": sig,
        "breakpoint_hit": hit,
        "signal_name": _SIGNALS.get(sig), "pc": pc, "sp": sp,
        "regs": {k: v for k, v in regs.items() if k not in ("cpsr", "msr", "pswm")},
        "fault_addr": None, "maps": [], "backtrace": [],   # not available over the stub
    }


def _read_mem(sock, addr: int, n: int) -> bytes:
    r = _txn(sock, f"m{addr:x},{n:x}")
    if not r or r.startswith("E"):
        return b""
    try:
        return bytes.fromhex(r)
    except ValueError:
        return b""


def _cstr(sock, addr: int, cap: int = 200) -> str:
    if not addr:
        return ""
    out = bytearray()
    while len(out) < cap:
        chunk = _read_mem(sock, addr + len(out), min(64, cap - len(out)))
        if not chunk:
            break
        nul = chunk.find(b"\x00")
        if nul != -1:
            out += chunk[:nul]
            break
        out += chunk
    return out.decode("latin-1", "ignore")


def _stop_sig(reply: str):
    """(kind, sig) for an RSP stop reply: kind in {trap, exit, term, none}."""
    if not reply:
        return "none", None
    if reply[0] in ("T", "S"):
        try:
            return "trap", int(reply[1:3], 16)
        except ValueError:
            return "trap", None
    if reply[0] == "W":
        return "exit", None
    if reply[0] == "X":
        return "term", None
    return "none", None


def monitor_calls(exe, arch, *, symbols, entry, pie, sink_names, endianness=None, bits=None,
                  argv=(), stdin: bytes = b"", timeout: float = 20.0, max_hits: int = 400):
    """Cross-arch call monitor: breakpoint the named sink functions (resolved from the ELF's own
    symbols, rebased by the emulator's load base) under qemu-user's gdbstub, and at each hit read
    the argument registers + deref them as C-strings. Returns generic per-hit arg data; the caller
    decodes it (copy length / command / operands) like the native monitor.
    """
    if not breakpoints_supported(arch):
        return {"ok": False, "note": f"no cross-arch breakpoint support for {arch}"}
    qemu = sandbox._qemu_for(arch, endianness, bits)
    if not qemu:
        return {"ok": False, "note": f"no qemu-user for {arch}"}
    targets = {n: v for n, v in symbols.items() if n in sink_names}
    if not targets:
        return {"ok": True, "hits": [], "note": "none of the requested sinks are in the symbols"}
    argregs = _ARG_REGS[arch]
    kind = _BP_KIND.get(arch, 4)
    port = _free_port()
    exedir = str(Path(exe).resolve().parent)
    cmd = sandbox.isolate_prefix(exedir, net=True) + \
        [qemu, "-g", str(port), str(exe), *[_argv_bytes(a) for a in argv]]
    proc = subprocess.Popen(cmd,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True,
                            preexec_fn=sandbox._rlimits(4096, int(timeout) + 30, set_as=False,
                                                        nproc=sandbox._nproc_cap(True)))
    try:
        if proc.stdin:
            try:
                proc.stdin.write(stdin)
                proc.stdin.close()
            except BrokenPipeError:
                pass
        sock = _connect(port, deadline=time.time() + 5)
        if not sock:
            return {"ok": False, "note": "gdbstub did not accept a connection"}
        deadline = time.time() + timeout
        try:
            regs0 = _parse_regs(_txn(sock, "g"), arch, endianness)
            rt_entry = regs0.get("pc")
            if rt_entry is None:
                return {"ok": False, "note": "could not read the runtime entry point"}
            base = (rt_entry - entry) if pie else 0
            bp_by_addr = {(v + base): n for n, v in targets.items()}
            for a in bp_by_addr:
                _txn(sock, f"Z0,{a:x},{kind}")
            hits = []
            reply = _txn(sock, "c", timeout=timeout)
            while len(hits) < max_hits and time.time() < deadline:
                kindr, sig = _stop_sig(reply)
                if kindr in ("exit", "term", "none"):
                    break
                regs = _parse_regs(_txn(sock, "g"), arch, endianness)
                pc = regs.get("pc")
                name = bp_by_addr.get(pc)
                if name:
                    ints = [regs.get(r, 0) for r in argregs]
                    strs = [_cstr(sock, v) for v in ints]
                    hits.append({"func": name, "argints": ints, "argstrs": strs})
                # step over: remove bp, single-step the original insn, re-arm, continue
                if pc in bp_by_addr:
                    _txn(sock, f"z0,{pc:x},{kind}")
                    _stop_sig(_txn(sock, "s", timeout=timeout))
                    _txn(sock, f"Z0,{pc:x},{kind}")
                reply = _txn(sock, "c", timeout=timeout)
            return {"ok": True, "hits": hits, "base": base}
        except socket.timeout:
            # A hang between breakpoints. Return what we captured, flagged as incomplete rather
            # than raising -- an unfinished trace is not a clean "nothing more happened".
            return {"ok": False, "note": "guest did not stop within timeout (trace incomplete)",
                    "hits": hits}
        finally:
            sock.close()
    finally:
        _kill(proc)


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
