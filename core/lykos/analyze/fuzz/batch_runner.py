"""Executes many fuzz inputs inside ONE sandbox, optionally recording block coverage.

Spawning bubblewrap costs 3.18 ms of a 3.55 ms execution -- a 9.5x tax paid on every input --
so the namespace is paid for once per batch here instead of once per input. Isolation is
unchanged: every target process is still a child inside the same unshared-net, read-only-root
namespace.

With a block list it also traces each child and reports which of those blocks were reached.
A campaign's coverage proxy was the SHAPE of the program's output, which sees a few thousand
distinct behaviours where real path coverage sees tens of thousands -- the difference between
noticing that a parser printed something new and noticing that it took a branch it never took
before.

Breakpoints are ONE-SHOT and the caller only ever arms blocks it has not seen, so the cost
decays: the first inputs pay a trap per new block and later ones pay almost nothing. That is
also exactly the signal a fuzzer wants -- "did this input reach anywhere new?" -- rather than a
hit count it would have to diff.

Run as: python3 batch_runner.py <mode> <per_timeout> <exe> [base argv...]
stdin:  u32 count, u32 n_blocks, then n_blocks * u64 block addresses (image-relative),
        then per input: u32 length + bytes
stdout: per input: i32 rc, u32 stdout_len, u32 stderr_len, u8 flags, u32 n_new,
        u64 fault_pc (image-relative, 0 if unknown), then stdout, stderr, and
        n_new * u64 newly reached block addresses
"""
import ctypes
import os
import struct
import subprocess
import sys

PTRACE_TRACEME, PTRACE_PEEKTEXT, PTRACE_POKETEXT = 0, 1, 4
PTRACE_CONT, PTRACE_KILL, PTRACE_GETREGS = 7, 8, 12
_INT3 = 0xCC
_SPAN_CAP = 32 << 20            # refuse to slurp a span so wide it is cheaper per block


def _readn(n):
    b = b""
    while len(b) < n:
        c = sys.stdin.buffer.read(n - len(b))
        if not c:
            break
        b += c
    return b


class _Regs(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx",
        "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base",
        "gs_base", "ds", "es", "fs", "gs")]


def _elf_min_vaddr(exe):
    """The vaddr the ELF itself asks to be loaded at: 0x400000 for a fixed image, 0 for PIE.

    Callers send FILE vaddrs (a decompiler address with its image base removed) and this is
    what turns one into a runtime address without the caller needing to know whether the
    target is position-independent.
    """
    try:
        with open(exe, "rb") as fh:
            d = fh.read(4096)
        if d[:4] != b"\x7fELF" or d[4] != 2:
            return 0
        phoff = struct.unpack("<Q", d[0x20:0x28])[0]
        phentsize, phnum = struct.unpack("<HH", d[0x36:0x3A])
        lo = None
        for i in range(phnum):
            e = phoff + i * phentsize
            p_type = struct.unpack("<I", d[e:e + 4])[0]
            if p_type != 1:                              # PT_LOAD
                continue
            vaddr = struct.unpack("<Q", d[e + 0x10:e + 0x18])[0]
            lo = vaddr if lo is None else min(lo, vaddr)
        return lo or 0
    except Exception:
        return 0


def _maps_base(pid, exe):
    """Where the loader actually put the target's first mapping."""
    want = os.path.basename(exe)
    try:
        with open("/proc/%d/maps" % pid) as fh:
            for line in fh:
                if line.rstrip().endswith(want) or ("/" + want) in line:
                    return int(line.split("-", 1)[0], 16)
    except OSError:
        pass
    return 0


def _handles(pid, sig) -> bool:
    """Does the tracee catch this signal? SigCgt in /proc/<pid>/status is the mask it has
    handlers installed for, so there is no need to deliver the signal to find out."""
    try:
        with open(f"/proc/{pid}/status", "rb") as fh:
            for line in fh:
                if line.startswith(b"SigCgt:"):
                    return bool(int(line.split()[1], 16) & (1 << (sig - 1)))
    except (OSError, ValueError, IndexError):
        pass
    return False


def _open_mem(pid):
    try:
        return os.open(f"/proc/{pid}/mem", os.O_RDWR)
    except OSError:
        return None


def _poke_byte(libc, pid, mem, addr, value):
    """Write one byte into the tracee, preferring /proc/pid/mem over a read-modify-write word."""
    if mem is not None:
        try:
            os.pwrite(mem, bytes([value]), addr)
            return
        except OSError:
            pass
    word = libc.ptrace(PTRACE_PEEKTEXT, pid, ctypes.c_void_p(addr), 0)
    if word == -1:
        return
    libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(addr),
                ctypes.c_void_p(((word & ~0xFF) | value) & 0xFFFFFFFFFFFFFFFF))


def _arm(libc, pid, mem, base, blocks, plan):
    """Plant an INT3 at every block. Returns {relative address: replaced byte}.

    Done one block at a time this is two ptrace syscalls each, and a campaign re-arms every
    block it has not yet reached on every single execution: on jhead that is ~1,900 syscalls
    before the program starts, which cost more than the execution and held a coverage campaign
    to 23 exec/s against 2,000 without tracing. /proc/pid/mem reads the whole span once and
    writes it back once -- the patched bytes are scattered, but rewriting the untouched ones
    with their own values is free next to a syscall apiece.

    With the syscalls gone the cost became PYTHON: a statically linked binary carries its libc,
    so Ghidra recovers 38,418 blocks instead of 1,887, and building a 36,000-entry patch map
    per execution held the same campaign to 15 exec/s. The patched image is identical for every
    input in a batch -- same binary, same blocks -- so it is built once and replayed, which is
    a single write per execution after the first.
    """
    if mem is not None and len(blocks) > 8 and plan is not None:
        if not plan:
            lo, hi = min(blocks), max(blocks) + 1
            if hi - lo <= _SPAN_CAP:
                try:
                    text = bytearray(os.pread(mem, hi - lo, base + lo))
                    if len(text) == hi - lo:
                        orig = {}
                        for rel in blocks:
                            orig[rel] = text[rel - lo]
                            text[rel - lo] = _INT3
                        plan.update(lo=lo, text=bytes(text), orig=orig)
                except OSError:
                    pass
        if plan:
            try:
                os.pwrite(mem, plan["text"], base + plan["lo"])
                return plan["orig"]
            except OSError:
                pass
    original = {}
    for rel in blocks:
        addr = base + rel
        word = libc.ptrace(PTRACE_PEEKTEXT, pid, ctypes.c_void_p(addr), 0)
        if word == -1:
            continue
        original[rel] = word & 0xFF
        libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(addr),
                    ctypes.c_void_p(((word & ~0xFF) | _INT3) & 0xFFFFFFFFFFFFFFFF))
    return original


def _trace_one(libc, argv, stdin_data, timeout, blocks, exe, plan=None):
    """Run one input under ptrace. Returns (rc, out, err, flags, reached, fault_pc)."""
    r_out, w_out = os.pipe()
    r_err, w_err = os.pipe()
    r_in, w_in = os.pipe()
    pid = os.fork()
    if pid == 0:                                        # child
        try:
            libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
            os.dup2(r_in, 0); os.dup2(w_out, 1); os.dup2(w_err, 2)
            for fd in (r_out, w_out, r_err, w_err, r_in, w_in):
                try:
                    os.close(fd)
                except OSError:
                    pass
            os.execv(argv[0], argv)
        except Exception:
            os._exit(127)
    os.close(w_out); os.close(w_err); os.close(r_in)
    try:
        os.write(w_in, stdin_data)
    except OSError:
        pass
    os.close(w_in)
    os.waitpid(pid, 0)                                  # stop at execve

    base = _maps_base(pid, exe) - _elf_min_vaddr(exe)
    mem = _open_mem(pid)
    # `original` is shared across the batch and keyed by RELATIVE address; what this execution
    # has already put back is per-execution, so the shared map is never mutated
    original, restored = _arm(libc, pid, mem, base, blocks, plan), set()

    reached, regs = [], _Regs()
    deadline = _now() + timeout
    rc, flags, deliver, fault_pc = 0, 0, 0, 0
    while True:
        libc.ptrace(PTRACE_CONT, pid, 0, ctypes.c_void_p(deliver))
        deliver = 0
        try:
            _wpid, status = os.waitpid(pid, os.WNOHANG)
            while _wpid == 0 and _now() < deadline:
                _wpid, status = os.waitpid(pid, os.WNOHANG)
            if _wpid == 0:
                libc.ptrace(PTRACE_KILL, pid, 0, 0)
                os.waitpid(pid, 0)
                flags = 1
                break
        except ChildProcessError:
            break
        if os.WIFEXITED(status):
            rc = os.WEXITSTATUS(status)
            break
        if os.WIFSIGNALED(status):
            rc = -os.WTERMSIG(status)
            break
        sig = os.WSTOPSIG(status)
        if sig != 5:
            # A signal the program HANDLES is not a crash. Under ptrace every signal stops the
            # tracee and is ours to decide on, and killing on sight reported a program that
            # catches SIGSEGV and recovers as crashed -- the same input then had two different
            # verdicts depending on whether block coverage happened to be switched on.
            # Anything using SIGSEGV deliberately (a JIT, a guard page, lazy mapping) would
            # have produced a finding and a PoC for a bug that is not there.
            if _handles(pid, sig):
                deliver = sig                           # let the program have it, and see
                continue
            # Where it faulted, which is what tells two bugs apart. Bucketing crashes by
            # signal alone collapsed 8,516 of them into one "unique" -- every SIGSEGV in the
            # program is the same finding, however many distinct defects produced them.
            if libc.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs)) == 0:
                fault_pc = regs.rip - base
            rc = -sig                                   # fatal: report it, and do not deliver,
            libc.ptrace(PTRACE_KILL, pid, 0, 0)         # so no core dump handler runs
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            break
        if libc.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs)) != 0:
            break
        hit = regs.rip - 1
        rel = hit - base
        if rel in original and rel not in restored:     # one-shot: restore and never re-arm
            restored.add(rel)
            _poke_byte(libc, pid, mem, hit, original[rel])
            regs.rip = hit
            libc.ptrace(13, pid, 0, ctypes.byref(regs))  # PTRACE_SETREGS
            reached.append(rel)
    if mem is not None:
        try:
            os.close(mem)
        except OSError:
            pass
    out = _drain(r_out); err = _drain(r_err)
    return rc, out, err, flags, reached, fault_pc


def _now():
    import time
    return time.time()


def _drain(fd, cap=4096):
    os.set_blocking(fd, False)
    data = b""
    try:
        while len(data) < cap:
            c = os.read(fd, cap - len(data))
            if not c:
                break
            data += c
    except (BlockingIOError, OSError):
        pass
    finally:
        os.close(fd)
    return data


def main():
    mode = sys.argv[1]
    per_timeout = float(sys.argv[2])
    exe = sys.argv[3]
    base_argv = sys.argv[4:]
    wf = "/tmp/lykos-fuzz-input.bin"        # fixed: a per-batch name leaked into diagnostics
    (count, n_blocks) = struct.unpack("<II", _readn(8))
    blocks = list(struct.unpack("<%dQ" % n_blocks, _readn(8 * n_blocks))) if n_blocks else []
    libc = ctypes.CDLL("libc.so.6", use_errno=True) if blocks else None
    if libc is not None:
        libc.ptrace.restype = ctypes.c_long
        libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p,
                                ctypes.c_void_p]
    out = sys.stdout.buffer
    plan: dict = {}          # the patched image, built on the first traced run and replayed
    for _ in range(count):
        (ln,) = struct.unpack("<I", _readn(4))
        data = _readn(ln)
        if mode == "arg":
            argv = [exe] + base_argv + [data.split(b"\x00", 1)[0].decode("latin-1")]
            stdin = b""
        elif mode == "file":
            with open(wf, "wb") as fh:
                fh.write(data)
            argv = [exe] + base_argv + [wf]
            stdin = b""
        else:
            argv, stdin = [exe] + base_argv, data
        reached, fault_pc = [], 0
        if blocks:
            rc, so, se, flags, reached, fault_pc = _trace_one(libc, argv, stdin, per_timeout,
                                                              blocks, exe, plan)
        else:
            try:
                pr = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=per_timeout)
                rc, so, se, flags = pr.returncode, pr.stdout[:4096], pr.stderr[:4096], 0
            except subprocess.TimeoutExpired:
                rc, so, se, flags = 0, b"", b"", 1
            except Exception:
                rc, so, se, flags = 0, b"", b"", 2
        out.write(struct.pack("<iIIBIQ", rc, len(so), len(se), flags, len(reached), fault_pc))
        out.write(so); out.write(se)
        if reached:
            out.write(struct.pack("<%dQ" % len(reached), *reached))
    out.flush()


if __name__ == "__main__":
    main()
