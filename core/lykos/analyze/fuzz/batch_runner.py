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
        then stdout, stderr, and n_new * u64 newly reached block addresses
"""
import ctypes
import os
import struct
import subprocess
import sys

PTRACE_TRACEME, PTRACE_PEEKTEXT, PTRACE_POKETEXT = 0, 1, 4
PTRACE_CONT, PTRACE_KILL, PTRACE_GETREGS = 7, 8, 12
_INT3 = 0xCC


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


def _trace_one(libc, argv, stdin_data, timeout, blocks, exe):
    """Run one input under ptrace. Returns (rc, out, err, flags, reached)."""
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
    original = {}
    for rel in blocks:
        addr = base + rel
        word = libc.ptrace(PTRACE_PEEKTEXT, pid, ctypes.c_void_p(addr), 0)
        if word == -1:
            continue
        original[addr] = word & 0xFF
        patched = (word & ~0xFF) | _INT3
        libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(addr),
                    ctypes.c_void_p(patched & 0xFFFFFFFFFFFFFFFF))

    reached, regs = [], _Regs()
    deadline = _now() + timeout
    rc, flags = 0, 0
    while True:
        libc.ptrace(PTRACE_CONT, pid, 0, 0)
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
        if sig != 5:                                    # a real fault: report it as the signal
            rc = -sig
            libc.ptrace(PTRACE_KILL, pid, 0, 0)
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            break
        if libc.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs)) != 0:
            break
        hit = regs.rip - 1
        if hit in original:                             # one-shot: restore and never re-arm
            word = libc.ptrace(PTRACE_PEEKTEXT, pid, ctypes.c_void_p(hit), 0)
            libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(hit),
                        ctypes.c_void_p(((word & ~0xFF) | original.pop(hit))
                                        & 0xFFFFFFFFFFFFFFFF))
            regs.rip = hit
            libc.ptrace(13, pid, 0, ctypes.byref(regs))  # PTRACE_SETREGS
            reached.append(hit - base)
    out = _drain(r_out); err = _drain(r_err)
    return rc, out, err, flags, reached


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
        reached = []
        if blocks:
            rc, so, se, flags, reached = _trace_one(libc, argv, stdin, per_timeout,
                                                    blocks, exe)
        else:
            try:
                pr = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=per_timeout)
                rc, so, se, flags = pr.returncode, pr.stdout[:4096], pr.stderr[:4096], 0
            except subprocess.TimeoutExpired:
                rc, so, se, flags = 0, b"", b"", 1
            except Exception:
                rc, so, se, flags = 0, b"", b"", 2
        out.write(struct.pack("<iIIBI", rc, len(so), len(se), flags, len(reached)))
        out.write(so); out.write(se)
        if reached:
            out.write(struct.pack("<%dQ" % len(reached), *reached))
    out.flush()


if __name__ == "__main__":
    main()
