"""Custom-allocator heap-primitive discovery by ptrace.

The LD_PRELOAD guard (heap_stage) only sees the libc allocator; a target with its OWN allocator
(a menu service's `ta_alloc`/`ta_free`, an arena pool, C++ `operator new`) is invisible to it. This
tracer is allocator-AGNOSTIC: it breakpoints the target's identified alloc/free pair, drives a
sequence of operations, and follows the pointer lifecycle to discover a DOUBLE-FREE (CWE-415) --
free of a chunk that is currently free -- the primitive that seeds tcache poisoning -> arbitrary
write. Deterministic, native x86-64, ASLR-off (so a PIE load base is fixed and computed from
/proc/<pid>/maps). Runs as a standalone helper subprocess (like ptrace_capture) so the ptrace
tracer owns the tracee and nothing leaks into the worker.

The importable half (`identify_allocator`) is pure and used by the stage to find the pair; the
`__main__` half is the tracer the stage execs under the sandbox.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------- allocator identification (pure)
_ALLOC_RE = re.compile(r"(?:^|_)(?:m|c|re|x|z)?alloc(?:_\w+)?$|(?:^|_)new(?:_\w+)?$|alloc(?:ate)?$",
                       re.I)
_FREE_RE = re.compile(r"(?:^|_)(?:x|z)?free(?:_\w+)?$|(?:^|_)(?:de)?alloc(?:ate)?$|(?:^|_)del(?:ete)?$|"
                      r"(?:^|_)release(?:_\w+)?$", re.I)
# libc names to skip: the guard-page stage already covers these; we want the target's OWN allocator.
_LIBC = {"malloc", "free", "calloc", "realloc", "reallocarray", "aligned_alloc", "posix_memalign",
         "valloc", "pvalloc", "memalign", "cfree"}


def identify_allocator(functions: dict, call_edges=None) -> dict | None:
    """Find the target's own alloc/free pair from its LOCAL function names, or None.

    `functions` maps name -> addr. A local `*_alloc`/`*alloc`/`new*` paired with a local
    `*_free`/`*free`/`delete*` is the allocator. libc malloc/free are skipped (the LD_PRELOAD guard
    already covers them). When several match, prefer the pair with the most similar name stem
    (ta_alloc/ta_free), which is what a hand-rolled allocator looks like."""
    allocs, frees = [], []
    for name, addr in (functions or {}).items():
        base = name.split("@")[0].lstrip("_")
        low = base.lower()
        if low in _LIBC:
            continue
        if _ALLOC_RE.search(base) and "free" not in low and "del" not in low:
            allocs.append((name, addr, low))
        if _FREE_RE.search(base) and ("free" in low or low.startswith("del") or "release" in low
                                      or low.endswith("dealloc") or "deallocate" in low):
            frees.append((name, addr, low))
    if not (allocs and frees):
        return None

    def _stem(n):
        return re.sub(r"(alloc|free|new|delete|release|dealloc)\w*$", "", n).rstrip("_")

    best = None
    for an, aa, al in allocs:
        for fn, fa, fl in frees:
            score = 2 if (_stem(al) and _stem(al) == _stem(fl)) else 0   # shared stem (ta_)
            score += 1 if ("alloc" in al and "free" in fl) else 0
            if best is None or score > best[0]:
                best = (score, {"alloc_name": an, "alloc": aa, "free_name": fn, "free": fa})
    return best[1] if best else None


def ret_offsets(func_bytes: bytes, limit: int = 8) -> list[int]:
    """Byte offsets of `ret` (0xC3) inside a function body -- where, at a breakpoint, rax holds the
    value the function is about to return. Skips 0xC3 bytes that are operands of a longer
    instruction only crudely (good enough for small allocator functions)."""
    return [i for i, b in enumerate(func_bytes) if b == 0xC3][:limit]


def heap_op_sequences(menu_options, *, max_seqs: int = 40) -> list[bytes]:
    """Menu input sequences that PROVOKE a double-free / UAF: for each option, drive it TWICE on
    the same object (allocate once, then repeat a free/delete option), which is the shape that
    frees a chunk that is already free. Includes create-then-double-act and a plain size-then-data
    create so the tracer sees an allocation first. Best-effort; empty when there is no menu."""
    opts = [str(o) for o in (menu_options or [])]
    if len(opts) < 2:
        return []
    nl = b"\n"
    seqs: list[bytes] = []
    create = opts[0].encode() + nl + b"64" + nl + b"A" * 32 + nl     # add an object (opt, size, data)
    for act in opts:                                                 # each option, twice (id 0)
        ab = act.encode()
        seqs.append(create + ab + nl + b"0" + nl + ab + nl + b"0" + nl)   # create; act 0; act 0
        seqs.append(create + ab + nl + ab + nl)                           # create; act; act (no id)
    # allocate two, cross-free, re-free (tcache double-free / UAF shapes)
    if len(opts) >= 3:
        a, b2 = opts[1].encode(), opts[2].encode()
        seqs.append(create + create + a + nl + b"0" + nl + a + nl + b"0" + nl)
        seqs.append(create + b2 + nl + b"0" + nl + b2 + nl + b"0" + nl)
    out, seen = [], set()
    for s in seqs:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out[:max_seqs]


if __name__ == "__main__":                                            # ---- the ptrace tracer ----
    import ctypes
    import json
    import os
    import signal
    import struct
    import sys

    PTRACE_TRACEME, PTRACE_PEEKTEXT, PTRACE_POKETEXT = 0, 1, 4
    PTRACE_CONT, PTRACE_SINGLESTEP, PTRACE_GETREGS, PTRACE_SETREGS = 7, 9, 12, 13

    class _Regs(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in (
            "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx",
            "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base",
            "gs_base", "ds", "es", "fs", "gs")]

    def main() -> int:
        spec = json.load(open(sys.argv[1]))
        exe = spec["exe"]
        stdin_bytes = bytes.fromhex(spec.get("stdin", ""))
        free_off = int(spec["free_off"])
        alloc_ret_offs = [int(x) for x in spec.get("alloc_ret_offs", [])]
        alloc_base_off = int(spec["alloc_off"])          # alloc function file/vaddr offset
        report = spec["report"]
        timeout = int(spec.get("timeout", 15))

        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace.restype = ctypes.c_long
        libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]

        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:                                     # child: trace me, become the target
            os.close(w)
            os.dup2(r, 0)
            os.close(r)
            libc.ptrace(PTRACE_TRACEME, 0, None, None)
            try:
                os.execv(exe, [exe])
            except OSError:
                os._exit(127)
        os.close(r)
        os.write(w, stdin_bytes)
        os.close(w)                                      # EOF ends the target's read loop

        os.waitpid(pid, 0)                               # initial stop at execv

        def getregs():
            rg = _Regs()
            libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(rg))
            return rg

        def setrip(rg, rip):
            rg.rip = rip
            libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(rg))

        def peek(addr):
            ctypes.set_errno(0)
            v = libc.ptrace(PTRACE_PEEKTEXT, pid, ctypes.c_void_p(addr), None)
            return None if (v == -1 and ctypes.get_errno()) else (v & 0xFFFFFFFFFFFFFFFF)

        def poke(addr, val):
            libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(addr), ctypes.c_void_p(val))

        def load_base():
            for line in open(f"/proc/{pid}/maps"):
                if exe.split("/")[-1] in line and "r-xp" in line or (exe in line):
                    return int(line.split("-")[0], 16)
            # fall back to the first executable mapping of the exe
            for line in open(f"/proc/{pid}/maps"):
                if exe.split("/")[-1] in line:
                    return int(line.split("-")[0], 16)
            return 0

        base = load_base()
        # For a non-PIE EXEC the vaddr offsets ARE absolute; base-add only relocates a PIE image.
        pie = spec.get("pie", False)
        rebase = base if pie else 0

        bps = {}                                         # addr -> ("free"|"alloc", orig_byte)
        def setbp(addr, kind):
            orig = peek(addr)
            if orig is None:
                return
            poke(addr, (orig & ~0xFF) | 0xCC)
            bps[addr] = (kind, orig & 0xFF)

        free_addr = rebase + free_off
        setbp(free_addr, "free")
        for ro in alloc_ret_offs:
            setbp(rebase + alloc_base_off + ro, "alloc")

        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
        signal.alarm(timeout)

        freed = set()                                    # pointers currently free
        events = []
        try:
            while True:
                libc.ptrace(PTRACE_CONT, pid, None, None)
                wpid, status = os.waitpid(pid, 0)
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    break
                if not (os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP):
                    # deliver other signals (e.g. the target's own SIGSEGV) and continue
                    libc.ptrace(PTRACE_CONT, pid, None,
                                ctypes.c_void_p(os.WSTOPSIG(status)))
                    continue
                rg = getregs()
                bp = rg.rip - 1
                info = bps.get(bp)
                if info is None:
                    continue
                kind, orig = info
                if kind == "free":
                    ptr = rg.rdi
                    if ptr:
                        if ptr in freed:
                            events.append({"error": "double-free", "addr": hex(ptr)})
                        freed.add(ptr)
                else:                                    # alloc return: rax = new pointer
                    ptr = rg.rax
                    freed.discard(ptr)                   # handed back out -> live again
                # step over the int3: restore, single-step, re-arm
                poke(bp, (peek(bp) & ~0xFF) | orig)
                setrip(rg, bp)
                libc.ptrace(PTRACE_SINGLESTEP, pid, None, None)
                os.waitpid(pid, 0)
                poke(bp, (peek(bp) & ~0xFF) | 0xCC)
        except TimeoutError:
            events.append({"note": "timeout"})
        finally:
            signal.alarm(0)
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except OSError:
                pass

        json.dump({"events": events,
                   "double_free": any(e.get("error") == "double-free" for e in events)},
                  open(report, "w"))
        return 0

    try:
        sys.exit(main())
    except Exception as e:                               # noqa: BLE001 -- helper: report, don't crash
        try:
            json.dump({"events": [], "error": repr(e), "double_free": False},
                      open(sys.argv[2] if len(sys.argv) > 2 else "/dev/null", "w"))
        except Exception:
            pass
        sys.exit(1)
