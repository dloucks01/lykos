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

# ---------------------------------------------------------------------------------- absorbed
# This tracer runs as a standalone script: the parent copies it into a scratch dir and runs it
# with `python3 heaptrace.py spec.json report.json`, so `lykos.observe` is not importable. A
# step skipped quietly here is exactly what turns a real use-after-free into "no heap error
# observed", so absorbed steps ride home in report.json and the parent folds them in.
_ABSORBED: list = []


def _absorbed(what):
    exc = sys.exc_info()[1]
    _ABSORBED.append({"what": what, "exc": repr(exc)[:200]})


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


#: Written into the allocation that takes a freed chunk, so the tracer can tell the attacker's
#: bytes from whatever was there before. All digits: a menu that case-folds stored text mangles
#: letters. The STAGE passes the one definition (`poc.primitive.RECLAIM_MARKER`) to both this and
#: the tracer spec; this default only serves a direct caller.
RECLAIM_MARKER = b"4718295036471829"


def heap_op_sequences(menu_options, *, max_seqs: int = 40,
                      marker: bytes = RECLAIM_MARKER) -> list[bytes]:
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
    # cross-option create; FREE-op; USE-op -- the use-after-free shape (free one option, then a
    # different option reads/writes the same object). Every ordered pair, since we do not know
    # which option is free vs print/modify; try object id 0 and 1 (either could be the first).
    for oid in (b"0", b"1"):
        for i in opts:
            for j in opts:
                if i == j:
                    continue
                seqs.append(create + i.encode() + nl + oid + nl + j.encode() + nl + oid + nl)
    # allocate two, cross-free, re-free (tcache double-free / UAF shapes)
    if len(opts) >= 3:
        a, b2 = opts[1].encode(), opts[2].encode()
        seqs.append(create + create + a + nl + b"0" + nl + a + nl + b"0" + nl)
        seqs.append(create + b2 + nl + b"0" + nl + b2 + nl + b"0" + nl)
    # RECLAIM shape: create two, free the first, then create a THIRD of the same size. The
    # allocator hands the freed chunk straight back (LIFO), which is the observation that turns a
    # lifetime defect into a controllable one -- and no other sequence here provokes it, so the
    # tracer's reclaim event could never fire however many sequences it drove.
    nd = marker                                         # the bytes the tracer looks for
    seqs.append(create + create
                + opts[1].encode() + nl + b"0" + nl                     # free object 0
                + opts[0].encode() + nl + b"64" + nl + nd + nl          # same size: takes it back
                + create)                                               # a stop AFTER the fill
    if len(opts) >= 3:                                  # ...and then USE the stale entry
        seqs.append(create + create + opts[1].encode() + nl + b"0" + nl
                    + opts[0].encode() + nl + b"64" + nl + nd + nl
                    + opts[2].encode() + nl + b"0" + nl)
    # heap-OVERFLOW shape: allocate a SMALL object, then drive each option with an over-long
    # payload (the classic "modify/edit" bug that writes past the requested size). Object id 0/1.
    small = opts[0].encode() + nl + b"16" + nl + b"A" * 8 + nl
    big = b"B" * 128
    for act in opts[1:]:
        ab = act.encode()
        seqs.append(small + ab + nl + b"0" + nl + big + nl)     # create small; modify 0 (over-long)
        seqs.append(small + ab + nl + big + nl)                 # create small; modify (no id)
    out, seen = [], set()
    for s in seqs:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out[:max_seqs]


# DR7 LEN encoding per watched length (x86): 00=1, 01=2, 11=4, 10=8 bytes.
_DR7_LEN = {1: 0b00, 2: 0b01, 4: 0b11, 8: 0b10}


def watch_len(addr: int, limit=None) -> int:
    """The hardware-watch length for a guard at `addr`: the largest of 8/4/2/1 that `addr` is
    aligned to, capped at `limit` (the guard element's size) when known.

    x86 IGNORES the low address bits below the watch length, so an 8-byte watch on an address
    that is only 4-aligned watches the qword it sits in -- i.e. the 4 bytes BEFORE the guard. For
    the guard just past an int[] with an odd count that is the array's own last element, and a
    legitimate in-bounds access was filed as an out-of-bounds index. Watching exactly from `addr`
    (and no wider than one element) keeps the guard outside the array on both sides."""
    n = 8
    while n > 1 and addr % n:
        n //= 2
    if limit:
        while n > 1 and n > int(limit):
            n //= 2
    return n


if __name__ == "__main__":                                            # ---- the ptrace tracer ----
    import ctypes
    import json
    import os
    import signal
    import sys
    import threading

    PTRACE_TRACEME, PTRACE_PEEKTEXT, PTRACE_PEEKUSER, PTRACE_POKETEXT, PTRACE_POKEUSER = 0, 1, 3, 4, 6
    PTRACE_CONT, PTRACE_SINGLESTEP, PTRACE_GETREGS, PTRACE_SETREGS = 7, 9, 12, 13
    PTRACE_GETSIGINFO = 0x4202                           # si_addr: WHERE the fault touched
    _DR = 848                                            # offsetof(struct user, u_debugreg) on x86-64

    class _Regs(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in (
            "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx",
            "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base",
            "gs_base", "ds", "es", "fs", "gs")]

    def main() -> int:
        with open(sys.argv[1]) as _f:
            spec = json.load(_f)
        exe = spec["exe"]
        stdin_bytes = bytes.fromhex(spec.get("stdin", ""))
        # alloc/free tracking is optional: with neither, the tracer runs in pure OOB-index mode
        # (only the static guard watchpoints below are armed).
        free_off = spec.get("free_off")
        free_off = int(free_off) if free_off is not None else None
        alloc_ret_offs = [int(x) for x in spec.get("alloc_ret_offs", [])]
        alloc_base_off = spec.get("alloc_off")           # alloc function file/vaddr offset
        alloc_base_off = int(alloc_base_off) if alloc_base_off is not None else None
        # PLT mode: alloc_off is the libc malloc PLT stub (a stripped target's allocator IS libc).
        # There is no local `ret` to read rax from, so at the stub entry we breakpoint the caller's
        # return address ([rsp]) one-shot and read rax there. libc's own metadata writes make the
        # end-of-chunk OVERFLOW watch unreliable (heap_check's guard pages cover libc overflow), so
        # PLT mode reports only double-free + use-after-free.
        alloc_is_plt = bool(spec.get("alloc_is_plt", False))
        report = spec["report"]
        timeout = int(spec.get("timeout", 15))
        # Static guard watchpoints: [off, note] pairs (vaddr offsets, rebased for PIE) armed from
        # the start. A read/write to a guard from program code = an out-of-bounds ARRAY access (the
        # guard sits just before/after a fixed-size global array = an unchecked index (CWE-129).
        # [offset, note] or [offset, note, length]: `length` (the element stride) bounds the
        # watch so it can never cover the array's own first element (see watch_len)
        static_watch = [(int(g[0]), str(g[1]), (int(g[2]) if len(g) > 2 and g[2] else None))
                        for g in spec.get("static_watch", []) if len(g) >= 2]
        # The bytes the driving sequence writes into the allocation that RECLAIMS a freed chunk.
        # With them the tracer can answer the question a target with no printing path cannot:
        # are the ATTACKER's bytes in the chunk a stale pointer still addresses? Memory is read
        # straight out of the child, so no `view` option and no program output is needed.
        marker = bytes.fromhex(spec.get("marker") or "")
        # A function the stage CHOSE, as a vaddr. Breakpointed so that "the program executed it"
        # is an observation rather than an inference from a missing crash: the reclaim payload
        # carries this address instead of the sentinel, and the breakpoint either fires or does
        # not. The stage needs the load base to build that payload, so the report carries it.
        exec_target = spec.get("exec_target")
        exec_target = int(exec_target) if exec_target is not None else None
        # [start, end) offsets of the allocator FAMILY (alloc/free + helpers). A watchpoint that
        # fires from inside this code is the allocator's own bookkeeping / compaction, not a program
        # use-after-free -- ignore those, count only accesses from outside the allocator.
        ignore_ranges = [(int(a), int(b)) for a, b in spec.get("ignore_ranges", [])]

        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace.restype = ctypes.c_long
        libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]

        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:                                     # child: trace me, become the target
            os.close(w)
            os.dup2(r, 0)
            os.close(r)
            try:                                         # ASLR off: deterministic chunk addresses
                cur = libc.personality(0xffffffff)       # so the chain's inline heap pointers land
                if cur != -1:
                    libc.personality(cur | 0x0040000)    # ADDR_NO_RANDOMIZE
            except Exception:
                _absorbed("continuing")
            libc.ptrace(PTRACE_TRACEME, 0, None, None)
            try:
                os.execv(exe, [exe])
            except OSError:
                os._exit(127)
        os.close(r)
        # Feed stdin from a thread: the target is stopped at its execv trap and has not started
        # reading, so a stdin_bytes larger than the ~64 KB pipe buffer would block this write with
        # no timeout yet armed (the SIGALRM is set up further down). A daemon thread writes and
        # closes w (EOF ends the target's read loop) without ever blocking the tracer.
        def _feed_stdin():
            try:
                os.write(w, stdin_bytes)
            except OSError:
                pass
            finally:
                try:
                    os.close(w)
                except OSError:
                    pass
        threading.Thread(target=_feed_stdin, daemon=True).start()

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

        def read_mem(addr, n):
            """`n` bytes of the tracee's memory, or b"" if unreadable. PEEK returns a word at a
            time, which is all this needs: the marker sits at the start of a reclaimed chunk."""
            out = bytearray()
            for off in range(0, (n + 7) & ~7, 8):
                w = peek(addr + off)
                if w is None:
                    break
                out += w.to_bytes(8, "little")
            return bytes(out[:n])

        # --- hardware watchpoints (DR0-3 + DR7) for use-after-free detection ---
        def poke_dr(n, val):
            libc.ptrace(PTRACE_POKEUSER, pid, ctypes.c_void_p(_DR + n * 8), ctypes.c_void_p(val))

        def peek_dr(n):
            ctypes.set_errno(0)
            v = libc.ptrace(PTRACE_PEEKUSER, pid, ctypes.c_void_p(_DR + n * 8), None)
            return 0 if (v == -1 and ctypes.get_errno()) else (v & 0xFFFFFFFFFFFFFFFF)

        def set_watch(slot, addr, rw=0b11, length=8):
            poke_dr(slot, addr)                          # DRn = watched address
            dr7 = peek_dr(7)
            dr7 |= (1 << (slot * 2))                     # Ln: local enable
            dr7 &= ~(0b1111 << (16 + slot * 4))
            dr7 |= (rw << (16 + slot * 4))               # R/W: 0b11 read+write, 0b01 write-only
            dr7 |= (_DR7_LEN.get(length, 0b10) << (18 + slot * 4))   # LEN: 1/2/4/8 bytes
            poke_dr(7, dr7)

        def clear_watch(slot):
            dr7 = peek_dr(7)
            dr7 &= ~((0b11 << (slot * 2)) | (0b1111 << (16 + slot * 4)))
            poke_dr(7, dr7)

        def load_base():
            """(load base, end of the exe's executable mapping). The code end bounds a UAF access to
            the target's OWN code, so a libc mem* the allocator calls is not read as a program UAF."""
            base = code_end = 0
            name = exe.split("/")[-1]
            with open(f"/proc/{pid}/maps") as _maps:
                for line in _maps:
                    if name not in line and exe not in line:
                        continue
                    a, b = line.split()[0].split("-")
                    if base == 0:
                        base = int(a, 16)
                    if "x" in line.split()[1]:               # executable segment of the exe
                        code_end = max(code_end, int(b, 16))
            return base, (code_end or (base + (1 << 24)))

        base, code_end = load_base()
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

        if exec_target is not None:
            setbp(rebase + exec_target, "exec")
        if free_off is not None:
            setbp(rebase + free_off, "free")
        if alloc_base_off is not None:
            setbp(rebase + alloc_base_off, "alloc_enter")    # entry: rdi = requested size
            for ro in alloc_ret_offs:
                setbp(rebase + alloc_base_off + ro, "alloc")

        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
        signal.alarm(timeout)

        freed = set()                                    # pointers currently free
        def check_reclaims():
            """AFTER: is the marker in a chunk that was handed back out? This is the oracle for a
            target with NO printing path -- the marker experiment in `heap_discover` needs a
            `view` option to read the stale entry back, and most targets have none. Memory is
            read straight out of the tracee, and the before/after pair is a stronger control than
            the output route can offer: a program that echoes recent input cannot fool a read of
            the chunk itself.
            """
            for chunk, info in list(pending_reclaim.items()):
                data = read_mem(chunk, min(256, int(info["size"]) + 16))
                if not data:
                    continue
                at = data.find(marker)
                if at < 0:
                    continue
                del pending_reclaim[chunk]
                events.append({"event": "reclaim-controlled", "addr": hex(chunk),
                               "offset": at, "size": info["size"],
                               # True would mean the marker was already there before the free,
                               # which disqualifies the observation; it is reported either way.
                               "marker_before_free": info["pre"]})
                # Now watch for the READ. Armed HERE, after the marker is confirmed, which is
                # what makes the observation unambiguous: the reclaiming owner's fill has already
                # happened, so any later read of this chunk from the program's own code is a read
                # of the ATTACKER's bytes by something that is not the filler. Before the reclaim
                # the same address carries a `uaf` watch, whose meaning is different -- that one
                # says "memory that is FREE was touched", and this one says "memory that now
                # belongs to someone else was read through a pointer the program should have
                # stopped using".
                stale_at[chunk] = at
                arm(chunk + at, "stale", chunk, 0b11)

        def siginfo_addr():
            """`si_addr` of the pending signal -- the address the fault touched -- or None."""
            buf = (ctypes.c_ubyte * 128)()
            if libc.ptrace(PTRACE_GETSIGINFO, pid, None, ctypes.byref(buf)) == -1:
                return None
            # siginfo_t on x86-64: si_signo/si_errno/si_code are three ints, then the union; for
            # SIGSEGV/SIGBUS the first member is void *si_addr at offset 16.
            return int.from_bytes(bytes(buf[16:24]), "little")

        def classify_fault(sig):
            """WHAT the program did with the attacker's bytes, from where it faulted.

            The last link of the reclaim chain. The three earlier facts are states of memory and
            an access; this one is a consequence, and it is read off the fault rather than
            guessed from the instruction stream: `pc == our bytes` means the program CALLED
            through the value it read, and `fault address == our bytes` means it dereferenced it.
            Anything else is reported as a fault after the reclaim with no mechanism claimed.
            """
            rg2 = getregs()
            where = siginfo_addr()
            words = {int.from_bytes(marker[i:i + 8], "little")
                     for i in range(0, max(1, len(marker) - 7))}
            kind, via = None, None
            if rg2.rip in words:
                # A CANONICAL but unmapped target: the fetch page-faults AT the target, so the
                # pc IS the attacker's bytes.
                kind = "control-flow-hijack"
            elif where is not None and where in words:
                kind = "dereference"
            else:
                # The common case for a printable sentinel, and it took a measurement to see:
                # eight ASCII bytes make a NON-CANONICAL address (the top bytes can never be
                # zero), so a jump to it raises #GP rather than a page fault -- and the kernel
                # reports #GP as SIGSEGV with si_addr 0 and the pc still ON the faulting
                # instruction. Neither of the two tests above can fire, and the hijack is real.
                # The evidence is then: the faulting instruction is an INDIRECT CALL/JMP through
                # a register, and that register holds the attacker's bytes.
                code = read_mem(rg2.rip, 4) or b""
                i = 0
                while i < len(code) and 0x40 <= code[i] <= 0x4F:     # REX prefixes
                    i += 1
                indirect = (i + 1 < len(code) and code[i] == 0xFF
                            and ((code[i + 1] >> 3) & 7) in (2, 3, 4, 5))
                if indirect:
                    for rn in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"):
                        if getattr(rg2, rn, None) in words:
                            kind, via = "control-flow-hijack", rn
                            break
            # What is in the watched chunk AT THE FAULT. Without it a "fault" verdict is a dead
            # end for whoever reads the report: the chunk held the marker when the reclaim was
            # confirmed, and if it does not now, something overwrote it and that is the fact
            # worth knowing.
            now = {}
            for chunk in list(stale_at)[:2]:
                d8 = read_mem(chunk, 16)
                if d8:
                    now[hex(chunk)] = d8.hex()
            events.append({"event": "reclaim-effect", "kind": kind or "fault",
                           "signal": int(sig), "pc": hex(rg2.rip),
                           "fault_addr": (hex(where) if where is not None else None),
                           # WHICH register carried the attacker's bytes into the control
                           # transfer, when that is how the hijack showed itself.
                           "via": via, "chunk_now": now})

        live = {}                                        # live ptr -> {"size", "end", "slot"}
        #: chunk -> was the marker ALREADY in it when it was freed? The before half of the
        #: reclaim test: finding the marker after a reclaim means nothing if it was there
        #: beforehand (the victim could have carried it), and the output oracle has no
        #: equivalent of this check.
        pre_marker = {}
        #: chunk -> {"size", "pre"} for a chunk handed back out and not yet inspected. Read at
        #: the next breakpoint, because at the allocation's RETURN the program has not filled it
        #: yet -- the fill is the read() that comes after.
        pending_reclaim = {}
        #: chunk -> the offset the marker was found at, for a chunk whose post-reclaim READ is
        #: being watched. The reading half of the reclaim chain.
        stale_at = {}
        stale_seen = set()
        pending_size = 0                                  # rdi captured at the last alloc entry
        free_slots = [0, 1, 2, 3]                         # DR0-3 available for watchpoints
        watches = {}                                      # slot -> {"addr", "kind", "chunk"}
        uaf_seen, of_seen, oob_seen = set(), set(), set()
        oneshot = set()                                   # PLT alloc-return bps: fire once, remove
        alloc_addrs = []                                  # chunk addresses in allocation order
        alloc_sizes = []                                  # requested size per allocation (parallel)
        events = []

        def in_allocator(rip):
            off = rip - rebase
            return any(a <= off < b for a, b in ignore_ranges)

        def arm(addr, kind, chunk, rw, length=8):
            """Take a debug-register slot and watch `addr` (UAF: read+write on freed data;
            overflow: write-only just past a live chunk's end). Best-effort: no-op when slots are
            exhausted."""
            if not free_slots:
                return None
            slot = free_slots.pop()
            watches[slot] = {"addr": addr, "kind": kind, "chunk": chunk}
            set_watch(slot, addr, rw, length)
            return slot

        def disarm(slot):
            if slot is None or slot not in watches:
                return
            clear_watch(slot)
            watches.pop(slot, None)
            free_slots.append(slot)

        def clear_covering(lo, hi):
            """Drop any watch whose address falls in [lo, hi) -- a chunk being (re)allocated there
            reclaims the region, so a stale UAF/overflow watch on it would false-positive."""
            for slot, w in list(watches.items()):
                if lo <= w["addr"] < hi:
                    disarm(slot)

        # Arm the static array guards up front (read+write): a hit means program code indexed the
        # array out of bounds. These hold their slots for the whole run.
        for off, note, glen in static_watch:
            ga = rebase + off
            slot = arm(ga, "static", None, 0b11, watch_len(ga, glen))
            if slot is not None:
                watches[slot]["note"] = note

        try:
            while True:
                libc.ptrace(PTRACE_CONT, pid, None, None)
                wpid, status = os.waitpid(pid, 0)
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    break
                if not (os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP):
                    _sig = os.WSTOPSIG(status)
                    # A FAULT after a reclaim is the last question in the chain: the program read
                    # the attacker's bytes, and this says what it DID with them. The marker is
                    # eight ASCII digits, so as a machine word it is an unmapped address -- if
                    # the program CALLS through it the pc IS our bytes, and if it dereferences it
                    # the faulting address is. Nothing is inferred from the signal alone.
                    if marker and stale_at and _sig in (signal.SIGSEGV, signal.SIGBUS,
                                                        signal.SIGILL):
                        try:
                            classify_fault(_sig)
                        except Exception:
                            _absorbed("continuing")
                    # deliver the signal (e.g. the target's own SIGSEGV) and continue
                    libc.ptrace(PTRACE_CONT, pid, None, ctypes.c_void_p(_sig))
                    continue
                rg = getregs()
                # A hardware-watchpoint hit (DR6 B0-B3) = freed memory was ACCESSED. Count it as a
                # use-after-free only when the access came from the target's OWN code and NOT from
                # the allocator family (its bookkeeping / compaction writes freed regions itself).
                dr6 = peek_dr(6)
                if dr6 & 0xF:
                    in_code = base <= rg.rip < code_end
                    in_alloc = in_allocator(rg.rip)
                    for slot in range(4):
                        if not (dr6 & (1 << slot)):
                            continue
                        w = watches.get(slot)
                        if not w:
                            continue
                        # UAF is conservative: only the target's OWN code counts (a libc mem* the
                        # allocator drives over a freed chunk is bookkeeping, not a program UAF).
                        if (w["kind"] == "uaf" and w["chunk"] in freed
                                and in_code and not in_alloc):
                            key = (w["chunk"], rg.rip)
                            if key not in uaf_seen:
                                uaf_seen.add(key)
                                events.append({"error": "use-after-free", "addr": hex(w["chunk"]),
                                               "pc": hex(rg.rip)})
                        # THE READING HALF: the program touched a chunk that was handed back
                        # out and refilled with the attacker's bytes. Same conservatism as the
                        # UAF case -- the target's own code only, never the allocator's -- and
                        # reported under its own name, because "read memory that now belongs to
                        # another object" is a different fact from "touched memory that is free".
                        elif (w["kind"] == "stale" and in_code and not in_alloc):
                            key = (w["chunk"], rg.rip)
                            if key not in stale_seen:
                                stale_seen.add(key)
                                events.append({
                                    "event": "reclaim-use", "addr": hex(w["chunk"]),
                                    "pc": hex(rg.rip),
                                    "marker_offset": stale_at.get(w["chunk"])})
                        # A WRITE to the qword just past a LIVE chunk is an overflow by
                        # construction; the writer is usually a libc strcpy/memcpy called by the
                        # program, so allow any PC except the allocator's own (its next-chunk setup
                        # writes there legitimately, but clear_covering drops the watch first).
                        elif w["kind"] == "overflow" and not in_alloc:
                            key = (w["addr"], rg.rip)
                            if key not in of_seen:
                                of_seen.add(key)
                                events.append({"error": "heap-overflow", "addr": hex(w["chunk"]),
                                               "end": hex(w["addr"]), "pc": hex(rg.rip)})
                        # A guard just before/after a fixed-size array was touched by program code:
                        # an out-of-bounds array index (a missing / off-by-one bound check).
                        elif w["kind"] == "static" and in_code and not in_alloc:
                            key = (w["addr"], rg.rip)
                            if key not in oob_seen:
                                oob_seen.add(key)
                                events.append({"error": "oob-index", "addr": hex(w["addr"]),
                                               "array": w.get("note"), "pc": hex(rg.rip)})
                    poke_dr(6, 0)
                    continue                              # the access already retired; resume
                if pending_reclaim:
                    check_reclaims()
                bp = rg.rip - 1
                info = bps.get(bp)
                if info is None:
                    continue
                kind, orig = info
                if kind == "free":
                    ptr = rg.rdi
                    if ptr:
                        if marker:
                            # BEFORE: the marker must not already be in this chunk, or finding it
                            # after the reclaim would prove nothing about who put it there.
                            pre_marker[ptr] = marker in read_mem(ptr, 64)
                        if ptr in freed:
                            events.append({"error": "double-free", "addr": hex(ptr)})
                        freed.add(ptr)
                        # the chunk is dead: drop its end-of-chunk overflow watch, then watch its
                        # data for a use-after-free.
                        if ptr in live:
                            disarm(live.pop(ptr).get("slot"))
                        if not any(w["chunk"] == ptr and w["kind"] == "uaf"
                                   for w in watches.values()):
                            arm(ptr, "uaf", ptr, 0b11)   # read+write on freed data = UAF
                elif kind == "exec":
                    # ARRIVAL at the chosen function. The attacker's own input carried this
                    # address into the reclaimed object and the program called it, so this is
                    # code execution observed at the target, not deduced from a signal.
                    events.append({"event": "reclaim-exec", "addr": hex(bp),
                                   "target": hex(exec_target or 0),
                                   "returns_to": hex(peek(rg.rsp) or 0)})
                elif kind == "alloc_enter":              # entry: capture the requested size (rdi)
                    pending_size = rg.rdi
                    if alloc_is_plt:                     # libc stub: no local ret -> catch the
                        ret = peek(rg.rsp)               # caller's return address ([rsp]) once
                        if ret and ret not in bps:
                            setbp(ret, "alloc")
                            oneshot.add(ret)
                else:                                    # alloc return: rax = new pointer
                    ptr = rg.rax
                    size, pending_size = pending_size, 0
                    # RECLAIM: this allocation was handed the address of a chunk that is currently
                    # FREE. The tracer already knew that -- it is what `freed.discard` below acts
                    # on -- and threw it away, so the one observation that turns a lifetime defect
                    # into a controllable one was computed and discarded on every run. It is not an
                    # error (the allocator is behaving exactly as designed), so it is recorded
                    # under `event` rather than `error`: nothing downstream may mistake it for a
                    # fault, and a target with no printing path still gets the evidence.
                    if ptr in freed:
                        events.append({"event": "reclaim", "addr": hex(ptr), "size": size})
                        if marker:
                            pending_reclaim[ptr] = {"size": max(int(size or 0), 64),
                                                    "pre": bool(pre_marker.get(ptr))}
                    freed.discard(ptr)                   # handed back out -> live again
                    if len(alloc_addrs) < 16:
                        alloc_addrs.append(ptr)          # deterministic (ASLR-off) chunk addresses
                        alloc_sizes.append(size)         # the requested size (operator new / malloc)
                    if alloc_is_plt:
                        clear_covering(ptr, ptr + max(size, 8))   # reclaim stale UAF watches
                    elif ptr and 0 < size <= (1 << 20):
                        end = (ptr + size + 7) & ~7      # first aligned qword past the buffer
                        clear_covering(ptr, end + 8)     # reclaim stale watches on this region
                        slot = arm(end, "overflow", ptr, 0b01)   # write past end = overflow
                        live[ptr] = {"size": size, "end": end, "slot": slot}
                    elif ptr:
                        clear_covering(ptr, ptr + 8)
                # step over the int3: restore, single-step, then re-arm (unless it was a one-shot
                # PLT alloc-return breakpoint, which is removed after it fires).
                poke(bp, (peek(bp) & ~0xFF) | orig)
                setrip(rg, bp)
                libc.ptrace(PTRACE_SINGLESTEP, pid, None, None)
                os.waitpid(pid, 0)
                if bp in oneshot:
                    oneshot.discard(bp)
                    bps.pop(bp, None)
                else:
                    poke(bp, (peek(bp) & ~0xFF) | 0xCC)
        except TimeoutError:
            events.append({"note": "timeout"})
        finally:
            # One last look before the tracee dies: the fill may have happened after the last
            # heap operation, which on a short sequence is the common case.
            try:
                if pending_reclaim and marker:
                    check_reclaims()
            except Exception:
                _absorbed("continuing")
            signal.alarm(0)
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except OSError:
                pass

        # Explicit close: this driver is killed on timeout, and a handle the GC never reached
        # leaves the parent a truncated report that it then fails to parse -- silently.
        with open(report, "w") as _rf:
            json.dump({"events": events,
                       # Where the image landed. ASLR is off in this tracer, so it is deterministic
                       # -- and the stage needs it to put a real code address in a reclaim payload.
                       "load_base": hex(rebase),
                       # Both halves of a use-after-free, reported separately because they are
                       # different observations: the program USED a dead chunk, and a dead chunk was
                       # handed back out to a later allocation.
                       "reclaim": any(e.get("event") == "reclaim" for e in events),
                       "reclaims": [e for e in events if e.get("event") == "reclaim"][:16],
                       # The chunk came back AND the attacker's bytes are in it -- the half the
                       # tracer could not show before, and the only reclaim evidence available on a
                       # target with no printing path. `marker_before_free` disqualifies an
                       # observation, so it travels with it rather than being filtered out here.
                       "reclaim_controlled": [e for e in events
                                              if e.get("event") == "reclaim-controlled"][:16],
                       # The program READ the attacker's bytes out of the reclaimed chunk. The chunk
                       # coming back is one fact, the bytes being the attacker's is a second, and
                       # this is the third -- the only one that shows a USE.
                       "reclaim_use": [e for e in events
                                       if e.get("event") == "reclaim-use"][:16],
                       # ...and what the program DID with them. `kind` is "control-flow-hijack" when
                       # the pc became our bytes, "dereference" when the faulting address did, and
                       # "fault" when neither -- a consequence observed, never inferred.
                       "reclaim_effect": [e for e in events
                                          if e.get("event") == "reclaim-effect"][:8],
                       # The chosen function was ENTERED. The end of the chain.
                       "reclaim_exec": [e for e in events
                                        if e.get("event") == "reclaim-exec"][:8],
                       "double_free": any(e.get("error") == "double-free" for e in events),
                       "use_after_free": any(e.get("error") == "use-after-free" for e in events),
                       "heap_overflow": any(e.get("error") == "heap-overflow" for e in events),
                       "oob_index": any(e.get("error") == "oob-index" for e in events),
                       "alloc_addrs": [hex(a) for a in alloc_addrs],
                       "alloc_sizes": alloc_sizes,
                       "absorbed": _ABSORBED},
                      _rf)
        return 0

    try:
        sys.exit(main())
    except Exception as e:                               # noqa: BLE001 -- helper: report, don't crash
        try:
            with open(sys.argv[2] if len(sys.argv) > 2 else "/dev/null", "w") as _ef:
                json.dump({"events": [], "error": repr(e), "double_free": False,
                           "absorbed": _ABSORBED}, _ef)
        except Exception:
            _absorbed("continuing")
        sys.exit(1)
