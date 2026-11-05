"""Precise P-Code detectors -- binary analogues of the source guard/overflow detectors.

The first (and so far only) detector here is ALLOCATION-SIZE INTEGER OVERFLOW (CWE-190 leading to
an undersized heap buffer, CWE-122/CWE-787): an allocator call whose size argument is computed by
an INT_MULT / INT_ADD / INT_LEFT that

  (a) CAN WRAP given the operands' TRUE source widths -- read off P-Code's explicit INT_ZEXT /
      INT_SEXT / SUBPIECE and the load widths, not off the register the arithmetic happens to sit
      in. `u16 * u16` computed in 32 bits cannot wrap; `u32 * u32` in 32 bits can; a 32-bit product
      zero-extended to 64 bits AFTER the multiply is a wrap; a u32 zero-extended to 64 bits BEFORE
      the multiply (`(size_t)n * 16`) is not;
  (b) has at least one ATTACKER-TAINTED operand, and every other non-constant operand is tainted
      too (an untainted unknown -- a struct field, a global -- is not something the attacker can
      drive, so it never makes a wrap reportable on its own);
  (c) has NO GUARD: no dominating compare+branch that bounds an operand (constant bounds are
      applied exactly, as a value range), no check of the result against an operand (`a+b < a`),
      no division-based `x > MAX / y` check, and no use of the operation's overflow indication
      (INT_CARRY / INT_SCARRY, or the high half of the double-width product that `mul`/`imul`/
      `umulh` and __builtin_mul_overflow compile to).

ONE RECORD PER ALLOCATION SITE -- never a roll-up -- so a record can be confirmed, matched to a CVE,
or dismissed on its own. Precision is the design constraint: whenever a guard is present that the
analysis cannot read exactly, the site is suppressed, not reported.

How it works (a pure function over the stored per-function IR, no stage wiring):

  * A per-function SYMBOLIC EVALUATION of the low P-Code into hash-consed value nodes (one node per
    distinct value, so the value a guard compares and the value the allocation consumes are the
    same node when they are the same value). Registers are modelled with their sub-register
    aliasing (EAX is the low half of RAX, w0 of x0), the stack as constant-offset slots relative
    to the entry stack pointer (so RBP- and RSP-relative accesses of one slot agree), other memory
    as a per-epoch load cache. Joins create phi nodes; intra-instruction conditional skips
    (cmov/csel) create select nodes.
  * TAINT is positive evidence only: bytes filled by an input source (read/recv/fread/fgets/scanf
    out-parameters, including the FORTIFY `__read_chk` forms), getc-family return values,
    atoi/strtol of a tainted string, argv/envp at main, and -- inter-procedurally -- parameters a
    caller passes tainted data or tainted-buffer pointers to, plus callee return values and values
    a callee stores through a pointer parameter (summaries, context-insensitive).
  * A VALUE-RANGE (interval) evaluation over the nodes, refined by the atomic predicates that hold
    on every path to the site (dominating branches, the edge into a phi, a select's condition).
  * The top-down walk of the allocation size finds the arithmetic node whose mathematical range
    exceeds the width it is consumed at, and checks the guard kinds above.

FIELD FACTS -- a value decoded in one function, stored into a struct or a global, and read in
another (`hdr->count = rd32(p)` in the parser, `malloc(hdr->count * 24)` in the consumer):

  * Identity. Every write the evaluation sees (STORE, an input fill, a memcpy) is filed under the
    abstract LOCATION it writes: an access path (root, offsets) whose root is a global's absolute
    address, an allocation SITE (the call that returned the object -- an allocator, a recognised
    size-preserving wrapper, or an internal function whose every non-NULL return is one such
    object), a function's stack frame, or "what parameter i of f points at"; every offset but
    the last is a pointer loaded from that offset (`*(*(p+8)+4)`), so pointer chains through
    structs and globals are followed. A parameter-rooted location is LIFTED through each call
    site to where that caller's argument points (up to 5 levels, 64 locations), keeping the call
    chain, so a setter's store and the consumer's load meet at the concrete object. Limits:
    allocation sites are context-insensitive (every object from one site is one object); array
    elements (`a[i].f`, a non-constant index) have no identity and are not judged; a pointer
    merged from two objects at a join has none either; writes a library routine makes
    internally, and SIMD-packed stores whose value the lifter cannot model, are invisible.
  * Range. A load reads the RANGE of the value stored there -- computed where it is stored, under
    that store's dominating checks, narrowed to the argument's range at the call chain when the
    stored value is the setter's parameter, clipped to the store width -- not the full width of
    the field: giflib's `int SWidth` holds a u16 from DGifGetWord, so `SWidth * 3` cannot wrap.
    A struct copy carries the source field's facts. Taint and constants are evaluated AT the call
    chain (a setter called with input on one object and with a constant on another taints one).
  * The write rule (per object): a load counts as attacker data only when EVERY write that may
    define its bytes is attacker data or a compile-time constant (an init `= 0`, `= 4096`: its
    range is known, so it cannot hide a larger trusted value). One untainted write of unknown
    value, a load spanning several writes, or a self-referential re-store (`h->n -= k`, a clamp
    written back) and the field is not judged at all -- this is what keeps a naive full-width
    field taint from reporting giflib's u16 fields.
  * Guards elsewhere. Checks on the field are applied where they could run first: branches that
    dominate the load (in its function and, three caller levels up, before the call), anything
    in a function called at those dominating points (a validator), and any check on the stored
    value in the function that stores it (`h->n = v; if (h->n > MAX) return -1;`). A check in
    another function is assumed to hold on the outcome that carries on past an early exit (both
    outcomes when that is unclear): a constant upper bound caps the range; a bound that cannot
    be applied exactly (a run-time value, an expression over the field) clears the field. Zero /
    sign checks and loop counters compared with the field bound nothing.
"""
from __future__ import annotations

import logging
from collections import defaultdict

from .catalog import normalize
from .taint import ARCH_ABI, _arch_key

_log = logging.getLogger(__name__)

# ----------------------------------------------------------------------------------- tables
#: allocator (normalized name) -> argument indices that carry the allocation SIZE. calloc /
#: reallocarray multiply their two arguments internally WITH an overflow check, so only a wrap
#: computed in the caller's own arithmetic, inside one argument, is a finding there.
ALLOC_SIZE_ARGS = {
    "malloc": (0,), "valloc": (0,), "pvalloc": (0,), "calloc": (0, 1), "realloc": (1,),
    "reallocarray": (1, 2), "aligned_alloc": (1,), "memalign": (1,),
    "libc_malloc": (0,), "libc_calloc": (0, 1), "libc_realloc": (1,), "libc_memalign": (1,),
    "xmalloc": (0,), "xzalloc": (0,), "xcalloc": (0, 1), "xrealloc": (1,), "xmemdup": (1,),
    "g_malloc": (0,), "g_malloc0": (0,), "g_realloc": (1,), "g_try_malloc": (0,),
    "g_try_malloc0": (0,), "g_try_realloc": (1,),
    "emalloc": (0,), "safe_malloc": (0,), "OPENSSL_malloc": (0,), "CRYPTO_malloc": (0,),
    "CRYPTO_zalloc": (0,), "CRYPTO_realloc": (1,), "av_malloc": (0,), "av_mallocz": (0,),
    "av_realloc": (1,), "png_malloc": (1,), "kmalloc": (0,), "kzalloc": (0,), "vmalloc": (0,),
    # operator new / new[] (normalize() strips the leading underscore of _Znwm)
    "Znwm": (0,), "Znam": (0,), "Znwj": (0,), "Znaj": (0,),
    "ZnwmRKSt9nothrow_t": (0,), "ZnamRKSt9nothrow_t": (0,),
}

#: input source -> (buffer arg index, length spec). Length spec: an arg index, a tuple of arg
#: indices whose product is the length, or None (unknown, e.g. NUL-terminated input).
_OUT_SOURCES = {
    "read": (1, 2), "pread": (1, 2), "pread64": (1, 2), "recv": (1, 2), "recvfrom": (1, 2),
    "read_chk": (1, 2), "recv_chk": (1, 2), "recvfrom_chk": (1, 2), "pread_chk": (1, 2),
    "fread": (0, (1, 2)), "fread_unlocked": (0, (1, 2)), "fread_chk": (0, (2, 3)),
    "fread_unlocked_chk": (0, (2, 3)),
    "fgets": (0, 1), "fgets_unlocked": (0, 1), "fgets_chk": (0, 2), "gets": (0, None),
    "gets_chk": (0, 1),
}
#: the scanf family: every pointer argument after the format is an out-parameter
_SCANF = {"scanf": 1, "fscanf": 2, "sscanf": 2, "vscanf": None, "vfscanf": None,
          "vsscanf": None}
#: sscanf only taints its outputs when its INPUT string is tainted
_SCANF_FROM_STRING = {"sscanf"}
#: functions whose RETURN VALUE is attacker data: name -> value range
_VALUE_SOURCES = {
    "getc": (0, 255), "fgetc": (0, 255), "getchar": (0, 255), "getc_unlocked": (0, 255),
    "fgetc_unlocked": (0, 255), "getchar_unlocked": (0, 255), "IO_getc": (0, 255),
    "getw": None,
}
#: string -> number conversions: the return is tainted iff the string argument (arg 0) is
_STR_TO_NUM = {"atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull",
               "strtoimax", "strtoumax", "strtol_internal", "strtoul_internal",
               "strtoll_internal", "strtoull_internal", "wcstol", "wcstoul"}
#: byte-order helpers: tainted in -> tainted out, value range of the output
_PASS_THROUGH = {"ntohl": 0xFFFFFFFF, "htonl": 0xFFFFFFFF, "ntohs": 0xFFFF, "htons": 0xFFFF,
                 "bswap_32": 0xFFFFFFFF, "bswap_16": 0xFFFF, "be32toh": 0xFFFFFFFF,
                 "le32toh": 0xFFFFFFFF, "be16toh": 0xFFFF, "le16toh": 0xFFFF}
#: lengths of in-memory objects: bounded by the address space, so `strlen(s) + 1` cannot wrap
_LENGTHS = {"strlen", "strnlen", "wcslen", "wcsnlen"}
#: copies that move attacker bytes from src (arg 1) into dst (arg 0): (dst, src, length spec)
_COPIES = {"memcpy": (0, 1, 2), "memmove": (0, 1, 2), "strcpy": (0, 1, None),
           "strncpy": (0, 1, 2), "strcat": (0, 1, None), "strncat": (0, 1, 2),
           "memcpy_chk": (0, 1, 2), "memmove_chk": (0, 1, 2), "strcpy_chk": (0, 1, None),
           "strncpy_chk": (0, 1, 2), "mempcpy": (0, 1, 2), "stpcpy": (0, 1, None),
           "bcopy": (1, 0, 2)}
#: sinks that WRITE through their destination (for the "written with the un-wrapped length"
#: corroboration): name -> (dst arg, length arg or None)
_WRITERS = {**{k: (v[0], v[2]) for k, v in _COPIES.items()},
            **{k: (v[0], v[1] if isinstance(v[1], int) else None)
               for k, v in _OUT_SOURCES.items()},
            "memset": (0, 2), "memset_chk": (0, 2)}

_ARITH = {"INT_MULT", "INT_ADD", "INT_LEFT"}
_CMP = {"INT_LESS", "INT_LESSEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_EQUAL", "INT_NOTEQUAL"}
_BOOL_OUT = _CMP | {"BOOL_NEGATE", "BOOL_AND", "BOOL_OR", "BOOL_XOR", "INT_CARRY", "INT_SCARRY",
                    "INT_SBORROW", "FLOAT_LESS", "FLOAT_EQUAL", "FLOAT_NAN"}
_RING = {"INT_ADD", "INT_SUB", "INT_MULT", "INT_AND", "INT_OR", "INT_XOR"}

#: per-function ceilings: a function past them is skipped whole and counted, never half-read
_MAX_BLOCKS = 2500
_MAX_OPS = 250_000
_MAX_PASSES = 4
_MAX_DEPTH = 48               # expression depth; deeper values become opaque
_MAX_DOMS = 96                # dominating blocks examined per context
_ROUNDS = 4                   # inter-procedural rounds
# field facts (a value stored to memory in one function, loaded in another)
_FIELD_DEPTH = 4              # offsets in an access path (pointers loaded on the way + the field)
_LIFT_DEPTH = 5               # caller levels a parameter-rooted location is lifted through
_LIFT_BUDGET = 64             # locations one write / load may denote
_FIELD_WRITES = 48            # writes examined per object field; more -> the field is not judged
_COPY_DEPTH = 2               # struct-copy (memcpy) hops followed to the source field

_X86_FAMILIES = [
    ("RAX", "EAX", "AX", "AL", "AH"), ("RBX", "EBX", "BX", "BL", "BH"),
    ("RCX", "ECX", "CX", "CL", "CH"), ("RDX", "EDX", "DX", "DL", "DH"),
    ("RSI", "ESI", "SI", "SIL"), ("RDI", "EDI", "DI", "DIL"),
    ("RBP", "EBP", "BP", "BPL"), ("RSP", "ESP", "SP", "SPL"), ("RIP", "EIP", "IP"),
    *[(f"R{n}", f"R{n}D", f"R{n}W", f"R{n}B") for n in range(8, 16)],
]


def _x86_regmap(full: int) -> dict:
    """x86 register name -> (family, byte offset, size)."""
    m = {}
    for grp in _X86_FAMILIES:
        fam = grp[0] if full == 8 else grp[1]
        sizes = (8, 4, 2, 1, 1) if len(grp) == 5 else (8, 4, 2, 1)
        for i, name in enumerate(grp):
            if full == 4 and sizes[i] == 8:
                continue
            off = 1 if (len(grp) == 5 and i == 4) else 0
            m[name] = (fam, off, sizes[i])
    return m


_REGMAPS = {"x86-64": _x86_regmap(8), "x86": _x86_regmap(4)}
_SP_FAMILY = {"x86-64": "RSP", "x86": "ESP", "aarch64": "SP", "arm": "SP", "mips": "SP",
              "ppc": "R1", "ppc64": "R1", "riscv": "SP", "loongarch": "SP", "m68k": "SP",
              "sparc": "SP", "sparcv9": "SP", "sh": "R15"}


def _mask(size: int) -> int:
    return (1 << (8 * size)) - 1


_CYCLE = ("cycle",)            # _ptr_path: a node on the current resolution stack (a loop)


def _shift(p, off):
    """Access path `p` moved by `off` bytes within its final object."""
    return (p[0], p[1][:-1] + (p[1][-1] + off,))


def _compose(q, p):
    """A parameter-rooted path `p` seen from a caller whose argument points at `q`."""
    offs = q[1][:-1] + (q[1][-1] + p[1][0],) + p[1][1:]
    return (q[0], offs) if len(offs) <= _FIELD_DEPTH else None


def _upper(rel, K):
    """The upper bound `x rel K` puts on x, or None."""
    return K - 1 if rel == "lt" else K if rel in ("le", "eq") else None


# ------------------------------------------------------------------------------- node store
class _Nodes:
    """Hash-consed value nodes. A node is an int id; its key is a tuple (kind, size, *payload)
    whose payload references other nodes by id. Equal values -> equal ids, which is what lets a
    guard on a value and the allocation that consumes it meet."""

    def __init__(self):
        self.key: list = []
        self.depth: list = []
        self.idx: dict = {}
        self.where: dict = {}            # node -> the instruction address that first built it
        self.phi_in: dict = defaultdict(dict)   # phi node -> {pred block: input node}
        self._top = 0

    def mk(self, key, depth=0, where=None):
        n = self.idx.get(key)
        if n is None:
            n = len(self.key)
            self.key.append(key)
            self.depth.append(depth)
            self.idx[key] = n
            if where is not None:
                self.where[n] = where
        return n

    def top(self, size, tag=None):
        """An unknown value. Tagged by where it arises, so re-evaluating a block reproduces the
        same node and the block fixpoint converges."""
        if tag is None:
            self._top += 1
            tag = self._top
        return self.mk(("top", size, tag))

    def kind(self, n):
        return self.key[n][0]

    def size(self, n):
        return self.key[n][1]

    def const(self, v, size):
        return self.mk(("c", size, v & _mask(size)))

    def cval(self, n):
        k = self.key[n]
        return k[2] if k[0] == "c" else None


def _signed(v: int, size: int) -> int:
    half = 1 << (8 * size - 1)
    return v - (1 << (8 * size)) if v >= half else v


class _Builder:
    """Constructs (and simplifies) operation nodes. The simplifications are what make two
    spellings of one value the same node: `cmp eax,K; ja` and `cmp K,eax; jb` become the same
    INT_LESS, the x86/aarch64 flag recipes collapse to comparisons, narrowing distributes over
    ring operations so a 64-bit product truncated to 32 bits IS a 32-bit product."""

    def __init__(self, nodes: _Nodes):
        self.N = nodes

    # helpers ---------------------------------------------------------------------------
    def _k(self, n):
        return self.N.key[n]

    def is_bool(self, n):
        k = self._k(n)
        if k[0] == "c":
            return k[1] == 1 and k[2] in (0, 1)
        return k[0] == "op" and k[2] in _BOOL_OUT

    def as_sub(self, n):
        """(x, y) if n is x - y (an INT_SUB, or an INT_ADD of a negated constant), else None."""
        k = self._k(n)
        if k[0] != "op":
            return None
        if k[2] == "INT_SUB":
            return k[3], k[4]
        if k[2] == "INT_ADD":
            c = self.N.cval(k[4])
            if c is not None:
                return k[3], self.N.const(-c, k[1])
        return None

    def op(self, mnem, size, a, b=None, where=None):
        N = self.N
        ka = N.key[a]
        kb = N.key[b] if b is not None else None
        ca = ka[2] if ka[0] == "c" else None
        cb = kb[2] if kb is not None and kb[0] == "c" else None
        m = _mask(size)

        # ---- constant folding
        if ca is not None and (b is None or cb is not None):
            v = _fold(mnem, ca, cb, N.size(a), N.size(b) if b is not None else 0, size)
            if v is not None:
                return N.const(v, size)

        # ---- stack-address arithmetic: ('sp', off, func) +/- const
        if mnem in ("INT_ADD", "INT_SUB") and ka[0] == "sp" and cb is not None:
            d = cb if mnem == "INT_ADD" else -cb
            return N.mk(("sp", size, _signed((ka[2] + d) & m, size), ka[3]))
        if mnem == "INT_ADD" and kb is not None and kb[0] == "sp" and ca is not None:
            return N.mk(("sp", size, _signed((kb[2] + ca) & m, size), kb[3]))
        if mnem == "INT_SUB" and ka[0] == "sp" and kb is not None and kb[0] == "sp":
            return N.const(ka[2] - kb[2], size)

        # ---- canonical operand order: constant second for commutative ops
        if mnem in ("INT_ADD", "INT_MULT", "INT_AND", "INT_OR", "INT_XOR", "BOOL_AND",
                    "BOOL_OR", "BOOL_XOR") and ca is not None and cb is None:
            a, b, ka, kb, ca, cb = b, a, kb, ka, cb, ca
        if mnem in ("INT_EQUAL", "INT_NOTEQUAL") and ca is not None and cb is None:
            a, b, ka, kb, ca, cb = b, a, kb, ka, cb, ca

        if mnem == "INT_SUB" and cb is not None:
            return self.op("INT_ADD", size, a, N.const(-cb, size), where)
        if mnem == "INT_ADD":
            if cb == 0:
                return a
            if ka[0] == "op" and ka[2] == "INT_ADD" and cb is not None:
                c2 = N.cval(ka[4])
                if c2 is not None:
                    return self.op("INT_ADD", size, ka[3], N.const(c2 + cb, size), where)
        if mnem == "INT_MULT":
            if cb == 1:
                return a
            if cb == 0:
                return N.const(0, size)
        if mnem in ("INT_LEFT", "INT_RIGHT", "INT_SRIGHT") and cb == 0:
            return a
        if mnem in ("INT_AND", "INT_OR") and a == b:
            return a
        if mnem == "INT_XOR" and a == b:
            return N.const(0, size)
        if mnem == "INT_AND":
            if cb == 0:
                return N.const(0, size)
            if cb is not None and cb == m:
                return a
            if size == 1 and cb == 1 and self.is_bool(a):
                return a
        if mnem == "INT_OR" and cb == 0:
            return a

        # ---- boolean algebra over comparisons
        if mnem in ("BOOL_AND", "INT_AND") and size == 1 and self.is_bool(a) and \
                (cb is not None or self.is_bool(b)):
            if cb is not None:
                return a if cb & 1 else N.const(0, 1)
            fused = self._fuse(a, b, conj=True)
            if fused is not None:
                return fused
            mnem = "BOOL_AND"
        if mnem in ("BOOL_OR", "INT_OR") and size == 1 and self.is_bool(a) and \
                (cb is not None or self.is_bool(b)):
            if cb is not None:
                return N.const(1, 1) if cb & 1 else a
            fused = self._fuse(a, b, conj=False)
            if fused is not None:
                return fused
            mnem = "BOOL_OR"
        if mnem in ("BOOL_XOR", "INT_XOR") and size == 1 and self.is_bool(a) and cb is not None:
            return self.negate(a) if cb & 1 else a
        if mnem == "BOOL_NEGATE":
            return self.negate(a)
        if mnem in ("INT_EQUAL", "INT_NOTEQUAL"):
            r = self._equality(mnem == "INT_EQUAL", a, b, ka, kb, cb)
            if r is not None:
                return r
        if mnem in ("INT_LESS", "INT_LESSEQUAL", "INT_SLESS", "INT_SLESSEQUAL") and a == b:
            return N.const(1 if mnem.endswith("EQUAL") else 0, 1)

        # ---- extensions / truncation
        if mnem in ("INT_ZEXT", "INT_SEXT"):
            if N.size(a) == size:
                return a
            if ka[0] == "op" and ka[2] == mnem:
                return self.op(mnem, size, ka[3], where=where)
            if mnem == "INT_SEXT" and ka[0] == "op" and ka[2] == "INT_ZEXT":
                return self.op("INT_ZEXT", size, ka[3], where=where)
        if mnem == "SUBPIECE":
            return self.subpiece(a, cb or 0, size, where)

        depth = 1 + max(N.depth[a], N.depth[b] if b is not None else 0)
        if depth > _MAX_DEPTH:
            return N.top(size)
        key = ("op", size, mnem, a) if b is None else ("op", size, mnem, a, b)
        return N.mk(key, depth, where)

    def subpiece(self, x, off, size, where=None):
        N = self.N
        kx = N.key[x]
        sx = kx[1]
        if off == 0 and size == sx:
            return x
        if kx[0] == "c":
            return N.const(kx[2] >> (8 * off), size)
        if kx[0] == "op":
            m = kx[2]
            if m in ("INT_ZEXT", "INT_SEXT") and off == 0:
                inner = kx[3]
                si = N.size(inner)
                if si == size:
                    return inner
                if si < size:
                    return self.op(m, size, inner, where=where)
                return self.subpiece(inner, 0, size, where)
            if m == "INT_ZEXT" and off >= N.size(kx[3]):
                return N.const(0, size)
            if m == "SUBPIECE":
                return self.subpiece(kx[3], N.cval(kx[4]) + off, size, where)
            if m == "PARTIAL":
                lo = kx[4]
                if off == 0 and size <= N.size(lo):
                    return self.subpiece(lo, 0, size, where)
            if off == 0 and m in _RING:
                # low bits of a ring operation depend only on the low bits of its operands: the
                # truncation of a 64-bit product to 32 bits IS the 32-bit product, which is where
                # a 32-bit wrap lives.
                return self.op(m, size, self.subpiece(kx[3], 0, size),
                               self.subpiece(kx[4], 0, size), where)
            if off == 0 and m == "INT_LEFT" and N.cval(kx[4]) is not None:
                return self.op("INT_LEFT", size, self.subpiece(kx[3], 0, size), kx[4], where)
        if kx[0] == "sp" and off == 0:
            return N.mk(("sp", size, kx[2], kx[3]))
        depth = 1 + N.depth[x]
        return N.mk(("op", size, "SUBPIECE", x, N.const(off, 4)), depth, where)

    def negate(self, a):
        N = self.N
        k = N.key[a]
        if k[0] == "c":
            return N.const(0 if k[2] else 1, 1)
        if k[0] == "op":
            m = k[2]
            flip = {"INT_LESS": ("INT_LESSEQUAL", True), "INT_LESSEQUAL": ("INT_LESS", True),
                    "INT_SLESS": ("INT_SLESSEQUAL", True), "INT_SLESSEQUAL": ("INT_SLESS", True),
                    "INT_EQUAL": ("INT_NOTEQUAL", False), "INT_NOTEQUAL": ("INT_EQUAL", False)}
            if m in flip:
                nm, swap = flip[m]
                x, y = (k[4], k[3]) if swap else (k[3], k[4])
                return N.mk(("op", 1, nm, x, y), N.depth[a])
            if m == "BOOL_NEGATE":
                return k[3]
        return N.mk(("op", 1, "BOOL_NEGATE", a), N.depth[a] + 1)

    def _cmp_parts(self, n):
        k = self.N.key[n]
        if k[0] == "op" and k[2] in _CMP:
            return k[2], k[3], k[4]
        return None

    def _fuse(self, a, b, conj):
        """`a <= b && a != b` -> `a < b`;  `a < b || a == b` -> `a <= b` (signed or not)."""
        pa, pb = self._cmp_parts(a), self._cmp_parts(b)
        if not pa or not pb:
            return None
        for (m1, x1, y1), (m2, x2, y2) in ((pa, pb), (pb, pa)):
            pair = {x2, y2}
            if {x1, y1} != pair:
                continue
            if conj and m2 == "INT_NOTEQUAL" and m1 in ("INT_LESSEQUAL", "INT_SLESSEQUAL"):
                return self.N.mk(("op", 1, "INT_LESS" if m1 == "INT_LESSEQUAL" else "INT_SLESS",
                                  x1, y1), max(self.N.depth[a], self.N.depth[b]))
            if not conj and m2 == "INT_EQUAL" and m1 in ("INT_LESS", "INT_SLESS"):
                return self.N.mk(("op", 1, "INT_LESSEQUAL" if m1 == "INT_LESS"
                                  else "INT_SLESSEQUAL", x1, y1),
                                 max(self.N.depth[a], self.N.depth[b]))
        return None

    def _equality(self, eq, a, b, ka, kb, cb):
        """Collapse the flag recipes: ZF = (x - y == 0) -> x == y; SF == OF -> signed >=;
        a boolean compared with 0/1 -> the boolean (or its negation)."""
        N = self.N
        if a == b:
            return N.const(1 if eq else 0, 1)
        if cb is not None and self.is_bool(a):
            keep = (cb == 1) == eq
            if cb in (0, 1):
                return a if keep else self.negate(a)
        if cb == 0:
            s = self.as_sub(a)
            if s is not None:
                return self.op("INT_EQUAL" if eq else "INT_NOTEQUAL", 1, s[0], s[1])
            if ka[0] == "op" and ka[2] == "INT_AND" and ka[3] == ka[4]:
                return self.op("INT_EQUAL" if eq else "INT_NOTEQUAL", 1, ka[3], b)
        # SF == OF  <=>  x >=s y,   with SF = (x - y) <s 0  and  OF = SBORROW(x, y)
        for p, q in ((ka, kb), (kb, ka)):
            if p is None or q is None or p[0] != "op" or q[0] != "op":
                continue
            if p[2] == "INT_SLESS" and q[2] == "INT_SBORROW" and N.cval(p[4]) == 0:
                s = self.as_sub(p[3])
                if s is not None and self._same_operands(s, (q[3], q[4])):
                    x, y = q[3], q[4]
                    return N.mk(("op", 1, "INT_SLESSEQUAL" if eq else "INT_SLESS",
                                 *((y, x) if eq else (x, y))), 1)
        if eq and a > b and kb is not None and kb[0] != "c":
            return N.mk(("op", 1, "INT_EQUAL", b, a), 1 + max(N.depth[a], N.depth[b]))
        if not eq and a > b and kb is not None and kb[0] != "c":
            return N.mk(("op", 1, "INT_NOTEQUAL", b, a), 1 + max(N.depth[a], N.depth[b]))
        return None

    def _same_operands(self, s, q):
        x, y = s
        qx, qy = q
        if x != qx:
            return False
        if y == qy:
            return True
        cy, cqy = self.N.cval(y), self.N.cval(qy)
        return cy is not None and cqy is not None and \
            (cy & _mask(self.N.size(y))) == (cqy & _mask(self.N.size(qy)))


def _fold(mnem, a, b, sa, sb, size):
    m = _mask(size)
    try:
        if mnem in ("COPY",):
            return a
        if mnem == "INT_ZEXT":
            return a
        if mnem == "INT_SEXT":
            return _signed(a, sa) & m
        if mnem == "INT_ADD":
            return (a + b) & m
        if mnem == "INT_SUB":
            return (a - b) & m
        if mnem == "INT_MULT":
            return (a * b) & m
        if mnem == "INT_AND":
            return a & b
        if mnem == "INT_OR":
            return a | b
        if mnem == "INT_XOR":
            return a ^ b
        if mnem == "INT_LEFT":
            return (a << b) & m if b < 128 else 0
        if mnem == "INT_RIGHT":
            return a >> b if b < 128 else 0
        if mnem == "INT_SRIGHT":
            return (_signed(a, sa) >> min(b, 127)) & m
        if mnem == "INT_DIV":
            return a // b if b else None
        if mnem == "INT_REM":
            return a % b if b else None
        if mnem == "INT_NEGATE":
            return ~a & m
        if mnem == "INT_2COMP":
            return (-a) & m
        if mnem == "INT_EQUAL":
            return int(a == b)
        if mnem == "INT_NOTEQUAL":
            return int(a != b)
        if mnem == "INT_LESS":
            return int(a < b)
        if mnem == "INT_LESSEQUAL":
            return int(a <= b)
        if mnem == "INT_SLESS":
            return int(_signed(a, sa) < _signed(b, sb))
        if mnem == "INT_SLESSEQUAL":
            return int(_signed(a, sa) <= _signed(b, sb))
        if mnem == "BOOL_NEGATE":
            return 0 if a else 1
        if mnem in ("BOOL_AND",):
            return int(bool(a) and bool(b))
        if mnem in ("BOOL_OR",):
            return int(bool(a) or bool(b))
        if mnem in ("BOOL_XOR",):
            return int(bool(a) != bool(b))
        if mnem == "INT_CARRY":
            return int(a + b > _mask(sa))
        if mnem == "POPCOUNT":
            return bin(a).count("1")
    except Exception:                                        # noqa: BLE001 -- unfoldable
        return None
    return None


# ----------------------------------------------------------------------------- P-Code parse
_PARSE_CACHE: dict = {}


def _tok(t):
    parts = t.split(":")
    if len(parts) < 3:
        return None
    sp = parts[0]
    try:
        size = int(parts[-1], 0)
    except ValueError:
        return None
    if sp == "reg":
        return ("reg", ":".join(parts[1:-1]).upper(), size)
    try:
        off = int(parts[1], 16) if parts[1].startswith("0x") else int(parts[1], 0)
    except ValueError:
        return None
    return (sp, off, size)


def _parse(pc):
    r = _PARSE_CACHE.get(pc)
    if r is not None:
        return r
    if " -> " in pc:
        left, out = pc.split(" -> ", 1)
        outt = _tok(out.strip())
    else:
        left, outt = pc, None
    toks = left.split()
    if not toks:
        r = (None, (), None)
    else:
        r = (toks[0], tuple(_tok(t) for t in toks[1:]), outt)
    if len(_PARSE_CACHE) < 400_000:
        _PARSE_CACHE[pc] = r
    return r


# ------------------------------------------------------------------------------------ CFG
def _idoms(order, preds):
    """Cooper-Harvey-Kennedy immediate dominators over blocks in the given (RPO) order."""
    pos = {a: i for i, a in enumerate(order)}
    idom = {order[0]: order[0]} if order else {}
    changed = True
    while changed:
        changed = False
        for a in order[1:]:
            ps = [p for p in preds.get(a, ()) if p in idom]
            if not ps:
                continue
            new = ps[0]
            for p in ps[1:]:
                x, y = p, new
                while x != y:
                    while pos[x] > pos[y]:
                        x = idom[x]
                    while pos[y] > pos[x]:
                        y = idom[y]
                new = x
            if idom.get(a) != new:
                idom[a] = new
                changed = True
    return idom


def _rpo(entry, succ):
    seen, out = set(), []
    stack = [(entry, iter(succ.get(entry, ())))]
    seen.add(entry)
    while stack:
        node, it = stack[-1]
        nxt = next(it, None)
        if nxt is None:
            stack.pop()
            out.append(node)
            continue
        if nxt not in seen and nxt in succ:
            seen.add(nxt)
            stack.append((nxt, iter(succ.get(nxt, ()))))
    out.reverse()
    return out


class _Func:
    """Per-function analysis facts (shared by the range/guard queries)."""

    def __init__(self, addr, ir):
        self.addr = addr
        blocks = [b for b in (ir or {}).get("blocks", []) or [] if b.get("addr") is not None]
        self.by = {b["addr"]: b for b in blocks}
        self.succ = {a: [s for s in (b.get("succ") or []) if s in self.by]
                     for a, b in self.by.items()}
        self.preds = defaultdict(list)
        for a, ss in self.succ.items():
            for s in ss:
                self.preds[s].append(a)
        self.entry = blocks[0]["addr"] if blocks else None
        self.order = _rpo(self.entry, self.succ) if blocks else []
        self.idom = _idoms(self.order, self.preds) if self.order else {}
        self.cond: dict = {}            # block -> (cond node, taken target block)
        self.calls: dict = {}           # call site -> call record
        self.rets: dict = {}            # (block, site) -> return node
        self.outs: dict = {}            # (param idx, off, size) -> {value nodes}
        self.regions: dict = {}         # (lo, hi) stack ranges filled with input -> origin spec
        self.stores: dict = {}          # (block, addr node, size, value node) -> None (ordered set)
        self.fills: dict = {}           # (block, ptr node, length, spec) -> None
        self._vconds = None             # comparisons computed as values (field guards)
        self._outc: dict = {}           # block -> branch outcomes that carry on (field guards)
        self.skipped = None
        self._reach: dict = {}
        self._atoms: dict = {}

    def dom_chain(self, b):
        out = []
        x = self.idom.get(b)
        while x is not None and len(out) < _MAX_DOMS:
            out.append(x)
            if self.idom.get(x) == x:
                break
            x = self.idom.get(x)
        return out

    def reach_avoid(self, start, goal, avoid):
        """(goal reachable from start without entering `avoid`, the blocks visited)."""
        key = (start, goal, avoid)
        r = self._reach.get(key)
        if r is not None:
            return r
        seen, todo, found = set(), [start], False
        while todo:
            x = todo.pop()
            if x in seen or x == avoid:
                continue
            seen.add(x)
            if x == goal:
                found = True
            todo.extend(self.succ.get(x, ()))
            if len(seen) > 4000:
                found = True                # budget: assume reachable (claims no guard)
                break
        r = (found, seen)
        self._reach[key] = r
        return r


# ------------------------------------------------------------------------------ analysis
#: external calls that take a pointer but never write through it (their argument slots survive)
_READ_ONLY = {"strlen", "strnlen", "strcmp", "strncmp", "strcasecmp", "strncasecmp", "memcmp",
              "strchr", "strrchr", "strstr", "memchr", "puts", "fputs", "printf", "fprintf",
              "dprintf", "printf_chk", "fprintf_chk", "write", "fwrite", "send", "sendto",
              "free", "atoi", "atol", "atoll", "perror", "fopen", "open", "open64", "stat",
              "access", "unlink", "strdup", "strndup", "close", "fclose", "fflush", "fseek",
              "ftell", "rewind", "exit", "abort", "assert_fail"}

_SCRATCH = {
    "x86-64": {"RAX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11"},
    "x86": {"EAX", "ECX", "EDX"},
    "aarch64": {"X%d" % i for i in range(19)} | {"X30"},
    "arm": {"R0", "R1", "R2", "R3", "R12", "LR"},
    "riscv": {"A%d" % i for i in range(8)} | {"T%d" % i for i in range(7)} | {"RA"},
    "mips": {"V0", "V1", "A0", "A1", "A2", "A3", "T0", "T1", "T2", "T3", "T4", "T5", "T6",
             "T7", "T8", "T9", "AT", "RA"},
}
_X86_FLAGS = {"CF", "ZF", "SF", "OF", "PF", "AF"}
#: modelled routines that return a C type narrower than a register: name -> (bytes, signed)
_RET_TYPES = {"atoi": (4, True), "getc": (4, True), "fgetc": (4, True), "getchar": (4, True),
              "getc_unlocked": (4, True), "fgetc_unlocked": (4, True), "IO_getc": (4, True),
              "getchar_unlocked": (4, True), "getw": (4, True), "ntohl": (4, False),
              "htonl": (4, False), "ntohs": (2, False), "htons": (2, False)}
#: library routines this module models by name; a lifted stub of one is never summarised
_KNOWN_LIB = (set(ALLOC_SIZE_ARGS) | set(_OUT_SOURCES) | set(_SCANF) | set(_VALUE_SOURCES) |
              _STR_TO_NUM | set(_PASS_THROUGH) | _LENGTHS | set(_COPIES) | set(_WRITERS) |
              _READ_ONLY | {"free", "memset", "memset_chk", "fileno", "fopen", "exit"})
_FLIP = {"lt": "gt", "gt": "lt", "le": "ge", "ge": "le", "eq": "eq", "ne": "ne"}
_RELS = {"INT_LESS": ("lt", "ge", False), "INT_LESSEQUAL": ("le", "gt", False),
         "INT_SLESS": ("lt", "ge", True), "INT_SLESSEQUAL": ("le", "gt", True),
         "INT_EQUAL": ("eq", "ne", None), "INT_NOTEQUAL": ("ne", "eq", None)}


def _hexint(a):
    try:
        s = str(a)
        return int(s, 16) if s.lower().startswith("0x") else int(s, 0)
    except (TypeError, ValueError):
        return None


def _copy_state(st):
    return [dict(st[0]), dict(st[1]), dict(st[2]), st[3]]


def _same_state(a, b):
    return a[0] == b[0] and a[1] == b[1] and a[2] == b[2] and a[3] == b[3]


class _Program:
    def __init__(self, func_irs, call_edges, arch, bits, names, entry_seeds):
        self.N = _Nodes()
        self.B = _Builder(self.N)
        self.ak = _arch_key(arch) or ""
        self.abi = ARCH_ABI.get(self.ak) or {}
        self.word = 4 if self.ak == "x86" else max(4, int(bits or 64) // 8)
        self.regmap = _REGMAPS.get(self.ak, {})
        self.fullsize = self.word
        self.sp_fam = _SP_FAMILY.get(self.ak, "SP")
        self.argfams = [self._fam_of_group(g) for g in
                        (self.abi.get("param_regs") or self.abi.get("args") or [])]
        self.callargfams = [self._fam_of_group(g) for g in self.abi.get("args") or []]
        self.retfam = self._fam_of_group(self.abi.get("ret") or {"RAX"})
        self.stack_args = bool(self.abi.get("stack_call"))
        self.func_irs = func_irs or {}
        self.names = dict(names or {})
        self.callmap: dict = {}
        self.addr_name: dict = {}
        self.cg: dict = defaultdict(set)
        for e in call_edges or ():
            dn = getattr(e, "dst_name", None)
            if e.site_addr:
                self.callmap[e.site_addr] = (normalize(dn) if dn else None, e.dst_addr,
                                             bool(getattr(e, "external", False)))
            if e.dst_addr and dn:
                self.addr_name.setdefault(_hexint(e.dst_addr), normalize(dn))
            if e.src_addr in self.func_irs and e.dst_addr in self.func_irs:
                self.cg[e.src_addr].add(e.dst_addr)
        for a, nm in self.names.items():
            if nm:
                self.addr_name.setdefault(_hexint(a), normalize(nm))
        self.func_by_int = {_hexint(a): a for a in self.func_irs}
        # inter-procedural facts
        self.p_taint: dict = {}         # (func, param idx) -> origin
        self.p_range: dict = {}         # (func, param idx) -> (lo, hi) over TAINTED call sites
        self.p_ptr: dict = {}           # (func, param idx) -> origin (points at tainted bytes)
        self.wrappers: dict = {}        # func -> size arg indices (size-preserving allocators)
        for f, nm in self.names.items():
            if normalize(nm or "").lower() in ("main", "wmain", "tmain") and f in self.func_irs:
                for i in (1, 2):
                    self.p_ptr[(f, i)] = "argv"
        for f, idxs in (entry_seeds or {}).items():
            for i in idxs:
                self.p_taint[(f, i)] = "entry-param"
                self.p_ptr[(f, i)] = "entry-param"
                self.p_range[(f, i)] = (0, _mask(self.word))
        self.funcs: dict = {}
        self.skipped: list = []
        self.filled: dict = {}          # base pointer -> [(lo, hi|None, origin spec)] input bytes
        self.gregions: dict = {}        # (lo, hi) absolute address range of a filled global
        self.call_rec: dict = {}        # call site -> record
        self._visiting: set = set()
        self._blk = None                # the block being evaluated (write records)
        # field facts: structural indexes, built once after evaluation (they do not depend on taint)
        self._paths: dict = {}          # pointer node -> access path (root, offsets) | None
        self._pstack: dict = {}         # nodes whose path is being computed -> stack depth
        self._ptmp: dict = {}           # provisional paths inside an open loop
        self._plow = 1 << 30
        self._rpaths: dict = {}         # internal call site -> the path its return points at
        self._lvls: dict = {}           # location -> ([(location in a caller, call chain)], cut)
        self._callers_idx = None        # function -> internal call records that call it
        self._fidx = None               # (root, deref prefix) -> offset bucket -> writes
        self._wild: dict = {}           # writes whose locations ran past the lift budget
        self._cidx = None               # location -> comparisons on a load of it
        self._ldat: dict = {}           # load node -> {(function, block, insn)} it is read in
        self._fwhere: dict = {}         # (path, size) -> the object a field fact came from
        self.fstats: dict = defaultdict(int)
        self.reset_memos()

    def reset_memos(self):
        self._memo_taint: dict = {}
        self._memo_ptr: dict = {}
        self._memo_rng: dict = {}
        self._memo_rt: dict = {}
        self._memo_rr: dict = {}
        self._memo_field: dict = {}     # load node -> (origin, range) from the field facts | None
        self._raw_ld: set = set()       # load nodes tainted as raw input bytes (not via a field)

    def _fam_of_group(self, grp):
        for r in sorted(grp, key=lambda r: (-len(r), r)):
            fam = self.regmap.get(r.upper())
            if fam:
                return fam[0]
        return self._canon(sorted(grp)[0])[0]

    def _canon(self, name):
        """register name -> (family, byte offset, size or None)."""
        n = name.upper()
        r = self.regmap.get(n)
        if r:
            return r
        if self.ak == "aarch64":
            if n.startswith("W") and n[1:].isdigit():
                return ("X" + n[1:], 0, 4)
            if n == "WSP":
                return ("SP", 0, 4)
            return (n, 0, None)
        if n.startswith("_"):
            return (n[1:], 0, None)
        if n.endswith("_LO"):
            return (n[:-3], 0, None)
        return (n, 0, None)

    def _param_index(self, key):
        if isinstance(key, tuple) and key and key[0] == "stk":
            return key[1]
        try:
            return self.argfams.index(key)
        except ValueError:
            return None

    # ------------------------------------------------------------------ evaluation driver
    def bottom_up(self):
        """Functions callees-first, so a caller sees its callees' out-parameter summaries and
        allocator-wrapper status."""
        done, order = set(), []
        for root in sorted(self.func_irs, key=str):
            if root in done:
                continue
            stack = [(root, iter(sorted(self.cg.get(root, ()), key=str)))]
            done.add(root)
            while stack:
                f, it = stack[-1]
                g = next(it, None)
                if g is None:
                    stack.pop()
                    order.append(f)
                    continue
                if g not in done:
                    done.add(g)
                    stack.append((g, iter(sorted(self.cg.get(g, ()), key=str))))
        return order

    def evaluate(self, faddr):
        F = _Func(faddr, self.func_irs.get(faddr))
        self.funcs[faddr] = F
        if not F.order:
            return F
        nops = sum(len(i.get("pcode") or ()) for b in F.by.values()
                   for i in (b.get("instructions") or ()))
        if len(F.by) > _MAX_BLOCKS or nops > _MAX_OPS:
            F.skipped = {"blocks": len(F.by), "ops": nops}
            self.skipped.append(faddr)
            return F
        N = self.N
        sp0 = N.mk(("sp", self.word, 0, faddr))
        entry_state = [{self.sp_fam: (sp0, self.word)}, {}, {}, ("e", faddr)]
        OUT: dict = {}
        for _pass in range(_MAX_PASSES):
            changed = False
            F.rets.clear()
            F.outs.clear()
            F.stores.clear()
            F.fills.clear()
            for a in F.order:
                ins = [(p, OUT[p]) for p in F.preds.get(a, ()) if p in OUT]
                if a == F.entry:
                    ins = ins + [("<entry>", entry_state)]
                if not ins:
                    continue
                st = _copy_state(ins[0][1]) if len(ins) == 1 else self._merge(F, a, ins)
                out = self._run_block(F, a, st)
                if a not in OUT or not _same_state(OUT[a], out):
                    OUT[a] = out
                    changed = True
            if not changed:
                break
        self._note_wrapper(F)
        return F

    def _note_wrapper(self, F):
        """A size-preserving allocator wrapper: one allocation whose size is the function's own
        parameter k, and every return is that allocation (or NULL)."""
        N = self.N
        allocs = [r for r in F.calls.values() if self._alloc_args(r) is not None]
        if len(allocs) != 1 or not F.rets:
            return
        r = allocs[0]
        sizes = self._alloc_args(r)
        if len(sizes) != 1 or sizes[0] >= len(r["args"]):
            return
        s = _strip(N, r["args"][sizes[0]])
        ks = N.key[s]
        if ks[0] != "arg" or ks[2] != F.addr:
            return
        idx = self._param_index(ks[3])
        if idx is None:
            return
        for v in F.rets.values():
            if v != r["ret"] and N.cval(v) != 0:
                kv = N.key[v]
                if kv[0] == "phi" and all(x == r["ret"] or N.cval(x) == 0 or x == v
                                          for x in N.phi_in.get(v, {}).values()):
                    continue
                return
        self.wrappers[F.addr] = (idx,)

    def _alloc_args(self, rec):
        sizes = ALLOC_SIZE_ARGS.get(rec.get("name") or "")
        if sizes is None and rec.get("internal"):
            sizes = self.wrappers.get(rec.get("dst"))
        return sizes

    # ------------------------------------------------------------------ block evaluation
    def _merge(self, F, a, ins):
        N, B = self.N, self.B
        regs, stk, heap = {}, {}, {}
        fams = set()
        for _, s in ins:
            fams |= set(s[0])
        for fam in fams:
            vals = [s[0].get(fam) for _, s in ins]
            if all(v is not None and v == vals[0] for v in vals):
                regs[fam] = vals[0]
                continue
            size = max(v[1] for v in vals if v is not None)
            ph = N.mk(("phi", size, F.addr, a, ("r", fam)))
            for (p, _s), v in zip(ins, vals):
                if v is None:
                    inp = N.mk(("arg", size, F.addr, fam)) if p == "<entry>" else \
                        N.top(size, ("clob", F.addr, p, fam))
                else:
                    inp = v[0] if v[1] == size else B.op("INT_ZEXT", size, v[0])
                N.phi_in[ph][p] = inp
            regs[fam] = (ph, size)
        offs = set()
        for _, s in ins:
            offs |= set(s[1])
        for off in offs:
            vals = [s[1].get(off) for _, s in ins]
            if all(v is not None and v == vals[0] for v in vals):
                stk[off] = vals[0]
                continue
            sizes = {v[0] for v in vals if v is not None}
            if len(sizes) != 1:
                continue
            size = sizes.pop()
            ph = N.mk(("phi", size, F.addr, a, ("s", off)))
            for (p, _s), v in zip(ins, vals):
                N.phi_in[ph][p] = v[1] if v is not None else self._slot_default(F, off, size)
            stk[off] = (size, ph)
        keys = None
        for _, s in ins:
            keys = set(s[2]) if keys is None else keys & set(s[2])
        for k in keys or ():
            vals = [s[2][k] for _, s in ins]
            if all(v == vals[0] for v in vals):
                heap[k] = vals[0]
        epochs = {s[3] for _, s in ins}
        epoch = epochs.pop() if len(epochs) == 1 else ("m", F.addr, a)
        return [regs, stk, heap, epoch]

    def _slot_default(self, F, off, size):
        """A stack slot the function has not written on this path: input bytes if a source
        filled it, an incoming stack argument (cdecl), or the unknown entry contents."""
        for (lo, hi), spec in F.regions.items():
            if lo <= off < hi:
                return self.N.mk(("srcld", size, spec, off, F.addr))
        if self.stack_args and off >= self.word and (off - self.word) % self.word == 0:
            return self.N.mk(("arg", size, F.addr, ("stk", (off - self.word) // self.word)))
        return self.N.mk(("stk", size, F.addr, off))

    def _read_reg(self, F, regs, name, size):
        N, B = self.N, self.B
        if name in ("XZR", "WZR") or (name == "ZERO" and self.ak in ("riscv", "mips")):
            return N.const(0, size)
        fam, off, _ = self._canon(name)
        cur = regs.get(fam)
        if cur is None:
            fsize = self.fullsize if (name in self.regmap or self.ak == "aarch64") else size
            fsize = max(fsize, size + off)
            regs[fam] = (N.mk(("arg", fsize, F.addr, fam)), fsize)
            cur = regs[fam]
        node, csize = cur
        if off == 0 and size == csize:
            return node
        if off + size <= csize:
            return B.subpiece(node, off, size)
        return B.op("INT_ZEXT", size, node)

    def _write_reg(self, F, regs, name, size, val, tag):
        N = self.N
        fam, off, _ = self._canon(name)
        cur = regs.get(fam)
        if off == 0 and (cur is None or size >= cur[1]):
            regs[fam] = (val, size)
            return
        if cur is None:
            cur = (N.mk(("arg", size + off, F.addr, fam)), size + off)
        node, csize = cur
        if off == 0:
            regs[fam] = (N.mk(("op", csize, "PARTIAL", node, val),
                              1 + max(N.depth[node], N.depth[val])), csize)
        else:
            regs[fam] = (N.top(csize, tag), csize)

    def _split(self, addr):
        k = self.N.key[addr]
        if k[0] == "op" and k[2] == "INT_ADD":
            c = self.N.cval(k[4])
            if c is not None:
                return k[3], _signed(c, k[1])
        return addr, 0

    def _load(self, F, st, addr, size, where):
        N, B = self.N, self.B
        stk, heap, epoch = st[1], st[2], st[3]
        ka = N.key[addr]
        if ka[0] == "sp" and ka[3] == F.addr:
            off = ka[2]
            e = stk.get(off)
            if e is not None:
                if e[0] == size:
                    return e[1]
                if size < e[0]:
                    return B.subpiece(e[1], 0, size)
            for o2, (s2, v2) in stk.items():
                if o2 < off and off + size <= o2 + s2:
                    return B.subpiece(v2, off - o2, size)
            return self._slot_default(F, off, size)
        hk = (addr, size)
        v = heap.get(hk)
        if v is not None:
            return v
        v = N.mk(("ld", size, addr, epoch), N.depth[addr] + 1, where)
        heap[hk] = v
        self._ldat.setdefault(v, set()).add((F.addr, self._blk, where))
        return v

    def _store(self, F, st, addr, size, val):
        N = self.N
        stk, heap = st[1], st[2]
        ka = N.key[addr]
        F.stores[(self._blk, addr, size, val)] = None       # for the field facts
        if ka[0] == "sp" and ka[3] == F.addr:
            off = ka[2]
            for o2 in [o for o, (s2, _v) in stk.items() if o < off + size and off < o + s2]:
                del stk[o2]
            stk[off] = (size, val)
            return
        base, boff = self._split(addr)
        for k in list(heap):
            kb, ko = self._split(k[0])
            if kb == base and (ko + k[1] <= boff or boff + size <= ko):
                continue                      # the same object, a disjoint field: survives
            del heap[k]
        heap[(addr, size)] = val
        kb = N.key[base]
        if kb[0] == "arg" and kb[2] == F.addr:
            idx = self._param_index(kb[3])
            if idx is not None:
                F.outs.setdefault((idx, boff, size), set()).add(val)

    def _read(self, F, st, uniq, t):
        N = self.N
        if t is None:
            return N.top(8, ("none",))
        sp, off, size = t
        if sp == "const":
            return N.const(off, size)
        if sp == "unique":
            v = uniq.get(off)
            return v if v is not None else N.top(size, ("u", F.addr, off))
        if sp == "reg":
            return self._read_reg(F, st[0], off, size)
        if sp == "register":
            return self._read_reg(F, st[0], "REG@%x" % off, size)
        if sp == "ram":
            return self._load(F, st, N.const(off, self.word), size, None)
        return N.top(size, ("sp?", sp, off))

    def _write(self, F, st, uniq, t, val, tag):
        sp, off, size = t
        if sp == "unique":
            uniq[off] = val
        elif sp == "reg":
            self._write_reg(F, st[0], off, size, val, tag)
        elif sp == "register":
            self._write_reg(F, st[0], "REG@%x" % off, size, val, tag)
        elif sp == "ram":
            self._store(F, st, self.N.const(off, self.word), size, val)

    def _run_block(self, F, a, st):
        N, B = self.N, self.B
        blk = F.by[a]
        instrs = blk.get("instructions") or []
        F.cond.pop(a, None)
        self._blk = a
        nins = len(instrs)
        for ii, ins in enumerate(instrs):
            iaddr = ins.get("addr")
            ops = ins.get("pcode") or []
            uniq: dict = {}
            sp_before = st[0].get(self.sp_fam)
            pending = None                # (skip-to index, cond, snapshot) for cmov/csel
            nops = len(ops)
            j = 0
            while j < nops:
                if pending is not None and j >= pending[0]:
                    uniq = self._join_skip(st, uniq, pending)
                    pending = None
                mnem, ins_t, out_t = _parse(ops[j])
                tag = (iaddr, j)
                if mnem is None:
                    j += 1
                    continue
                if mnem == "CBRANCH":
                    cond = self._read(F, st, uniq, ins_t[1]) if len(ins_t) > 1 else None
                    tgt = ins_t[0] if ins_t else None
                    if j == nops - 1 and (ii == nins - 1 or (tgt and tgt[0] == "ram")):
                        if ii == nins - 1 and tgt and tgt[0] == "ram" and cond is not None:
                            F.cond[a] = (cond, "0x%x" % tgt[1])
                        j += 1
                        continue
                    if tgt and tgt[0] == "const":
                        to = j + _signed(tgt[1], max(1, min(tgt[2], 8)))
                    elif tgt and tgt[0] == "ram" and tgt[1] == _hexint(iaddr):
                        to = j                    # a rep-prefix self loop: run once
                    else:
                        to = nops                 # x86 cmov: skip to the next instruction
                    if to > j + 1 and cond is not None and pending is None:
                        pending = (to, cond, (_copy_state(st), dict(uniq)))
                    j += 1
                    continue
                if mnem == "BRANCH":
                    tgt = ins_t[0] if ins_t else None
                    if tgt and tgt[0] == "const":
                        for jj in range(j + 1, nops):
                            _m, _i, o = _parse(ops[jj])
                            if o is not None:
                                self._write(F, st, uniq, o, N.top(o[2], (iaddr, jj)), (iaddr, jj))
                        break
                    if tgt and tgt[0] == "ram" and "0x%x" % tgt[1] not in F.by:
                        if tgt[1] in self.addr_name or tgt[1] in self.func_by_int:
                            self._call(F, a, st, iaddr, tgt[1], sp_before, tail=True)
                            F.rets[(a, iaddr)] = self._read_reg(F, st[0], self.retfam,
                                                                self.word)
                    j += 1
                    continue
                if mnem in ("CALL", "CALLIND"):
                    tgt = ins_t[0] if ins_t else None
                    t_int = tgt[1] if (tgt and tgt[0] == "ram" and mnem == "CALL") else None
                    self._call(F, a, st, iaddr, t_int, sp_before)
                    j += 1
                    continue
                if mnem == "RETURN" or (mnem == "BRANCHIND" and not F.succ.get(a)):
                    F.rets[(a, iaddr)] = self._read_reg(F, st[0], self.retfam, self.word)
                    j += 1
                    continue
                if mnem == "STORE":
                    if len(ins_t) >= 3 and ins_t[2] is not None:
                        addr = self._read(F, st, uniq, ins_t[1])
                        val = self._read(F, st, uniq, ins_t[2])
                        self._store(F, st, addr, ins_t[2][2], val)
                    j += 1
                    continue
                if out_t is None:
                    j += 1
                    continue
                osize = out_t[2]
                if mnem == "LOAD":
                    addr = self._read(F, st, uniq, ins_t[1]) if len(ins_t) > 1 else \
                        N.top(self.word, tag)
                    val = self._load(F, st, addr, osize, iaddr)
                elif mnem == "COPY":
                    val = self._read(F, st, uniq, ins_t[0])
                elif mnem in ("INT_ZEXT", "INT_SEXT", "INT_NEGATE", "INT_2COMP", "BOOL_NEGATE",
                              "POPCOUNT", "LZCOUNT"):
                    val = B.op(mnem, osize, self._read(F, st, uniq, ins_t[0]), where=iaddr)
                elif mnem == "SUBPIECE":
                    x = self._read(F, st, uniq, ins_t[0])
                    off = ins_t[1][1] if len(ins_t) > 1 and ins_t[1] and \
                        ins_t[1][0] == "const" else 0
                    val = B.subpiece(x, off, osize, iaddr)
                elif mnem == "PIECE" and len(ins_t) >= 2:
                    hi = self._read(F, st, uniq, ins_t[0])
                    lo = self._read(F, st, uniq, ins_t[1])
                    if N.cval(hi) == 0:
                        val = B.op("INT_ZEXT", osize, lo)
                    else:
                        val = N.mk(("op", osize, "PIECE", hi, lo),
                                   1 + max(N.depth[hi], N.depth[lo]))
                elif len(ins_t) >= 2 and not mnem.startswith("FLOAT") and \
                        mnem not in ("CPOOLREF", "NEW", "CAST", "PTRADD", "PTRSUB", "MULTIEQUAL",
                                     "INDIRECT", "CALLOTHER"):
                    x = self._read(F, st, uniq, ins_t[0])
                    y = self._read(F, st, uniq, ins_t[1])
                    val = B.op(mnem, osize, x, y, where=iaddr)
                else:
                    val = N.top(osize, tag)
                self._write(F, st, uniq, out_t, val, tag)
                j += 1
            if pending is not None:
                self._join_skip(st, uniq, pending)
        return st

    def _join_skip(self, st, uniq, pending):
        """Merge the skipped and the executed path of a cmov/csel into select(cond, skipped,
        executed) values."""
        _to, cond, (snap, suniq) = pending
        B, N = self.B, self.N
        regs = st[0]
        for fam in set(regs) | set(snap[0]):
            new, old = regs.get(fam), snap[0].get(fam)
            if new == old or new is None or old is None:
                continue
            size = max(new[1], old[1])
            nv = new[0] if new[1] == size else B.op("INT_ZEXT", size, new[0])
            ov = old[0] if old[1] == size else B.op("INT_ZEXT", size, old[0])
            regs[fam] = (N.mk(("sel", size, cond, ov, nv),
                              1 + max(N.depth[nv], N.depth[ov])), size)
        out = dict(uniq)
        for k in set(uniq) & set(suniq):
            new, old = uniq[k], suniq[k]
            if new != old and N.size(new) == N.size(old):
                out[k] = N.mk(("sel", N.size(new), cond, old, new),
                              1 + max(N.depth[new], N.depth[old]))
        return out

    # ------------------------------------------------------------------------------ calls
    def _call(self, F, a, st, iaddr, t_int, sp_before, tail=False):
        N, B = self.N, self.B
        regs, stk, heap = st[0], st[1], st[2]
        cm = self.callmap.get(iaddr)
        name = cm[0] if cm else None
        dst = cm[1] if cm else None
        if name is None and t_int is not None:
            name = self.addr_name.get(t_int)
        if dst is None and t_int is not None:
            dst = self.func_by_int.get(t_int)
        if name is None and dst is not None:
            name = normalize(self.names.get(dst) or "") or None
        # an import stub lifted as a function (aarch64 PLT) is the library routine, not code to
        # summarise: modelling `strlen`'s stub as "returns its argument" would invent taint
        internal = dst in self.func_irs and not (cm and cm[2]) and name not in _KNOWN_LIB
        args = []
        if self.callargfams:
            for fam in self.callargfams:
                args.append(self._read_reg(F, regs, fam, self.word))
        elif self.stack_args and sp_before is not None:
            k = N.key[sp_before[0]]
            if k[0] == "sp":
                for i in range(8):
                    v = stk.get(k[2] + self.word * i)
                    args.append(v[1] if v else N.top(self.word, (iaddr, "arg", i)))
        ret = N.mk(("ret", self.word, iaddr, dst if internal else name))
        nm = name or ""
        rec = {"site": iaddr, "block": a, "name": nm, "dst": dst, "internal": internal,
               "args": args, "ret": ret, "func": F.addr, "tail": tail}
        F.calls[iaddr] = rec
        self.call_rec[iaddr] = rec
        origin = f"{nm or 'call'}@{iaddr}"
        handled = set()
        src = _OUT_SOURCES.get(nm)
        if src is not None and src[0] < len(args):
            self._fill(F, st, args[src[0]], self._len_of(args, src[1]), origin)
            handled.add(src[0])
        if nm in _SCANF and _SCANF[nm] is not None:
            spec = ("if-ptr", args[0], origin) if nm in _SCANF_FROM_STRING and args else origin
            for i, p in enumerate(args[_SCANF[nm]:], _SCANF[nm]):
                # the register file holds stale values past the last real argument: stop at the
                # first one that is not an address
                if not self._addressish(F, p):
                    break
                self._fill(F, st, p, 8, spec, flen=4)
                handled.add(i)
        cp = _COPIES.get(nm)
        if cp is not None and len(args) > max(cp[0], cp[1]):
            self._fill(F, st, args[cp[0]], self._len_of(args, cp[2]),
                       ("if-ptr", args[cp[1]], origin))
            handled.add(cp[0])
        summary = (self.funcs.get(dst).outs if internal and dst in self.funcs else {}) or {}
        # the callee may write through any pointer it was given: drop the heap cache; forget the
        # stack slots whose address it received (unless a source or a summary defined them)
        heap.clear()
        for i, p in enumerate(args):
            kp = N.key[p]
            if kp[0] != "sp" or kp[3] != F.addr or i in handled or nm in _READ_ONLY:
                continue
            if any(k[0] == i for k in summary):
                continue
            if internal and not self._writes_through(dst, i):
                continue                    # the callee only reads through this pointer
            lo = kp[2]
            for o in [o for o in stk if lo <= o < lo + 64]:
                # a neighbour of the passed object (not its first word) keeps, in the top's tag,
                # the value it held: still unknown for taint and range, but the field facts may
                # take a pointer's object identity from it (`&ext` passed beside `gif` would
                # otherwise erase which object `gif` points at)
                old = stk[o][1] if o >= lo + self.word else None
                stk[o] = (stk[o][0], N.top(stk[o][0], ("clobs", iaddr, o, old)))
        for (pi, off, sz) in summary:
            if pi < len(args):
                p = args[pi]
                tgt = B.op("INT_ADD", self.word, p, N.const(off, self.word)) if off else p
                leaf = N.mk(("out", sz, iaddr, pi, off))
                kt = N.key[tgt]
                if kt[0] == "sp" and kt[3] == F.addr:
                    self._store(F, st, tgt, sz, leaf)
                else:
                    heap[(tgt, sz)] = leaf
        for fam in list(regs):
            if fam in _SCRATCH.get(self.ak, ()) or fam in self.callargfams or \
                    (self.ak in ("x86-64", "x86") and fam in _X86_FLAGS):
                del regs[fam]
        rt = _RET_TYPES.get(nm) if not internal else None
        if rt is not None and rt[0] < self.word:
            # the routine returns a narrower C type: only its low part is the value (atoi's
            # upper half of x0/RAX is not part of the int it returns)
            inner = N.mk(("ret", rt[0], iaddr, name))
            rv = B.op("INT_SEXT" if rt[1] else "INT_ZEXT", self.word, inner)
            rec["ret_value"] = inner
        else:
            rv = ret
        regs[self.retfam] = (rv, self.word)
        if sp_before is not None and self.ak in ("x86-64", "x86"):
            regs[self.sp_fam] = sp_before
        st[3] = ("c", iaddr)

    def _addressish(self, F, p):
        N = self.N
        b, _off = self._split(p)
        k = N.key[b]
        if k[0] == "sp":
            return k[3] == F.addr and k[2] < 0
        if k[0] == "c":
            return k[2] >= 0x1000
        return k[0] in ("ret", "ld", "arg", "phi")

    def _writes_through(self, f, i):
        """May internal function `f` write through its pointer parameter i? A direct store
        (its out-parameter summary), or passing the pointer on to any call that is not known
        read-only. Unknown (not yet evaluated) -> yes."""
        F = self.funcs.get(f)
        if F is None or F.skipped or not F.order:
            return True
        if any(k[0] == i for k in F.outs):
            return True
        N = self.N
        for rec in F.calls.values():
            if rec["name"] in _READ_ONLY:
                continue
            for a in rec["args"]:
                kb = N.key[self._split(a)[0]]
                if kb[0] == "arg" and kb[2] == f and self._param_index(kb[3]) == i:
                    return True
        return False

    def _len_of(self, args, ln):
        N = self.N
        if ln is None:
            return None
        idxs = (ln,) if isinstance(ln, int) else ln
        v = 1
        for i in idxs:
            c = N.cval(args[i]) if i < len(args) else None
            if c is None:
                return None
            v *= c
        return v

    def _fill(self, F, st, ptr, length, spec, flen=None):
        """Bytes at `ptr` now hold input (`spec` = an origin, or ('if-ptr', src, origin) for a
        copy whose source may or may not be input -- resolved lazily, so evaluation does not
        depend on taint facts). `flen`: the byte count the field facts file it under, when the
        evaluation's own length is only an over-estimate (a scanf conversion)."""
        N = self.N
        fl = length if flen is None else flen
        if isinstance(fl, int) and 0 < fl <= 0x100000:
            F.fills[(self._blk, ptr, fl, spec)] = None     # for the field facts (known length only)
        k = N.key[ptr]
        if k[0] == "sp" and k[3] == F.addr:
            lo = k[2]
            hi = lo + (length if length and 0 < length <= 0x100000 else 0x1000)
            stk = st[1]
            for o in [o for o in stk if lo <= o < hi]:
                del stk[o]
            F.regions.setdefault((lo, hi), spec)
            return
        if k[0] == "c":
            # a global buffer (`static buf[N]; fread(buf, ...)`): indexed later as `i + &buf`,
            # where the constant is the base, not a field displacement
            lo = k[2]
            hi = lo + (length if length and 0 < length <= 0x1000000 else 0x1000)
            self.gregions.setdefault((lo, hi), spec)
            return
        # offset-granular: `read(fd, p + 16, 4)` makes p[16..20) input, not all of *p -- which
        # matters under ASan, where every local of a frame lives behind one fake-stack pointer
        base, off = self._split(ptr)
        hi = off + length if length and 0 < length <= 0x1000000 else None
        self.filled.setdefault(base, []).append((off, hi, spec))

    # ------------------------------------------------------------------------------ taint
    def _spec(self, spec, seen):
        if isinstance(spec, str):
            return spec
        if isinstance(spec, tuple) and spec and spec[0] == "if-ptr":
            o = self.ptr_taint(spec[1], seen)
            return f"{spec[2]} <- {o}" if o else None
        return None

    def taint(self, n, seen=None):
        """Origin text if node `n` is attacker-controlled, else None."""
        r = self._memo_taint.get(n, 0)
        if r != 0:
            return r
        seen = set() if seen is None else seen
        if ("t", n) in seen or len(seen) > 2000:
            return None
        seen.add(("t", n))
        N = self.N
        k = N.key[n]
        kind = k[0]
        out = None
        if kind == "srcld":
            out = self._spec(k[2], seen)
        elif kind == "arg":
            idx = self._param_index(k[3])
            if idx is not None:
                out = self.p_taint.get((k[2], idx))
        elif kind == "ret":
            out = self._ret_taint(k, seen)
        elif kind == "out":
            out = self._out_taint(k, seen)
        elif kind == "ld":
            out = self._load_taint(k[2], seen)
            if out:
                self._raw_ld.add(n)
            else:
                ff = self._field(n, seen)
                out = ff[0] if ff else None
        elif kind == "op":
            for x in k[3:]:
                if isinstance(x, int) and N.key[x][0] != "c":
                    out = self.taint(x, seen)
                    if out:
                        break
        elif kind == "sel":
            for x in (k[3], k[4]):
                out = self.taint(x, seen)
                if out:
                    break
        elif kind == "phi":
            for x in N.phi_in.get(n, {}).values():
                out = self.taint(x, seen)
                if out:
                    break
        self._memo_taint[n] = out
        return out

    def _filled_at(self, base, off, seen):
        """Origin if byte `off` of the object at `base` was filled with input (`off` None: an
        index the analysis cannot pin -- any filled range of the object counts)."""
        for lo, hi, spec in self.filled.get(base, ()):
            if off is None or (lo <= off and (hi is None or off < hi)):
                o = self._spec(spec, seen)
                if o:
                    return o
        return None

    def _load_taint(self, addr, seen):
        b, c = self._split(addr)
        if b in self.filled:
            o = self._filled_at(b, c if b != addr or c == 0 else None, seen)
            if o:
                return o
        for b in self._bases(addr):
            o = self.ptr_taint(b, seen) if b not in self.filled else \
                self._filled_at(b, None if b != addr else 0, seen)
            if o:
                return o
        if self.gregions:
            for c in self._const_terms(addr):
                o = self._in_global(c, seen)
                if o:
                    return o
        return None

    def _const_terms(self, addr, depth=0):
        N = self.N
        k = N.key[addr]
        if k[0] == "c":
            return [k[2]]
        if depth > 6 or k[0] != "op" or k[2] != "INT_ADD":
            return []
        return self._const_terms(k[3], depth + 1) + self._const_terms(k[4], depth + 1)

    def _in_global(self, c, seen):
        for (lo, hi), spec in self.gregions.items():
            if lo <= c < hi:
                o = self._spec(spec, seen)
                if o:
                    return o
        return None

    def _bases(self, addr, depth=0):
        """The pointer-like components of an address -- not its (scaled) index terms. A table
        indexed by input yields table contents, not input, so an index never taints a load."""
        N = self.N
        k = N.key[addr]
        if depth > 6 or k[0] != "op" or k[2] != "INT_ADD":
            return [addr]
        out = []
        for x in (k[3], k[4]):
            kx = N.key[x]
            if kx[0] == "c" or (kx[0] == "op" and kx[2] in ("INT_MULT", "INT_LEFT", "INT_ZEXT",
                                                             "INT_SEXT")):
                continue
            out.extend(self._bases(x, depth + 1))
        return out

    def ptr_taint(self, n, seen=None):
        """Origin text if `n` points at attacker-controlled bytes."""
        r = self._memo_ptr.get(n, 0)
        if r != 0:
            return r
        seen = set() if seen is None else seen
        if ("p", n) in seen or len(seen) > 2000:
            return None
        seen.add(("p", n))
        N = self.N
        k = N.key[n]
        out = None
        out = self._filled_at(n, 0, seen)
        if out is None:
            kind = k[0]
            if kind == "c" and self.gregions:
                out = self._in_global(k[2], seen)
            elif kind == "sp":
                F = self.funcs.get(k[3])
                for (lo, hi), sp in (F.regions.items() if F else ()):
                    if lo <= k[2] < hi:
                        out = self._spec(sp, seen)
                        if out:
                            break
            elif kind == "arg":
                idx = self._param_index(k[3])
                if idx is not None:
                    out = self.p_ptr.get((k[2], idx))
            elif kind == "ld":
                # a pointer read out of attacker-controlled memory points where the attacker says;
                # an attacker-set integer FIELD is not such a pointer, so the field facts stay out
                out = self._load_taint(k[2], seen)
            elif kind in ("srcld", "out"):
                out = self.taint(n, seen)
            elif kind == "ret":
                callee = k[3]
                if callee in self.funcs:
                    for v in self.funcs[callee].rets.values():
                        out = self.ptr_taint(v, seen)
                        if out:
                            break
            elif kind == "op" and k[2] == "INT_ADD":
                b, c = self._split(n)
                if b != n and b in self.filled:
                    out = self._filled_at(b, c, seen)
                else:
                    for b in self._bases(n):
                        if b != n:
                            out = self.ptr_taint(b, seen) if b not in self.filled else \
                                self._filled_at(b, None, seen)
                            if out:
                                break
            elif kind == "phi":
                for x in N.phi_in.get(n, {}).values():
                    out = self.ptr_taint(x, seen)
                    if out:
                        break
            elif kind == "sel":
                out = self.ptr_taint(k[3], seen) or self.ptr_taint(k[4], seen)
        self._memo_ptr[n] = out
        return out

    def _ret_taint(self, k, seen):
        callee = k[3]
        if callee in self.funcs:
            r = self._memo_rt.get(callee, 0)
            if r != 0:
                return r
            out = None
            for v in self.funcs[callee].rets.values():
                out = self.taint(v, seen)
                if out:
                    break
            self._memo_rt[callee] = out
            return out
        if callee in _VALUE_SOURCES:
            return f"{callee}@{k[2]}"
        rec = self.call_rec.get(k[2])
        if rec and rec["args"]:
            if callee in _STR_TO_NUM:
                o = self.ptr_taint(rec["args"][0], seen)
                return f"{callee}({o})" if o else None
            if callee in _PASS_THROUGH:
                return self.taint(rec["args"][0], seen)
        return None

    def _out_taint(self, k, seen):
        rec = self.call_rec.get(k[2])
        F = self.funcs.get(rec["dst"]) if rec else None
        if F is None:
            return None
        for v in F.outs.get((k[3], k[4], k[1]), ()):
            o = self.taint(v, seen)
            if o:
                return o
        return None

    # ------------------------------------------------------------------------ field facts
    # A value decoded in one function, stored into a struct or a global, and read in another.
    # Every write the evaluation saw (STORE, input fill, memcpy) is filed under the ABSTRACT
    # LOCATION it writes; a load reads the writes filed under its own location. See the module
    # docstring ("field facts") for the identity scheme, the range rule and the guard rule.
    def _ptr_path(self, n):
        """Where pointer value `n` points: (root, offsets) or None. Roots: ("g",) a global
        (offsets[0] is the absolute address), ("h", site) the object an allocation call at `site`
        returned, ("p", f, i) whatever f's parameter i points at, ("s", f) f's stack frame
        (offsets[0] is the frame offset). Every offset but the last is a pointer LOADED from that
        offset of the object before it: *(*(p + 8) + 4) is (("p", f, 0), (8, 4))."""
        r = self._paths.get(n, 0)
        if r != 0:
            return r
        d = self._pstack.get(n)
        if d is not None:                          # a loop: optimistic, settled by the phi
            self._plow = min(self._plow, d)
            return _CYCLE
        if n in self._ptmp:
            return self._ptmp[n]
        depth = len(self._pstack)
        self._pstack[n] = depth
        saved, self._plow = self._plow, 1 << 30
        try:
            r = self._ptr_path_(n)
        finally:
            del self._pstack[n]
        low, self._plow = self._plow, min(saved, self._plow)
        if r is _CYCLE and low >= depth:
            r = None                               # nothing but the loop itself: unknown
        if low >= depth:
            self._paths[n] = r                     # final: no open loop below this node
        else:
            self._ptmp[n] = r                      # provisional on an enclosing loop's phi
        if depth == 0:
            self._ptmp.clear()
        return r

    def _ptr_path_(self, n):
        N = self.N
        base, off = self._split(n)
        kb = N.key[base]
        kind = kb[0]
        if kind == "c":
            return (("g",), (kb[2],)) if kb[2] >= 0x1000 else None
        if kind == "arg":
            idx = self._param_index(kb[3])
            return (("p", kb[2], idx), (off,)) if idx is not None else None
        if kind == "sp":
            return (("s", kb[3]), (kb[2] + off,))
        if kind == "top":
            tag = kb[2]
            if isinstance(tag, tuple) and tag and tag[0] == "clobs" and tag[3] is not None:
                q = self._ptr_path(tag[3])
                if q is _CYCLE:
                    return _CYCLE if off == 0 else None
                return _shift(q, off) if q is not None else None
            return None
        if kind == "out":
            # the pointer a callee stored through its parameter: a load of that field after
            # the call ("out", size, site, param, offset)
            rec = self.call_rec.get(kb[2])
            if rec is None or kb[1] != self.word or kb[3] >= len(rec["args"]):
                return None
            q = self._ptr_path(rec["args"][kb[3]])
            if q in (None, _CYCLE) or len(q[1]) >= _FIELD_DEPTH:
                return None
            return (q[0], _shift(q, kb[4])[1] + (off,))
        if kind == "ret":
            rec = self.call_rec.get(kb[2])
            if rec is None or kb[1] != self.word:
                return None
            if self._alloc_args(rec) is not None:
                return (("h", kb[2]), (off,))
            if rec["internal"] and rec["dst"] in self.funcs:
                rp = self._ret_path(rec)
                return _shift(rp, off) if rp else None
            return None
        if kind == "ld":
            q = self._ptr_path(kb[2])
            if q in (None, _CYCLE) or len(q[1]) >= _FIELD_DEPTH or kb[1] != self.word:
                return None
            return (q[0], q[1] + (off,))
        if kind in ("phi", "sel"):
            if base != n:
                q = self._ptr_path(base)
                return _shift(q, off) if q not in (None, _CYCLE) else None
            ins = list(N.phi_in.get(base, {}).values()) if kind == "phi" else [kb[3], kb[4]]
            got, cyc = None, False
            for x in ins:
                if x == base or N.cval(x) == 0:
                    continue                       # a NULL arm does not change the object
                p = self._ptr_path(x)
                if p is _CYCLE:
                    cyc = True
                    continue                       # the value carried round a loop unchanged
                if p is None or (got is not None and p != got):
                    return None                    # two objects, or a loop-carried pointer
                got = p
            return got if got is not None or not cyc else _CYCLE
        return None

    def _ret_path(self, rec):
        """The object an internal call returns: one path for every non-NULL return (a
        constructor's allocation, a global, or -- mapped through this call -- a parameter)."""
        site = rec["site"]
        r = self._rpaths.get(site, 0)
        if r != 0:
            return r
        self._rpaths[site] = None
        F = self.funcs.get(rec["dst"])
        got = None
        for v in (F.rets.values() if F is not None else ()):
            if self.N.cval(v) == 0:
                continue
            p = self._ptr_path(v)
            p = None if p is _CYCLE else p
            if p is not None and p[0][0] == "p" and p[0][1] == rec["dst"]:
                i = p[0][2]
                q = self._ptr_path(rec["args"][i]) if i < len(rec["args"]) else None
                p = _compose(q, p) if q not in (None, _CYCLE) else None
            if p is None or (got is not None and p != got):
                got = None
                break
            got = p
        self._rpaths[site] = got
        return got

    def _callers(self):
        if self._callers_idx is None:
            idx = defaultdict(list)
            for rec in self.call_rec.values():
                if rec["internal"] and rec["dst"] in self.funcs:
                    idx[rec["dst"]].append(rec)
            self._callers_idx = idx
        return self._callers_idx

    def _levels(self, loc):
        """`loc` and every location it denotes in the callers of its function (a parameter-rooted
        location is lifted through each call site to where that caller's argument points), each
        with the call chain that maps it: ([(location, chain)], cut by the budget)."""
        r = self._lvls.get(loc)
        if r is not None:
            return r
        out, cut, todo = [(loc, ())], False, [(loc, ())]
        callers = self._callers()
        while todo and not cut:
            cur, ch = todo.pop()
            root = cur[0]
            if root[0] != "p" or len(ch) >= _LIFT_DEPTH:
                continue
            sites = {x["site"] for x in ch}
            for rec in callers.get(root[1], ()):
                args = rec["args"]
                if rec["site"] in sites or root[2] >= len(args):
                    continue
                q = self._ptr_path(args[root[2]])
                nl = _compose(q, cur) if q not in (None, _CYCLE) else None
                if nl is None:
                    continue
                out.append((nl, ch + (rec,)))
                if len(out) > _LIFT_BUDGET:
                    cut = True
                    break
                todo.append((nl, ch + (rec,)))
        r = (out, cut)
        self._lvls[loc] = r
        return r

    def _field_index(self):
        """Every write of the program filed under every location it may write."""
        if self._fidx is not None:
            return self._fidx
        idx: dict = defaultdict(lambda: defaultdict(list))
        wild: dict = defaultdict(list)
        for f, F in self.funcs.items():
            writes = [(addr, size, ("v", f, blk, val)) for (blk, addr, size, val) in F.stores]
            for (blk, ptr, ln, spec) in F.fills:
                if isinstance(spec, tuple) and spec and spec[0] == "if-ptr":
                    writes.append((ptr, ln, ("c", f, blk, spec[1], spec[2])))
                else:
                    writes.append((ptr, ln, ("f", f, blk, spec)))
            for addr, size, ent in writes:
                p = self._ptr_path(addr)
                if p is None:
                    continue
                lv, cut = self._levels(p)
                if cut:
                    wild[(p[1][-1], size)].append(ent)
                for loc, ch in lv:
                    lo = loc[1][-1]
                    e = (lo, lo + size, ent, ch)
                    b = idx[(loc[0], loc[1][:-1])]
                    if size > 256:
                        b["big"].append(e)
                    else:
                        for k in range(lo >> 4, ((lo + size - 1) >> 4) + 1):
                            b[k].append(e)
        self._fidx, self._wild = idx, wild
        return idx

    def _writes_at(self, key, d, size):
        """The writes filed under object `key` that overlap bytes [d, d + size)."""
        b = self._field_index().get(key)
        if not b:
            return []
        got, out = set(), []
        for k in [*range(d >> 4, ((d + size - 1) >> 4) + 1), "big"]:
            for e in b.get(k, ()):
                if id(e) in got or e[1] <= d or e[0] >= d + size:
                    continue
                got.add(id(e))
                out.append(e)
        return out

    def _field(self, n, seen=None):
        """(origin, range) for load node `n` read from the field facts, or None."""
        r = self._memo_field.get(n, 0)
        if r != 0:
            return r
        self._memo_field[n] = None                 # recursion guard
        seen = set() if seen is None else seen
        k = self.N.key[n]
        p = self._ptr_path(k[2])
        r = None
        if p is not None:
            q = self._field_query(p, k[1], seen)
            if q:
                r = self._field_guarded(n, q)
        self._memo_field[n] = r
        return r

    def _field_query(self, p, size, seen, depth=0):
        """The attacker data a `size`-byte load at location `p` reads: (origin, range, the
        tainted value writes, the levels of p) or None. Judged per OBJECT (each level of p): an
        object counts when every write that may define those bytes is attacker data or a
        compile-time constant; the load's facts are the union over the objects that count."""
        key = ("fq", p, size)
        if key in seen:
            return None
        seen.add(key)
        self._field_index()
        lv, _cut = self._levels(p)
        for ent in self._wild.get((p[1][-1], size), ()):
            if self._write_value(ent, (), 0, size, seen, depth) is None:
                return None          # a write we could not place may be an untainted one
        origin, lo, hi, vals, where = None, None, None, [], []
        for loc, _ch in lv:
            r = self._level_fact((loc[0], loc[1][:-1]), loc[1][-1], size, seen, depth)
            if not r:
                continue
            origin = origin or r[0]
            lo = r[1][0] if lo is None else min(lo, r[1][0])
            hi = r[1][1] if hi is None else max(hi, r[1][1])
            vals.extend(r[2])
            where.append(loc)
        if origin is None:
            return None
        # name the object: a concrete one (heap / global / stack) over a parameter's pointee
        self._fwhere[(p, size)] = min(where, key=lambda x: x[0][0] == "p")
        return (origin, (lo, hi), vals, lv)

    def _level_fact(self, key, d, size, seen, depth):
        ws = self._writes_at(key, d, size)
        if not ws:
            return None
        if len(ws) > _FIELD_WRITES:
            return None
        origin, lo, hi, vals = None, None, None, []
        for (s_lo, s_hi, ent, ch) in ws:
            if not (s_lo <= d and d + size <= s_hi):
                return None          # the load spans several writes: its value is none of them
            r = self._write_value(ent, ch, d - s_lo, size, seen, depth)
            if r is None:
                return None          # a write that is neither attacker data nor a constant
            o, rr = r
            origin = origin or o
            lo = rr[0] if lo is None else min(lo, rr[0])
            hi = rr[1] if hi is None else max(hi, rr[1])
            if o and ent[0] == "v":
                vals.append((ent, ch))
        if origin is None:
            return None              # constants only: nothing the attacker drives
        return (origin, (lo, hi), vals)

    def _write_value(self, ent, ch, rel, size, seen, depth):
        """What bytes [rel, rel + size) of one write hold: (origin | None for a constant, range),
        or None when it is neither attacker data nor a constant."""
        N = self.N
        full = (0, _mask(size))
        kind = ent[0]
        if kind == "v":
            _k, f, blk, val = ent
            vs = N.size(val)
            c = self._chain_const(val, ch)
            if c is not None:
                v = (c >> (8 * rel)) & _mask(size)
                return (None, (v, v))
            o = self._chain_taint(val, ch, seen)
            if not o:
                return None
            # the stored value's range where it is stored (its dominating checks), narrowed by
            # the range the argument has at this call chain when the value is a parameter
            r = self.rng(val, (f, blk, ()), True)
            rc = self._chain_range(val, ch)
            if rc is not None and r[0] >= 0 and max(r[0], rc[0]) <= min(r[1], rc[1]):
                r = (max(r[0], rc[0]), min(r[1], rc[1]))
            if r[0] < 0 or r[1] > _mask(vs):
                r = (0, _mask(vs))                 # clipped to the store width
            if rel:
                r = (r[0] >> (8 * rel), r[1] >> (8 * rel))
            return (o, r if r[1] <= full[1] else full)
        if kind == "f":
            o = self._spec(ent[3], seen)
            return (o, full) if o else None
        if kind == "c":
            _k, f, blk, src, origin = ent
            # a struct copy: the field of the copy holds what the source field holds
            if depth < _COPY_DEPTH:
                q = self._ptr_path(src)
                if q is not None:
                    r = self._field_query(_shift(q, rel), size, seen, depth + 1)
                    if r:
                        return (f"{origin} <- {r[0]}", r[1])
            o = self.ptr_taint(src, seen)
            return (f"{origin} <- {o}", full) if o else None
        return None

    def _chain_taint(self, v, ch, seen, depth=0):
        """Taint of a stored value AT the call chain the write was lifted through: the storing
        function's parameters are the arguments of that chain's call sites, so a setter called
        with a constant on one object and with input on another taints only the second."""
        if not ch:
            return self.taint(v, seen)
        N = self.N
        k = N.key[v]
        kind = k[0]
        if kind == "arg":
            rec = ch[0]
            idx = self._param_index(k[3]) if k[2] == rec["dst"] else None
            if idx is not None and idx < len(rec["args"]):
                return self._chain_taint(rec["args"][idx], ch[1:], seen, depth + 1)
            return self.taint(v, seen)
        if depth > 20:
            return self.taint(v, seen)
        if kind in ("op", "sel"):
            xs = (k[3], k[4]) if kind == "sel" else [x for x in k[3:] if isinstance(x, int)]
            for x in xs:
                if N.key[x][0] != "c":
                    o = self._chain_taint(x, ch, seen, depth + 1)
                    if o:
                        return o
            return None
        if kind == "phi":
            mark = ("ct", v, len(ch))
            if mark in seen:
                return None
            seen.add(mark)
            for x in N.phi_in.get(v, {}).values():
                if x != v:
                    o = self._chain_taint(x, ch, seen, depth + 1)
                    if o:
                        return o
            return None
        return self.taint(v, seen)

    def _chain_const(self, v, ch, depth=0):
        """The stored value as a constant at this call chain, else None."""
        N = self.N
        c = N.cval(v)
        if c is not None or not ch or depth > 8:
            return c
        k = N.key[v]
        if k[0] == "arg":
            rec = ch[0]
            idx = self._param_index(k[3]) if k[2] == rec["dst"] else None
            if idx is None or idx >= len(rec["args"]):
                return None
            r = self._chain_const(rec["args"][idx], ch[1:], depth + 1)
            return None if r is None else r & _mask(k[1])
        if k[0] == "op" and k[2] in ("INT_ZEXT", "INT_SEXT", "SUBPIECE", "INT_AND", "INT_OR",
                                      "INT_ADD", "INT_MULT", "INT_LEFT", "INT_RIGHT"):
            a = self._chain_const(k[3], ch, depth + 1)
            b = self._chain_const(k[4], ch, depth + 1) if len(k) > 4 else None
            if a is None or (len(k) > 4 and b is None):
                return None
            if k[2] == "SUBPIECE":
                return (a >> (8 * b)) & _mask(k[1])
            return _fold(k[2], a, b, N.size(k[3]), N.size(k[4]) if len(k) > 4 else 0, k[1])
        return None

    def _chain_range(self, v, ch):
        """When the stored value IS a parameter, its range at the chain's call site."""
        if not ch:
            return None
        N = self.N
        k = N.key[_strip(N, v)]
        rec = ch[0]
        if k[0] != "arg" or k[2] != rec["dst"]:
            return None
        idx = self._param_index(k[3])
        if idx is None or idx >= len(rec["args"]):
            return None
        a = rec["args"][idx]
        r = self.rng(a, (rec["func"], rec["block"], ()), True)
        rr = self._chain_range(a, ch[1:])
        if rr is not None and r[0] >= 0 and max(r[0], rr[0]) <= min(r[1], rr[1]):
            r = (max(r[0], rr[0]), min(r[1], rr[1]))
        return r if r[0] >= 0 else None

    # field guards ------------------------------------------------------------------------
    def _value_conds(self, F):
        """Comparisons F computes as VALUES (returned, passed, stored, or a cmov/csel select's
        condition) -- a validator's `return n <= MAX` has no branch of its own."""
        if F._vconds is not None:
            return F._vconds
        N = self.N
        roots = list(F.rets.values()) + [a for r in F.calls.values() for a in r["args"]] + \
            [k[3] for k in F.stores]
        out, seen, todo = set(), set(), list(roots)
        while todo and len(seen) < 6000:
            x = todo.pop()
            if x in seen:
                continue
            seen.add(x)
            k = N.key[x]
            if k[0] == "sel":
                out.add(k[2])
                todo.extend((k[3], k[4]))
            elif k[0] == "op":
                if k[2] in _CMP and k[1] == 1:
                    out.add(x)
                todo.extend(v for v in k[3:] if isinstance(v, int))
            elif k[0] == "phi" and k[2] == F.addr:
                todo.extend(N.phi_in.get(x, {}).values())   # a value merged from its paths
        F._vconds = out
        return out

    def _outcomes(self, F, blk):
        """The outcomes of block blk's branch that can lead on into the function's work. When one
        successor is an early exit (a handful of blocks of its own, while the other carries on
        through many) only the other outcome is a guard; otherwise both are possible."""
        memo = F._outc
        r = memo.get(blk)
        if r is not None:
            return r
        r = (True, False)
        c = F.cond.get(blk)
        succ = F.succ.get(blk, [])
        if c is not None and len(set(succ)) == 2 and c[1] in succ:
            taken = c[1]
            fall = [x for x in succ if x != taken][0]
            rt = self._reach_from(F, taken, blk)
            rf = self._reach_from(F, fall, blk)
            ut, uf = rt - rf, rf - rt
            if len(ut) <= 4 and len(uf) >= 8:
                r = (False,)                       # the taken side bails out
            elif len(uf) <= 4 and len(ut) >= 8:
                r = (True,)
        memo[blk] = r
        return r

    @staticmethod
    def _reach_from(F, start, avoid, cap=600):
        seen, todo = set(), [start]
        while todo and len(seen) < cap:
            x = todo.pop()
            if x in seen or x == avoid:
                continue
            seen.add(x)
            todo.extend(F.succ.get(x, ()))
        return seen

    def _cmp_index(self):
        """Every load a comparison reads (a branch condition, or a comparison used as a value),
        filed under each location it may read: loc -> [(function, condition, load, block)]."""
        if self._cidx is not None:
            return self._cidx
        N = self.N
        idx: dict = defaultdict(list)
        for f, F in self.funcs.items():
            conds = [(blk, cond) for blk, (cond, _t) in F.cond.items()] + \
                [(None, c) for c in self._value_conds(F)]
            for blk, cond in conds:
                for s in _subnodes(N, (cond,), 200):
                    ks = N.key[s]
                    if ks[0] != "ld":
                        continue
                    p = self._ptr_path(ks[2])
                    if p is None:
                        continue
                    for loc, _ch in self._levels(p)[0]:
                        idx[loc].append((f, cond, s, blk))
        self._cidx = idx
        return idx

    def _field_guarded(self, n, q):
        """Apply every comparison the program makes on this field's value -- a load of the field
        anywhere, or the value where it is stored (and up the setter's call chain). Whether a
        check in ANOTHER function precedes the allocation is unknown, so a check is assumed to
        hold on the outcome(s) that carry on (see _outcomes): a constant upper bound caps the
        range, and a bound the analysis cannot apply exactly (a run-time value, an expression
        over the field) clears the field. Zero / sign checks (`x == 0`, `x <= 0`, `x < 0`) bound
        nothing and are ignored, as are loop counters compared with the field."""
        origin, (lo, hi), vals, lv = q
        N = self.N
        size = N.size(n)
        groups: dict = {}

        def add(func, cond, blk, exact, leaves=()):
            g = groups.setdefault((func, cond), (set(), set(), blk))
            g[0].update(exact)
            g[1].update(leaves)

        # (A) checks on a load of the field that run BEFORE this load: exact dominating
        # branches here and in the callers before their call; anything inside the callees that
        # those dominating call sites invoke (a validator)
        locs = {loc for loc, _ch in lv}
        exact_atoms, before = self._checks_before(n)
        for atom in exact_atoms:
            ms = {x for x in _subnodes(N, (atom[0], atom[2]), 120)
                  if N.key[x][0] == "ld" and self.field_locs(x) & locs}
            if ms:
                e = self._check_effect(atom, ms, set())
                if e == "opaque":
                    self.fstats["cleared_by_check"] += 1
                    return None
                if e is not None:
                    lo, hi = _apply_signed(lo, hi, "le", e[1], size) if e[2] else \
                        _apply_unsigned(lo, hi, "le", e[1])
                    if lo > hi:
                        return None
        cidx = self._cmp_index()
        for loc in locs:
            for (f, cond, m, blk) in cidx.get(loc, ()):
                if before is None or f in before:
                    add(f, cond, blk, (m,))
        # (B) checks on the stored value where it is stored (they run before any later load)
        for (ent, ch) in vals:
            func, v, chain = ent[1], ent[3], ch
            for _ in range(_LIFT_DEPTH + 1):
                s = _strip(N, v)
                exact = {v, s}
                leaves = {t for t in _subnodes(N, (v,), 60)
                          if N.key[t][0] in ("srcld", "ld", "arg", "ret", "out", "phi")} - exact
                mine = exact | leaves
                F = self.funcs.get(func)
                if F is not None:
                    conds = [(blk, cond) for blk, (cond, _t) in F.cond.items()] + \
                        [(None, c) for c in self._value_conds(F)]
                    for blk, cond in conds:
                        if _subnodes(N, (cond,), 200) & mine:
                            add(func, cond, blk, exact, leaves)
                ks = N.key[s]
                if not chain or ks[0] != "arg" or ks[2] != chain[0]["dst"]:
                    break
                idx = self._param_index(ks[3])
                if idx is None or idx >= len(chain[0]["args"]):
                    break
                v, func, chain = chain[0]["args"][idx], chain[0]["func"], chain[1:]
        for (f, cond), (exact, leaves, blk) in groups.items():
            F = self.funcs.get(f)
            outs = self._outcomes(F, blk) if (F is not None and blk is not None) else (True, False)
            for pos in outs:
                for atom in self.atoms(cond, pos):
                    e = self._check_effect(atom, exact, leaves - exact)
                    if e is None:
                        continue
                    if e == "opaque":
                        self.fstats["cleared_by_check"] += 1
                        return None
                    _c, U, sg = e
                    lo, hi = _apply_signed(lo, hi, "le", U, size) if sg else \
                        _apply_unsigned(lo, hi, "le", U)
                    if lo > hi:
                        return None
        self.fstats["facts"] += 1
        k = N.key[n]
        at = self._fwhere.get((self._ptr_path(k[2]), k[1])) or lv[0][0]
        return (f"{origin} (stored to {self._loc_text(at)})", (lo, hi))

    def _checks_before(self, n):
        """For load node n: (atoms that hold where it is read -- its function's dominating
        branches and, up to three caller levels, the callers' branches dominating the call --,
        the set of functions invoked at call sites dominating those points, transitively; None
        when that set ran past its budget, meaning: any function)."""
        atoms, roots = [], set()
        todo = [(f, b, _hexint(w), 0) for (f, b, w) in self._ldat.get(n, ())]
        seen = set()
        callers = self._callers()
        while todo:
            f, b, ref, d = todo.pop()
            if (f, b, ref) in seen or len(seen) > 64:
                continue
            seen.add((f, b, ref))
            F = self.funcs.get(f)
            if F is None or b is None:
                continue
            atoms.extend(self.ctx_atoms((f, b, ())))
            doms = set(F.dom_chain(b))
            for rec in F.calls.values():
                if not (rec["internal"] and rec["dst"] in self.funcs):
                    continue
                # a dominating block's calls, or this block's calls made before the point
                if rec["block"] in doms or (rec["block"] == b and (
                        ref is None or (_hexint(rec["site"]) or 0) < ref)):
                    roots.add(rec["dst"])
            if d < 3:
                for rec in callers.get(f, ()):
                    todo.append((rec["func"], rec["block"], _hexint(rec["site"]), d + 1))
        before, todo = set(), list(roots)
        while todo:
            g = todo.pop()
            if g in before:
                continue
            before.add(g)
            if len(before) > 400:
                return atoms, None
            todo.extend(self.cg.get(g, ()))
        return atoms, before

    def _check_effect(self, atom, exact, leaves):
        """What one outcome of a comparison implies for the field: None, ("cap", U, signed), or
        "opaque" (a bound that cannot be applied exactly)."""
        N = self.N
        lhs, rel, rhs, signed = atom
        sl, sr = _subnodes(N, (lhs,), 120), _subnodes(N, (rhs,), 120)
        mine = exact | leaves
        if not ((sl | sr) & mine):
            return None
        cl, cr = N.cval(lhs), N.cval(rhs)
        if cl is not None or cr is not None:
            for (tgt, rl, K, sg) in self._peel(lhs, rel, rhs, signed):
                if tgt in mine:
                    U = _upper(rl, K)
                    if U is None or U <= 0:
                        return None                # a lower bound, or a zero / sign check
                    return ("cap", U, sg) if tgt in exact else "opaque"
            e_rel, K, ks = (rel, cr, N.size(rhs)) if cr is not None else (_FLIP[rel], cl,
                                                                           N.size(lhs))
            U = _upper(e_rel, _signed(K, ks) if signed else K)
            return "opaque" if U is not None and U > 0 else None
        fl, fr = bool(sl & mine), bool(sr & mine)
        if fl and fr:
            return "opaque"
        rl = rel if fl else _FLIP[rel]
        if rl not in ("lt", "le", "eq"):
            return None                            # the field is bounded BELOW by it
        if any(self._is_induction(s) for s in (sr if fl else sl)):
            return None                            # a loop counter compared with the field
        return "opaque"

    def _loc_text(self, loc):
        root, offs = loc
        tail = "".join(f"->{o:#x}" if i else f"+{o:#x}" for i, o in enumerate(offs))
        if root[0] == "g":
            return f"global {offs[0]:#x}" + "".join(f"->{o:#x}" for o in offs[1:])
        if root[0] == "h":
            return f"heap@{root[1]}{tail}"
        if root[0] == "s":
            return f"stack of {self.names.get(root[1], root[1])}{tail}"
        return f"*param{root[2]} of {self.names.get(root[1], root[1])}{tail}"

    def field_locs(self, n):
        """Every location load node `n` may read (empty for a non-load or an unplaced one)."""
        k = self.N.key[n]
        if k[0] != "ld":
            return frozenset()
        p = self._ptr_path(k[2])
        return frozenset(loc for loc, _ch in self._levels(p)[0]) if p is not None else frozenset()

    # ------------------------------------------------------------------------------ ranges
    def full(self, n):
        return (0, _mask(self.N.size(n)))

    def rng(self, n, ctx, attacker=False):
        """Value range (mathematical) of node `n` under the predicates holding in `ctx`.

        `attacker`: an untainted non-constant leaf counts as [0, 1] -- the attacker cannot drive
        it, so it must never be what makes a wrap reportable."""
        key = (n, ctx, attacker)
        r = self._memo_rng.get(key)
        if r is not None:
            return r
        if key in self._visiting or len(self._visiting) > 250:
            return self.full(n)
        self._visiting.add(key)
        try:
            r = self._refine(n, self._rng(n, ctx, attacker), ctx, attacker)
        finally:
            self._visiting.discard(key)
        self._memo_rng[key] = r
        return r

    def _leaf_range(self, n, k, attacker):
        kind = k[0]
        full = (0, _mask(k[1]))
        if kind == "c":
            return (k[2], k[2])
        if kind == "sp":
            return full
        tainted = self.taint(n)
        if attacker and not tainted:
            return (0, 1)
        if kind == "arg":
            idx = self._param_index(k[3])
            r = self.p_range.get((k[2], idx)) if idx is not None else None
            if r is not None and tainted and r[1] <= full[1] and r[0] >= -(full[1] >> 1):
                return r
            return full
        if kind == "ret":
            callee = k[3]
            if callee in self.funcs:
                r = self._ret_range(callee)
                return r if (r is not None and r[1] <= full[1] and r[0] >= 0) else full
            vs = _VALUE_SOURCES.get(callee)
            if vs:
                return vs
            if callee in _LENGTHS:
                return (0, (1 << (8 * self.word - 1)) - 1)
            if callee in _PASS_THROUGH:
                return (0, min(_PASS_THROUGH[callee], full[1]))
            return full
        if kind == "out":
            rec = self.call_rec.get(k[2])
            F = self.funcs.get(rec["dst"]) if rec else None
            vals = F.outs.get((k[3], k[4], k[1]), ()) if F else ()
            lo = hi = None
            for v in vals:
                blk = None
                r = self.rng(v, (F.addr, blk, ()), False)
                lo = r[0] if lo is None else min(lo, r[0])
                hi = r[1] if hi is None else max(hi, r[1])
            if lo is not None and lo >= 0 and hi <= full[1]:
                return (lo, hi)
            return full
        if kind == "srcld":
            return full
        if kind == "ld" and tainted and n not in self._raw_ld:
            ff = self._field(n)
            if ff is not None:
                lo, hi = ff[1]
                if hi <= full[1] and lo >= -(full[1] >> 1) - 1:
                    return (lo, hi)
        return full

    def _edge_ctx(self, f, p, b):
        """The context of a value flowing along the CFG edge p -> b: p's dominating predicates
        plus p's own branch condition on that edge (the `if (n > K) n = K;` clamp)."""
        if p == "<entry>":
            return (f, None, ())
        F = self.funcs.get(f)
        c = F.cond.get(p) if F is not None else None
        if c is not None:
            succ = set(F.succ.get(p, []))
            if len(succ) == 2 and b in succ:
                return (f, p, ((c[0], c[1] == b),))
        return (f, p, ())

    def _ret_range(self, callee):
        r = self._memo_rr.get(callee)
        if r is not None:
            return r
        self._memo_rr[callee] = (0, _mask(self.word))       # recursion guard
        F = self.funcs[callee]
        lo = hi = None
        for (blk, _site), v in F.rets.items():
            rr = self.rng(v, (callee, blk, ()), False)
            lo = rr[0] if lo is None else min(lo, rr[0])
            hi = rr[1] if hi is None else max(hi, rr[1])
        r = (lo, hi) if lo is not None else (0, _mask(self.word))
        self._memo_rr[callee] = r
        return r

    def _rng(self, n, ctx, attacker):
        N = self.N
        k = N.key[n]
        kind = k[0]
        size = k[1]
        full = (0, _mask(size))
        if kind not in ("op", "sel", "phi"):
            return self._leaf_range(n, k, attacker)
        if kind == "phi":
            lo = hi = None
            for p, x in N.phi_in.get(n, {}).items():
                if x == n:
                    continue
                r = self.rng(x, self._edge_ctx(k[2], p, k[3]), attacker)
                lo = r[0] if lo is None else min(lo, r[0])
                hi = r[1] if hi is None else max(hi, r[1])
            return (lo, hi) if lo is not None else full
        if kind == "sel":
            f, blk, extra = ctx
            ra = self.rng(k[3], (f, blk, extra + ((k[2], True),)), attacker)
            rb = self.rng(k[4], (f, blk, extra + ((k[2], False),)), attacker)
            return (min(ra[0], rb[0]), max(ra[1], rb[1]))
        m = k[2]
        if m in _BOOL_OUT:
            return (0, 1)
        x = k[3]
        y = k[4] if len(k) > 4 else None
        rx = self.rng(x, ctx, attacker)
        ry = self.rng(y, ctx, attacker) if y is not None else None
        r = _arith_range(N, m, size, x, y, rx, ry)
        return self._fit(r, size) if r is not None else full

    @staticmethod
    def _fit(r, size):
        W = 8 * size
        lo, hi = r
        if lo >= 0 and hi < (1 << W):
            return r
        if -(1 << (W - 1)) <= lo < 0 and hi < (1 << (W - 1)):
            return r
        return (0, _mask(size))

    # -------------------------------------------------------------------------- predicates
    def atoms(self, cond, positive, depth=0):
        """Atomic predicates (lhs, rel, rhs, signed) that hold when `cond` == positive."""
        N = self.N
        k = N.key[cond]
        if k[0] == "c":
            return []
        if depth > 6 or k[0] != "op":
            return [(cond, "ne" if positive else "eq", N.const(0, k[1]), False)]
        m = k[2]
        if m == "BOOL_NEGATE":
            return self.atoms(k[3], not positive, depth + 1)
        if m == "BOOL_AND":
            return (self.atoms(k[3], True, depth + 1) + self.atoms(k[4], True, depth + 1)) \
                if positive else []
        if m == "BOOL_OR":
            return (self.atoms(k[3], False, depth + 1) + self.atoms(k[4], False, depth + 1)) \
                if not positive else []
        if m in _RELS:
            p, q, s = _RELS[m]
            return [(k[3], p if positive else q, k[4], s)]
        return [(cond, "ne" if positive else "eq", N.const(0, k[1]), False)]

    def ctx_atoms(self, ctx):
        f, blk, extra = ctx
        F = self.funcs.get(f)
        out = []
        if F is not None and blk is not None:
            got = F._atoms.get(blk)
            if got is None:
                F._atoms[blk] = []                       # recursion guard
                got = self._block_atoms(F, blk)
                F._atoms[blk] = got
            out.extend(got)
        for cond, pos in extra:
            out.extend(self.atoms(cond, pos))
        return out

    def _edge_atoms(self, F, p, b, depth):
        """Predicates holding on the CFG edge p -> b."""
        out = list(self._block_atoms(F, p, depth + 1)) if depth < 2 else []
        c = F.cond.get(p)
        if c is not None:
            cond, taken = c
            succ = set(F.succ.get(p, []))
            if len(succ) == 2 and b in succ:
                out.extend(self.atoms(cond, taken == b))
        return out

    def _block_atoms(self, F, S, depth=0):
        if depth == 0 and S in F._atoms and F._atoms[S]:
            return F._atoms[S]
        out = []
        for D in F.dom_chain(S):
            c = F.cond.get(D)
            if c is None:
                continue
            cond, taken = c
            succ = F.succ.get(D, [])
            others = [x for x in succ if x != taken]
            if taken not in F.by or not others or len(set(succ)) < 2:
                continue
            fall = others[0]
            rt, seen_t = (True, {S}) if taken == S else F.reach_avoid(taken, S, D)
            rf, seen_f = (True, {S}) if fall == S else F.reach_avoid(fall, S, D)
            if rt and not rf:
                pos, between = True, seen_t
            elif rf and not rt:
                pos, between = False, seen_f
            else:
                continue
            for at in self.atoms(cond, pos):
                if not self._phi_stale(at, between, D):
                    out.append(at)
                    out.extend(self._phi_implied(F, at, depth))
        return out

    def _phi_implied(self, F, atom, depth):
        """`phi == K` where only one incoming value can equal K: whatever held on that incoming
        edge holds here too (the -O0 shape of __builtin_mul_overflow: a 0/1 flag merged at a
        join, then tested)."""
        N = self.N
        lhs, rel, rhs, _s = atom
        if rel not in ("eq", "ne") or depth > 1:
            return []
        K = N.cval(rhs)
        if K is None:
            return []
        phis = [s for s in _subnodes(N, (lhs,), 40)
                if N.key[s][0] == "phi" and N.key[s][2] == F.addr]
        if len(phis) != 1:
            return []
        tgt = phis[0]
        ok = []
        for p, x in N.phi_in.get(tgt, {}).items():
            c = N.cval(x)
            v = _eval_with(N, lhs, tgt, c) if c is not None else None
            if v is None or (v == K) == (rel == "eq"):
                ok.append(p)              # this incoming value can make the test come out so
        if len(ok) != 1 or ok[0] == "<entry>":
            return []
        return self._edge_atoms(F, ok[0], N.key[tgt][3], depth)

    def _phi_stale(self, atom, between, D):
        """A predicate on a phi of a block re-entered between the check and the use describes an
        older value of that phi."""
        N = self.N
        for side in (atom[0], atom[2]):
            todo, n = [side], 0
            while todo and n < 40:
                x = todo.pop()
                n += 1
                k = N.key[x]
                if k[0] == "phi" and k[3] != D and k[3] in between:
                    return True
                if k[0] in ("op", "sel"):
                    todo.extend(v for v in k[3:] if isinstance(v, int))
        return False

    def _refine(self, n, r, ctx, attacker):
        N = self.N
        if N.key[n][0] == "c":
            return r
        atoms = self.ctx_atoms(ctx)
        if not atoms:
            return r
        size = N.size(n)
        lo, hi = r
        for (lhs, rel, rhs, signed) in atoms:
            for (tgt, rl, K, sg) in self._peel(lhs, rel, rhs, signed):
                if tgt != n:
                    continue
                if sg:
                    lo, hi = _apply_signed(lo, hi, rl, K, size)
                else:
                    lo, hi = _apply_unsigned(lo, hi, rl, K)
            if N.cval(rhs) is None and N.cval(lhs) is None and (lhs == n or rhs == n):
                # a relational bound: x <= y caps x at y's upper end
                other = rhs if lhs == n else lhs
                rl = rel if lhs == n else _FLIP[rel]
                if rl in ("lt", "le", "eq") and not self._is_induction(other):
                    ro = self.rng(other, ctx, False)
                    if ro[0] >= 0 and (signed is not True or lo >= 0):
                        hi = min(hi, ro[1] - (1 if rl == "lt" else 0))
        if lo > hi:
            return r
        return (lo, hi)

    def _peel(self, lhs, rel, rhs, signed):
        """An atom against a constant, as constraints (node, rel, K, signed) on lhs AND on the
        values lhs is an exact function of: its zero/sign extension, x >> k, x & high-mask."""
        N = self.N
        cl, cr = N.cval(lhs), N.cval(rhs)
        if cl is not None and cr is None:
            lhs, rhs, rel, cl, cr = rhs, lhs, _FLIP[rel], cr, cl
        if cr is None or cl is not None:
            return []
        K = _signed(cr, N.size(rhs)) if signed else cr
        out = []
        x, sg = lhs, bool(signed)
        for _ in range(6):
            out.append((x, rel, K, sg))
            k = N.key[x]
            if k[0] != "op":
                break
            m = k[2]
            if m == "INT_ZEXT":
                inner = k[3]
                if (sg and K < 0) or K > _mask(N.size(inner)):
                    break
                x, sg = inner, False
                continue
            if m == "INT_SEXT" and sg:
                inner = k[3]
                half = 1 << (8 * N.size(inner) - 1)
                if not -half <= K < half:
                    break
                x = inner
                continue
            if m == "INT_RIGHT" and not sg and N.cval(k[4]) is not None and K >= 0:
                s = N.cval(k[4])
                x = k[3]
                if rel == "eq" and K == 0:
                    rel, K = "lt", 1 << s
                elif rel == "lt":
                    K = K << s
                elif rel == "le":
                    K = ((K + 1) << s) - 1
                elif rel == "gt":
                    rel, K = "ge", (K + 1) << s
                elif rel == "ge":
                    K = K << s
                else:
                    break
                continue
            if m == "INT_AND" and not sg and rel == "eq" and K == 0 and N.cval(k[4]) is not None:
                low = (~N.cval(k[4])) & _mask(N.size(x))
                if low & (low + 1) == 0:               # the mask is "every bit above k"
                    x, rel, K = k[3], "le", low
                    continue
            break
        return out

    def _is_induction(self, n, depth=0):
        """A loop-carried value: a phi one of whose inputs is computed from itself."""
        N = self.N
        k = N.key[n]
        if k[0] != "phi":
            if depth < 2 and k[0] in ("op", "sel"):
                return any(isinstance(v, int) and self._is_induction(v, depth + 1)
                           for v in k[3:5])
            return False
        for x in N.phi_in.get(n, {}).values():
            todo, seen = [x], 0
            while todo and seen < 30:
                y = todo.pop()
                seen += 1
                if y == n:
                    return True
                ky = N.key[y]
                if ky[0] in ("op", "sel"):
                    todo.extend(v for v in ky[3:] if isinstance(v, int))
        return False


def _apply_unsigned(lo, hi, rel, K):
    if rel == "lt":
        return max(lo, 0), min(hi, K - 1) if lo >= 0 else K - 1
    if rel == "le":
        return max(lo, 0), min(hi, K) if lo >= 0 else K
    if rel == "eq":
        return (K, K)
    if rel == "gt" and lo >= 0:
        return max(lo, K + 1), hi
    if rel == "ge" and lo >= 0:
        return max(lo, K), hi
    return lo, hi


def _apply_signed(lo, hi, rel, K, size):
    half = 1 << (8 * size - 1)
    if lo >= 0 and hi >= half:            # the signed view of an unsigned range
        slo, shi = (lo - 2 * half, hi - 2 * half) if lo >= half else (-half, half - 1)
    else:
        slo, shi = lo, hi
    if rel == "lt":
        shi = min(shi, K - 1)
    elif rel == "le":
        shi = min(shi, K)
    elif rel == "gt":
        slo = max(slo, K + 1)
    elif rel == "ge":
        slo = max(slo, K)
    elif rel == "eq":
        slo, shi = max(slo, K), min(shi, K)
    if slo > shi:
        return lo, hi
    return slo, shi


def _arith_range(N, m, size, x, y, rx, ry):
    """The mathematical (un-wrapped) range of `x m y`, or None for "full width"."""
    W = 8 * size
    if m == "INT_ZEXT":
        return rx if rx[0] >= 0 else (0, _mask(N.size(x)))
    if m == "INT_SEXT":
        half = 1 << (8 * N.size(x) - 1)
        if rx[0] < 0 or rx[1] < half:
            return rx
        if rx[0] >= half:
            return (rx[0] - 2 * half, rx[1] - 2 * half)
        return (-half, half - 1)
    if m == "SUBPIECE":
        off = N.cval(y) or 0
        if rx[0] >= 0 and (rx[1] >> (8 * off)) <= _mask(size):
            return (rx[0] >> (8 * off), rx[1] >> (8 * off))
        return None
    if m == "INT_ADD":
        # `x - c` reaches here as `x + (-c mod 2^W)` (the builder's canonical form): a constant
        # with the top bit set is a subtraction, not a 2^W-sized addend
        for v, rv, other in ((y, ry, rx), (x, rx, ry)):
            c = N.cval(v)
            if c is not None and c >= (1 << (W - 1)):
                neg = c - (1 << W)
                lo, hi = other[0] + neg, other[1] + neg
                if lo < 0 <= other[0]:
                    # an unsigned underflow is a different defect (CWE-191), not a wrap past 2^W
                    return (0, other[1]) if hi >= 0 else None
                return (lo, hi)
        return (rx[0] + ry[0], rx[1] + ry[1])
    if m == "INT_SUB":
        lo, hi = rx[0] - ry[1], rx[1] - ry[0]
        if lo < 0 <= rx[0] and ry[0] >= 0:
            # an unsigned underflow is a different defect (CWE-191); the minuend bounds the rest
            return (0, rx[1]) if hi >= 0 else None
        return (lo, hi)
    if m == "INT_MULT":
        ps = (rx[0] * ry[0], rx[0] * ry[1], rx[1] * ry[0], rx[1] * ry[1])
        return (min(ps), max(ps))
    if m == "INT_LEFT":
        c = N.cval(y)
        if c is None or c >= W:
            return None
        return (rx[0] << c, rx[1] << c)
    if m == "INT_RIGHT":
        c = N.cval(y)
        if rx[0] < 0:
            rx = (0, _mask(N.size(x)))
        return (0, rx[1]) if c is None else (rx[0] >> c, rx[1] >> c)
    if m == "INT_SRIGHT":
        c = N.cval(y)
        if c is not None and rx[0] >= 0 and rx[1] < (1 << (W - 1)):
            return (rx[0] >> c, rx[1] >> c)
        return None
    if m == "INT_AND":
        his = [r[1] for r in (rx, ry) if r[0] >= 0]
        return (0, min(his)) if his else None
    if m in ("INT_OR", "INT_XOR"):
        if rx[0] < 0 or ry[0] < 0:
            return None
        return (0, (1 << max(rx[1].bit_length(), ry[1].bit_length())) - 1)
    if m == "INT_DIV":
        if rx[0] < 0 or ry[0] < 0:
            return None
        return (rx[0] // max(ry[1], 1), rx[1] // max(ry[0], 1))
    if m == "INT_REM":
        return (0, ry[1] - 1) if ry[0] >= 0 and ry[1] > 0 else None
    if m in ("POPCOUNT", "LZCOUNT"):
        return (0, 8 * N.size(x))
    return None


def _strip(N, n):
    """Remove value-preserving wrappers (zero/sign extension, low-part truncation)."""
    for _ in range(8):
        k = N.key[n]
        if k[0] == "op" and k[2] in ("INT_ZEXT", "INT_SEXT"):
            n = k[3]
            continue
        if k[0] == "op" and k[2] == "SUBPIECE" and N.cval(k[4]) == 0:
            n = k[3]
            continue
        break
    return n


# ----------------------------------------------------------------------------- detection
def _subnodes(N, roots, limit=300):
    out, todo = set(), list(roots)
    while todo and len(out) < limit:
        x = todo.pop()
        if x in out:
            continue
        out.add(x)
        k = N.key[x]
        if k[0] in ("op", "sel"):
            todo.extend(v for v in k[3:] if isinstance(v, int))
    return out


def _pretty(P, n, depth=0):
    """A short C-like rendering of a value node, for the record's `reason`/operands."""
    N = P.N
    k = N.key[n]
    kind = k[0]
    if depth > 4:
        return "..."
    if kind == "c":
        return hex(k[2]) if k[2] > 9 else str(k[2])
    if kind == "srcld":
        org = k[2] if isinstance(k[2], str) else k[2][2]
        return f"in[{org}+{k[3]:#x}]:u{8 * k[1]}"
    if kind == "arg":
        idx = P._param_index(k[3])
        return f"param{idx if idx is not None else k[3]}:u{8 * k[1]}"
    if kind == "ret":
        return f"{k[3] if isinstance(k[3], str) else P.names.get(k[3], k[3])}()@{k[2]}"
    if kind == "out":
        return f"*out{k[3]}@{k[2]}:u{8 * k[1]}"
    if kind == "ld":
        return f"*({_pretty(P, k[2], depth + 1)}):u{8 * k[1]}"
    if kind == "sp":
        return f"&stack[{k[2]:#x}]"
    if kind == "stk":
        return f"stack[{k[3]:#x}]:u{8 * k[1]}"
    if kind == "phi":
        return f"phi@{k[3]}"
    if kind == "sel":
        return f"select({_pretty(P, k[3], depth + 1)}, {_pretty(P, k[4], depth + 1)})"
    if kind != "op":
        return kind
    m = k[2]
    sym = {"INT_MULT": "*", "INT_ADD": "+", "INT_SUB": "-", "INT_LEFT": "<<",
           "INT_RIGHT": ">>", "INT_AND": "&", "INT_OR": "|", "INT_XOR": "^", "INT_DIV": "/"}
    if m in sym and len(k) > 4:
        return f"({_pretty(P, k[3], depth + 1)} {sym[m]} {_pretty(P, k[4], depth + 1)})" \
               f":{8 * k[1]}"
    if m in ("INT_ZEXT", "INT_SEXT"):
        return f"{'zext' if m == 'INT_ZEXT' else 'sext'}{8 * k[1]}({_pretty(P, k[3], depth + 1)})"
    if m == "SUBPIECE":
        return f"trunc{8 * k[1]}({_pretty(P, k[3], depth + 1)})"
    return f"{m.lower()}(...)"


class _Detector:
    def __init__(self, P: _Program):
        self.P = P
        self.N = P.N
        self._mults = None

    def find_wraps(self, n, ctx, out, seen, depth=0, demand=None):
        """Every arithmetic node in the size expression whose mathematical range exceeds the width
        it is consumed at, with an attacker-tainted operand.

        `demand` is the mask of result bits the consumer keeps (an AND with a constant, a
        truncation). `x << c` under a mask whose low c bits are clear -- aarch64 ubfiz/sbfiz,
        `(x & 0xffffffff) << 4` -- only ever uses `x & (mask >> c)`: the bits it shifts out were
        never part of the value, so it cannot wrap. A mask with low bits set is a truncation
        AFTER the arithmetic, and the wrap is checked at the mask's width."""
        P, N = self.P, self.N
        if depth > 14 or (n, ctx, demand) in seen or len(seen) > 600:
            return
        seen.add((n, ctx, demand))
        k = N.key[n]
        kind = k[0]
        if kind == "sel":
            f, b, ex = ctx
            self.find_wraps(k[3], (f, b, ex + ((k[2], True),)), out, seen, depth + 1, demand)
            self.find_wraps(k[4], (f, b, ex + ((k[2], False),)), out, seen, depth + 1, demand)
            return
        if kind == "phi":
            for p, x in N.phi_in.get(n, {}).items():
                # a loop-carried input is the value's own recurrence (`v = (v << 8) | byte`, a
                # running total): its arithmetic is not the size computation at this site
                if p != "<entry>" and x != n and not _depends_on(N, x, n):
                    self.find_wraps(x, P._edge_ctx(k[2], p, k[3]), out, seen, depth + 1, demand)
            return
        if kind != "op":
            return
        m = k[2]
        size = k[1]
        dm = _mask(size) if demand is None else demand & _mask(size)
        child_demand = {}                         # operand node -> demand mask for it
        if m in _ARITH and len(k) > 4:
            x, y = k[3], k[4]
            shift = N.cval(y) if m == "INT_LEFT" else None
            if m == "INT_MULT" and N.cval(y) is not None and N.cval(y) & (N.cval(y) - 1) == 0:
                shift = N.cval(y).bit_length() - 1
            aligned = shift is not None and shift > 0 and dm & ((1 << shift) - 1) == 0
            tx, ty = P.taint(x), P.taint(y)
            if tx or ty:
                rx = P.rng(x, ctx, attacker=True)
                ry = P.rng(y, ctx, attacker=True)
                if aligned:
                    cap = dm >> shift
                    rx = (min(rx[0], cap) if rx[0] >= 0 else 0, min(rx[1], cap))
                    child_demand[x] = cap
                math = _arith_range(N, m, size, x, y, rx, ry)
                W = min(8 * size, dm.bit_length())
                if math is not None and math[1] >= (1 << W) and \
                        (m != "INT_LEFT" or N.cval(y) is not None):
                    out.append({"node": n, "ctx": ctx, "op": m, "width": W, "x": x, "y": y,
                                "rx": rx, "ry": ry, "max": math[1], "tx": tx, "ty": ty})
            elif aligned:
                child_demand[x] = dm >> shift
        if m in _BOOL_OUT:
            return
        nd = None
        if m == "INT_AND" and N.cval(k[4]) is not None:
            nd = dm & N.cval(k[4])
        elif m in ("INT_OR", "INT_XOR", "INT_ADD", "INT_SUB"):
            nd = (1 << dm.bit_length()) - 1
        elif m == "SUBPIECE" and N.cval(k[4]) == 0:
            nd = _mask(size) & dm
        elif m in ("INT_ZEXT", "INT_SEXT"):
            nd = dm & _mask(N.size(k[3]))
        for v in k[3:]:
            if isinstance(v, int) and N.key[v][0] != "c":
                self.find_wraps(v, ctx, out, seen, depth + 1, child_demand.get(v, nd))

    def guard(self, w):
        """(status, reason) when a guard on this wrap exists, else None."""
        P, N = self.P, self.N
        n, ctx = w["node"], w["ctx"]
        sn = _strip(N, n)
        opnds = {_strip(N, v) for v in (w["x"], w["y"]) if N.cval(v) is None}
        terms = _subnodes(N, (n,), 200)
        leaves = {t for t in terms if N.key[t][0] in ("srcld", "ld", "arg", "ret", "out", "phi")
                  and P.taint(t)}
        wide_ok = self._wide_equivalents(w)
        for (lhs, rel, rhs, signed) in P.ctx_atoms(ctx):
            subs = _subnodes(N, (lhs, rhs))
            # (1) the operation's overflow indication is tested
            for s in subs:
                ks = N.key[s]
                if ks[0] != "op":
                    continue
                if ks[2] in ("INT_CARRY", "INT_SCARRY") and \
                        {_strip(N, ks[3]), _strip(N, ks[4])} & terms and \
                        all(_strip(N, v) in terms or N.cval(v) is not None
                            for v in (ks[3], ks[4])):
                    return ("guarded-overflow-flag", "the operation's carry/overflow flag is "
                            "tested on the path to the allocation")
                if s in wide_ok:
                    return ("guarded-overflow-flag", "the double-width product of the same "
                            "operands (the high half / overflow flag) is tested on the path")
                if ks[2] == "INT_DIV" and _strip(N, ks[4]) in terms and \
                        N.cval(_strip(N, ks[4])) is None:
                    return ("guarded-division", "a division-based overflow check "
                            "(x > MAX / y, or r / y != x) dominates the allocation")
            # (2) the result is checked against one of its operands (a + b < a)
            sl, sr = _strip(N, lhs), _strip(N, rhs)
            if (sl == sn and sr in opnds) or (sr == sn and sl in opnds):
                return ("guarded-result-check", "the result is compared with an operand "
                        "(the wrap check `a + b < a`) on the path")
            # (3) an expression over the same attacker-controlled inputs (an operand, a partial
            # sum, a differently-scaled copy) is bounded from above by a run-time value -- the
            # remaining length, `SIZE_MAX - total`, ... Bounding the wrapped RESULT itself is not
            # this: that check runs on the small wrapped value (a post-wrap check, reported).
            for a_, rl, b_ in ((lhs, rel, rhs), (rhs, _FLIP[rel], lhs)):
                if rl not in ("lt", "le", "eq") or N.cval(b_) is not None or \
                        P._is_induction(b_) or _strip(N, a_) == sn:
                    continue
                if _subnodes(N, (a_,), 120) & leaves and not (_subnodes(N, (b_,), 120) & {sn}):
                    return ("guarded-runtime-bound", "an expression over the operands' inputs "
                            "is bounded above by a run-time value on every path to the "
                            "allocation")
        return None

    def _opkey(self, v):
        """An operand's identity for matching two spellings of one product: the stripped value,
        or the constant's numeric value (so `n * 16:4` and `zext(n) * 16:8` agree)."""
        sv = _strip(self.N, v)
        c = self.N.cval(sv)
        return ("c", c) if c is not None else sv

    def _wide_equivalents(self, w):
        """Double-width products of the same operands -- what imul/mul/umulh flags and
        __builtin_mul_overflow examine."""
        N = self.N
        if w["op"] != "INT_MULT":
            return set()
        if self._mults is None:
            self._mults = defaultdict(list)
            for key, nid in N.idx.items():
                if key[0] == "op" and key[2] == "INT_MULT" and len(key) > 4:
                    self._mults[frozenset((self._opkey(key[3]), self._opkey(key[4])))].append(
                        (nid, key[1]))
        k = frozenset((self._opkey(w["x"]), self._opkey(w["y"])))
        return {nid for nid, size in self._mults.get(k, ()) if size > N.size(w["node"])}

    def post_wrap_check(self, w):
        """A comparison of the (already wrapped) result against something that is not one of
        its operands: it runs on the small wrapped value, so it does not stop the overflow."""
        P, N = self.P, self.N
        sn = _strip(N, w["node"])
        for (lhs, rel, rhs, signed) in P.ctx_atoms(w["ctx"]):
            if sn in (_strip(N, lhs), _strip(N, rhs)) and rel not in ("ne",):
                return f"{_pretty(P, lhs)} {rel} {_pretty(P, rhs)}"
        return None

    def written_after(self, F, alloc, w):
        """A write into the new buffer driven by the UN-wrapped quantity: a copy/read whose length
        is an operand of the wrap, or a write indexed by a loop bounded by an operand."""
        P, N = self.P, self.N
        R = alloc["ret"]
        leaves = {_strip(N, v) for v in (w["x"], w["y"]) if N.cval(v) is None}
        leaves |= self._same_field_loads(F, leaves)
        size_node = alloc["args"][alloc["size_arg"]]
        for rec in F.calls.values():
            spec = _WRITERS.get(rec["name"])
            if spec is None or rec["site"] == alloc["site"]:
                continue
            di, li = spec
            if di >= len(rec["args"]) or not self._derives(rec["args"][di], R):
                continue
            if li is not None and li < len(rec["args"]):
                L = rec["args"][li]
                if _strip(N, L) != _strip(N, size_node) and \
                        _subnodes(N, (L,), 80) & leaves and w["node"] not in _subnodes(N, (L,)):
                    return {"site": rec["site"], "sink": rec["name"],
                            "detail": f"{rec['name']}() writes {_pretty(P, L)} bytes into it"}
            dst = rec["args"][di]
            ctx = (F.addr, rec["block"], ())
            if any(P._is_induction(s) for s in _subnodes(N, (dst,), 60)):
                for (lhs, rel, rhs, _sg) in P.ctx_atoms(ctx):
                    sides = _subnodes(N, (lhs, rhs), 80)
                    if sides & leaves and any(P._is_induction(s) for s in sides):
                        return {"site": rec["site"], "sink": rec["name"],
                                "detail": f"{rec['name']}() writes into it in a loop bounded by "
                                          f"{_pretty(P, lhs)} {rel} {_pretty(P, rhs)}"}
        return None

    def _same_field_loads(self, F, leaves):
        """Loads in F of the same field as a load among `leaves` -- `n = hdr->count` re-read
        after a call is a different load node but the same operand."""
        P, N = self.P, self.N
        locs = set()
        for x in leaves:
            locs |= P.field_locs(x)
        if not locs:
            return set()
        out = set()
        for rec in F.calls.values():
            for a in rec["args"]:
                for s in _subnodes(N, (a,), 80):
                    if N.key[s][0] == "ld" and P.field_locs(s) & locs:
                        out.add(s)
        for _blk, (cond, _t) in F.cond.items():
            for s in _subnodes(N, (cond,), 120):
                if N.key[s][0] == "ld" and P.field_locs(s) & locs:
                    out.add(s)
        return out

    def _derives(self, p, R, depth=0):
        N = self.N
        if p == R:
            return True
        if depth > 4:
            return False
        k = N.key[p]
        if k[0] == "op" and k[2] == "INT_ADD":
            return self._derives(k[3], R, depth + 1) or self._derives(k[4], R, depth + 1)
        if k[0] == "phi":
            return any(self._derives(x, R, depth + 1) for x in N.phi_in.get(p, {}).values()
                       if x != p)
        return False


def alloc_overflow_sites(func_irs, call_edges, arch, *, bits=64, names=None, entry_seeds=None,
                         include_suppressed=False, stats_out=None, should_stop=None) -> list:
    """Allocation-size integer overflows, one record per allocation SITE.

    func_irs     {function addr: ir dict}  -- FunctionDAO `ir` (blocks/instructions/pcode)
    call_edges   CallEdge rows (src_addr, site_addr, dst_addr, dst_name, external)
    arch, bits   the target's architecture / pointer width
    names        {function addr: name} -- names main (argv seeding) and PLT thunks for tail calls
    entry_seeds  {function addr: {param idx}} -- extra attacker-controlled parameters (a library's
                 exported API), as value AND pointee taint
    include_suppressed  also return the sites the guard analysis cleared, with their reason
    stats_out    dict filled with counts (functions, skipped, allocation sites, by status)
    should_stop  a cancel check, polled between functions

    Each record: function_addr, function, site_addr, allocator, size_arg, cwe ("CWE-190"),
    consequence ("CWE-122", or "CWE-787" when a write with the un-wrapped length is seen), op,
    op_addr, width_bits, operands [{expr, bits, range, tainted, origin}], max_value,
    guard_status ("unguarded" | "post-wrap-check" | a "guarded-*" reason when suppressed),
    reason, written_after, confidence.
    """
    stop = should_stop or (lambda: False)
    stats = {"functions": len(func_irs or {}), "skipped_over_budget": 0, "alloc_sites": 0,
             "tainted_sizes": 0, "reported": 0, "via_field": 0, "suppressed": defaultdict(int),
             "cut_short": False}
    P = _build_program(func_irs, call_edges, arch, bits, names, entry_seeds, stop, stats)
    if P is None:
        if stats_out is not None:
            stats_out.update(stats)
        return []
    D = _Detector(P)
    out = []
    for faddr, F in P.funcs.items():
        if stop():
            stats["cut_short"] = True
            break
        for rec in F.calls.values():
            sizes = P._alloc_args(rec)
            if sizes is None:
                continue
            stats["alloc_sites"] += 1
            if any(P.taint(rec["args"][si]) for si in sizes if si < len(rec["args"])):
                stats["tainted_sizes"] += 1
            r = _site_record(P, D, F, rec, sizes)
            if r is None:
                stats["suppressed"]["no-tainted-wrap"] += 1
                continue
            if r["guard_status"].startswith("guarded"):
                stats["suppressed"][r["guard_status"]] += 1
                if include_suppressed:
                    out.append(r)
                continue
            stats["reported"] += 1
            if any("(stored to " in str(o.get("origin") or "") for o in r["operands"]):
                stats["via_field"] += 1
            out.append(r)
    stats["suppressed"] = dict(stats["suppressed"])
    stats["field"] = dict(P.fstats)
    if stats_out is not None:
        stats_out.update(stats)
    out.sort(key=lambda r: (str(r["function_addr"]), _hexint(r["site_addr"]) or 0))
    return out


def _build_program(func_irs, call_edges, arch, bits, names, entry_seeds, stop, stats):
    """Evaluate every function and run the inter-procedural parameter fixpoint; the analysed
    _Program, or None (with stats["note"]) when the arch has no calling convention."""
    P = _Program(func_irs, call_edges, arch, bits, names, entry_seeds)
    if not P.ak or not (P.callargfams or P.stack_args):
        stats["note"] = f"no calling convention for arch {arch!r}"
        return None
    for f in P.bottom_up():
        if stop():
            stats["cut_short"] = True
            break
        try:
            P.evaluate(f)
        except RecursionError:
            P.funcs.pop(f, None)
            P.skipped.append(f)
    stats["skipped_over_budget"] = len(P.skipped)
    # inter-procedural taint fixpoint over the parameters (summaries are read lazily)
    for _it in range(8):
        P.reset_memos()
        changed = False
        for rec in list(P.call_rec.values()):
            dst = rec["dst"]
            if not rec["internal"] or dst not in P.funcs:
                continue
            ctx = (rec["func"], rec["block"], ())
            for i, a in enumerate(rec["args"]):
                key = (dst, i)
                t = P.taint(a)
                if t:
                    if key not in P.p_taint:
                        P.p_taint[key] = t
                        changed = True
                    r = P.rng(a, ctx)
                    old = P.p_range.get(key)
                    new = r if old is None else (min(old[0], r[0]), max(old[1], r[1]))
                    if new != old:
                        P.p_range[key] = new if _it < 5 else (0, _mask(P.word))
                        changed = changed or _it < 5
                pt = P.ptr_taint(a)
                if pt and key not in P.p_ptr:
                    P.p_ptr[key] = pt
                    changed = True
        if not changed:
            break
    P.reset_memos()
    return P


def _site_record(P, D, F, rec, sizes):
    N = P.N
    best = None
    for si in sizes:
        if si >= len(rec["args"]):
            continue
        ctx = (F.addr, rec["block"], ())
        wraps: list = []
        D.find_wraps(rec["args"][si], ctx, wraps, set())
        for w in wraps:
            g = D.guard(w)
            cand = (si, w, g)
            if g is None:
                best = cand
                break
            if best is None:
                best = cand
        if best is not None and best[2] is None:
            break
    if best is None:
        return None
    si, w, g = best
    alloc = {**rec, "size_arg": si}
    operands = []
    for v, rv, tv in ((w["x"], w["rx"], w["tx"]), (w["y"], w["ry"], w["ty"])):
        sv = _strip(N, v)
        operands.append({"expr": _pretty(P, v), "bits": 8 * N.size(sv),
                         "range": [rv[0], rv[1]], "tainted": bool(tv), "origin": tv})
    op_sym = {"INT_MULT": "*", "INT_ADD": "+", "INT_LEFT": "<<"}[w["op"]]
    expr = f"{operands[0]['expr']} {op_sym} {operands[1]['expr']}"
    name = rec["name"] or P.names.get(rec["dst"], str(rec["dst"]))
    if g is not None:
        status, why = g
        written = None
        post = None
    else:
        post = D.post_wrap_check(w)
        status = "post-wrap-check" if post else "unguarded"
        written = D.written_after(F, alloc, w)
        why = (f"{w['op']} {expr} is computed in {w['width']} bits but can reach "
               f"{w['max']:#x} (> 2^{w['width']}) from attacker-controlled operands, with no "
               f"dominating bound, overflow-flag or division check")
        if post:
            why += f"; the only check, `{post}`, runs on the already-wrapped value"
        if written:
            why += f"; then {written['detail']} -- an overflow of the undersized buffer"
    conf = 0.0
    if g is None:
        conf = 0.6 if status == "unguarded" else 0.5
        if written:
            conf += 0.2
        if all(o["tainted"] or N.cval(v) is not None for o, v in
               zip(operands, (w["x"], w["y"]))):
            conf += 0.05
    return {
        "function_addr": F.addr, "function": P.names.get(F.addr), "site_addr": rec["site"],
        "allocator": name, "size_arg": si, "cwe": "CWE-190",
        "consequence": "CWE-787" if written else "CWE-122",
        "op": w["op"], "op_addr": N.where.get(w["node"]), "width_bits": w["width"],
        "operands": operands, "expr": expr, "max_value": w["max"],
        "guard_status": status, "reason": why, "post_wrap_check": post,
        "written_after": written, "confidence": round(min(conf, 0.9), 2),
    }


def _eval_with(N, e, var, val, depth=0):
    """Evaluate node `e` with node `var` := constant `val`; None if `e` depends on anything else."""
    if e == var:
        return val & _mask(N.size(var))
    k = N.key[e]
    if k[0] == "c":
        return k[2]
    if k[0] != "op" or depth > 10:
        return None
    m = k[2]
    if m == "SUBPIECE":
        a = _eval_with(N, k[3], var, val, depth + 1)
        return None if a is None else (a >> (8 * (N.cval(k[4]) or 0))) & _mask(k[1])
    a = _eval_with(N, k[3], var, val, depth + 1)
    if a is None:
        return None
    b = None
    if len(k) > 4:
        b = _eval_with(N, k[4], var, val, depth + 1)
        if b is None:
            return None
    return _fold(m, a, b, N.size(k[3]), N.size(k[4]) if len(k) > 4 else 0, k[1])


def _depends_on(N, x, target, limit=200):
    """Is `target` among the values `x` is computed from (through ops, selects and phis)?"""
    todo, seen = [x], set()
    while todo and len(seen) < limit:
        y = todo.pop()
        if y == target:
            return True
        if y in seen:
            continue
        seen.add(y)
        k = N.key[y]
        if k[0] in ("op", "sel"):
            todo.extend(v for v in k[3:] if isinstance(v, int))
        elif k[0] == "phi":
            todo.extend(N.phi_in.get(y, {}).values())
    return False
