#!/usr/bin/env python3
"""Hypothesis driver: propose vulnerability hypotheses and solve for inputs that TRIGGER them.

Runs in an angr-capable interpreter (never imported by the stdlib core):

    <angr_python> hyp_driver.py <spec.json> <out.json>

One angr process does the whole static -> PoC step for one binary:

  1. PROPOSE  -- walk the recovered CFG and emit hypotheses at the places a memory-safety or
                 injection bug can live: calls to copy / format / command / allocation sinks, and
                 indexed or in-loop stores. A hypothesis is a SITE plus a machine-checkable
                 VIOLATION, never a prose warning.
  2. DIRECT   -- one multi-target best-first symbolic exploration from the real program entry,
                 ordered by interprocedural CFG distance to the nearest unsolved site (call-stack
                 aware, loop-penalised). Static analysis supplies target LOCATIONS; the path
                 condition (magic bytes, type fields, lengths, checksums) falls out of the solver.
  3. VIOLATE  -- the violation is checked where it happens, and solved for when it can happen:
       * every memory write (direct stores AND the stores libc models perform, e.g. memcpy/read)
         is checked against the protected regions of the live program: the saved return-address
         slot of every active frame, the requested bounds and freed state of every heap chunk,
         and the bounds of the global object a symbolic-index write is based on;
       * symbolic-address reads are checked the same way (out-of-bounds read), and reads of a
         freed chunk are use-after-free;
       * a symbolic instruction pointer is control-flow hijack;
       * at sink calls: the format argument carries input bytes (CWE-134), the command string
         carries input bytes (CWE-78), the allocation size can wrap (CWE-190), a chunk is freed
         twice (CWE-415).
     A violation that is SATISFIABLE on the current path is solved to concrete input bytes.

The driver never claims a bug: it emits candidate inputs. The core replays each one and only a
replay whose crash/oracle matches the site confirms the hypothesis (models can be unsound: the
validator is the precision filter, and failures come back as exclusions).

spec.json: binary, argv (list, "@@" = input carrier), input_mode (file|stdin|arg), input_size,
           max_seconds, max_states, width, exclude {hyp_id: [b64,...]}, only [hyp_id,...],
           max_rss_mb (default 8192: past it the driver writes partial results and exits 3),
           solver_timeout_ms (default 10000), solver_max_mb (z3 heap cap, default max_rss_mb)
out.json : ok, angr_version, stats, hypotheses:[{id, kind, cwe, site, func, func_addr, callee,
           status, reached, solutions:[{input_b64, detail, values}], note}], error
"""
import base64
import json
import os
import signal
import sys
import time
import traceback
import warnings

warnings.filterwarnings("ignore")

INF = 10 ** 6

FMT_SINKS = {"printf": 0, "vprintf": 0, "fprintf": 1, "vfprintf": 1, "dprintf": 1, "vdprintf": 1,
             "sprintf": 1, "vsprintf": 1, "snprintf": 2, "vsnprintf": 2, "syslog": 1, "vsyslog": 1,
             "__printf_chk": 1, "__fprintf_chk": 2, "__sprintf_chk": 3, "__snprintf_chk": 4}
CMD_SINKS = {"system": 0, "popen": 0}
ALLOC_SINKS = {"malloc": 0, "realloc": 1, "_Znwm": 0, "_Znam": 0, "valloc": 0, "aligned_alloc": 1}
COPY_SINKS = {"memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat", "sprintf", "vsprintf",
              "snprintf", "read", "fread", "fgets", "recv", "recvfrom", "memset", "gets", "scanf",
              "sscanf", "fscanf", "__isoc99_scanf", "__isoc99_sscanf", "__isoc99_fscanf", "stpcpy",
              "__memcpy_chk", "__strcpy_chk", "__read_chk", "bcopy", "wcscpy", "getline", "pread"}
FREE_SINKS = {"free"}
BORING_FUNCS = {"_start", "_init", "_fini", "deregister_tm_clones", "register_tm_clones",
                "__do_global_dtors_aux", "frame_dummy", "__libc_csu_init", "__libc_csu_fini",
                "_dl_relocate_static_pie"}

# payloads tried for injection sinks, strongest first; the core's oracle looks for their effect
FMT_PAYLOADS = [b"%n%n%n%n", b"%s%s%s%s%s%s", b"%n%n", b"%x%n"]
CMD_PAYLOADS = [b";id;#", b"|id|", b"$(id)", b"`id`", b"\nid\n", b";id"]
HIJACK_MARK = {64: 0x4141414141414141, 32: 0x41414141}

CWE = {"stack-write": "CWE-121", "heap-write": "CWE-122", "global-write": "CWE-787",
       "stack-read": "CWE-125", "heap-read": "CWE-125", "global-read": "CWE-125",
       "control-flow-hijack": "CWE-121", "format-string": "CWE-134", "cmd-injection": "CWE-78",
       "int-overflow-alloc": "CWE-190", "use-after-free": "CWE-416", "double-free": "CWE-415"}


class Deadline(BaseException):
    """BaseException so no broad `except Exception` in angr/claripy/our callbacks can swallow it."""


def _alarm(_sig, _frm):
    raise Deadline()


def _write(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh)


def _place(base, carrier):
    out = [str(a) for a in (base or [])]
    if "@@" in out:
        return [carrier if a == "@@" else a for a in out]
    return out + [carrier]


class Driver:
    def __init__(self, angr, claripy, spec):
        self.angr, self.claripy, self.spec = angr, claripy, spec
        self.t0 = time.time()
        self.hyps = {}             # id -> dict
        self.site_of_block = {}    # block addr -> [hyp ids] (directing targets)
        self.dist = {}             # hyp id -> {block addr: distance}
        self.dmin = {}             # combined min distance over unsolved directing hyps
        self.visits = {}
        self.exclude = {k: {base64.b64decode(x) for x in v} for k, v in (spec.get("exclude") or {}).items()}
        self.only = set(spec.get("only") or [])
        self.stats = {"steps": 0, "violations": 0, "unsat_checks": 0}
        self.inp = None            # the symbolic input bitvector
        self._plt_cache = {}
        self.inp_len = 0

    # ------------------------------------------------------------------ setup
    def load(self):
        angr = self.angr
        self.p = angr.Project(self.spec["binary"], auto_load_libs=False,
                              load_options={"main_opts": {}})
        self.arch_bits = self.p.arch.bits
        self.word = self.p.arch.bytes
        self.cfg = self.p.analyses.CFGFast(normalize=True, data_references=False,
                                           resolve_indirect_jumps=True)
        self.main_obj = self.p.loader.main_object
        self.x86 = self.p.arch.name in ("AMD64", "X86")
        self._install_models()
        self.dlocals = self._dwarf_locals()
        self._globals_table()

    def _globals_table(self):
        """Data objects with known extent: ELF symbols with a size (best effort; stripped -> sections)."""
        objs = []
        try:
            for s in self.main_obj.symbols:
                if s.is_function or not s.size or s.size <= 0:
                    continue
                if getattr(s, "is_import", False):
                    continue
                objs.append((s.rebased_addr, s.rebased_addr + s.size, s.name))
        except Exception:
            pass
        if not objs:
            try:
                for sec in self.main_obj.sections:
                    if sec.name in (".data", ".bss") and sec.memsize:
                        objs.append((sec.vaddr, sec.vaddr + sec.memsize, sec.name))
            except Exception:
                pass
        objs.sort()
        self.gobjs = objs

    def _gobj(self, addr):
        for lo, hi, name in self.gobjs:
            if lo <= addr < hi:
                return lo, hi, name
        return None

    def func_of(self, addr):
        try:
            f = self.cfg.kb.functions.floor_func(addr)
            if f is not None and f.addr <= addr < f.addr + max(1, f.size or 1) + 0x1000:
                return f
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ models
    def _install_models(self):
        """Replace libc models whose angr version is unsound for bug finding."""
        angr, claripy = self.angr, self.claripy
        drv = self

        class BoundedSnprintf(angr.SimProcedure):
            """snprintf that honours the size bound and %s/%.*s/%.Ns precision (angr's ignores both,
            which invents overflows that cannot happen and loses the real format-string payload)."""
            def run(self, dst, size, fmt):  # noqa: D401
                return drv._snprintf(self, dst, size, fmt, va_start=3)

        class BoundedSprintf(angr.SimProcedure):
            def run(self, dst, fmt):
                return drv._snprintf(self, dst, None, fmt, va_start=2)

        class BoundedMemset(angr.SimProcedure):
            """memset whose written data is capped like angr's memcpy. angr's own model builds
            `[char] * (min(num) + max_buffer_size)` as a Python list when num is symbolic: on a path
            where num can only be huge (`len - k` wrapped) that one list took 116GB and got the
            whole terminal session OOM-killed. The store keeps the real (symbolic) length, so the
            mem_write oracle still sees the full write and reports the overflow."""
            def run(self, dst, char, num):
                st = self.state
                if char.size() != st.arch.byte_width:
                    char = claripy.Extract(st.arch.byte_width - 1, 0, char)
                cap = max(1, int(st.libc.max_memcpy_size))
                if st.solver.symbolic(num):
                    n = min(cap, max(st.solver.min_int(num), st.solver.max_int(num)))
                    size = num
                else:
                    n = min(cap, st.solver.eval(num))
                    size = None
                if n <= 0:
                    return dst
                if st.solver.symbolic(char):
                    data = claripy.Concat(*([char] * n))
                else:
                    data = claripy.BVV(bytes([st.solver.eval(char)]) * n)
                if size is None:
                    st.memory.store(dst, data)
                else:
                    st.memory.store(dst, data, size=size)
                return dst

        class BoundedMemsetChk(BoundedMemset):
            def run(self, dst, char, num, _destlen):   # noqa: D401
                return super().run(dst, char, num)

        class PreciseSscanf(angr.SimProcedure):
            """sscanf with C semantics (literals, whitespace, widths, failure branch); angr's
            ignores literal text, always succeeds and pins every %s at its maximum length."""
            def run(self, src, fmt):   # noqa: D401
                return drv._sscanf(self, src, fmt, va_start=2)

        for name, cls in (("snprintf", BoundedSnprintf), ("sprintf", BoundedSprintf),
                          ("memset", BoundedMemset), ("__memset_chk", BoundedMemsetChk),
                          ("sscanf", PreciseSscanf), ("__isoc99_sscanf", PreciseSscanf),
                          ("__isoc23_sscanf", PreciseSscanf)):
            sym = self.p.loader.find_symbol(name)
            if sym is not None:
                self.p.hook_symbol(name, cls(), replace=True)

        heap_cls = None
        try:
            from angr.state_plugins.heap.heap_brk import SimHeapBrk
            heap_cls = SimHeapBrk
        except Exception:
            pass
        if heap_cls is not None and not getattr(heap_cls, "_lyk_patched", False):
            o_malloc, o_free, o_calloc, o_realloc = (heap_cls._malloc, heap_cls._free,
                                                     heap_cls._calloc, heap_cls._realloc)

            def _rec(state, addr, size):
                try:
                    a = state.solver.eval_one(addr)
                except Exception:
                    return
                ch = dict(state.globals.get("chunks", {}))
                ch[a] = (size, False)
                state.globals["chunks"] = ch

            def _malloc(self, sim_size):
                addr = o_malloc(self, sim_size)
                _rec(self.state, addr, sim_size)
                return addr

            def _calloc(self, n, sz):
                addr = o_calloc(self, n, sz)
                _rec(self.state, addr, n * sz)
                return addr

            def _realloc(self, ptr, size):
                addr = o_realloc(self, ptr, size)
                _rec(self.state, addr, size)
                return addr

            def _free(self, ptr):
                st = self.state
                try:
                    a = st.solver.eval_one(ptr)
                except Exception:
                    a = None
                ch = st.globals.get("chunks", {})
                if a is not None and a in ch:
                    size, freed = ch[a]
                    if freed:
                        drv.violation(st, "double-free", None,
                                      f"free() of chunk {a:#x} that is already freed")
                    ch = dict(ch)
                    ch[a] = (size, True)
                    st.globals["chunks"] = ch
                return o_free(self, ptr)

            heap_cls._malloc, heap_cls._free = _malloc, _free
            heap_cls._calloc, heap_cls._realloc = _calloc, _realloc
            heap_cls._lyk_patched = True

    def _snprintf(self, proc, dst, size, fmt, va_start):
        """Precise model for formats with at most ONE variable-length conversion (%s / %.*s / %.Ns);
        anything else falls back to angr's FormatParser model."""
        claripy, st = self.claripy, proc.state
        try:
            f = st.solver.eval(st.memory.load(fmt, 512, inspect=False), cast_to=bytes).split(b"\0")[0]
            if st.solver.symbolic(st.memory.load(fmt, len(f) + 1, inspect=False)):
                raise ValueError("symbolic format")
        except Exception:
            return self._fallback_fmt(proc, dst, size, fmt, va_start)
        cc = proc.cc
        argi = [va_start]

        def nextarg():
            i = argi[0]
            argi[0] += 1
            return proc.va_arg("void*") if False else _arg(i)

        def _arg(i):
            try:
                return cc.get_args(st, [proc.angr_proto_ptr if False else None] * 0) and None
            except Exception:
                return None

        regs = list(getattr(cc, "ARG_REGS", []) or [])

        def arg(i):
            if i < len(regs):
                return getattr(st.regs, regs[i])
            sp = st.regs.sp
            return st.memory.load(sp + (i - len(regs) + 1) * self.word, self.word,
                                  endness=st.arch.memory_endness, inspect=False)

        pre, var, post, k, i = b"", None, b"", 0, va_start
        segs = []                    # list of ("lit", bytes) | ("var", (ptr, prec_ast|None))
        lit = bytearray()
        while k < len(f):
            c = f[k:k + 1]
            if c != b"%":
                lit += c
                k += 1
                continue
            j = k + 1
            prec = None
            while j < len(f) and f[j:j + 1] in b"-+ #0":
                j += 1
            while j < len(f) and f[j:j + 1].isdigit():
                j += 1                          # width: only safe when not used with %s below
            width_given = j > k + 1 and f[k + 1:j].strip(b"-+ #0") != b""
            if f[j:j + 1] == b".":
                j += 1
                if f[j:j + 1] == b"*":
                    prec = ("ast", arg(i))
                    i += 1
                    j += 1
                else:
                    d0 = j
                    while j < len(f) and f[j:j + 1].isdigit():
                        j += 1
                    prec = ("int", int(f[d0:j] or b"0"))
            while j < len(f) and f[j:j + 1] in b"hlqjzt":
                j += 1
            conv = f[j:j + 1]
            if conv == b"%":
                lit += b"%"
            elif conv == b"c":
                v = st.solver.eval(arg(i)) & 0xff
                i += 1
                lit += bytes([v])
            elif conv in (b"d", b"i", b"u", b"x", b"X", b"o", b"p") and not width_given:
                v = st.solver.eval(arg(i))
                i += 1
                lit += {b"d": b"%d", b"i": b"%d", b"u": b"%u", b"x": b"%x", b"X": b"%X",
                        b"o": b"%o", b"p": b"0x%x"}[conv] % v
            elif conv == b"s" and not width_given:
                if any(s[0] == "var" for s in segs):
                    return self._fallback_fmt(proc, dst, size, fmt, va_start)
                segs.append(("lit", bytes(lit)))
                lit = bytearray()
                segs.append(("var", (arg(i), prec)))
                i += 1
            else:
                return self._fallback_fmt(proc, dst, size, fmt, va_start)
            k = j + 1
        segs.append(("lit", bytes(lit)))
        if not any(s[0] == "var" for s in segs):
            out = b"".join(s[1] for s in segs)
            total = len(out)
            if size is not None:
                n = st.solver.eval(size)
                if n == 0:
                    return claripy.BVV(total, st.arch.bits)
                out = out[: n - 1]
            st.memory.store(dst, out + b"\0")
            return claripy.BVV(total, st.arch.bits)
        pre = segs[0][1]
        ptr, prec = segs[1][1]
        post = segs[2][1] if len(segs) > 2 else b""
        maxv = max(16, st.libc.max_str_len)
        if prec is not None and prec[0] == "int":
            maxv = min(maxv, prec[1])
        # One load, not maxv single-byte loads: each symbolic-address load is its own
        # concretization, and these model-internal reads must not fire the read oracle.
        _blob = st.memory.load(ptr, maxv, inspect=False)
        src = [_blob.get_byte(t) for t in range(maxv)]
        # nz length of src, bounded
        L = claripy.BVV(maxv, 32)
        for t in reversed(range(maxv)):
            L = claripy.If(src[t] == 0, claripy.BVV(t, 32), L)
        if prec is not None and prec[0] == "ast":
            p = prec[1][31:0] if prec[1].size() >= 32 else prec[1].zero_extend(32 - prec[1].size())
            p = claripy.If(claripy.SLT(p, 0), claripy.BVV(maxv, 32), p)   # negative precision = none
            L = claripy.If(claripy.ULT(p, L), p, L)
        P, S = len(pre), len(post)
        total = L + (P + S)
        W = P + maxv + S + 1
        nlim = None
        if size is not None:
            try:
                nlim = st.solver.eval_one(size)
            except Exception:
                nlim = st.solver.max(size)
            if nlim == 0:
                return total.zero_extend(st.arch.bits - 32)
            W = min(W, nlim)
        old = st.memory.load(dst, W, inspect=False)
        outb = []
        for kpos in range(W):
            if kpos < P:
                b = claripy.BVV(pre[kpos], 8)
            else:
                jj = kpos - P
                tail = old.get_byte(kpos)
                for t in range(S, -1, -1):
                    vb = claripy.BVV(post[t], 8) if t < S else claripy.BVV(0, 8)
                    tail = claripy.If(claripy.BVV(jj, 32) == L + t, vb, tail)
                b = claripy.If(claripy.ULT(claripy.BVV(jj, 32), L),
                               src[jj] if jj < maxv else claripy.BVV(0, 8), tail)
            if nlim is not None and kpos == nlim - 1:
                b = claripy.If(claripy.UGE(total, kpos), claripy.BVV(0, 8), b)
            outb.append(b)
        st.memory.store(dst, claripy.Concat(*outb))
        return total.zero_extend(st.arch.bits - 32)

    SCANF_WS = b" \t\n\v\f\r"
    SCANF_INT = {b"d": (10, True), b"i": (10, True), b"u": (10, False), b"x": (16, False),
                 b"X": (16, False), b"o": (8, False)}

    def _sscanf(self, proc, src, fmt, va_start):
        """Solver-encoded sscanf. No forking: the return value is a sum of If(ok_k, 1, 0) over the
        conversions and every store is conditional on ok_k, so the caller's `!= N` branch splits
        the paths. Token lengths are symbolic; positions after a variable-length token are
        resolved over their feasible values (at most POS_FANOUT, else a sound subset)."""
        claripy, st = self.claripy, proc.state
        try:
            f = st.solver.eval(st.memory.load(fmt, 256, inspect=False), cast_to=bytes).split(b"\0")[0]
            if st.solver.symbolic(st.memory.load(fmt, len(f) + 1, inspect=False)):
                raise ValueError("symbolic format")
        except Exception:
            from angr.procedures.libc.sscanf import sscanf as _ss
            return proc.inline_call(_ss, src, fmt).ret_expr
        cc = proc.cc
        regs = list(getattr(cc, "ARG_REGS", []) or [])

        def arg(i):
            if i < len(regs):
                return getattr(st.regs, regs[i])
            return st.memory.load(st.regs.sp + (i - len(regs) + 1) * self.word, self.word,
                                  endness=st.arch.memory_endness, inspect=False)

        M = max(32, min(1024, st.libc.max_str_len))
        blob = st.memory.load(src, M, inspect=False)
        B = [blob.get_byte(t) for t in range(M)]
        WS = [claripy.BVV(c, 8) for c in self.SCANF_WS]
        FAN = int(self.spec.get("scanf_pos_fanout", 64))

        def is_ws(b):
            return claripy.Or(*[b == w for w in WS])

        class Pos:
            """A position: concrete, or a symbolic ast resolved (lazily, only if a later directive
            reads at it) over its [min, max] range -- all of it when <= FAN values, else FAN evenly
            spaced values kept by constraint (an under-approximation: every input stays real)."""
            def __init__(self, ast):
                self.ast = ast
                self._vals = None

            @property
            def vals(self):
                if self._vals is None:
                    if not st.solver.symbolic(self.ast):
                        self._vals = [st.solver.eval(self.ast)]
                    else:
                        lo, hi = st.solver.min(self.ast), st.solver.max(self.ast)
                        hi = min(hi, lo + M)
                        if hi - lo + 1 <= FAN:
                            self._vals = list(range(lo, hi + 1))
                        else:
                            step = (hi - lo) / (FAN - 1)
                            self._vals = sorted({lo + round(i * step) for i in range(FAN)})
                            st.add_constraints(claripy.Or(*[self.ast == v for v in self._vals]))
                return self._vals

            def at(self, j):
                """byte at position + j"""
                if len(self.vals) == 1:
                    k = self.vals[0] + j
                    return B[k] if k < M else claripy.BVV(0, 8)
                e = claripy.BVV(0, 8)
                for v in self.vals:
                    k = v + j
                    e = claripy.If(self.ast == v, B[k] if k < M else claripy.BVV(0, 8), e)
                return e

        W32 = 32
        pos = Pos(claripy.BVV(0, W32))
        ok = claripy.true()
        count = claripy.BVV(0, W32)
        argi = va_start
        consumed_any = False

        def skip_ws(pos, ok, maxw=8):
            """C: a whitespace directive (and most conversions) skip ANY run of whitespace. Runs
            are bounded at maxw (longer runs are excluded from the success branch)."""
            if all(len(pos.vals) == 1 and pos.vals[0] + t < M and not st.solver.symbolic(B[pos.vals[0] + t])
                   and st.solver.eval(B[pos.vals[0] + t]) not in self.SCANF_WS for t in range(1)):
                return pos, ok            # concrete non-whitespace next: nothing to skip
            n = claripy.BVS("scanf_ws", W32)
            st.add_constraints(claripy.ULE(n, maxw))
            conds = []
            for j in range(maxw + 1):
                inside = claripy.ULT(claripy.BVV(j, W32), n)
                at_end = n == j
                conds.append(claripy.If(inside, is_ws(pos.at(j)), claripy.true()))
                conds.append(claripy.Or(claripy.Not(at_end), claripy.Not(is_ws(pos.at(j)))))
            return Pos(pos.ast + n), claripy.And(ok, *conds)

        k = 0
        while k < len(f):
            c = f[k:k + 1]
            if c in (b" ", b"\t", b"\n"):
                pos, ok = skip_ws(pos, ok)
                k += 1
                continue
            if c != b"%" or f[k + 1:k + 2] == b"%":
                lit = b"%" if c == b"%" else c
                ok = claripy.And(ok, pos.at(0) == lit[0])
                pos = Pos(pos.ast + 1)
                k += 2 if c == b"%" else 1
                continue
            j = k + 1
            suppress = f[j:j + 1] == b"*"
            if suppress:
                j += 1
            d0 = j
            while j < len(f) and f[j:j + 1].isdigit():
                j += 1
            width = int(f[d0:j]) if j > d0 else None
            lm = b""
            while j < len(f) and f[j:j + 1] in b"hlLqjzt":
                lm += f[j:j + 1]
                j += 1
            conv = f[j:j + 1]
            k = j + 1
            if conv == b"n":
                if not suppress:
                    dst = arg(argi)
                    argi += 1
                    st.memory.store(dst, pos.ast, endness=st.arch.memory_endness, condition=ok)
                continue
            if conv == b"c":
                n = width or 1
                cond = claripy.And(*[pos.at(t) != 0 for t in range(n)])
                ok = claripy.And(ok, cond)
                if not suppress:
                    dst = arg(argi)
                    argi += 1
                    st.memory.store(dst, claripy.Concat(*[pos.at(t) for t in range(n)]), condition=ok)
                    count = count + claripy.If(ok, claripy.BVV(1, W32), claripy.BVV(0, W32))
                pos = Pos(pos.ast + n)
                continue
            if conv == b"s":
                pos, ok = skip_ws(pos, ok)
                N = width if width else max(1, M - 1 - (pos.vals[0] if len(pos.vals) == 1 else 0))
                L = claripy.BVS("scanf_tok_len", W32)
                st.add_constraints(claripy.UGE(L, 1), claripy.ULE(L, N))   # ranges only: hard
                cons = []
                for t in range(N + 1):
                    b = pos.at(t)
                    inside = claripy.ULT(claripy.BVV(t, W32), L)
                    if t < N:
                        cons.append(claripy.If(inside, claripy.And(b != 0, claripy.Not(is_ws(b))),
                                               claripy.true()))
                    # the token ends at a delimiter, NUL, or the width
                    if t < N:
                        cons.append(claripy.Or(L != t, b == 0, is_ws(b)))
                tok_ok = claripy.And(*cons)
                ok = claripy.And(ok, tok_ok)
                if not suppress:
                    dst = arg(argi)
                    argi += 1
                    data = claripy.Concat(*[claripy.If(claripy.ULT(claripy.BVV(t, W32), L),
                                                       pos.at(t), claripy.BVV(0, 8))
                                            for t in range(N + 1)])
                    size = (L + 1).zero_extend(self.arch_bits - W32) if self.arch_bits > W32 else L + 1
                    st.memory.store(dst, data, size=size, condition=ok)
                    count = count + claripy.If(ok, claripy.BVV(1, W32), claripy.BVV(0, W32))
                pos = Pos(pos.ast + L)
                consumed_any = True
                continue
            if conv in self.SCANF_INT:
                base, signed = self.SCANF_INT[conv]
                pos, ok = skip_ws(pos, ok)
                nbits = 64 if lm in (b"l", b"ll", b"q", b"j", b"z", b"t") and self.arch_bits == 64 else \
                    (16 if lm == b"h" else 8 if lm == b"hh" else 32)
                maxd = width or {10: 19 if nbits == 64 else 10, 16: 16 if nbits == 64 else 8,
                                 8: 22 if nbits == 64 else 11}[base]
                neg = (pos.at(0) == ord("-")) if signed else claripy.false()
                has_sign = claripy.Or(pos.at(0) == ord("-"), pos.at(0) == ord("+")) if signed else claripy.false()
                off = claripy.If(has_sign, claripy.BVV(1, W32), claripy.BVV(0, W32))
                p1 = Pos(pos.ast + off)
                D = claripy.BVS("scanf_digits", W32)
                st.add_constraints(claripy.UGE(D, 1), claripy.ULE(D, maxd))
                cons = []
                val = claripy.BVV(0, 64)
                for t in range(maxd + 1):
                    b = p1.at(t)
                    if base == 16:
                        dig = claripy.Or(claripy.And(claripy.UGE(b, ord("0")), claripy.ULE(b, ord("9"))),
                                         claripy.And(claripy.UGE(b, ord("a")), claripy.ULE(b, ord("f"))),
                                         claripy.And(claripy.UGE(b, ord("A")), claripy.ULE(b, ord("F"))))
                        dv = claripy.If(claripy.ULE(b, ord("9")), b - ord("0"),
                                        claripy.If(claripy.UGE(b, ord("a")), b - ord("a") + 10, b - ord("A") + 10))
                    else:
                        dig = claripy.And(claripy.UGE(b, ord("0")), claripy.ULE(b, ord("0") + base - 1))
                        dv = b - ord("0")
                    inside = claripy.ULT(claripy.BVV(t, W32), D)
                    if t < maxd:
                        cons.append(claripy.If(inside, dig, claripy.true()))
                        cons.append(claripy.Or(D != t, claripy.Not(dig)))
                        val = claripy.If(inside, val * base + dv.zero_extend(56), val)
                tok_ok = claripy.And(*cons)
                ok = claripy.And(ok, tok_ok)
                val = claripy.If(neg, -val, val)
                if not suppress:
                    dst = arg(argi)
                    argi += 1
                    st.memory.store(dst, val[nbits - 1:0], endness=st.arch.memory_endness, condition=ok)
                    count = count + claripy.If(ok, claripy.BVV(1, W32), claripy.BVV(0, W32))
                pos = Pos(p1.ast + D)
                continue
            # %[ / floats / anything else: fall back to angr's model
            from angr.procedures.libc.sscanf import sscanf as _ss
            return proc.inline_call(_ss, src, fmt).ret_expr
        del consumed_any
        return count.zero_extend(self.arch_bits - W32) if self.arch_bits > W32 else count

    def _fallback_fmt(self, proc, dst, size, fmt, va_start):
        from angr.procedures.libc.snprintf import snprintf as _sn
        from angr.procedures.libc.sprintf import sprintf as _sp
        if size is None:
            return proc.inline_call(_sp, dst, fmt).ret_expr
        return proc.inline_call(_sn, dst, size, fmt).ret_expr

    # ------------------------------------------------------------------ propose
    def propose(self):
        kb = self.cfg.kb
        for f in list(kb.functions.values()):
            if f.is_plt or f.is_simprocedure or f.name in BORING_FUNCS or f.is_syscall:
                continue
            if not self.main_obj.contains_addr(f.addr):
                continue
            for cs in f.get_call_sites():
                tgt = f.get_call_target(cs)
                callee = kb.functions.function(addr=tgt) if tgt is not None else None
                name = (callee.name if callee is not None else "") or ""
                base = name.split("@")[0]
                try:
                    blk = self.p.factory.block(cs)
                    ins = blk.instruction_addrs[-1]
                except Exception:
                    continue
                kinds = []
                if base in FMT_SINKS:
                    kinds.append("format-string")
                if base in CMD_SINKS:
                    kinds.append("cmd-injection")
                if base in ALLOC_SINKS:
                    kinds.append("int-overflow-alloc")
                if base in COPY_SINKS:
                    kinds.append("copy")
                for kd in kinds:
                    self._add_hyp(kd, ins, cs, f, callee=base)
            self._propose_stores(f)
        self.call_sites = {h["site"]: h for h in self.hyps.values() if h["callee"]}

    def _propose_stores(self, f):
        """Indexed / pointer stores (address computed from loaded values, scaled or added) and
        any non-frame-constant store inside a loop: the directing targets for OOB writes."""
        try:
            import networkx as nx
            loop_blocks = set()
            for comp in nx.strongly_connected_components(f.graph):
                if len(comp) > 1:
                    loop_blocks |= {n.addr for n in comp}
                else:
                    n = next(iter(comp))
                    if f.graph.has_edge(n, n):
                        loop_blocks.add(n.addr)
        except Exception:
            loop_blocks = set()
        sp_off = {self.p.arch.registers.get("sp", (None,))[0], self.p.arch.registers.get("bp", (None,))[0]}
        for blk_node in f.blocks:
            try:
                vex = self.p.factory.block(blk_node.addr, size=blk_node.size).vex
            except Exception:
                continue
            prov = {}   # tmp -> ("frame"|"index"|"ptr"|"const")
            cur_ins = blk_node.addr
            for stmt in vex.statements:
                tag = stmt.tag
                if tag == "Ist_IMark":
                    cur_ins = stmt.addr
                elif tag == "Ist_WrTmp":
                    e = stmt.data
                    et = e.tag
                    if et == "Iex_Get":
                        prov[stmt.tmp] = "frame" if e.offset in sp_off else "ptr"
                    elif et == "Iex_Const":
                        prov[stmt.tmp] = "const"
                    elif et == "Iex_Load":
                        prov[stmt.tmp] = "ptr"
                    elif et == "Iex_RdTmp":
                        prov[stmt.tmp] = prov.get(e.tmp, "ptr")
                    elif et in ("Iex_Binop", "Iex_Unop"):
                        kids = [prov.get(a.tmp, "ptr") if a.tag == "Iex_RdTmp" else "const"
                                for a in getattr(e, "args", [])]
                        op = e.op
                        if "Shl" in op or "Mul" in op:
                            prov[stmt.tmp] = "index" if any(k in ("ptr", "index") for k in kids) else "const"
                        elif "Add" in op or "Sub" in op:
                            nonconst = [k for k in kids if k != "const"]
                            if any(k == "index" for k in nonconst):
                                prov[stmt.tmp] = "index"
                            elif len(nonconst) >= 2:
                                prov[stmt.tmp] = "index"
                            elif nonconst:
                                prov[stmt.tmp] = nonconst[0]
                            else:
                                prov[stmt.tmp] = "const"
                        else:
                            prov[stmt.tmp] = "ptr" if any(k != "const" for k in kids) else "const"
                    else:
                        prov[stmt.tmp] = "ptr"
                elif tag == "Ist_Store":
                    a = stmt.addr
                    pv = prov.get(a.tmp, "const") if a.tag == "Iex_RdTmp" else "const"
                    if pv == "index" or (pv == "ptr" and blk_node.addr in loop_blocks):
                        self._add_hyp("store", cur_ins, blk_node.addr, f,
                                      note=("in-loop " if blk_node.addr in loop_blocks else "") + pv)

    def _add_hyp(self, kind, ins, block, f, callee=None, note=""):
        hid = f"{kind}@{ins:#x}"
        if hid in self.hyps:
            return
        if self.only and hid not in self.only:
            return
        self.hyps[hid] = {"id": hid, "kind": kind, "cwe": CWE.get(kind), "site": ins,
                          "block": block, "func": f.name, "func_addr": f.addr, "callee": callee,
                          "status": "proposed", "reached": 0, "solutions": [], "note": note,
                          "triggered_by": []}
        self.site_of_block.setdefault(block, []).append(hid)

    # ------------------------------------------------------------------ distance
    def distances(self):
        import networkx as nx
        g = nx.DiGraph()
        for a, b in self.cfg.graph.edges():
            g.add_edge(a.addr, b.addr)
        self.rg = g.reverse(copy=False)
        for hid, h in self.hyps.items():
            if h["block"] in self.rg:
                self.dist[hid] = nx.single_source_shortest_path_length(self.rg, h["block"])
            else:
                self.dist[hid] = {h["block"]: 0}
        self._recompute_dmin()

    def _recompute_dmin(self):
        dm = {}
        for hid, d in self.dist.items():
            h = self.hyps[hid]
            if h["solutions"] or h.get("saturated"):
                continue
            for a, v in d.items():
                if v < dm.get(a, INF):
                    dm[a] = v
        self.dmin = dm

    def score(self, s):
        dm = self.dmin
        d = dm.get(s.addr, INF)
        try:
            for fr in s.callstack:
                ra = fr.ret_addr
                if ra:
                    v = dm.get(ra, INF)
                    if v + 1 < d:
                        d = v + 1
        except Exception:
            pass
        vis = self.visits.get(s.addr, 0)
        return (d if d < INF else INF) + vis // 4

    # ------------------------------------------------------------------ state
    def initial_state(self):
        angr, claripy = self.angr, self.claripy
        mode = self.spec.get("input_mode", "file")
        n = int(self.spec.get("input_size", 512))
        self.inp_len = n
        self.inp = claripy.BVS("input", n * 8)
        opts = {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY} - {angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY}
        prog = self.spec["binary"]
        base = self.spec.get("argv") or ["@@"]
        kw = {}
        if mode == "file":
            fname = "lykos_input"
            args = [prog] + _place(base, fname)
            kw["fs"] = {fname: angr.SimFile(fname, content=self.inp, size=n)}
        elif mode == "stdin":
            args = [prog] + [a for a in base if a != "@@"]
            kw["stdin"] = angr.SimFileStream(name="stdin", content=self.inp, has_end=True)
        else:   # arg
            args = [prog] + _place(base, self.inp)
        st = self.p.factory.full_init_state(args=args, add_options=opts,
                                            remove_options={angr.options.LAZY_SOLVES}, **kw)
        # arg mode: the argument ends at its first NUL (solve() cuts there), so its length is
        # free. Forcing every byte non-zero pinned it to exactly input_size, which made any
        # length-bounded path (strcpy into a small buffer, a length check) unsatisfiable.
        st.libc.max_str_len = max(st.libc.max_str_len, min(1024, n + 16))
        st.libc.max_buffer_size = max(st.libc.max_buffer_size, min(1024, n + 16))
        st.libc.max_variable_size = 4096
        st.libc.max_memcpy_size = max(st.libc.max_memcpy_size, n + 16)
        # Symbolic addresses (buf[off] after `off += len`) are resolved to a FEW concrete values
        # instead of an ITE over thousands: the record-parsing loops every file format has would
        # otherwise make each later solver query pay for every possible offset. The oracles run at
        # BP_BEFORE, on the still-symbolic address, so violation checks lose nothing.
        from angr.concretization_strategies import SimConcretizationStrategy

        class _Few(SimConcretizationStrategy):
            def __init__(self, k, **kw):
                super().__init__(**kw)
                self._k = k

            def _concretize(self, memory, addr, **kw):
                return self._eval(memory, addr, self._k, **kw)

        st.memory.read_strategies = [_Few(int(self.spec.get("read_fanout", 2)))]
        st.memory.write_strategies = [_Few(1)]
        st.inspect.b("mem_write", when=angr.BP_BEFORE, action=self._on_write)
        st.inspect.b("mem_read", when=angr.BP_BEFORE, action=self._on_read)
        return st

    # ------------------------------------------------------------------ DWARF stack objects
    def _dwarf_locals(self):
        """{function entry (as loaded): [(name, cfa_offset, size)]} for locals/params whose DWARF
        location is DW_OP_fbreg on a DW_OP_call_frame_cfa frame base (gcc/clang -g). Gives the
        object-level stack oracle what ASan knows: where each array ends. Stripped binaries or
        register/location-list variables simply contribute nothing (frame-level oracle only)."""
        out = {}
        if self.spec.get("no_dwarf"):
            return out
        try:
            from elftools.elf.elffile import ELFFile
        except Exception:
            return out
        delta = self.main_obj.mapped_base - self.main_obj.linked_base

        def sleb(bs):
            res, shift = 0, 0
            for b in bs:
                res |= (b & 0x7f) << shift
                shift += 7
                if not b & 0x80:
                    if b & 0x40:
                        res -= 1 << shift
                    return res
            return None

        def tsize(die, depth=0):
            if die is None or depth > 20:
                return None
            if die.tag == "DW_TAG_array_type":
                el = tsize(die.get_DIE_from_attribute("DW_AT_type"), depth + 1) \
                    if "DW_AT_type" in die.attributes else None
                n = 1
                for ch in die.iter_children():
                    if ch.tag != "DW_TAG_subrange_type":
                        continue
                    if "DW_AT_count" in ch.attributes:
                        n *= ch.attributes["DW_AT_count"].value
                    elif "DW_AT_upper_bound" in ch.attributes and \
                            isinstance(ch.attributes["DW_AT_upper_bound"].value, int) and \
                            ch.attributes["DW_AT_upper_bound"].form != "DW_FORM_exprloc" and \
                            not ch.attributes["DW_AT_upper_bound"].form.startswith("DW_FORM_ref"):
                        n *= ch.attributes["DW_AT_upper_bound"].value + 1
                    else:
                        return None          # VLA / unknown bound
                return el * n if el else None
            if "DW_AT_byte_size" in die.attributes:
                return die.attributes["DW_AT_byte_size"].value
            if "DW_AT_type" in die.attributes:
                return tsize(die.get_DIE_from_attribute("DW_AT_type"), depth + 1)
            return None

        try:
            with open(self.spec["binary"], "rb") as fh:
                elf = ELFFile(fh)
                if not elf.has_dwarf_info():
                    return out
                for cu in elf.get_dwarf_info().iter_CUs():
                    for die in cu.iter_DIEs():
                        if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes:
                            continue
                        fb = die.attributes.get("DW_AT_frame_base")
                        if fb is None or fb.value != [0x9c]:      # DW_OP_call_frame_cfa
                            continue
                        objs = []
                        stack = [die]
                        while stack:
                            d = stack.pop()
                            for ch in d.iter_children():
                                if ch.tag == "DW_TAG_lexical_block":
                                    stack.append(ch)
                                    continue
                                if ch.tag not in ("DW_TAG_variable", "DW_TAG_formal_parameter"):
                                    continue
                                loc = ch.attributes.get("DW_AT_location")
                                if loc is None or loc.form != "DW_FORM_exprloc" or not loc.value \
                                        or loc.value[0] != 0x91:   # DW_OP_fbreg
                                    continue
                                off = sleb(loc.value[1:])
                                sz = tsize(ch.get_DIE_from_attribute("DW_AT_type")) \
                                    if "DW_AT_type" in ch.attributes else None
                                if off is None or not sz:
                                    continue
                                nm = ch.attributes["DW_AT_name"].value.decode("utf-8", "replace") \
                                    if "DW_AT_name" in ch.attributes else "?"
                                objs.append((nm, off, sz))
                        if objs:
                            out[die.attributes["DW_AT_low_pc"].value + delta] = objs
        except Exception:
            return {}
        self.stats["dwarf_funcs"] = len(out)
        return out

    def _stack_objects(self, s):
        """[(lo, hi, name, function)] for the DWARF locals of every frame on the call stack."""
        if not self.dlocals:
            return []
        res = []
        cfa_adj = self.word if self.x86 else 0
        for sp, _ra, fa in self._frames(s):
            objs = self.dlocals.get(fa)
            if not objs:
                continue
            cfa = sp + cfa_adj
            for nm, off, sz in objs:
                res.append((cfa + off, cfa + off + sz, nm, self._fname(fa)))
        return res

    @staticmethod
    def _obj_at(objs, a):
        for o in objs:
            if o[0] <= a < o[1]:
                return o
        return None

    # ------------------------------------------------------------------ oracles
    def _site_for(self, s):
        """The program instruction responsible for the current access: the instruction itself for a
        direct store, else the call site that entered the libc model doing the store."""
        ins = s.scratch.ins_addr
        if ins is not None and self._is_prog_code(ins):
            return ins
        try:
            for fr in s.callstack:
                cs = fr.call_site_addr
                if cs and self._is_prog_code(cs):
                    # call_site_addr is the calling BLOCK; the call is its last instruction
                    try:
                        return self.p.factory.block(cs).instruction_addrs[-1]
                    except Exception:
                        return cs
        except Exception:
            pass
        return ins

    def _is_prog_code(self, a):
        """An instruction of the program itself: in the main object and not a PLT stub."""
        if not self.main_obj.contains_addr(a):
            return False
        r = self._plt_cache.get(a)
        if r is None:
            f = self.func_of(a)
            r = not (f is not None and (f.is_plt or f.is_simprocedure))
            self._plt_cache[a] = r
        return r

    def _frames(self, s):
        out = []
        try:
            for fr in s.callstack:
                sp = fr.stack_ptr
                if isinstance(sp, int) and sp and fr.func_addr is not None:
                    out.append((sp, fr.ret_addr, fr.func_addr))
        except Exception:
            pass
        return out

    def _is_stack(self, s, a):
        top = self.p.arch.initial_sp
        return top - 0x800000 <= a <= top + 0x10000

    def _on_write(self, s):
        try:
            addr = s.inspect.mem_write_address
            ln = s.inspect.mem_write_length
            if addr is None:
                return
            if ln is None:
                expr = s.inspect.mem_write_expr
                ln = (expr.size() // 8) if expr is not None else 1
            self._note_store_reach(s, addr)
            self._check_access(s, addr, ln, write=True)
        except Deadline:
            raise
        except self.claripy.errors.ClaripyError:
            self.stats["solver_giveups"] = self.stats.get("solver_giveups", 0) + 1
        except Exception:
            pass

    def _note_store_reach(self, s, addr):
        """Reach accounting for proposed store sites. A store that only ever hits ONE concrete
        address (`*minv = x` through a pointer argument) can never go out of bounds: once it has
        been reached SATURATE_REACHES times, stop steering toward it. Indexed stores keep moving
        and stay live (a loop bug needs many visits before the index runs off the end)."""
        ins = s.scratch.ins_addr
        if ins is None:
            return
        h = self.hyps.get(f"store@{ins:#x}")
        if h is None or h["solutions"] or h.get("saturated"):
            return
        h["reached"] += 1
        if h["status"] == "proposed":
            h["status"] = "reached"
        if s.solver.symbolic(addr):
            h["_multi"] = True
            return
        seen = h.setdefault("_addrs", set())
        if len(seen) < 2:
            seen.add(s.solver.eval(addr))
        if not h.get("_multi") and len(seen) == 1 and h["reached"] > self.SATURATE_REACHES:
            h["saturated"] = True
            h["note"] = (h.get("note") or "") + " (single fixed address: saturated)"
            self._recompute_dmin()

    def _on_read(self, s):
        try:
            addr = s.inspect.mem_read_address
            if addr is None:
                return
            ln = s.inspect.mem_read_length
            if ln is None:
                ln = 1
            sym = s.solver.symbolic(addr)
            if not sym and not s.globals.get("chunks") and not self.dlocals:
                return
            self._check_access(s, addr, ln, write=False)
        except Deadline:
            raise
        except self.claripy.errors.ClaripyError:
            self.stats["solver_giveups"] = self.stats.get("solver_giveups", 0) + 1
        except Exception:
            pass

    def _chunk_for(self, chunks, a):
        best = None
        for base in chunks:
            if base <= a and (best is None or base > best):
                best = base
        if best is None or a - best > 0x100000:
            return None
        return best

    def _check_access(self, s, addr, ln, write, site=None):
        claripy = self.claripy
        ln_ast = ln if not isinstance(ln, int) else claripy.BVV(ln, self.arch_bits)
        if ln_ast.size() < self.arch_bits:
            ln_ast = ln_ast.zero_extend(self.arch_bits - ln_ast.size())
        elif ln_ast.size() > self.arch_bits:
            ln_ast = ln_ast[self.arch_bits - 1:0]
        sym_addr = s.solver.symbolic(addr)
        sym_len = s.solver.symbolic(ln_ast)
        chunks = s.globals.get("chunks", {})
        conds = []
        if not sym_addr and not sym_len:
            # ---- concrete fast path: pure Python, a solver call only for symbolic chunk sizes
            lo = s.solver.eval(addr)
            hi = lo + s.solver.eval(ln_ast)
            ins = s.scratch.ins_addr
            if self._is_stack(s, lo) and (write or (ins is not None and self._is_prog_code(ins))):
                # (reads by libc models, e.g. strlen's chunked scan, run past buffers by design)
                o = self._obj_at(self._stack_objects(s), lo)
                if o is not None and hi > o[1]:
                    conds.append(("stack-write" if write else "stack-read", None,
                                  f"{'writes' if write else 'reads'} {hi - o[1]} byte(s) past the end of "
                                  f"local '{o[2]}' ({o[1] - o[0]} bytes) of {o[3]}", o[0], None, "obj"))
            if write and self.x86 and self._is_stack(s, lo):
                for sp, ra, fa in self._frames(s):
                    if lo <= sp < hi:
                        conds.append(("stack-write", None,
                                      f"overwrites the saved return address of {self._fname(fa)}",
                                      sp))
                        break
            if chunks and not self._is_stack(s, lo):
                base = self._chunk_for(chunks, lo)
                if base is not None:
                    size, freed = chunks[base]
                    if freed:
                        conds.append(("use-after-free", None,
                                      f"{'writes' if write else 'reads'} chunk {base:#x} after free()",
                                      base))
                    elif isinstance(size, int) or not getattr(size, "symbolic", False):
                        n = size if isinstance(size, int) else s.solver.eval(size)
                        if hi > base + n and lo < base + n + 0x10000:
                            conds.append(("heap-write" if write else "heap-read", None,
                                          f"{'writes' if write else 'reads'} past the end of the "
                                          f"{n}-byte chunk at {base:#x}", base))
                    else:
                        sz = size.zero_extend(self.arch_bits - size.size()) if size.size() < self.arch_bits else size
                        if hi > base:
                            conds.append(("heap-write" if write else "heap-read",
                                          claripy.UGT(claripy.BVV(hi, self.arch_bits), base + sz),
                                          f"{'writes' if write else 'reads'} past the end of the chunk "
                                          f"at {base:#x} (its size comes from input)", base))
        else:
            # ---- symbolic address or length: ask the solver whether a violation is possible
            if not write and not sym_addr:
                return                    # symbolic-length reads are libc model internals
            try:
                # Region classification needs ONE feasible address; the violation itself is a
                # separate satisfiable() query. min() is a ~70-query binary search, and reads are
                # ~90% of oracle calls, so they take a single eval. Writes keep min(): it picks the
                # innermost frame above the write for the saved-return-address check.
                a_lo = s.solver.min(addr) if write else s.solver.eval(addr)
            except Exception:
                return
            end = addr + ln_ast
            if write and self.x86:
                for sp, ra, fa in self._frames(s):
                    if sp < a_lo:
                        continue
                    conds.append(("stack-write",
                                  claripy.And(claripy.ULE(addr, sp), claripy.UGT(end, sp)),
                                  f"overwrites the saved return address of {self._fname(fa)} "
                                  f"(slot {sp:#x})", sp))
                    break                 # the innermost frame above the write is the one it smashes
            if self._is_stack(s, a_lo):
                objs = self._stack_objects(s)
                gb = self._const_base(addr) if sym_addr else a_lo
                o = self._obj_at(objs, gb) if gb is not None else None
                if o is not None:
                    olo, ohi = o[0], o[1]
                    if sym_addr:
                        cond = claripy.Or(claripy.ULT(addr, olo), claripy.UGT(end, ohi))
                        # the nearest out-of-bounds access: the natural PoC, and inside the
                        # redzone a sanitizer build actually checks (a far index skips it)
                        near = claripy.Or(claripy.And(claripy.UGE(addr, ohi), claripy.ULT(addr, ohi + 32)),
                                          claripy.And(claripy.ULT(addr, olo), claripy.UGE(addr, olo - 32)))
                        why = (f"{'writes' if write else 'reads'} outside local '{o[2]}' "
                               f"({ohi - olo} bytes) of {o[3]} at an input-controlled index")
                    else:
                        cond, near = claripy.UGT(end, ohi), None
                        why = (f"{'writes' if write else 'reads'} past the end of local '{o[2]}' "
                               f"({ohi - olo} bytes) of {o[3]} (length from input)")
                    conds.append(("stack-write" if write else "stack-read", cond, why, olo, near, "obj"))
            if chunks and not self._is_stack(s, a_lo):
                base = self._chunk_for(chunks, a_lo)
                if base is not None:
                    size, freed = chunks[base]
                    if isinstance(size, int):
                        size = claripy.BVV(size, self.arch_bits)
                    if size.size() < self.arch_bits:
                        size = size.zero_extend(self.arch_bits - size.size())
                    if freed:
                        conds.append(("use-after-free", claripy.UGE(addr, base),
                                      f"{'writes' if write else 'reads'} chunk {base:#x} after free()",
                                      base))
                    else:
                        near = claripy.ULT(addr, base + size + 32) if sym_addr else None
                        conds.append(("heap-write" if write else "heap-read",
                                      claripy.And(claripy.UGE(addr, base), claripy.UGT(end, base + size)),
                                      f"{'writes' if write else 'reads'} past the end of the chunk "
                                      f"allocated at {base:#x}", base, near))
            if not sym_addr and not self._is_stack(s, a_lo):
                obj = self._gobj(a_lo)
                if obj is not None:
                    lo_, hi_, name = obj
                    conds.append(("global-write" if write else "global-read",
                                  claripy.UGT(end, hi_),
                                  f"{'writes' if write else 'reads'} past the end of global "
                                  f"'{name}' [{lo_:#x},{hi_:#x})", lo_))
            if sym_addr:
                gb = self._const_base(addr)
                obj = self._gobj(gb) if gb is not None else None
                if obj is not None:
                    lo_, hi_, name = obj
                    near = claripy.Or(claripy.And(claripy.UGE(addr, hi_), claripy.ULT(addr, hi_ + 32)),
                                      claripy.And(claripy.ULT(addr, lo_), claripy.UGE(addr, lo_ - 32)))
                    conds.append(("global-write" if write else "global-read",
                                  claripy.Or(claripy.ULT(addr, lo_), claripy.UGT(end, hi_)),
                                  f"{'writes' if write else 'reads'} outside global '{name}' "
                                  f"[{lo_:#x},{hi_:#x}) at an input-controlled index", lo_, near))
                elif self._is_stack(s, a_lo) and not any(len(c) > 5 and c[5] == "obj" for c in conds):
                    fr = self._frames(s)
                    if fr:
                        sp0 = fr[0][0]
                        cur_sp = s.solver.eval(s.regs.sp)
                        conds.append(("stack-write" if write else "stack-read",
                                      claripy.Or(claripy.ULT(addr, cur_sp - 0x1000),
                                                 claripy.UGE(end, sp0 + self.word)),
                                      f"{'writes' if write else 'reads'} outside the current stack "
                                      f"frame at an input-controlled index", sp0))
        if not conds:
            return
        if site is None:
            site = self._site_for(s)
        for c in conds:
            kind, cond, why, key = c[:4]
            near = c[4] if len(c) > 4 else None
            is_obj = len(c) > 5 and c[5] == "obj"
            hid = f"{kind}@{site:#x}" if site is not None else f"{kind}@?"
            h = self.hyps.get(hid)
            if h is not None and (len(h["solutions"]) >= 2 or h.get("saturated")):
                continue
            extra = [] if cond is None else [cond]
            if cond is not None and not s.solver.satisfiable(extra_constraints=extra):
                self.stats["unsat_checks"] += 1
                continue
            if near is not None and s.solver.satisfiable(extra_constraints=extra + [near]):
                extra = extra + [near]
            elif kind == "stack-write" and cond is not None and not is_obj:
                strong = claripy.UGE(addr + ln_ast, key + self.word)
                if s.solver.satisfiable(extra_constraints=extra + [strong]):
                    extra = extra + [strong]
            self.violation(s, kind, site, why, extra=extra)

    def _const_base(self, ast):
        """The constant term of an address expression like base + idx*scale (best effort)."""
        try:
            if ast.op == "__add__":
                consts = [a for a in ast.args if not a.symbolic]
                if consts:
                    return sum(self.angr.claripy.backends.concrete.convert(c).value for c in consts) \
                        if False else sum(c.concrete_value for c in consts) % (1 << ast.size())
                for a in ast.args:
                    r = self._const_base(a)
                    if r is not None:
                        return r
            if ast.op == "__sub__":
                return self._const_base(ast.args[0])
        except Exception:
            return None
        return None

    def _fname(self, fa):
        try:
            return self.cfg.kb.functions.function(addr=fa).name
        except Exception:
            return hex(fa)

    def violation(self, s, kind, site, why, extra=()):
        """A violation that is satisfiable on this path: solve it to concrete input bytes."""
        if site is None:
            site = self._site_for(s)
        hid = f"{kind}@{site:#x}" if site is not None else f"{kind}@?"
        h = self.hyps.get(hid)
        if h is None:
            f = self.func_of(site) if site is not None else None
            h = {"id": hid, "kind": kind, "cwe": CWE.get(kind), "site": site, "block": None,
                 "func": f.name if f else None, "func_addr": f.addr if f else None,
                 "callee": None, "status": "proposed", "reached": 1, "solutions": [],
                 "note": "found by the access oracle during exploration", "triggered_by": []}
            self.hyps[hid] = h
        if len(h["solutions"]) >= 3:
            return
        self.stats["violations"] += 1
        sol = self.solve(s, list(extra), hid)
        if sol is not None:
            sol["detail"] = why
            h["solutions"].append(sol)
            h["status"] = "solved"
            self._mark_directing_solved(site)

    def _mark_directing_solved(self, site):
        changed = False
        for h in self.hyps.values():
            if h["site"] == site and h["kind"] in ("copy", "store") and not h.get("saturated"):
                h["saturated"] = True
                h["status"] = h["status"] if h["status"] == "solved" else "violation-elsewhere"
                changed = True
        if changed:
            self._recompute_dmin()

    def solve(self, s, extra, hid, values=None):
        excl = self.exclude.get(hid, set())
        cons = list(extra)
        for b in excl:
            if len(b) == self.inp_len:
                cons.append(self.inp != self.claripy.BVV(b))
        try:
            if not s.solver.satisfiable(extra_constraints=cons):
                return None
            data = s.solver.eval(self.inp, cast_to=bytes, extra_constraints=cons)
        except Exception:
            return None
        if self.spec.get("input_mode") == "arg":
            data = data.split(b"\0")[0]
        out = {"input_b64": base64.b64encode(data).decode(), "values": values or {},
               "t": round(time.time() - self.t0, 2)}
        return out

    # ------------------------------------------------------------------ sink checks at calls
    def at_call(self, s):
        """Called for a state that just entered a callee from a proposed sink call site."""
        try:
            if s.history.jumpkind != "Ijk_Call":
                return
            src = s.history.jump_source
        except Exception:
            return
        if src is None:
            return
        h_any = None
        for kind in ("format-string", "cmd-injection", "int-overflow-alloc", "copy"):
            h = self.hyps.get(f"{kind}@{src:#x}")
            if h is None:
                continue
            h_any = h
            h["reached"] += 1
            if h["status"] == "proposed":
                h["status"] = "reached"
            if h["solutions"] or h.get("saturated"):
                continue
            if kind == "format-string":
                self._check_fmt(s, h)
            elif kind == "cmd-injection":
                self._check_cmd(s, h)
            elif kind == "int-overflow-alloc":
                self._check_alloc(s, h)
            if kind != "copy" and h["reached"] > self.SATURATE_REACHES and not h["solutions"]:
                # reached over and over and never violable (a constant format string, a fixed
                # command): stop steering the search toward it
                h["saturated"] = True
                self._recompute_dmin()
        # copy sinks: check the write the call is about to do, then pin a symbolic size to one
        # feasible in-bounds value for the rest of this path (keeps the libc model from building a
        # max_memcpy_size-wide conditional store that every later solver query pays for)
        hc = self.hyps.get(f"copy@{src:#x}")
        if hc is not None:
            self._copy_call(s, hc)
            if hc["reached"] > self.SATURATE_REACHES and not hc["solutions"] and not hc.get("saturated"):
                hc["saturated"] = True
                self._recompute_dmin()
        return h_any

    SATURATE_REACHES = 24

    # dst arg index, size expression builder
    COPY_SIZE = {"memcpy": (0, lambda a: a(2)), "memmove": (0, lambda a: a(2)),
                 "__memcpy_chk": (0, lambda a: a(2)), "memset": (0, lambda a: a(2)),
                 "strncpy": (0, lambda a: a(2)), "read": (1, lambda a: a(2)),
                 "__read_chk": (1, lambda a: a(2)), "pread": (1, lambda a: a(2)),
                 "recv": (1, lambda a: a(2)), "recvfrom": (1, lambda a: a(2)),
                 "fgets": (0, lambda a: a(1)), "bcopy": (1, lambda a: a(2)),
                 "fread": (0, lambda a: a(1) * a(2))}

    def _copy_call(self, s, h):
        spec = self.COPY_SIZE.get(h["callee"])
        if spec is None:
            return
        try:
            dst = self._arg(s, spec[0])
            n = spec[1](lambda i: self._arg(s, i))
        except Exception:
            return
        if s.solver.symbolic(dst):
            return
        sym_n = s.solver.symbolic(n)
        if not h.get("saturated"):
            before = len(self.hyps)
            self._check_access(s, dst, n, write=True, site=h["site"])
            del before
        if sym_n:
            claripy = self.claripy
            d = s.solver.eval(dst)
            cap = None
            for sp, ra, fa in self._frames(s):
                if sp > d:
                    cap = sp - d
                    break
            pick = None
            if cap is not None:
                lim = claripy.ULE(n, cap)
                if s.solver.satisfiable(extra_constraints=[lim]):
                    pick = s.solver.max(n, extra_constraints=[lim])
            if pick is None:
                try:
                    pick = s.solver.min(n)
                except Exception:
                    return
            s.add_constraints(n == pick)

    def _arg(self, s, i):
        cc = self.angr.calling_conventions.default_cc(self.p.arch.name)
        regs = list(getattr(cc, "ARG_REGS", []) or [])
        if i < len(regs):
            return getattr(s.regs, regs[i])
        # stack args: return address at [sp] on x86 after the call
        off = (i - len(regs) + (1 if self.x86 else 0)) * self.word
        return s.memory.load(s.regs.sp + off, self.word, endness=s.arch.memory_endness, inspect=False)

    def _input_bytes_at(self, s, ptr, maxlen=512):
        """(byte ASTs, index of first byte carrying input) for the C string at ptr."""
        out = []
        first_sym = None
        for k in range(maxlen):
            b = s.memory.load(ptr + k, 1, inspect=False)
            out.append(b)
            if b.symbolic:
                if first_sym is None and any(v.startswith("input") for v in b.variables):
                    first_sym = k
            elif s.solver.eval(b) == 0:
                break
        return out, first_sym

    def _check_fmt(self, s, h):
        fmt = self._arg(s, FMT_SINKS[h["callee"]])
        try:
            bs, first = self._input_bytes_at(s, fmt)
        except Exception:
            return
        if first is None:
            return
        claripy = self.claripy
        for pay in FMT_PAYLOADS:
            for start in range(first, min(first + 8, len(bs))):
                if start + len(pay) > len(bs):
                    break
                cond = claripy.And(*[bs[start + t] == pay[t] for t in range(len(pay))])
                if s.solver.satisfiable(extra_constraints=[cond]):
                    self.violation(s, "format-string", h["site"],
                                   f"input bytes reach the format argument of {h['callee']}(); "
                                   f"payload {pay.decode()} interpreted as conversions", extra=[cond])
                    if self.hyps.get(f"format-string@{h['site']:#x}", {}).get("solutions"):
                        return

    def _check_cmd(self, s, h):
        cmd = self._arg(s, CMD_SINKS[h["callee"]])
        try:
            bs, first = self._input_bytes_at(s, cmd)
        except Exception:
            return
        if first is None:
            return
        claripy = self.claripy
        for pay in self._cmd_payloads(s, bs, first):
            for start in range(first, len(bs) - len(pay) + 1):
                if not all(bs[start + t].symbolic for t in range(len(pay))):
                    continue
                cond = claripy.And(*[bs[start + t] == pay[t] for t in range(len(pay))])
                if s.solver.satisfiable(extra_constraints=[cond]):
                    self.violation(s, "cmd-injection", h["site"],
                                   f"input bytes reach the command string of {h['callee']}(); "
                                   f"injected '{pay.decode().strip()}' runs as a shell command",
                                   extra=[cond])
                    return

    def _cmd_payloads(self, s, bs, first):
        """Payloads for the shell quoting context where input starts. `grep -w '%s'` puts input
        inside single quotes, where `;id;#` is inert text: the payload must close the quote."""
        quote, esc = None, False
        for b in bs[:first]:
            if b.symbolic:
                break
            c = chr(s.solver.eval(b))
            if esc:
                esc = False
            elif c == "\\" and quote != "'":
                esc = True
            elif quote is None and c in "'\"":
                quote = c
            elif c == quote:
                quote = None
        if quote is None:
            return CMD_PAYLOADS
        q = quote.encode()
        own = [q + p for p in CMD_PAYLOADS if not p.startswith(b"\n")]
        if quote == '"':
            own += [b"$(id)", b"`id`"]   # substitutions still run inside double quotes
        return own

    def _check_alloc(self, s, h):
        claripy = self.claripy
        size = self._arg(s, ALLOC_SINKS[h["callee"]])
        if not size.symbolic:
            return
        conds = []

        def walk(e, depth=0):
            if depth > 12 or not hasattr(e, "op"):
                return
            if e.op in ("__mul__", "__add__", "__lshift__") and len(e.args) == 2 and e.symbolic:
                a, b = e.args
                w = e.size()
                if e.op == "__mul__":
                    conds.append(claripy.UGT(a.zero_extend(w) * b.zero_extend(w), (1 << w) - 1))
                elif e.op == "__add__":
                    conds.append(claripy.UGT(a.zero_extend(1) + b.zero_extend(1), (1 << w) - 1))
            for k in getattr(e, "args", ()):
                if hasattr(k, "op"):
                    walk(k, depth + 1)
        walk(size)
        for c in conds:
            if s.solver.satisfiable(extra_constraints=[c]):
                self.violation(s, "int-overflow-alloc", h["site"],
                               f"the size passed to {h['callee']}() wraps around: the allocation is "
                               f"smaller than the data written into it", extra=[c])
                return

    # ------------------------------------------------------------------ explore
    def explore(self):
        angr = self.angr
        st = self.initial_state()
        # Any exception while stepping one state (angr's stock libc models raise IndexError /
        # TypeError on unusual arguments) drops THAT state, never the whole run. Deadline and
        # the memory guard are BaseException-based and still propagate.
        sm = self.p.factory.simulation_manager(st, save_unconstrained=True,
                                               resilience=(Exception,))
        width = int(self.spec.get("width", 24))
        max_states = int(self.spec.get("max_states", 2000))
        deadline = self.t0 + float(self.spec.get("max_seconds", 120))
        sm.stashes.setdefault("deferred", [])
        while time.time() < deadline:
            if not sm.active:
                if not sm.deferred:
                    self.stats["drained"] = True
                    break
                sm.deferred.sort(key=self.score)
                sm.stashes["active"] = sm.deferred[:width]
                sm.stashes["deferred"] = sm.deferred[width:]
            for s in sm.active:
                self.visits[s.addr] = self.visits.get(s.addr, 0) + 1
            _ts = time.time()
            _addrs = [hex(x.addr) for x in sm.active[:6]]
            sm.step()
            self.stats["steps"] += 1
            if self.spec.get("verbose") and time.time() - _ts > 2:
                print(f"[hyp] slow step {time.time()-_ts:.1f}s at {_addrs} rss={_rss_mb()}MB "
                      f"active={len(sm.active)} deferred={len(sm.deferred)}", file=sys.stderr, flush=True)
            if self.stats["steps"] % 50 == 0 and self.spec.get("verbose"):
                solved = sum(1 for h in self.hyps.values() if h["solutions"])
                print(f"[hyp] t={time.time()-self.t0:.0f}s steps={self.stats['steps']} "
                      f"active={len(sm.active)} deferred={len(sm.deferred)} solved={solved}",
                      file=sys.stderr, flush=True)
            for s in sm.active:
                self._guarded(self.at_call, s)
            for s in list(sm.unconstrained):
                self._guarded(self._hijack, s)
            sm.stashes["unconstrained"] = []
            for e in sm.errored:
                key = f"{type(e.error).__name__}@{e.state.addr:#x}"
                errs = self.stats.setdefault("errored", {})
                errs[key] = errs.get(key, 0) + 1
            sm.stashes["errored"] = []
            sm.stashes["deadended"] = []
            pool = sm.active + sm.deferred
            if self.dmin is not None:
                pool.sort(key=self.score)
            if len(pool) > max_states:
                pool = pool[:max_states]
            # States that can still reach an open hypothesis get the active slots. States that
            # cannot (score >= INF) get at most a sixth of them while any directed state exists:
            # stepping them costs every directed lineage time (a 17-iteration loop bug starved
            # behind 20+ such states). With no directed state left, explore freely for the oracles.
            directed = [x for x in pool if self.score(x) < INF] if self.dmin else []
            if directed:
                act = directed[:width]
                spare = max(2, width // 6) if len(act) < width else 0
                rest = [x for x in pool if self.score(x) >= INF]
                act += rest[:spare]
                ids = {id(x) for x in act}
                sm.stashes["active"] = act
                sm.stashes["deferred"] = [x for x in pool if id(x) not in ids]
            else:
                sm.stashes["active"] = pool[:width]
                sm.stashes["deferred"] = pool[width:]
            if all((h["solutions"] or h.get("saturated")) for h in self.hyps.values()
                   if h["kind"] in ("copy", "store", "format-string", "cmd-injection", "int-overflow-alloc")) \
                    and self.hyps:
                # every directing target settled: keep going only for oracle finds until drained
                if not sm.deferred and not sm.active:
                    break

    def _guarded(self, fn, s):
        """A solver query that hits the per-query time/memory bound is an unknown, not a crash:
        skip that one check and keep exploring."""
        try:
            fn(s)
        except self.claripy.errors.ClaripyError:
            self.stats["solver_giveups"] = self.stats.get("solver_giveups", 0) + 1

    def _hijack(self, s):
        claripy = self.claripy
        mark = HIJACK_MARK.get(self.arch_bits, 0x41414141)
        site = None
        try:
            site = s.history.jump_source
        except Exception:
            pass
        cond = s.regs.ip == mark
        if s.solver.satisfiable(extra_constraints=[cond]):
            self.violation(s, "control-flow-hijack", site,
                           f"the instruction pointer is loaded from input (set here to {mark:#x})",
                           extra=[cond])


def main(spec_path, out_path):
    res = {"ok": False, "hypotheses": [], "stats": {}}
    try:
        import angr
        import claripy
        import logging
        logging.getLogger("angr").setLevel(logging.ERROR)
        logging.getLogger("cle").setLevel(logging.ERROR)
        logging.getLogger("pyvex").setLevel(logging.ERROR)
        res["angr_version"] = getattr(angr, "__version__", "?")
    except Exception as e:      # noqa: BLE001
        res["error"] = f"angr unavailable: {e}"
        _write(out_path, res)
        return 2
    spec = json.load(open(spec_path))
    rss_cap = int(spec.get("max_rss_mb", 8192))
    _bound_solver(spec, rss_cap)
    drv = Driver(angr, claripy, spec)
    _start_mem_guard(drv, res, out_path, rss_cap)
    signal.signal(signal.SIGALRM, _alarm)
    signal.signal(signal.SIGTERM, _alarm)
    signal.alarm(int(spec.get("max_seconds", 120)) + 30)
    try:
        drv.load()
        drv.propose()
        drv.distances()
        res["stats"]["proposed"] = len(drv.hyps)
        res["stats"]["t_setup"] = round(time.time() - drv.t0, 2)
        try:
            drv.explore()
        except Deadline:
            res["stats"]["cutoff"] = True
        res["ok"] = True
    except Deadline:
        res["ok"] = bool(drv.hyps)
        res["stats"]["cutoff"] = True
    except Exception as e:      # noqa: BLE001
        res["error"] = f"{type(e).__name__}: {e}"
        res["trace"] = traceback.format_exc()[-2000:]
    finally:
        signal.alarm(0)
    _dump(drv, res, out_path)
    return 0


def _dump(drv, res, out_path):
    out = []
    for h in list(drv.hyps.values()):
        hh = dict(h)
        hh.pop("triggered_by", None)
        for k in [k for k in hh if k.startswith("_")]:
            hh.pop(k)
        hh["site"] = f"{h['site']:#x}" if isinstance(h.get("site"), int) else None
        hh["block"] = f"{h['block']:#x}" if isinstance(h.get("block"), int) else None
        hh["func_addr"] = f"{h['func_addr']:#x}" if isinstance(h.get("func_addr"), int) else None
        out.append(hh)
    res["hypotheses"] = out
    mo = getattr(drv, "main_obj", None)
    if mo is not None:      # lets a caller map sites back to file addresses (PIE is rebased)
        res["image"] = {"mapped_base": mo.mapped_base, "linked_base": mo.linked_base,
                        "pic": bool(mo.pic)}
    res["stats"].update(drv.stats)
    res["stats"]["t_total"] = round(time.time() - drv.t0, 2)
    _write(out_path, res)


def _bound_solver(spec, rss_cap_mb):
    """Give every claripy solver a per-query timeout (claripy's default is 5 minutes, so one hard
    query can eat a whole budget) and cap z3's heap. Past the bound z3 returns unknown, claripy
    raises ClaripySolverInterruptError, and that one check is skipped."""
    import z3
    from claripy.frontend.full_frontend import FullFrontend
    timeout = int(spec.get("solver_timeout_ms", 10000))
    # z3 counts its WHOLE heap (every cached AST of every state) against this, not one query,
    # so it sits at the RSS cap: it only stops z3 from overrunning the cap on its own.
    z3.set_param("memory_max_size", int(spec.get("solver_max_mb", rss_cap_mb)))
    orig = FullFrontend.__init__

    def init(self, solver_backend, timeout_=None, max_memory=None, **kw):
        timeout_ = kw.pop("timeout", timeout_)
        orig(self, solver_backend, timeout=timeout if timeout_ is None else timeout_,
             max_memory=max_memory, **kw)

    FullFrontend.__init__ = init


def _rss_mb():
    try:
        with open("/proc/self/statm") as fh:
            return int(fh.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") // (1 << 20)
    except (OSError, ValueError, IndexError):
        return 0


def _start_mem_guard(drv, res, out_path, cap_mb):
    """Hard RSS cap. Symbolic execution can grow by tens of GB inside a single z3 call, where no
    Python-level check runs, and an unbounded run gets the whole desktop session OOM-killed. A
    polling thread catches it within ~0.5s, writes what was found so far, and exits."""
    import threading

    def watch():
        n = 0
        while True:
            time.sleep(0.5)
            n += 1
            rss = _rss_mb()
            drv.stats["peak_rss_mb"] = max(drv.stats.get("peak_rss_mb", 0), rss)
            if drv.spec.get("verbose") and n % 4 == 0:
                print(f"[hyp] mem t={time.time()-drv.t0:.0f}s rss={rss}MB steps={drv.stats['steps']}",
                      file=sys.stderr, flush=True)
            if rss > cap_mb:
                res["stats"]["mem_cutoff"] = True
                res["error"] = f"memory cap hit: rss {rss} MB > max_rss_mb {cap_mb}"
                try:
                    _dump(drv, res, out_path)
                except Exception:   # noqa: BLE001 - racing the main thread; the exit matters most
                    _write(out_path, {"ok": False, "hypotheses": [], "stats": {"mem_cutoff": True},
                                      "error": res["error"]})
                os._exit(3)

    threading.Thread(target=watch, name="hyp-mem-guard", daemon=True).start()
    # No RLIMIT_AS backstop: z3 and angr's native code abort the whole process (SIGABRT, no
    # output) when an allocation fails, and virtual size runs far ahead of RSS. The hard cap
    # belongs to the caller's cgroup (systemd-run --scope -p MemoryMax=..., as the bench does).


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
