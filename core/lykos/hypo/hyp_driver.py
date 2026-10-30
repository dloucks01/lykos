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
           solver_timeout_ms (default 10000), solver_max_mb (default min(4096, max_rss_mb/2))
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

        for name, cls in (("snprintf", BoundedSnprintf), ("sprintf", BoundedSprintf),
                          ("memset", BoundedMemset), ("__memset_chk", BoundedMemsetChk)):
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
        if mode == "arg":
            for k in range(n):
                st.solver.add(self.inp.get_byte(k) != 0)
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
            self._check_access(s, addr, ln, write=True)
        except Deadline:
            raise
        except self.claripy.errors.ClaripyError:
            self.stats["solver_giveups"] = self.stats.get("solver_giveups", 0) + 1
        except Exception:
            pass

    def _on_read(self, s):
        try:
            addr = s.inspect.mem_read_address
            if addr is None:
                return
            ln = s.inspect.mem_read_length
            if ln is None:
                ln = 1
            sym = s.solver.symbolic(addr)
            if not sym and not s.globals.get("chunks"):
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
                        conds.append(("heap-write" if write else "heap-read",
                                      claripy.And(claripy.UGE(addr, base), claripy.UGT(end, base + size)),
                                      f"{'writes' if write else 'reads'} past the end of the chunk "
                                      f"allocated at {base:#x}", base))
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
                    conds.append(("global-write" if write else "global-read",
                                  claripy.Or(claripy.ULT(addr, lo_), claripy.UGT(end, hi_)),
                                  f"{'writes' if write else 'reads'} outside global '{name}' "
                                  f"[{lo_:#x},{hi_:#x}) at an input-controlled index", lo_))
                elif self._is_stack(s, a_lo):
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
        for kind, cond, why, key in conds:
            hid = f"{kind}@{site:#x}" if site is not None else f"{kind}@?"
            h = self.hyps.get(hid)
            if h is not None and (len(h["solutions"]) >= 2 or h.get("saturated")):
                continue
            extra = [] if cond is None else [cond]
            if cond is not None and not s.solver.satisfiable(extra_constraints=extra):
                self.stats["unsat_checks"] += 1
                continue
            if kind == "stack-write" and cond is not None:
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
        # copy sinks: check the write the call is about to do, then pin a symbolic size to one
        # feasible in-bounds value for the rest of this path (keeps the libc model from building a
        # max_memcpy_size-wide conditional store that every later solver query pays for)
        hc = self.hyps.get(f"copy@{src:#x}")
        if hc is not None:
            self._copy_call(s, hc)
            if h["reached"] > 40 and not h["solutions"]:
                h["saturated"] = True
                self._recompute_dmin()
        return h_any

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
        for pay in CMD_PAYLOADS:
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
        sm = self.p.factory.simulation_manager(st, save_unconstrained=True)
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
            sm.stashes["errored"] = []
            sm.stashes["deadended"] = []
            pool = sm.active + sm.deferred
            if self.dmin is not None:
                pool.sort(key=self.score)
            if len(pool) > max_states:
                pool = pool[:max_states]
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
    """Give every claripy solver a per-query timeout and a z3 memory limit. claripy's defaults are
    a 5-minute timeout and no memory limit, and a single bad query (a long ITE chain from a parsing
    loop) has grown z3 from ~400MB to 116GB in seconds -- too fast for any polling guard. Past the
    bound z3 returns unknown, claripy raises ClaripySolverInterruptError, and the check is skipped."""
    import z3
    from claripy.frontend.full_frontend import FullFrontend
    timeout = int(spec.get("solver_timeout_ms", 10000))
    max_mb = int(spec.get("solver_max_mb", max(512, min(4096, rss_cap_mb // 2))))
    z3.set_param("memory_max_size", max_mb)     # process-wide backstop (covers simplify etc.)
    orig = FullFrontend.__init__

    def init(self, solver_backend, timeout_=None, max_memory=None, **kw):
        timeout_ = kw.pop("timeout", timeout_)
        orig(self, solver_backend,
             timeout=timeout if timeout_ is None else timeout_,
             max_memory=max_mb if max_memory is None else max_memory, **kw)

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
    # The thread cannot run while one C call holds the GIL (a giant list multiply did exactly
    # that). An address-space limit turns such an allocation into a MemoryError instead.
    try:
        import resource
        lim = (2 * cap_mb + 4096) << 20
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        if soft == resource.RLIM_INFINITY or soft > lim:
            resource.setrlimit(resource.RLIMIT_AS, (lim, hard))
    except (ImportError, ValueError, OSError):
        pass


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
