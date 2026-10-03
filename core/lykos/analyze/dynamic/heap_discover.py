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
    """Fixed-width input width W, or None for a line-based target. A target that reads scalars with
    `read(0, buf, W)` (not fgets/gets/scanf) consumes exactly W bytes per field regardless of
    newlines, so the driver must pad each field to W. Detected from constant `mov edx, imm` lengths
    immediately before `read@plt` calls, when no line reader (fgets/gets/scanf) is present."""
    if not shutil.which("objdump"):
        return None
    try:                                                 # -M intel: match `mov edx,0xN` operands
        out = subprocess.run(["objdump", "-d", "--no-show-raw-insn", "-M", "intel", str(exe)],
                             capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    if re.search(r"<(fgets|gets|__isoc99_scanf|scanf|fscanf|getline)@plt>", out):
        return None                                      # a line reader -> line-based
    from collections import Counter
    widths: Counter = Counter()
    prev_edx = None
    for ln in out.splitlines():
        m = re.search(r"mov\s+edx,0x([0-9a-fA-F]+)", ln)
        if m:
            prev_edx = int(m.group(1), 16)
        elif "<read@plt>" in ln and "call" in ln and prev_edx in (1, 2, 3, 4, 8, 16):
            widths[prev_edx] += 1
        elif "call" in ln:
            prev_edx = None                              # a different call clobbers edx
    return widths.most_common(1)[0][0] if widths else None


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
        cmd = sandbox.isolate_prefix(str(workdir), net=False, rw_binds=[str(workdir)]) + [str(exe)]
        return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, cwd=str(workdir),
                                preexec_fn=sandbox._rlimits(2048, 20, set_as=False))
    try:
        return menu.crawl_menu(spawn, opts, per_option=2.5, width=width)
    except Exception:
        return {}


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
    opts = menu.detect_menu(strings)
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
