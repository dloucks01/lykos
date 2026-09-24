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
    alloc = heaptrace.identify_allocator(functions, edges)
    if not alloc:
        ctx.emit("heaptrace.done", payload={"applicable": False,
                 "note": "no distinct custom allocator found (libc malloc/free is covered by "
                         "heap_check); nothing to trace"})
        ctx.progress(pct=100, msg="no custom allocator to trace")
        return {}

    workdir = Path(tempfile.mkdtemp(prefix="lykos-heaptrace-"))
    sandbox.protect_dir(getattr(ctx.content, "root", None))
    try:
        exe = workdir / "target.bin"
        exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
        os.chmod(exe, 0o755)
        helper = workdir / "heaptrace.py"
        helper.write_bytes(_HELPER.read_bytes())

        pie = (target.mitigations or {}).get("pie") == "on"
        ret_offs = _alloc_ret_offsets(exe, alloc["alloc_name"])
        strings = [x.value for x in StringDAO(ctx.conn).list_by_target(target.id)
                   if getattr(x, "value", None)]
        opts = menu.detect_menu(strings)
        seqs = heaptrace.heap_op_sequences(opts) or [
            b"1\n64\nA\n2\n0\n2\n0\n", b"1\n2\n2\n"]     # generic create-then-double-free fallback
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
                "report": str(report), "timeout": 8}))
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
            if rep.get("double_free"):
                found = (seq, rep)
                break

        if not found:
            ctx.emit("heaptrace.done", payload={
                "applicable": True, "double_free": False, "allocator": alloc["alloc_name"],
                "note": (f"traced the target's own allocator ({alloc['alloc_name']}/"
                         f"{alloc['free_name']}) over {len(seqs)} operation sequences; no double-free "
                         "surfaced. A UAF/overflow may still exist (this pass proves double-free "
                         "only) -- and the menu semantics may need analyst-supplied op sequences.")})
            ctx.progress(pct=100, msg="no double-free surfaced on the custom allocator")
            return {"metrics": {"applicable": True, "double_free": False}}

        seq, rep = found
        input_sha = ctx.put_artifact("heap-op-sequence", data=seq)
        detail = (f"double-free (CWE-415) discovered on the target's own allocator "
                  f"{alloc['alloc_name']}/{alloc['free_name']}: the traced sequence freed a chunk "
                  f"that was already free. Seeds tcache poisoning -> arbitrary write. "
                  f"(op sequence {input_sha[:12]})")
        FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
            "cwe": "CWE-415", "title": "Double free", "severity": "high",
            "detector": "heap_trace", "state": "corroborated", "confidence": 0.85,
            "dedup_key": f"CWE-415:heaptrace:{alloc['free_name']}",
            "function_addr": alloc["free"], "site_addr": None, "site_detail": alloc["free_name"],
            "evidence": [{"channel": "heap-trace", "detail": detail}]})
        ctx.emit("heaptrace.done", payload={
            "applicable": True, "double_free": True, "allocator": alloc["alloc_name"],
            "input_sha": input_sha,
            # the aaheg chainer consumes this Vuln shape (vclass double_free -> tcache-poison chain)
            "vuln": {"vclass": "double_free", "note": f"{alloc['alloc_name']}/{alloc['free_name']}"}})
        ctx.progress(pct=100, msg=f"double-free discovered on {alloc['free_name']}")
        return {"metrics": {"double_free": True}, "output_shas": [input_sha]}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def register() -> None:
    register_stage(HEAP_TRACE_STAGE, heap_trace_stage, resource_class="cpu",
                   tool="ptrace", tool_version="1")


def enqueue_heap_trace(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, HEAP_TRACE_STAGE, target_id=target.id,
                         params=params or {}, force=force)
