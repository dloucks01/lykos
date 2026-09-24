"""Out-of-bounds array-index discovery stage.

A menu service that stores objects in a FIXED-SIZE global table (`authors[10]`) and selects one by a
user-supplied id is a classic CWE-129 shape: the id is validated against the wrong bound (only an
upper bound, or an off-by-one, or -- auth-or-out -- no lower bound, so id 0 indexes `authors[-1]`),
and the code then reads a pointer / writes a field through that out-of-bounds slot. `heap_trace`
finds allocator-lifecycle bugs; this stage finds the INDEX bug.

It arms a hardware read/write watchpoint on the guard word just before and just after each
fixed-size global array, then drives every index-taking menu option with boundary indices (0,
capacity, capacity+1). A guard access from program code proves the index escaped the array -- an
unchecked array index. Native x86-64 / ELF only; deterministic; reuses the heaptrace ptrace helper
in its static-watch mode."""
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
from .heap_discover import _crawl_menu_model, _read_width

OOB_INDEX_STAGE = "oob_index"
_HELPER = Path(__file__).with_name("heaptrace.py")
_WORD = 8


def _array_candidates(objects: dict) -> list[dict]:
    """Fixed-size global arrays worth guarding: a word-multiple OBJECT of at least two elements
    (a pointer/handle table). Scalars (size 8) and oversized blobs are skipped."""
    out = []
    for name, (addr, size) in (objects or {}).items():
        if "@" in name or size % _WORD or not (2 * _WORD <= size <= (1 << 20)):
            continue
        out.append({"name": name, "addr": addr, "size": size, "cap": size // _WORD,
                    "stride": _WORD})
    out.sort(key=lambda a: -a["size"])
    return out[:8]


def _data_ranges(exe: Path) -> list[tuple[int, int]]:
    """[start, end) virtual ranges of the writable global sections (.data/.bss), so an indexed
    displacement can be recognised as a global-array base."""
    if not shutil.which("objdump"):
        return []
    try:
        out = subprocess.run(["objdump", "-h", str(exe)], capture_output=True, text=True,
                             timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    ranges = []
    for ln in out.splitlines():
        p = ln.split()
        if len(p) >= 5 and p[1] in (".data", ".bss"):
            try:
                size, vma = int(p[2], 16), int(p[3], 16)
            except ValueError:
                continue
            if size:
                ranges.append((vma, vma + size))
    return ranges


# an indexed global access: `[... reg*scale + 0xDISP]` (mov rax,[rax*8+0x6020c0]) -- the DISP is the
# array base, scale the element stride. Intel syntax (objdump -M intel). Non-PIE (absolute base).
_IDX_ACCESS = re.compile(r"\*([1248])\+0x([0-9a-fA-F]+)\]")
# a PIE global base: `lea reg,[rip+0x..]  # <vaddr>` -- objdump computes the target vaddr in the
# comment even when stripped. A table's stride is not on this line, so assume a pointer table.
_LEA_RIP = re.compile(r"\blea\s+\w+,\[rip[+-]0x[0-9a-fA-F]+\]\s*#\s*([0-9a-fA-F]+)")


def _array_candidates_symfree(exe: Path) -> list[dict]:
    """Fixed-size global arrays recovered from the DISASSEMBLY when the binary is stripped: a data
    displacement indexed by a scaled register (`[reg*scale + base]`). The exact element count is not
    in the binary, so the capacity is estimated from the gap to the next global base (bounded by a
    default); the before-guard (base - stride) catches the dominant underflow regardless. A non-PIE
    base is an absolute displacement; a PIE base comes from objdump's computed `lea rip` comment
    (the tracer rebases the guard via /proc/maps)."""
    if not shutil.which("objdump"):
        return []
    try:
        out = subprocess.run(["objdump", "-d", "--no-show-raw-insn", "-M", "intel", str(exe)],
                             capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return _candidates_from_disasm(out, _data_ranges(exe))


def _candidates_from_disasm(disasm: str, ranges: list) -> list[dict]:
    """Pure: indexed data accesses in `disasm` -> array candidates, given writable-section ranges.
    The capacity is estimated from the gap to the next global base (underflow guard is exact)."""
    if not ranges:
        return []

    def in_data(a):
        return any(s <= a < e for s, e in ranges)

    strides: dict = {}                                    # base -> stride (scale)
    for ln in disasm.splitlines():
        for m in _IDX_ACCESS.finditer(ln):               # non-PIE: absolute [reg*scale+0xDISP]
            base = int(m.group(2), 16)
            if in_data(base):
                strides.setdefault(base, int(m.group(1)))
        m = _LEA_RIP.search(ln)                           # PIE: lea reg,[rip+..] # <vaddr>
        if m:
            base = int(m.group(1), 16)
            if in_data(base):
                strides.setdefault(base, 8)               # a table's stride is off-line; assume ptr
    bases = sorted(strides)
    cands = []
    for i, base in enumerate(bases):
        stride = strides[base]
        gap = (bases[i + 1] - base) if i + 1 < len(bases) else stride * 64
        cap = max(2, min(64, gap // stride))             # estimate; underflow guard is exact anyway
        cands.append({"name": f"data_{base:x}", "addr": base, "stride": stride,
                      "size": cap * stride, "cap": cap})
    return cands[:8]


def _idx_options(model: dict, opts: list[str]) -> list[str]:
    """Menu options that take an index/id field (their boundary values are what we probe). When the
    crawl learned no template (a stateful option that short-circuits on a clean process), fall back
    to every option -- a bare `option\\nINDEX\\n` still exercises the array-select path."""
    named = [o for o in opts if o in model and "idx" in model[o]]
    return named or list(opts)


def _drive(opt: str, model: dict, boundary: int, *, width=None) -> bytes:
    """Input that selects `opt` and supplies `boundary` for its index field (other fields filled
    with in-bounds typed values). `width` encodes a fixed-width read(fd, buf, W) protocol."""
    fields = model.get(opt)
    if fields:
        return menu._scalar(opt.encode(), width) + menu._fill(
            fields, idx=str(boundary).encode(), width=width)
    return menu._scalar(opt.encode(), width) + menu._scalar(str(boundary).encode(), width)


def oob_index_stage(ctx) -> dict:
    from ...db.dao import FindingDAO, StringDAO, TargetDAO
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("oob_index requires a target_id")
    host = sandbox.host_arch()
    if (target.arch and target.arch != host) or (target.file_type or "").lower() not in ("elf", ""):
        ctx.emit("oob_index.done", payload={"applicable": False,
                 "note": "out-of-bounds array-index probing is native x86-64 / ELF only"})
        return {}

    target_bytes = ctx.content.path(target.sha256).read_bytes()
    sym_arrays = _array_candidates(exploit.elf_objects_sized(target_bytes))
    pie = (target.mitigations or {}).get("pie") == "on"

    workdir = Path(tempfile.mkdtemp(prefix="lykos-oob-"))
    sandbox.protect_dir(getattr(ctx.content, "root", None))
    try:
        exe = workdir / "target.bin"
        exe.write_bytes(target_bytes)
        os.chmod(exe, 0o755)
        (workdir / "heaptrace.py").write_bytes(_HELPER.read_bytes())

        # Symbol table gives array sizes directly; a STRIPPED binary needs the arrays recovered from
        # the disassembly -- absolute `[reg*scale+base]` (non-PIE) or `lea reg,[rip+..] # <vaddr>`
        # (PIE, from objdump's computed comment). The tracer rebases a PIE guard via /proc/maps.
        arrays = sym_arrays or _array_candidates_symfree(exe)
        if not arrays:
            ctx.emit("oob_index.done", payload={"applicable": False,
                     "note": "no fixed-size global array (selectable object table) to probe"})
            ctx.progress(pct=100, msg="no indexable array table found")
            return {}

        strings = [x.value for x in StringDAO(ctx.conn).list_by_target(target.id)
                   if getattr(x, "value", None)]
        opts = menu.detect_menu(strings)
        width = _read_width(exe)
        model = _crawl_menu_model(workdir, exe, opts, width=width) if opts else {}
        idx_opts = _idx_options(model, opts) or ["1", "2", "3", "4"]
        # prime one valid object so the select path is reachable, if an allocating option exists
        alloc = next((o for o in opts if o in model and menu._is_alloc(model[o])), None)
        prime = (menu._scalar(alloc.encode(), width)
                 + menu._fill(model[alloc], width=width)) if alloc else b""

        ctx.emit("oob_index.arrays", payload={
            "arrays": [{"name": a["name"], "cap": a["cap"]} for a in arrays],
            "index_options": idx_opts})
        ctx.progress(msg=f"probing {len(arrays)} table(s) over {len(idx_opts)} index option(s)")

        found = None
        for arr in arrays:
            if found or ctx.should_cancel():
                break
            stride = arr.get("stride", _WORD)
            guards = [[arr["addr"] - stride, f"{arr['name']}[-1]"],
                      [arr["addr"] + arr["size"], f"{arr['name']}[{arr['cap']}]"]]
            for opt in idx_opts:
                if found or ctx.should_cancel():
                    break
                for boundary in (0, -1, arr["cap"], arr["cap"] + 1):
                    seq = prime + _drive(opt, model, boundary, width=width)
                    report = workdir / "report.json"
                    report.unlink(missing_ok=True)
                    (workdir / "spec.json").write_text(json.dumps({
                        "exe": str(exe), "stdin": seq.hex(), "pie": pie,
                        "static_watch": guards, "report": str(report), "timeout": 8}))
                    cmd = (sandbox.isolate_prefix(str(workdir), net=False, rw_binds=[str(workdir)])
                           + ["python3", str(workdir / "heaptrace.py"), str(workdir / "spec.json"),
                              str(report)])
                    try:
                        sandbox.run_reaped(cmd, timeout=15, capture_output=True, cwd=str(workdir),
                                           preexec_fn=sandbox._rlimits(2048, 20, set_as=False))
                        rep = json.loads(report.read_text())
                    except Exception:
                        continue
                    if rep.get("oob_index"):
                        ev = next((e for e in rep.get("events", [])
                                   if e.get("error") == "oob-index"), {})
                        found = (arr, opt, boundary, seq, ev)
                        break

        if not found:
            ctx.emit("oob_index.done", payload={
                "applicable": True, "oob_index": False,
                "arrays": [a["name"] for a in arrays],
                "note": (f"probed {len(arrays)} array table(s) with boundary indices; every index "
                         "stayed in bounds (the id validation looks correct).")})
            ctx.progress(pct=100, msg="no out-of-bounds array index surfaced")
            return {"metrics": {"applicable": True, "oob_index": False}}

        arr, opt, boundary, seq, ev = found
        input_sha = ctx.put_artifact("oob-index-sequence", data=seq)
        detail = (f"Out-of-bounds array index (CWE-129) on {arr['name']}[{arr['cap']}]: option "
                  f"{opt} with index {boundary} reached {ev.get('array')} "
                  f"(guard {ev.get('addr')}) from code at {ev.get('pc')} -- the id bound check is "
                  f"missing or off-by-one. Reading a pointer / writing a field through the "
                  f"out-of-bounds slot yields an arbitrary read/write primitive. "
                  f"(sequence {input_sha[:12]})")
        FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
            "cwe": "CWE-129", "title": "Improper validation of array index", "severity": "high",
            "detector": "oob_index", "state": "corroborated", "confidence": 0.85,
            "dedup_key": f"CWE-129:oobindex:{arr['name']}",
            "function_addr": None, "site_addr": ev.get("pc"), "site_detail": arr["name"],
            "evidence": [{"channel": "oob-index", "detail": detail}]})
        ctx.emit("oob_index.done", payload={
            "applicable": True, "oob_index": True, "array": arr["name"], "option": opt,
            "index": boundary, "input_sha": input_sha,
            "vuln": {"vclass": "oob_write", "note": f"{arr['name']}[{boundary}]"}})
        ctx.progress(pct=100, msg=f"out-of-bounds array index on {arr['name']} (option {opt}, "
                                  f"index {boundary})")
        return {"metrics": {"oob_index": True}, "output_shas": [input_sha]}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def register() -> None:
    register_stage(OOB_INDEX_STAGE, oob_index_stage, resource_class="cpu",
                   tool="ptrace", tool_version="1")


def enqueue_oob_index(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, OOB_INDEX_STAGE, target_id=target.id,
                         params=params or {}, force=force)
