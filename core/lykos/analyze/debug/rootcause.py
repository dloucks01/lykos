"""Root-cause analysis of a confirmed crash (Phase 6, zero-AI).

Turns a fault capture (registers, fault address, faulting-instruction bytes, backtrace, memory
maps -- from the ptrace helper or GDB) into a structured explanation: what kind of memory-
safety failure occurred, where, and how attacker input reached it. The dynamic fault is then
*sliced* against the static call graph and taint results to name the path from an input source
to the crash site. objdump, when present, disassembles the faulting instruction (read vs write
vs return); everything else is pure stdlib.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

from ..detect.catalog import SOURCES, normalize

_OBJDUMP_MACH = {"x86-64": "i386:x86-64", "x86": "i386", "aarch64": "aarch64", "arm": "arm"}


def _to_int(x):
    try:
        return int(x, 0) if isinstance(x, str) else int(x)
    except (ValueError, TypeError):
        return None


def disasm_one(pc_bytes: bytes, arch: str):
    """Disassemble the first instruction in `pc_bytes` via objdump; None if unavailable."""
    if not pc_bytes or not shutil.which("objdump"):
        return None
    mach = _OBJDUMP_MACH.get(arch, "i386:x86-64")
    fd, path = tempfile.mkstemp(suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(pc_bytes)
        r = subprocess.run(["objdump", "-D", "-b", "binary", "-m", mach, "-M", "intel", path],
                           capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    for line in r.stdout.splitlines():
        s = line.strip()
        parts = s.split("\t")
        if len(parts) >= 3 and parts[0].rstrip().endswith(":"):
            return parts[2].strip()
    return None


def mapping_for(maps, addr):
    if addr is None:
        return None
    for m in maps or []:
        if m["start"] <= addr < m["end"]:
            return m
    return None


def _fn_ranges(functions):
    out = []
    for f in functions:
        fa = _to_int(f.addr)
        if fa is None:
            continue
        size = f.size or 1
        out.append((fa, fa + size, f))
    out.sort()
    return out


def _fn_at(ranges, addr):
    for lo, hi, f in ranges:
        if lo <= addr < hi:
            return f
    return None


def symbolize(addr, maps, ranges, target_path):
    m = mapping_for(maps, addr)
    module = os.path.basename(m["path"]) if (m and m["path"]) else (
        "[anon]" if m else "??")
    entry = {"addr": addr, "module": module,
             "offset": (addr - m["start"]) if m else None, "symbol": None}
    f = _fn_at(ranges, addr)                      # absolute match (no-PIE)
    if f is not None:
        entry["symbol"] = f.name or f"sub_{f.addr}"
        entry["func_addr"] = f.addr
    return entry


def _is_memory_write(disasm):
    """Intel-syntax: a store has the memory operand as the destination (before the comma)."""
    if not disasm:
        return False
    ops = disasm.split(None, 1)
    if len(ops) < 2:
        return False
    dest = ops[1].split(",")[0]
    return "[" in dest                            # destination dereferences memory -> a write


def classify(cap, disasm):
    sig = cap.get("signal_name")
    pc = cap.get("pc")
    fault = cap.get("fault_addr")
    maps = cap.get("maps") or []
    pc_map = mapping_for(maps, pc)
    pc_exec = bool(pc_map and "x" in pc_map.get("perms", ""))

    if not pc_exec:
        return {"class": "control-flow-hijack", "cwe": "CWE-787", "severity": "critical",
                "detail": f"program counter 0x{(pc or 0):x} is not in executable memory "
                          "(attacker-controlled execution transfer)"}
    if sig == "SIGABRT":
        return {"class": "detected-corruption-abort", "cwe": "CWE-787", "severity": "high",
                "detail": "process aborted by a runtime integrity check "
                          "(stack canary / _FORTIFY_SOURCE / heap consistency)"}
    if sig == "SIGFPE":
        return {"class": "arithmetic-exception", "cwe": "CWE-369", "severity": "high",
                "detail": "arithmetic fault (divide-by-zero or INT_MIN/-1)"}
    if sig == "SIGILL":
        return {"class": "illegal-instruction", "cwe": "CWE-119", "severity": "high",
                "detail": "illegal instruction (corrupted code or control flow)"}

    mnem = (disasm or "").split()[0] if disasm else ""
    if mnem in ("ret", "retq", "retn"):
        return {"class": "stack-return-overwrite", "cwe": "CWE-121", "severity": "critical",
                "detail": "fault at a function return: the saved return address was "
                          "overwritten (stack-based buffer overflow)"}
    is_write = _is_memory_write(disasm)
    rw = "write" if is_write else "read"
    if fault is not None and fault < 0x1000:
        return {"class": "null-pointer-dereference", "cwe": "CWE-476", "severity": "medium",
                "detail": f"{rw} through a NULL/near-NULL pointer (fault at 0x{fault:x})"}
    cwe = "CWE-787" if is_write else "CWE-125"
    return {"class": f"out-of-bounds-{rw}", "cwe": cwe, "severity": "high",
            "detail": f"invalid {rw} at 0x{(fault or 0):x}"
                      + (f" via `{disasm}`" if disasm else "")}


def _callgraph_path(call_edges, sources_callers, crash_fn_addr, maxdepth=8):
    """Shortest forward call path from any source-calling function to the crash function."""
    from collections import deque
    succ = {}
    for e in call_edges:
        sa, da = _to_int(e.src_addr), _to_int(e.dst_addr)
        if sa is not None and da is not None:
            succ.setdefault(sa, set()).add(da)
    target = _to_int(crash_fn_addr)
    seen = set()
    q = deque((s, [s]) for s in sources_callers)
    while q:
        node, path = q.popleft()
        if node == target:
            return path
        if node in seen or len(path) > maxdepth:
            continue
        seen.add(node)
        for nxt in succ.get(node, ()):
            q.append((nxt, path + [nxt]))
    return None


def build_slice(cap, functions, call_edges, findings, maps, target_path):
    ranges = _fn_ranges(functions)
    chain = [cap.get("pc")] + list(cap.get("backtrace") or [])
    frames = [symbolize(a, maps, ranges, target_path) for a in chain if a is not None]
    crash_fn = next((fr for fr in frames if fr.get("func_addr")), None)

    sources_callers = {_to_int(e.src_addr) for e in call_edges
                       if normalize(e.dst_name) in SOURCES and _to_int(e.src_addr) is not None}
    path = None
    tainted = False
    if crash_fn:
        path = _callgraph_path(call_edges, sources_callers, crash_fn["func_addr"])
        for f in findings:
            if f.function_addr == crash_fn["func_addr"] and any(
                    (e.get("channel") if isinstance(e, dict) else "") .startswith("taint")
                    for e in (f.evidence or [])):
                tainted = True
    addr_to_name = {}
    for lo, _hi, fn in ranges:
        addr_to_name[lo] = fn.name or f"sub_{fn.addr}"
    named_path = [{"addr": hex(a), "symbol": addr_to_name.get(a)} for a in (path or [])]
    return {"backtrace": frames, "crash_function": crash_fn,
            "source_path": named_path, "input_tainted": tainted,
            "reachable_from_source": bool(path)}


def analyze(cap, functions, call_edges, findings, target_path, arch):
    disasm = disasm_one(bytes.fromhex(cap.get("pc_bytes", "")), arch)
    verdict = classify(cap, disasm)
    sl = build_slice(cap, functions, call_edges, findings, cap.get("maps") or [], target_path)
    summary = _summary(verdict, sl, cap, disasm)
    return {"signal": cap.get("signal_name"), "pc": cap.get("pc"),
            "fault_addr": cap.get("fault_addr"), "faulting_instruction": disasm,
            "classification": verdict, "slice": sl, "summary": summary}


def _summary(verdict, sl, cap, disasm):
    where = ""
    cf = sl.get("crash_function")
    if cf and cf.get("symbol"):
        where = f" in {cf['symbol']}"
    elif cf:
        where = f" in {cf['module']}+0x{cf['offset']:x}"
    reach = ""
    if sl.get("source_path"):
        names = [p["symbol"] or p["addr"] for p in sl["source_path"]]
        reach = " reached from untrusted input via " + " -> ".join(names)
    tail = f"; faulting instruction `{disasm}`" if disasm else ""
    return (f"{verdict['class']} ({verdict['cwe']}){where}: {verdict['detail']}{reach}{tail}")
