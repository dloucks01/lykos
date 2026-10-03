#!/usr/bin/env python3
"""Isolated Ghidra P-Code lifter (pypcode / SLEIGH), run as a SEPARATE PROCESS.

pypcode is a C extension and can crash the interpreter -- a native double-free / SIGABRT on
particular instruction encodings, observed on ppc64 big-endian. In-process that abort would take
the whole analysis server down (the disassemble stage runs in a worker thread, and a native crash
cannot be caught). So the lifting happens here, in a child process the parent launches and reaps:
a crash kills only this child, the parent keeps every function's structure (which comes from rizin,
not pypcode) plus whatever P-Code was flushed before the crash.

Usage:  pcode_worker.py <in.json> <out.jsonl>
  in.json   {"langid": "<SLEIGH id>", "instrs": [[addr_int, "hexbytes"], ...]}
            OR, for whole-function recovery on an arch the structural backend cannot disassemble,
            {"langid": "<SLEIGH id>", "regions": [[addr_int, "hexbytes"], ...]} where each region is
            a function's entire byte range -- the worker LINEARLY disassembles it (SLEIGH decides the
            instruction boundaries), so no external disassembler is needed.
  out.jsonl "instrs" mode: one {"a": "0x..", "p": ["OP in -> out", ...]} per instruction.
            "regions" mode: one {"region": "0x..", "insns": [{"a","len","text","p":[...]}, ...]} per
            region. Flushed incrementally so a crash mid-stream still leaves the work done before it.
"""
import json
import sys


def _vn(ctx, v) -> str:
    """Format one varnode exactly as the in-process lifter / ExportAnalysis.java does."""
    sp = v.space.name
    if sp == "register":
        try:
            rn = ctx.getRegisterName(v.space, v.offset, v.size)
        except Exception:                                    # noqa: BLE001
            rn = None
        return f"reg:{rn}:{v.size}" if rn else f"register:{hex(v.offset)}:{v.size}"
    if sp == "const":
        return f"const:{hex(v.offset)}:{v.size}"
    return f"{sp}:{hex(v.offset)}:{v.size}"


def _ops_for(ctx, raw: bytes, addr: int) -> list:
    """P-Code op strings for a single instruction's bytes at `addr` (IMARK dropped)."""
    ops = []
    tx = ctx.translate(raw, base_address=int(addr), max_instructions=1)
    for op in tx.ops:
        if op.opcode.name == "IMARK":
            continue
        s = op.opcode.name
        for vin in op.inputs:
            s += " " + _vn(ctx, vin)
        if op.output is not None:
            s += " -> " + _vn(ctx, op.output)
        ops.append(s)
    return ops


def _disasm_region(ctx, addr: int, raw: bytes, cap: int = 20000) -> list:
    """Linearly disassemble a whole function's bytes. Returns [{a,len,text,p}]; SLEIGH owns the
    instruction boundaries, so this recovers an arch the structural backend cannot disassemble."""
    out = []
    dis = ctx.disassemble(raw, base_address=int(addr), max_instructions=cap)
    for ins in dis.instructions:
        a = ins.addr.offset if hasattr(ins.addr, "offset") else int(ins.addr)
        off = a - addr
        ibytes = raw[off:off + ins.length]
        try:
            p = _ops_for(ctx, ibytes, a)
        except Exception:                                    # noqa: BLE001 -- one bad insn, not all
            p = []
        out.append({"a": hex(a), "len": ins.length,
                    "text": (ins.mnem + " " + ins.body).strip(), "p": p})
    return out


def main(in_path: str, out_path: str) -> int:
    with open(in_path) as fh:
        spec = json.load(fh)
    langid = spec.get("langid")
    instrs = spec.get("instrs") or []
    regions = spec.get("regions") or []
    import pypcode
    ctx = pypcode.Context(langid)
    n = 0
    with open(out_path, "w") as out:
        for addr, hexb in instrs:
            ops = []
            try:
                raw = bytes.fromhex(hexb) if hexb else b""
                if raw:
                    ops = _ops_for(ctx, raw, int(addr))
            except Exception:                                # noqa: BLE001 -- one bad insn, not all
                ops = []
            out.write(json.dumps({"a": hex(int(addr)), "p": ops}) + "\n")
            n += 1
            if n % 256 == 0:                                 # flush so a later crash keeps these
                out.flush()
        for addr, hexb in regions:
            try:
                raw = bytes.fromhex(hexb) if hexb else b""
                insns = _disasm_region(ctx, int(addr), raw) if raw else []
            except Exception:                                # noqa: BLE001 -- one bad region, not all
                insns = []
            out.write(json.dumps({"region": hex(int(addr)), "insns": insns}) + "\n")
            out.flush()
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: pcode_worker.py <in.json> <out.jsonl>", file=sys.stderr)
        sys.exit(64)
    sys.exit(main(sys.argv[1], sys.argv[2]))
