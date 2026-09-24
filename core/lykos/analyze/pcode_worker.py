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
  out.jsonl one {"a": "0x..", "p": ["OP in -> out", ...]} per instruction, flushed incrementally
            so a crash mid-stream still leaves the ops lifted before it.
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


def main(in_path: str, out_path: str) -> int:
    with open(in_path) as fh:
        spec = json.load(fh)
    langid = spec.get("langid")
    instrs = spec.get("instrs") or []
    import pypcode
    ctx = pypcode.Context(langid)
    n = 0
    with open(out_path, "w") as out:
        for addr, hexb in instrs:
            ops = []
            try:
                raw = bytes.fromhex(hexb) if hexb else b""
                if raw:
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
            except Exception:                                # noqa: BLE001 -- one bad insn, not all
                ops = []
            out.write(json.dumps({"a": hex(int(addr)), "p": ops}) + "\n")
            n += 1
            if n % 256 == 0:                                 # flush so a later crash keeps these
                out.flush()
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: pcode_worker.py <in.json> <out.jsonl>", file=sys.stderr)
        sys.exit(64)
    sys.exit(main(sys.argv[1], sys.argv[2]))
