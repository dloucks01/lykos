"""Static x86-64 (SysV) frame facts read straight off a function's recovered IR -- no execution.

The non-executed recipes (format-string %n, stack overflow) need a handful of EXACT stack facts at a
call site, and every one of them is a literal property of the instructions, not an inference:

  * where the call's pointer argument comes from: `lea rdi,[rbp-0x110]` -> the stack buffer at
    rbp-0x110; `mov rdi,qword [rbp-8]` -> a pointer loaded from a local (the buffer is elsewhere);
  * the frame geometry: `push rbp; mov rbp,rsp; [push rbx...]; sub rsp,N` -> at any call site in the
    body, rsp == rbp - (8*pushes + N), provided nothing between the prologue and the site moves rsp;
  * the saved return address sits at rbp+8 (frame-pointer frames).

Everything here returns None the moment a fact is NOT literal (a frame without rbp whose rsp moves,
an `and rsp,-16` realignment, a push in the argument window, an operand that is not a plain
base+displacement) -- the callers then fall back to a probe-first recipe instead of computing a
number from a guess. Pure functions over the IR dicts `{"blocks":[{"instructions":[{addr,text}]}]}`
the disassembler stores (rizin-flavoured Intel syntax: `lea rax, [rbp - 0x110]`)."""
from __future__ import annotations

import re
from typing import Optional

#: SysV integer argument registers in order, with their sub-registers.
ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
_SUBS = {
    "rax": {"rax", "eax", "ax", "al"}, "rbx": {"rbx", "ebx", "bx", "bl"},
    "rcx": {"rcx", "ecx", "cx", "cl"}, "rdx": {"rdx", "edx", "dx", "dl"},
    "rsi": {"rsi", "esi", "si", "sil"}, "rdi": {"rdi", "edi", "di", "dil"},
    "r8": {"r8", "r8d", "r8w", "r8b"}, "r9": {"r9", "r9d", "r9w", "r9b"},
    "r10": {"r10", "r10d", "r10w", "r10b"}, "r11": {"r11", "r11d", "r11w", "r11b"},
    "r12": {"r12", "r12d", "r12w", "r12b"}, "r13": {"r13", "r13d", "r13w", "r13b"},
    "r14": {"r14", "r14d", "r14w", "r14b"}, "r15": {"r15", "r15d", "r15w", "r15b"},
}
_FULL = {sub: full for full, subs in _SUBS.items() for sub in subs}

# `[rbp - 0x110]`, `[rsp + 0x20]`, `qword [rbp-8]`, `[rbp]`; also objdump's `QWORD PTR [rbp-0x8]`.
_MEM = re.compile(r"\[\s*(rbp|rsp)\s*(?:([+-])\s*(0x[0-9a-fA-F]+|\d+))?\s*\]", re.I)


def instructions(ir) -> list:
    """[(addr:int, text:str)] in IR order (blocks are stored in address order). Tolerates hex-string
    or int addresses; drops entries without an address."""
    out = []
    for b in (ir or {}).get("blocks", []) or []:
        for i in b.get("instructions") or []:
            a = i.get("addr")
            try:
                a = int(a, 16) if isinstance(a, str) else int(a)
            except (TypeError, ValueError):
                continue
            out.append((a, (i.get("text") or "").split(";")[0].strip()))
    out.sort(key=lambda x: x[0])
    return out


def mem_operand(op: str):
    """`[rbp - 0x110]` -> ("rbp", -0x110); `[rsp + 8]` -> ("rsp", 8). None for anything else."""
    m = _MEM.search(op or "")
    if not m:
        return None
    disp = int(m.group(3), 0) if m.group(3) else 0
    return m.group(1).lower(), (-disp if m.group(2) == "-" else disp)


def _split(text: str):
    """(mnemonic, [operands]) for Intel syntax `mnem dst, src`."""
    t = (text or "").strip()
    if not t:
        return "", []
    parts = t.split(None, 1)
    mn = parts[0].lower()
    if len(parts) == 1:
        return mn, []
    ops, depth, cur = [], 0, ""
    for ch in parts[1]:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            ops.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        ops.append(cur.strip())
    return mn, ops


def _dest_full(text: str):
    mn, ops = _split(text)
    if not ops:
        return mn, None
    return mn, _FULL.get(ops[0].lower())


def pointer_source(before: list, reg: str):
    """Where the pointer in `reg` at the end of `before` (texts, oldest first) comes from, following
    up to two register-to-register moves:

      ("stack", base, disp)  -- `lea reg,[rbp-0x110]`: the ADDRESS of a stack slot (a local buffer)
      ("load", base, disp)   -- `mov reg,qword [rbp-8]`: a pointer read FROM a stack slot
      ("literal", None, None) -- `lea reg,[0x402004]` / `lea reg, str.x` / rip-relative: a constant
      None                   -- anything else (call return, arithmetic, global load): indeterminate
    """
    cur = _FULL.get(reg, reg)
    end = len(before)                                     # a hop resumes ABOVE the move it followed
    for _hop in range(3):
        moved = False
        for j in range(end - 1, -1, -1):
            t = before[j]
            mn, ops = _split(t)
            if not ops or _FULL.get(ops[0].lower()) != cur:
                continue
            src = ops[1] if len(ops) > 1 else ""
            if mn == "lea":
                mo = mem_operand(src)
                if mo:
                    return ("stack", mo[0], mo[1])
                if "rip" in src.lower() or re.search(r"\bstr\.|\[0x[0-9a-f]+\]|obj\.", src, re.I):
                    return ("literal", None, None)
                return None
            if mn == "mov":
                mo = mem_operand(src)
                if mo:
                    return ("load", mo[0], mo[1])
                if src.lower() in ("rsp", "rbp"):         # mov rdi, rsp -- the buffer AT rsp/rbp
                    return ("stack", src.lower(), 0)
                nxt = _FULL.get(src.lower())
                if nxt:
                    cur, end = nxt, j
                    moved = True
                    break
                return None
            return None                                   # defined by something else
        if not moved:
            return None
    return None


def defining_text(before: list, reg: str) -> Optional[str]:
    """The instruction text that finally defines `reg` at the end of `before`, following up to two
    register-to-register moves (`lea rax,[0x402004]; mov rsi,rax` -> the lea). None if not found."""
    cur, end = _FULL.get(reg, reg), len(before)
    for _hop in range(3):
        for j in range(end - 1, -1, -1):
            mn, ops = _split(before[j])
            if not ops or _FULL.get(ops[0].lower()) != cur:
                continue
            src = ops[1] if len(ops) > 1 else ""
            if mn == "mov" and _FULL.get(src.lower()):
                cur, end = _FULL[src.lower()], j
                break
            return before[j]
        else:
            return None
    return None


def frame_geometry(instrs: list) -> Optional[dict]:
    """The prologue's frame facts: {"fp": True, "pushes": n, "sub": N, "body": idx} for the canonical
    `push rbp; mov rbp,rsp; [push r..]*; [sub rsp,N]` frame, where `body` is the index of the first
    instruction after the prologue. None when the function has no rbp frame or realigns rsp
    (`and rsp,..`) -- those layouts are not literal facts."""
    i, n = 0, len(instrs)
    while i < n and instrs[i][1].split()[:1] in (["endbr64"], ["nop"]):
        i += 1
    if i >= n or instrs[i][1].replace(" ", "").lower() != "pushrbp":
        return None
    i += 1
    if i >= n or instrs[i][1].replace(" ", "").lower() != "movrbp,rsp":
        return None
    i += 1
    pushes, sub = 0, 0
    while i < n:
        mn, ops = _split(instrs[i][1])
        if mn == "push" and ops and _FULL.get(ops[0].lower()):
            pushes += 1
        elif mn == "sub" and ops and ops[0].lower() == "rsp" and len(ops) > 1:
            try:
                sub = int(ops[1], 0)
            except ValueError:
                return None
            i += 1
            break
        else:
            break
        i += 1
    for _a, t in instrs[i:]:
        mn, ops = _split(t)
        if mn == "and" and ops and ops[0].lower() == "rsp":
            return None                                   # realigned stack: rbp-relative math breaks
    return {"fp": True, "pushes": pushes, "sub": sub, "body": i}


def rsp_below_rbp(instrs: list, site_idx: int) -> Optional[int]:
    """F such that rsp == rbp - F at the call instruction `instrs[site_idx]`, or None if any
    instruction between the prologue and the site could have moved rsp (push/pop/sub/add/alloca).
    A `call` in between is balanced (callee pops its return address; SysV caller-cleans nothing on
    x86-64 for register-only calls), so it does not disqualify."""
    g = frame_geometry(instrs)
    if g is None or site_idx < g["body"]:
        return None
    for _a, t in instrs[g["body"]:site_idx]:
        mn, ops = _split(t)
        if mn in ("push", "pop", "pushf", "popf", "enter"):
            return None
        if mn in ("sub", "add", "lea", "mov", "and") and ops and ops[0].lower() == "rsp":
            return None
    return 8 * g["pushes"] + g["sub"]


def site_index(instrs: list, site_addr) -> Optional[int]:
    try:
        sa = int(site_addr, 16) if isinstance(site_addr, str) else int(site_addr)
    except (TypeError, ValueError):
        return None
    for k, (a, _t) in enumerate(instrs):
        if a == sa:
            return k
    return None


def call_target(text: str) -> Optional[str]:
    """Normalised callee name of a `call` (`sym.imp.printf` -> `printf`, `printf@plt` -> `printf`)."""
    m = re.match(r"\s*call\s+(?:qword\s+)?(\S+)", text or "", re.I)
    if not m:
        return None
    t = m.group(1)
    t = re.sub(r"^(sym\.imp\.|sym\.|imp\.|reloc\.)", "", t)
    t = re.sub(r"^<|>$", "", t)
    t = t.split("@")[0]
    t = re.sub(r"^__isoc99_", "", t)
    return t or None


def in_loop(instrs: list, site_idx: int) -> bool:
    """True when a branch located AFTER the site jumps back to an address at or before it -- the sink
    is re-executed (a read/print loop), so a write planted by one pass is used by the next."""
    if site_idx is None:
        return False
    sa = instrs[site_idx][0]
    for a, t in instrs[site_idx + 1:]:
        m = re.match(r"\s*j[a-z]{1,3}\s+(0x[0-9a-fA-F]+)\b", t, re.I)
        if m and int(m.group(1), 16) <= sa:
            return True
    # a branch BEFORE the site that jumps forward over it into a loop test that jumps back is the
    # gcc `jmp cond; body: ...; cond: ...; jne body` shape -- covered above (the jne is after).
    return False


def calls_after(instrs: list, site_idx: int) -> list:
    """Callee names of the direct calls after `site_idx` in IR order (deduplicated, order kept)."""
    out = []
    for _a, t in instrs[(site_idx or 0) + 1:]:
        n = call_target(t)
        if n and n not in out:
            out.append(n)
    return out


def arg_window(instrs: list, site_idx: int) -> list:
    """Texts of the argument-setup window: from the previous call (exclusive) to the site."""
    win = []
    for _a, t in reversed(instrs[:site_idx]):
        if re.match(r"\s*call\b", t, re.I):
            break
        win.append(t)
    return list(reversed(win))


def stack_disp_below_rsp(instrs: list, site_idx: int, src) -> Optional[int]:
    """Byte offset of a ("stack", base, disp) slot ABOVE rsp at the site (>= 0), or None."""
    if not src or src[0] != "stack":
        return None
    _kind, base, disp = src
    if base == "rsp":
        # rsp-relative at the lea; valid if rsp did not move between the lea and the call
        return disp if disp >= 0 else None
    F = rsp_below_rbp(instrs, site_idx)
    if F is None:
        return None
    d = F + disp                                          # (rbp + disp) - (rbp - F)
    return d if d >= 0 else None
