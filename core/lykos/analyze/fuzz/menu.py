"""Menu / interactive-protocol seed synthesis.

Menu-driven services (add/modify/print/delete loops, games, "auth" gates) hide their defect behind
a state machine the fuzzer has to navigate: junk input never selects a valid option, so a blind
campaign runs thousands of executions in the front-door menu and never reaches the vulnerable
sub-handler. We read the menu OUT of the binary's own strings -- the numbered options it prints --
and synthesise multi-step navigation seeds (choose an option, then supply a size / data), so
coverage-guided fuzzing starts INSIDE the menu and mutates the fields that actually reach the bug.

Pure heuristic + stdlib. Best-effort: no menu detected -> no seeds, never an error.
"""
from __future__ import annotations

import re
import selectors
import time

# the same item found ANYWHERE in a line, not only at its start: a compact menu prints every
# option on ONE line ("1)alloc 2)free 3)use 0)quit"), so anchoring to the line start sees only the
# first. A separator must precede the digit (start / space / a table border) so a version string
# mid-line ("build 2.3.4") is not read as options.
_OPT_SCAN = re.compile(r"(?:^|[\s|>#])\s*[\[\(<]?\s*(\d{1,2})\s*(?:[\]\)>]|[-.):|])\s*[A-Za-z]")
# a choice prompt the loop reads after printing the menu
_PROMPT = re.compile(r"(choice|option|select|menu|enter|cmd|command|action|your)\b", re.I)

_PAYLOADS = [b"A" * 64, b"A" * 256, b"%p%p%p%p%p%p", b"-1", b"999999"]
_SIZES = [b"1", b"64", b"256", b"1024"]
_NL = b"\n"


def detect_menu(strings) -> list[str]:
    """The valid menu-choice tokens the binary advertises, best-effort. Empty when no menu."""
    opts: set[str] = set()
    prompt = False
    for s in strings or []:
        # A whole menu is often ONE printf format string; the string store keeps its newlines as
        # the literal escape "\n" (backslash-n), so unescape before splitting into option lines.
        text = str(s).replace("\\n", "\n").replace("\\r", "\n").replace("\\t", " ")
        for raw in text.splitlines():
            # boxed menus prefix each option with a table border ("| [1] Allocate |"); strip a
            # leading border / bullet so the option token is at the start for the matcher.
            line = raw.lstrip("|*>#-=+ \t│┃‖●·")
            # Every option on the line, not just the first: one-per-line menus match at the start
            # and compact single-line menus match the rest after each separator.
            for m in _OPT_SCAN.finditer(line):
                opts.add(m.group(1))
            if _PROMPT.search(line):
                prompt = True
    # Require at least two numbered options; a choice prompt raises confidence but isn't required
    # (some menus print options without a separate "Choice:" string).
    if len(opts) < 2:
        return []
    _ = prompt
    return sorted(opts, key=lambda x: int(x))


def menu_seeds(strings, *, max_seeds: int = 64) -> list[bytes]:
    """Multi-step stdin navigation seeds for a detected menu, or [] when none is found.

    Each seed drives the menu to a state where user data is read, then supplies a payload the
    mutator will grow into an overflow/format-string. Sequences that CREATE then ACT (add then
    modify/free) reach use-after-free / heap-overflow states a single option cannot."""
    opts = detect_menu(strings)
    if not opts:
        return []
    seeds: list[bytes] = []
    for c in opts:
        cb = c.encode()
        seeds.append(cb + _NL)                                   # bare option (learn its handler)
        for pl in _PAYLOADS[:3]:
            seeds.append(cb + _NL + pl + _NL)                    # option -> data
    # option -> size -> data: the classic "how many bytes?" then that many (heap/stack overflow)
    for c in opts[:4]:
        cb = c.encode()
        for size in _SIZES:
            seeds.append(cb + _NL + size + _NL + b"A" * 64 + _NL)
    # create-then-act sequences (reach UAF / overwrite states)
    if len(opts) >= 2:
        first, second, last = opts[0].encode(), opts[1].encode(), opts[-1].encode()
        add = first + _NL + b"64" + _NL + b"A" * 64 + _NL
        seeds.append(add + second + _NL + b"64" + _NL + b"B" * 256 + _NL)   # add then modify (big)
        seeds.append(add + last + _NL)                                       # add then delete/print
        seeds.append(add + add + second + _NL)                              # two allocs then act
    out, seen = [], set()
    for s in seeds:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out[:max_seeds]


# ------------------------------------------------------------ menu-semantic sequence inference ----
# A menu OPTION (add/modify/free/print) reads a fixed, ORDERED list of typed fields (an index, a
# size, a string). The generic op-sequences above guess a single (option,size,data) shape, so a
# richer flow -- auth-or-out's add reads Name, Surname, Age, Note-size, Note -- never allocates and
# the tracer sees nothing. We LEARN each option's field template by driving the live process one
# prompt at a time (below), then compose correctly-typed operation sequences from it.

#: A PLURAL object noun asks HOW MANY; the singular asks WHICH ONE. "entries:" is a count and
#: "entry:" is an index, and the same holds for records/items/slots/blocks -- which is why these
#: live here and their singulars stay in `_IDX_KW` below. Measured: an `add(idx, records)` creator
#: whose count prompt reads `records: ` was typed as a STRING, so the crawl answered it "lykos",
#: `strtol` returned 0, the option allocated nothing, and no option in the menu named a size --
#: the whole op-model was unusable and every sequence drove objects that did not exist.
_PLURAL_COUNT = (r"\b(records|items|entries|elements|rows|columns|cols|chunks|blocks|lines|"
                 r"fields|slots|notes|nodes|frames|packets|pages|users|accounts)\b")

# A prompt naming a size/count/age is a NUMBER; one naming an id/index/slot is an INDEX (its
# boundary values -- 0, capacity -- are what an OOB-index probe drives); else a STRING.
# The index keywords are index INDICATORS only (id/index/slot/...), never object nouns like
# "author" -- "Author Note size" is a size, not an index, so NUM must win there.
_NUM_KW = re.compile(r"(size|\bsz\b|length|\blen\b|count|number|\bnum\b|\bage\b|amount|\bqty\b|quantity|"
                     r"bytes|how many|price|score|year|\bhow much\b|\bvalue\b|\bval\b|"
                     r"\bbig\b|\bhow long\b|capacity|\bbuf(fer)? ?size\b|" + _PLURAL_COUNT + r")", re.I)
_IDX_KW = re.compile(r"(\bid\b|\bidx\b|index|\bslot\b|\bentry\b|position|\bpos\b|\bwhich\b|"
                     r"\bno\.?\b|\bpage\b)", re.I)


_YN_KW = re.compile(r"\by\s*/\s*n\b|\byes\s*/\s*no\b|\(\s*y\s*/\s*n\s*\)|\[\s*y\s*/\s*n\s*\]"
                    r"|would you like|\bconfirm\b|\(y\)es|proceed\?", re.I)


def classify_prompt(text: str) -> str:
    """Field type a prompt asks for: 'yn' (a yes/no confirmation), 'idx' (array index / id), 'num'
    (a size/count) or 'str'.

    A yes/no confirmation is checked FIRST: a `would you like ... ? (y/n)` prompt answered with a
    typed string or a number gets rejected ("only y/n permitted") and the option never completes, so
    the crawl never models it -- exactly why a create flow with a save/continue confirmation stayed
    invisible. A size keyword (num) then wins over a bare index word so "Note size" is a size; an
    explicit index word (id/index/slot) with no size keyword is an index; everything else is a string."""
    t = str(text or "")
    if _YN_KW.search(t):
        return "yn"
    has_num, has_idx = _NUM_KW.search(t), _IDX_KW.search(t)
    if has_num:
        return "num"
    if has_idx:
        return "idx"
    return "str"


def _tail_prompt(chunk: str) -> str:
    """The trailing prompt of a just-emitted output chunk: text after the last newline (a bare
    "Name: " with no newline), else the last non-empty line."""
    if not chunk:
        return ""
    after = chunk.rsplit("\n", 1)[-1]
    # A trailing INPUT GLYPH with no letters -- "💀 ", "> ", "$ ", "# " -- is decoration, not the
    # question; the real prompt ("How big is your request?", "Name of victim:") is on the line(s)
    # before it. Classifying the glyph makes every field look like a bare string (an ornate menu's crawl
    # returned an empty model for exactly this). Prefer the last non-empty line that has letters.
    if after.strip() and re.search(r"[A-Za-z]", after):
        return after
    lines = [ln for ln in chunk.splitlines() if ln.strip() and re.search(r"[A-Za-z]", ln)]
    if lines:
        return lines[-1]
    return after if after.strip() else ""


#: A question, not output: a prompt ends in `:`/`>`/`?` and the program then stops writing, so
#: the line is UNFINISHED. `ok\n` after a completed write is output and must not count.
_PROMPT_TAIL = re.compile(r"[:>?]\s*\Z")


def _skipped_prompt(head: str) -> bool:
    """Did the option print a prompt for a field it then did NOT read?

    An edit reads its data only when the slot holds an object -- `printf("data: ");
    if (db[i]) read(...)` -- and an isolated crawl never primes one, so the option prints
    `data: `, skips the read and loops back to the menu. The prompt is the evidence the field
    exists; the guard is why it was not read this time. Without it the model said
    `2 -> [idx, num]`, no sequence could overflow anything, and a notebook whose overflow is
    three operations deep fuzzed 6,064 times with zero crashes **[measured]**.
    """
    if not head or head.endswith("\n"):
        return False                                     # a finished line is output, not a question
    return bool(_PROMPT_TAIL.search(head)) and classify_prompt(_tail_prompt(head)) == "str"


def _menu_start(text: str) -> int:
    """Index where the re-printed menu begins in a drained chunk, or len(text).

    Needed to read what the option printed BEFORE it looped back: the prompt for a field it
    skipped sits there, and `_tail_prompt` over the whole chunk would classify the menu instead.
    Matched by OPTION rather than by line, because a prompt with no newline and the menu that
    follows it share one line -- `data: 1.add 2.edit 3.show 4.free 5.exit` is exactly the chunk
    this has to cut in two.
    """
    m = _OPT_SCAN.search(str(text or ""))
    return m.start() if m else len(text or "")


def _looks_like_menu(text: str) -> bool:
    """The option list re-appeared -- the current option's sub-flow has finished and looped."""
    return len(detect_menu([text])) >= 2


_VALUE = {"idx": b"1", "num": b"16", "str": b"AAAA", "yn": b"y"}

# A y/n that asks whether to CONTINUE / repeat / keep processing is answered NO -- answering yes loops
# the option back on itself (it never returns to the menu, so the crawl can't model it). Everything
# else (save?/confirm?/sure?) is answered YES to let the operation complete.
_YN_NO = re.compile(r"\b(continue|again|more|another|keep going|retry|repeat|re-?process|processing)\b",
                    re.I)


def yn_answer(text) -> bytes:
    """The y/n answer that lets an option COMPLETE: 'n' to a continue/repeat prompt (yes would loop),
    'y' otherwise."""
    return b"n" if _YN_NO.search(str(text or "")) else b"y"


# --- field encoding: line-delimited by default, or FIXED-WIDTH for a read(fd, buf, W) protocol ---
# A target that reads scalars with `read(0, buf, W)` (not fgets/scanf) consumes exactly W bytes per
# field regardless of newlines; a value+"\n" then under-reads and desyncs every later field. In
# fixed-width mode each scalar is padded to W bytes (atoi stops at the padding) and a data buffer is
# sent raw (its read already consumed exactly its size).
def _scalar(value: bytes, width) -> bytes:
    return (value + b" " * (width or 0))[:width] if width else value + _NL


def _data(payload: bytes, width, term: bool = True) -> bytes:
    """The data field's bytes. The newline is a TERMINATOR for a line-based reader, and one byte
    too many for a `read(fd, buf, size)` whose size we just supplied: it stays in the pipe and the
    next operation reads it as an empty line. That only matters when another operation FOLLOWS --
    every sequence used to end at the write -- and it is how the one sequence that proves a heap
    overflow (write the object's callback, then CALL it) quietly became "write, then exit": the
    stray newline was read as menu choice 0 **[measured]**."""
    if width:
        return payload
    return payload + _NL if term else payload


def _drain(proc, sel, *, idle: float, deadline: float) -> tuple[str, bool]:
    """Read stdout until the process stalls waiting for input (returns the new output + alive=True),
    exits (alive=False) or the deadline passes. A stall -- select times out, process alive --
    is how we know it printed a prompt and is now blocked on read()."""
    buf = bytearray()
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            try:                                             # flush anything still buffered
                rest = proc.stdout.read() or b""
            except (OSError, ValueError):
                rest = b""
            buf += rest
            return buf.decode("latin1"), False
        if sel.select(idle):
            try:                                             # read1: return what's buffered, never
                b = proc.stdout.read1(4096)                  # block waiting to fill 4096 bytes
            except (OSError, ValueError):
                b = b""
            if not b:                                        # EOF without poll yet
                return buf.decode("latin1"), proc.poll() is None
            buf += b
        elif buf:                                        # stalled with output in hand = a prompt
            return buf.decode("latin1"), True
        # stalled with no output yet: keep waiting until the deadline
    return buf.decode("latin1"), proc.poll() is None


def drive_to_menu(proc, sel, *, idle: float, deadline: float, width=None, tries: int = 3):
    """Drain to the first menu, benignly ANSWERING any pre-menu prompt (a `what is your name?` /
    `username:` gate that many challenges put before the menu) so the crawl/driver lands ON the menu
    instead of feeding a menu option to that prompt and desyncing. Each pre-menu prompt is classified
    and answered like a field (a number, an index, or a short string). Returns (last_text, alive)."""
    out, alive = _drain(proc, sel, idle=idle, deadline=min(deadline, time.monotonic() + 1.5))
    for _ in range(tries):
        if _looks_like_menu(out) or not alive:
            break
        prompt = _tail_prompt(out)
        ftype = classify_prompt(prompt)
        if ftype == "num":
            send = _scalar(_VALUE["num"], width)
        elif ftype == "idx":
            send = _scalar(_VALUE["idx"], width)
        elif ftype == "yn":
            send = _scalar(yn_answer(prompt), width)
        else:
            send = _data(_VALUE["str"], width)
        try:
            proc.stdin.write(send)
            proc.stdin.flush()
        except (OSError, ValueError):
            break
        out, alive = _drain(proc, sel, idle=idle, deadline=min(deadline, time.monotonic() + 1.5))
    return out, alive


def crawl_menu(spawn, options, *, max_fields: int = 10, idle: float = 0.2,
               per_option: float = 3.0, width=None) -> dict[str, list[str]]:
    """Learn each option's ordered field template by DRIVING the live process one prompt at a time.

    `spawn()` returns a fresh subprocess.Popen (stdin=PIPE, stdout=PIPE, stderr merged) -- the stage
    wraps the sandbox; a test passes a fake. For each option we start a clean process, drive to the
    menu, select the option, then repeatedly: read to the next prompt, classify it, feed a typed
    value, and record the field -- until the menu re-appears (flow done) or the process exits. Pure
    best-effort: any failure yields no template (the caller falls back). `width` selects the
    fixed-width (read(fd, buf, W)) encoding; None drives the target line-by-line."""
    model: dict[str, list[str]] = {}
    for opt in options:
        proc = None
        try:
            proc = spawn()
            sel = selectors.DefaultSelector()
            sel.register(proc.stdout, selectors.EVENT_READ)
            # Pass any pre-menu gate FIRST, then start the per-option budget -- the name-gate
            # navigation must not eat into the time to crawl the option's own fields.
            drive_to_menu(proc, sel, idle=idle, deadline=time.monotonic() + per_option, width=width)
            deadline = time.monotonic() + per_option
            try:
                proc.stdin.write(_scalar(opt.encode(), width))
                proc.stdin.flush()
            except (OSError, ValueError):                     # process quit before we could select
                continue
            fields: list[str] = []
            last_num = 0
            returned = False       # did the menu come back? (option completed, process alive)
            for _ in range(max_fields):
                out, alive = _drain(proc, sel, idle=idle, deadline=deadline)
                if _looks_like_menu(out):
                    # A PROMPT PRINTED AND NOT WAITED ON is still a field. An edit reads its data
                    # only when the slot holds an object -- `printf("data: "); if (db[i]) read(...)`
                    # -- and an isolated crawl never primes one, so the option printed `data: `,
                    # skipped the read and looped straight back to the menu. The model then said
                    # `2 -> [idx, num]`: no buffer, so no sequence could overflow anything, and a
                    # notebook whose overflow is three operations deep fuzzed 6,064 times with
                    # zero crashes **[measured]**. The prompt is the evidence the field exists;
                    # the guard is why it was not read this time.
                    if _skipped_prompt(out[:_menu_start(out)]):
                        fields.append("str")
                    returned = True
                    break
                if not alive:
                    break
                prompt = _tail_prompt(out)
                ftype = classify_prompt(prompt)
                if ftype == "num":
                    last_num = int(_VALUE["num"])
                    send = _scalar(_VALUE["num"], width)
                    fields.append(ftype)
                elif ftype == "idx":
                    send = _scalar(_VALUE["idx"], width)
                    fields.append(ftype)
                elif ftype == "yn":                      # context-sensitive: 'n' to a continue/repeat
                    ans = yn_answer(prompt)              # prompt (else it loops), 'y' to save/confirm
                    send = _scalar(ans, width)
                    fields.append("yn=" + ans.decode())  # record the answer so replay matches
                else:                                    # a data buffer sized to a preceding size
                    payload = b"A" * last_num if (width and last_num) else _VALUE["str"]
                    send = _data(payload, width)
                    fields.append(ftype)
                try:
                    proc.stdin.write(send)
                    proc.stdin.flush()
                except (OSError, ValueError):
                    break
            # Record an option that COMPLETED and returned to the menu, even when it read no
            # fields: a no-argument action -- a fixed-size `malloc`, a bare `free`/`use`/`print`
            # -- is a real menu operation, and the heap op-sequences (double-free, use-after-free)
            # are built out of exactly these. The menu reprinting is the completion signal: an
            # option that EXITED the process ("quit") never returns to it (and any "bye" line it
            # prints must not be mistaken for a field), so it stays unrecorded and no sequence
            # selects it and cuts itself short.
            if returned:
                model[opt] = fields
        except Exception:                                    # noqa: BLE001 -- best-effort probe
            pass
        finally:
            if proc is not None:
                _kill(proc)
    return model


def _kill(proc) -> None:
    # Close the pipes FIRST, suppressing the BrokenPipe from flushing buffered bytes to a process
    # that has already exited -- a menu's "Exit" option makes this the common case. Left to garbage
    # collection, that unflushed BufferedWriter raises an *unraisable* BrokenPipeError the caller
    # cannot catch (and which pytest turns into a failure), so the crawl looked flaky on any target
    # that can quit mid-probe.
    for stream in (getattr(proc, "stdin", None), getattr(proc, "stdout", None)):
        try:
            if stream is not None:
                stream.close()
        except Exception:                                    # noqa: BLE001
            pass
    try:
        proc.kill()
        proc.wait(timeout=1)
    except Exception:                                        # noqa: BLE001
        pass


_OVERFLOW = 512   # bytes past a typical stack/heap buffer -- reaches the saved return address


def _fill(fields, *, big_last: bool = False, idx: bytes = b"1", num: bytes = b"16",
          big: bytes = b"B" * 200, width=None, no_term: bool = False) -> bytes:
    """Input for ONE invocation of an option with the given field template. `big_last` makes the
    last STRING field over-long (the overflow payload); otherwise every field gets a small in-bounds
    value of the right type. A string that FOLLOWS a size field is padded to that many bytes, so a
    `read(fd, buf, size)` allocator gets exactly what it asked for -- a short fill would under-read
    and desync every later option. `width` switches scalars to fixed-width (read(fd, buf, W)).

    The overflow payload alone is not enough when a `read(fd, buf, size)` gates the copy on a
    caller-supplied length: the buffer read stops at `size` bytes no matter how long the string is
    (this is exactly the `Author Note size:` then `Note:` flow). So when overflowing, the size field
    that governs the buffer -- the last `num` before the target string -- is driven LARGE too, and
    the string is filled to match, so the copy actually runs off the end."""
    last_str = max((i for i, f in enumerate(fields) if f == "str"), default=-1)
    # The size field that governs the overflowable buffer: the last num BEFORE the target string
    # (a leading `Age:` num is not a buffer size). Only relevant when we are trying to overflow.
    size_idx = (max((i for i, f in enumerate(fields) if f == "num" and i < last_str), default=-1)
                if big_last and last_str >= 0 else -1)
    out = bytearray()
    sz = 0
    for i, f in enumerate(fields):
        if f == "idx":
            out += _scalar(idx, width)
        elif f == "num":
            if i == size_idx:
                out += _scalar(str(_OVERFLOW).encode(), width)   # ask for far more than the buffer
                sz = _OVERFLOW
            else:
                out += _scalar(num, width)
                try:
                    sz = int(num)
                except ValueError:
                    sz = 0
        elif big_last and i == last_str:
            n = _OVERFLOW if size_idx >= 0 else len(big)
            out += _data(b"B" * n, width, term=not (no_term and sz))
        else:
            payload = b"A" * sz if 0 < sz <= 4096 else b"AAAA"   # match the preceding size
            out += _data(payload, width, term=not (no_term and sz))
    return bytes(out)


def _is_alloc(fields) -> bool:
    """An allocating option (add/create) reads a size (num), usually with a string to fill AFTER it
    -- the "how many bytes?" then the buffer. A size-only option (just num(s), the classic
    `malloc(size)` menu) also allocates. Leading name/label strings before the size are fine.

    `add(slot, count)` counts too -- a size into a SLOT TABLE, with the buffer filled by a separate
    option (`fill(slot)`). That shape was not recognised at all, so a menu whose only creator is
    `1.add(idx, records)` named NO allocator and every op sequence began by driving an object that
    had never been created **[measured]**. It is also the shape where an integer overflow in the
    allocation matters: the copy length is recomputed by the other option, from the count, so the
    wrap under-allocates without under-copying."""
    ni = next((i for i, f in enumerate(fields) if f == "num"), None)
    if ni is None:
        return False
    return (any(f == "str" for f in fields[ni + 1:])
            or all(f == "num" for f in fields)
            or all(f in ("num", "idx") for f in fields))


def alloc_primers(model: dict, alloc, width=None) -> list[bytes]:
    """Input that creates TWO live objects with an allocating option -- the state every overflow,
    use-after-free and code-pointer hijack sequence starts from. Shared by the op-sequence builder
    and the primitive-chaining search, which each had their own copy of it, each wrong in the same
    two ways:

      * DISTINCT SLOTS. `one + one` drove the option's default id twice, so a slot-table menu ended
        up with ONE live object and a leaked chunk -- and an overflow needs a neighbour to reach.
        Both copies carried a comment claiming two objects; neither made two.
      * An UNDERSIZED allocation, which no other shape can reach. Where the creator takes a count
        and the buffer is filled by a SEPARATE option, the copy length is recomputed from that
        count, so size arithmetic that wraps (`(unsigned)(n * 16)`) allocates nothing like enough
        and the fill runs off the chunk -- an integer overflow with something to aim. The wrap
        thresholds are the only counts that do it: byte mutation effectively never emits the
        decimal text of a nine-digit number, and the "large" values every other shape drives (999,
        0x7FFFFFFF) make malloc REFUSE rather than under-allocate. Only for a count-WITHOUT-buffer
        creator: where the size field is followed by the string it fills, a wrap under-copies by
        the same amount and there is no overflow to find -- which also leaves every size-then-data
        notebook's budget exactly as it was.

    Default primer first, so a caller that stops at the first success behaves as it always did."""
    if alloc is None:
        return []
    fields = model.get(alloc) or []

    def _op(**kw):
        return _scalar(str(alloc).encode(), width) + _fill(fields, width=width, **kw)

    if any(x == "idx" for x in fields):
        out = [_op(idx=b"0") + _op(idx=b"1")]
    else:
        one = _op()
        out = [one + one]
    if "num" in fields and "str" not in fields:
        out += [_op(idx=b"0", num=wn) + _op(idx=b"1", num=b"2") for wn in _WRAP_NUMS]
    return out


def menu_op_sequences(model: dict, options, *, max_seqs: int = 48, width=None,
                      allocates: bool = False) -> list[bytes]:
    """Correctly-typed heap operation sequences built from a crawled menu model.

    Picks an allocating option (a size-then-string flow) to prime an object, then drives every other
    option once with an over-long last string (heap-overflow shape); for index-taking options it also
    drives twice on the same id (double-free / UAF shape) and once with an OUT-OF-RANGE index. That
    last shape matters: a menu that bounds an index only on the high side (`cmp idx, N`; no lower
    bound) takes a NEGATIVE index straight into an OOB read/write of the object table (CWE-129, the
    "auth-or-out" class). Generic seeds never reach the indexed handler at all -- they can't get past
    the front-door menu -- so only a correctly-typed op-sequence can put a bad index there at all.
    Empty when the model has no allocator."""
    opts = [str(o) for o in (options or [])]
    present = [o for o in opts if o in model]
    alloc = next((o for o in present if _is_alloc(model[o])), None)
    # THREE SHAPES OF PRIMER, because none of them can be told from the others by its fields:
    #   * a size-flow option (`add(size, data)`) -- the one this function has always used;
    #   * a no-ARGUMENT option (empty template) -- a fixed-size `malloc`, and equally the bare
    #     `free`/`use`/`print` whose SEQUENCE is the double-free / use-after-free;
    #   * an INDEX-ONLY option (`new(slot)`) -- a fixed-size record in a slot table,
    #     `db[i] = malloc(sizeof *db[i])`, which asks for no size at all.
    # The third was missing and the first was TRUSTED, and both halves of that cost the same
    # target: a menu of `1.add(idx) 2.edit(idx,len,data) 3.show(idx) 4.free(idx)` names `2` as
    # its allocator (a size followed by a buffer is exactly an edit's shape too), so every
    # sequence began by editing an object that had never been created and nothing in the menu
    # ever allocated. EVERY candidate is now primed with in turn -- which is what the tracer and
    # the fault are for -- and the sequences are interleaved so a later candidate still gets its
    # strongest shapes in under the cap.
    noarg = [o for o in present if not model[o]]
    # The index-only shape needs evidence from OUTSIDE the menu that the target allocates at all:
    # with nothing but index-only options, `new(slot)` and `delete(slot)` are the same template.
    # heap_discover has resolved a malloc/free pair by the time it asks; a caller that cannot say
    # gets exactly the old answer, and a menu of index-only operations with no create still
    # emits nothing.
    idx_only = ([o for o in present if model[o] and all(x == "idx" for x in model[o])]
                if allocates else [])
    if alloc is None and not noarg and not idx_only:
        return []
    def _op(o, **kw):                                    # option choice + its filled fields
        return _scalar(o.encode(), width) + _fill(model[o], width=width, **kw)
    # Out-of-range indices for the unchecked-index shape: negative (below a high-only bound) and far
    # above any plausible table size. The mutator widens these further, but the campaign must be
    # handed a valid navigation that ALREADY lands a bad index in the handler to build from.
    oob = (b"-1", b"-2", b"9999")
    seqs: list[bytes] = []
    # --- the precise path: prime objects with a candidate creator, then drive each option with an
    #     over-long last string / a repeated id / a bad index / a trigger after the write. ---
    primers = list(alloc_primers(model, alloc, width))
    for c in idx_only[:3]:
        primers.append(_op(c, idx=b"0") + _op(c, idx=b"1"))
    # The ops that CARRY a payload go first for every primer. An option with a string field is the
    # only one that can overflow anything, and the cap is tight: with the options taken in menu
    # order, the index-only shapes of a four-option menu filled it and the one sequence that
    # mattered -- overflow, then call -- fell one item past the end **[measured]**.
    ordered = ([o for o in present if "str" in model[o]]
               + [o for o in present if model[o] and "str" not in model[o]])
    per_primer = []
    for prime in primers:
        mine: list = []
        for o in ordered:
            f = model[o]
            if not f:
                continue
            idx_opt = any(x == "idx" for x in f)
            for iv in (b"0", b"1"):                      # target id 0 and 1 (0- or 1-based tables)
                mine.append(prime + _op(o, big_last=True, idx=iv))
                # ...and then an index-only option, which is where an overwritten CODE POINTER is
                # CALLED. The corrupting write and the detonation are DIFFERENT operations, so a
                # sequence that stops at the write faults nowhere -- an overflow into the
                # object's own callback is invisible until something calls it.
                for tr in idx_only:
                    mine.append(prime + _op(o, big_last=True, idx=iv, no_term=True)
                                + _op(tr, idx=iv))
                    # ...and the NEIGHBOUR's. An overflow runs forward, so the code pointer it
                    # reaches first belongs to the next object, not this one -- and when the
                    # callback sits at the START of the record (`struct { void (*show)(); char
                    # text[]; }`) the overflowed object's own pointer is BEHIND the write and can
                    # never be reached. Only the same id was ever detonated, so that whole layout
                    # was invisible: the write landed, nothing called it, and the sequence faulted
                    # nowhere **[measured]**.
                    mine.append(prime + _op(o, big_last=True, idx=iv, no_term=True)
                                + _op(tr, idx=(b"1" if iv == b"0" else b"0")))
                if all(x == "idx" for x in f):           # double-free / UAF: index-only op, twice
                    mine.append(prime + _op(o, idx=iv) + _op(o, idx=iv))
            if idx_opt:
                for iv in oob:                           # unchecked-index (CWE-129)
                    mine.append(prime + _op(o, idx=iv))
                    mine.append(prime + _op(o, big_last=True, idx=iv))
        per_primer.append(mine)
    # INTERLEAVED, not concatenated: the cap is a few dozen sequences and one primer's shapes run
    # to more than that on a five-option menu, so a concatenated list spends the whole budget on
    # whichever candidate happened to be named first -- which is the mistake above, in a second
    # form. Round-robin gives every candidate its strongest shapes.
    for i in range(max((len(m) for m in per_primer), default=0)):
        for m in per_primer:
            if i < len(m):
                seqs.append(m[i])
    # --- generic path: reach use-after-free / double-free / double-use even when the allocator and
    #     the trigger take NO argument, which the size-flow heuristic above cannot name. An
    #     alloc->free->use flow is literally "select every option in order", and no single-option
    #     seed reaches it; a no-arg double-free is the SAME option twice once an object is live. ---
    gprime = b"".join(_op(o) for o in noarg) or (_op(alloc) if alloc else b"")
    if not gprime and idx_only:
        gprime = _op(idx_only[0], idx=b"0")
    seqs.append(b"".join(_op(o) for o in present))       # walk every option in menu order
    seqs.append(b"".join(_op(o) for o in reversed(present)))   # and in reverse
    for o in present:
        f = model[o]
        ivs = (b"0", b"1") if any(x == "idx" for x in f) else (None,)
        for iv in ivs:
            kw = {"idx": iv} if iv is not None else {}
            # prime a live object with the no-arg options, then drive THIS op twice: a bare
            # free/use repeated (CWE-416/CWE-415), or free(id) on the same id twice.
            seqs.append(gprime + _op(o, **kw) + _op(o, **kw))
    out, seen = [], set()
    for s in seqs:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out[:max_seqs]


#: Counts that make a size computation UNDER-ALLOCATE, so the allocation is tiny while the copy
#: that follows is huge. Three families, because the arithmetic that wraps is not visible from the
#: menu and each family needs a different value:
#:
#:   * a 32-bit product -- 2**32//16, //8, //4, and 2**32 itself for `n + 1` / `n * 1`;
#:   * a 32-bit product truncated to 16 bits (`unsigned short sz = n * 16`), where the thresholds
#:     are 2**16 over the same element sizes -- four orders of magnitude lower, so none of the
#:     32-bit values comes anywhere near them;
#:   * zero, for `malloc(n * k)` with the length taken from somewhere else, and for the `n - 1`
#:     shape whose allocation is the one that wraps.
#:
#: 32-bit first: a 64-bit host's `size_t` arithmetic is the common case, and a caller that stops
#: at the first success should not pay for the rarer ones.
_WRAP_NUMS = (b"268435456", b"536870912", b"1073741824", b"4294967296",
              b"4096", b"8192", b"16384", b"65536", b"0")

# Numeric values worth trying for a size/count/index field: boundaries, a negative (unchecked
# index / signed-vs-unsigned), and sizes that overflow a typical stack or heap buffer.
_MENU_NUMS = (0, 1, 2, 8, 16, 32, 64, 100, 127, 128, 255, 256, 512, 1024, 4096,
              -1, -2, 9999, 65535, 0x7FFFFFFF)
_STR_ALPHABET = bytes(c for c in range(1, 256) if c != 0x0A)   # any byte but newline (ends a line)


class MenuMutator:
    """Structure-aware mutator for a numbered-menu / interactive-protocol target.

    A blind byte mutator flips the option digits and desyncs the state machine on the very first
    mutation, so the handlers BEHIND the menu -- where the bug lives -- are never reached: a menu
    service fuzzed blind runs thousands of executions parked at the front door. This mutator keeps
    every navigation VALID -- real option tokens, correctly-typed fields, a size-prefixed read
    matched to its size so the stream never desyncs -- and mutates only the field PAYLOADS: a
    string grown into an overflow, a size/index driven to a boundary or a negative, a dictionary
    token injected. It GENERATES a fresh valid walk each call from the crawled menu model rather
    than editing the raw seed, so a corrupted corpus entry can never derail the navigation.

    Line-based targets (gets/fgets/scanf) get newline-delimited fields with newline-free string
    payloads; a fixed-width read(fd,buf,W) protocol gets `width`-padded scalars and raw data."""

    def __init__(self, rng, model: dict, options, *, width=None, dictionary=None):
        self.rng = rng
        self.width = width
        self.dict = [d for d in (dictionary or []) if d and _NL not in d]
        # Keep only options the crawl learned a field template for; those are the ones we can drive.
        self.model = {}
        for o in (options or []):
            f = model.get(str(o)) or model.get(o)
            if f:
                self.model[str(o)] = list(f)
        self.options = list(self.model) or [str(o) for o in (options or []) if str(o)]
        self.alloc = next((o for o in self.options if _is_alloc(self.model.get(o, []))), None)

    def mutate(self, data: bytes = b"", corpus=()) -> bytes:
        """A fresh, valid multi-operation navigation with mutated fields. `data`/`corpus` are
        ignored on purpose: regenerating from the model is what keeps the walk in-protocol."""
        if not self.options:
            return data or b"1\n"
        rng = self.rng
        out = bytearray()
        # Prime with allocations so index / free / print / modify operations act on live objects
        # (a use-after-free or an unchecked index only misbehaves once something exists to touch).
        if self.alloc and rng.random() < 0.8:
            for _ in range(rng.randint(1, 2)):
                out += self._op(self.alloc, overflow=False)
        for _ in range(rng.randint(1, 6)):
            out += self._op(rng.choice(self.options), overflow=rng.random() < 0.4)
        return bytes(out) or b"1\n"

    def _op(self, o: str, *, overflow: bool) -> bytes:
        fields = self.model.get(o, [])
        out = bytearray(_scalar(o.encode(), self.width))       # the option choice, always valid
        rng = self.rng
        last_str = max((i for i, f in enumerate(fields) if f == "str"), default=-1)
        # the size field that governs the overflowable buffer: the last num BEFORE the last string
        size_i = (max((i for i, f in enumerate(fields) if f == "num" and i < last_str), default=-1)
                  if overflow and last_str >= 0 else -1)
        sz = 0
        for i, f in enumerate(fields):
            if f == "idx":
                out += _scalar(self._index(), self.width)
            elif f == "num":
                if i == size_i:
                    n = rng.choice((256, 512, 1024, 4096))     # ask for far more than the buffer
                    sz = n
                    out += _scalar(str(n).encode(), self.width)
                else:
                    n = rng.choice(_MENU_NUMS)
                    sz = n if 0 < n <= 4096 else 0
                    out += _scalar(str(n).encode(), self.width)
            else:                                              # str
                if overflow and i == last_str:
                    ln = sz or rng.choice((128, 256, 512, 1024))
                    out += _data(bytes((rng.choice(b"ABCD"),)) * ln, self.width)
                else:
                    out += _data(self._str(sz), self.width)
        return bytes(out)

    def _index(self) -> bytes:
        r = self.rng.random()
        if r < 0.6:                                            # a plausible in-range id
            return str(self.rng.randint(0, 4)).encode()
        return str(self.rng.choice((-1, -2, 9999, 100000, 0x7FFFFFFF))).encode()

    def _str(self, sz: int) -> bytes:
        rng = self.rng
        if self.dict and rng.random() < 0.3:
            return rng.choice(self.dict)
        if 0 < sz <= 4096:                                     # match a preceding size: no desync
            return bytes((rng.choice(b"ABCD"),)) * sz
        ln = rng.randint(1, 48)
        return bytes(rng.choice(_STR_ALPHABET) for _ in range(ln))


#: A benign value per field type, used to walk a linear protocol to its end while LEARNING it.
#: Deliberately small and valid: the crawl is discovering the shape, not attacking it.
_PROBE = {"idx": b"1", "num": b"16", "str": b"probe", "yn": b"y"}

#: Line lengths to try, each just under a plausible `read(0, buf, N)` buffer (64/128/256/512).
#: N is not knowable from outside and BOTH directions are wrong: a line longer than N spills its
#: tail into the next field and desyncs every field after it, while a line far shorter than N
#: cannot reach a defect that needs the buffer nearly full. Measured both failures on `replaceme`
#: -- a 160-byte filler ahead of its 0x80 reader swallowed field two's expression, and a 48-byte
#: one left the result 165 bytes against a 192-byte buffer, just short of the overflow. So the
#: size is swept, and the campaign's own feedback keeps whichever engaged the parser.
_LINE_SIZES = (48, 112, 240, 496)

#: Runs inside an example that look like a FIELD rather than a delimiter.
_FIELDISH = re.compile(rb"[A-Za-z0-9_.-]{2,}")

#: Past this a "protocol" is a loop, not a field list -- a REPL re-prompting forever looks like
#: an endless sequence of fields, and the model only has to describe one pass.
_MAX_LINEAR = 8


def crawl_linear(spawn, *, max_fields: int = _MAX_LINEAR, idle: float = 0.15,
                 timeout: float = 5.0, width=None) -> list:
    """The ordered field types of a LINEAR prompt protocol: `['str', 'str']`, or [] if the target
    does not prompt.

    A linear protocol is a numbered menu minus the dispatch: the program prints a prompt, reads a
    field, prints the next prompt, reads the next field, and then acts on all of them. `crawl_menu`
    cannot model it (there are no options to select) and `detect_menu` does not fire, so such a
    target got the blind path -- and a blind campaign delivers ONE blob to stdin, where a program
    that reads its fields with separate `read(0, buf, N)` calls takes the whole blob as field one
    and reaches EOF on field two.

    Measured on the HTB target `replaceme`: 63,234 executions produced nothing, and every single
    one was rejected at the first gate with "Missing 's/' at the beginning", because the sed
    expression it needs in field TWO arrived inside field one. Driven one field per prompt, the
    same bytes reach the parser.

    `spawn()` returns a fresh interactive process (the stage wraps the sandbox; a test passes a
    fake). Best-effort: any failure yields [], and the campaign keeps the blind path.
    """
    proc = None
    try:
        proc = spawn()
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        fields: list = []
        out, alive = _drain(proc, sel, idle=idle, deadline=min(deadline,
                                                               time.monotonic() + 1.5))
        while alive and len(fields) < max_fields and time.monotonic() < deadline:
            prompt = _tail_prompt(out)
            if not prompt:
                break
            ftype = classify_prompt(prompt)
            fields.append(ftype)
            send = (_scalar(yn_answer(prompt), width) if ftype == "yn"
                    else _scalar(_PROBE[ftype], width) if ftype in ("idx", "num")
                    else _data(_PROBE["str"], width))
            try:
                proc.stdin.write(send)
                proc.stdin.flush()
            except (OSError, ValueError):
                break
            out, alive = _drain(proc, sel, idle=idle,
                                deadline=min(deadline, time.monotonic() + 1.5))
        return fields
    except Exception:                                    # discovery is never a blocker
        return []
    finally:
        if proc is not None:
            _kill(proc)


def _grow_to(ex: bytes, size: int) -> bytes:
    """The example with its LAST field expanded so the whole line is `size` bytes.

    Clipping the example to the slot instead would break the grammar at the far end: a
    `s/old/new/` cut at 128 bytes loses its closing delimiter, and the target answers "Missing
    '/' after the replacement" -- measured. Growing a field keeps every delimiter the parser
    checks and still fills the buffer the defect needs full.
    """
    runs = list(_FIELDISH.finditer(ex))
    if not runs:
        return b""
    last = runs[-1]
    room = size - (len(ex) - (last.end() - last.start()))
    if room < 1:
        return b""
    return ex[:last.start()] + b"A" * room + ex[last.end():]


def linear_seeds(fields: list, examples=(), *, max_seeds: int = 24) -> list:
    """Seeds shaped like the protocol: one LINE per field, with a documented example -- as given
    and grown to fill the field -- tried in each position and at each plausible line size.

    A linear protocol's defect is behind a particular field: `replaceme`'s overflow is in the
    SECOND one and only reachable once the first holds enough text for the replacement to work
    on, so a seed has to fill every field, and which field carries the interesting value is
    exactly what the campaign has to try. Filler for the other fields comes from the example's
    own tokens, because a search-and-replace or lookup grammar refers to content the other field
    must contain.
    """
    if not fields:
        return []
    out: list = []
    exs = [e for e in (examples or ()) if e]
    for size in _LINE_SIZES:
        for ex in exs or [b"A" * size]:
            toks = _FIELDISH.findall(ex) or [b"A"]
            filler = (toks[0] * (1 + size // max(1, len(toks[0]))))[:size]
            for variant in (ex, _grow_to(ex, size)):
                if not variant or len(variant) > size:
                    continue
                for pos in range(len(fields)):
                    lines = []
                    for i, f in enumerate(fields):
                        if i == pos:
                            lines.append(variant)
                        elif f == "num":
                            lines.append(_PROBE["num"])
                        elif f == "idx":
                            lines.append(_PROBE["idx"])
                        elif f == "yn":
                            lines.append(b"y")
                        else:
                            lines.append(filler)
                    out.append(_NL.join(lines) + _NL)
    seen, uniq = set(), []
    for b in out:
        if b not in seen:
            seen.add(b)
            uniq.append(b)
    return uniq[:max_seeds]
