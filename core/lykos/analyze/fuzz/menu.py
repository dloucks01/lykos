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

# a numbered menu item: "1 - Add", "2. Modify", "[3] Print", "(4) Delete", "5) Quit", "6: exit".
# The digit is delimited by a closing bracket OR a separator, and a LETTER must follow (so version
# strings like "1.5 GB" or "2.3.4" do not read as menu options).
_OPT = re.compile(r"^\s*[\[\(<]?\s*(\d{1,2})\s*(?:[\]\)>]|[-.):|])\s*[A-Za-z]")
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
        for line in text.splitlines():
            m = _OPT.match(line)
            if m:
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

# A prompt naming a size/count/age is a NUMBER; one naming an id/index/slot is an INDEX (its
# boundary values -- 0, capacity -- are what an OOB-index probe drives); else a STRING.
# The index keywords are index INDICATORS only (id/index/slot/...), never object nouns like
# "author" -- "Author Note size" is a size, not an index, so NUM must win there.
_NUM_KW = re.compile(r"(size|length|\blen\b|count|number|\bnum\b|\bage\b|amount|\bqty\b|quantity|"
                     r"bytes|how many|price|score|year|\bhow much\b)", re.I)
_IDX_KW = re.compile(r"(\bid\b|\bidx\b|index|\bslot\b|\bentry\b|position|\bpos\b|\bwhich\b|"
                     r"\bno\.?\b)", re.I)


def classify_prompt(text: str) -> str:
    """Field type a prompt asks for: 'idx' (array index / id), 'num' (a size/count) or 'str'.

    A size keyword (num) wins over a bare index word so "Note size" is a size; an explicit index
    word (id/index/slot) with no size keyword is an index; everything else is a string."""
    t = str(text or "")
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
    if after.strip():
        return after
    lines = [ln for ln in chunk.splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def _looks_like_menu(text: str) -> bool:
    """The option list re-appeared -- the current option's sub-flow has finished and looped."""
    return len(detect_menu([text])) >= 2


_VALUE = {"idx": b"1", "num": b"16", "str": b"AAAA"}


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


def crawl_menu(spawn, options, *, max_fields: int = 10, idle: float = 0.2,
               per_option: float = 3.0) -> dict[str, list[str]]:
    """Learn each option's ordered field template by DRIVING the live process one prompt at a time.

    `spawn()` returns a fresh subprocess.Popen (stdin=PIPE, stdout=PIPE, stderr merged) -- the stage
    wraps the sandbox; a test passes a fake. For each option we start a clean process, drive to the
    menu, select the option, then repeatedly: read to the next prompt, classify it, feed a typed
    value, and record the field -- until the menu re-appears (flow done) or the process exits. Pure
    best-effort: any failure yields no template for that option (the caller falls back)."""
    model: dict[str, list[str]] = {}
    for opt in options:
        proc = None
        try:
            proc = spawn()
            sel = selectors.DefaultSelector()
            sel.register(proc.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + per_option
            _drain(proc, sel, idle=idle,
                   deadline=min(deadline, time.monotonic() + 1.5))  # first menu
            proc.stdin.write(opt.encode() + _NL)
            proc.stdin.flush()
            fields: list[str] = []
            for _ in range(max_fields):
                out, alive = _drain(proc, sel, idle=idle, deadline=deadline)
                if _looks_like_menu(out) or not alive:
                    break
                ftype = classify_prompt(_tail_prompt(out))
                fields.append(ftype)
                try:
                    proc.stdin.write(_VALUE[ftype] + _NL)
                    proc.stdin.flush()
                except (OSError, ValueError):
                    break
            if fields:
                model[opt] = fields
        except Exception:                                    # noqa: BLE001 -- best-effort probe
            pass
        finally:
            if proc is not None:
                _kill(proc)
    return model


def _kill(proc) -> None:
    try:
        proc.kill()
        proc.wait(timeout=1)
    except Exception:                                        # noqa: BLE001
        pass


def _fill(fields, *, big_last: bool = False, idx: bytes = b"1", num: bytes = b"16",
          big: bytes = b"B" * 200) -> bytes:
    """Input lines for ONE invocation of an option with the given field template. `big_last` makes
    the last STRING field over-long (the overflow payload); otherwise every field gets a small
    in-bounds value of the right type."""
    last_str = max((i for i, f in enumerate(fields) if f == "str"), default=-1)
    out = bytearray()
    for i, f in enumerate(fields):
        if f == "idx":
            out += idx + _NL
        elif f == "num":
            out += num + _NL
        else:
            out += (big if (big_last and i == last_str) else b"AAAA") + _NL
    return bytes(out)


def _is_alloc(fields) -> bool:
    """An allocating option (add/create) reads a size (num) with a string to fill AFTER it -- the
    "how many bytes?" then the buffer. Leading name/label strings before the size are fine."""
    ni = next((i for i, f in enumerate(fields) if f == "num"), None)
    return ni is not None and any(f == "str" for f in fields[ni + 1:])


def menu_op_sequences(model: dict, options, *, max_seqs: int = 40) -> list[bytes]:
    """Correctly-typed heap operation sequences built from a crawled menu model.

    Picks an allocating option (a size-then-string flow) to prime an object, then drives every other
    option once with an over-long last string (heap-overflow shape) and, for index-only options,
    twice on the same id (double-free / UAF shape). Empty when the model has no allocator."""
    opts = [str(o) for o in (options or [])]
    alloc = next((o for o in opts if o in model and _is_alloc(model[o])), None)
    if alloc is None:
        return []
    one = alloc.encode() + _NL + _fill(model[alloc], big_last=False)
    prime = one + one                                    # two objects: ids 0 and 1 both exist
    seqs: list[bytes] = []
    for o in opts:
        f = model.get(o)
        if not f:
            continue
        ob = o.encode()
        for iv in (b"0", b"1"):                          # target id 0 and 1 (0- or 1-based tables)
            # overflow: after priming, drive this option with an over-long final string
            seqs.append(prime + ob + _NL + _fill(f, big_last=True, idx=iv))
            # double-free / UAF: an index-only option driven twice on the same object
            if all(x == "idx" for x in f):
                seqs.append(prime + ob + _NL + _fill(f, idx=iv) + ob + _NL + _fill(f, idx=iv))
    out, seen = [], set()
    for s in seqs:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out[:max_seqs]
