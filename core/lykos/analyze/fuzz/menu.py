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


# --- field encoding: line-delimited by default, or FIXED-WIDTH for a read(fd, buf, W) protocol ---
# A target that reads scalars with `read(0, buf, W)` (not fgets/scanf) consumes exactly W bytes per
# field regardless of newlines; a value+"\n" then under-reads and desyncs every later field. In
# fixed-width mode each scalar is padded to W bytes (atoi stops at the padding) and a data buffer is
# sent raw (its read already consumed exactly its size).
def _scalar(value: bytes, width) -> bytes:
    return (value + b" " * (width or 0))[:width] if width else value + _NL


def _data(payload: bytes, width) -> bytes:
    return payload if width else payload + _NL


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
            deadline = time.monotonic() + per_option
            _drain(proc, sel, idle=idle,
                   deadline=min(deadline, time.monotonic() + 1.5))  # first menu
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
                    returned = True
                    break
                if not alive:
                    break
                ftype = classify_prompt(_tail_prompt(out))
                fields.append(ftype)
                if ftype == "num":
                    last_num = int(_VALUE["num"])
                    send = _scalar(_VALUE["num"], width)
                elif ftype == "idx":
                    send = _scalar(_VALUE["idx"], width)
                else:                                    # a data buffer sized to a preceding size
                    payload = b"A" * last_num if (width and last_num) else _VALUE["str"]
                    send = _data(payload, width)
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
          big: bytes = b"B" * 200, width=None) -> bytes:
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
            out += _data(b"B" * n, width)                        # fill the over-large read
        else:
            payload = b"A" * sz if 0 < sz <= 4096 else b"AAAA"   # match the preceding size
            out += _data(payload, width)
    return bytes(out)


def _is_alloc(fields) -> bool:
    """An allocating option (add/create) reads a size (num), usually with a string to fill AFTER it
    -- the "how many bytes?" then the buffer. A size-only option (just num(s), the classic
    `malloc(size)` menu) also allocates. Leading name/label strings before the size are fine."""
    ni = next((i for i, f in enumerate(fields) if f == "num"), None)
    if ni is None:
        return False
    return any(f == "str" for f in fields[ni + 1:]) or all(f == "num" for f in fields)


def menu_op_sequences(model: dict, options, *, max_seqs: int = 40, width=None) -> list[bytes]:
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
    # A no-ARGUMENT option (empty field template) is a candidate allocator or trigger the size-flow
    # heuristic cannot name: a fixed-size `malloc` reads nothing, and so do the bare `free`/`use`/
    # `print` operations whose SEQUENCE is the double-free / use-after-free. With neither a size-flow
    # allocator nor any no-arg option there is nothing that can build heap state, so still empty --
    # which keeps a menu of index-only operations (delete/modify by id, no create) from emitting
    # sequences that act on objects it can never allocate.
    noarg = [o for o in present if not model[o]]
    if alloc is None and not noarg:
        return []
    def _op(o, **kw):                                    # option choice + its filled fields
        return _scalar(o.encode(), width) + _fill(model[o], width=width, **kw)
    # Out-of-range indices for the unchecked-index shape: negative (below a high-only bound) and far
    # above any plausible table size. The mutator widens these further, but the campaign must be
    # handed a valid navigation that ALREADY lands a bad index in the handler to build from.
    oob = (b"-1", b"-2", b"9999")
    seqs: list[bytes] = []
    # --- precise path: a size-flow allocator (add/create reading a size) was identified. Prime two
    #     objects, then drive each option with an over-long last string / doubled id / bad index. ---
    if alloc is not None:
        one = _op(alloc)
        prime = one + one                                # two objects: ids 0 and 1 both exist
        for o in present:
            f = model[o]
            if not f:
                continue
            idx_opt = any(x == "idx" for x in f)
            for iv in (b"0", b"1"):                      # target id 0 and 1 (0- or 1-based tables)
                seqs.append(prime + _op(o, big_last=True, idx=iv))
                if all(x == "idx" for x in f):           # double-free / UAF: index-only op, twice
                    seqs.append(prime + _op(o, idx=iv) + _op(o, idx=iv))
            if idx_opt:
                for iv in oob:                           # unchecked-index (CWE-129)
                    seqs.append(prime + _op(o, idx=iv))
                    seqs.append(prime + _op(o, big_last=True, idx=iv))
    # --- generic path: reach use-after-free / double-free / double-use even when the allocator and
    #     the trigger take NO argument, which the size-flow heuristic above cannot name. An
    #     alloc->free->use flow is literally "select every option in order", and no single-option
    #     seed reaches it; a no-arg double-free is the SAME option twice once an object is live. ---
    gprime = b"".join(_op(o) for o in noarg) or (_op(alloc) if alloc else b"")
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
