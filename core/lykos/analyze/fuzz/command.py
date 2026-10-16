"""Text-command interface: a line-oriented service whose actions are WORDS, not menu numbers.

`strncmp(cmd, "free", 4)` / `strcmp(verb, "use")` is the classic console / heap shell. The
numbered-menu path (menu.py) never fires on it -- there are no option digits -- and the verbs are
the comparison literals, which are often 2-3 characters, BELOW the string table's minimum length
(so a `strncmp(cmd, "use", 3)` literal is otherwise invisible to every stage). They are mined here
from a low-min-length raw scan, gated on the binary actually linking a string comparison, and
driven as line sequences.

The reason this needs its own path: a use-after-free is `free` then `use`, a double-free is `free`
twice. A byte mutator would have to invent BOTH words and ORDER them on consecutive lines, which it
effectively never does inside a budget; and COMPCOV/CmpLog help MATCH a word in one execution but
not SEQUENCE two of them across lines. The state machine is the barrier, exactly as for a numbered
menu -- so, like menu_op_sequences, this hands the campaign correctly-ordered navigations to build
from.
"""
from __future__ import annotations

import re

_NL = b"\n"
_CMP = ("strncmp", "strcmp", "strcasecmp", "strncasecmp")
_READLINE = ("fgets", "gets", "getline", "fscanf", "scanf", "getchar", "read")
# Structural / runtime tokens that are never a command verb, so a sequence does not spend its
# budget on them. Deliberately NOT filtered: free / read / open / close / new / ... -- those double
# as real command verbs, and the comparison-literal origin (below) is what earns a token its place.
_NOISE = {
    "main", "puts", "printf", "fprintf", "sprintf", "snprintf", "vprintf", "scanf", "sscanf",
    "fgets", "fputs", "fread", "fwrite", "fflush", "setbuf", "setvbuf", "getline", "fopen",
    "fclose", "fdopen", "stdin", "stdout", "stderr", "glibc", "gcc", "clang", "null", "true",
    "false", "usage", "strncmp", "strcmp", "strcasecmp", "strncasecmp", "strlen", "strncpy",
    "strcpy", "strcat", "strncat", "strchr", "strstr", "strtok", "memcpy", "memset", "memmove",
    "memcmp", "atoi", "atol", "strtol", "strtoul", "exit", "abort", "malloc", "calloc", "realloc",
}
# CRT / compiler-emitted symbol names that leak into the token scan and are never commands.
_NOISE_SUBSTR = ("dummy", "clones", "dtors", "ctors", "gmon", "tm_clone", "cxa", "libc",
                 "deregister", "register_tm", "start_main", "frame", "init_array", "fini")
#: Separators a dispatcher writes INSIDE its own comparison literal: `strncmp(line,"show=",5)`.
#: The literal is the dispatch token, so the verb is `show=` and a command is `show=<argument>` --
#: one line, not two. Mining the bare word instead produces `show`, which that very strncmp
#: rejects, so the handler is never entered however many sequences are tried.
_ARG_SEPS = "=:"
#: A verb, with the separator kept when the literal carries one.
_VERB = re.compile(r"([a-z][a-z_]{1,11})([=:]?)")
#: Arguments to try after a separator. A long filler for a copy in the handler, then the same
#: boundary/wrap values a config field gets -- because a handler that takes a NUMBER (a length, a
#: count, an index) is the shape whose defect no amount of byte mutation reaches: see
#: textconf.numeric_boundary_seeds on why the decimal text of a 10-digit number never appears.
_ARG_FILLERS = (b"A" * 64, b"A" * 256)
_ARG_NUMERIC = 10


def _tokens(data: bytes, minlen: int) -> list[str]:
    from ..invocation import raw_strings
    return [getattr(s, "value", s) for s in raw_strings(data, minlen=minlen)]


def mine_verbs(data: bytes, *, cap: int = 16) -> list[str]:
    """Candidate command verbs, or [] when the binary is not a line-oriented text-command matcher.

    Two gates keep this off the vast majority of binaries (strcmp alone is near-universal): the
    target must link a string-comparison primitive (the dispatch) AND a line reader (fgets/gets/
    scanf/...). Then the verbs are the short lowercase tokens from a min-length-3 scan -- below the
    string table's minimum, which is why a 2-3 char comparison literal never reaches the normal
    mining at all -- minus the runtime/structural names that are never commands."""
    tokset = set(_tokens(data, 2))
    if not any(c in tokset for c in _CMP) or not any(r in tokset for r in _READLINE):
        return []
    verbs: list[str] = []
    seen: set[str] = set()
    for t in _tokens(data, 3):
        m = _VERB.fullmatch(t)
        if m is None or t in seen:
            continue
        word = m.group(1)                              # the separator is not part of the NAME
        if word in _NOISE:
            continue
        if any(sub in word for sub in _NOISE_SUBSTR):  # CRT / compiler symbol, never a command
            continue
        seen.add(t)
        verbs.append(t)
    # KEYED FIRST, then shortest. A token whose literal already carries `=` or `:` is not a guess:
    # a compiler emits `show=` only because the program compares against it, whereas a bare
    # lowercase word is any identifier, string fragment or debug name that happened to survive the
    # scan. Ranking them together let sixteen such fragments fill the whole `cap` and leave the one
    # real dispatch token out of it -- measured on a target whose commands are `show=` and `name=`:
    # neither was mined, while `buf`, `std`, `uptr` and `data_` were **[measured]**.
    verbs.sort(key=lambda v: (v[-1] not in _ARG_SEPS, len(v), v))
    return verbs[:cap]


#: Magnitudes that make a LENGTH, COUNT or INDEX argument fault, in the order that works.
#:
#: Measured on a `show=<n>` handler reading n bytes out of a 64-byte buffer: every value from 65
#: to 4294967295 reports a heap-buffer-overflow, and `-1`, LONG_MAX and SIZE_MAX report NOTHING
#: AT ALL -- the C library rejects an operation that large before it touches any memory, so the
#: read never happens. Leading with the biggest value, which is the intuitive choice and the one
#: this code made first, therefore spends the seed budget on the only values that cannot work.
#:
#: These come first for that reason; `textconf`'s wrap thresholds follow, because those are tuned
#: for ALLOCATION arithmetic (`n * 16` wrapping a 32-bit size) where huge genuinely is the point.
#: `-1` is kept -- a signed length reaching memcpy becomes SIZE_MAX and faults on other targets --
#: just not first. `0` goes last: it cannot over-read anything.
_REACH_FIRST = (b"4096", b"256", b"65536", b"1048576", b"1024")


def _dangerous_first(limit: int) -> list[bytes]:
    """Boundary argument values, ordered so the ones that actually fault lead.

    `textconf`'s own order puts the type boundaries first (`0`, `-1`, `INT_MAX`, ...) and that
    order is a contract for its callers, so this reorders its own slice rather than touching it.
    """
    from .textconf import _BOUNDARY_VALUES

    def rank(v: bytes):
        try:
            n = int(v)
        except ValueError:
            return (3, 0)
        if n == 0:
            return (4, 0)                    # cannot over-read; last
        if n < 0:
            return (2, n)                    # SIZE_MAX once used as a length, but often rejected
        if n > 0xFFFFFFFF:
            return (3, -n)                   # measured: rejected before any memory is touched
        return (1, -n)                       # in range, biggest first
    rest = [v for v in sorted(_BOUNDARY_VALUES, key=rank) if v not in _REACH_FIRST]
    return (list(_REACH_FIRST) + rest)[:max(0, limit)]


def command_seeds(verbs, *, max_seeds: int = 96) -> list[bytes]:
    """Line-oriented command sequences built from the mined verbs. We do not know which verb
    allocates, frees or uses, so we enumerate the shapes a heap bug takes:

    * each verb REPEATED -- a no-argument double-free / double-use (`free`, `free`);
    * every ordered DISTINCT TRIPLE -- the create -> free -> use flow of a use-after-free
      (`new`, `del`, `run`), which a pair cannot express because it never allocates first;
    * every ordered pair, and each verb followed by a long data line (overflow in a write handler);
    * each verb alone, to learn its handler.

    The doubles and triples lead, so the calibration pass (which runs seeds verbatim before any
    mutation) detonates the crash-bearing navigations first. Empty below two verbs. The triple
    count is n*(n-1)*(n-2); the verb list is already capped small and the whole set is truncated to
    `max_seeds`, with the mutator covering longer / rarer sequences during the campaign."""
    vs = [v.encode() for v in verbs if v]
    keyed = [v for v in vs if v[-1:].decode("latin-1") in _ARG_SEPS]
    # A single BARE verb is not a sequence and never was. A single KEYED verb is still worth
    # driving: there is nothing to order, but there is an argument to vary, and the argument is
    # where its handler's defect lives.
    if len(vs) < 2 and not keyed:
        return []
    payload = b"A" * 64
    doubles = [v + _NL + v + _NL for v in vs]              # double-free / double-use
    triples = [a + _NL + b + _NL + c + _NL                 # create -> free -> use
               for a in vs for b in vs for c in vs if a != b and b != c and a != c]
    pairs = [a + _NL + b + _NL for a in vs for b in vs if a != b]
    overflow = [v + _NL + payload + _NL for v in vs]       # write handler overflow
    singles = [v + _NL for v in vs]
    # `show=<argument>` -- ON THE VERB'S OWN LINE, which is the only form its strncmp accepts.
    # Numbers included, and they are the point: a handler that reads a length or an index out of
    # the argument has a defect selected by the VALUE, and `show=0` reaches the same code as
    # `show=2147483647` while doing nothing at all.
    args = list(_ARG_FILLERS) + _dangerous_first(_ARG_NUMERIC)
    # BY ARGUMENT, not by verb: `[k + a for k in keyed for a in args]` spends every one of the
    # first verb's arguments before the second verb gets its first, so under the cap only the
    # earliest verb was ever driven with a large value. Each verb now gets argument one before
    # any verb gets argument two.
    keyed_args = [k + a + _NL for a in args for k in keyed]
    # ROUND-ROBIN, not concatenation. Taken in order, the triple enumeration is n*(n-1)*(n-2) --
    # 3,360 sequences for the 16 verbs this miner returns -- so with `max_seeds` at 96 the seeds
    # were 16 doubles and 80 triples, and the overflow and single families never appeared at all
    # **[measured]**. A family that is always truncated to nothing is a family that is not tested,
    # so each gets a turn and the cap costs breadth rather than whole shapes.
    families = [keyed_args, doubles, triples, pairs, overflow, singles]
    out: list[bytes] = []
    seen: set[bytes] = set()
    i = 0
    while len(out) < max_seeds and any(i < len(f) for f in families):
        for fam in families:
            if i >= len(fam):
                continue
            if len(out) >= max_seeds:
                break
            cand = fam[i]
            if cand not in seen:
                seen.add(cand)
                out.append(cand)
        i += 1
    return out


class CommandMutator:
    """Keeps every mutation a VALID command flow: a handful of verb lines, with the occasional data
    line (to overflow a write handler) and dictionary token. A blind byte mutator spends its budget
    on inputs the dispatcher rejects at the first `strncmp`; this stays inside the handlers, where
    the bugs are, exactly as MenuMutator does for a numbered menu."""

    def __init__(self, rng, verbs, dictionary=None):
        self.rng = rng
        vb = [v.encode() if isinstance(v, str) else bytes(v) for v in verbs if v]
        self.verbs = vb or [b"help"]
        self.dictionary = [d if isinstance(d, bytes) else str(d).encode()
                           for d in (dictionary or [])]

    def mutate(self, data: bytes = b"", corpus=()) -> bytes:
        rng = self.rng
        lines: list[bytes] = []
        for _ in range(rng.randint(2, 6)):
            r = rng.random()
            if self.dictionary and r < 0.10:
                lines.append(rng.choice(self.dictionary))
            elif r < 0.30:
                lines.append(b"A" * rng.choice((8, 32, 64, 256, 512)))   # data / overflow line
            else:
                lines.append(rng.choice(self.verbs))
        return _NL.join(lines) + _NL
