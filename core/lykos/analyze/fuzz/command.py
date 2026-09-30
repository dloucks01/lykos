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
        if not re.fullmatch(r"[a-z][a-z_]{1,11}", t) or t in _NOISE or t in seen:
            continue
        if any(sub in t for sub in _NOISE_SUBSTR):     # CRT / compiler symbol, never a command
            continue
        seen.add(t)
        verbs.append(t)
    # Shortest first: a command verb is usually a terse word and the sequence budget is finite, so
    # the likeliest verbs lead (and calibration runs the seeds built from them before any mutation).
    verbs.sort(key=lambda v: (len(v), v))
    return verbs[:cap]


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
    if len(vs) < 2:
        return []
    payload = b"A" * 64
    doubles = [v + _NL + v + _NL for v in vs]              # double-free / double-use
    triples = [a + _NL + b + _NL + c + _NL                 # create -> free -> use
               for a in vs for b in vs for c in vs if a != b and b != c and a != c]
    pairs = [a + _NL + b + _NL for a in vs for b in vs if a != b]
    overflow = [v + _NL + payload + _NL for v in vs]       # write handler overflow
    singles = [v + _NL for v in vs]
    seeds = doubles + triples + pairs + overflow + singles
    out: list[bytes] = []
    seen: set[bytes] = set()
    for s in seeds:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out[:max_seeds]


class CommandMutator:
    """Keeps every mutation a VALID command flow: a handful of verb lines, with the occasional data
    line (to overflow a write handler) and dictionary token. A blind byte mutator spends its budget
    on inputs the dispatcher rejects at the first `strncmp`; this stays inside the handlers, where
    the bugs are, exactly as MenuMutator does for a numbered menu."""

    def __init__(self, rng, verbs, dictionary=None):
        self.rng = rng
        self.verbs = [v.encode() if isinstance(v, str) else bytes(v) for v in verbs if v] or [b"help"]
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
