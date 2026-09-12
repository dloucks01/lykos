"""A mutator for line-oriented text configuration -- `key = value`, `key: value`, INI.

Every format model in `structure` is binary: magic bytes, integer fields, length-prefixed
blobs. That covers image and archive parsers and covers nothing about the target this platform
is most often pointed at -- a service whose only input is a config file it is REQUIRED to be
given, whose parser is a `fgets` loop with a `strchr(line, '=')` in it and a `strcpy` into a
fixed buffer behind that.

Blind mutation does not reach such a bug, and the reason is worth stating exactly. The defect
needs `name=` followed by more bytes than the destination holds. A byte mutator has to invent
the literal key, the separator, and the overlong run together before the parser will even look
at them: measured against a 64-byte `strcpy` sink, 2,000 executions with a mined dictionary
produced 826 distinct behaviours and zero crashes, because "826 distinct behaviours" of a
parser that rejects every line is still no progress at all.

So generate the shape instead. The keys come from the binary's own strings -- a config parser
compares against every key it accepts, so they are all in there -- and each value is drawn from
a pool built to break the code behind it: lengths that straddle typical buffer sizes, format
specifiers, integer boundaries, traversal, and a NUL.
"""
from __future__ import annotations

import re

from .mutator import Mutator

# A key a config parser would compare against: a lowercase identifier, not a sentence, a path,
# or a run of code bytes. The case rule is doing real work -- scanning a binary's raw bytes
# yields "ATSH", "AVAUA" and "uHdH" (x86 register-save sequences) and "Genu"/"ntel" (the CPUID
# vendor string, split across registers), all of which match a letters-and-digits shape
# perfectly and filled the first sixteen key slots on a program whose keys are `name`,
# `listen` and `workers`.
_KEYISH = re.compile(r"^[a-z][a-z0-9_.-]{2,30}$")
_VOWEL = re.compile(r"[aeiou]")
# `name=%s listen=%s workers=%d` -- a key written next to its separator. This is much stronger
# evidence than a bare word, and it is the only place some keys appear at all: `name` is packed
# against its neighbour in .rodata (`@@name`) and never shows up as a standalone string, so
# mining bare words alone missed the one key that reaches the bug.
_KEY_EQ = re.compile(r"(?:^|[\s,;|\[({])([A-Za-z][A-Za-z0-9_.-]{1,30})\s*[=:]")
# An identifier's case is consistent: all-lowercase, Capitalized, or ALL_CAPS. Disassembled
# code bytes are not -- `u6H`, `ubH`, `yKAF` all sit next to a `=` somewhere in a binary.
_WORDY = re.compile(r"^(?:[A-Za-z][a-z0-9_.-]{1,30}|[A-Z][A-Z0-9_.-]{1,30})$")
_RUN = re.compile(r"(.)\1\1")                 # "IMMMMEMMMM": not a name, a data pattern


def _plausible(t: str) -> bool:
    return bool(_WORDY.match(t) and _VOWEL.search(t.lower())
                and not _RUN.search(t) and t.lower() not in _NOT_KEY)
# Words that are in every binary and are not config keys.
_NOT_KEY = {"main", "printf", "fprintf", "stderr", "stdout", "stdin", "malloc", "free",
            "memcpy", "strcpy", "strlen", "fopen", "fclose", "fgets", "usage", "error",
            "warning", "true", "false", "null", "none", "gcc", "GCC", "GLIBC", "text",
            "data", "bss", "init", "fini", "note", "symtab", "strtab", "shstrtab",
            # the CPUID vendor strings, which appear in every x86 binary as four-byte chunks
            # because that is how they come back in EBX/EDX/ECX. "ntel" is lowercase, has a
            # vowel and is four characters, so no shape rule rejects it -- it just has to be
            # named.
            "genu", "ineI", "ntel", "auth", "enti", "camd", "geny", "ineg", "ntia"}
SEPARATORS = ("=", ": ", " = ", ":")

# Values chosen to break what is behind the key. The long runs straddle the buffer sizes that
# actually appear in C (16/32/64/128/256/512), because a value that is merely "long" tells you
# nothing about which one overflowed.
_LENGTHS = (15, 17, 31, 33, 63, 65, 127, 129, 255, 257, 511, 1023, 4097)
_NASTY = (
    b"%s%s%s%s%s%s%s%s", b"%n%n%n%n", b"%1000000d",
    b"-1", b"0", b"2147483647", b"-2147483648", b"4294967295", b"18446744073709551615",
    b"0x7fffffff", b"../../../../etc/passwd", b"\x00", b"\xff\xfe\xfd",
)


def keys_from(strings, *, limit: int = 64) -> list:
    """Plausible config keys out of a binary's strings.

    A config parser holds a literal for every key it accepts -- that is how `strcmp(k, "name")`
    works -- so the accepted vocabulary is already in the file. The filter is deliberately
    tight: a wrong key is a line the parser skips, which is an execution that does nothing.

    Two sources, and the order matters because the mutator picks uniformly from what it is
    given. Keys written beside a separator come first: they are unambiguous, and a statically
    linked binary otherwise buries five real keys under sixty libc symbols.
    """
    out: list = []
    seen = set()
    # strongest first: keys written beside their own separator
    for s in strings:
        for m in _KEY_EQ.finditer(s or ""):
            t = m.group(1)
            if t in seen or not _plausible(t):
                continue
            seen.add(t)
            out.append(t)
    for s in strings:
        t = (s or "").strip()
        if t in seen or not _KEYISH.match(t) or not _plausible(t):
            continue
        if len(out) >= limit:
            break
        seen.add(t)
        out.append(t)
        if len(out) >= limit:
            break
    return out


def seed_for(keys, *, sep: str = "=") -> bytes:
    """A config file the parser accepts, so the campaign starts inside it rather than at the
    `fopen`. Values are ordinary on purpose: this is the valid baseline to mutate away from."""
    lines = [b"# lykos"]
    for k in (keys or ["name", "listen", "workers"])[:8]:
        lines.append(k.encode("ascii", "replace") + sep.encode() + b"lykos")
    return b"\n".join(lines) + b"\n"


class KeyValueMutator:
    """Line-aware mutator with the byte Mutator's interface.

    Falls back to byte havoc for input that is not text, so a campaign that picked this model
    wrongly degrades to the old behaviour instead of spinning on inputs it cannot parse.
    """

    def __init__(self, rng, keys=(), dictionary=None, separators=SEPARATORS):
        self.rng = rng
        self.keys = list(keys) or ["name", "value", "path", "port"]
        self.seps = list(separators)
        self.byte = Mutator(rng, dictionary)

    def _value(self) -> bytes:
        r = self.rng
        pick = r.random()
        if pick < 0.55:
            n = r.choice(_LENGTHS)
            return r.choice((b"A", b"\xff", b"%s", b"../")) * n
        if pick < 0.85:
            return r.choice(_NASTY)
        return bytes(r.randrange(0x20, 0x7F) for _ in range(r.randint(1, 24)))

    def _line(self) -> bytes:
        k = self.rng.choice(self.keys).encode("ascii", "replace")
        return k + self.rng.choice(self.seps).encode() + self._value()

    def mutate(self, data: bytes, corpus=()) -> bytes:
        if data and b"\x00" in data[:512] and b"=" not in data[:512]:
            return self.byte.mutate(data, corpus)      # not text: let havoc have it
        lines = (data or b"").split(b"\n")
        if len(lines) > 4096:
            return self.byte.mutate(data, corpus)
        r = self.rng
        for _ in range(r.randint(1, 3)):
            op = r.random()
            if op < 0.45 or not lines:
                lines.insert(r.randrange(len(lines) + 1), self._line())
            elif op < 0.65:
                lines[r.randrange(len(lines))] = self._line()
            elif op < 0.8:
                # keep the key, break the value: the key is what gets the line PARSED
                i = r.randrange(len(lines))
                head, sep, _ = lines[i].partition(b"=")
                lines[i] = (head + b"=" + self._value()) if sep else self._line()
            elif op < 0.9 and len(lines) > 1:
                del lines[r.randrange(len(lines))]
            else:
                # one very long line: the `fgets` buffer itself is a boundary
                lines[r.randrange(len(lines))] = self._line() * r.randint(4, 40)
        return b"\n".join(lines)
