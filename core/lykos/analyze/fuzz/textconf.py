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
    strings = list(strings or ())                 # walked twice: a generator would be spent
    # strongest first: keys written beside their own separator. Bounded by `limit` too: this loop
    # used to ignore it, so a binary with hundreds of `word=` strings handed the mutator hundreds
    # of keys and a real one was drawn proportionally less often.
    for s in strings:
        if len(out) >= limit:
            break
        for m in _KEY_EQ.finditer(s or ""):
            t = m.group(1)
            if t in seen or not _plausible(t):
                continue
            seen.add(t)
            out.append(t)
            if len(out) >= limit:
                break
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


# Edge values for a field parsed as a NUMBER. A config key fed to atoi / Integer.parseInt / an
# array index hides its bug behind a specific value -- 0, -1, INT_MAX, overflow -- that random
# mutation of a text placeholder lands only by luck inside a short (JVM-slow) exec budget.
# A multiplication wraps once the COUNT reaches 2**bits // elem_size, and the product then
# lands on a SMALL number -- so `malloc(n * elem)` succeeds with a tiny buffer and the loop that
# follows writes far past it. That is the whole integer-overflow-to-heap-overflow shape
# (CWE-190 -> CWE-122/787), and the type boundaries below never reach it: 4294967295 * 16 wraps
# to 4294967280, which is still an enormous allocation that simply FAILS, so the program takes
# its `if (!p) return` path and exits cleanly on the one value a fuzzer would think to try.
#
# The thresholds are derived, not guessed at per target: elem_size is almost always a small
# power of two (int/long/pointer) or a small struct, so 2**bits//k over small k covers the class.
# `base + 1` matters as much as `base` -- it wraps to exactly k, the smallest allocation that
# still enters the loop.
def _wrap_thresholds(bits, factors):
    out = []
    for k in factors:
        base = (1 << bits) // k
        out += [base, base + 1]
    return out


# The type boundaries every numeric parser is tested against. These LEAD for a config field,
# where the bug behind a number is usually an index or a bound: `-1` and `0` are what reach an
# unchecked array index, and they are the values the JVM/heap cases depend on arriving first.
_TYPE_BOUNDARIES = [0, -1, 2147483647, 2147483648, 4294967295]

# Ordering matters because seed CALIBRATION detonates the corpus in order and a short budget may
# never reach the tail -- so each consumer leads with the values its own bug class needs, over
# one shared pool. A config field wants the type boundaries first (above); a bare count fed to
# an allocation wants the WRAP thresholds first, since that is the only way its product lands on
# a size malloc will accept.
_WRAP_FIRST = tuple(dict.fromkeys(
    _wrap_thresholds(32, (16, 8, 4, 2))
    + _TYPE_BOUNDARIES + [1, 4294967296, 65535, 65536]
    + _wrap_thresholds(32, (32, 64, 24, 256, 12, 3))
    + _wrap_thresholds(64, (16, 8, 2))
    + [18446744073709551615]))

#: As text, for a field inside a `key=value` config. Type boundaries first; the wrap thresholds
#: follow, so an existing caller's `limit=5` gets exactly the five values it always did.
_BOUNDARY_VALUES = tuple(str(v).encode()
                         for v in dict.fromkeys(_TYPE_BOUNDARIES + list(_WRAP_FIRST)))


def numeric_boundary_seeds(limit: int = 16) -> list:
    """Bare decimal seeds for a target that reads a NUMBER rather than a structured document.

    `boundary_seeds` covers a numeric field inside a config; this covers the other shape, where
    the program's entire input is a count or an index read by `scanf("%u")` / `strtoul` / `atoi`.
    Blind byte mutation effectively never emits the DECIMAL TEXT of a 9-10 digit number, so a
    wrap-driven allocation bug is unreachable by mutation alone however long the campaign runs --
    it is not a matter of budget. A newline terminates the value for a reader that scans a line
    as well as for one that stops at whitespace.
    """
    return [str(v).encode() + b"\n" for v in _WRAP_FIRST[:max(0, limit)]]


def boundary_seeds(keys, *, sep: str = "=", limit: int = 5) -> list:
    """One accepted config per boundary value, with that value on EVERY discovered key at once.

    A numeric-field bug (unchecked array index, off-by-one bound, signed overflow) becomes
    reachable on the first execution instead of by chance -- the same reason a byte fuzzer ships
    a dictionary. General, not target-specific: a robust parser simply accepts these and the
    campaign moves on; only a real bug turns one into a crash."""
    if not keys:
        return []
    ks = [(k.encode("ascii", "replace") if isinstance(k, str) else k) for k in keys[:8]]
    sep = sep.encode() if isinstance(sep, str) else sep
    out = []
    for v in _BOUNDARY_VALUES[:limit]:
        out.append(b"\n".join(k + sep + v for k in ks) + b"\n")
    return out


#: A mutant is never grown past this. Every op inserts or lengthens a line (one "very long line"
#: is up to 40 x a 4 KiB value) and a kept mutant is mutated again, so a lineage compounded:
#: measured, 300 chained generations from a 30-byte config reached 510 KB and kept growing.
#: An op that would cross the cap is undone; the input never shrinks below what it arrived as.
_MAX_TEXT = 1 << 18


class KeyValueMutator:
    """Line-aware mutator with the byte Mutator's interface.

    Falls back to byte havoc for input that is not text, so a campaign that picked this model
    wrongly degrades to the old behaviour instead of spinning on inputs it cannot parse.
    """

    def __init__(self, rng, keys=(), dictionary=None, separators=SEPARATORS):
        self.rng = rng
        # str keys: a bytes key (mined straight from a binary) raised AttributeError on .encode
        self.keys = [k.decode("latin-1") if isinstance(k, (bytes, bytearray)) else str(k)
                     for k in keys if k] or ["name", "value", "path", "port"]
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
        cap = max(_MAX_TEXT, len(data or b""))
        for _ in range(self.rng.randint(1, 3)):
            before = list(lines)
            self._op(lines)
            if sum(len(x) for x in lines) + len(lines) - 1 > cap:
                lines[:] = before                       # would cross the cap: undo this op
        return b"\n".join(lines)

    def _op(self, lines) -> None:
        r = self.rng
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


# A specimen the program DOCUMENTS for itself. Many CLI tools and prompt-driven services write
# their input grammar into a usage line or a prompt -- "in SED format (e.g. s/old/new/)" -- and
# that example is a valid input by construction, written by the author of the parser that reads
# it. Nothing in the pipeline was reading it: the strings mined for seeds were the program's
# ERROR messages ("Missing 's/' at the beginning of the replacement string."), which name the
# gate without passing it.
#
# Measured need, on the HTB target `replaceme`: its defect is a 192-byte stack buffer overflowed
# by `s/a/<long>/`, and 63,234 blind and directed executions never constructed the expression,
# because a mutator has to invent `s/`, two `/` delimiters and a long replacement field at once.
# The binary names the shape in its own prompt.
#: `e.g.` with BOTH dots and a separator after it, because the loose form mined junk from the
#: symbol table: `e\.?\s?g\.?` matched the bare "eg" inside "register_tm_clones" and the "e.g"
#: inside ".note.gnu.property", yielding "ister_tm_clones" and "nu.property" as "examples".
_EXAMPLE = re.compile(
    r"(?:(?<![A-Za-z])e\.g\.|(?<![A-Za-z])eg\.|for example|examples?\s*[:,]|such as|"
    r"format\s*[:,])\s*[\"'(\[]?([^\s\"'()\[\]]{3,96})")

#: A field pushed past any plausible fixed-size buffer. The example documents the SHAPE; the
#: defect behind it is almost always a length, so each field is also offered long.
_LONG_FIELD = 256

#: Runs inside the example that look like a FIELD rather than punctuation or a keyword: the
#: `old` and `new` of `s/old/new/`, the `KEY` and `VALUE` of `KEY=VALUE`.
_FIELDISH = re.compile(r"[A-Za-z0-9_.-]{2,}")


def example_seeds(strings, *, limit: int = 8) -> list:
    """Input specimens the binary documents for itself, plus a long-field variant of each.

    The example is a valid input written by the author of the parser; the long variant is the
    same input with one field grown past any plausible buffer, which is the defect the example's
    own format usually hides. Best-effort and bounded: a program that documents nothing yields
    nothing, and seeding is an optimisation rather than a precondition.
    """
    out: list = []
    for s in strings or ():
        if len(set(out)) >= limit:
            break                                     # enough: the rest would be cut anyway
        if not s or not isinstance(s, str):
            continue
        for m in _EXAMPLE.finditer(s):
            ex = m.group(1).rstrip(".,;:)")
            # a bare word is a value, not a grammar, and `keys_from` already mines those; the
            # point here is an example carrying STRUCTURE (delimiters, an operator, a path)
            if len(ex) < 3 or ex.isalnum():
                continue
            out.append(ex.encode("latin-1", "ignore"))
            for f in _FIELDISH.finditer(ex):
                out.append((ex[:f.start()] + "A" * _LONG_FIELD
                            + ex[f.end():]).encode("latin-1", "ignore"))
    seen, uniq = set(), []
    for b in out:
        if b not in seen:
            seen.add(b)
            uniq.append(b)
    return uniq[:limit]


# --- a PLAUSIBLE config with content (doc 47 R2.d / P5) -------------------------------------------
# `seed_for` is the baseline the MUTATOR starts from; this is the file a target is GIVEN so it runs
# at all -- a daemon that `fopen`s /etc/app/app.conf and refuses an empty one ("no listen
# address configured") never reaches the code a campaign is aimed at. The keys still come from the
# binary's own strings; the values are ordinary and shaped by the key's NAME (a port gets a port, a
# directory key a directory), because a value the parser rejects is the same dead end as no file.

#: `[general]` / `[server]` -- an INI section header the parser compares against.
_SECTION = re.compile(r"^\[([A-Za-z][A-Za-z0-9 _.:-]{0,30})\]$")
#: A key's value shaped by its name. Checked in order; the first match wins.
_VALUE_BY_NAME = (
    (re.compile(r"(?i)port$|_port|^port"), "8080"),
    (re.compile(r"(?i)host|addr|address|listen|bind|server|ip$"), "127.0.0.1"),
    (re.compile(r"(?i)(?:dir|directory|root|home|prefix|path|spool|cache)$"), "{dir}"),
    (re.compile(r"(?i)file$|log$|pid$|pidfile|logfile|conf$|config$"), "{file}"),
    (re.compile(r"(?i)^(?:enable|enabled|disable|debug|verbose|daemon|daemonize|foreground|"
                r"use_|allow)"), "yes"),
    (re.compile(r"(?i)count|num|max|min|size|limit|timeout|level|threads|workers|interval|"
                r"retries|len|depth"), "1"),
    (re.compile(r"(?i)user|group|owner"), "nobody"),
    (re.compile(r"(?i)name|id$|ident"), "lykos"),
)


def value_for(key: str, *, dir_value: str = "/tmp", file_value: str = "/dev/null") -> str:
    """An ordinary value for config key (or env var) `key`, shaped by its name."""
    for rx, v in _VALUE_BY_NAME:
        if rx.search(key or ""):
            return v.replace("{dir}", dir_value).replace("{file}", file_value)
    return "lykos"


def sections_from(strings, *, limit: int = 4) -> list:
    """INI section names (`[general]` -> "general") the binary compares against, in order."""
    out: list = []
    for s in strings or ():
        m = _SECTION.match((s or "").strip())
        if m and m.group(1) not in out:
            out.append(m.group(1))
            if len(out) >= limit:
                break
    return out


def separator_from(strings) -> str:
    """`key = value` vs `key=value` vs `key: value`, from the formats the binary itself prints or
    scans (`%s = %s`, `%[^=]=%s`, `%s: %s`). "=" when nothing says otherwise."""
    spaced = colon = 0
    for s in strings or ():
        s = s or ""
        if "%s = %" in s or re.search(r"\w = %", s):
            spaced += 1
        elif "%s: %" in s or "%[^:]" in s:
            colon += 1
    if spaced and spaced >= colon:
        return " = "
    if colon:
        return ": "
    return "="


def plausible_config(path: str, strings, *, keys=None, dir_value: str = "/tmp",
                     file_value: str = "/dev/null", limit: int = 12) -> bytes:
    """A config file WITH content for `path`, in the format its name implies.

    `keys` are the candidate keys (default: `keys_from(strings)`); `strings` also supply INI
    section headers and the separator. The format follows the extension -- JSON, YAML, XML or
    line-oriented `key<sep>value` (with the first `[section]` the binary names, for .ini/.conf).
    Never empty: an empty file is exactly what a target that checks "configured at all" rejects.
    """
    strings = list(strings or ())
    keys = list(keys if keys is not None else keys_from(strings, limit=limit))[:limit]
    ext = (path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else "")
    vals = [(k, value_for(k, dir_value=dir_value, file_value=file_value)) for k in keys]
    if ext == "json":
        import json
        return (json.dumps({k: v for k, v in vals} or {"name": "lykos"}, indent=2) + "\n").encode()
    if ext in ("xml",):
        body = "".join(f"  <{k}>{v}</{k}>\n" for k, v in vals if re.match(r"^[A-Za-z_][\w.-]*$", k))
        return ('<?xml version="1.0"?>\n<config>\n' + body + "</config>\n").encode()
    if ext in ("yaml", "yml"):
        lines = ["# lykos: synthesized"] + ([f"{k}: {v}" for k, v in vals] or ["name: lykos"])
        return ("\n".join(lines) + "\n").encode()
    sep = separator_from(strings)
    lines = ["# lykos: synthesized"]
    secs = sections_from(strings)
    if secs:
        lines.append(f"[{secs[0]}]")
    lines += [f"{k}{sep}{v}" for k, v in vals] or [f"name{sep}lykos"]
    return ("\n".join(lines) + "\n").encode()
