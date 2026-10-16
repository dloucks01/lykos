"""Work out how a target has to be INVOKED, and propose a working command line.

Real services are not `./target < input`. They take a config path behind a flag, a display
id, an instance identifier, a jar to run -- and without them they print a usage line and exit.
Every execution then looks identical, which is indistinguishable from a program with no bug:
a campaign against such a target managed 8,000 executions, one distinct behaviour and no
crashes, and reported it as a clean run.

Four independent signals, strongest first. Each says something the others do not, so they are
merged rather than ranked:

  1. the `getopt`/`getopt_long` option string -- "c:d:j:i:v" names every flag AND says which
     take a value (the colon). This is a string constant, so it survives stripping.
  2. `getopt_long`'s `struct option[]` table -- long names, with has_arg.
  3. string literals compared against argv -- `strcmp(argv[i], "-c")` is how programs that
     roll their own parsing spell the same thing.
  4. the usage line itself -- "usage: %s -c <config> -d <display-id>" -- which is the only
     signal that carries a HINT of what each value should look like.

What it cannot do is know your deployment: an instance id or a display really is site-
specific. So the output is a template with placeholders and a plausible default for each,
meant to be reviewed, not a guess presented as fact.
"""
from __future__ import annotations

import hashlib
import pathlib
import re
import uuid
from typing import Optional

# "c:d:j:i:v" / "+:hvc:" -- a run of option letters, colons marking a required value. Leading
# '+', '-' and ':' are getopt mode flags, not options.
#
# At least one colon is REQUIRED, and that is the whole difference between a real option
# string and the alphabet: every static binary carries "abcdefghijklmnopqrstuvwxyz" and
# "0123456789ABCDEF", which match the letters-only shape perfectly and contributed sixty
# imaginary switches. An option string with no value-taking option at all is possible, but
# missing one of those costs far less than inventing an option for every letter.
# The one definition of the input-placeholder contract, shared with the fuzzing runner and the
# PoC bundle: `@@` marks where the input belongs in an argv that is not simply "the last
# argument".
INPUT_PLACEHOLDER = "@@"
# A converter is `tool [opts] INPUT OUTPUT`: the input goes at `@@`, but it also needs a writable
# OUTPUT path as a trailing positional or it refuses to run (tiffcp, ffmpeg, convert). This second
# placeholder marks that slot; the runner/capture layers substitute a real scratch path for it.
OUTPUT_PLACEHOLDER = "@@out"
# The concrete output path a converter writes: RELATIVE, so it lands in whatever writable cwd the
# run happens in -- the sandbox chdirs to a writable tmpfs /tmp, and an unwrapped run uses a temp
# cwd. An absolute path under the exe dir (read-only bind) or a /tmp subdir (empty tmpfs) is not
# writable, so the tool fails to create its output and looks like a wrong invocation.
OUTPUT_SCRATCH = "lykos.out"
_OUT_WORD = re.compile(r"(?i)^(out|output|outfile|dst|dest|destination|target|result|outputfile)$")


def output_positional(usage) -> bool:
    """Does the usage line end in an OUTPUT positional (a converter's `... input output`)?

    True when, after dropping `[optional]` groups and flags, two or more bare positionals remain
    and one after the first names an output. Then the invocation must append a scratch output path
    or the tool prints usage and exits -- which otherwise looks like a wrong invocation forever."""
    if not usage:
        return False
    t = re.sub(r"(?i)^.*?\busage\b\s*:?\s*", "", usage)
    t = re.sub(r"\[[^\]]*\]", " ", t)                    # drop [options]-style optional groups
    toks = [w for w in re.split(r"\s+", t) if w and not w.startswith("-")]
    bare = [re.sub(r"[<>().]", "", w).strip(".") for w in toks]
    bare = [w for w in bare if w and w != "%s"]
    return len(bare) >= 2 and any(_OUT_WORD.match(w) for w in bare[1:])


_OPTSTRING = re.compile(r"^[+-]?:?(?=[^:]*:)([A-Za-z0-9]:{0,2}){2,24}$")
# usage: prog -c <config> --jar=FILE
_USAGE_FLAG = re.compile(r"(--?[A-Za-z][A-Za-z0-9_-]*)(?:[= ]+([<\[]?[A-Za-z0-9_.<>\[\]-]+))?")
_USAGE_LINE = re.compile(r"(?i)\busage\b\s*:?\s")

# What a value should look like, from the placeholder the usage line used.
_HINTS = (
    (re.compile(r"(?i)conf|cfg|ini|settings"), "config", "@@"),
    (re.compile(r"(?i)jar|classpath|\bcp\b|java"), "jar", "app.jar"),
    (re.compile(r"(?i)disp|screen|\bx11\b"), "display", ":0"),
    (re.compile(r"(?i)uuid|guid|cslid|clsid|\bid\b|instance"), "id",
     "00000000-0000-4000-8000-000000000000"),
    (re.compile(r"(?i)port"), "port", "8080"),
    # A multicast group is an address, and a receiver that takes one is a whole class of
    # target here -- video over multicast. Without this `-g <group>` got no kind at all, so
    # nothing could fill it in and the receiver joined a group named "x" while the harness
    # sent to the real one.
    (re.compile(r"(?i)host|addr|ip\b|group|grp|mcast|multicast"), "host", "127.0.0.1"),
    (re.compile(r"(?i)user|login"), "user", "lykos"),
    # `out` only as a whole word: it was matching "timeout" (a NUMBER), handing `-t <timeout>` a
    # file-path value instead of a count and breaking the invocation of any timeout-driven service.
    (re.compile(r"(?i)path|dir|file|\bout\b|log"), "path", "@@"),
    (re.compile(r"(?i)num|count|size|len|threads|workers|sec|timeout|interval|"
                r"delay|ttl|level|float|double|real|\bms\b|\bn\b|\bt\b"), "number", "0"),
)


# Format-template placeholders: a value whose SHAPE is written out literally, like a session id
# `NNN-NNN-NNN-NNN`, a time `HH:MM`, a MAC `XX:XX:XX:XX:XX:XX`. A service that validates the shape
# (`-s <NNN-NNN-NNN-NNN>`, `-csid 111-111-222-222`) rejects a generic "x" and never reaches its
# real work, so nothing downstream -- fuzzing, the crash, the PoC -- can happen. These class chars
# are the common conventions; a run of them (with literal separators) IS a template.
_SHAPE_CLASS = {"N": "1", "#": "1", "9": "1", "D": "1",      # a digit slot
                "X": "a", "A": "a", "x": "a", "H": "a"}      # an alnum / hex slot
_SHAPE_SEP = set("-_.:/ @")


def _shape_value(placeholder):
    """Concrete value matching a literal format-template placeholder, else None.

    `NNN-NNN-NNN-NNN` -> `111-111-111-111`; `HH:HH:HH` -> `aa:aa:aa`. Returns None for an ordinary
    descriptive word (`config`, `seconds`) so the keyword hints still handle those. A template is a
    string made only of class chars + separators, with at least three class chars so a short word
    like `IP` is not mistaken for one."""
    if not placeholder:
        return None
    p = placeholder.strip().strip("<>[]").strip()
    if not p or len(p) > 128:
        return None
    nclass = sum(1 for c in p if c in _SHAPE_CLASS)
    if nclass < 3:
        return None
    if any(c not in _SHAPE_CLASS and c not in _SHAPE_SEP and not c.isdigit() for c in p):
        return None                                  # a real word crept in -> not a pure template
    return "".join(_SHAPE_CLASS.get(c, c) for c in p)


_PRINTABLE = bytes(range(0x20, 0x7F)) + b"\t"


class PlainString:
    """A `StringDAO` row's shape for a string that did not come from the database.

    Strings reach the DB only via `disassemble`, and three separate consumers need them
    before that -- the fuzzing dictionary, the format detector and the CWE detectors that read
    only strings. Each grew its own stand-in, and each was missing a different field: one
    lacked `xrefs` and crashed the credential detector outright, and a stand-in with `addr =
    None` gave every finding the dedup key `CWE-798:None`, collapsing every credential in a
    jar into one. `addr` is therefore a stable synthetic location, not a number -- for a jar
    that is the class the constant lives in, which is more use to a reader than an offset.
    """

    __slots__ = ("value", "addr", "xrefs", "section")

    def __init__(self, value, addr=None, xrefs=(), section=None):
        self.value = value
        self.addr = addr
        self.xrefs = list(xrefs)
        self.section = section


def string_rows(values, *, where=None):
    """`PlainString` rows for a flat list of strings, each with a distinguishing location."""
    out = []
    for v in values:
        loc = where or "const"
        out.append(PlainString(v, addr=f"{loc}:{hashlib.sha1(v.encode()).hexdigest()[:8]}"))
    return out


def raw_strings(data: bytes, *, minlen: int = 4, limit: int = 200000) -> list:
    """Printable runs straight out of the file bytes.

    The string table is populated by `disassemble`, which means Ghidra, which means minutes.
    But the question this module answers -- how do I even run this thing -- is the FIRST one
    an operator has, before any analysis at all: a target invoked without its required flags
    prints usage and exits on every execution, and a campaign started in that state is wasted
    from the first input. A usage line is plain ASCII in .rodata, so scanning for it needs no
    decompiler.
    """
    from . import jvm
    if jvm.is_class(data) or jvm.is_jar(data):
        # A jar is a zip: scanning it for printable runs reads DEFLATE output and finds
        # nothing, so every consumer of a target's strings -- this module, the fuzzing
        # dictionary, the format detector, the credential detector -- quietly concluded there
        # was nothing there. The constant pool holds them all in the clear.
        return jvm.strings_of(data)[:limit]
    # The WHOLE file, and with a C-speed scan rather than a Python byte loop.
    #
    # This used to stop at `data[:limit * 8]` -- the first 1.6 MB -- which conflated "at most
    # 200,000 strings" with "at most 1.6 MB of bytes". Measured consequence: libtiff's plain
    # `tiffinfo` is 1.24 MB and yielded 5,815 strings including every TIFF marker, while the
    # same project's ASan-instrumented `tiffcrop` is 5.47 MB, so its .rodata sat PAST the cap
    # and the scan returned 784 strings of mostly code -- no usage line, no format tokens, no
    # dictionary. Every consumer went blind at once: invocation discovery proposed a flag
    # soup the target refused, the format detector found nothing and the campaign fell through
    # to mutating text commands mined from three-letter fragments, against a TIFF reader.
    #
    # A byte prefix is the wrong bound for "how much work is this": a large binary is exactly
    # the case where the strings matter most. `limit` still bounds the OUTPUT, which is the
    # bound that was wanted.
    rx = re.compile(b"[" + re.escape(_PRINTABLE) + b"]{" + str(int(minlen)).encode() + b",}")
    out = []
    for m in rx.finditer(data):
        out.append(m.group().decode("ascii", "replace"))
        if len(out) >= limit:
            break
    return out


# A structured value written out in a string -- a usage/error/format message like "want
# NNN-NNN-NNN-NNN" or "e.g. 111-222-333-444": groups of DIGITS (or N/#/X template chars) joined by
# a `-`, `:`, `.` or `_`, three or more groups. Digit-ish groups only, and NOT `/`-separated, so a
# file path (usr/lib/gcc/...), a soname (ld-linux-x86-64.so) or a dotted library name is NOT
# mistaken for a value -- that false match injected a path as a flag's value. A date (2024-01-02)
# or a dotted version (1.2.3) still qualifies, which is fine: they are valid shaped values.
_SHAPE_IN_TEXT = re.compile(r"(?<![\w./:-])([0-9NX#]{1,8}(?:[-:._][0-9NX#]{1,8}){2,})(?![\w./:-])")


def mine_shape_values(strings) -> list:
    """Concrete values of any STRUCTURED shape the binary writes in its own strings.

    A target with no --help and only a terse usage line still often documents a required value's
    shape in an error message as a TEMPLATE ("bad session id (want NNN-NNN-NNN-NNN)"). Only
    templates -- tokens carrying explicit N/#/X shape chars -- are mined, and rendered to a concrete
    value. A bare literal like a version `4.0.3` or `16.2.0-1` is NOT mined: those appear all over a
    real binary and are not shapes anyone asked for, so mining them injected a version string as a
    flag's value. Longest first (more specific)."""
    seen, out = set(), []
    for s in strings or []:
        for m in _SHAPE_IN_TEXT.finditer(s or ""):
            val = _shape_value(m.group(1))             # templates only (must have N/#/X chars)
            if val and val not in seen and 5 <= len(val) <= 64:
                seen.add(val)
                out.append(val)
    out.sort(key=len, reverse=True)
    return out


def _hint_for(flag: str, placeholder: Optional[str], name: Optional[str] = None) -> tuple:
    # A literal format template in the placeholder is the most specific signal -- honour it before
    # the keyword hints, so `-s <NNN-NNN-NNN-NNN>` gets a shape-matching value, not a keyword guess.
    shaped = _shape_value(placeholder)
    if shaped is not None:
        return "value", shaped
    # `name` is a descriptive long alias (e.g. "config" from `--config`): the short `-c` means
    # nothing, but the alias names the value's kind.
    for rx, kind, default in _HINTS:
        if rx.search(placeholder or "") or rx.search(flag) or rx.search(name or ""):
            return kind, default
    # Neither a template nor a known keyword: a plain lowercase placeholder is usually an
    # ENUMERATED VALID VALUE rather than a metavariable -- `usage: prog -m parse` is documenting
    # that -m takes "parse". Handing such a flag the generic "x" makes the program reject the
    # invocation ("unknown mode x"), so nothing the flag unlocks is ever reached and the run looks
    # like a target with no reachable input at all. A metavariable is conventionally UPPERCASE or
    # bracketed, both of which are excluded here, so only a concrete-looking token is taken at its
    # word; anything else still falls back to "x".
    lit = (placeholder or "").strip().strip("<>[]").strip()
    if lit and lit == lit.lower() and re.fullmatch(r"[a-z][a-z0-9._-]{1,31}", lit):
        return "value", lit
    return "value", "x"


# Words that ARE the option-string shape. "Usage:" is U-s-a-g-e plus a colon, which matches
# perfectly, and gif2rgb -- whose usage line carries no flags at all -- came back with five
# invented ones at medium confidence. Every message prefix in the C world has this shape, so
# the colon rule alone is not enough.
_NOT_OPTSTRING = {"usage", "error", "warning", "note", "info", "fatal", "debug", "trace",
                  "name", "value", "file", "line", "size", "type", "code", "path", "host",
                  "port", "time", "date", "from", "caused", "at", "in", "to", "options"}


def from_optstring(strings) -> dict:
    """Flags from a getopt option string. `{flag: takes_value}`."""
    out: dict = {}
    for s in strings:
        t = (s or "").strip()
        if not (3 <= len(t) <= 64) or not _OPTSTRING.match(t):
            continue
        if t.lower().rstrip(":").lstrip("+-") in _NOT_OPTSTRING:
            continue
        body = t.lstrip("+-").lstrip(":")
        i = 0
        while i < len(body):
            ch = body[i]
            n = 0
            while i + 1 + n < len(body) and body[i + 1 + n] == ":":
                n += 1
            if ch.isalnum():
                # two colons is an OPTIONAL value; one is required
                out["-" + ch] = n >= 1
            i += 1 + n
    return out


_HELP_METAVAR = re.compile(r"(?i)^(<.+>|\[.+\]|[A-Z][A-Z0-9_.=-]*|[a-z][a-z0-9_-]*|\d[\w.-]*)$")


def from_help(lines) -> tuple:
    """Flags + value shapes mined from `--help` / `-h` option-table output.

    Modern GNU tools print a terse `Usage: ... [options]` in .rodata and keep the real option
    list in --help (objdump, xmllint, exiv2, tiffcp -- the CVE-rich CLI-fuzz targets). Each option
    row names the flag(s) and, when it takes a value, the metavar that gives the VALUE SHAPE:

        -c, --config FILE        -> -c/--config take a FILE
        --start-time <float>     -> a float value
        -s <NNN-NNN-NNN-NNN>     -> a shaped session id
        -v, --verbose            -> a switch

    Returns ({flag: takes_value}, {flag: placeholder}). The description is separated from the
    option column by a run of 2+ spaces, so it is cut away before parsing; a row whose remaining
    tokens are not a single metavar-shaped word is treated as a switch (so a single-space
    'description' cannot masquerade as a value)."""
    takes: dict = {}
    placeholders: dict = {}
    names: dict = {}
    for raw in lines or []:
        line = (raw or "").rstrip()
        if not line.lstrip().startswith("-"):
            continue
        col = re.split(r"\s{2,}", line.strip(), maxsplit=1)[0]
        flags, rest = [], []
        for tok in re.split(r"[,\s]+", col):
            if not tok:
                continue
            if tok.startswith("-") and "=" in tok:              # --config=FILE
                f, _, mv = tok.partition("=")
                if re.fullmatch(r"--?[A-Za-z][\w-]*", f):
                    flags.append(f)
                    if mv:
                        rest.append(mv)
            elif re.fullmatch(r"--?[A-Za-z][\w-]*", tok):       # -c / --config
                flags.append(tok)
            else:
                rest.append(tok)
        if not flags:
            continue
        # a value exists only when exactly one trailing token remains and it is metavar-shaped;
        # several tokens means we captured a single-spaced description, not a value.
        mv = rest[0] if len(rest) == 1 and _HELP_METAVAR.match(rest[0]) else None
        ph = (mv or "").strip("<>[]") or None
        # `-c, --config FILE` is ONE option: collapse the aliases to a single canonical flag
        # (prefer the short form -- getopt confirms it and it keeps the argv short) so the proposal
        # does not emit `-c @@ --config <other>`, where the synonym overrides @@ with a dead path.
        canon = next((f for f in flags if re.fullmatch(r"-[A-Za-z0-9]", f)), flags[0])
        takes[canon] = takes.get(canon, False) or (ph is not None)
        if ph and canon not in placeholders:
            placeholders[canon] = ph
        # keep the descriptive long alias (`--config` -> "config") as a KIND hint: the short
        # canonical flag `-c` carries no meaning, but "config" tells us the value is a config file
        # (so the campaign uses the key=value mutator), and a bare `FILE` metavar would not.
        longest = max((f for f in flags), key=len)
        if longest.startswith("--") and canon not in names:
            names[canon] = longest.lstrip("-")
    return takes, placeholders, names


def from_usage(strings) -> tuple:
    """(flags, usage line). The usage text is the only place the VALUE SHAPES are written."""
    flags: dict = {}
    usage = None
    best = -1
    for s in strings:
        t = s or ""
        if not _USAGE_LINE.search(t) or len(t) > 512:
            continue
        # the richest usage line, not the first: programs print a bare "Usage:" header and
        # then the real synopsis, and reporting the header loses every bracket with it
        n = sum(1 for _ in _USAGE_FLAG.finditer(t))
        if usage is None or n > best:
            usage, best = t.strip(), n
        for m in _USAGE_FLAG.finditer(t):
            flag, placeholder = m.group(1), m.group(2)
            if flag in ("-", "--") or len(flag) > 32:
                continue
            takes = bool(placeholder and placeholder.strip("<>[]"))
            flags[flag] = flags.get(flag, False) or takes
            if takes:
                flags[flag] = True
    return flags, usage


def from_argv_compares(strings) -> dict:
    """Flags a program compares argv against directly (`strcmp(argv[i], "-c")`).

    A bare "-c"/"--config" string in the table is weak evidence on its own, so this only
    contributes flags; whether they take a value comes from the other signals.
    """
    out: dict = {}
    for s in strings:
        t = (s or "").strip()
        if re.fullmatch(r"--?[A-Za-z][A-Za-z0-9_-]{0,30}", t):
            out[t] = False
    return out


def optional_flags(usage: str) -> set:
    """Flags the usage line marks OPTIONAL, by the bracket convention every usage line uses.

    This is the difference between a proposal that helps and one that hurts. unzip documents
    `Usage: unzip [-opts[modifiers]] file[.zip] [list] [-x xlist] [-d exdir]` -- every flag
    bracketed, because unzip needs none of them -- and reading that as a requirement produced
    `-d /tmp/lykos-arg -x x`, which unzip rejects with "cannot find or open x". A command line
    built from optional flags is strictly worse than no command line at all, because the
    target refuses it and the campaign looks clean again.
    """
    out, depth = set(), 0
    for m in re.finditer(r"[\[\]]|(--?[A-Za-z][A-Za-z0-9_-]*)", usage or ""):
        tok = m.group(0)
        if tok == "[":
            depth += 1
        elif tok == "]":
            depth = max(0, depth - 1)
        elif depth:
            out.add(m.group(1))
    return out


# A subcommand-dispatched tool (`tool <command> [opts] INPUT`) parses NOTHING when run as
# `tool INPUT` -- it prints its command list and exits, so the fuzzer never reaches the parser and
# the campaign stalls at L0. mutool, git, openssl, busybox, ImageMagick and many others work this
# way. We detect the command table and pick the subcommand that READS a single input document, so
# the fuzzed input actually flows into the parser.
_DISPATCH_HINT = re.compile(
    r"(?im)^\s*usage:.*<(?:command|subcommand|verb|tool)>"       # usage: tool [opts] <command> ...
    r"|^\s*(?:available\s+)?(?:sub)?commands:\s*$")              # a 'Commands:' section header
# a command-list row: leading indent, a lowercase command word, then a description (often after
# `--` or 2+ spaces). Deliberately narrow so an ordinary wrapped help line is not mistaken for one.
_SUBCMD_ROW = re.compile(r"^[ \t]+([a-z][a-z0-9][a-z0-9_-]{0,18})(?:[ \t]*--|[ \t]{2,}|\t)\s*(.+?)\s*$")
# commands whose job is to READ/parse one input document -- the ones worth fuzzing. Ranked: a
# renderer/convertor exercises the deepest parser, then structural dumps, then light info.
_READ_CMD_PRIORITY = ["draw", "convert", "render", "rasterize", "rip", "dump", "show", "info",
                      "trace", "extract", "clean", "cat", "parse", "read", "check", "test", "view",
                      "inspect", "list", "ls", "print", "display", "decode", "disasm", "run"]
# verbs in a description that mean "this consumes an input document".
_READ_VERBS = ("convert", "render", "show", "display", "information", "info", "rewrite", "parse",
               "read", "dump", "extract", "trace", "inspect", "decode", "print", "draw", "view",
               "list", "check", "analyse", "analyze", "rasteri")
# commands that do NOT read a single input doc (create from scratch, need many inputs, side effects).
_NONREAD_CMD = {"create", "new", "make", "init", "merge", "combine", "sign", "gen", "generate",
                "help", "version", "config", "add", "commit", "push", "pull", "clone", "serve",
                "server", "daemon", "install", "update", "upgrade", "remove", "delete", "set"}


def from_subcommands(help_text: str) -> "tuple[Optional[str], list]":
    """(best_input_reading_subcommand, all_subcommands) for a dispatch-style tool, else (None, []).

    Requires BOTH a dispatch usage hint (`usage: tool <command>`) and a parsed command list, so a
    program that merely lists examples is not mistaken for one. The chosen command is the
    highest-ranked one that reads a single input document (a renderer/convertor first, as it drives
    the deepest parser), avoiding create/merge/sign/help and friends."""
    text = help_text or ""
    if not _DISPATCH_HINT.search(text):
        return None, []
    cmds: dict = {}
    for raw in text.splitlines():
        m = _SUBCMD_ROW.match(raw.rstrip())
        if not m:
            continue
        name, desc = m.group(1), m.group(2).strip()
        if name in cmds or name in ("usage", "options", "commands"):
            continue
        cmds[name] = desc.lower()
    if len(cmds) < 2:                                    # a single match is almost certainly noise
        return None, []
    names = list(cmds)

    def _rank(name):
        if name in _NONREAD_CMD:
            return (3, 99, name)                         # last resort only
        reads = any(v in cmds[name] for v in _READ_VERBS)
        pri = _READ_CMD_PRIORITY.index(name) if name in _READ_CMD_PRIORITY else 50
        return (0 if reads or name in _READ_CMD_PRIORITY else 1, pri, name)

    best = min(names, key=_rank)
    if best in _NONREAD_CMD:                             # nothing looked like a reader -> don't guess
        return None, names
    return best, names


# --------------------------------------------------------------------------- multi-call binaries
# A MULTI-CALL binary is one executable that is many programs, chosen by the first positional
# argument (or by argv[0] through a symlink). busybox is the canonical one and it is everywhere
# this project's firmware work points: 347 programs in a 1 MB static image, and every embedded
# device has one.
#
# `from_subcommands` cannot see it, for two reasons that are both about shape rather than about
# busybox. Its dispatch hint wants `usage: tool <command>` and busybox writes
# `Usage: busybox [function [arguments]...]`; and its row parser wants one command per line with
# a description, where a multi-call binary prints a WRAPPED, comma-separated block of bare names
# under `Currently defined functions:`. So the campaign fuzzed `busybox` itself -- which parses
# nothing, prints its usage and exits -- and the parsers behind the dispatch (unlzma, tar, awk;
# busybox 1.21.1's own CVE list is an out-of-bounds read in the unlzma decompressor and a
# use-after-free in awk) were never reached at all.
_MULTICALL_HINT = re.compile(r"(?im)multi-call binary"
                             r"|^\s*usage:\s*\S+\s+\[?(?:function|applet)\b")
#: The listing a multi-call binary offers about itself. Far better evidence than parsing wrapped
#: help text, and it is the binary's own answer rather than ours.
_LIST_FLAGS = ("--list", "--list-full")
#: `Currently defined functions:` / `Applets:` and the block of bare names under it.
_LIST_HEADER = re.compile(r"(?im)^[ \t]*(?:currently defined functions|applets|functions|"
                          r"commands)[ \t]*:[ \t]*$")
#: A bare name in such a block: `[`, `[[`, `add-shell`, `dpkg-deb`, `nslookup`. Comma- or
#: whitespace-separated, and the `[`/`[[` forms are dropped because they are the test builtin.
_LIST_NAME = re.compile(r"[a-z][a-z0-9][a-z0-9_.-]{0,20}")
#: Programs a campaign must NOT invoke. These act on the HOST rather than parse an input, and
#: "it runs in a sandbox" is not a reason to fire them: the sandbox bounds memory, the filesystem
#: view and the process tree -- it does not change what `reboot`, `mkfs` or `passwd` MEAN. The
#: list is deliberately about EFFECT, so it reads the same for any multi-call binary, not just
#: busybox.
_MULTICALL_DENY = re.compile(
    r"(?i)^(?:reboot|halt|poweroff|shutdown|init|linuxrc|telinit|runlevel"
    r"|kill|killall|killall5|pkill|fuser"
    r"|rm|rmdir|shred|mkfs[.\w]*|mkdosfs|mke2fs|makedevs|mknod|devmem|fdisk|sfdisk|fsck\w*|wipefs|dd|mount|umount"
    r"|swapon|swapoff|losetup|blockdev|mkswap|freeramdisk|fdformat|eject"
    r"|insmod|rmmod|modprobe|depmod|lsmod|chroot|pivot_root|switch_root|setarch"
    r"|hwclock|date|rdate|ntpd|adjtimex"
    r"|passwd|chpasswd|adduser|deluser|addgroup|delgroup|add-shell|remove-shell"
    r"|su|login|sulogin|getty|vlock|chown|chgrp|chmod|chattr"
    r"|ifconfig|ifup|ifdown|ip|route|arp|arping|iptables|brctl|udhcpc|udhcpd|dhcprelay"
    r"|telnetd|httpd|ftpd\w*|inetd|crond|klogd|syslogd|watchdog|nbd-client|zcip"
    r"|poweroff|acpid|mdev|hotplug\w*|run-init|nohup|setsid|start-stop-daemon)$")
#: Parser DEPTH, in order. Each entry is a shape rather than a name list, so it ranks the
#: applets of any multi-call binary: a decompressor reads a whole format from one stream and is
#: the deepest single-input parser a utility box has; then archive readers, then text/record
#: parsers. `_READ_CMD_PRIORITY` orders what is left over, exactly as for a subcommand tool.
_MULTICALL_PRIORITY = (
    re.compile(r"^(?:un(?:lzma|xz|zip|compress|lzop|gzip)|lzcat|xzcat|bzcat|zcat|lzopcat|gunzip"
               r"|bunzip2|lzma|xz|gzip|bzip2|lzop|compress)$"),
    re.compile(r"^(?:tar|cpio|ar|rpm|rpm2cpio|dpkg|dpkg-deb|unzip|zip)$"),
    re.compile(r"^(?:awk|sed|ed|diff|patch|od|hexdump|xxd|strings|base64|uudecode|uuencode"
               r"|dos2unix|unix2dos|expand|unexpand|fold|sort|uniq|cut|tr|grep|egrep|fgrep)$"),
    re.compile(r"^(?:cat|head|tail|wc|md5sum|sha1sum|sha256sum|sha512sum|cksum|cmp|file|readelf"
               r"|nm|objdump|lsattr|stat)$"),
)


#: `Usage: busybox [function [arguments]...]` -- the dispatcher's own name, in its own .rodata.
_SELF_NAME = re.compile(r"(?im)^\s*usage:\s+([A-Za-z0-9_.+-]{2,24})\s+\[?(?:function|applet)\b")


def multicall_self_name(text: str) -> Optional[str]:
    """The name a multi-call binary insists on being invoked as, or None.

    THIS IS NOT COSMETIC. busybox dispatches on argv[0] first: invoked as anything that is not
    one of its applets -- and `target.bin`, the name every stage in this pipeline stages a
    target under, is not -- it answers `target.bin: applet not found` and exits 1. Every probe,
    every campaign execution and every replay against the renamed file hits that one line, which
    is why the dispatcher discovery found 14 doors by hand and none inside the engine. The image
    says what it wants to be called in its own usage string, so the fix is to read it and stage
    the file under that name.
    """
    m = _SELF_NAME.search(text or "")
    return m.group(1) if m else None


def exec_name_for(data: bytes) -> str:
    """The filename this binary has to be staged under, or "" for the usual `target.bin`.

    Derived from the TARGET rather than from the run that found a crash, so the fuzz campaign,
    the PoC replay and the shipped bundle each arrive at the same answer without a new field to
    thread between them.
    """
    try:
        strings = [getattr(x, "value", x) for x in raw_strings(data, minlen=8, limit=200000)]
    except Exception:                                   # noqa: BLE001 -- best-effort
        return ""
    blob = "\n".join(s for s in strings if isinstance(s, str))
    if not _MULTICALL_HINT.search(blob):
        return ""
    name = multicall_self_name(blob)
    # A name with a path separator or an odd character is not something to create a file from.
    return name if name and name.replace("-", "").replace("_", "").replace(".", "").isalnum() \
        else ""


def is_multicall(help_text: str) -> bool:
    """Does this text say the program is a multi-call binary?

    Exposed because the caller has to decide whether to spend an execution looking for the
    listing, and because `_help_text` -- which scores candidate help outputs by how many OPTION
    rows they carry -- returns None for busybox: its usage has no `-x` rows at all, and its
    programs are a wrapped comma-separated block rather than one described command per line. So
    the stage asks this of the bare invocation's own output when the scored help text has
    nothing to say, which is how the dispatcher is found on the one target it matters most for.
    """
    return bool(_MULTICALL_HINT.search(help_text or ""))


def multicall_names(help_text: str, *, list_output: Optional[str] = None) -> list:
    """The programs a multi-call binary contains, or [] when it is not one.

    `list_output` is what the binary printed for its own listing flag (see `multicall_list_flag`);
    when it is absent the names are read out of the block under the help text's own header, which
    is the same information wrapped.
    """
    if not _MULTICALL_HINT.search(help_text or ""):
        return []
    text = list_output if list_output else _block_after_header(help_text or "")
    if not text:
        return []
    out, seen = [], set()
    for m in _LIST_NAME.finditer(text):
        name = m.group(0)
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def _block_after_header(help_text: str) -> str:
    """The wrapped block of names under `Currently defined functions:`, or ""."""
    m = _LIST_HEADER.search(help_text)
    if not m:
        return ""
    rest = help_text[m.end():]
    # The block ends at the first blank line that is followed by something unindented, which is
    # how busybox separates it from whatever a build appends after it.
    lines = []
    for ln in rest.splitlines():
        if not ln.strip():
            if lines:
                break
            continue
        lines.append(ln)
    return "\n".join(lines)


def multicall_list_flag(help_text: str) -> Optional[str]:
    """The listing flag this binary documents for itself, or None.

    Taken from the help text rather than tried blind: a flag we invent is a flag some other
    program means something else by.
    """
    low = (help_text or "").lower()
    for flag in _LIST_FLAGS:
        if flag in low:
            return flag
    return None


def rank_multicall(names) -> list:
    """The contained programs worth fuzzing, deepest parser first. An ALLOW-list, by shape.

    A multi-call binary is not a subcommand tool with a few verbs: busybox lists 345 programs,
    and among them are `reboot`, `mkfs.ext2`, `devmem` (physical memory), `passwd`, `nc`, `wget`
    and the whole of service supervision. A deny-list is the wrong instrument for that -- it has
    to be complete to be safe, and one name nobody thought of is a campaign firing `mkfs.vfat`
    with a mutated argv. So this returns ONLY what a shape pattern recognises as a program that
    reads one input and parses it: a decompressor, an archive reader, a text/record parser, a
    hash or a dumper. Everything else is left alone, including things that would be harmless,
    and the count of what was skipped is reported rather than hidden.

    The order is the second half of the job: a budget buys a handful of doors out of 345, so
    depth-first is what decides whether the search reaches a real parser. Decompressors come
    first because one reads an entire format from a single stream -- and busybox 1.21.1's own
    CVE list leads with an out-of-bounds read in the unlzma decompressor.
    """
    out = []
    for n in names:
        if len(n) < 2 or _MULTICALL_DENY.match(n) or n in _NONREAD_CMD:
            continue
        tier = next((i for i, pat in enumerate(_MULTICALL_PRIORITY) if pat.match(n)), None)
        if tier is None:
            continue                                  # unknown effect: not invoked
        out.append((tier, n))
    out.sort()
    return [n for _, n in out]


#: Argv shapes to try for one contained program, in order. Bare stdin first, because every
#: decompressor and every filter in a utility box reads it; then the file positional; then the
#: two list-an-archive forms, which is what an archive reader needs to parse a whole container
#: without unpacking it anywhere.
_MULTICALL_SHAPES = ((), (INPUT_PLACEHOLDER,), ("-t", INPUT_PLACEHOLDER), ("-tf", INPUT_PLACEHOLDER),
                     ("-d",), ("-f", INPUT_PLACEHOLDER))
#: A program whose BARE invocation compresses instead of parsing. Both directions accept the
#: input and neither prints a usage line, so the probe below cannot tell them apart -- and the
#: difference is the whole point: compressing our own mutated bytes exercises a writer, while
#: `-d` runs the decompressor, which is the parser that reads attacker-controlled structure.
_COMPRESSOR = re.compile(r"^(?:gzip|bzip2|xz|lzma|lzop|compress|zip)$")
#: What a program prints when it did NOT accept the invocation. Checked in the OUTPUT rather than
#: in the exit code: busybox exits 1 both for "usage" and for "that is not a valid archive", and
#: the second one is a parser that ran, which is exactly what a door is.
_REFUSED = re.compile(r"(?im)^\s*(?:usage|busybox\b.*multi-call|.*applet not found)")


#: The program inside the SAME image that produces what a door consumes. A utility box ships
#: both directions of every codec it has, so the target can generate its own valid seed -- which
#: is the one thing a decompressor fuzzing campaign actually needs. Measured elsewhere in this
#: project: jhead took 98,500 executions to find nothing where a valid sample found the bug in
#: 60 seconds, because a parser rejects random bytes before reaching any of its own logic.
_MULTICALL_INVERSE = {
    "unlzma": "lzma", "lzcat": "lzma", "unxz": "xz", "xzcat": "xz",
    "bunzip2": "bzip2", "bzcat": "bzip2", "gunzip": "gzip", "zcat": "gzip",
    "unlzop": "lzop", "lzopcat": "lzop", "uncompress": "compress", "unzip": "zip",
}


def multicall_inverse(name: str) -> Optional[str]:
    """The contained program that WRITES what `name` reads, or None."""
    return _MULTICALL_INVERSE.get((name or "").lower())


def multicall_seed(run, name: str, *, text: bytes = b"lykos seed\n" * 8) -> bytes:
    """A valid input for this door, made by the target's own inverse program, or b"".

    `run(argv, stdin) -> result` as for `multicall_doors`. The seed is the target's answer, not
    ours: nothing here knows the LZMA header, and nothing here has to.
    """
    inverse = multicall_inverse(name)
    if not inverse:
        return b""
    try:
        r = run([inverse], text)
    except Exception:                                   # noqa: BLE001 -- seeding is best-effort
        return b""
    out = getattr(r, "stdout", b"") or b""
    # It has to be COMPRESSED output: not the text echoed back, and not the usage line a
    # program prints when it does not have an inverse by that name -- a multi-call binary
    # answers an unknown function with its own help, and help text makes a terrible seed.
    if not out or out == text or _REFUSED.search(out.decode("utf-8", "replace")):
        return b""
    return bytes(out)


#: Three names, one decoder: `bunzip2`, `bzcat` and `bzip2 -d` are the same code reached three
#: ways, and a budget that buys five doors must not spend them all on bzip2. The family is what
#: a door is really a door INTO, so the probe keeps the first that opens per family and moves on.
#: Without this, busybox's eight verified doors were bunzip2/bzcat/bzip2/gunzip/gzip/lzcat/... --
#: two distinct decoders in the first five, and `unlzma`, the one its CVE list names, unreached.
_CODEC_FAMILY = {
    "bunzip2": "bzip2", "bzcat": "bzip2", "bzip2": "bzip2",
    "gunzip": "gzip", "zcat": "gzip", "gzip": "gzip",
    "unlzma": "lzma", "lzcat": "lzma", "lzma": "lzma",
    "unxz": "xz", "xzcat": "xz", "xz": "xz",
    "unlzop": "lzop", "lzopcat": "lzop", "lzop": "lzop",
    "uncompress": "compress", "compress": "compress", "zcat.compress": "compress",
    "unzip": "zip", "zip": "zip",
    "egrep": "grep", "fgrep": "grep", "grep": "grep",
    "md5sum": "hash", "sha1sum": "hash", "sha256sum": "hash", "sha512sum": "hash",
    "sha3sum": "hash", "cksum": "hash", "sum": "hash",
    "hexdump": "hexdump", "hd": "hexdump", "od": "hexdump", "xxd": "hexdump",
    "dos2unix": "d2u", "unix2dos": "d2u",
    "uudecode": "uu", "uuencode": "uu",
}


def codec_family(name: str) -> str:
    """The decoder `name` reaches, or the name itself when it is the only way in."""
    return _CODEC_FAMILY.get((name or "").lower(), (name or "").lower())


def multicall_doors(run, names, *, sample: bytes = b"", cap: int = 8,
                    probe_cap: int = 24) -> list:
    """[(program, argv)] for the contained programs that ACCEPT an invocation, verified by running.

    Proposing is not knowing. `tar` with the input on stdin prints its usage and exits, `unlzma`
    reads it, and nothing in a name says which -- so each candidate costs one execution against
    the target's own behaviour, and a program that refuses every shape is dropped rather than
    fuzzed through a door that was never open. That is the same contract `verify` applies to a
    discovered flag set, for the same reason: an unverified proposal produces a campaign that
    executes thousands of times and never enters the parser.

    `run(argv, stdin) -> result` is injected so this is testable without a sandbox. Two bounds
    on the cost, because 345 candidates * 6 shapes is not a budget anyone would spend looking
    for a door: `cap` stops once enough are open, and `probe_cap` stops a binary whose programs
    all refuse from being probed to the end of the list -- which under qemu is the expensive
    case, at tens of milliseconds per execution.
    """
    doors: list = []
    families: set = set()
    for name in list(names)[:probe_cap]:
        if len(doors) >= cap:
            break
        if codec_family(name) in families:
            continue                                    # the same decoder, reached another way
        shapes = _MULTICALL_SHAPES
        if _COMPRESSOR.match(name):
            shapes = (("-d",),) + tuple(sh for sh in shapes if sh != ("-d",))
        for shape in shapes:
            argv = [name] + [str(a) for a in shape]
            try:
                r = run(argv, sample)
            except Exception:                           # noqa: BLE001 -- probing is best-effort
                continue
            blob = ((getattr(r, "stdout", b"") or b"") + b"\n"
                    + (getattr(r, "stderr", b"") or b"")).decode("utf-8", "replace")
            if _REFUSED.search(blob):
                continue
            doors.append((name, argv))
            families.add(codec_family(name))
            break
    return doors


def discover(strings, *, usage_hint: Optional[str] = None, help_text: Optional[str] = None) -> dict:
    """Everything we can say about how to invoke this target.

    The USAGE LINE is the authority on which flags exist, and the others only refine it. That
    ordering is not a preference, it is precision: an option string is a short run of letters
    and colons, which thousands of strings in any libc match by accident -- trusting it
    directly invented sixty flags for a program with five, and a proposed command line full of
    invented flags is worse than none, because the target rejects it and the campaign looks
    clean again.

    With no usage line we fall back to a single unambiguous option string, and say so with a
    lower confidence. With neither, we say nothing.

    Returns {flags: [{flag, takes_value, kind, default}], usage, sources, confidence}.
    """
    strings = [s for s in (strings or []) if s]
    if usage_hint:
        strings = list(strings) + [usage_hint]
    use, usage = from_usage(strings)
    opt = from_optstring(strings)
    cmp_ = from_argv_compares(strings)
    help_flags, help_ph, help_names = (from_help((help_text or "").splitlines())
                                       if help_text else ({}, {}, {}))
    # A dispatch-style tool (`tool <command> INPUT`) parses nothing without its subcommand. Look
    # for the command table in --help AND in the strings (many print it on a bare/`-h` run).
    subcmd, _all = from_subcommands("\n".join(list(strings) + ([help_text] if help_text else [])))

    def _refine(flags_in, sources):
        # the option string is trustworthy about VALUES for flags we already named
        for flag in list(flags_in):
            if len(flag) == 2 and flag in opt:
                flags_in[flag] = flags_in[flag] or opt[flag]
                if "getopt" not in sources:
                    sources.append("getopt")
        for flag in cmp_:
            if flag in flags_in and "argv-compare" not in sources:
                sources.append("argv-compare")

    if use:
        flags_in = dict(use)
        sources = ["usage"]
        confidence = "high"
        _refine(flags_in, sources)
        # --help enumerates options the terse usage line omits, and names their value shapes.
        for flag, takes in help_flags.items():
            flags_in[flag] = flags_in.get(flag, False) or takes
        if help_flags:
            sources.append("help")
    elif help_flags:
        # no usage line, but --help gave us a real, verifiable option table: trust it.
        flags_in, sources, confidence = dict(help_flags), ["help"], "high"
        _refine(flags_in, sources)
    elif len(opt) and len(opt) <= 12:
        flags_in, sources, confidence = dict(opt), ["getopt"], "medium"
    else:
        # No flags, but a converter's `input output` usage still names a usable invocation (the two
        # positionals), so carry output_positional out even on the "none" path.
        return {"flags": [], "usage": usage, "sources": (["subcommand"] if subcmd else []),
                "confidence": "medium" if subcmd else "none",
                "output_positional": output_positional(usage), "subcommand": subcmd}

    placeholders = {}
    for text in ([usage] if usage else []):
        for m in _USAGE_FLAG.finditer(text):
            if m.group(2):
                placeholders[m.group(1)] = m.group(2)
    for flag, ph in help_ph.items():                 # help names shapes usage often omits
        placeholders.setdefault(flag, ph)

    optional = optional_flags(usage or "")
    flags = []
    for flag in sorted(flags_in):
        takes = flags_in[flag]
        kind, default = _hint_for(flag, placeholders.get(flag), name=help_names.get(flag))
        flags.append({"flag": flag, "takes_value": takes,
                      "optional": flag in optional,
                      "kind": kind if takes else "switch",
                      "default": default if takes else None,
                      "placeholder": placeholders.get(flag), "name": help_names.get(flag)})
    # Last resort for a value flag whose shape neither usage nor --help gave us (default is the
    # generic "x"): a structured value the binary documents in an error/format string. Not every
    # parameter-driven target has a --help, but a strict validator almost always PRINTS the shape
    # it wants, so mine it. Each generic flag takes a distinct mined shape when several exist.
    generic = [f for f in flags if f["takes_value"] and f["default"] == "x"]
    if generic:
        shapes = mine_shape_values(strings)
        for i, f in enumerate(generic):
            if shapes:
                f["default"] = shapes[i] if i < len(shapes) else shapes[0]
                if "strings" not in sources:
                    sources.append("strings")
    # getopt names flags the usage line / --help left out. We do NOT promote them into the main
    # invocation (that is the "sixty invented flags" trap), but a value-taking one can be the
    # OPTIONAL input slot a reader hides its input behind -- `tcpdump -r <pcap>` is in the optstring,
    # not the terse usage. Add such flags as OPTIONAL, so only the input-slot fallback in
    # propose_argv can pick one, and the caller VERIFIES the chosen invocation against the real
    # target (so a wrong guess is empirically dropped).
    if sources and sources[0] in ("usage", "help"):
        have = {f["flag"] for f in flags}
        for oflag, otakes in opt.items():
            if otakes and oflag not in have:
                k, d = _hint_for(oflag, None)
                flags.append({"flag": oflag, "takes_value": True, "optional": True,
                              "kind": k, "default": d, "placeholder": None, "name": None,
                              "from_getopt": True})
    if subcmd and "subcommand" not in sources:
        sources.append("subcommand")
    return {"flags": flags, "usage": usage, "sources": sources, "confidence": confidence,
            "output_positional": output_positional(usage), "subcommand": subcmd}


def propose_argv(found: dict, *, input_kind: str = "config") -> list:
    """A concrete argv template, with `@@` marking where the fuzzed input goes.

    Only flags that TAKE A VALUE are filled: a switch we were not asked for is not ours to
    turn on, and neither is one the usage line brackets as OPTIONAL. At most one value slot
    becomes `@@` -- the one whose kind matches the input the
    campaign is going to mutate -- because the rest have to stay valid for the program to
    reach its parser at all.

    AT MOST one, not exactly one: with no usage line there are no placeholders to read a kind
    from, and `-c` on its own says nothing about what it holds. Picking a flag anyway would be
    a guess wearing the same clothes as a finding. So every value-taking flag gets a concrete
    default and the returned argv contains no `@@`, which the runner handles by APPENDING the
    input positionally. Callers that need to know which happened test `"@@" in argv`.
    """
    # A CONVERTER (`tool [opts] INPUT OUTPUT`) is driven by its two positionals; its flags sit in
    # the usage line's `[options]`, i.e. they are OPTIONAL extras, and filling them with placeholder
    # values (`-c x`) only makes the tool reject the whole invocation. So for a converter, propose
    # just the positionals: input at @@, a scratch path at OUTPUT_PLACEHOLDER.
    # A dispatch-style tool needs its subcommand FIRST (`mutool draw @@`), or it prints its command
    # list and never parses the input. Everything else is placed after it.
    sub = found.get("subcommand")
    if found.get("output_positional"):
        return ([sub] if sub else []) + [INPUT_PLACEHOLDER, OUTPUT_PLACEHOLDER]
    # The fuzzed input is a FILE, delivered behind whichever flag names a file to read. `config`
    # is the canonical kind, but a --help metavar of FILE/PATH gives kind `path` for the very same
    # slot, so both are input slots -- otherwise a help-mined `-c FILE` got a dead default path and
    # the input went nowhere. A `jar` is a module to load, not the fuzz input, so it is excluded.
    input_kinds = {input_kind, "path"}
    argv: list = [sub] if sub else []
    placed = False
    for f in found.get("flags") or []:
        if not f.get("takes_value") or f.get("optional"):
            continue
        argv.append(f["flag"])
        if not placed and f.get("kind") in input_kinds:
            argv.append("@@")
            placed = True
        else:
            argv.append(_concrete(f))
    # No REQUIRED flag carries the input, but the target may read its input behind an OPTIONAL file
    # flag -- `tcpdump -r <pcap>`, `openssl ... -in <file>`. Append that one, with the input at it,
    # so a reader whose only input path is optional still gets fuzzed. Pick a READ flag, never an
    # output one (`-w`/`-o`/`--out`), or we would write to the fuzzed path instead of reading it.
    # A DISPATCH tool takes its input as the positional after the subcommand (`mutool draw @@`),
    # so an OPTIONAL read-ish flag must not claim the slot: `-r` on `mutool draw` is a
    # RESOLUTION, and `mutool draw -r input.pdf` feeds the document to that flag and then has no
    # input left -- the tool prints usage and the campaign looks clean forever. The
    # optional-read-flag branch below exists for a flag-only reader (`tcpdump -r <pcap>`), which
    # is the case with no subcommand to anchor a positional.
    if not placed and sub:
        argv.append(INPUT_PLACEHOLDER)
        placed = True
    if not placed:
        # A file-kind read flag is the clearest input slot; a bare getopt value-flag with no metavar
        # (kind "value") is a candidate too, chosen by how read-like its name is -- `-r`/`-i`/`-in`
        # before `-f`/`-file`. The caller verifies the result, so a wrong pick is dropped.
        cands = [f for f in (found.get("flags") or [])
                 if f.get("takes_value") and f.get("optional")
                 and f.get("kind") in (input_kinds | {"value"}) and _is_read_flag(f)]
        cands.sort(key=_read_rank)
        if cands:
            argv += [cands[0]["flag"], "@@"]
            placed = True
    # A converter (`tool [opts] INPUT OUTPUT`): the input is a trailing positional AND a writable
    # OUTPUT path must follow, or it refuses to run. Emit both placeholders explicitly (input before
    # output); the delivery layers substitute a real scratch output for OUTPUT_PLACEHOLDER.
    if not placed and found.get("output_positional"):
        argv += [INPUT_PLACEHOLDER, OUTPUT_PLACEHOLDER]
        placed = True
    # A dispatch subcommand takes its input as the positional after it (`mutool draw @@`): if no
    # flag claimed the input, place it there rather than leaving the runner to guess.
    if not placed and sub:
        argv.append(INPUT_PLACEHOLDER)
        placed = True
    return argv


_READ_FLAG = re.compile(r"(?i)read|input|\bin\b|\bsrc\b|source|load|\bfile\b|\br\b|\bi\b|\bf\b")
_WRITE_FLAG = re.compile(r"(?i)out|write|save|dest|\bdst\b|export|log|\bo\b|\bw\b")
# Read-likeness ranking (lower = more clearly an input): an explicit "read"/"input" beats the
# single letters r/i, which beat the generic "file"/f -- so `tcpdump -r` is chosen over `-f`.
_READ_RANK = ("read", r"\binput\b", r"\bin\b", "src", "source", "load", r"\br\b", r"\bi\b",
              "file", r"\bf\b")


def _read_rank(f: dict) -> int:
    hay = (f.get("flag", "").lstrip("-") + " " + (f.get("name") or "")
           + " " + (f.get("placeholder") or "")).lower()
    for i, pat in enumerate(_READ_RANK):
        if re.search(pat, hay):
            return i
    return 99


def _is_read_flag(f: dict) -> bool:
    """A flag that names an INPUT to read, not an output to write. Checks the flag letter, its
    long alias and its metavar; an output signal vetoes it so the campaign never feeds the target a
    path it will overwrite."""
    hay = " ".join(x for x in (f.get("flag", "").lstrip("-"), f.get("name") or "",
                               f.get("placeholder") or "") if x)
    if _WRITE_FLAG.search(hay):
        return False
    return bool(_READ_FLAG.search(hay))


def _concrete(f: dict) -> str:
    d = f.get("default") or "x"
    if d == "@@":                            # a second path-ish value: give it a real one
        return "/tmp/lykos-arg"
    if f.get("kind") == "id" and d.startswith("00000000"):
        return str(uuid.UUID(int=0))
    return d


# Kinds whose value NAMES A FILE. A proposal that points at a file which does not exist cannot
# be verified and cannot be used: a service required to be given `-j <app.jar>` was handed the
# literal string "app.jar", refused it because no such file exists, and the run concluded the
# whole invocation was wrong -- leaving the operator exactly where they started. The file has
# to be real before the proposal can be tested.
_FILE_KINDS = {"config", "jar", "path"}

# A jar with a manifest and no classes is a structurally valid jar: enough for a launcher that
# checks the file opens, and if the service actually loads a class from it the failure is
# reported honestly rather than hidden.
_MIN_MANIFEST = b"Manifest-Version: 1.0\nCreated-By: lykos\n\n"


def materialize(found: dict, directory, *, sample=None) -> list:
    """A proposed argv with real files on disk behind every value that names one.

    Returns the argv; `@@` is left in place, because the campaign substitutes its own mutated
    input there. Everything else that names a file becomes a path that exists.

    `directory` MUST be the directory the target executable is staged in. The sandbox masks
    /tmp with a private tmpfs and binds back only the executable's own directory, so a file
    written anywhere else exists on the host and not inside the sandbox -- the target then
    reports "cannot open jar", which looks exactly like a wrong proposal and is not one.
    """
    import zipfile
    d = pathlib.Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    argv = propose_argv(found)
    out: list = []
    i = 0
    kinds = {f["flag"]: f.get("kind") for f in found.get("flags") or []}
    while i < len(argv):
        a = argv[i]
        if a == OUTPUT_PLACEHOLDER:                       # a converter's scratch output path
            out.append(OUTPUT_SCRATCH)                    # relative -> the sandbox's writable cwd
            i += 1
            continue
        out.append(a)
        kind = kinds.get(a)
        if i + 1 < len(argv) and kind in _FILE_KINDS and argv[i + 1] != INPUT_PLACEHOLDER:
            if kind == "jar":
                path = d / "app.jar"
                with zipfile.ZipFile(path, "w") as z:
                    z.writestr("META-INF/MANIFEST.MF", _MIN_MANIFEST.decode())
            else:
                path = d / ("lykos.conf" if kind == "config" else "lykos.dat")
                path.write_bytes(sample if sample is not None else b"# lykos\n")
            out.append(str(path))
            i += 2
            continue
        i += 1
    return out


_REJECT = re.compile(r"(?i)\b(usage|invalid option|unrecogni[sz]ed|unknown option|"
                     r"must (be|give|specify)|required|missing)\b")
# The invocation named a FILE the target could not find/open/create -- a wrong proposal (unzip's
# `-x x` -> "cannot find or open x"), or an output path that is not writable. Distinct from the
# target ENGAGING our input content and failing on the bytes (a converter's "bad magic" / "Sanity
# check failed"), which got PAST the argument gate and must count as accepted. So a non-zero exit is
# "refused" only on one of these file errors, usage text, or output indistinguishable from the bare
# run -- never on a content error.
_FILEERR = re.compile(r"(?i)cannot (find|open|access|read|create|stat)|could not open|"
                      r"no such file|does not exist|unable to open|read-only file|"
                      r"permission denied|not found")
# The target ENGAGED our input and failed on its CONTENT/FORMAT, not on opening a file -- it got
# past argument parsing, which is exactly what a correct invocation looks like before fuzzing
# supplies real bytes. `mutool draw X` on a non-document prints "cannot find document handler for
# file" (the FILE opened fine; its FORMAT was not recognised), which must NOT be read as a file
# error. Checked before _FILEERR / _REJECT so a content error overrides their broader phrasing.
_CONTENT_OK = re.compile(
    r"(?i)document handler|cannot recognize|unsupported (file|document|format|image|type|filter)|"
    r"unknown (format|filter|type|encoding|codec)|not a (valid )?\w+ (file|document|image)|"
    r"bad (magic|header)|sanity check|parse error|syntax error|corrupt|malformed|"
    r"premature end|decode|invalid \w+ (header|structure|format|stream)")


def verify(run, exe, argv, sample_path, *, timeout: float = 10.0) -> dict:
    """Does this invocation actually get the target past its argument parsing?

    A proposal read off the strings is a hypothesis, and applying one unchecked is how you get
    the failure it was meant to fix: unzip needs no flags at all, and `-d <dir> -x x` is a
    worse command line than none. So run it.

    `run(argv) -> RunResult` is injected so this works for native, emulated and Wine targets
    without knowing which. The comparison is against the target's own no-argument behaviour:
    if running with no arguments is refused and running with ours is not, we are past the gate.
    """
    def once(a):
        r = run(list(a))
        out = ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "replace")[:4000]
        return {"rc": r.exit_code, "crashed": bool(r.crashed), "text": out,
                "nonzero": (r.exit_code or 0) not in (0, None)}

    def _rejected(res, other):
        t = res["text"]
        if _CONTENT_OK.search(t):                        # engaged our content (format error) -> in
            return False
        if _REJECT.search(t):                            # usage / invalid option / required / ...
            return True
        if _FILEERR.search(t):                           # named a file it can't find/open -> wrong
            return True
        if not res["nonzero"]:                           # ran clean (exit 0) -> accepted
            return False
        # Non-zero exit: refused ONLY if it never engaged our input -- no output, or output that is
        # just the same usage/banner as the no-argument run. A different, non-file, non-usage error
        # (a converter's "bad magic" / "Sanity check failed") means the parser RAN past the args.
        s = t.strip()
        return (not s) or s[:160] == other["text"].strip()[:160]

    bare = once([])
    ours = once([sample_path if a == "@@" else a for a in argv]) if argv else bare
    accepted = bool(ours["crashed"]) or not _rejected(ours, bare)
    return {
        "accepted": accepted,
        "argv": list(argv),
        "bare_rejected": _rejected(bare, {"text": ""}),
        "why": ("the target runs with this invocation" if accepted else
                "the target still refuses this invocation -- "
                + (ours["text"].strip().splitlines() or ["no output"])[0][:160]),
        "target_says": (bare["text"].strip().splitlines() or [""])[0][:200],
    }
