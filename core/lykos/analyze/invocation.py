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
    (re.compile(r"(?i)host|addr|ip\b"), "host", "127.0.0.1"),
    (re.compile(r"(?i)user|login"), "user", "lykos"),
    (re.compile(r"(?i)path|dir|file|out|log"), "path", "@@"),
    (re.compile(r"(?i)num|count|size|len|threads|workers"), "number", "1"),
)


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
    out, cur = [], bytearray()
    for b in data[:limit * 8]:
        if b in _PRINTABLE:
            cur.append(b)
            continue
        if len(cur) >= minlen:
            out.append(cur.decode("ascii", "replace"))
            if len(out) >= limit:
                return out
        cur.clear()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "replace"))
    return out


def _hint_for(flag: str, placeholder: Optional[str]) -> tuple:
    for rx, kind, default in _HINTS:
        if rx.search(placeholder or "") or rx.search(flag):
            return kind, default
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


def discover(strings, *, usage_hint: Optional[str] = None) -> dict:
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

    if use:
        flags_in = dict(use)
        sources = ["usage"]
        # the option string is trustworthy about VALUES for flags usage already named
        for flag in list(flags_in):
            if len(flag) == 2 and flag in opt:
                flags_in[flag] = flags_in[flag] or opt[flag]
                if "getopt" not in sources:
                    sources.append("getopt")
        for flag in cmp_:
            if flag in flags_in and "argv-compare" not in sources:
                sources.append("argv-compare")
        confidence = "high"
    elif len(opt) and len(opt) <= 12:
        flags_in, sources, confidence = dict(opt), ["getopt"], "medium"
    else:
        return {"flags": [], "usage": usage, "sources": [], "confidence": "none"}

    placeholders = {}
    for text in ([usage] if usage else []):
        for m in _USAGE_FLAG.finditer(text):
            if m.group(2):
                placeholders[m.group(1)] = m.group(2)

    optional = optional_flags(usage or "")
    flags = []
    for flag in sorted(flags_in):
        takes = flags_in[flag]
        kind, default = _hint_for(flag, placeholders.get(flag))
        flags.append({"flag": flag, "takes_value": takes,
                      "optional": flag in optional,
                      "kind": kind if takes else "switch",
                      "default": default if takes else None})
    return {"flags": flags, "usage": usage, "sources": sources, "confidence": confidence}


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
    argv: list = []
    placed = False
    for f in found.get("flags") or []:
        if not f.get("takes_value") or f.get("optional"):
            continue
        argv.append(f["flag"])
        if not placed and f.get("kind") == input_kind:
            argv.append("@@")
            placed = True
        else:
            argv.append(_concrete(f))
    return argv


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
                "rejected": bool(_REJECT.search(out)) or (r.exit_code or 0) not in (0, None)}
    bare = once([])
    ours = once([sample_path if a == "@@" else a for a in argv]) if argv else bare
    accepted = bool(ours["crashed"]) or not ours["rejected"]
    return {
        "accepted": accepted,
        "argv": list(argv),
        "bare_rejected": bare["rejected"],
        "why": ("the target runs with this invocation" if accepted else
                "the target still refuses this invocation -- "
                + (ours["text"].strip().splitlines() or ["no output"])[0][:160]),
        "target_says": (bare["text"].strip().splitlines() or [""])[0][:200],
    }
