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
        for line in str(s).splitlines():
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
