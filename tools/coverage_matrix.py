#!/usr/bin/env python3
"""What this engine can demonstrate, along the axes that actually decide it.

Why this exists, and why it is not a list of CWEs. The obvious way to ask "can we find
everything?" is to enumerate CWE ids and write a fixture per id, and that question cannot be
answered: `core/` mentions 221 CWE strings, 29 are emitted by a literal `cwe="CWE-x"`, the rest
live in CVE-database rows and taxonomy tables, and one fixture legitimately carries five of them
(`int_overflow_alloc` -> 190, 131, 122, 787, 119). CWE is a vocabulary for DESCRIBING a defect,
not a dimension of capability.

The dimensions that have actually decided outcomes in this project, every one of them measured:

  * **mechanism** -- what the defect IS (a stack smash, a lifetime error, an out-of-bounds read,
    an injection). Roughly twenty of these cover the 68 conformance cases.
  * **channel** -- how the input arrives: stdin, a file, argv, the environment, a socket, one
    field per prompt, or a program inside a multi-call binary. A campaign aimed at the wrong
    channel does no work and reports a clean zero.
  * **substrate** -- what executes the image: the host CPU, qemu-user for another ISA, wine, the
    JVM, CPython, a WASM engine, the CLR, the firmware rehoster, or a source build we made.
  * **oracle** -- what makes the defect VISIBLE: a signal on its own, a guard-page allocator, an
    ASan/UBSan/MSan/TSan build, valgrind, or a sanitizer-reported abort. busybox's lzma read
    faults only under the guard page; an uninitialised read is invisible without MSan.

A cell is a (mechanism, substrate) or (mechanism, channel) pair, and its value is the best level
some case DEMANDS there -- L0 identified, L1 verified crash, L2 primitive, L3 effect. Run with
`--measured <conformance output>` to overlay what the last run actually REACHED, which is the
only number that means anything.

The axes are derived from the fixtures themselves (the channel from what the fixture's own source
reads, the substrate from its cross-compiler prefix and file type), so the matrix cannot drift
from the cases the way a hand-kept table does.

Usage:
  python3 tools/coverage_matrix.py                        # what the gates demand
  python3 tools/coverage_matrix.py --measured run.txt     # ...and what they last reached
  python3 tools/coverage_matrix.py --holes                # only the empty cells
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parent.parent / "core"
TOOLS = Path(__file__).resolve().parent
for _p in (CORE, TOOLS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import pipeline_conformance as pc  # noqa: E402
from lykos import observe  # noqa: E402
from lykos.eval import archgate  # noqa: E402

#: CWE -> mechanism. Several CWEs map to one mechanism on purpose: 121/122/787/119/120 are all
#: "somebody wrote past the end", and the distinction between them is bookkeeping, not
#: capability. A mechanism is what you need a different TECHNIQUE to find or to prove.
MECHANISM = {
    "stack-overflow": ("CWE-121",),
    "heap-overflow": ("CWE-122",),
    "oob-write": ("CWE-787", "CWE-788", "CWE-120", "CWE-119"),
    "oob-read": ("CWE-125", "CWE-126", "CWE-127"),
    "bad-index": ("CWE-129",),
    "lifetime": ("CWE-416", "CWE-415", "CWE-590", "CWE-824"),
    "uninitialised": ("CWE-457", "CWE-908"),
    "null-deref": ("CWE-476",),
    "format-string": ("CWE-134",),
    "integer-overflow": ("CWE-190", "CWE-131", "CWE-191", "CWE-680"),
    "div-by-zero": ("CWE-369",),
    "type-confusion": ("CWE-843",),
    "disclosure": ("CWE-200", "CWE-203"),
    "command-injection": ("CWE-78", "CWE-77", "CWE-88"),
    "code-injection": ("CWE-94", "CWE-95"),
    "path-traversal": ("CWE-22", "CWE-23", "CWE-36"),
    "sql-injection": ("CWE-89", "CWE-943"),
    "xxe": ("CWE-611", "CWE-827"),
    "ssrf": ("CWE-918",),
    "race": ("CWE-362", "CWE-367"),
    "resource-exhaustion": ("CWE-400", "CWE-770", "CWE-789", "CWE-835", "CWE-401"),
}
_CWE_TO_MECH = {c: m for m, cs in MECHANISM.items() for c in cs}

#: How the fixture's own source says its input arrives. Read from the C, not from a table kept
#: beside it: the fixture is the only thing that cannot lie about this.
_CHANNEL_SIGNS = (
    ("socket", (r"\bsocket\s*\(", r"\baccept\s*\(", r"\bbind\s*\(")),
    ("env", (r"\bgetenv\s*\(",)),
    # FILE before ARGV, and only when the path COMES FROM argv: `fopen(argv[1])` is the file
    # channel (the path is in argv, the input is the file's bytes), while `strcpy(b, argv[1])` is
    # the argv channel. A `fopen("flag.txt")` is neither -- it is an internal resource, and
    # claiming it as the input channel is the same mistake `how_to_feed` documents on the other
    # side of the pipeline.
    ("file", (r"\bf?open\s*\(\s*argv", r"\bfreopen\s*\(\s*argv",
              r"\bf?open\s*\(\s*[a-z_]*path")),
    ("argv", (r"argv\s*\[\s*1\s*\]", r"argv\[i\]")),
    ("stdin", (r"\bread\s*\(\s*0", r"\bscanf\s*\(", r"\bgets\s*\(",
               r"\bfread\s*\([^)]*stdin", r"\bgetchar\s*\(", r"\bfgets\s*\(")),
)
#: PROMPTED delivery is not "the fixture prints a colon" -- nearly every one does. It is a
#: program that reads its fields one at a time, so the bytes have to be PACED one line per
#: prompt (see fuzz/runner.run_input_prompted, and the HTB target it was measured on). Two or
#: more prompt-and-read pairs is the signature; a single `printf("in: ")` before one read is an
#: ordinary stdin fixture, and treating it as prompted put 19 of the 22 out-of-bounds-write
#: cases in the wrong column the first time this table was printed.
_PROMPT_PAIR = re.compile(r"printf\s*\(\s*\"[^\"]*[:>]\s*\"")

#: What makes the defect visible in that case. `as_source` means the platform compiles its own
#: ASan+UBSan build (and MSan/TSan for the classes that need them); a plain binary gets the
#: guard-page allocator and the signal; a `clean` case has nothing to see.
def oracle_of(case) -> str:
    if getattr(case, "clean", False):
        return "none (precision case)"
    if getattr(case, "as_source", False):
        return "sanitizer build"
    txt = (case.note or "").lower()
    if "msan" in txt or "uninitial" in txt:
        return "msan"
    if "race" in txt or "tsan" in txt:
        return "tsan"
    if "valgrind" in txt or "memcheck" in txt:
        return "valgrind"
    return "signal + guard page"


def substrate_of(case) -> str:
    """A SHORT label, because this is a grid: `q:mips64el` has to fit in a column."""
    ft = (getattr(case, "want_file_type", "") or "").lower()
    if ft and ft != "elf":
        return {"pe": "wine", "jar": "jvm", "class": "jvm", "pyc": "cpython",
                "wasm": "wasm", "dotnet": "clr"}.get(ft, ft[:7])
    cross = (getattr(case, "cross", "") or "")
    if cross:
        return "wine" if "mingw" in cross else "q:" + cross.split("-")[0]
    if getattr(case, "as_source", False):
        return "src"
    if "firmware" in case.name:
        return "fw"
    return "native"


def channel_of(case) -> str:
    src = case.src or ""
    if "multicall" in case.name or "dispatch" in case.name:
        return "door"
    if len(_PROMPT_PAIR.findall(src)) >= 2:
        return "prompt"
    for name, pats in _CHANNEL_SIGNS:
        if any(re.search(p, src) for p in pats):
            return name
    if not src.strip().startswith("#include"):
        return "built"                       # a `build=` case: a .pyc/.NET/jar artifact, no C
    # A fixture that reads NOTHING is not an unknown channel, it is a class whose defect needs no
    # input at all -- `uninit_stack_read` prints a never-initialised local, and calling that
    # "unknown" hid the one honest answer in a list of inference failures.
    return "no-input"


def mechanisms_of(case) -> list:
    cwes = list(case.want_cwe or ())
    for grp in (getattr(case, "want_all_cwe", ()) or ()):
        cwes += list(grp if isinstance(grp, (tuple, list)) else (grp,))
    out = []
    for c in cwes:
        m = _CWE_TO_MECH.get(c)
        if m and m not in out:
            out.append(m)
    if not out:
        # A case that asserts a LEVEL and nothing else carries no CWE arm on purpose, so it says
        # its mechanism outright. Without this the two cases that took heap-overflow from L0 to
        # L3 showed up under "(level only)" and the heap-overflow row still read L0.
        named = str(getattr(case, "mechanism", "") or "")
        if named:
            return [named]
        if getattr(case, "clean", False):
            return ["(precision control)"]
        if getattr(case, "want_file_type", ""):
            return ["(front-end only)"]
        return ["(level only)"]
    return out


_LVL = {"": 0, "L0": 1, "L1": 2, "L2": 3, "L3": 4}
_NAME = {0: "-", 1: "L0", 2: "L1", 3: "L2", 4: "L3"}
#: A conformance table row: `name | OK | profile ... L2* | findings [123s]`.
_MEASURED = re.compile(r"^(\S+)\s+\|\s+(PASS|FAIL|SKIP)\s+\|\s+(.*?)\s+\|")
_LVL_IN_PROFILE = re.compile(r"\bL([0-3])\*?\b")


def read_measured(path: Path) -> dict:
    """{case: level} from a conformance run's own output -- what was REACHED, not demanded."""
    out: dict = {}
    for line in path.read_text(errors="replace").splitlines():
        m = _MEASURED.match(line.strip())
        if not m:
            continue
        lv = _LVL_IN_PROFILE.findall(m.group(3))
        out[m.group(1)] = ("L" + lv[-1]) if lv else ("L0" if m.group(2) == "PASS" else "")
    return out


def rows(measured: dict) -> list:
    out = []
    for case in pc._CASES:
        lvl = f"L{case.want_level}"
        got = measured.get(case.name)
        for mech in mechanisms_of(case):
            out.append({"case": case.name, "mechanism": mech, "channel": channel_of(case),
                        "substrate": substrate_of(case), "oracle": oracle_of(case),
                        "want": lvl, "reached": got or ""})
    # The ISA ladder is its own instrument and its own axis: one mechanism (a stack smash) across
    # fifteen substrates, which is exactly the shape the conformance cases cannot carry.
    for case in archgate.MATRIX:
        out.append({"case": f"archgate:{case.label}", "mechanism": "stack-overflow",
                    "channel": "stdin", "substrate": f"q:{case.label}",
                    "oracle": "signal + guard page", "want": case.expect, "reached": ""})
    return out


def _grid(data, axis, title, measured_mode):
    mechs = sorted({r["mechanism"] for r in data})
    cols = sorted({r[axis] for r in data})
    width = min(max(len(c) for c in cols) + 1, 11)
    head = "mechanism".ljust(26) + "".join(c[:width - 1].ljust(width) for c in cols)
    lines = [title, "-" * len(head), head]
    for m in mechs:
        cells = []
        for c in cols:
            hit = [r for r in data if r["mechanism"] == m and r[axis] == c]
            if not hit:
                cells.append(".".ljust(width))
                continue
            key = "reached" if measured_mode else "want"
            best = max((_LVL.get(r[key] or "", 0) for r in hit), default=0)
            mark = _NAME[best]
            if measured_mode and best == 0:
                mark = "?"                      # a case exists here and was not run
            cells.append(f"{mark}({len(hit)})".ljust(width))
        lines.append(m.ljust(26) + "".join(cells))
    return "\n".join(lines)


def main() -> int:
    # A diagnostic instrument's own diagnostics have to be readable: with nothing configured a
    # `_log.warning` from inside the engine reaches stderr through `logging.lastResort`, with no
    # timestamp, module or line. `LYKOS_LOG` still selects the level, so the default stays quiet.
    observe.configure()
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--measured", type=Path,
                    help="a conformance run's output; overlays the level each case REACHED")
    ap.add_argument("--holes", action="store_true", help="only the empty cells")
    a = ap.parse_args()
    measured = read_measured(a.measured) if a.measured else {}
    data = rows(measured)
    mode = bool(measured)

    if not a.holes:
        print(_grid(data, "substrate", "MECHANISM x SUBSTRATE", mode))
        print()
        print(_grid(data, "channel", "MECHANISM x CHANNEL", mode))
        print()
        print(_grid(data, "oracle", "MECHANISM x ORACLE", mode))
        print()

    # THE HOLES. Not every cell is meaningful -- a path traversal has no business on the firmware
    # rehoster -- so this lists what EXISTS per mechanism and leaves the judgement to a reader
    # who knows which absences are real.
    print("WHAT EACH MECHANISM IS COVERED ON")
    print("-" * 70)
    for m in sorted({r["mechanism"] for r in data}):
        subs = sorted({r["substrate"] for r in data if r["mechanism"] == m})
        chans = sorted({r["channel"] for r in data if r["mechanism"] == m})
        best = max((_LVL.get(r["reached"] if mode else r["want"], 0)
                    for r in data if r["mechanism"] == m), default=0)
        print(f"{m:26s} {_NAME[best]:>3}  substrates={len(subs):2d}  channels={len(chans)}  "
              f"{', '.join(chans)}")
    unknown = sorted({r["case"] for r in data if r["channel"] == "unknown"})
    if unknown:
        print()
        print("CHANNEL NOT INFERABLE FROM THE FIXTURE (inference is from the fixture's own "
              "source):")
        for name in unknown:
            print("  " + name)
    print()
    print(f"{len(pc._CASES)} conformance cases + {len(archgate.MATRIX)} ISA cases -> "
          f"{len(data)} (mechanism, case) pairs"
          + ("" if mode else "; pass --measured to show REACHED levels instead of demanded"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
