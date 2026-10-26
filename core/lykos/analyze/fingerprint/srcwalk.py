"""The one walk over an unpacked source tree that the line-oriented source scanners share
(int_overflow, source_sinks, uaf). Each used to carry its own copy, and all three had the same
two defects:

  * the skip rule (tests/, vendor/, examples/ ...) was tested against the ABSOLUTE path, so a
    case store that happened to live under a directory named `test`, `demo` or `vendor` skipped
    every file and the scanner reported a clean tree;
  * findings were keyed and described by the file's basename, so `a/util.c:12` and
    `b/util.c:12` merged into one finding -- one defect hidden, and the evidence could not say
    which file it meant.

The label is the basename when it is unique in the tree (so existing findings keep their keys
and a re-scan does not duplicate them) and the tree-relative path when it is not.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

MAX_FILES = 6000
MAX_FILE = 4 << 20
SRC_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")
SKIP_SEGMENTS = frozenset({"examples", "example", "demo", "demos", "test", "tests",
                           "third_party", "3rdparty", "vendor", "node_modules"})


def source_files(root, *, suffixes=SRC_SUFFIXES, max_files: int = MAX_FILES,
                 max_file: int = MAX_FILE):
    """Yield (label, path, text) for each scannable source file under `root`, in sorted order."""
    root = Path(root)
    picked = []
    for p in sorted(root.rglob("*")):
        if len(picked) >= max_files:
            break
        if not p.is_file() or p.suffix.lower() not in suffixes:
            continue
        rel = p.relative_to(root)
        if SKIP_SEGMENTS & {seg.lower() for seg in rel.parts}:
            continue
        try:
            if p.stat().st_size > max_file:
                continue
        except OSError:
            continue
        picked.append((p, rel))
    counts = Counter(p.name for p, _ in picked)
    for p, rel in picked:
        try:
            text = p.read_text("utf-8", "replace")
        except OSError:
            continue
        yield (p.name if counts[p.name] == 1 else rel.as_posix()), p, text
