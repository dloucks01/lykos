"""Seed inputs mined from a source project's own tests, samples and fuzz corpora.

A structured-input parser is fuzzed well only from inputs that already parse: a blind mutator does
not invent a valid Markdown table, an EXIF block or a TIFF directory inside a short budget. Most
projects SHIP such inputs -- md4c has `test/fuzz-input/`, libtiff `test/images/`, expat
`tests/xmlconf/` -- and lykos ignored them: the md4c demo only had seeds because the operator
passed them by hand. This collects them, bounded, from the directories projects keep them in.

What is deliberately NOT taken: files named as known crashers or regressions (`crash-*`, `poc*`,
`*cve*`, `oom-*`, `timeout-*`, `*fail*`). Those are the project's record of bugs it already fixed;
seeding with them would rediscover a known crash and make a run look like a find it did not make.
"""
from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path

#: Directory names a project keeps example/test inputs in (any path segment, case-insensitive).
_SEED_DIRS = re.compile(r"^(tests?|testdata|test[-_]data|test[-_]?files|fuzz(ing)?|fuzz[-_]input|"
                        r"corpus|corpora|seeds?|samples?|examples?|data|fixtures|inputs?|images|"
                        r"testsuite|conformance|cases)$", re.I)
#: Not inputs: source, build and documentation files.
_NOT_INPUT = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".py", ".pyc", ".sh", ".bat",
              ".cmake", ".in", ".am", ".ac", ".m4", ".mk", ".o", ".a", ".so", ".dll", ".exe",
              ".pl", ".rb", ".js", ".java", ".class", ".go", ".rs", ".swift", ".cs", ".patch",
              ".diff", ".orig", ".rej", ".yml", ".yaml", ".toml", ".gitignore", ".gitattributes",
              ".1", ".3", ".man", ".pod", ".spec", ".pc", ".def", ".sln", ".vcxproj", ".pro"}
_NOT_INPUT_NAMES = {"makefile", "cmakelists.txt", "readme", "readme.md", "license", "license.md",
                    "copying", "changelog", "changelog.md", "authors", "news", "install",
                    "todo", "meson.build", "configure", "dockerfile"}
#: The project's record of bugs it already found -- never a seed (see the module docstring).
_KNOWN_BAD = re.compile(r"(crash|poc|cve|oom-|timeout-|leak-|fail|regress|asan|ubsan|msan|"
                        r"bug\d|issue\d|ossfuzz|clusterfuzz)", re.I)
_SKIP = (".git", "_lykos_build", "node_modules", "build", "cmake-build")

MAX_SEEDS = 48
MAX_BYTES = 64 * 1024


def candidates(root) -> list[Path]:
    """Files under the tree's test/sample/corpus directories that look like INPUTS, smallest
    first, deduplicated by content, at most MAX_SEEDS."""
    root = Path(root)
    found: list[tuple[int, Path]] = []
    seen: set = set()
    for p in sorted(root.rglob("*")):
        try:
            if not p.is_file():
                continue
            rel = p.relative_to(root).parts
        except (OSError, ValueError):
            continue
        if any(seg in _SKIP or seg.startswith(".") for seg in rel[:-1]):
            continue
        if not any(_SEED_DIRS.match(seg) for seg in rel[:-1]):
            continue
        name = p.name.lower()
        if p.suffix.lower() in _NOT_INPUT or name in _NOT_INPUT_NAMES or name.startswith("."):
            continue
        if _KNOWN_BAD.search(name) or any(_KNOWN_BAD.search(seg) for seg in rel[:-1]):
            continue
        try:
            size = p.stat().st_size
            if not 0 < size <= MAX_BYTES:
                continue
            data = p.read_bytes()
            if data[:2] == b"#!":
                continue                                 # a script, not an input
            digest = hashlib.sha1(data).hexdigest()
        except OSError:
            continue
        if digest in seen:
            continue
        seen.add(digest)
        found.append((size, p))
    found.sort(key=lambda t: (t[0], str(t[1])))
    # Smallest first, but spread across file types: 48 tiny .txt files would starve the one .md
    # or .jpg the parser actually reads.
    by_ext: dict = {}
    for size, p in found:
        by_ext.setdefault(p.suffix.lower(), []).append(p)
    out: list[Path] = []
    while len(out) < MAX_SEEDS and any(by_ext.values()):
        for ext in sorted(by_ext):
            if by_ext[ext] and len(out) < MAX_SEEDS:
                out.append(by_ext[ext].pop(0))
    return out


def mine(root, out_dir) -> list[str]:
    """Copy the mined seeds into `out_dir` (they must outlive the materialised tree) and return
    their paths. Empty when the tree ships nothing usable."""
    picks = candidates(root)
    if not picks:
        return []
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for i, p in enumerate(picks):
        dst = out_dir / f"{i:02d}-{p.name}"[:96]
        try:
            shutil.copyfile(p, dst)
            paths.append(str(dst))
        except OSError:
            continue
    return paths
