"""Read files out of a target's uploaded SOURCE TREE, for the GUI's source view.

A source upload is kept as one gzipped tar artifact (`source-project`). The finding views need a
few lines around `clear.c:214`, and the code view needs the file list -- neither should untar 45 MB
per request. The tree is extracted ONCE per artifact into the case directory (the same
`mined-seeds/<sha12>/tree` the seed miner already extracts, when present) with tar's "data"
filter, so a member can never land outside it.

Paths in and out are TREE-RELATIVE (`libfreerdp/codec/clear.c`): the browser never sees or sends a
server path. A bare basename (`dc.c` -- what most finding titles carry) is resolved through a
basename index; an ambiguous one returns the candidates instead of guessing.
"""
from __future__ import annotations

import io
import os
import tarfile
import threading
from pathlib import Path
from typing import Optional

_SRC_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".inl", ".m", ".mm", ".rs",
            ".go", ".py", ".java", ".js", ".ts", ".s", ".S", ".asm", ".y", ".l", ".cmake", ".txt",
            ".in", ".ac", ".am", ".mk", ".sh", ".json", ".xml", ".yml", ".yaml", ".md")
_SKIP_DIRS = {".git", ".svn", "_lykos_cmake_sh_asan", "_lykos_cmake_sh_clean",
              "_lykos_cmake_st_asan", "_lykos_cmake_st_clean", "_qlbuild", "node_modules"}
MAX_FILES = 20000
MAX_WINDOW = 400
_lock = threading.Lock()
_index: dict = {}          # tree root -> (files list, basename -> [rel])


def project_for(store, target):
    from ..analyze.source_lookup import source_project_for
    return source_project_for(store.conn, target)


def tree_root(store, target) -> Optional[Path]:
    """The extracted tree for `target`'s source project, extracting it on first use."""
    art = project_for(store, target)
    if art is None:
        return None
    base = Path(store.dir)
    mined = base / "mined-seeds" / art.sha256[:12] / "tree"
    if mined.is_dir() and any(mined.iterdir()):
        return mined
    root = base / "src-cache" / art.sha256[:12]
    marker = root / ".lykos-extracted"
    with _lock:
        if marker.is_file():
            return root
        root.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(store.content.get_bytes(art.sha256)), mode="r:gz") as tf:
            tf.extractall(root, filter="data")
        marker.write_text("1")
    return root


def _build_index(root: Path):
    with _lock:
        hit = _index.get(str(root))
        if hit is not None:
            return hit
    files: list = []
    by_base: dict = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in _SKIP_DIRS and not d.startswith("."))
        for fn in sorted(fns):
            if not fn.endswith(_SRC_EXT) and fn not in ("CMakeLists.txt", "Makefile", "configure"):
                continue
            rel = os.path.relpath(os.path.join(dp, fn), root)
            files.append(rel)
            by_base.setdefault(fn, []).append(rel)
            if len(files) >= MAX_FILES:
                break
        if len(files) >= MAX_FILES:
            break
    out = (files, by_base)
    with _lock:
        _index[str(root)] = out
    return out


def list_files(root: Path) -> dict:
    files, _ = _build_index(root)
    return {"files": files, "truncated": len(files) >= MAX_FILES}


def resolve(root: Path, path: str) -> tuple:
    """(rel, candidates): the tree-relative file `path` names, or the candidates when only an
    ambiguous basename matches. `path` may be tree-relative, carry a build-dir prefix
    (`/tmp/x/bundle/freerdp-3.20.0/libfreerdp/...`), or be a bare basename."""
    p = (path or "").strip().replace("\\", "/").lstrip("/")
    if not p or "\0" in p:
        return None, []
    files, by_base = _build_index(root)
    fileset = set(files)
    if p in fileset:
        return p, []
    # the longest tree-relative suffix of a longer path (build-dir prefixes, absolute paths)
    parts = p.split("/")
    for i in range(1, len(parts)):
        suf = "/".join(parts[i:])
        if suf in fileset:
            return suf, []
    cands = by_base.get(parts[-1], [])
    if len(cands) == 1:
        return cands[0], []
    return None, cands[:50]


def read_window(root: Path, rel: str, line: Optional[int], context: int = 12) -> dict:
    """Lines around `line` (1-based) of the tree file `rel`, or the file's head when no line."""
    full = (root / rel).resolve()
    if root.resolve() not in full.parents or not full.is_file():
        return {"error": "not in the source tree"}
    text = full.read_bytes()[:4_000_000].decode("utf-8", "replace").splitlines()
    total = len(text)
    context = max(0, min(int(context), MAX_WINDOW))
    if line and 1 <= line <= total:
        start = max(1, line - context)
        end = min(total, line + context)
    else:
        start, end = 1, min(total, 2 * context + 1 if context else MAX_WINDOW)
    return {"path": rel, "line": line, "start": start, "total": total,
            "lines": text[start - 1:end]}
