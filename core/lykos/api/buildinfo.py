"""Which build of lykos is serving this GUI -- so a stale air-gap disc is noticeable.

An operator on an offline laptop runs whatever was burned to the disc. When a fix lands after
that, nothing on screen said the build predates it: the GUI looked the same either way. This
answers "what am I running" from the best evidence available, in order:

  1. a BUILD STAMP written at packaging time -- `BUILD_INFO.json` at the repo root or inside the
     package (`{"commit": ..., "built": ..., "label": ...}`); the runnable bundle is a
     `git archive` with no `.git`, so a stamp is the only commit record it can carry;
  2. the git checkout itself (`.git`), read directly -- no subprocess is needed for HEAD;
  3. failing both, the newest source-file modification time, which still dates the code.

The toolchain bundle's own manifest date (`vendor/manifest/BUNDLE.txt`, "built:") is added when
present: the engines can be older than the code. Cheap, read-only, cached for a minute.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_TTL = 60.0
_cache: dict = {"at": 0.0, "info": None}


def _pkg_dir() -> Path:
    return Path(__file__).resolve().parents[1]                  # core/lykos


def _repo_root() -> Optional[Path]:
    root = Path(__file__).resolve().parents[3]
    return root if (root / "core" / "lykos").is_dir() else None


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_stamp() -> Optional[dict]:
    cands = [_pkg_dir() / "BUILD_INFO.json"]
    root = _repo_root()
    if root:
        cands.insert(0, root / "BUILD_INFO.json")
    for p in cands:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(d, dict):
            return {k: (str(v)[:200] if v is not None else None) for k, v in d.items()
                    if k in ("commit", "built", "label", "branch", "dirty")}
    return None


def _git_head(root: Path) -> Optional[dict]:
    git = root / ".git"
    if git.is_file():                                   # a worktree: "gitdir: <path>"
        try:
            ref = git.read_text().strip()
            if ref.startswith("gitdir:"):
                git = (root / ref.split(":", 1)[1].strip()).resolve()
        except OSError:
            return None
    if not git.is_dir():
        return None
    try:
        head = (git / "HEAD").read_text().strip()
    except OSError:
        return None
    branch = None
    sha = head
    if head.startswith("ref:"):
        ref = head.split(":", 1)[1].strip()
        branch = ref.rsplit("/", 1)[-1]
        common = git
        cd = git / "commondir"                           # linked worktree -> the shared refs
        if cd.is_file():
            try:
                common = (git / cd.read_text().strip()).resolve()
            except OSError:
                pass
        sha = None
        for base in (git, common):
            try:
                sha = (base / ref).read_text().strip()
                break
            except OSError:
                continue
        if sha is None:
            try:
                for line in (common / "packed-refs").read_text().splitlines():
                    if line.endswith(" " + ref):
                        sha = line.split(" ", 1)[0]
                        break
            except OSError:
                pass
    if not sha or len(sha) < 7:
        return None
    out = {"commit": sha[:40], "branch": branch}
    # The commit's own date, from its loose object (a packed one is left undated -- unpacking a
    # packfile is not worth it for a footer; the code mtime still dates the build).
    try:
        import zlib
        objs = git / "objects"
        cd = git / "commondir"
        if cd.is_file():
            objs = (git / cd.read_text().strip()).resolve() / "objects"
        raw = zlib.decompress((objs / sha[:2] / sha[2:40]).read_bytes())
        for line in raw.split(b"\n"):
            if line.startswith(b"committer "):
                out["built"] = _iso(float(line.rsplit(b" ", 2)[1]))
                break
            if not line.strip():                         # end of the commit header
                break
    except Exception:                                    # noqa: BLE001 -- undated is fine
        pass
    return out


def _code_mtime() -> Optional[str]:
    newest = 0.0
    for dirpath, _dirs, files in os.walk(_pkg_dir()):
        if "__pycache__" in dirpath:
            continue
        for f in files:
            if f.endswith((".py", ".js", ".html")):
                try:
                    newest = max(newest, os.stat(os.path.join(dirpath, f)).st_mtime)
                except OSError:
                    continue
    return _iso(newest) if newest else None


def _toolchain_built() -> Optional[str]:
    try:
        from .. import vendorenv
        vd = vendorenv.vendor_dir()
    except Exception:                                    # noqa: BLE001 -- best-effort only
        return None
    if not vd:
        return None
    for p in (vd / "manifest" / "BUNDLE.txt", vd / "toolchain" / "manifest" / "BUNDLE.txt"):
        try:
            for line in p.read_text(errors="replace").splitlines():
                if line.lower().startswith("built:"):
                    return line.split(":", 1)[1].strip()[:64]
        except OSError:
            continue
    return None


def build_info(*, fresh: bool = False) -> dict[str, Any]:
    now = time.time()
    if not fresh and _cache["info"] is not None and now - _cache["at"] < _TTL:
        return _cache["info"]
    from .. import __version__
    info: dict[str, Any] = {"version": __version__, "source": "none", "commit": None,
                            "branch": None, "built": None, "label": None}
    stamp = _read_stamp()
    if stamp:
        info.update({k: v for k, v in stamp.items() if v})
        info["source"] = "stamp"
    else:
        root = _repo_root()
        g = _git_head(root) if root else None
        if g:
            info.update(g)
            info["source"] = "git"
    info["code_mtime"] = _code_mtime()
    info["toolchain_built"] = _toolchain_built()
    short = (info.get("commit") or "")[:7]
    info["short"] = short or None
    info["display"] = (f"lykos {info['version']}"
                       + (f" · {short}" if short else "")
                       + (f" ({info['label']})" if info.get("label") else "")
                       + (f" · code {info['code_mtime'][:10]}" if info.get("code_mtime") else ""))
    _cache.update(at=now, info=info)
    return info
