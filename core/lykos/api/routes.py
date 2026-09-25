"""HTTP route table and static-asset serving for the analyst API.

Split out of `server.py` (which was a single ~1600-line module) so the routing surface and the
traversal-safe static reader live in one small, reviewable place. `server.Handler` imports these;
moving them changes nothing at runtime -- the regexes and readers are pure, `self`-free.
"""
from __future__ import annotations

import re
from pathlib import Path

# Path patterns, each capturing the id(s) in the route. Kept together so the whole routing surface
# is visible in one place.
_RUN_ID = re.compile(r"^/runs/([^/]+)$")
_RUN_CANCEL = re.compile(r"^/runs/([^/]+)/cancel$")
_RUN_OUTPUT = re.compile(r"^/runs/([^/]+)/output$")
_TARGET_INVOKE = re.compile(r"^/targets/([^/]+)/invocation$")
_TARGET_REPLAY = re.compile(r"^/targets/([^/]+)/replay$")
_TARGET_CAPS = re.compile(r"^/targets/([^/]+)/capabilities$")
_CASE_ID = re.compile(r"^/cases/([^/]+)$")
_TARGET_ID = re.compile(r"^/targets/([^/]+)$")
_ARTIFACT = re.compile(r"^/artifacts/([0-9a-fA-F]+)$")
_ARTIFACT_BUNDLE = re.compile(r"^/artifacts/([0-9a-fA-F]+)/bundle$")
_CASE_EVENTS = re.compile(r"^/cases/([^/]+)/events$")
_CASE_TARGETS = re.compile(r"^/cases/([^/]+)/targets$")
_CASE_RUNS = re.compile(r"^/cases/([^/]+)/runs$")
_TARGET_FUNCS = re.compile(r"^/targets/([^/]+)/functions$")
_FUNC_ID = re.compile(r"^/functions/([^/]+)$")
_TARGET_CG = re.compile(r"^/targets/([^/]+)/callgraph$")
_TARGET_STR = re.compile(r"^/targets/([^/]+)/strings$")
_TARGET_FIND = re.compile(r"^/targets/([^/]+)/findings$")
_CASE_FIND = re.compile(r"^/cases/([^/]+)/findings$")
_FIND_ID = re.compile(r"^/findings/([^/]+)$")
_TARGET_DYN = re.compile(r"^/targets/([^/]+)/dynresults$")
_TARGET_POC = re.compile(r"^/targets/([^/]+)/pocs$")
_TARGET_ADVICE = re.compile(r"^/targets/([^/]+)/advice$")
_TARGET_SOURCE = re.compile(r"^/targets/([^/]+)/source$")
_CASE_REPORT = re.compile(r"^/cases/([^/]+)/report$")
_CASE_EXPORT = re.compile(r"^/cases/([^/]+)/export$")
_CASE_SYSMAP = re.compile(r"^/cases/([^/]+)/systemmap$")
_CASE_VERIFS = re.compile(r"^/cases/([^/]+)/verifications$")
_CASE_AUTOPILOT = re.compile(r"^/cases/([^/]+)/autopilot$")
_CASE_AUTOPILOT_CANCEL = re.compile(r"^/cases/([^/]+)/autopilot/cancel$")

# Assets the SPA loads after index.html: the vendored ESM runtime and the app modules. Only these
# subtrees are served, and only plain web asset types -- nothing else under the package is
# reachable, and a name with `..` or a leading slash never resolves.
_STATIC_ASSET = re.compile(
    r"^/((?:app|vendor)/(?!\.\.?(?:/|$))[A-Za-z0-9._-]+(?:/(?!\.\.?(?:/|$))[A-Za-z0-9._-]+)*)$")
_ASSET_TYPES = {
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}


def _read_ui() -> bytes:
    """Load the UI page — works from a filesystem checkout AND from a zipapp (.pyz)."""
    return _read_static("index.html")


def _read_static(relpath: str) -> bytes:
    """Read one file under lykos/api/static — from a checkout AND from a zipapp (.pyz).

    `relpath` is already validated by the route regex: no `..`, no leading slash, no
    backslash. It is joined component-by-component so a traversal can never form even if the
    regex is later loosened.
    """
    parts = [p for p in relpath.split("/") if p and p != "."]
    if any(p == ".." for p in parts):
        raise FileNotFoundError(relpath)
    try:
        from importlib import resources
        node = resources.files("lykos.api") / "static"
        for p in parts:
            node = node / p
        return node.read_bytes()
    except FileNotFoundError:
        raise
    except Exception:
        base = (Path(__file__).parent / "static").resolve()
        target = base.joinpath(*parts).resolve()
        if base != target and base not in target.parents:
            raise FileNotFoundError(relpath)
        return target.read_bytes()
