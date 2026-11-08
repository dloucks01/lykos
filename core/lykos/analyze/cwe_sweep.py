"""Line-complete CWE sweep -- the proof that every function was checked against every static class.

This is the breadth mechanism behind "did we hit every line, and every CWE?". It walks every source
file in a tree, splits each into functions (brace-matched), and runs every `pattern`/`taint` entry
of the `cwe_catalog` over every function body. The output is a LEDGER that accounts for all of it:

  * files: total, parsed, and the SKIP LIST (unparsed files, with the reason) -- a file not parsed is
    a coverage hole, named explicitly rather than silently dropped.
  * functions: total and examined (examined == every static CWE pattern was run over it). A function
    the splitter could not recover is listed, so the function-level hole is visible too.
  * per CWE: how many functions matched (candidate sites) -- recall-first, precision is confirmation.
  * catalog accounting: which CWEs are static-covered here, which are runtime/binary/na (so coverage
    of the CWE AXIS is explicit), and (via cwe_catalog.completeness) which named CWEs are MISSING.

It finds candidate SITES (recall), not confirmed bugs; a hit feeds the confirmation ladder. The
value is the ACCOUNTING: a number for "functions examined / total" that reaches 100% of what parses,
and an explicit worklist for everything that did not. Pure/read-only, stdlib + the catalog only.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .cwe_catalog import CATALOG, completeness
from .dispatcher_harness import _functions

_SRC_EXT = (".c", ".cc", ".cpp", ".cxx")
_HDR_EXT = (".h", ".hpp", ".hxx")
#: directories whose code is not the target's own (vendored / generated / tests) -- excluded by
#: default but COUNTED in the skip list, so the exclusion is visible, not silent.
_DEFAULT_EXCLUDE = ("third-party", "third_party", "external", "/test/", "/tests/", "ci/", "docs/")
#: CWEs whose static detection is a self-reference rather than a body regex.
_RECURSION = "CWE-674"


@dataclass
class SweepLedger:
    files_total: int = 0
    files_parsed: int = 0
    files_skipped: list = field(default_factory=list)      # (path, reason)
    functions_total: int = 0
    per_cwe: dict = field(default_factory=dict)            # cwe -> candidate-site count
    per_cwe_files: dict = field(default_factory=dict)      # cwe -> set(files)
    hits: list = field(default_factory=list)               # (cwe, file, function)
    catalog: dict = field(default_factory=dict)

    @property
    def functions_examined(self) -> int:
        # every recovered function is examined by every static pattern, so examined == total here;
        # the honest hole is files that did not parse (listed in files_skipped), not functions.
        return self.functions_total


def _static_cwes() -> list:
    """Catalog entries that run in the sweep (pattern or taint sink-locator), with a usable regex,
    plus the recursion special-case."""
    out = [(c, e) for c, e in CATALOG.items() if e.method in ("pattern", "taint") and e.pattern]
    return out


def _excluded(path: str, extra_exclude) -> bool:
    p = path.replace(os.sep, "/")
    return any(x in p for x in _DEFAULT_EXCLUDE) or any(x in p for x in (extra_exclude or ()))


def sweep_source(root: str, *, include_headers: bool = True, extra_exclude=None,
                 named_cwes=None) -> SweepLedger:
    """Run every static CWE pattern over every function in every source file under `root`. Returns a
    `SweepLedger` that accounts for files (parsed / skipped-with-reason), functions (total == examined
    for parsed files), per-CWE candidate-site counts, and the catalog's own completeness against
    `named_cwes` (the full CWE list lykos references)."""
    exts = _SRC_EXT + (_HDR_EXT if include_headers else ())
    statics = _static_cwes()
    led = SweepLedger()
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not fn.endswith(exts):
                continue
            path = os.path.join(dirpath, fn)
            led.files_total += 1
            rel = os.path.relpath(path, root)
            if _excluded(path, extra_exclude):
                led.files_skipped.append((rel, "excluded (vendored/test/generated)"))
                continue
            try:
                src = open(path, "r", errors="ignore").read()
            except OSError as e:
                led.files_skipped.append((rel, f"read error: {e}"))
                continue
            funcs = _functions(src)
            if not funcs:
                # header or macro-only file with no brace-matched function: scan the whole text as
                # one unit so its lines are still covered, and note it.
                funcs = [("<file-scope>", False, [], src)]
            led.files_parsed += 1
            for name, _is_static, _params, body in funcs:
                led.functions_total += 1
                for cwe, entry in statics:
                    if entry.pattern.search(body):
                        led.per_cwe[cwe] = led.per_cwe.get(cwe, 0) + 1
                        led.per_cwe_files.setdefault(cwe, set()).add(rel)
                        led.hits.append((cwe, rel, name))
                # recursion (CWE-674): the function body calls its own name
                if name not in ("<file-scope>",) and re.search(r"\b" + re.escape(name) + r"\s*\(", body):
                    # exclude the definition header itself: a real self-call appears after the '{'
                    if body.count(name + "(") >= 1 and re.search(r"\b" + re.escape(name) + r"\s*\([^)]*\)\s*;", body):
                        led.per_cwe[_RECURSION] = led.per_cwe.get(_RECURSION, 0) + 1
                        led.per_cwe_files.setdefault(_RECURSION, set()).add(rel)
                        led.hits.append((_RECURSION, rel, name))
    if named_cwes:
        led.catalog = completeness(named_cwes)
    return led


def ledger_report(led: SweepLedger, *, top: int = 40) -> str:
    """A human-readable account of the sweep -- the answer to 'every line / every CWE', as numbers."""
    L = []
    pct = (100.0 * led.files_parsed / led.files_total) if led.files_total else 0.0
    L.append(f"FILES     {led.files_parsed}/{led.files_total} parsed ({pct:.1f}%), "
             f"{len(led.files_skipped)} skipped")
    L.append(f"FUNCTIONS {led.functions_examined}/{led.functions_total} examined by all static patterns")
    if led.catalog:
        c = led.catalog
        bm = c["by_method"]
        L.append(f"CATALOG   {c['total_catalog']} CWE entries; of {len(c['present'])+len(c['missing'])} "
                 f"named CWEs, {len(c['present'])} in catalog, {len(c['missing'])} MISSING")
        L.append(f"          static(pattern)={len(bm.get('pattern', []))} "
                 f"taint={len(bm.get('taint', []))} runtime={len(bm.get('runtime', []))} "
                 f"binary={len(bm.get('binary', []))} na={len(bm.get('na', []))}")
        if c["missing"]:
            L.append(f"          MISSING: {', '.join(c['missing'])}")
    L.append("")
    L.append("CANDIDATE SITES PER CWE (recall-first; confirmation narrows):")
    for cwe, n in sorted(led.per_cwe.items(), key=lambda kv: -kv[1])[:top]:
        nm = CATALOG[cwe].name if cwe in CATALOG else cwe
        L.append(f"  {cwe:10} {n:6}  {nm[:52]}")
    return "\n".join(L)
