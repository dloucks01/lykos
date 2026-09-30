"""Binary function matching, patch-diff and N-day variant hunting -- on lykos's own recovered IR.

Nearly half of in-the-wild zero-days are *variants* of a previously-fixed bug: the same flawed code
copy-pasted into a sibling function, statically linked into another product, or left unpatched in an
older branch. The workflow that finds them is diff-then-hunt:

  1. **diff** a vulnerable binary against its patched build -> the function(s) that changed localize
     the fix, and therefore the bug.
  2. **signature** the pre-patch (vulnerable) function.
  3. **hunt** that signature across a corpus of other binaries -> every binary still carrying a
     matching (unpatched) copy is a candidate N-day, and an *unreported* one is a 0-day.

lykos's ``patchdiff.py`` already diffs two binaries by NAME (with an exact structural-hash fallback
for stripped code) -- it answers "which named function changed between these two builds". This
module adds the two things that turns a diff into a variant HUNT: (1) **fuzzy** similarity, so a
function that was *recompiled or lightly edited* still matches (exact hashes do not), and (2)
``variant_scan`` across a whole CORPUS of binaries, so a vulnerable function's signature can be
chased through every product/version you hold. It reuses the functions/CFG/calls lykos's decompiler
already recovered -- no external BinDiff/BSim, self-contained and offline -- and is deliberately a
*lightweight* matcher (BinDiff-lite) on architecture-neutral features that survive relinking:

  * the **callee set** (which functions/APIs it calls): a strcpy/malloc/parse_header caller is that
    caller whatever its address;
  * the **P-Code mnemonic profile** (opcode histogram): the instruction *mix*, independent of
    registers and addresses, and largely independent of ISA because P-Code is the common IR;
  * a **structural fingerprint** (block count, edge count, cyclomatic complexity).

It will not match aggressively-different optimization levels the way a heavyweight semantic matcher
does -- for that, the roadmap (doc 28) points at Ghidra BSim -- but for the common N-day case (same
source, same/similar toolchain, version N vs N+1, one library linked into many products) it is fast,
deterministic, non-AI and offline.
"""
from __future__ import annotations

import math
from collections import Counter

# Auto-generated / thunk names carry no identity: two different `fcn.00401abc` are not "the same
# function", so name-anchoring must ignore them and fall back to structural matching.
_GENERIC_PREFIXES = ("fcn.", "sub_", "loc.", "unk_", "nullsub", "j_", "sym.imp.", "imp.")


def _norm_name(name) -> str:
    n = (name or "").strip()
    for pre in ("sym.", "sym.imp.", "imp."):
        if n.startswith(pre):
            n = n[len(pre):]
    return n


def _is_generic(name) -> bool:
    n = (name or "").strip()
    return (not n) or n.startswith(_GENERIC_PREFIXES)


def _block_list(*sources):
    """The basic-block LIST from whichever recovered shape we were handed: native_re's function
    dict keeps it under ``cfg.blocks`` (top-level ``blocks`` is a COUNT), while a persisted
    Function.ir keeps ``blocks`` as the list directly. Return the first list found, else []."""
    for src in sources:
        if not isinstance(src, dict):
            continue
        cfg = src.get("cfg")
        if isinstance(cfg, dict) and isinstance(cfg.get("blocks"), list):
            return cfg["blocks"]
        if isinstance(src.get("blocks"), list):
            return src["blocks"]
    return []


def _pcode_ops(blocks):
    for b in blocks or ():
        for i in b.get("instructions", []) or []:
            for pc in i.get("pcode", []) or []:
                op = pc.split(" -> ", 1)[0].split()
                if op:
                    yield op[0]


def function_features(func) -> dict:
    """Architecture-neutral features of one recovered function (see module doc).

    Accepts a Function DAO object or a native_re function dict. Missing fields degrade gracefully
    (a function with no recovered IR still has a name + callee set).
    """
    def _get(k, default=None):
        if isinstance(func, dict):
            return func.get(k, default)
        return getattr(func, k, default)

    ir = _get("ir") if not isinstance(func, dict) else None
    blocks = _block_list(ir, func if isinstance(func, dict) else {})
    nblocks = len(blocks) if blocks else int(_get("blocks", 0) or 0)
    nedges = 0
    for b in blocks:
        nedges += len(b.get("succ") or ())
    if not nedges:
        nedges = int(_get("edges", 0) or 0)
    calls = _get("calls") or []
    callees = sorted({_norm_name(c.get("dst_name")) for c in calls
                      if isinstance(c, dict) and not _is_generic(c.get("dst_name"))})
    mnem = Counter(_pcode_ops(blocks))
    # cyclomatic complexity M = E - N + 2 (single-entry/exit approximation)
    complexity = max(1, nedges - nblocks + 2) if nblocks else 0
    return {
        "name": _norm_name(_get("name")),
        "generic": _is_generic(_get("name")),
        "addr": _get("addr"),
        "blocks": nblocks, "edges": nedges, "complexity": complexity,
        "callees": callees, "mnem": mnem, "size": int(_get("size", 0) or 0),
    }


def _cosine(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    keys = set(a) | set(b)
    dot = sum(a.get(k, 0) * b.get(k, 0) for k in keys)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def _jaccard(a, b) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def _struct_sim(fa, fb) -> float:
    def close(x, y):
        if x == 0 and y == 0:
            return 1.0
        return 1.0 - abs(x - y) / max(x, y, 1)
    return (close(fa["blocks"], fb["blocks"])
            + close(fa["edges"], fb["edges"])
            + close(fa["complexity"], fb["complexity"])) / 3.0


def similarity(fa: dict, fb: dict) -> float:
    """Similarity in [0,1] of two feature dicts: callee-set (0.4) + mnemonic profile (0.4) +
    structure (0.2). Address- and register-independent, so it survives relinking and rebasing."""
    return round(0.4 * _jaccard(fa["callees"], fb["callees"])
                 + 0.4 * _cosine(fa["mnem"], fb["mnem"])
                 + 0.2 * _struct_sim(fa, fb), 4)


def match_functions(funcs_a, funcs_b, *, threshold: float = 0.5) -> dict:
    """Match functions of binary A to binary B. Returns {matched, only_a, only_b}.

    Two phases (BinDiff's approach): first anchor on identical non-generic names (a symbolized
    build vs its patch), then greedily match the remainder by feature similarity above `threshold`.
    Each ``matched`` entry is ``{a, b, name, similarity}`` with the two feature dicts.
    """
    fa = [function_features(f) for f in funcs_a]
    fb = [function_features(f) for f in funcs_b]
    by_name_b = {}
    for f in fb:
        if not f["generic"]:
            by_name_b.setdefault(f["name"], []).append(f)

    matched = []
    used_b = set()

    # phase 1: exact non-generic name anchors
    remaining_a = []
    for a in fa:
        cands = by_name_b.get(a["name"]) if not a["generic"] else None
        pick = None
        if cands:
            pick = max((c for c in cands if id(c) not in used_b),
                       key=lambda c: similarity(a, c), default=None)
        if pick is not None:
            used_b.add(id(pick))
            matched.append({"a": a, "b": pick, "name": a["name"],
                            "similarity": similarity(a, pick)})
        else:
            remaining_a.append(a)

    # phase 2: greedy structural matching of the rest
    free_b = [f for f in fb if id(f) not in used_b]
    pairs = []
    for a in remaining_a:
        for b in free_b:
            s = similarity(a, b)
            if s >= threshold:
                pairs.append((s, a, b))
    pairs.sort(key=lambda p: -p[0])
    matched_a = set()
    for s, a, b in pairs:
        if id(a) in matched_a or id(b) in used_b:
            continue
        matched_a.add(id(a))
        used_b.add(id(b))
        matched.append({"a": a, "b": b, "name": a["name"] or b["name"], "similarity": s})

    only_a = [a for a in fa if id(a) not in {id(m["a"]) for m in matched}]
    only_b = [b for b in fb if id(b) not in used_b]
    return {"matched": matched, "only_a": only_a, "only_b": only_b}


def diff(funcs_vuln, funcs_patched, *, changed_below: float = 0.985) -> dict:
    """Diff a vulnerable binary against its patched build.

    Returns ``{changed, added, removed, identical}``. ``changed`` are matched functions whose
    similarity is below ``changed_below`` -- the patch touched them, so they localize the fix (and
    thus the bug); each is ``{name, similarity, vuln, patched}`` (feature dicts) ordered
    most-changed first. ``added``/``removed`` are functions present in only one side.
    """
    m = match_functions(funcs_vuln, funcs_patched)
    changed, identical = [], []
    for pair in m["matched"]:
        entry = {"name": pair["name"], "similarity": pair["similarity"],
                 "vuln": pair["a"], "patched": pair["b"]}
        (changed if pair["similarity"] < changed_below else identical).append(entry)
    changed.sort(key=lambda c: c["similarity"])
    return {"changed": changed, "identical": identical,
            "removed": m["only_a"], "added": m["only_b"]}


def variant_scan(signature: dict, funcs, *, threshold: float = 0.9) -> list:
    """Find functions in `funcs` that match a vulnerable-function `signature` (a feature dict from
    ``function_features``). Returns ``[{name, addr, similarity}]`` above `threshold`, best first --
    each a candidate UNPATCHED variant of the known bug (a potential N-day / 0-day).
    """
    out = []
    for f in funcs:
        feat = function_features(f)
        s = similarity(signature, feat)
        if s >= threshold:
            out.append({"name": feat["name"], "addr": feat["addr"], "similarity": s})
    out.sort(key=lambda x: -x["similarity"])
    return out
