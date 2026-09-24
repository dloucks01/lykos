"""Binary patch-diff (1-day analysis).

Compare two versions of a binary at the FUNCTION level to localise a security fix -- the function
whose body changed between the vulnerable and the patched build IS the patch -- and to answer the
operator's real question in firmware work: does this target already carry the fix, or is it still
exposed? Fully deterministic: functions are matched by name when symbols survive (common for
libraries and many firmware images), else by a structural fingerprint, and a matched pair whose
fingerprint differs is a changed function. The fingerprint is layout/address independent -- CFG
shape (block + edge counts) plus the instruction-mnemonic histogram -- so recompilation noise
(different addresses, register allocation) does not read as a change, but a real edit does.
"""
from __future__ import annotations

import hashlib
from collections import Counter


def _mnem(text) -> str:
    t = (text or "").strip()
    if not t:
        return ""
    return t.replace("\t", " ").split(" ", 1)[0]


def function_fingerprint(fn: dict) -> dict:
    """A structural, address-independent fingerprint of one function (from native_re.analyze)."""
    cfg = fn.get("cfg") or {}
    blocks = cfg.get("blocks") or []
    hist: Counter = Counter()
    ninsn = 0
    for b in blocks:
        for ins in (b.get("instructions") or []):
            m = _mnem(ins.get("text") or ins.get("disasm"))
            if m:
                hist[m] += 1
                ninsn += 1
    edges = cfg.get("edges") or fn.get("edges") or 0
    callees = tuple(sorted({(c.get("dst_name") or c.get("name") or "")
                            for c in (fn.get("calls") or [])
                            if (c.get("dst_name") or c.get("name"))}))
    h = hashlib.sha1()
    h.update(f"{len(blocks)}|{edges}|".encode())
    for k, v in sorted(hist.items()):
        h.update(f"{k}:{v};".encode())
    return {"name": fn.get("name"), "addr": fn.get("addr"), "blocks": len(blocks),
            "edges": edges, "ninsn": ninsn, "callees": callees, "hash": h.hexdigest()}


def _real_name(n) -> bool:
    """A stable cross-build key: a real symbol, not a disassembler-invented placeholder."""
    n = n or ""
    return bool(n) and not any(n.startswith(p) for p in
                               ("fcn.", "sub_", "sub.", "loc.", "unk", "func_", "j_"))


def diff(funcs_a: list, funcs_b: list) -> dict:
    """Diff two function lists (native_re.analyze()['functions']). `a` is the OLD/vulnerable build,
    `b` the NEW/patched one. Returns changed / added / removed / unchanged-count. The `changed` list
    -- functions present in both under the same name but with a different body -- is where a security
    patch lives, ranked by how much the body moved."""
    A = [function_fingerprint(f) for f in (funcs_a or [])]
    B = [function_fingerprint(f) for f in (funcs_b or [])]
    an = {f["name"]: f for f in A if _real_name(f["name"])}
    bn = {f["name"]: f for f in B if _real_name(f["name"])}
    changed, unchanged = [], 0
    for name, fa in an.items():
        fb = bn.get(name)
        if fb is None:
            continue
        if fa["hash"] == fb["hash"]:
            unchanged += 1
        else:
            moved = abs(fa["ninsn"] - fb["ninsn"]) + abs(fa["blocks"] - fb["blocks"]) \
                + len(set(fa["callees"]) ^ set(fb["callees"]))
            changed.append({
                "name": name, "old_addr": fa["addr"], "new_addr": fb["addr"],
                "blocks": [fa["blocks"], fb["blocks"]], "insns": [fa["ninsn"], fb["ninsn"]],
                "new_callees": sorted(set(fb["callees"]) - set(fa["callees"])),
                "dropped_callees": sorted(set(fa["callees"]) - set(fb["callees"])),
                "moved": moved})
    changed.sort(key=lambda c: -c["moved"])
    # named functions that appear or disappear entirely
    added = sorted(set(bn) - set(an))
    removed = sorted(set(an) - set(bn))
    # stripped fallback: match the unnamed by structural hash; the rest are add/remove inventory
    a_hashes = Counter(f["hash"] for f in A if not _real_name(f["name"]))
    b_hashes = Counter(f["hash"] for f in B if not _real_name(f["name"]))
    stripped_added = sum((b_hashes - a_hashes).values())
    stripped_removed = sum((a_hashes - b_hashes).values())
    return {"changed": changed, "added": added, "removed": removed, "unchanged": unchanged,
            "n_old": len(A), "n_new": len(B),
            "stripped_added": stripped_added, "stripped_removed": stripped_removed,
            "symbols": bool(an or bn)}


def is_patched(target_funcs: list, vulnerable_fn: dict, patched_fn: dict):
    """1-day check: does the target's copy of a function match the PATCHED shape or the VULNERABLE
    one? Returns 'patched', 'vulnerable', or None (function not found / inconclusive). `vulnerable_fn`
    and `patched_fn` are fingerprints (or functions) of the same function from the two reference
    builds. Matched by name, then by structural hash."""
    vf = vulnerable_fn if "hash" in vulnerable_fn else function_fingerprint(vulnerable_fn)
    pf = patched_fn if "hash" in patched_fn else function_fingerprint(patched_fn)
    name = pf.get("name") or vf.get("name")
    cand = None
    if _real_name(name):
        cand = next((function_fingerprint(f) for f in target_funcs
                     if f.get("name") == name), None)
    if cand is None:
        return None
    if cand["hash"] == pf["hash"]:
        return "patched"
    if cand["hash"] == vf["hash"]:
        return "vulnerable"
    return None
