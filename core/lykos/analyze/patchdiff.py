"""Binary patch-diff (1-day analysis).

Compare two versions of a binary at the FUNCTION level to localise a security fix -- the function
whose body changed between the vulnerable and the patched build IS the patch -- and to answer the
operator's real question in firmware work: does this target already carry the fix, or is it still
exposed? Fully deterministic: functions are matched by name when symbols survive (common for
libraries and many firmware images), else by a structural fingerprint, and a matched pair whose
fingerprint differs is a changed function. The fingerprint is layout/address independent -- CFG
shape (block + edge counts), the instruction-mnemonic histogram, the callee set and the SMALL
non-address immediates -- so recompilation noise (different addresses, register allocation) does
not read as a change, but a real edit (including an immediate-only bounds fix) does.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter


def _mnem(text) -> str:
    t = (text or "").strip()
    if not t:
        return ""
    return t.replace("\t", " ").split(" ", 1)[0]


# ---- operand constants ------------------------------------------------------------------------
# The mnemonic histogram is blind to an IMMEDIATE-only patch -- the classic bounds fix
# `cmp eax, 0x40` -> `cmp eax, 0x20` keeps every mnemonic -- so the patched function hashed
# "unchanged" and the one function the diff exists to localise vanished. We therefore also hash the
# multiset of SMALL immediate operands, while keeping the fingerprint layout-independent: everything
# that can encode an ADDRESS is excluded, so relinking/rebasing still does not read as a change:
#   * branch/call targets (the callee set already covers calls);
#   * memory operands -- `[rip + 0x2edf]`, `[rbp - 0x40]`, `0x10(sp)` (displacements move with
#     layout and frame allocation);
#   * address-forming instructions (adrp/auipc/lui/addis/sethi/movw/movt...) AND the instruction
#     that completes the pair (`add x0, x0, #0x8c8` after an adrp is an address's low bits);
#   * any immediate >= 0x10000 (an absolute address in a non-PIE image, a pointer, a hash seed).
# What survives is the stuff security patches edit: bounds, sizes, shift counts, flag masks.
_BRANCH = re.compile(
    r"^(j[a-z]*|call[a-z]*|loop[a-z]*|b|bl|blx|bx|blr|br|bal|bc[a-z]*|bctr[a-z]*|cbn?z|tbn?z"
    r"|b\.?(eq|ne|cs|cc|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al|eqz|nez|gez|ltz|lez|gtz|ltu|geu|a)"
    r"(\.[wn])?|b(eq|ne|lt|ge|gt|le)[a-z]*)$")
_ADDR_FORMING = frozenset({"adrp", "adr", "auipc", "lui", "addis", "lis", "sethi", "movw", "movt",
                           "la", "dla"})
_MEM = re.compile(r"\[[^\]]*\]|\S*\([^)]*\)")            # [..] and disp(reg) memory operands
_NUM = re.compile(r"(?<![\w.$])[#$]?(-?)(0x[0-9a-f]+|\d+)(?![\w.])", re.I)
_SMALL = 0x10000


def _consts(blocks) -> Counter:
    """The multiset of small, non-address immediate operands in a function body (see above)."""
    out: Counter = Counter()
    for b in blocks:
        after_addr = False
        for ins in (b.get("instructions") or []):
            text = (ins.get("text") or ins.get("disasm") or "").replace("\t", " ").strip()
            if not text:
                continue
            mnem, _, ops = text.partition(" ")
            ops = ops.split(";", 1)[0]                     # drop a disassembler comment
            m = mnem.lower()
            if after_addr or m in _ADDR_FORMING or _BRANCH.match(m):
                after_addr = m in _ADDR_FORMING
                continue
            after_addr = False
            for sign, num in _NUM.findall(_MEM.sub(" ", ops)):
                try:
                    v = int(num, 16) if num.lower().startswith("0x") else int(num)
                except ValueError:
                    continue
                if v >= _SMALL:
                    continue                            # address-like: layout, not semantics
                out[f"{m}:{'-' if sign else ''}{v:#x}"] += 1
    return out


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
    consts = _consts(blocks)
    h = hashlib.sha1()
    h.update(f"{len(blocks)}|{edges}|".encode())
    for k, v in sorted(hist.items()):
        h.update(f"{k}:{v};".encode())
    # immediate operands (layout-independent subset) -- catches a `cmp 64->32` bounds fix
    h.update(("|consts:" + ";".join(f"{k}={v}" for k, v in sorted(consts.items()))).encode())
    # Fold the CALLEE SET into the hash (it was computed but ignored): a security patch that swaps a
    # call target -- strcpy -> a bounded wrapper, memcpy -> a checked copy -- leaves the `call`
    # mnemonic unchanged, so without this the patched function hashed identical and read "unchanged",
    # hiding exactly the function the diff exists to localize.
    h.update(("|callees:" + ",".join(callees)).encode())
    return {"name": fn.get("name"), "addr": fn.get("addr"), "blocks": len(blocks),
            "edges": edges, "ninsn": ninsn, "callees": callees, "consts": dict(consts),
            "hash": h.hexdigest()}


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
            ca, cb = Counter(fa.get("consts") or {}), Counter(fb.get("consts") or {})
            new_c, old_c = cb - ca, ca - cb
            moved = abs(fa["ninsn"] - fb["ninsn"]) + abs(fa["blocks"] - fb["blocks"]) \
                + len(set(fa["callees"]) ^ set(fb["callees"])) \
                + sum(new_c.values()) + sum(old_c.values())
            changed.append({
                "name": name, "old_addr": fa["addr"], "new_addr": fb["addr"],
                "blocks": [fa["blocks"], fb["blocks"]], "insns": [fa["ninsn"], fb["ninsn"]],
                "new_callees": sorted(set(fb["callees"]) - set(fa["callees"])),
                "dropped_callees": sorted(set(fa["callees"]) - set(fb["callees"])),
                # immediate operands that appeared / disappeared ("cmp:0x20" / "cmp:0x40")
                "new_consts": sorted(new_c), "dropped_consts": sorted(old_c),
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


# ---- patch-signature classification: turn a changed function into a typed N-day candidate --------

#: callee-name signatures (substring, case-insensitive) that a fix ADDS, grouped by what they mean.
_FIX_ADDS = {
    "bounds-check": ("checkandlog", "ensurecapacity", "ensureremaining", "safeseek", "validate",
                     "_valid", "boundcheck", "checklen", "check_len", "_min", "clamp", "_cap",
                     "require"),
    "size-arith-guard": ("mul_overflow", "add_overflow", "umul", "uadd", "safe_mul", "safe_add",
                         "ckd_", "_overflow"),
    "null-check": ("assert", "_check_null", "isnull"),
}
#: callee swaps: an UNSAFE call the vuln used, dropped in favour of a bounded one.
_UNSAFE_DROPPED = ("strcpy", "strcat", "sprintf", "gets", "memcpy", "stpcpy", "lstrcpy", "wcscpy")
_SAFE_ADDED = ("strncpy", "strlcpy", "snprintf", "strncat", "strlcat", "memcpy_s", "memmove")
_FREE_NAMES = ("free", "cfree", "kfree", "g_free", "release", "destroy", "_free", "unref")


def classify_change(c: dict) -> dict:
    """Infer the LIKELY vulnerability a fix addressed, from the shape of the change `c` (one entry
    of `diff()['changed']`). Returns {cwe, exploit_class, why, confidence}. A labelled HYPOTHESIS
    from the patch signature -- never an assertion -- used to rank changed functions into an
    exploit-loop worklist (memory-corruption fixes first). `confidence` is the ranking weight."""
    new_cl = [x.lower() for x in (c.get("new_callees") or [])]
    drop_cl = [x.lower() for x in (c.get("dropped_callees") or [])]
    new_consts = c.get("new_consts") or []
    # a comparison immediate that appeared -- the classic "added a bounds/length check" silent fix.
    added_cmp = [k for k in new_consts if k.split(":")[0] in ("cmp", "sub", "test", "and", "jae",
                                                              "jbe", "ja", "jb", "jg", "jl")]

    def has(cls_key):
        sigs = _FIX_ADDS[cls_key]
        return any(s in n for n in new_cl for s in sigs)

    # 1) unsafe -> bounded copy swap: a textbook overflow fix.
    if any(u in n for n in drop_cl for u in _UNSAFE_DROPPED) and \
            any(s in n for n in new_cl for s in _SAFE_ADDED):
        return _c("CWE-787", "overflow", 0.8,
                  "the fix replaced an unbounded copy with a bounded one "
                  f"({', '.join(sorted({u for n in drop_cl for u in _UNSAFE_DROPPED if u in n}))}"
                  f" -> {', '.join(sorted({s for n in new_cl for s in _SAFE_ADDED if s in n}))})")
    # 2) size-arithmetic overflow guard added -> integer-overflow-to-heap-overflow.
    if has("size-arith-guard"):
        return _c("CWE-190", "overflow", 0.75,
                  "the fix added checked size arithmetic (overflow-guarded multiply/add) before an "
                  "allocation or copy -- the unguarded arithmetic is the vulnerability")
    # 3) a bounds/length/capacity validator added, or a length comparison constant appeared.
    if has("bounds-check") or added_cmp:
        why = "the fix added a bounds/length check"
        if has("bounds-check"):
            got = sorted({s for n in new_cl for s in _FIX_ADDS["bounds-check"] if s in n})
            why += f" (new call to {', '.join(got[:4])})"
        if added_cmp:
            why += f"; new comparison immediate(s) {', '.join(added_cmp[:4])}"
        why += " -- its absence let an attacker-controlled length run past the buffer"
        return _c("CWE-787", "overflow", 0.65, why)
    # 4) a free/release appeared or moved -> lifetime fix (use-after-free / double-free).
    if any(f in n for n in new_cl for f in _FREE_NAMES) or \
            any(f in n for n in drop_cl for f in _FREE_NAMES):
        return _c("CWE-416", "uaf", 0.5,
                  "the fix changed where memory is freed/released -- a use-after-free or double-free "
                  "lifetime bug")
    # 5) body changed but no memory-safety signature -> unknown (still a lead, low rank).
    return _c("NVD-CWE-noinfo", "unknown", 0.3,
              "the function body changed but the patch shows no clear memory-safety signature; "
              "the weakness class is unknown until the engines reach it")


def _c(cwe, cls, conf, why):
    return {"cwe": cwe, "exploit_class": cls, "confidence": conf, "why": why}


def exploit_worklist(diff_result: dict, *, top: int = 25) -> list:
    """Rank a diff()'s changed functions into a typed exploit-loop worklist: each entry is the
    change plus its classification, memory-corruption fixes first (by class weight x how much the
    body moved). This is the hand-off from patch-diff to the exploit loop."""
    out = []
    for c in diff_result.get("changed") or []:
        cls = classify_change(c)
        out.append({**c, **{"classification": cls}})
    order = {"overflow": 0, "uaf": 1, "unknown": 2}
    out.sort(key=lambda e: (order.get(e["classification"]["exploit_class"], 3),
                            -e["classification"]["confidence"], -e.get("moved", 0)))
    return out[:top]
