"""Source-reachability over the recovered call graph: the shortest call path from a function that
reads EXTERNAL INPUT to a finding's function.

This is control-flow reachability from an input source -- NOT a verified byte-level dataflow taint.
A found path is sound (it is built from real recovered call edges, and the graph's incompleteness
only causes paths to be MISSED, never fabricated). One source for the report figure, the report's
structured field, and the GUI's clickable chain, so the drawing, the data and the links agree.
"""
from __future__ import annotations

from collections import deque
from typing import Optional

#: The call path is bounded so a pathological graph cannot blow up the BFS; real source->sink paths
#: are short, so this never truncates a path a reader would want.
_MAX_PATH = 8


def bare_sym(n) -> str:
    """Strip disassembler decoration (sym., imp., leading _, @plt) to a comparable symbol name."""
    n = str(n or "")
    for p in ("sym.imp.", "sym.", "imp.", "_"):
        if n.startswith(p):
            n = n[len(p):]
    return n.split("@")[0]


def reachability_steps(call_edges, f: dict) -> Optional[list]:
    """The shortest call path from an input-source-calling function to this finding's function, as
    a list of {label, addr, sub, tone} hops (source first, sink last). None when the finding has no
    function or no such path exists -- a path is never fabricated. `addr` is the function's address,
    so a renderer can link each hop to its node in the call graph."""
    fa = f.get("function_addr")
    if not fa:
        return None
    try:
        from .detect.taint import SOURCES
    except Exception:                               # noqa: BLE001
        return None
    succ: dict[str, set] = {}
    name: dict[str, str] = {}
    source_callers: set[str] = set()
    for e in call_edges:
        if e.src_addr is None or e.dst_addr is None:
            continue
        s, d = str(e.src_addr), str(e.dst_addr)
        succ.setdefault(s, set()).add(d)
        if e.dst_name:
            name.setdefault(d, str(e.dst_name))
        if bare_sym(e.dst_name) in SOURCES:
            source_callers.add(s)
    target = str(fa)
    if not source_callers or target in source_callers:
        return None
    seen = set(source_callers)
    q = deque((s, [s]) for s in sorted(source_callers))
    path = None
    while q:
        node, p = q.popleft()
        if node == target:
            path = p
            break
        if len(p) >= _MAX_PATH:
            continue
        for nxt in sorted(succ.get(node, ())):
            if nxt not in seen:
                seen.add(nxt)
                q.append((nxt, p + [nxt]))
    if not path or len(path) < 2:
        return None
    steps = []
    for i, a in enumerate(path):
        tone = "source" if i == 0 else ("sink" if i == len(path) - 1 else "")
        sub = "reads input" if i == 0 else ("the finding" if i == len(path) - 1 else None)
        steps.append({"label": name.get(a) or a, "addr": a, "sub": sub, "tone": tone})
    return steps
