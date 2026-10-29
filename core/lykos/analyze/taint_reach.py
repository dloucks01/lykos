"""Taint-to-entry grounding: is a finding's function actually reachable from an ATTACKER-CONTROLLED
entry, or is its "untrusted input" an assumed-untrusted parameter that no attacker path ever feeds?

A source/taint detector reports "the path flows from function parameter X with no sanitisation" --
but a function parameter is only attacker-controlled if some caller, transitively from an attacker
entry (a fuzz harness `LLVMFuzzerTestOneInput`, a network read), passes attacker data into it. A
generic `fopen(path)` wrapper that only the local config loader ever calls is not a path-traversal
bug, however unsanitised. This module answers the reachability half of that question from the
recovered call graph.

Soundness stance (precision is paramount):
  * REACHABLE from an attacker entry is a strong POSITIVE: the function genuinely runs on attacker
    input -> promote to the trustworthy shortlist.
  * NOT reachable in the recovered graph is a WEAK negative, not a proof of safety: the static call
    graph misses indirect / function-pointer / plugin dispatch (which plugin/channel dispatch code
    uses heavily). So an unreached finding is DEPRIORITISED with that caveat stated -- never dropped
    as a hard false positive the way instrumentation-noise or a 64-bit-safe multiply is.
Reachability is computed by function NAME, unioned across every harness target, because a library
function found in `libX.so` (no entry of its own) is attacker-reachable exactly when the same name
is reached from a harness that statically links it.
"""
from __future__ import annotations

import re
from typing import Optional

#: Entry symbols whose arguments are attacker-controlled: the libFuzzer harness entry, and common
#: network/stream read sinks that mark a byte source. Matched case-insensitively as substrings.
_ATTACKER_ENTRIES = (
    "llvmfuzzertestoneinput",
    "recv", "recvfrom", "read(", "bio_read", "ssl_read", "sslread", "gnutls_record_recv",
    "transport_read", "tls_read", "stream_read",
)


def _norm(a) -> Optional[int]:
    if a is None:
        return None
    if isinstance(a, int):
        return a
    s = str(a).strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def _is_entry(name: Optional[str]) -> bool:
    if not name:
        return False
    low = name.lower()
    if "llvmfuzzertestoneinput" in low:
        return True
    # a plain network-read import (keep it tight: these as standalone-ish names, not substrings of
    # unrelated identifiers like "spread" for "read")
    return low in ("recv", "recvfrom", "read", "bio_read", "ssl_read", "gnutls_record_recv")


# ---- the MALICIOUS-PEER attack surface ---------------------------------------------------------
# For a network protocol target (RDP, TLS, a parser daemon) the attacker is not a fuzz harness --
# it is the PEER on the wire. Reachability measured only from a fuzz entry misses the entire
# protocol/codec/channel surface (the common, wrong result). These recognise the peer-data entry
# points so reachability can seed from the real attack surface.

#: byte-source reads from a remote peer (whole-ish names / imports).
_PEER_READ = frozenset({
    "recv", "recvfrom", "recvmsg", "read", "pread", "readv", "bio_read", "ssl_read", "sslread",
    "gnutls_record_recv", "tls_read", "transport_read", "stream_read", "wsarecv"})

#: name roles of a function that PARSES peer/wire data: a receive/PDU/order handler, a codec
#: decoder, a channel data-received callback. Substring/suffix patterns, case-insensitive. Tight
#: enough to mean "wire parser", not any helper -- the basis is stated when it promotes a finding.
_PEER_PARSE_RE = re.compile(
    r"(?i)(?:^|_)(?:recv|read)_(?:pdu|order|message|msg|header|capability|caps|packet|data)"
    r"|_recv$|_recv_pdu|_recv_callback|on_?data_?received|_process_(?:message|pdu|packet|data)"
    r"|_decompress(?:$|_)|_decode(?:$|_)|_read_(?:pdu|order|server|client|message)"
    r"|_parse_(?:pdu|packet|message|header|server|client)")


def is_peer_entry(name: Optional[str]) -> bool:
    """True when `name` is itself a malicious-peer data entry: a network read, or a function whose
    role is parsing wire data (PDU/order/codec/channel). Such a function is attacker-reachable by
    definition -- a peer drives it -- even when the static call graph (indirect PDU/channel dispatch
    via function-pointer tables) cannot connect it upward to a read."""
    if not name:
        return False
    low = name.lower()
    base = re.split(r"[.:]", low)[-1]
    if base in _PEER_READ or low in _PEER_READ:
        return True
    return bool(_PEER_PARSE_RE.search(base))


def peer_entry_basis(name: str) -> str:
    """Human basis for why `name` is a peer entry (for the grounding evidence trail)."""
    base = re.split(r"[.:]", (name or "").lower())[-1]
    if base in _PEER_READ or (name or "").lower() in _PEER_READ:
        return "a network read from the peer"
    return "a wire-data parser (PDU/order/codec/channel handler) a malicious peer drives"


def reachable_names_for_target(functions: list, call_edges: list, *, entry_substr=None) -> set:
    """Set of function NAMES reachable from the target's attacker entries over its call graph.

    `functions`: rows with .addr and .name. `call_edges`: rows with .src_addr and (.dst_addr or
    .dst_name). Returns an empty set when the target has no attacker entry (e.g. a bare library)."""
    addr2name: dict = {}
    for f in functions:
        a = _norm(getattr(f, "addr", None) if not isinstance(f, dict) else f.get("addr"))
        n = getattr(f, "name", None) if not isinstance(f, dict) else f.get("name")
        if a is not None and n:
            addr2name[a] = n
    # name -> set(callee names)
    adj: dict = {}
    for e in call_edges:
        sa = _norm(getattr(e, "src_addr", None) if not isinstance(e, dict) else e.get("src_addr"))
        da = _norm(getattr(e, "dst_addr", None) if not isinstance(e, dict) else e.get("dst_addr"))
        dn = getattr(e, "dst_name", None) if not isinstance(e, dict) else e.get("dst_name")
        src = addr2name.get(sa)
        dst = dn or addr2name.get(da)
        if src and dst:
            adj.setdefault(src, set()).add(dst)
    # entry names: declared fuzzer/read entries, plus any edge whose callee is an attacker entry
    entries = {n for n in addr2name.values() if _is_entry(n)}
    if entry_substr:
        entries |= {n for n in addr2name.values() if entry_substr.lower() in n.lower()}
    for callees in adj.values():
        entries |= {c for c in callees if _is_entry(c)}
    if not entries:
        return set()
    # BFS
    seen = set(entries)
    stack = list(entries)
    while stack:
        cur = stack.pop()
        for nxt in adj.get(cur, ()):  # callees
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def unified_name_graph(conn, case_id: str):
    """One name-keyed call graph UNIONED across every target in the case: (adjacency, entries).

    A harness binary holds `entry -> parse_X`; the deep chain `parse_X -> parse_X_int -> ...` is
    best recovered in the LIBRARY binary that defines it (which has no entry of its own). BFS per
    target and union-of-results severs that cross-binary path -- so instead we union all EDGES by
    function name into one graph and BFS once. The same name in two binaries is the same function
    (static link), so this reconnects the harness entry to the library's deep call chains."""
    from ..db.dao import CallEdgeDAO, FunctionDAO, TargetDAO
    adj: dict = {}
    entries: set = set()
    for t in TargetDAO(conn).list_by_case(case_id):
        funcs = FunctionDAO(conn).list_by_target(t.id)
        edges = CallEdgeDAO(conn).list_by_target(t.id)
        addr2name = {}
        for f in funcs:
            a = _norm(getattr(f, "addr", None))
            n = getattr(f, "name", None)
            if a is not None and n:
                addr2name[a] = n
                if _is_entry(n):
                    entries.add(n)
        for e in edges:
            src = addr2name.get(_norm(getattr(e, "src_addr", None)))
            dst = getattr(e, "dst_name", None) or addr2name.get(_norm(getattr(e, "dst_addr", None)))
            if src and dst:
                adj.setdefault(src, set()).add(dst)
                if _is_entry(dst):
                    entries.add(dst)
    return adj, entries


def _bfs(adj: dict, seeds: set) -> set:
    seen = set(seeds)
    stack = list(seeds)
    while stack:
        cur = stack.pop()
        for nxt in adj.get(cur, ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def harness_reachable_names(conn, case_id: str) -> set:
    """Function names reachable from a FUZZ-HARNESS / network-read entry over the unified
    cross-binary name graph. The harnessed slice -- kept for back-compat and for distinguishing the
    harnessed surface from the full peer surface."""
    adj, entries = unified_name_graph(conn, case_id)
    return _bfs(adj, entries) if entries else set()


def attacker_reachable_names(conn, case_id: str) -> set:
    """Function names on the MALICIOUS-PEER attack surface: everything reachable from a fuzz/network
    entry PLUS every wire-data parser (PDU/order/codec/channel handler) and everything they reach.

    For a network protocol target the peer drives the parsers directly, and the static call graph
    cannot follow the indirect PDU/channel dispatch -- so a fuzz-harness-only reachability (the old
    behaviour) dismisses the real attack surface. Seeding BFS from the peer-parser roles themselves
    fixes that: the parsers are attacker-reachable by definition, and their callees come along."""
    adj, entries = unified_name_graph(conn, case_id)
    names = set(adj) | {d for cs in adj.values() for d in cs} | set(entries)
    seeds = set(entries) | {n for n in names if is_peer_entry(n)}
    return _bfs(adj, seeds) if seeds else set()


_SIG_RE = re.compile(r'^[A-Za-z_][\w \t\*&]*\b([A-Za-z_]\w+)\s*\(')
_KW = ("if", "for", "while", "switch", "return", "sizeof", "else", "do", "case")


def enclosing_function(source_text: str, line: int) -> Optional[str]:
    """The C function that encloses 1-based `line`, by scanning backwards for the nearest function
    DEFINITION at column 0 (a `type name(...)` not ending in `;` -- so not a prototype or a call).
    Best-effort, deterministic."""
    lines = source_text.splitlines()
    if not (1 <= line <= len(lines)):
        return None
    for i in range(line - 1, -1, -1):
        stripped = lines[i].rstrip()
        m = _SIG_RE.match(stripped)
        if not m or m.group(1) in _KW:
            continue
        # A prototype or a call statement ends in ';'; a definition's signature does not. A
        # continuation (args spilling over) ends in ',' or '(' -- skip those, the real head is above.
        if stripped.endswith(";") or stripped.endswith(",") or stripped.endswith("("):
            continue
        return m.group(1)
    return None


def name_of_finding(finding: dict, conn=None, source_lookup=None) -> Optional[str]:
    """Best-effort function name for a finding: a binary addr mapped via FunctionDAO, else an
    enclosing-function parse of the cited source line, else a name named in the evidence prose."""
    fa = finding.get("function_addr")
    tid = finding.get("target_id")
    if fa and tid and conn is not None:
        try:
            from ..db.dao import FunctionDAO
            for f in FunctionDAO(conn).list_by_target(tid):
                if _norm(getattr(f, "addr", None)) == _norm(fa) and getattr(f, "name", None):
                    return f.name
        except Exception:                                 # noqa: BLE001
            pass
    # source: enclosing function at the cited file:line
    for e in finding.get("evidence") or []:
        d = e.get("detail") if isinstance(e, dict) else None
        if not d:
            continue
        m = re.search(r'([\w./+\-]+\.(?:c|cc|cpp|cxx)):(\d+)', d)
        if m and source_lookup:
            txt = source_lookup(m.group(1))
            if txt:
                fn = enclosing_function(txt, int(m.group(2)))
                if fn:
                    return fn
        mm = re.search(r"\bin (?:function )?([A-Za-z_][\w.:]{2,})", d)
        if mm:
            return mm.group(1)       # may be a mangled/dotted symbol; ground_reach matches the tail
    return None


def ground_reach(finding: dict, reachable: set, *, conn=None, source_lookup=None) -> dict:
    """{reachable: True/False/None, name, reason} for a finding against the attacker-reachable name
    set. None when no function name could be resolved (cannot decide -> keep, uncertain)."""
    name = name_of_finding(finding, conn=conn, source_lookup=source_lookup)
    if not name:
        return {"reachable": None, "name": None,
                "reason": "no function could be resolved for the finding -- reachability undecided"}
    # A function that IS itself a peer-data parser is attacker-reachable by definition, even if the
    # graph could not connect it upward (indirect PDU/channel dispatch) -- state that basis.
    if is_peer_entry(name):
        return {"reachable": True, "name": name, "basis": "peer-entry",
                "reason": f"'{name}' is {peer_entry_basis(name)} -- attacker-reachable by role"}
    # match on the bare name and on a symbol tail (method.foo.bar -> bar; C++ a::b -> b)
    tail = re.split(r'[.:]', name)[-1]
    hit = name in reachable or tail in reachable \
        or any(r == name or r.endswith("." + name) or r.split("::")[-1] == tail for r in reachable)
    if hit:
        return {"reachable": True, "name": name, "basis": "reached",
                "reason": f"'{name}' is reachable from an attacker entry (peer parser / network "
                          "read / fuzz harness) in the recovered call graph -- attacker input reaches it"}
    return {"reachable": False, "name": name, "basis": "unreached",
            "reason": f"'{name}' was not reached from any attacker entry in the recovered call graph "
                      "(indirect/plugin dispatch may hide a path) -- deprioritised, not dismissed"}
