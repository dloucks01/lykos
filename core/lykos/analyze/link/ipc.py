"""IPC / RPC channel modelling (doc 17.1 discovery + 17.2 channel-as-sink->source).

Deterministic and Ghidra-free: reads each component's dynamic-symbol imports (captured at
triage) to identify IPC endpoints and their role (sender / receiver), and scans the binary
for channel-name literals (POSIX mq / shm names, FIFO and unix-socket paths). Two components
that use the same IPC family and share a channel key -- one sending, one receiving -- are
linked by an `ipc` component edge. Modelling the channel as a taint sink (send) -> taint
source (recv), an untrusted-input producer wired to a dangerous-sink consumer yields a
cross-component candidate finding (doc 17.2).

Honest limit: channel matching is by shared literal key + API role (reachability across the
channel), not precise payload data-flow; findings land as *candidates*.
"""
from __future__ import annotations

import re
from collections import defaultdict

from ..detect.catalog import DANGEROUS, SOURCES, normalize
from ..detect.catalog import name as cwe_name
from .resolve import _triage_records

# normalized libc/librt symbol -> (family, role)   role: send | recv | open | map | create
IPC_APIS = {
    "mq_open": ("mq", "open"), "mq_send": ("mq", "send"), "mq_timedsend": ("mq", "send"),
    "mq_receive": ("mq", "recv"), "mq_timedreceive": ("mq", "recv"),
    "msgget": ("sysvmq", "open"), "msgsnd": ("sysvmq", "send"), "msgrcv": ("sysvmq", "recv"),
    "shm_open": ("shm", "open"), "shmget": ("shm", "open"),
    "shmat": ("shm", "map"), "mmap": ("shm", "map"),
    "mkfifo": ("fifo", "create"), "mkfifoat": ("fifo", "create"), "mknod": ("fifo", "create"),
    "socket": ("socket", "open"), "bind": ("socket", "recv"), "listen": ("socket", "recv"),
    "accept": ("socket", "recv"), "accept4": ("socket", "recv"),
    "connect": ("socket", "send"),
    "send": ("socket", "send"), "sendto": ("socket", "send"), "sendmsg": ("socket", "send"),
    "recv": ("socket", "recv"), "recvfrom": ("socket", "recv"), "recvmsg": ("socket", "recv"),
}
# families whose direction is ambiguous statically (both endpoints read & write)
_AMBIGUOUS = {"shm", "fifo"}

_STR = re.compile(rb"[\x20-\x7e]{3,192}")
_KEYISH = re.compile(r"^/[A-Za-z0-9_.+\-/]{1,150}$")
# obvious non-channel system paths to drop
_SYS_PREFIX = ("/lib", "/lib64", "/usr", "/proc", "/sys", "/bin", "/sbin", "/etc/ld",
               "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/tty")


def _scan_keys(data: bytes) -> set[str]:
    """Channel-name literals: leading-slash names that are not system library paths."""
    out: set[str] = set()
    for m in _STR.finditer(data or b""):
        s = m.group().decode("ascii", "replace")
        if not _KEYISH.match(s):
            continue
        if any(s == p or s.startswith(p + "/") or s.startswith(p) for p in _SYS_PREFIX):
            continue
        if s.endswith(".so") or ".so." in s or s.endswith("/"):
            continue
        out.add(s)
    return out


def component_ipc(content, target, triage_rec: dict) -> dict:
    """IPC profile for one component from its imports + channel-name literals."""
    imports = set((triage_rec.get("imports", {}) or {}).get("symbols", []) or [])
    norm = {normalize(s) for s in imports}

    families: dict[str, set] = defaultdict(set)      # family -> {roles}
    for sym in norm:
        fr = IPC_APIS.get(sym)
        if fr:
            families[fr[0]].add(fr[1])

    sources = sorted(norm & SOURCES)
    sinks = []
    for sym in sorted(norm):
        if sym in DANGEROUS:
            cwe, sev, _desc = DANGEROUS[sym]
            sinks.append((cwe, sev, sym))

    keys: set[str] = set()
    try:
        if content.exists(target.sha256):
            keys = _scan_keys(content.get_bytes(target.sha256))
    except OSError:
        keys = set()

    return {"families": {f: r for f, r in families.items()}, "keys": keys,
            "sources": sources, "sinks": sinks, "norm": norm}


def _is_sender(roles: set, family: str) -> bool:
    return "send" in roles or family in _AMBIGUOUS


def _is_receiver(roles: set, family: str) -> bool:
    return "recv" in roles or family in _AMBIGUOUS


def _sev_rank(sev: str) -> int:
    order = ["info", "low", "medium", "high", "critical"]
    return order.index(sev) if sev in order else 0


def match_channels(targets: dict, profiles: dict) -> tuple[list, list]:
    """Pure matcher: given {tid: target} and {tid: profile}, return (edges, findings).

    An edge is created when component A (sender on family F, key K) and component B
    (receiver on F, key K) share the literal channel key K. A candidate finding is added
    when the channel wires an untrusted-input producer to a dangerous-sink consumer.
    """
    edges: list = []
    findings: list = []
    seen: set = set()
    for aid in sorted(profiles):
        ap = profiles[aid]
        for bid in sorted(profiles):
            if aid == bid:
                continue
            bp = profiles[bid]
            shared = ap["keys"] & bp["keys"]
            if not shared:
                continue
            for family in sorted(ap["families"]):
                if family not in bp["families"]:
                    continue
                if not (_is_sender(ap["families"][family], family)
                        and _is_receiver(bp["families"][family], family)):
                    continue
                for key in sorted(shared):
                    # ambiguous families: single direction from the input-bearing side
                    if family in _AMBIGUOUS and not ap["sources"] and bp["sources"]:
                        continue
                    ek = (aid, bid, family, key)
                    if ek in seen:
                        continue
                    seen.add(ek)
                    edges.append({"src": aid, "dst": bid, "family": family, "key": key})
                    if ap["sources"] and bp["sinks"]:
                        cwe, sev, sink = max(bp["sinks"], key=lambda s: _sev_rank(s[1]))
                        findings.append(_ipc_finding(targets[aid], targets[bid], family, key,
                                                     cwe, sev, sink, ap["sources"][0]))
    return edges, findings


def model_ipc_case(conn, content, case_id: str, *, persist: bool = True) -> dict:
    """Discover IPC channels across the case's components and (optionally) persist `ipc`
    edges + cross-component candidate findings. Returns a summary."""
    from ...db.dao import ComponentEdgeDAO, FindingDAO, TargetDAO

    targets = {t.id: t for t in TargetDAO(conn).list_by_case(case_id)}
    recs = _triage_records(conn, content, case_id)
    profiles = {tid: component_ipc(content, t, recs.get(tid, {}) or {})
                for tid, t in targets.items()}
    edges, findings = match_channels(targets, profiles)

    if persist:
        ce = ComponentEdgeDAO(conn)
        fd = FindingDAO(conn)
        ce.clear_case(case_id, kind="ipc")
        for e in edges:
            ce.upsert(case_id, e["src"], e["dst"], kind="ipc", symbol=e["key"],
                      detail=f"{e['family']}:{e['key']}")
        for cand in findings:
            fd.upsert(cand["_target"], case_id, cand)
        conn.commit()
    return {"components": len(profiles), "ipc_edges": len(edges),
            "channels": sorted({e["family"] + ":" + e["key"] for e in edges}),
            "cross_findings": len(findings)}


def _ipc_finding(a, b, family, key, cwe, sev, sink, source_sym) -> dict:
    return {
        "_target": b.id,   # sink component (where the finding lands); ignored by FindingDAO
        "cwe": cwe,
        "title": (f"IPC channel taint: untrusted input in {a.filename} may reach "
                  f"{sink}() in {b.filename} over {family} channel {key}"),
        "severity": sev,
        "state": "candidate",
        "confidence": 0.4,
        "detector": "ipc_taint",
        "function_addr": None,
        "site_addr": None,
        "dedup_key": f"ipc:{a.id}:{b.id}:{family}:{key}",
        "evidence": [
            {"channel": "ipc",
             "detail": (f"{a.filename} ({source_sym} source) sends on {family} channel "
                        f"{key}; {b.filename} receives on it")},
            {"channel": "ipc-reachability",
             "detail": (f"{b.filename} calls {sink}() ({cwe_name(cwe)}); untrusted input "
                        f"can cross the channel to it (reachability, not payload data-flow)")},
        ],
    }
