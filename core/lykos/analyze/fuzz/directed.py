"""Directed fuzzing at static candidates (Phase 5, zero-AI).

Classical distance-based directed greybox fuzzing (AFLGo-style) says: don't explore blindly,
steer toward the code sites that static analysis already flagged as dangerous. We can't
recompile the target to embed AFLGo's compile-time distances, so we approximate the same idea
with the artifacts we already extract:

  1. select targets -- the highest-value static findings that carry a code address
     (dangerous-API sinks, especially taint/reachability-corroborated ones);
  2. callgraph distance -- BFS backward from each target function over the call graph, so we
     know which functions lie on a path that reaches a target;
  3. targeted corpus/dictionary -- the string constants those near-target functions actually
     reference in their P-Code (resolved via each string's xref sites) become high-priority
     seeds and dictionary tokens, biasing the mutator toward inputs that drive execution
     toward the sink.

The campaign itself reuses `fuzz_campaign` (sandbox -> minimize -> Confirmed finding). With no
coverage instrumentation the directedness lives entirely in the input distribution; when the
static graph is absent (e.g. Ghidra was not run) the stage degrades to an undirected campaign
with a string-mined dictionary and says so.
"""
from __future__ import annotations

import base64
import random
from collections import defaultdict

from ...db.dao import (
    CallEdgeDAO,
    DynResultDAO,
    FindingDAO,
    FunctionDAO,
    StringDAO,
    TargetDAO,
)
from ...hashing import canonical_json
from ...jobs.registry import register_stage
from ..detect.catalog import SOURCES, normalize
from . import cmpdict
from .stage import (
    _DEFAULT_SEEDS,
    _mine_dictionary,
    _recovered_blocks,
    _structure_mutator,
    fuzz_campaign,
)


def _cmp_tokens_for(functions, keep=None):
    """Static input-to-state tokens (see cmpdict) from the hydrated IR of `functions`, optionally
    restricted to the addresses in `keep` (the near-target set). Empty when no IR / no P-Code."""
    irs = {}
    for f in functions or ():
        fa = _addr(f.addr)
        ir = getattr(f, "ir", None)
        if fa is not None and ir and (keep is None or fa in keep):
            irs[fa] = ir
    return cmpdict.mine_cmp_dictionary(irs)


def _merge_dict(cmptoks, base, limit=400):
    """cmp-immediate tokens first (a 4-byte magic is the most discriminating thing to splice),
    then the string-mined tokens, de-duplicated."""
    if not cmptoks:
        return base
    seen = set(cmptoks)
    return (list(cmptoks) + [t for t in base if t not in seen])[:limit]

DIRECTED_STAGE = "directed_fuzz"
TOOL = "directed"
TOOL_VERSION = "directed-1"

# detectors whose findings name a code site worth steering toward (static candidates only;
# crash/dynamic findings are already confirmed, so they are not fuzzing *targets*).
_TARGET_DETECTORS = {"dangerous_api", "weak_crypto", "weak_random", "insecure_tmp"}
_STATE_RANK = {"corroborated": 3, "candidate": 2, "confirmed": 1, "poc-backed": 0}
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _addr(x):
    """Parse a hex/decimal address string to int; None on failure."""
    if x is None:
        return None
    try:
        return int(x, 16) if isinstance(x, str) and x.lower().startswith("0x") \
            else int(x, 0) if isinstance(x, str) else int(x)
    except (ValueError, TypeError):
        return None


def select_targets(findings):
    """Rank static candidate findings that carry a function address as fuzzing targets."""
    out = []
    for f in findings:
        if f.detector not in _TARGET_DETECTORS or f.function_addr is None:
            continue
        has_taint = any(
            (e.get("channel") if isinstance(e, dict) else "") in
            ("taint-dataflow", "taint-reachability")
            for e in (f.evidence or []))
        score = (_STATE_RANK.get(f.state, 0) * 100 + (50 if has_taint else 0)
                 + _SEV_RANK.get(f.severity, 0) * 5 + f.confidence)
        out.append({"function_addr": f.function_addr, "site_addr": f.site_addr,
                    "cwe": f.cwe, "detector": f.detector, "title": f.title,
                    "has_taint": has_taint, "score": score})
    out.sort(key=lambda t: t["score"], reverse=True)
    return out


def callgraph_distance(call_edges, target_fn_addrs):
    """Backward BFS over the call graph: distance[fn] = min call-hops from fn down to a
    target function (0 at a target). Functions with no finite distance can't reach a target."""
    callers = defaultdict(set)              # callee entry -> {caller entries}
    for e in call_edges:
        da, sa = _addr(e.dst_addr), _addr(e.src_addr)
        if da is not None and sa is not None:
            callers[da].add(sa)
    dist = {}
    frontier = {a for a in (_addr(t) for t in target_fn_addrs) if a is not None}
    d = 0
    while frontier:
        nxt = set()
        for fn in frontier:
            if fn in dist:
                continue
            dist[fn] = d
            nxt |= callers.get(fn, set())
        frontier = nxt - dist.keys()
        d += 1
    return dist


def _instr_to_func(functions):
    """Map an instruction address (int) to its enclosing function address (int), using CFG
    instruction addresses when available and [addr, addr+size) ranges otherwise."""
    ranges = []
    for f in functions:
        fa = _addr(f.addr)
        if fa is None:
            continue
        ir = f.ir or {}
        placed = False
        for blk in ir.get("blocks", ()) or ():
            for ins in blk.get("instructions", ()) or ():
                ia = _addr(ins.get("addr"))
                if ia is not None:
                    ranges.append((ia, ia + 1, fa))
                    placed = True
        if not placed and f.size:
            ranges.append((fa, fa + int(f.size), fa))
    ranges.sort()

    def lookup(ia):
        best = None
        for lo, hi, fa in ranges:
            if lo <= ia < hi:
                best = fa
            elif lo > ia:
                break
        return best
    return lookup


def mine_targeted_dictionary(functions, strings, distance, *, max_dist=4, limit=400):
    """Strings referenced (via their xref sites) by functions on a path to a target, ordered
    closest-first. These are the constants the near-target code actually compares against."""
    if not distance:
        return []
    to_func = _instr_to_func(functions)
    by_dist = []                            # (min_distance, token_bytes)
    seen = set()
    for s in strings:
        v = (s.value or "").strip()
        if not v or len(v) > 96:
            continue
        best = None
        for xr in (s.xrefs or ()):
            ia = _addr(xr)
            if ia is None:
                continue
            fa = to_func(ia)
            if fa is not None and fa in distance:
                best = distance[fa] if best is None else min(best, distance[fa])
        if best is None or best > max_dist:
            continue
        tok = v.encode("latin-1", "ignore")
        if tok in seen:
            continue
        seen.add(tok)
        by_dist.append((best, tok))
    by_dist.sort(key=lambda x: x[0])
    return [tok for _, tok in by_dist[:limit]]


def _sources_reaching_targets(call_edges, distance):
    """Names of untrusted-input source functions called from within any function that can
    reach a target (finite distance). Used to explain reachability / pick an input mode."""
    got = set()
    for e in call_edges:
        sa = _addr(e.src_addr)
        if sa in distance and normalize(e.dst_name) in SOURCES:
            got.add(normalize(e.dst_name))
    return got


def plan_directed_campaign(findings, functions, call_edges, strings):
    """Build a directed plan: ranked targets, callgraph distances, a targeted dictionary and
    seed corpus, and the input sources that reach the targets. Falls back to a string-mined
    dictionary (undirected) when there are no addressed static candidates."""
    targets = select_targets(findings)
    # Menu-navigation seeds so the campaign starts INSIDE a numbered menu (heap/service targets),
    # not blindly at the front door. Best-effort; empty when the binary is not menu-driven.
    try:
        from . import menu as _menu
        _svals = [getattr(s, "value", s) for s in (strings or [])]
        menu_seeds = _menu.menu_seeds([v for v in _svals if isinstance(v, str)])
    except Exception:
        menu_seeds = []
    if not targets:
        # Undirected: still plant input-to-state tokens mined from every function's comparison
        # constants, so magic-gated code is reached even without a specific target to steer toward.
        undirected = _merge_dict(_cmp_tokens_for(functions), _mine_dictionary(strings))
        return {"targets": [], "directed": False,
                "dictionary": undirected,
                "seeds": menu_seeds + [t for t in undirected[:64]] + list(_DEFAULT_SEEDS),
                "sources": set(),
                "note": "no addressed static candidates; running undirected"}

    distance = callgraph_distance(call_edges, [t["function_addr"] for t in targets])
    tdict = mine_targeted_dictionary(functions, strings, distance)
    if not tdict:                            # graph present but no near-target string consts
        tdict = _mine_dictionary(strings)
    # Input-to-state (RedQueen/CmpLog-style) tokens mined STATICALLY from the P-Code comparison
    # constants of the functions on a path to a target -- the magic bytes, tags and length gates
    # the near-target code tests the input against. A byte-level mutator never guesses a 4-byte
    # magic; planting it from the dictionary reaches the gated branch immediately, and this works
    # even black-box under qemu where CmpLog cannot run. Merged FIRST (most discriminating).
    near = {fa for fa, d in distance.items() if d <= 4}
    tdict = _merge_dict(_cmp_tokens_for(functions, keep=near), tdict)
    # seed the corpus with the targeted tokens themselves so comparisons are hit immediately,
    # plus menu-navigation seeds so a menu-driven target is fuzzed from inside its state machine
    seeds = menu_seeds + [t for t in tdict[:64]] + list(_DEFAULT_SEEDS)
    sources = _sources_reaching_targets(call_edges, distance)
    return {"targets": targets, "directed": True, "dictionary": tdict, "seeds": seeds,
            "sources": sources, "distance_count": len(distance),
            "note": None if sources else "targets not shown reachable from a known input source"}


def _prior_corpus(ctx, target, limit=64, maxbytes=8192):
    """Seed from the target's accumulated INTERESTING inputs -- concolic-generated inputs and
    prior crashers -- so each fuzz run BUILDS ON the last instead of restarting from string-mined
    tokens. This closes the concolic->fuzz loop and persists corpus across stages: an input
    concolic solved to pass a guarded branch (a magic value, a length check) becomes a seed the
    fuzzer mutates AROUND, reaching the code beyond the branch that a blind campaign never enters.

    Concolic inputs first (they were solved specifically to reach new paths), then crashers, then
    any other recorded input; capped in count and size so seeding stays cheap."""
    def _rank(r):
        note = (r.note or "")
        return (0 if "concolic" in note else 1, 0 if r.crashed else 1)
    out, seen = [], set()
    for r in sorted(DynResultDAO(ctx.conn).list_by_target(target.id), key=_rank):
        sha = getattr(r, "input_sha", None)
        if not sha or sha in seen:
            continue
        seen.add(sha)
        try:
            b = ctx.content.get_bytes(sha)
        except Exception:
            continue
        if 0 < len(b) <= maxbytes:
            out.append(b)
        if len(out) >= limit:
            break
    return out


def _target_label(targets):
    if not targets:
        return "no static target"
    t = targets[0]
    where = t.get("site_addr") or t.get("function_addr")
    return f"{t.get('cwe') or t.get('detector')} @ {where}"


def directed_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("directed_fuzz requires a target_id")

    p = ctx.params or {}
    mode = p.get("input_mode", "stdin")               # stdin | arg | file
    max_execs = int(p.get("max_execs", 4000))
    max_seconds = float(p.get("max_seconds", 30))
    exec_timeout = float(p.get("exec_timeout", 2))
    rng = random.Random(int(p.get("seed", 1337)))

    findings = FindingDAO(ctx.conn).list_by_target(target.id)
    functions = FunctionDAO(ctx.conn).list_by_target(target.id)
    # hydrate IR for instruction->function mapping (list_by_target omits the heavy ir blob)
    fdao = FunctionDAO(ctx.conn)
    hydrated = []
    for f in functions:
        full = fdao.get(f.id) if f.blocks else f
        hydrated.append(full or f)
    call_edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    strings = StringDAO(ctx.conn).list_by_target(target.id)

    plan = plan_directed_campaign(findings, hydrated, call_edges, strings)

    # allow explicit seeds from params to augment the mined corpus, and ALWAYS reuse the target's
    # accumulated interesting inputs (concolic-solved inputs + prior crashers) so coverage
    # compounds across runs instead of each campaign starting cold.
    extra_seeds = [base64.b64decode(x) for x in p.get("seeds", [])]
    prior = _prior_corpus(ctx, target)
    corpus = extra_seeds + prior + plan["seeds"]

    ctx.emit("directed.start", payload={
        "directed": plan["directed"], "targets": len(plan["targets"]),
        "top_target": _target_label(plan["targets"]) if plan["directed"] else None,
        "dictionary": len(plan["dictionary"]), "seeds": len(corpus),
        "reused": len(prior),          # interesting inputs carried over from earlier stages
        "sources": sorted(plan["sources"]), "note": plan["note"]})
    ctx.progress(msg=("directed at " + _target_label(plan["targets"])) if plan["directed"]
                 else "undirected (no static targets)")

    note_prefix = ("found by directed fuzzing (target: " + _target_label(plan["targets"]) + ")"
                   if plan["directed"] else "found by directed fuzzing (undirected fallback)")
    mutator = _structure_mutator(p, rng, plan["dictionary"])   # structure-aware if format set
    if mutator:
        note_prefix += " [structure-aware]"
        ctx.emit("directed.format", payload={"model": p.get("format_name") or "custom"})
    # Arm block coverage so the directed campaign reports how much of the recovered code it
    # actually reached -- the honest "% of the binary covered", not AFL's edge-map density.
    blocks = _recovered_blocks(ctx, target)
    # Sink-directed steering: distance from every recovered block to the nearest target sink, so the
    # campaign RETAINS inputs that get closer to the flagged CWE site (AFLGo, no recompile). Only
    # meaningful when we have real targets; the undirected fallback passes an empty map (no steer).
    from . import blockdist
    _sites = {a for a in (blockdist._addr(t.get("site_addr")) for t in plan["targets"])
              if a is not None}
    bdist = blockdist.block_distance(hydrated, call_edges, _sites) if _sites else {}
    if bdist:
        ctx.emit("directed.blockdist", payload={"targets": len(_sites),
                 "blocks_with_distance": len(bdist),
                 "nearest": round(min(bdist.values()), 2)})
    st = fuzz_campaign(ctx, target, corpus=corpus, dictionary=plan["dictionary"], mode=mode,
                       max_execs=max_execs, max_seconds=max_seconds, exec_timeout=exec_timeout,
                       rng=rng, detector="directed_fuzz", event_prefix="directed",
                       note_prefix=note_prefix, mutator=mutator, cover_blocks=blocks,
                       block_dist=bdist)
    hit, known = st.get("blocks_hit", 0), st.get("blocks_known", 0)
    summary = {"backend": "directed", "execs": st.get("execs", 0), "crashes": st.get("crashes", 0),
               "directed": bool(plan["directed"]), "top_target": _target_label(plan["targets"]) if plan["directed"] else None,
               "coverage": {"kind": "block", "blocks_hit": hit, "blocks_known": known,
                            "pct": round(100.0 * hit / known, 1) if known else None}}
    sha = ctx.put_artifact("fuzz-summary", data=canonical_json(summary))
    return {"output_shas": [sha], "output_kind": "fuzz-summary"}


def register() -> None:
    register_stage(DIRECTED_STAGE, directed_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=3600)


def enqueue_directed_fuzz(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, DIRECTED_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
