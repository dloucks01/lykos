"""Phase 3 — the `detect_cwe` stage: run detectors over IR/call-graph/strings -> findings."""
from __future__ import annotations

from ...db.dao import CallEdgeDAO, FindingDAO, FunctionDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from . import bounds, taint
from .catalog import entry_seed_params
from .detectors import DETECTORS, DetectContext, correlate

DETECT_STAGE = "detect_cwe"
TOOL = "detect"
TOOL_VERSION = "detect-1"


# Attacker-influenced dereference. Every other detector keys on a CALL, so this whole class
# was invisible: jhead's only demonstrated bug is an out-of-bounds READ at
# `movzx eax,BYTE PTR [rax]`, which is not a call to anything and which nothing could see.
_DEREF = {
    "load": ("CWE-125", "low",
             "Out-of-bounds read candidate: dereferences a pointer computed from "
             "attacker-controlled input"),
    "store": ("CWE-787", "medium",
              "Out-of-bounds write candidate: writes through a pointer computed from "
              "attacker-controlled input"),
}


def _deref_candidates(derefs, functions):
    """One finding per KIND, carrying every site -- the grain the rest of the channel uses.

    Deliberately filed as low-confidence inventory, not an assertion. Whether any particular
    dereference is actually unchecked needs a bound on the INDEX, which this does not have;
    what it does have is the exact set of places attacker data reaches a pointer, which is
    where the out-of-bounds reads and writes live. A reproduced crash landing on one of these
    sites promotes it (see rootcause.attribute) -- that is what turns the inventory into a
    finding.
    """
    names = {f.addr: f.name for f in functions}
    out = []
    for kind in ("load", "store"):
        hits = [d for d in derefs if d["kind"] == kind]
        if not hits:
            continue
        cwe, sev, title = _DEREF[kind]
        where = sorted({names.get(d["function_addr"]) or str(d["function_addr"])
                        for d in hits})
        # One candidate per site sharing a dedup_key: upsert merges them into a single
        # finding and records each as a site, which is how the call-sink detectors already
        # report a defect that occurs in many places.
        summary = {"channel": "taint-dataflow",
                   "detail": (f"{len(hits)} attacker-influenced {kind}"
                              f"{'s' if len(hits) != 1 else ''} across {len(where)} "
                              f"functions: " + ", ".join(where[:8])
                              + (" ..." if len(where) > 8 else ""))}
        for d in hits:
            fn = names.get(d["function_addr"]) or str(d["function_addr"])
            out.append({
                "cwe": cwe, "title": title, "severity": sev, "state": "candidate",
                "confidence": 0.35, "detector": "tainted_deref",
                "function_addr": d["function_addr"], "site_addr": d["site_addr"],
                "dedup_key": f"{cwe}:tainted_deref:{kind}",
                "site_detail": f"attacker-influenced {kind} through a computed pointer in {fn}",
                "evidence": [summary],
            })
    return out


# A bounds check that can WRAP is not a bounds check. jhead's out-of-bounds read is exactly
# this: `if (OffsetVal + ByteCount > ExifLength)` computed in 32 bits, where 0x00ffffff +
# 0xff000002 is 1 -- the sum looks tiny, the check passes, and the offset still points far
# outside the buffer. The platform FOUND that bug dynamically and could not see it statically,
# which is the gap this closes.
_CMP_OPS = {"INT_LESS", "INT_LESSEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_EQUAL",
            "INT_NOTEQUAL"}
_ADD_OPS = {"INT_ADD", "INT_MULT", "INT_LEFT"}


def _intover_candidates(func_irs, functions, only=None, width=4):
    """Sums narrower than a pointer that are then COMPARED: a check the sum can wrap past.

    `only` restricts this to the functions attacker data actually reaches. Without it the
    pattern is everywhere -- eighteen of jhead's functions do 32-bit arithmetic in a
    comparison, most of it loop and buffer bookkeeping that no input can steer -- and a report
    that doubles in size to say so is the inventory-as-findings mistake again.
    """
    names = {f.addr: f.name for f in functions}
    out = []
    for faddr, ir in (func_irs or {}).items():
        if only is not None and faddr not in only:
            continue
        for b in ((ir or {}).get("blocks") or []):
            for i in b.get("instructions", []) or []:
                produced: dict = {}
                for pc in i.get("pcode", []) or []:
                    mnem, args, outk = _pcode(pc)
                    if mnem in _ADD_OPS and outk and _tok_width(outk) == width:
                        # BOTH addends must be values. `i + 1 < n` is a loop, not a hazard,
                        # and allowing a constant addend flagged sixteen extra functions in
                        # jhead -- a pointer bump or a loop counter in nearly every one. The
                        # shape that wraps is two attacker-sized quantities added together:
                        # an offset plus a count, which is jhead's bug exactly.
                        if all(not t.startswith("const:") for t in args):
                            produced[outk] = mnem
                    elif mnem in _CMP_OPS:
                        hit = next((k for k in args if k in produced), None)
                        if hit is None:
                            continue
                        fn = names.get(faddr) or str(faddr)
                        out.append({
                            "cwe": "CWE-190", "severity": "low", "state": "candidate",
                            # inventory grade on purpose: this is the SHAPE of a check that
                            # can wrap, not evidence that this one does. What makes it worth
                            # reporting is that the platform found jhead's wrapping check
                            # dynamically and could not see it statically at all.
                            "confidence": 0.3, "detector": "int_overflow_check",
                            "title": ("Bounds check on a sum that can wrap "
                                      f"({width * 8}-bit arithmetic)"),
                            "function_addr": faddr, "site_addr": i.get("addr"),
                            "dedup_key": f"CWE-190:int_overflow_check:{faddr}",
                            "site_detail": (f"{produced[hit]} at {width * 8} bits feeds a "
                                            f"comparison in {fn}: if the sum wraps, the check "
                                            f"passes on a value that is far too large"),
                            "evidence": [{"channel": "pcode",
                                          "detail": (f"{produced[hit]} -> {mnem} at "
                                                     f"{i.get('addr')} in {fn}")}],
                        })
                        break
    return out


def _pcode(pc):
    """(mnemonic, operand tokens, output token) -- output is None for a branch or store."""
    left, _, out = pc.partition(" -> ")
    parts = left.split()
    return (parts[0] if parts else ""), parts[1:], (out.strip() or None)


def _tok_width(tok):
    try:
        return int(tok.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return 0


def _program_only(ctx, target, functions):
    """(functions, call_edges, dropped) restricted to the program's own code where possible."""
    from ..elf import program_ranges
    edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    try:
        blob = ctx.content.path(target.sha256).read_bytes()
        ranges = program_ranges(blob)
    except Exception:
        ranges = []
    if not ranges:
        return functions, edges, 0
    from ..debug import rootcause
    from ..elf import parse as parse_elf
    try:
        entry = parse_elf(blob).entry
    except Exception:
        entry = None
    base = rootcause.image_base(functions, entry) or 0
    los = [lo for lo, _ in ranges]

    def own(addr) -> bool:
        import bisect
        try:
            a = (int(addr, 16) if isinstance(addr, str) else int(addr or 0)) - base
        except (TypeError, ValueError):
            return True                      # unparseable: keep it rather than hide it
        i = bisect.bisect_right(los, a) - 1
        return i >= 0 and a < ranges[i][1]

    keep_fn = [f for f in functions if own(f.addr)]
    keep_ed = [e for e in edges if own(e.src_addr)]
    dropped = (len(functions) - len(keep_fn)) + (len(edges) - len(keep_ed))
    if not keep_fn or not keep_ed:
        return functions, edges, 0           # attribution said nothing useful; do not blind it
    return keep_fn, keep_ed, dropped


def detect_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("detect_cwe requires a target_id")

    fdao = FunctionDAO(ctx.conn)
    functions = fdao.list_by_target(target.id)
    # A statically linked binary carries its libc, and the decompiler recovers all of it, so
    # the report fills with the LIBRARY's own calls: jhead's memcpy finding carried 95 sites,
    # nearly all of them inside glibc, which says nothing about jhead. Where the symbol table
    # can say which code is the program's own, detection listens to it -- the same attribution
    # coverage uses. When it cannot (stripped, no local symbols), nothing is filtered.
    functions, edges, dropped = _program_only(ctx, target, functions)
    # hydrate decompiler stack frames (heavy; omitted from the list view) for size-aware detection
    frames = {}
    for f in functions:
        if not f.blocks:
            continue
        full = fdao.get(f.id)
        if full and full.frame and (full.frame.get("vars") or full.frame.get("params")):
            frames[f.addr] = full.frame

    dctx = DetectContext(
        target_id=target.id, case_id=target.case_id,
        call_edges=edges,
        strings=StringDAO(ctx.conn).list_by_target(target.id),
        functions=functions,
        mitigations=target.mitigations or {}, frames=frames)

    ctx.progress(msg="running CWE detectors")
    cands = []
    for det in DETECTORS:
        cands += det(dctx)
    cands = correlate(cands, dctx)

    # inter-procedural data-flow taint over P-Code: flag sink sites whose argument
    # registers carry tainted data (across function boundaries), and upgrade findings.
    ctx.progress(msg="data-flow taint analysis (inter-procedural)")
    func_irs = {}
    for f in dctx.functions:
        if not f.blocks:
            continue
        full = fdao.get(f.id)
        if full and full.ir:
            func_irs[f.addr] = full.ir
    entry_seeds = entry_seed_params(dctx.functions, dctx.frames)   # argv/envp at main
    derefs: list = []
    tainted_sites = taint.analyze_program(func_irs, dctx.call_edges, target.arch,
                                          entry_seeds=entry_seeds, mem_out=derefs)
    cands += _deref_candidates(derefs, dctx.functions)
    # only where attacker data demonstrably lands: a function that dereferences input, or one
    # whose call to a dangerous sink taint reaches
    touched = {d["function_addr"] for d in derefs}
    touched |= {c["function_addr"] for c in cands
                if c.get("site_addr") in tainted_sites and c.get("function_addr")}
    cands += _intover_candidates(func_irs, dctx.functions, only=touched)
    for c in cands:
        if c["detector"] == "dangerous_api" and c.get("site_addr") in tainted_sites:
            c["state"] = "corroborated"
            c["confidence"] = max(c["confidence"], 0.8)
            c["site_state"] = "corroborated"      # THIS site is the one taint reaches
            c["site_confidence"] = 0.8
            c["evidence"].append({"channel": "taint-dataflow",
                                  "detail": "tainted value reaches a sink argument "
                                            "(intra-procedural P-Code taint)"})

    # Bounds channel: can this copy actually exceed its destination? The rule channel flags
    # every memcpy/strncpy and the taint channel confirms "attacker data reaches it", which on
    # a parser is true of nearly everything -- on jhead that was 20 LOW findings amounting to
    # "this program calls memcpy". A copy whose length is a compile-time constant that FITS
    # the recovered destination is not a defect, and saying so turns that noise into inventory.
    ctx.progress(msg="bounds analysis on copy sinks")
    verdicts = bounds.classify_program(func_irs, dctx.call_edges, frames, target.arch,
                                       bits=target.bits or 64)
    for c in cands:
        v = verdicts.get(c.get("site_addr"))
        # stack_buffer_overflow reports the same strcpy sites at CWE-121/high, so a bounds
        # verdict has to reach it too -- otherwise a copy proven safe still shows up as a
        # high-severity stack smash. Both of gzip 1.3.5's CWE-121 candidates were that.
        if not v or c.get("detector") not in ("dangerous_api", "stack_frame"):
            continue
        c["site_verdict"] = v["verdict"]          # the ruling is about THIS place
        if v["verdict"] == bounds.SAFE:
            # provably bounded: demote out of the headline, keep as inventory with the reason
            c["severity"] = "info"
            c["state"] = "candidate"
            c["confidence"] = min(c.get("confidence", 0.4), 0.15)
            c["evidence"].append({"channel": "bounds", "detail": v["why"]})
            c["site_detail"] = v["why"]
        elif v["verdict"] in (bounds.SUSPECT, bounds.SIGNED):
            # Surfaced for review -- NOT promoted, because a recovered frame can name the
            # wrong variable for a reused stack slot (see bounds.py). Critically also NOT
            # demoted: a SIGNED verdict means a bounds check exists and does not bound, so
            # treating it as "bounded" would bury the defect under its own guard.
            c["evidence"].append({"channel": "bounds", "detail": v["why"]})
            c["site_detail"] = v["why"]

    fd = FindingDAO(ctx.conn)
    for c in cands:
        # Stamp the run: this channel's verdicts from an EARLIER run are replaced rather than
        # max-merged, which is what lets a demotion (a copy proven bounded, say) actually take
        # effect. Sites within this run still take the strongest.
        c["run_id"] = ctx.run_id
        fd.upsert(target.id, target.case_id, c)
    counts = fd.counts_by_state(target.id)
    ctx.emit("findings.done", payload={"candidates": len(cands), "states": counts,
                                       "library_sites_skipped": dropped})
    ctx.progress(pct=100, msg="%d candidate findings" % len(cands))
    return {}


def register() -> None:
    register_stage(DETECT_STAGE, detect_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION)


def enqueue_detect(queue, target, *, force: bool = True):
    # force by default: re-detect after re-analysis should re-run rather than cache-hit
    return queue.enqueue(target.case_id, DETECT_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         force=force)
