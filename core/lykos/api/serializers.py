"""Model->dict serializers and shared route constants for the analyst API.

Pure, self-free functions split out of `server.py` so both the Handler (routing) and the
endpoint mixin can share the one projection of each row into JSON.
"""
from __future__ import annotations


_INGEST = "ingest_triage"


_REPORT_FORMATS = {"html", "pdf", "sarif", "json"}


def _csv(vals):
    """Parse a repeated/CSV query param into a list, or None if absent."""
    if not vals:
        return None
    out = []
    for v in vals:
        out += [x for x in v.split(",") if x]
    return out or None


def _case(c):
    return {"id": c.id, "name": c.name, "notes": c.notes,
            "engagement_ref": c.engagement_ref, "created_at": c.created_at}


def _target(t):
    return {"id": t.id, "case_id": t.case_id, "filename": t.filename, "sha256": t.sha256,
            "md5": t.md5, "sha1": t.sha1, "size": t.size, "file_type": t.file_type,
            "arch": t.arch, "bits": t.bits, "endianness": t.endianness,
            "linking": t.linking, "stripped": t.stripped, "mitigations": t.mitigations,
            "entropy": t.entropy, "toolchain_hint": t.toolchain_hint}


def _poc(x):
    # finding_id links the PoC to the defect it proves. Without it the workbench cannot tell
    # which finding a bundle belongs to and would offer the same download on every card.
    return {"id": x.id, "finding_id": x.finding_id, "level": x.level, "verified": x.verified,
            "signal": x.signal_name, "input_sha": x.input_sha, "bundle_sha": x.bundle_sha,
            "created_at": x.created_at}


def _dynresult(d):
    # argv and fault_pc are recorded and were not projected. Both matter to a reader looking
    # at a crash row: argv is HOW the input was delivered -- now that a target may need
    # `-c @@` to run at all, "which invocation produced this" is not a detail -- and fault_pc
    # is WHERE it faulted, which is what the dedup key is built from, so two rows that look
    # identical are distinguishable only by a field the API did not return.
    return {"id": d.id, "crashed": d.crashed, "timed_out": d.timed_out,
            "signal": d.signal_name, "exit_code": d.exit_code, "isolation": d.isolation,
            "input_mode": d.input_mode, "input_sha": d.input_sha,
            "argv": list(getattr(d, "argv", None) or []),
            "fault_pc": (hex(d.fault_pc) if getattr(d, "fault_pc", None) else None),
            "duration_ms": d.duration_ms, "note": d.note, "created_at": d.created_at}


def _finding(f, sites=None, site_count=None, proven=0):
    """Serialize a finding. `sites` is the list of places the defect occurs; `site_count` is
    the cheap aggregate for list views. A finding is a DEFECT -- the sites are evidence."""
    d = {"id": f.id, "target_id": f.target_id, "case_id": f.case_id, "cwe": f.cwe,
         "title": f.title, "severity": f.severity, "state": f.state,
         "confidence": f.confidence, "function_addr": f.function_addr,
         "site_addr": f.site_addr, "detector": f.detector, "evidence": f.evidence,
         # the dedup key lets the UI fold an unlocated crash into its located, analysed twin
         "dedup_key": f.dedup_key}
    if sites is not None:
        d["sites"] = sites
    d["site_count"] = len(sites) if sites is not None else (site_count or 0)
    # How many of those places are individually PROVEN. A poc-backed finding with 99 sites and
    # one proven occurrence must not read like one where all 99 are.
    d["proven_sites"] = len([s for s in sites if s.get("state") == "poc-backed"]) \
        if sites is not None else (proven or 0)
    return d


def _call_edge(e):
    return {"src_addr": e.src_addr, "site_addr": e.site_addr, "dst_addr": e.dst_addr,
            "dst_name": e.dst_name, "external": e.external}


def _stringref(x):
    return {"addr": x.addr, "value": x.value, "xrefs": x.xrefs}


def _function(f, code=False):
    d = {"id": f.id, "target_id": f.target_id, "addr": f.addr, "name": f.name,
         "size": f.size, "blocks": f.blocks, "edges": f.edges,
         "signature": getattr(f, "signature", None)}
    if code:
        d["decompiled"] = f.decompiled
        d["frame"] = getattr(f, "frame", None)   # params + stack-var layout (offsets/sizes/buffers)
        d["ir"] = f.ir          # {blocks:[{addr,instructions:[{addr,text,pcode:[...]}],succ}]}
    return d


def _run(r, *, crashes=None):
    d = {"id": r.id, "case_id": r.case_id, "target_id": r.target_id, "stage": r.stage,
         "status": r.status, "error": r.error, "attempts": r.attempts,
         "cache_key": r.cache_key, "created_at": r.created_at,
         "started_at": r.started_at, "ended_at": r.ended_at}
    if crashes is not None:
        # the run's YIELD, so a `DONE` row is not read as success whether or not it found anything
        # (doc 30 P5.5): the number of crashing executions this run recorded (0 for a stage that
        # does not run the target).
        d["crashes"] = crashes
    return d


def _event(e):
    return {"id": e.id, "type": e.type, "level": e.level, "case_id": e.case_id,
            "run_id": e.run_id, "ts": e.ts, "payload": e.payload}
