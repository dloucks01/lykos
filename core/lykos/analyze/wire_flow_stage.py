"""`wire_flow` stage — run the wire-value→dangerous-use detector over the case source (depth add).

Wires wire_flow.find_wire_flows into the pipeline so the pattern behind every confirmed FreeRDP bug
(a wire-read value reaching a divisor / index / seek / alloc-size / memcpy-length with no bound) is
detected across the whole tree on every run, not only where fuzzing happens to reach. Files a
candidate finding per flow (detector 'wire_flow'); these join the same grounding/triage/confirmation
ladder. Cheap, offline string analysis.
"""
from __future__ import annotations

import io
import tarfile
import os

from ..db.dao import FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .source_lookup import source_project_for
from . import wire_flow

WIRE_FLOW_STAGE = "wire_flow"
TOOL = "lykos.wire_flow"
TOOL_VERSION = "1"
_CWE_SEV = {"CWE-369": "medium", "CWE-129": "high", "CWE-125": "medium",
            "CWE-190": "medium", "CWE-120": "high"}
_EXCL = ("third-party", "third_party", "external", "/test/", "/tests/", "/_")


def _source_root(ctx, target):
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        return None
    root = ctx.scratch() / "wireflow-src"
    if not root.exists():
        root.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                              mode="r:gz") as tf:
                for m in tf.getmembers():
                    if m.isfile() and not m.name.startswith("/") and ".." not in m.name:
                        tf.extract(m, root)
        except Exception:                                # noqa: BLE001
            return None
    return root


def wire_flow_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("wire_flow requires a target_id")
    root = _source_root(ctx, target)
    if root is None:
        return {"metrics": {"wire_flow": "no source project"}}
    fd = FindingDAO(ctx.conn)
    n = 0
    by_use: dict = {}
    for dp, _d, files in os.walk(str(root)):
        for fn in files:
            if not fn.endswith((".c", ".h")):
                continue
            p = os.path.join(dp, fn)
            if any(x in p.replace(os.sep, "/") for x in _EXCL):
                continue
            try:
                src = open(p, "r", errors="ignore").read()
            except OSError:
                continue
            rel = os.path.relpath(p, str(root))
            for w in wire_flow.find_wire_flows(src):
                by_use[w.use] = by_use.get(w.use, 0) + 1
                fd.upsert(target.id, target.case_id, {
                    "cwe": w.cwe, "severity": _CWE_SEV.get(w.cwe, "medium"), "state": "candidate",
                    "detector": "wire_flow", "stage": WIRE_FLOW_STAGE,
                    "title": f"Wire value -> {w.use} without a bound: {w.var} in {w.function}()",
                    "dedup_key": f"wire_flow:{w.cwe}:{rel}:{w.function}:{w.var}:{w.use}",
                    "evidence": [{"channel": "source", "detail": f"{rel}: {w.function}() uses wire-read "
                                  f"'{w.var}' as a {w.use} with no bound check -- {w.line_hint}"}]})
                n += 1
    return {"metrics": {"wire_flow_candidates": n, "by_use": by_use}}


register_stage(WIRE_FLOW_STAGE, wire_flow_stage, resource_class="quick",
               tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_wire_flow(queue, target, *, force: bool = True):
    return queue.enqueue(target.case_id, WIRE_FLOW_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
