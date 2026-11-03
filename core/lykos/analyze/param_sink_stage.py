"""`param_sink` stage — interprocedural wire→param-sink flows as findings (static-depth, precise).

Runs param_sink.confirmed_flows over the case source: a function that uses a parameter/field as a
divisor/index/seek/size/length without self-validation, AND a caller that passes a wire-derived
argument to that parameter. Files only those CONFIRMED interprocedural flows (325 raw param-sinks on
FreeRDP filtered to ~7), so it adds cross-function depth the intraprocedural detectors miss without
flooding. Cheap offline string analysis.
"""
from __future__ import annotations

import io
import os
import tarfile

from ..db.dao import FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .source_lookup import source_project_for
from . import param_sink

PARAM_SINK_STAGE = "param_sink"
TOOL = "lykos.param_sink"
TOOL_VERSION = "1"
_SEV = {"CWE-369": "medium", "CWE-129": "high", "CWE-125": "medium", "CWE-190": "medium", "CWE-120": "high"}
_EXCL = ("third-party", "third_party", "external", "/test/", "/tests/", "/_")


def _source_root(ctx, target):
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        return None
    root = ctx.scratch() / "paramsink-src"
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


def param_sink_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("param_sink requires a target_id")
    root = _source_root(ctx, target)
    if root is None:
        return {"metrics": {"param_sink": "no source project"}}
    files = {}
    for dp, _d, fs in os.walk(str(root)):
        for fn in fs:
            if not fn.endswith(".c"):
                continue
            p = os.path.join(dp, fn)
            if any(x in p.replace(os.sep, "/") for x in _EXCL):
                continue
            try:
                files[os.path.relpath(p, str(root))] = open(p, "r", errors="ignore").read()
            except OSError:
                pass
    flows = param_sink.confirmed_flows(files)
    fd = FindingDAO(ctx.conn)
    for ps, caller, fsrc in flows:
        fd.upsert(target.id, target.case_id, {
            "cwe": ps.cwe, "severity": _SEV.get(ps.cwe, "medium"), "state": "candidate",
            "detector": "param_sink", "stage": PARAM_SINK_STAGE,
            "title": f"Interprocedural wire -> {ps.use}: {ps.function}() uses unvalidated '{ps.param}'",
            "dedup_key": f"param_sink:{ps.cwe}:{fsrc}:{ps.function}:{ps.param}:{ps.use}",
            "evidence": [{"channel": "source", "detail": f"{fsrc}: {ps.function}() uses parameter "
                          f"'{ps.param}' as a {ps.use} with no self-validation; caller {caller}() passes "
                          f"a wire-derived argument. {ps.line_hint}"}]})
    return {"metrics": {"param_sink_confirmed_flows": len(flows)}}


register_stage(PARAM_SINK_STAGE, param_sink_stage, resource_class="quick",
               tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_param_sink(queue, target, *, force: bool = True):
    return queue.enqueue(target.case_id, PARAM_SINK_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
