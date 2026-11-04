"""`sibling_guard` stage -- files the missing-sibling-validation findings
(sibling_guard.find_missing_sibling_guards) over the case source: a handler that omits a bounds/
validation guard a majority of its dispatch-family siblings make (the copy-paste variant bug, e.g.
CVE-2026-26955's missing is_within_surface). Medium-confidence leads ranked by the asymmetry; cheap,
offline, non-fuzzing. See sibling_guard.py.
"""
from __future__ import annotations
import io, os, tarfile
from ..db.dao import FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .source_lookup import source_project_for
from . import sibling_guard

SIBLING_GUARD_STAGE = "sibling_guard"; TOOL = "lykos.sibling_guard"; TOOL_VERSION = "1"
_EXCL = ("third-party", "third_party", "external", "/test/", "/tests/", "/_lykos", "/_qlbuild")


def _extract(ctx, target):
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        return None
    r = ctx.scratch() / "sibguard-src"
    if not r.exists():
        r.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                              mode="r:gz") as tf:
                for m in tf.getmembers():
                    if m.isfile() and not m.name.startswith("/") and ".." not in m.name:
                        tf.extract(m, r)
        except Exception:                                    # noqa: BLE001
            return None
    return r


def guard_gap_sibling_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("sibling_guard requires a target_id")
    root = _extract(ctx, target)
    if root is None:
        return {"metrics": {"sibling_guard": "no source project"}}
    fd = FindingDAO(ctx.conn); n = 0
    for dp, _d, fs in os.walk(str(root)):
        if any(x in dp.replace(os.sep, "/") for x in _EXCL):
            continue
        for fn in fs:
            if not fn.endswith((".c", ".cc", ".cpp")):
                continue
            p = os.path.join(dp, fn)
            try:
                text = open(p, errors="ignore").read()
            except OSError:
                continue
            rel = os.path.relpath(p, str(root))
            for g in sibling_guard.find_missing_sibling_guards(text):
                used = ", ".join(s.split("_")[-1] for s in g["used_by"][:6])
                fd.upsert(target.id, target.case_id, {
                    "cwe": "CWE-20", "severity": "medium", "state": "candidate",
                    "detector": "sibling_guard", "stage": SIBLING_GUARD_STAGE,
                    "title": f"Missing sibling validation: {g['fn']}() omits '{g['missing']}' that "
                             f"{len(g['used_by'])}/{g['family_size']} siblings enforce",
                    "dedup_key": f"sibguard:{rel}:{g['fn']}:{g['missing']}",
                    "evidence": [{"channel": "sibling-guard",
                                  "detail": f"{rel}:{g['line']}: {g['fn']}() in the '{g['family']}_*' "
                                            f"handler family does NOT gate on '{g['missing']}', but "
                                            f"{len(g['used_by'])}/{g['family_size']} siblings do "
                                            f"({used}) -- a copy-paste variant omission lets unchecked "
                                            f"input reach the sink (confidence {g['confidence']})."}]})
                n += 1
    return {"metrics": {"sibling_guard_findings": n}}


register_stage(SIBLING_GUARD_STAGE, guard_gap_sibling_stage, resource_class="quick", tool=TOOL,
               tool_version=TOOL_VERSION, timeout=300)


def enqueue_sibling_guard(queue, target, *, force=True):
    return queue.enqueue(target.case_id, SIBLING_GUARD_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
