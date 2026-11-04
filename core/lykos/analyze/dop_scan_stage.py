"""`dop_scan` stage — data-oriented (DOP) hijack-surface discovery over the case source.

Files, as findings, the SECURITY-DECISION variables a data-only write could flip (dop.find_dop_targets):
`if (<auth/admin/allow-named var>) { <privileged action> }` gates. These are not bugs on their own --
they are the TARGET a memory write weaponizes without touching control flow (the attack-path
WRITE->AUTH DOP edge). CWE-840 (business-logic / improper-authorization surface). Cheap, offline.
"""
from __future__ import annotations
import io, os, tarfile
from ..db.dao import FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .source_lookup import source_project_for
from .poc import dop

DOP_SCAN_STAGE = "dop_scan"; TOOL = "lykos.dop_scan"; TOOL_VERSION = "1"
_EXCL = ("third-party", "third_party", "external", "/test/", "/tests/", "/_")


def _root(ctx, target):
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        return None
    r = ctx.scratch() / "dop-src"
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


def dop_scan_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("dop_scan requires a target_id")
    root = _root(ctx, target)
    if root is None:
        return {"metrics": {"dop_scan": "no source project"}}
    fd = FindingDAO(ctx.conn); n = 0
    for dp, _d, fs in os.walk(str(root)):
        for fn in fs:
            if not fn.endswith((".c", ".cc", ".cpp")):
                continue
            p = os.path.join(dp, fn)
            if any(x in p.replace(os.sep, "/") for x in _EXCL):
                continue
            try:
                src = open(p, errors="ignore").read()
            except OSError:
                continue
            rel = os.path.relpath(p, str(root))
            for t in dop.find_dop_targets(src):
                fd.upsert(target.id, target.case_id, {
                    "cwe": "CWE-840", "severity": "medium", "state": "candidate",
                    "detector": "dop_target", "stage": DOP_SCAN_STAGE,
                    "title": f"data-only hijack surface: decision var '{t['var']}' gates a privileged path",
                    "dedup_key": f"dop:{rel}:{t['var']}:{t['line']}",
                    "evidence": [{"channel": "dop-target",
                                  "detail": f"{rel}:{t['line']}: a write that flips '{t['var']}' takes the "
                                            f"privileged branch with no control-flow hijack (DOP). {t['hint']}"}]})
                n += 1
    return {"metrics": {"dop_targets": n}}


register_stage(DOP_SCAN_STAGE, dop_scan_stage, resource_class="quick", tool=TOOL,
               tool_version=TOOL_VERSION, timeout=300)


def enqueue_dop_scan(queue, target, *, force=True):
    return queue.enqueue(target.case_id, DOP_SCAN_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
