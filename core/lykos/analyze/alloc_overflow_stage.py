"""`alloc_overflow` stage -- files the allocation-size integer-overflow findings
(alloc_overflow.find_alloc_overflows) over the case source: a wire-derived product/sum used as an
alloc/copy size with no overflow guard (CWE-190 -> CWE-787). Precise sibling of guard_gap for the
second-largest FreeRDP CVE class (e.g. the 2024 clear/planar codec overflows). Cheap, offline.
"""
from __future__ import annotations
import io, os, tarfile
from ..db.dao import FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .source_lookup import source_project_for
from . import alloc_overflow

ALLOC_OVERFLOW_STAGE = "alloc_overflow"; TOOL = "lykos.alloc_overflow"; TOOL_VERSION = "1"
_EXCL = ("third-party", "third_party", "external", "/test/", "/tests/", "/_lykos", "/_qlbuild",
         "/winpr/libwinpr/crt/")


def _extract(ctx, target):
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        return None
    r = ctx.scratch() / "allocov-src"
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


def alloc_overflow_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("alloc_overflow requires a target_id")
    root = _extract(ctx, target)
    if root is None:
        return {"metrics": {"alloc_overflow": "no source project"}}
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
            for g in alloc_overflow.find_alloc_overflows(text):
                fd.upsert(target.id, target.case_id, {
                    "cwe": g["cwe"], "severity": "high", "state": "candidate",
                    "detector": "alloc_overflow", "stage": ALLOC_OVERFLOW_STAGE,
                    "title": f"Integer overflow in allocation size ({g['kind']}) in {g['fn']}()",
                    "dedup_key": f"allocov:{rel}:{g['fn']}:{g['size'][:32]}",
                    "evidence": [{"channel": "alloc-overflow",
                                  "detail": f"{rel}:{g['line']}: {g['kind']} size '{g['size']}' is a "
                                            f"product/sum of wire-controlled values with no overflow "
                                            f"guard (no 64-bit widening / builtin-overflow / division "
                                            f"check) -- a 32-bit wrap undersizes the buffer and the "
                                            f"following writes go out of bounds."}]})
                n += 1
    return {"metrics": {"alloc_overflow_findings": n}}


register_stage(ALLOC_OVERFLOW_STAGE, alloc_overflow_stage, resource_class="quick", tool=TOOL,
               tool_version=TOOL_VERSION, timeout=300)


def enqueue_alloc_overflow(queue, target, *, force=True):
    return queue.enqueue(target.case_id, ALLOC_OVERFLOW_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
