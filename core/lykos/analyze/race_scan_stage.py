"""`race_scan` stage — double-fetch (CWE-367) + uninitialized-pointer (CWE-824) over the case source."""
from __future__ import annotations
import io, os, tarfile
from ..db.dao import FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .source_lookup import source_project_for
from . import race_scan
RACE_STAGE = "race_scan"; TOOL = "lykos.race_scan"; TOOL_VERSION = "1"
_EXCL = ("third-party", "third_party", "external", "/test/", "/tests/", "/_")


def _root(ctx, target):
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        return None
    r = ctx.scratch() / "race-src"
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


def race_scan_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("race_scan requires a target_id")
    root = _root(ctx, target)
    if root is None:
        return {"metrics": {"race_scan": "no source project"}}
    fd = FindingDAO(ctx.conn); df = up = 0
    for dp, _d, fs in os.walk(str(root)):
        for fn in fs:
            if not fn.endswith(".c"):
                continue
            p = os.path.join(dp, fn)
            if any(x in p.replace(os.sep, "/") for x in _EXCL):
                continue
            try:
                src = open(p, errors="ignore").read()
            except OSError:
                continue
            rel = os.path.relpath(p, str(root))
            for b in race_scan.find_double_fetch(src):
                fd.upsert(target.id, target.case_id, {
                    "cwe": "CWE-367", "severity": "medium", "state": "candidate",
                    "detector": "double_fetch", "stage": RACE_STAGE,
                    "title": f"double-fetch (TOCTOU): '{b.field}' re-read between check and use in {b.function}()",
                    "dedup_key": f"df:{rel}:{b.function}:{b.field}:{b.use_line}",
                    "evidence": [{"channel": "source",
                                  "detail": f"{rel}: {b.function}() checks '{b.field}' (line {b.check_line}) then "
                                            f"re-reads it for a dangerous use (line {b.use_line}): {b.hint}"}]})
                df += 1
            for b in race_scan.find_uninit_ptr(src):
                fd.upsert(target.id, target.case_id, {
                    "cwe": "CWE-824", "severity": "medium", "state": "candidate",
                    "detector": "uninit_ptr", "stage": RACE_STAGE,
                    "title": f"uninitialized pointer '{b.ptr}' dereferenced in {b.function}()",
                    "dedup_key": f"up:{rel}:{b.function}:{b.ptr}:{b.use_line}",
                    "evidence": [{"channel": "source",
                                  "detail": f"{rel}: {b.function}() declares '{b.ptr}' (line {b.decl_line}) with no "
                                            f"initializer and dereferences it (line {b.use_line}): {b.hint}"}]})
                up += 1
    return {"metrics": {"double_fetch": df, "uninit_ptr": up}}


register_stage(RACE_STAGE, race_scan_stage, resource_class="quick", tool=TOOL,
               tool_version=TOOL_VERSION, timeout=300)


def enqueue_race_scan(queue, target, *, force=True):
    return queue.enqueue(target.case_id, RACE_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
