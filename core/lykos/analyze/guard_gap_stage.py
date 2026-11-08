"""`guard_gap` stage -- files the attacker-controlled-length-without-a-bounds-guard findings
(guard_gap.find_guard_gaps) over the case source. These are the genuine missing-`CheckAndLogRequired
Length` over-read/over-write bugs that the volume length detectors bury under false positives; a
variant-corroborated one (a sibling handler guards the same field -- a static heuristic, still a
candidate) is high severity. Cheap, offline, non-fuzzing. See guard_gap.py for the mechanism.
"""
from __future__ import annotations
import io, os, tarfile
from ..db.dao import FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .source_lookup import source_project_for
from . import guard_gap

GUARD_GAP_STAGE = "guard_gap"; TOOL = "lykos.guard_gap"; TOOL_VERSION = "1"
_EXCL = ("third-party", "third_party", "external", "/test/", "/tests/", "/_lykos", "/_qlbuild",
         "/winpr/libwinpr/crt/")


def _extract(ctx, target):
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        return None
    r = ctx.scratch() / "guardgap-src"
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


def _sources(root):
    out = {}
    for dp, _d, fs in os.walk(str(root)):
        if any(x in dp.replace(os.sep, "/") for x in _EXCL):
            continue
        for fn in fs:
            if fn.endswith((".c", ".h", ".cc", ".cpp")):
                p = os.path.join(dp, fn)
                try:
                    out[p] = open(p, errors="ignore").read()
                except OSError:
                    pass
    return out


def guard_gap_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("guard_gap requires a target_id")
    root = _extract(ctx, target)
    if root is None:
        return {"metrics": {"guard_gap": "no source project"}}
    srcs = _sources(root)
    guards = guard_gap.discover_guards(srcs)
    fd = FindingDAO(ctx.conn); n = 0; vc_n = 0
    for p, text in srcs.items():
        if not p.endswith((".c", ".cc", ".cpp")):
            continue
        rel = os.path.relpath(p, str(root))
        for g in guard_gap.find_guard_gaps(text, guards):
            vc = guard_gap.variant_sibling(text, g, guards)   # static corroboration, not a confirm
            vc_n += 1 if vc else 0
            sev = "high" if vc else "medium"
            detail = (f"{rel}:{g['line']}: '{g['var']}' is read off the wire in {g['fn']}() and "
                      f"used as a {g['kind']} bound with no Stream_CheckAndLogRequiredLength (or "
                      f"project guard wrapper) on it -- attacker-controlled {g['kind']} past the "
                      f"stream buffer.")
            if vc:
                detail += (f" Variant-corroborated (sibling {vc}() guards the same field "
                           f"'{g['base']}'): the omission is likely a copy-paste defect rather than "
                           f"an intentional read. Static heuristic only -- no execution evidence.")
            fd.upsert(target.id, target.case_id, {
                "cwe": g["cwe"], "severity": sev, "state": "candidate",
                "detector": "guard_gap", "stage": GUARD_GAP_STAGE,
                "title": f"Missing stream-length guard: '{g['base']}' bounds a {g['kind']} in "
                         f"{g['fn']}()" + (" (variant-corroborated)" if vc else ""),
                "dedup_key": f"guardgap:{rel}:{g['fn']}:{g['base']}:{g['kind']}",
                "evidence": [{"channel": "guard-gap", "detail": detail}]})
            n += 1
    return {"metrics": {"guard_gap_findings": n, "guard_gap_variant_corroborated": vc_n,
                        "guard_wrappers": len(guards)}}


register_stage(GUARD_GAP_STAGE, guard_gap_stage, resource_class="quick", tool=TOOL,
               tool_version=TOOL_VERSION, timeout=300)


def enqueue_guard_gap(queue, target, *, force=True):
    return queue.enqueue(target.case_id, GUARD_GAP_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
