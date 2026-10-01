"""Phase 6/A — the `synthesize_secret` stage: turn a *static* hard-coded-secret finding
(CWE-798 / CWE-321) into a packaged, self-verifying PoC — **without executing the target**.

Every other poc-backed finding until now traced to a crash the pipeline *reproduced*; a
hard-coded credential needs no crash and no fuzzing — it is already sitting in the binary. This
stage takes the secrets the static detector flags (same `_secret()` logic, so the dedup keys
match and the existing finding is *promoted*, not duplicated), locates each one's concrete byte
offset in the file, **verifies** it by re-extracting those exact bytes from the binary, and
packages a self-contained PoC bundle: the binary, the extracted secret(s), and a pure-stdlib
offline re-extractor that any analyst can run to independently recover the credential from the
binary alone. That extractability *is* the vulnerability, so the demonstrating artifact is the
secret itself — the deterministic analog of a crash reproducer.

Deterministic, offline clean, and safe (it only reads the file — it never runs the
target). Honest limit: it proves the credential is embedded and recoverable; whether that
credential is still live on a real service is out of scope (rotate it regardless).
"""
from __future__ import annotations

from ...db.dao import FindingDAO, PocDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from ..detect.detectors import _secret  # the exact static-detection predicate (parity)
from . import bundle

SECRET_STAGE = "synthesize_secret"
TOOL = "secret-poc"
TOOL_VERSION = "secret-poc-1"


def _file_offset(blob: bytes, value: str):
    """The byte offset of the secret in the file, so the reproducer can seek to it. Match the
    printable prefix (private keys span many lines / the DB value may be truncated)."""
    if not value:
        return None
    needle = value.encode("latin-1", "replace")
    for probe in (needle, needle[:64], needle[:32], needle.split(b"\n", 1)[0]):
        if len(probe) >= 6:
            i = blob.find(probe)
            if i >= 0:
                return i
    return None


def _cstr_at(blob: bytes, off: int) -> bytes:
    end = blob.find(b"\x00", off)
    return blob[off:(end if end >= 0 else len(blob))]


def secret_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("synthesize_secret requires a target_id")

    strings = StringDAO(ctx.conn).list_by_target(target.id)
    if not strings:
        ctx.emit("secret.done", payload={"ok": False, "packaged": 0,
                 "note": "no strings recovered — run Decompile (disassemble) first so the "
                         "hard-coded-secret detector has strings to work from"})
        ctx.progress(pct=100, msg="no strings to package a secret from")
        return {}

    blob = ctx.content.path(target.sha256).read_bytes()

    # Re-run the static predicate so this stage is self-contained and its dedup keys line up
    # exactly with detect_cwe's `hardcoded_secrets` (which promotes the same finding).
    secrets, seen = [], set()
    for s in strings:
        hit = _secret(s.value or "")
        if not hit:
            continue
        cwe, sev, title = hit
        dedup = f"{cwe}:{s.addr}"
        if dedup in seen:
            continue
        seen.add(dedup)
        off = _file_offset(blob, s.value or "")
        # Verify: re-extract from the binary at the offset and confirm it matches (deterministic,
        # no execution). Only a re-extractable secret becomes a PoC.
        verified = off is not None and (s.value or "").encode("latin-1", "replace")[:16] \
            in _cstr_at(blob, off)
        secrets.append({"value": s.value, "cwe": cwe, "severity": sev, "title": title,
                        "addr": s.addr, "dedup_key": dedup, "file_offset": off,
                        "verified": verified})

    if not secrets:
        ctx.emit("secret.done", payload={"ok": True, "packaged": 0,
                 "note": "no hard-coded secrets detected in this binary's strings"})
        ctx.progress(pct=100, msg="no hard-coded secrets to package")
        return {}

    usable = [s for s in secrets if s["verified"]]
    if not usable:
        ctx.emit("secret.done", payload={"ok": True, "packaged": 0,
                 "found": len(secrets),
                 "note": "secrets were flagged but none could be re-extracted verbatim from the "
                         "binary (wide/encoded strings) — not packaged as a PoC"})
        ctx.progress(pct=100, msg="secrets flagged but not verbatim-recoverable")
        return {}

    meta = {"target_sha256": target.sha256, "arch": target.arch, "level": "L0-secret",
            "verified": True, "tool_version": TOOL_VERSION,
            "secret_count": len(usable),
            "cwes": sorted({s["cwe"] for s in usable})}
    data = bundle.build_secret(blob, usable, meta)
    bundle_sha = ctx.put_artifact("poc-bundle", data=data,
                                  meta={"verified": True, "level": "L0-secret",
                                        "kind": "secret-extraction"})

    fd = FindingDAO(ctx.conn)
    packaged = 0
    for s in usable:
        preview = (s["value"] or "")
        preview = preview if len(preview) <= 48 else preview[:45] + "..."
        fd.upsert(target.id, target.case_id, {
            "cwe": s["cwe"], "severity": s["severity"], "detector": "secret_poc",
            "state": "poc-backed", "confidence": 0.9, "title": s["title"],
            "site_addr": s["addr"], "function_addr": None,
            "evidence": [{"channel": "poc",
                          "detail": f"secret extractable offline from the binary at file offset "
                                    f"0x{s['file_offset']:x} (no execution); value {preview!r}. "
                                    f"verified PoC bundle {bundle_sha[:12]}"}],
            "dedup_key": s["dedup_key"]})
        fid = fd.id_for_dedup(target.id, s["dedup_key"])
        poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L0-secret",
                                         verified=True, bundle_sha=bundle_sha)
        if fid:
            PocDAO(ctx.conn).set_finding(poc_id, fid)
        packaged += 1

    ctx.emit("secret.done", payload={"ok": True, "packaged": packaged, "bundle": bundle_sha,
             "level": "L0-secret",
             "secrets": [{"cwe": s["cwe"], "title": s["title"],
                          "file_offset": s["file_offset"]} for s in usable]})
    ctx.progress(pct=100, msg=f"packaged {packaged} hard-coded secret(s) into a verified PoC")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle"}


def register() -> None:
    register_stage(SECRET_STAGE, secret_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=60)


def enqueue_secret(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, SECRET_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="quick", force=force)
