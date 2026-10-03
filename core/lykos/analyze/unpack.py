"""The `unpack` stage — statically unpack a runtime-packed executable so the rest of the pipeline
analyses its REAL code, not the compressed stub.

A UPX-packed binary is, to every machine-code stage, a tiny decompressor plus an opaque high-entropy
blob: disassembly finds a few stub functions, the detectors see nothing, and the CVE banner scan
misses the statically-linked libraries hidden in the compressed image. Triage already flags the
packing (high entropy + the `UPX!` marker); this stage acts on it -- it decompresses the image and
registers the UNPACKED binary as a child target, which then flows through triage and every analysis
stage like any other binary (the same container -> child-target shape as `firmware_carve`).

UPX is the dominant real-world packer and round-trips losslessly via its own `-d`, so this is exact,
not a heuristic reconstruction. Other packers are detected (triage) but not yet unpacked here; the
stage says so rather than silently doing nothing."""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from ..jobs.registry import register_stage

UNPACK_STAGE = "unpack"
TOOL = "unpack"
TOOL_VERSION = "unpack-1"
_SCAN = 1 << 16                                  # bytes to scan at each end for the UPX marker


def is_upx(data: bytes) -> bool:
    """True when `data` is a UPX-packed executable. Modern UPX strips the `UPX0`/`UPX1` section
    names, so the reliable signal is the `UPX!` magic that bookends the packed stream (it appears in
    the l_info header near the start and again in the trailing p_info). Require it at BOTH ends to
    separate a packed image from a file that merely mentions the string."""
    if len(data) < 64:
        return False
    # The `UPX!` magic occurs at least twice in a packed image (the l_info header near the start and
    # the packed-stream trailer near the end). Count occurrences in the actual bytes -- bounded to
    # the two ends for a large file, but NOT by concatenating overlapping windows (which would double-
    # count a single marker in a small file and misclassify it).
    if len(data) <= 2 * _SCAN:
        n = data.count(b"UPX!")
    else:
        n = data[:_SCAN].count(b"UPX!") + data[-_SCAN:].count(b"UPX!")
    names = b"UPX0" in data[:_SCAN] or b"UPX1" in data[:_SCAN]   # older UPX keeps section names
    return n >= 2 or names


def upx_available() -> Optional[str]:
    return shutil.which("upx")


def upx_unpack(data: bytes, *, timeout: int = 60) -> tuple[Optional[bytes], str]:
    """Decompress a UPX image with the `upx -d` tool. Returns (unpacked_bytes, note); the bytes are
    None with a reason when the tool is missing, the input is not UPX, or decompression fails. UPX
    decompression only reads its own container and writes the original file, so it is safe to run on
    an untrusted sample; it still runs under a timeout and in a throwaway directory."""
    if not is_upx(data):
        return None, "not UPX-packed"
    tool = upx_available()
    if not tool:
        return None, "upx tool not installed (detected packing, cannot unpack)"
    d = Path(tempfile.mkdtemp(prefix="lykos-unpack-"))
    try:
        src, dst = d / "packed.bin", d / "unpacked.bin"
        src.write_bytes(data)
        try:
            proc = subprocess.run([tool, "-d", "-q", "-o", str(dst), str(src)],
                                  capture_output=True, timeout=timeout,
                                  stdin=subprocess.DEVNULL, check=False)
        except subprocess.TimeoutExpired:
            return None, "upx -d timed out"
        if proc.returncode != 0 or not dst.exists():
            err = (proc.stderr or proc.stdout or b"").decode("utf-8", "replace").strip()[:200]
            return None, f"upx -d failed: {err or 'unknown error'}"
        out = dst.read_bytes()
        if not out or out == data:
            return None, "upx -d produced no change"
        return out, f"unpacked {len(data)} -> {len(out)} bytes via upx -d"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def looks_packed(store, target) -> bool:
    """Cheap pre-check the orchestrator uses to decide whether to run the unpack stage, without a
    full read: inspect the head and tail of the target's bytes for the UPX marker."""
    try:
        data = store.content.path(target.sha256).read_bytes()
    except Exception:                                        # noqa: BLE001
        return False
    return is_upx(data)


def unpack_stage(ctx) -> dict:
    """Unpack a packed target into a child target. Self-gating: a no-op (and cheap) on an unpacked
    binary, so the orchestrator can run it on any target. On a UPX image it decompresses and
    registers the result as a child target that triage + every analysis stage then process."""
    from ..db.dao import FindingDAO, TargetDAO
    from ..jobs.queue import JobQueue
    from .ingest import enqueue_triage

    tdao = TargetDAO(ctx.conn)
    target = tdao.get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("unpack requires a target_id")
    data = ctx.content.path(target.sha256).read_bytes()

    if not is_upx(data):
        ctx.progress(pct=100, msg="not a packed image (nothing to unpack)")
        return {"metrics": {"packed": False}}

    ctx.progress(msg="UPX-packed image detected; decompressing")
    out, note = upx_unpack(data)
    if out is None:
        # detected packing but could not unpack -- say so; do not pretend the packed bytes are code
        fd = FindingDAO(ctx.conn)
        fd.upsert(target.id, target.case_id, {
            "cwe": "CWE-1066",                               # inadequately analysable artifact
            "title": "Packed executable could not be unpacked",
            "severity": "info", "state": "candidate", "confidence": 0.5, "detector": "unpack",
            "site_addr": None, "function_addr": None, "dedup_key": f"unpack-fail:{target.id}",
            "evidence": [{"channel": "unpack", "detail": note}]})
        ctx.progress(pct=100, msg=note)
        return {"metrics": {"packed": True, "unpacked": False, "reason": note}}

    sha = ctx.put_artifact("target-blob", data=out)
    name = f"{target.filename}:unpacked"
    sub = tdao.upsert(target.case_id, name, sha,
                      md5=hashlib.md5(out).hexdigest(), sha1=hashlib.sha1(out).hexdigest(),
                      size=len(out))
    enqueue_triage(JobQueue(ctx.conn), sub, force=True)      # triage + full pipeline, like any binary
    fd = FindingDAO(ctx.conn)
    fd.upsert(target.id, target.case_id, {
        "cwe": "CWE-1066", "title": "Runtime-packed executable (UPX) — unpacked for analysis",
        "severity": "info", "state": "corroborated", "confidence": 0.95, "detector": "unpack",
        "site_addr": None, "function_addr": None, "dedup_key": f"unpack:{target.id}",
        "evidence": [{"channel": "unpack",
                      "detail": f"{note}; analysis continues on child target {name} ({sha[:12]})"}]})
    ctx.emit("unpack.done", payload={"packed": True, "unpacked": True, "child_target_id": sub.id,
                                     "child_sha256": sha, "orig_size": len(data), "unpacked_size": len(out)})
    ctx.progress(pct=100, msg=f"{note}; registered child target {name}")
    return {"output_shas": [sha], "output_kind": "target-blob",
            "metrics": {"packed": True, "unpacked": True, "child_target_id": sub.id,
                        "orig_size": len(data), "unpacked_size": len(out)}}


def register() -> None:
    register_stage(UNPACK_STAGE, unpack_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_unpack(queue, target, *, force: bool = True):
    return queue.enqueue(target.case_id, UNPACK_STAGE, target_id=target.id, force=force)
