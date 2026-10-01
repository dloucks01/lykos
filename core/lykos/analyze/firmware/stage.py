"""The `firmware_carve` stage (doc 17.5) — decompose a firmware image.

Carves the image by signature, registers each embedded ELF as a new case target (which then
triages and joins the component graph like any binary), identifies a bare-metal blob's
architecture/base/entry via the headerless loader, flags embedded private keys as findings,
and stores a decomposition report.
"""
from __future__ import annotations

import hashlib
import json

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.queue import JobQueue
from ...jobs.registry import register_stage
from ..detect.detectors import _secret
from ..ingest import enqueue_triage
from .carve import extract_components, extract_filesystems, scan_signatures
from .headerless import analyze_blob

FIRMWARE_STAGE = "firmware_carve"
TOOL = "lykos-firmware"
TOOL_VERSION = "firmware-1"


def firmware_carve_stage(ctx) -> dict:
    tdao = TargetDAO(ctx.conn)
    target = tdao.get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("firmware_carve requires a target_id (the firmware image)")
    data = ctx.content.path(target.sha256).read_bytes()

    ctx.progress(msg="scanning firmware image signatures")
    hits = scan_signatures(data)
    components = extract_components(data)
    # Real firmware stores its binaries inside a compressed root filesystem, so the raw-byte scan
    # above sees nothing. Unpack the filesystem (SquashFS/cpio) and pull the real files out.
    ctx.progress(msg="unpacking embedded filesystem(s)")
    fs_files = extract_filesystems(data)

    q = JobQueue(ctx.conn)
    registered = []

    def _register(name: str, blob: bytes, offset: int, kind: str, note: str) -> None:
        sha = ctx.put_artifact("target-blob", data=blob)
        md5 = hashlib.md5(blob).hexdigest()
        sha1 = hashlib.sha1(blob).hexdigest()
        sub = tdao.upsert(target.case_id, name, sha, md5=md5, sha1=sha1, size=len(blob))
        enqueue_triage(q, sub, force=True)       # triages + joins the component graph like any binary
        registered.append({"offset": offset, "kind": kind, "filename": name,
                           "note": note, "sha256": sha, "target_id": sub.id})

    # raw / compressed-kernel ELFs embedded directly in the image
    for comp in components:
        _register(f"{target.filename}:{comp['filename']}", comp["bytes"],
                  comp["offset"], comp["kind"], comp["note"])
    # ELF files living inside an unpacked root filesystem (the common real-world case)
    for f in fs_files:
        if f["kind"] == "elf":
            _register(f"{target.filename}:fs@0x{f['offset']:x}/{f['path']}", f["bytes"],
                      f["offset"], "elf", f"ELF in {f['fs']} rootfs ({len(f['bytes'])} bytes)")

    # bare-metal blob (no ELF header) -> headerless architecture/base/entry identification
    headerless = None
    if (target.file_type or "").lower() != "elf":
        headerless = analyze_blob(data)

    # embedded secrets -> findings. Private keys appearing as raw magic in the image (CWE-321)...
    fd = FindingDAO(ctx.conn)
    key_hits = [h for h in hits if h["type"] in ("privkey", "cert")]
    for h in key_hits:
        if h["type"] != "privkey":
            continue
        fd.upsert(target.id, target.case_id, {
            "cwe": "CWE-321", "title": f"Embedded private key in firmware ({h['description']})",
            "severity": "high", "state": "corroborated", "confidence": 0.7,
            "detector": "firmware_carve", "site_addr": f"0x{h['offset']:x}",
            "function_addr": None, "dedup_key": f"fw-key:{h['offset']}",
            "evidence": [{"channel": "firmware", "detail":
                          f"{h['description']} carved at offset 0x{h['offset']:x}"}]})
    # ...and secrets hiding in filesystem files -- private keys, AWS keys, hard-coded creds. A
    # secret sitting in a shipped config/key file is as real as one baked into a binary.
    fs_secrets = 0
    seen_secret: set = set()
    for f in fs_files:
        text = f["bytes"][:1 << 20].decode("utf-8", "replace")
        for line in text.splitlines()[:5000]:
            hit = _secret(line)
            if not hit:
                continue
            cwe, sev, title = hit
            dk = (cwe, f["path"])
            if dk in seen_secret:
                continue
            seen_secret.add(dk)
            fs_secrets += 1
            fd.upsert(target.id, target.case_id, {
                "cwe": cwe, "title": f"{title} in firmware file {f['path']}",
                "severity": sev, "state": "corroborated", "confidence": 0.75,
                "detector": "firmware_carve", "site_addr": None, "function_addr": None,
                "dedup_key": f"fw-fs-secret:{cwe}:{f['path']}",
                "evidence": [{"channel": "firmware", "detail":
                              f"{title} in {f['fs']} rootfs file {f['path']!r}"}]})

    report = {
        "image": target.filename, "size": len(data),
        "signatures": hits, "components": registered, "headerless": headerless,
        "fs_files": len(fs_files),
        "embedded_keys": len([h for h in key_hits if h["type"] == "privkey"]) + fs_secrets,
    }
    report_sha = ctx.put_artifact("firmware-decomposition",
                                  data=json.dumps(report, indent=2, default=str).encode(),
                                  meta={"components": len(registered)})

    ctx.emit("firmware.done", payload={
        "signatures": len(hits), "components": len(registered),
        "arch": (headerless or {}).get("arch"), "method": (headerless or {}).get("method"),
        "base_addr": (headerless or {}).get("base_addr"),
        "keys": report["embedded_keys"], "report": report_sha})
    ctx.progress(pct=100, msg=(f"carved {len(registered)} component(s), {len(hits)} signature "
                               f"hit(s)"
                               + (f"; {headerless['arch']} via {headerless['method']}"
                                  if headerless and headerless.get("arch") else "")))
    return {"output_shas": [report_sha], "output_kind": "firmware-decomposition"}


def register() -> None:
    register_stage(FIRMWARE_STAGE, firmware_carve_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=600)


def enqueue_firmware(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, FIRMWARE_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
