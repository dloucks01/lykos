"""IT-01/03/05/18/19 + JE-26 — ingest helper and the `ingest_triage` stage.

`ingest()` stores a file content-addressed and creates/dedups its target row. The
`ingest_triage` stage reads that blob, builds the triage record, updates the target's
denormalized fields, and emits the triage JSON as an output artifact. `register()` wires
the stage into the job engine.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..db.dao import TargetDAO
from ..hashing import canonical_json, hash_all_file
from ..jobs.registry import cached_output_json, register_stage
from .triage import TOOL, TOOL_VERSION, build_triage

INGEST_TRIAGE_STAGE = "ingest_triage"


def _apply_triage_denorm(targets: TargetDAO, target_id: str, rec: dict) -> None:
    targets.update_triage(
        target_id, file_type=rec["file_type"], arch=rec["arch"], bits=rec["bits"],
        endianness=rec["endianness"], linking=rec["linking"], stripped=rec["stripped"],
        mitigations=rec["mitigations"], entropy=rec["entropy"]["overall"])


def backfill_triage_denorm(store, target_id: str, run_id: str) -> bool:
    """Recover a target row's denormalized triage columns from a triage run's cached output.

    The triage stage denormalizes arch/bits/endianness/... onto the target row from inside its
    body. On a *cache hit* the job engine clones the prior run's output artifacts to the new run
    but never re-runs the body -- so a freshly uploaded copy of an already-analyzed binary (same
    bytes, new target row, e.g. a second case) would keep NULL arch, and arch-branching stages
    (the cross-arch monitor, disassembly routing) would misread it as native. This reads the
    linked triage-json artifact and writes the columns onto the new row. Returns True if it did.
    """
    if store.targets.get(target_id).arch is not None:
        return False
    rec = cached_output_json(store, run_id)
    if isinstance(rec, dict) and "arch" in rec and "entropy" in rec:
        _apply_triage_denorm(store.targets, target_id, rec)
        return True
    return False


class NotAnalysable(ValueError):
    """A file that cannot be a target, with a reason fit to show a user."""


def ingest(store, case_id: str, path: str | Path, filename: Optional[str] = None):
    """IT-03/05: store the file (content-addressed) + create/dedup the target row.

    An empty file is refused here rather than downstream. Accepting one produced a target
    whose every triage field was null, a `detect_cwe` run that reported "done", and an advice
    panel recommending coverage-guided fuzzing -- a confident plan for nothing at all. There
    is no analysis anywhere in this platform that can say something true about zero bytes.
    """
    path = Path(path)
    info = hash_all_file(path)
    if not info["size"]:
        raise NotAnalysable(f"{filename or path.name} is empty (0 bytes) -- nothing to analyse")
    store.put_artifact(case_id, "target-blob", src=path)
    return store.targets.upsert(case_id, filename or path.name, info["sha256"],
                                md5=info["md5"], sha1=info["sha1"], size=info["size"])


def ingest_triage_stage(ctx) -> dict:
    """The registered stage. `ctx.target_id` must reference an already-ingested target."""
    targets = TargetDAO(ctx.conn)
    target = targets.get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("ingest_triage requires a target_id referencing an ingested blob")

    ctx.progress(msg="reading blob")
    blob_path = ctx.content.path(target.sha256)
    ctx.check_cancel()

    ctx.progress(msg="parsing + mitigations")
    rec = build_triage(blob_path,
                       {"sha256": target.sha256, "md5": target.md5, "sha1": target.sha1,
                        "size": target.size}, target.filename)
    ctx.check_cancel()

    # denormalize the triage subset onto the target row
    _apply_triage_denorm(targets, target.id, rec)

    sha = ctx.put_artifact("triage-json", data=canonical_json(rec))
    ctx.progress(pct=100, msg="triage complete")
    ctx.emit("triage.done", payload={"arch": rec["arch"], "file_type": rec["file_type"],
                                     "parse_errors": len(rec["parse_errors"])})
    return {"output_shas": [sha], "output_kind": "triage-json"}


def register() -> None:
    register_stage(INGEST_TRIAGE_STAGE, ingest_triage_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION,
                   on_cache_hit=backfill_triage_denorm)


def enqueue_triage(queue, target, *, force: bool = False):
    """Convenience: enqueue ingest_triage with cache-correct inputs/tool_version."""
    return queue.enqueue(target.case_id, INGEST_TRIAGE_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         force=force)
