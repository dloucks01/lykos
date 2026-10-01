"""DM-16 / DM-17 — Content hashing + canonical serialization.

Shared primitives imported by the artifact store (P0.4) and the result cache (JE-15/16),
and used by the triage worker (IT-20) to keep output deterministic. Stdlib-based.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any, Iterable

_CHUNK = 1 << 20  # 1 MiB


def new_id() -> str:
    """DM-01: portable text primary key."""
    return uuid.uuid4().hex


# ------------------------------------------------------------------ content hashing (DM-16)
def hash_bytes(data: bytes, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


def hash_file(path: str | Path, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_all_file(path: str | Path) -> dict[str, Any]:
    """One pass over the file → md5/sha1/sha256 + size."""
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(), "size": size}


# ------------------------------------------------------- canonical serialization (DM-17)
def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON: recursively sorted keys, compact separators, UTF-8.

    Dict insertion order does not affect the output, so identical logical content
    hashes identically — the property the result cache relies on.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def params_hash(params: dict[str, Any] | None) -> str:
    return hash_bytes(canonical_json(params or {}))


def compute_cache_key(
    stage: str,
    input_hashes: Iterable[str],
    params: dict[str, Any] | None,
    tool_version: str | None,
) -> str:
    """JE-16 composition, built on the DM-17 canonical primitive.

    cache_key = sha256( stage ‖ sorted(input_hashes) ‖ canonical(params) ‖ tool_version )
    """
    h = hashlib.sha256()
    h.update(stage.encode("utf-8"))
    h.update(b"\x00")
    for ih in sorted(input_hashes):
        h.update(ih.encode("utf-8"))
        h.update(b"\x00")
    h.update(canonical_json(params or {}))
    h.update(b"\x00")
    h.update((tool_version or "").encode("utf-8"))
    return h.hexdigest()
