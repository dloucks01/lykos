"""Keep what a fuzz campaign reached: its corpus, bounded, as one artifact per campaign.

A campaign's corpus is the only record of the inputs that reached NEW code -- AFL's queue, the
sandbox fuzzer's kept inputs. Every campaign discarded it at the end, so "is this finding's site
reachable from the input?" could not be answered from work lykos had already done (gif2rgb:
16 distinct executed inputs kept, while AFL alone had 127 new paths). The finding resolver
(analyze/resolve_stage.py) replays these to decide reach, and later runs can seed from them.

Format: gzip of a sequence of (u32 little-endian length, bytes). Meta: target_id, source, count,
mode, argv. Bounded: at most `cap` inputs of at most `_MAX_INPUT` bytes each.
"""
from __future__ import annotations

import gzip
import struct
from typing import Iterable, Optional

KIND = "fuzz-corpus"
_MAX_INPUT = 64 << 10
_CAP = 256


def pack(inputs: Iterable[bytes], cap: int = _CAP) -> tuple:
    """(blob, count): the distinct, non-empty inputs (first `cap`, each <= 64 KiB), gzipped."""
    seen, parts, n = set(), [], 0
    for x in inputs:
        if not x or len(x) > _MAX_INPUT:
            continue
        b = bytes(x)
        if b in seen:
            continue
        seen.add(b)
        parts.append(struct.pack("<I", len(b)) + b)
        n += 1
        if n >= cap:
            break
    return gzip.compress(b"".join(parts), compresslevel=6), n


def unpack(blob: bytes) -> list:
    raw = gzip.decompress(blob)
    out, i = [], 0
    while i + 4 <= len(raw):
        (ln,) = struct.unpack_from("<I", raw, i)
        i += 4
        if ln > _MAX_INPUT or i + ln > len(raw):
            break
        out.append(raw[i:i + ln])
        i += ln
    return out


def keep(ctx, target, inputs: Iterable[bytes], *, source: str, mode: Optional[str] = None,
         argv=None, cap: int = _CAP) -> Optional[str]:
    """Store a campaign's corpus; returns the artifact sha or None (nothing / failure)."""
    try:
        blob, n = pack(inputs, cap)
        if not n:
            return None
        return ctx.put_artifact(KIND, data=blob, meta={
            "target_id": target.id, "source": source, "count": n, "mode": mode,
            "argv": [str(a) for a in (argv or [])]})
    except Exception:                                    # noqa: BLE001 -- a convenience, never fatal
        return None


def load(conn, content, case_id: str, target_id: str) -> list:
    """[(input bytes, mode, argv, source)] from every kept corpus of this target."""
    from ...db.dao import ArtifactDAO
    out = []
    for a in ArtifactDAO(conn).list_by_case(case_id):
        if a.kind != KIND:
            continue
        meta = a.meta or {}
        if meta.get("target_id") != target_id:
            continue
        try:
            items = unpack(content.get_bytes(a.sha256))
        except Exception:                                # noqa: BLE001 -- a damaged blob: skip it
            continue
        for x in items:
            out.append((x, meta.get("mode"), list(meta.get("argv") or []), meta.get("source")))
    return out
