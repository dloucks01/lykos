"""Deterministic known-function signatures for firmware rehosting -- the data the handler
mechanism consumes, without an LLM reading the SDK.

Two deterministic sources, both stdlib byte-level (no disassembler needed):

  1. WEAK DEFAULT HANDLERS -- vendor startup code points most of the Cortex-M vector table at a
     weak `Default_Handler` that is an infinite `b .` self-loop. Firing one during interrupt
     dispatch would hang; recognising it (its vector target's code is a self-branch) and mapping
     it to "skip" lets the dispatch move on. Precise (only vector targets are checked) and safe.

  2. A growable BYTE-SIGNATURE TABLE -- {name, arch, pattern, action, entry_off} for recognisable
     library functions (delay/HAL stubs). Seeded small; broadening it across vendor SDKs is a
     data-collection effort an operator extends via $LYKOS_HAL_SIGNATURES (same shape). This is
     the deterministic replacement for "an LLM identifies the HAL functions."

`scan(blob, arch, base, endianness)` returns {entry_addr: action} to merge into the rehost
handlers.
"""
from __future__ import annotations

import json
import logging
import os
import re
import struct

_log = logging.getLogger(__name__)

# name -> (arch, byte-pattern regex, action, offset from match start to the function entry).
# Kept tiny and low-false-positive on purpose; operators extend via $LYKOS_HAL_SIGNATURES.
_SEED_SIGNATURES = [
    # a Thumb no-op stub that is ONLY `bx lr` (0x4770): already returns, mark explicit for clarity
    {"name": "thumb_noop_stub", "arch": "cortex-m", "pattern": "^\\x70\\x47",
     "action": "skip", "entry_off": 0},
]


def _load_extra():
    path = os.environ.get("LYKOS_HAL_SIGNATURES")
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            return list(json.load(f))
    except Exception:
        _log.debug("failed to load $LYKOS_HAL_SIGNATURES %s", path, exc_info=True)
        return []


def _weak_handlers(blob: bytes, base: int) -> dict:
    """Cortex-M vector-table handlers whose target code is an infinite self-loop (`b .`, 0xE7FE,
    optionally preceded by a WFI). These are weak Default_Handler stubs -> skip."""
    out = {}
    n = min(len(blob) // 4, 128)
    for i in range(2, n):                              # skip SP (0) and Reset (1)
        v = struct.unpack_from("<I", blob, 4 * i)[0]
        if not (v & 1):
            continue
        h = v & ~1
        off = h - base
        if 0 <= off <= len(blob) - 2:
            hw = struct.unpack_from("<H", blob, off)[0]
            if hw == 0xE7FE:                           # b . (self branch) = infinite spin
                out[h] = "skip"
    return out


def scan(blob: bytes, arch: str, base: int, endianness: str = "little") -> dict:
    """{entry_addr: action} for recognised functions in the blob. Cortex-M weak handlers plus any
    byte-signature matches (seed + operator-supplied)."""
    handlers: dict = {}
    arch = (arch or "").lower()
    if arch == "cortex-m":
        handlers.update(_weak_handlers(blob, base))
    for sig in _SEED_SIGNATURES + _load_extra():
        if sig.get("arch") and sig["arch"].lower() != arch:
            continue
        try:
            rx = re.compile(sig["pattern"].encode("latin-1") if isinstance(sig["pattern"], str)
                            else sig["pattern"])
        except re.error:
            continue
        for m in rx.finditer(blob):
            # a byte-signature match is only treated as a function entry when it is a vector
            # target (Cortex-M) -- a raw byte match anywhere is too noisy to act on blindly.
            if arch == "cortex-m":
                addr = base + m.start() + int(sig.get("entry_off", 0))
                if _is_vector_target(blob, base, addr):
                    handlers.setdefault(addr, sig.get("action", "skip"))
    return {hex(a): act for a, act in handlers.items()}


def _is_vector_target(blob: bytes, base: int, addr: int) -> bool:
    n = min(len(blob) // 4, 128)
    for i in range(1, n):
        v = struct.unpack_from("<I", blob, 4 * i)[0]
        if (v & ~1) == (addr & ~1):
            return True
    return False
