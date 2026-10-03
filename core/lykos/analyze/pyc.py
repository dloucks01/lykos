"""CPython bytecode (.pyc) header + light structural parser. A .pyc is a 16-byte header (a 2-byte
version magic + 0x0d0a, a 4-byte bit field, then either an mtime+source-size or, for a hash-based
pyc, an 8-byte source hash) followed by a marshalled top-level code object. This maps the magic to a
Python version and surfaces the readable symbol/string material the marshalled blob carries
(co_names, co_consts strings, the source filename), which is what the string and invocation
detectors consume -- CPython bytecode has no native machine code or instruction pointer, so the
exploit ladder does not apply.

Full unmarshalling of an untrusted .pyc is not attempted (it would execute the marshal state machine
over attacker-controlled input); instead the header is parsed exactly and strings are extracted by a
bounded, format-aware scan of marshal string records. Defensive: partial record + errors, never an
exception."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

# magic int (first 2 bytes, little-endian) -> Python version. CPython bumps this every release; the
# map covers 3.6+ (the versions that still matter) and falls back to "Python 3.x (magic N)".
_MAGIC_VERSION = {
    3379: "3.6", 3390: "3.7", 3425: "3.8", 3439: "3.9", 3495: "3.10",
    3531: "3.11", 3571: "3.12", 3613: "3.13", 3627: "3.14",
}
# marshal type codes for the string-ish records we harvest (high bit = FLAG_REF, masked off)
_STR_CODES = {ord("s"), ord("u"), ord("t"), ord("a"), ord("Z"), ord("z")}


@dataclass
class PycInfo:
    arch: str = "cpython-bytecode"
    bits: Optional[int] = None
    endianness: str = "little"
    magic: Optional[int] = None
    python_version: Optional[str] = None
    hash_based: bool = False
    flags: Optional[int] = None
    sections: list = field(default_factory=list)
    imports: dict = field(default_factory=lambda: {"libraries": [], "functions_count": 0})
    exports_count: int = 0
    imported_symbols: list = field(default_factory=list)
    exported_symbols: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    toolchain_hint: str = "unknown"
    mitigations: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def parse(data: bytes) -> PycInfo:
    info = PycInfo()
    if len(data) < 16 or data[2:4] != b"\r\n":
        info.errors.append("not a .pyc (missing magic/\\r\\n)")
        return info
    info.magic = data[0] | (data[1] << 8)
    info.python_version = _MAGIC_VERSION.get(info.magic, f"3.x (magic {info.magic})")
    (info.flags,) = (int.from_bytes(data[4:8], "little"),)
    info.hash_based = bool(info.flags & 0x1)
    info.toolchain_hint = f"CPython {info.python_version}"
    body = data[16:]
    names, strings = _harvest(body)
    # names that look like dotted/importable identifiers are the module's call surface; the rest are
    # literal strings for the dictionary/string detectors.
    info.imported_symbols = names[:512]
    info.imports = {"libraries": sorted({n.split(".")[0] for n in names if "." in n})[:64],
                    "functions_count": len(names), "symbols": names[:512]}
    info.strings = strings[:1024]
    info.mitigations = {"nx": "n/a", "pie": "n/a", "sandbox": "cpython-vm"}
    return info


def _harvest(body: bytes) -> tuple[list[str], list[str]]:
    """Pull readable identifiers and literals out of the marshalled code object WITHOUT running the
    marshal state machine: walk for string-type records (`s`/`u`/`t`/`a`/`z`/`Z`) whose 4-byte (or
    1-byte short) length prefix yields printable ASCII. Bounded and best-effort -- it over- rather
    than under-collects, which is the right bias for feeding detectors."""
    names, strings = [], []
    seen = set()
    n = len(body)
    i = 0
    ident = re.compile(rb"^[A-Za-z_][A-Za-z0-9_.]*$")
    while i < n and len(seen) < 20000:
        code = body[i] & 0x7F                                    # mask FLAG_REF (0x80)
        if code in _STR_CODES:
            if code in (ord("z"), ord("Z")):                     # short-ascii: 1-byte length
                if i + 1 >= n:
                    break
                length = body[i + 1]
                start = i + 2
            else:                                                # s/u/t/a: 4-byte length
                if i + 5 > n:
                    break
                length = int.from_bytes(body[i + 1:i + 5], "little")
                start = i + 5
            if 0 < length <= 4096 and start + length <= n:
                chunk = body[start:start + length]
                if chunk and all(32 <= c < 127 or c in (9, 10, 13) for c in chunk):
                    s = chunk.decode("ascii", "replace")
                    if s not in seen:
                        seen.add(s)
                        (names if ident.match(chunk) else strings).append(s)
                    i = start + length
                    continue
        i += 1
    return names, strings


def to_format_details(info: PycInfo) -> dict[str, Any]:
    return {"pyc": {"magic": info.magic, "python_version": info.python_version,
                    "hash_based": info.hash_based, "flags": info.flags,
                    "names": len(info.imported_symbols), "strings": len(info.strings)}}
