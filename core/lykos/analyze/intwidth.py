"""Integer signedness / width analysis (static gap 4) — CWE-190/191/196/197 precision.

Two wire-value bug shapes the range engine alone misses:
  * SIGNED USE: a value read into a SIGNED type (INT16/INT32/int) and then used as a size / length /
    index. A huge unsigned wire value becomes negative, passes a `< max` sanity check, and wraps to
    a huge value when converted to size_t at the allocation/copy -> CWE-195/196/190.
  * TRUNCATION: a wider wire value (UINT32) stored into a narrower type (UINT16/UINT8) and then used
    as a size/length -> the high bits are lost, so a bound check on the narrow value does not bound
    the real quantity -> CWE-197.

Pure source analysis: find the declared width/signedness of a Stream_Read destination (or an
assignment that narrows it), then a dangerous use. Conservative + testable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .dispatcher_harness import _functions
from .wire_flow import _strip_comments

# Stream_Read_INT* (signed) and the destination's declared type.
_READ = re.compile(r"\bStream_Read_(U?)INT(8|16|32|64)\s*\(\s*\w+\s*,\s*([A-Za-z_][\w.\->]*)")
_DECL = re.compile(r"\b(INT8|INT16|INT32|INT64|int|short|char|long|size_t|UINT8|UINT16|UINT32|UINT64|"
                   r"BYTE|WORD|DWORD)\s+\*?\s*([A-Za-z_]\w*)")
_SIZE_USE = re.compile(r"\b(?:malloc|calloc|realloc|alloca|memcpy|memmove|memset|Stream_Read|"
                       r"Stream_Write)\s*\([^;]*\b%s\b")
_WIDTH = {"INT8": 8, "UINT8": 8, "BYTE": 8, "char": 8, "INT16": 16, "UINT16": 16, "WORD": 16,
          "short": 16, "INT32": 32, "UINT32": 32, "DWORD": 32, "int": 32,
          "INT64": 64, "UINT64": 64, "long": 64, "size_t": 64}
_SIGNED = {"INT8", "INT16", "INT32", "INT64", "int", "short", "char", "long"}


@dataclass
class IntWidthBug:
    function: str
    var: str
    kind: str                      # "signed-size" | "truncation"
    cwe: str
    hint: str


def find_intwidth_bugs(src: str) -> list:
    out = []
    for name, _s, _p, raw in _functions(src):
        body = _strip_comments(raw)
        decl = {m.group(2): m.group(1) for m in _DECL.finditer(body)}   # var -> declared type
        for m in _READ.finditer(body):
            signed_read = (m.group(1) == "")             # Stream_Read_INT* (no U)
            rw = int(m.group(2))
            var = m.group(3).split(".")[-1].split("->")[-1]
            dtype = decl.get(var)
            use = re.search(_SIZE_USE.pattern % re.escape(var), body)
            if not use:
                continue
            # signed destination (or signed read) used as a size/length -> negative->huge risk
            if signed_read or (dtype in _SIGNED):
                out.append(IntWidthBug(name, var, "signed-size", "CWE-195",
                                       body.splitlines()[body[:use.start()].count(chr(10))].strip()[:80]))
            # a read wider than its destination type -> truncation before the size use
            elif dtype and _WIDTH.get(dtype, 64) < rw:
                out.append(IntWidthBug(name, var, "truncation", "CWE-197",
                                       f"{rw}-bit read into {dtype} ({_WIDTH[dtype]}-bit) used as size"))
    return out
