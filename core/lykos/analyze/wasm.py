"""WebAssembly module parser. A .wasm module is a binary stack-machine program: a magic + version,
then a sequence of length-prefixed sections. This reads the structural shape -- declared sections,
imported and exported names (with their kinds), function/memory/table counts and the host functions
the module calls -- which is what the string, import and invocation detectors need. There is no
native machine code and no instruction pointer, so the exploit ladder does not apply; the value is
turning a .wasm from unrecognized into an analyzable, described target.

Best-effort and defensive: a truncated or hostile module yields a partial record + errors, never an
exception. LEB128 lengths are attacker-controlled, so every read is bounds-checked and bounded."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# section id -> name (WASM MVP + common post-MVP ids)
_SECTIONS = {0: "custom", 1: "type", 2: "import", 3: "function", 4: "table", 5: "memory",
             6: "global", 7: "export", 8: "start", 9: "element", 10: "code", 11: "data",
             12: "data_count", 13: "tag"}
_EXTERN_KIND = {0: "func", 1: "table", 2: "memory", 3: "global"}
_MAX_VEC = 1_000_000                              # a hostile LEB count; bound every vector loop


@dataclass
class WasmInfo:
    arch: str = "wasm"
    bits: int = 32                               # wasm32 is the near-universal target; 64 is rare
    endianness: str = "little"
    version: Optional[int] = None
    linking: str = "dynamic"                     # a module links to its host via imports
    sections: list[dict] = field(default_factory=list)
    imports: dict = field(default_factory=lambda: {"libraries": [], "functions_count": 0})
    exports_count: int = 0
    imported_symbols: list = field(default_factory=list)
    exported_symbols: list = field(default_factory=list)
    func_count: int = 0
    mem_pages: Optional[int] = None
    has_start: bool = False
    toolchain_hint: str = "unknown"
    mitigations: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def _uleb(data: bytes, pos: int) -> tuple[int, int]:
    """Read an unsigned LEB128 at `pos`; returns (value, new_pos). Caps the shift so a malformed,
    never-terminating sequence cannot spin."""
    result = shift = 0
    while pos < len(data) and shift <= 63:
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            return result, pos
        shift += 7
    raise ValueError("bad LEB128")


def _name(data: bytes, pos: int) -> tuple[str, int]:
    n, pos = _uleb(data, pos)
    n = min(n, 4096)
    s = data[pos:pos + n].decode("utf-8", "replace")
    return s, pos + n


def parse(data: bytes) -> WasmInfo:
    info = WasmInfo()
    if len(data) < 8 or data[:4] != b"\x00asm":
        info.errors.append("not a WebAssembly module (bad magic)")
        return info
    info.version = int.from_bytes(data[4:8], "little")
    pos = 8
    try:
        while pos < len(data):
            sec_id = data[pos]
            pos += 1
            size, pos = _uleb(data, pos)
            if size < 0 or pos + size > len(data):
                info.errors.append("section overruns module")
                break
            body = data[pos:pos + size]
            info.sections.append({"name": _SECTIONS.get(sec_id, f"id-{sec_id}"), "size": size})
            _parse_section(sec_id, body, info)
            pos += size
    except ValueError as e:
        info.errors.append(str(e))
    except Exception as e:                                        # noqa: BLE001 -- parse is best-effort
        info.errors.append(f"wasm parse: {e!r}")
    info.imports = {"libraries": sorted({m for m, _ in getattr(info, "_imp_pairs", [])})[:64],
                    "functions_count": len(info.imported_symbols),
                    "symbols": info.imported_symbols[:512]}
    info.exports_count = len(info.exported_symbols)
    info.toolchain_hint = _toolchain(data)
    # WASM's safety model is structural, not flag-based: linear memory is bounds-checked by the
    # engine and the call stack is not addressable, so classic stack-smash/NX/PIE do not apply.
    info.mitigations = {"sandbox": "engine-enforced", "nx": "n/a", "pie": "n/a"}
    return info


def _parse_section(sec_id: int, body: bytes, info: WasmInfo):
    if sec_id == 2:                                              # import section
        pairs = []
        count, pos = _uleb(body, 0)
        for _ in range(min(count, _MAX_VEC)):
            if pos >= len(body):
                break
            mod, pos = _name(body, pos)
            field_, pos = _name(body, pos)
            kind = body[pos] if pos < len(body) else 0xFF
            pos += 1
            pos = _skip_import_desc(body, pos, kind)
            pairs.append((mod, field_))
            info.imported_symbols.append(f"{mod}.{field_}" + (f" [{_EXTERN_KIND.get(kind,'?')}]"
                                                               if kind != 0 else ""))
        info._imp_pairs = pairs                                  # noqa: SLF001 -- used in parse()
    elif sec_id == 7:                                            # export section
        count, pos = _uleb(body, 0)
        for _ in range(min(count, _MAX_VEC)):
            if pos >= len(body):
                break
            nm, pos = _name(body, pos)
            kind = body[pos] if pos < len(body) else 0xFF
            pos += 1
            _, pos = _uleb(body, pos) if pos < len(body) else (0, pos)
            info.exported_symbols.append(f"{nm} [{_EXTERN_KIND.get(kind,'?')}]")
    elif sec_id == 3:                                            # function section (count of funcs)
        count, _ = _uleb(body, 0)
        info.func_count = min(count, _MAX_VEC)                   # a LEB count is up to 2^70; clamp
    elif sec_id == 5:                                            # memory section -> initial pages
        count, pos = _uleb(body, 0)
        if count:
            flags, pos = _uleb(body, pos)
            initial, pos = _uleb(body, pos)
            info.mem_pages = min(initial, 0x10000)               # wasm32 max is 65536 pages; clamp
    elif sec_id == 8:                                            # start section
        info.has_start = True


def _skip_import_desc(body: bytes, pos: int, kind: int) -> int:
    """Advance past an import's type descriptor (its shape depends on the external kind)."""
    try:
        if kind == 0:                                            # func: a type index
            _, pos = _uleb(body, pos)
        elif kind == 1:                                          # table: elemtype + limits
            pos += 1
            pos = _skip_limits(body, pos)
        elif kind == 2:                                          # memory: limits
            pos = _skip_limits(body, pos)
        elif kind == 3:                                          # global: valtype + mutability
            pos += 2
    except ValueError:
        pass
    return pos


def _skip_limits(body: bytes, pos: int) -> int:
    flags, pos = _uleb(body, pos)
    _, pos = _uleb(body, pos)                                    # minimum
    if flags & 1:
        _, pos = _uleb(body, pos)                                # maximum
    return pos


def _toolchain(data: bytes) -> str:
    """Name the producer from the conventional custom sections Emscripten/Rust/wasm-bindgen emit."""
    for needle, name in ((b"producers", "has producers section"), (b"wasm-bindgen", "wasm-bindgen"),
                         (b"rustc", "rustc"), (b"emscripten", "Emscripten"), (b"clang", "clang")):
        if needle in data:
            return name
    return "unknown"


def to_format_details(info: WasmInfo) -> dict[str, Any]:
    return {"wasm": {"version": info.version, "functions": info.func_count,
                     "memory_pages": info.mem_pages, "has_start": info.has_start,
                     "sections": [s["name"] for s in info.sections],
                     "imports": len(info.imported_symbols), "exports": info.exports_count}}
