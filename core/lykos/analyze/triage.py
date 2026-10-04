"""IT-00, IT-16..IT-18, IT-20 — triage record schema, builder, validator.

Deterministic: the record carries NO timestamps or absolute paths, so identical input +
tool_version yields byte-identical JSON and the result cache (JE-16) hits on re-run.
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Optional

from . import dotnet as dotnetmod
from . import elf as elfmod
from . import filetype
from . import jvm as jvmmod
from . import macho as machomod
from . import pe as pemod
from . import pyc as pycmod
from . import wasm as wasmmod

SCHEMA_VERSION = 1
TOOL = "elf-stdlib"
TOOL_VERSION = "triage-4"          # bump to invalidate the cache when parsing changes
#   triage-4: static-pie linking classification (PT_DYNAMIC no longer implies dynamic)
MITIGATION_ENUM = {"on", "off", "partial", "unknown"}
_FILE_TYPES = {filetype.ELF, filetype.PE, filetype.MACHO, filetype.JAR,
               filetype.CLASS, filetype.WASM, filetype.PYC, filetype.DOTNET,
               filetype.FIRMWARE, filetype.RAW, filetype.OTHER}
_PACK_ENTROPY = 7.2
# Entropy is a whole-file scan in pure Python; on every ingest that is a DoS on a large upload.
# A 2 MB prefix is representative for the packer heuristic and matches the ELF/PE section cap.
_ENTROPY_CAP = 2 * 1024 * 1024


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in freq if c), 3)


# leading-byte signatures for common non-executable container/text formats, so a mistaken
# upload is described helpfully rather than dismissed as "unknown data".
_CONTENT_MAGIC = [
    (b"PK\x03\x04", "ZIP archive (or ZIP-based document)"),
    (b"PK\x05\x06", "empty ZIP archive"),
    (b"\x1f\x8b", "gzip-compressed data"),
    (b"BZh", "bzip2-compressed data"),
    (b"\xfd7zXZ\x00", "xz-compressed data"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"!<arch>\n", "ar/deb archive"),
    (b"%PDF-", "PDF document"),
    (b"\x89PNG\r\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"<?xml", "XML document"),
    (b"{\n", "JSON/text data"),
]

# interpreter basename -> friendly language name (for shebang scripts)
_SCRIPT_LANG = {
    "sh": "shell", "bash": "Bourne-Again shell", "dash": "shell", "zsh": "Z shell",
    "ksh": "Korn shell", "python": "Python", "python2": "Python", "python3": "Python",
    "perl": "Perl", "ruby": "Ruby", "node": "Node.js", "php": "PHP", "lua": "Lua",
    "awk": "AWK", "tclsh": "Tcl", "Rscript": "R", "pwsh": "PowerShell",
}


def _classify_content(data: bytes) -> str:
    """Human description of a non-binary blob (script / archive / text / data)."""
    if not data:
        return "empty file"
    if data[:2] == b"#!":
        line = data[:256].split(b"\n", 1)[0].decode("latin-1", "ignore")
        toks = line[2:].strip().split()
        interp = ""
        for t in toks:                                # skip `/usr/bin/env`
            base = t.rsplit("/", 1)[-1]
            if base and base != "env" and not base.startswith("-"):
                interp = base
                break
        lang = _SCRIPT_LANG.get(interp, interp or "script")
        return f"{lang} script" if lang != "script" else "shell/interpreter script"
    for magic, desc in _CONTENT_MAGIC:
        if data[:len(magic)] == magic:
            return desc
    sample = data[:4096]
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    if printable / len(sample) >= 0.95:
        return "plain-text / source file"
    return "unrecognized data (not a known binary format)"


# A headerless firmware scan runs on every file that matched no format magic, so bound the
# bytes it inspects: the pure-Python prologue scoring in `headerless` walks the whole blob,
# and firmware images that need this path are small (flash/SRAM sized). 16 MiB is far above
# any bare-metal image and keeps the every-ingest cost bounded.
_FW_SCAN_CAP = 16 * 1024 * 1024


def _firmware_fallback(data: bytes) -> Optional[dict]:
    """Second opinion for a blob that matched no container magic: is it actually firmware?

    `filetype.detect` only knows the six firmware containers by their offset-0 magic. A
    bare-metal Cortex-M image, a raw flash dump, or a blob with a gzipped kernel embedded at a
    non-zero offset has none of those, so it fell through to "not a binary, import an ELF" --
    the exact confident-wrong-answer this platform has a history of giving about images the
    carve stage then pulls executables and keys out of. Consult the headerless loader (which
    can name the CPU) and the carve signature scan (which finds embedded components), and only
    then decide. Returns None when neither finds anything -- it really is not a binary.
    """
    blob = data[:_FW_SCAN_CAP]
    try:
        from .firmware.headerless import analyze_blob
    except Exception:
        analyze_blob = None
    if analyze_blob is not None:
        try:
            hl = analyze_blob(blob)
        except Exception:
            hl = None
        if hl and hl.get("arch"):
            return {"mode": "headerless", "headerless": hl}
    try:
        from .firmware.carve import scan_signatures
    except Exception:
        scan_signatures = None
    if scan_signatures is not None:
        try:
            hits = scan_signatures(blob)
        except Exception:
            hits = []
        # offset 0 would already have been a container magic; we want EMBEDDED content
        embedded = [h for h in hits if (h.get("offset") or 0) > 0]
        if embedded:
            return {"mode": "carve", "hits": embedded}
    return None


def _packer_heuristic(overall: float, sections: list[dict]) -> dict:
    reasons, packer = [], None
    if overall >= _PACK_ENTROPY:
        reasons.append(f"high overall entropy {overall}")
    names = " ".join(s.get("name", "") for s in sections).lower()
    if "upx" in names:
        reasons.append("UPX section names")
        packer = "upx"
    return {"overall": overall, "packed_hint": bool(reasons), "packer": packer,
            "reasons": reasons}


def build_triage(path: str | Path, hashes: dict[str, Any], filename: str) -> dict:
    """Produce a schema-v1 triage record. Best-effort; never raises on bad input."""
    parse_errors: list[str] = []
    rec: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "sha256": hashes.get("sha256"), "md5": hashes.get("md5"),
        "sha1": hashes.get("sha1"), "size": hashes.get("size"),
        "file_type": filetype.RAW, "detected": None,
        "analyzable": False, "advisory": None,
        "arch": None, "bits": None, "endianness": None, "linking": None,
        "stripped": None, "entry_point": None, "interpreter": None,
        "sections": [], "imports": {"libraries": [], "functions_count": 0, "symbols": []},
        "exports_count": 0, "exports": {"count": 0, "symbols": []},
        "toolchain_hint": "unknown", "mitigations": {},
        "entropy": {"overall": 0.0, "packed_hint": False, "packer": None, "reasons": []},
        "format_details": {}, "parse_errors": parse_errors,
        "tool": TOOL, "tool_version": TOOL_VERSION,
    }
    try:
        data = Path(path).read_bytes()
    except Exception as e:
        parse_errors.append(f"read: {e!r}")
        return rec

    rec["file_type"] = filetype.detect(data[:64])
    if rec["file_type"] == filetype.JAR and not jvmmod.is_jar(data):
        # `PK\x03\x04` is every zip, not only a Java one: a firmware bundle, a .docx and an
        # archive of source all start with it. Deciding this here rather than inside the JAR
        # branch keeps the branch chain honest -- resetting the type mid-branch skipped the
        # not-a-binary description entirely and left `detected` as None.
        rec["file_type"] = filetype.OTHER
    rec["_data_head"] = data[:4096]                     # transient: for non-binary classify
    rec["entropy"] = _packer_heuristic(_shannon(data[:_ENTROPY_CAP]), [])

    if rec["file_type"] == filetype.ELF:
        info = elfmod.parse(data)
        parse_errors.extend(info.errors)
        rec.update({
            "arch": info.arch, "bits": info.bits, "endianness": info.endianness,
            "linking": info.linking, "stripped": info.stripped,
            "entry_point": (f"0x{info.entry:x}" if info.entry is not None else None),
            "interpreter": info.interpreter, "sections": info.sections,
            "imports": info.imports, "exports_count": info.exports_count,
            "exports": {"count": info.exports_count, "symbols": info.exported_symbols},
            "toolchain_hint": info.toolchain_hint, "mitigations": info.mitigations,
            "format_details": elfmod.to_format_details(info),
        })
        rec["entropy"] = _packer_heuristic(rec["entropy"]["overall"], info.sections)
        rec["detected"] = _describe(rec)
        rec["analyzable"] = True                       # ELF is the fully-supported format
        rec["advisory"] = None
    elif rec["file_type"] == filetype.PE and dotnetmod.is_dotnet(data):
        # A .NET assembly IS a PE, so magic detection called it `pe` -- but it is CIL bytecode, not
        # native machine code. Disassembling CIL as x86 is pure garbage (the RISC-V-as-x86 trap), so
        # route it to the managed path: inventory the metadata the format gives in the clear and
        # stop the PoC ladder honestly at the managed boundary.
        rec["file_type"] = filetype.DOTNET
        info = dotnetmod.parse(data)
        parse_errors.extend(info.errors)
        rec.update({
            "arch": "cil", "bits": info.bits or 32, "endianness": "little", "linking": "dynamic",
            "stripped": False, "entry_point": None,
            "imports": {"libraries": [], "functions_count": info.method_count,
                        "symbols": info.names[:512]},
            "exports_count": info.type_count,
            "exports": {"count": info.type_count, "symbols": info.names[:512]},
            "toolchain_hint": (f".NET CLR {info.clr_version}" if info.clr_version else ".NET"),
            "format_details": dotnetmod.to_format_details(info),
        })
        rec["detected"] = _describe_dotnet(info)
        rec["analyzable"] = True
        # Say exactly where the ladder stops, like the JVM path: the CLR checks every array access
        # and owns every pointer, so there is no native instruction pointer to take.
        rec["advisory"] = (
            ".NET assembly analysed: the metadata gives every type and method NAME (#Strings) and "
            "every string literal (#US) in the clear -- more than a stripped native PE -- so the "
            "string-based detectors, invocation discovery and the fuzzing dictionary all work. "
            "Execution is under the CLR, where a defect surfaces as a managed exception, not a "
            "signal. Not available: native disassembly (the body is CIL, not x86) and the L2/L3 "
            "exploit ladder -- the managed runtime owns every pointer, so there is no IP to hijack.")
    elif rec["file_type"] == filetype.PE:
        info = pemod.parse(data)
        parse_errors.extend(info.errors)
        rec.update({
            "arch": info.arch, "bits": info.bits, "endianness": info.endianness,
            "linking": info.linking, "stripped": info.stripped,
            "entry_point": (f"0x{info.entry:x}" if info.entry is not None else None),
            "sections": info.sections, "imports": info.imports,
            "exports_count": info.exports_count,
            "exports": {"count": info.exports_count, "symbols": info.exported_symbols},
            "toolchain_hint": info.toolchain_hint, "mitigations": info.mitigations,
            "format_details": pemod.to_format_details(info),
        })
        rec["entropy"] = _packer_heuristic(rec["entropy"]["overall"], info.sections)
        rec["detected"] = _describe(rec)
        # The old advisory said disassembly, CWE detection and the dynamic stages were "not
        # yet available for this format" -- while the platform was disassembling 282 functions
        # out of this very binary, producing findings from it and running it under Wine. What
        # is actually missing is narrower, so say that instead.
        rec["analyzable"] = True
        rec["advisory"] = (
            "PE analysed: headers, disassembly, CWE detection and execution under Wine all "
            "work. Not available for PE: the LD_PRELOAD heap checker and P-Code dynamic "
            "taint (both Linux/ELF), and fuzzing runs at Wine speed (~1 execution/second) "
            "with no coverage feedback, so it is not a practical campaign.")
    elif rec["file_type"] in (filetype.JAR, filetype.CLASS):
        info = jvmmod.parse(data)
        parse_errors.extend(info.errors)
        rec.update({
            "arch": "jvm", "bits": 64, "endianness": "big", "linking": "dynamic",
            "stripped": False,
            "entry_point": info.main_class,
            "imports": {"libraries": sorted({c.split(".")[0].rsplit("/", 1)[0]
                                             for c in info.calls if "/" in c})[:64],
                        "functions_count": len(info.calls),
                        "symbols": [c.split(".")[-1] for c in info.calls][:512]},
            "exports_count": len(info.classes),
            "exports": {"count": len(info.classes), "symbols": info.classes[:512]},
            "toolchain_hint": f"javac (class file v{info.major})" if info.major
                              else "javac",
            "format_details": jvmmod.to_format_details(info),
        })
        rec["detected"] = _describe_jvm(info, rec["file_type"])
        rec["analyzable"] = True
        # Say exactly where the ladder stops. A managed runtime checks every array access
        # and owns every pointer, so there is no instruction pointer to take -- claiming
        # otherwise would be a lie about the runtime, not a missing feature.
        rec["advisory"] = (
            "Java analysed: the constant pool gives every string and every method call in "
            "the clear, which is more than a stripped ELF yields, so invocation discovery, "
            "the fuzzing dictionary and the string-based detectors all work. Execution is "
            "under the JVM, where a defect surfaces as an uncaught exception rather than a "
            "signal; JVM startup dominates each execution (~27 ms measured), so a campaign "
            "runs at roughly 36 executions/second rather than hundreds. Not available "
            "for Java: Ghidra "
            "disassembly and P-Code analysis (there is no machine code), and PoC levels "
            "L2/L3 -- the JVM owns the instruction pointer, so control-flow hijack is not "
            "a claim this format can support.")
    elif rec["file_type"] == filetype.WASM:
        info = wasmmod.parse(data)
        parse_errors.extend(info.errors)
        rec.update({
            "arch": info.arch, "bits": info.bits, "endianness": info.endianness,
            "linking": info.linking, "imports": info.imports,
            "exports_count": info.exports_count,
            "exports": {"count": info.exports_count, "symbols": info.exported_symbols},
            "sections": info.sections, "toolchain_hint": info.toolchain_hint,
            "mitigations": info.mitigations, "format_details": wasmmod.to_format_details(info),
        })
        rec["detected"] = (f"WebAssembly module (v{info.version}, {info.func_count} functions, "
                           f"{len(info.imported_symbols)} imports, {info.exports_count} exports)")
        rec["analyzable"] = True
        rec["advisory"] = (
            "WebAssembly analysed: the module's imports (its host call surface), exports, "
            "function/memory counts and embedded strings are inventoried -- they feed the invocation "
            "map and the fuzzing dictionary, and the string detectors run over them. Not yet "
            "available for WASM: a wasm-specific vulnerability detector, native disassembly, and the "
            "x86/ELF dynamic stages -- a .wasm has no machine code or addressable call stack, and "
            "its linear memory is bounds-checked by the engine, so the stack-smash/NX/PIE/PoC "
            "ladder does not apply; run it under a wasm engine (wasmtime/node) for dynamic work.")
    elif rec["file_type"] == filetype.PYC:
        info = pycmod.parse(data)
        parse_errors.extend(info.errors)
        rec.update({
            "arch": info.arch, "endianness": info.endianness, "imports": info.imports,
            "stripped": False, "toolchain_hint": info.toolchain_hint,
            "mitigations": info.mitigations, "format_details": pycmod.to_format_details(info),
        })
        rec["detected"] = (f"CPython bytecode (.pyc) — Python {info.python_version}"
                           + (", hash-based" if info.hash_based else ""))
        rec["analyzable"] = True
        rec["advisory"] = (
            f"CPython {info.python_version} bytecode analysed: the version magic, header and the "
            "readable identifiers/strings in the marshalled code object were parsed, and detect_cwe "
            "flags the dangerous call surface (os.system/eval/exec/pickle.loads) as candidates from "
            "those symbols -- decompile (decompyle3/uncompyle6) to confirm the dataflow. Not "
            "available for .pyc: native disassembly and the x86/ELF dynamic/PoC stages -- the CPython "
            "VM owns the instruction pointer, so control-flow hijack is not a claim this format "
            "supports.")
    elif rec["file_type"] == filetype.FIRMWARE:
        kind = filetype.firmware_kind(data[:64]) or "firmware image"
        rec["detected"] = f"Firmware image — {kind}"
        # Analysable, but not by the stages that want machine code: the image is a CONTAINER,
        # and what is in it becomes analysable once carved. Saying "not a recognised
        # executable, library or firmware image" about a file the carve stage then pulls two
        # executables and a private key out of is a confident wrong answer.
        rec["analyzable"] = True
        rec["advisory"] = (
            f"{kind} detected. This is a container, not a program: run firmware_carve to "
            f"extract the components (executables, filesystems, keys) as targets of their "
            f"own, then analyse those. Disassembly and the dynamic stages apply to the "
            f"carved components, not to the image.")
    elif rec["file_type"] == filetype.MACHO:
        info = machomod.parse(data)
        parse_errors.extend(info.errors)
        rec.update({
            "arch": info.arch, "bits": info.bits, "endianness": info.endianness,
            "linking": info.linking, "stripped": info.stripped,
            "entry_point": (f"0x{info.entry:x}" if info.entry is not None else None),
            "interpreter": info.interpreter, "sections": info.sections, "imports": info.imports,
            "exports_count": info.exports_count,
            "exports": {"count": info.exports_count, "symbols": info.exported_symbols},
            "toolchain_hint": info.toolchain_hint, "mitigations": info.mitigations,
            "format_details": machomod.to_format_details(info),
        })
        rec["detected"] = _describe(rec) + (" (universal)" if info.fat else "")
        # Header-level analysis is real (arch, linked dylibs, symbols, mitigations, and the
        # string/symbol/invocation detectors all apply, plus Ghidra disassembles Mach-O). What is
        # missing is the Linux/ELF dynamic stack: qemu-user/Wine cannot run a macOS binary here, so
        # the dynamic/fuzzing/PoC stages do not -- say that precisely rather than "detected only".
        rec["analyzable"] = True
        enc = " The __TEXT is FairPlay-encrypted, so the code pages read here are ciphertext." \
            if info.encrypted else ""
        rec["advisory"] = (
            "Mach-O analysed: header, architecture, linked dylibs, symbol table and the "
            "advertised mitigations (PIE, stack execution, code signature, encryption) were "
            "parsed, so the string, symbol and invocation detectors and Ghidra disassembly apply."
            + enc +
            " Not available for Mach-O: the dynamic stages (fuzzing, the heap checker, PoC "
            "levels L1-L3) -- running a macOS/iOS binary needs a macOS host or emulator this "
            "Linux build does not provide.")
    else:
        # Before calling this "not a binary", ask the headerless loader and the carve scan --
        # a firmware image without a container magic at offset 0 is still firmware, and saying
        # otherwise is the confident wrong answer this platform has a history of giving.
        fw = _firmware_fallback(data)
        if fw is not None:
            rec["file_type"] = filetype.FIRMWARE
            rec["analyzable"] = True
            if fw["mode"] == "headerless":
                hl = fw["headerless"]
                sub = hl.get("sub")
                kind = ("bare-metal " + (hl.get("arch") or "?")
                        + (f"/{sub}" if sub else "") + " firmware")
                rec.update({"arch": hl.get("arch"), "bits": hl.get("bits"),
                            "endianness": hl.get("endianness"),
                            "entry_point": (f"0x{hl['entry']:x}"
                                            if hl.get("entry") is not None else None)})
                rec["detected"] = (
                    f"Firmware image — {kind} (headerless: {hl.get('method')}, "
                    f"confidence {hl.get('confidence')})")
                rec["advisory"] = (
                    f"{kind} identified by the headerless loader "
                    f"({hl.get('evidence') or hl.get('method')}). This is a raw image, not an "
                    f"ELF/PE: run firmware_carve to extract any embedded components, or "
                    f"firmware_rehost to run a bare-metal image under emulation. Machine-code "
                    f"disassembly and the ELF/PE dynamic stages apply to carved components, "
                    f"not to the raw image.")
            else:
                types = sorted({h.get("type") for h in fw["hits"] if h.get("type")})
                rec["detected"] = ("Firmware image — embedded components ("
                                   + ", ".join(types) + ")")
                rec["advisory"] = (
                    "This image carries embedded components ("
                    + ", ".join(types) + ") at non-zero offsets. It is a container, not a "
                    "program: run firmware_carve to extract them (executables, filesystems, "
                    "keys) as targets of their own, then analyse those. Disassembly and the "
                    "dynamic stages apply to the carved components, not to the raw image.")
        else:
            desc = _classify_content(rec["_data_head"])
            rec["detected"] = f"Not a binary — {desc}"
            rec["analyzable"] = False
            rec["advisory"] = (f"This file is not a supported executable binary ({desc}). It "
                               "was imported and hashed, but there is no machine code to "
                               "analyze: disassembly, CWE detection, and the "
                               "dynamic/fuzzing/PoC stages do not apply. Import an ELF "
                               "executable or shared object to analyze.")
    rec.pop("_data_head", None)
    return rec


def _describe_jvm(info, ftype) -> str:
    kind = "JAR" if ftype == filetype.JAR else "Java class"
    parts = [kind]
    if info.java_version:
        parts.append(f"Java {info.java_version}")
    if info.main_class:
        parts.append(f"main-class {info.main_class}")
    if info.classes:
        parts.append(f"{len(info.classes)} class" + ("es" if len(info.classes) != 1 else ""))
    if info.signed:
        parts.append("signed")
    return ", ".join(parts)


def _describe_dotnet(info) -> str:
    parts = [".NET assembly"]
    if info.clr_version:
        parts.append(f"CLR {info.clr_version}")
    if info.type_count:
        parts.append(f"{info.type_count} type" + ("s" if info.type_count != 1 else ""))
    if info.method_count:
        parts.append(f"{info.method_count} method" + ("s" if info.method_count != 1 else ""))
    if info.runtime_flags & 0x1:
        parts.append("IL-only")
    return ", ".join(parts)


def _describe(rec: dict) -> str:
    # was hardcoded "ELF", which described a Windows PE as an ELF the moment PE triage
    # started filling these fields in
    parts = [{"pe": "PE", "macho": "Mach-O"}.get(rec.get("file_type"), "ELF")]
    if rec["bits"]:
        parts.append(f"{rec['bits']}-bit")
    if rec["endianness"]:
        parts.append(rec["endianness"])
    if rec["arch"]:
        parts.append(rec["arch"])
    if rec["linking"]:
        parts.append({"dynamic": "dynamically linked", "static-pie": "statically linked (PIE)",
                      "static": "statically linked"}.get(rec["linking"], "statically linked"))
    if rec["stripped"]:
        parts.append("stripped")
    sub = (rec.get("format_details") or {}).get("subsystem")
    if sub:
        parts.append(sub)
    return ", ".join(parts)


def validate(rec: dict) -> list[str]:
    """Return a list of schema violations (empty = valid)."""
    errs = []
    if rec.get("schema_version") != SCHEMA_VERSION:
        errs.append("bad schema_version")
    for k in ("sha256", "file_type", "mitigations", "entropy", "parse_errors",
              "tool_version"):
        if k not in rec:
            errs.append(f"missing key {k}")
    if rec.get("file_type") not in _FILE_TYPES:
        errs.append(f"bad file_type {rec.get('file_type')!r}")
    if rec.get("bits") not in (None, 32, 64):
        errs.append(f"bad bits {rec.get('bits')!r}")
    for mk, mv in (rec.get("mitigations") or {}).items():
        if mv not in MITIGATION_ENUM:
            errs.append(f"bad mitigation {mk}={mv!r}")
    return errs
