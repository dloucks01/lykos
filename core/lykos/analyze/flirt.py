"""FLIRT-style library-function identification for STRIPPED STATIC binaries (pure stdlib).

A statically-linked, stripped ELF compiles libc in with NO symbols, so a call to strcpy/gets/
system shows up in recovery as `fcn.XXXXXX` -- invisible to the call-graph detectors (dangerous_api
keys on the call edge's dst_name) and to the symbol-driven exploit paths. 625 functions recovered,
0 named, 0 dangerous_api findings on a static strcpy target: the sink is there and unseen.

This recovers the NAMES of the security-relevant libc functions by matching each recovered
function's bytes against signatures built from a REFERENCE static archive (libc.a). The archive is
the right reference, not libc.so: its `.o` members carry the exact function bodies the static
binary links -- the IFUNC-resolved variants (`__strcpy_avx2`) included, which a shared libc hides
behind an IFUNC stub -- AND a relocation table (`.rela.<section>`) that says precisely which bytes
are variant (a call/PC-relative operand the linker fills in). So the match MASKS exactly those
bytes, like real FLIRT keys on a masked pattern, instead of guessing which bytes move.

Scope is deliberately the security-relevant sinks + a few primitives, not all of libc: naming the
dangerous calls is what unblocks detection, and a narrow set keeps false names near zero.
"""
from __future__ import annotations

import struct
from typing import Optional

# The functions worth naming: shell/exec sinks (RCE), the classic unbounded-copy sinks (overflow),
# the format sinks, and a couple of I/O primitives the exploit paths look for. Variant spellings
# (IFUNC resolutions, internal aliases) map to the canonical name the detectors expect.
_WANTED = {
    "system", "popen", "execve", "execv", "execvp", "execl", "execlp", "execle",
    "gets", "strcpy", "strcat", "stpcpy", "sprintf", "vsprintf", "scanf", "sscanf",
    "printf", "fprintf", "snprintf", "memcpy", "mempcpy", "memmove", "strncpy", "strncat",
    "read", "write", "open", "recv",
}
# IFUNC / internal spellings -> canonical. A static link pulls in e.g. __strcpy_avx2 or __GI_strcpy;
# strip the decoration so the recovered name is the one dangerous_api/detect.catalog know.
_ALIAS_PREFIXES = ("__GI_", "__libc_", "__")
_VARIANT_SUFFIX = ("_avx2", "_avx", "_sse2", "_sse2_unaligned", "_ssse3", "_erms", "_avx512",
                   "_avx512_no_vzeroupper", "_avx_unaligned", "_avx_unaligned_erms",
                   "_sse2_unaligned_erms", "_generic", "_ia32", "_avx512_unaligned",
                   "_avx512_unaligned_erms", "_evex", "_evex_unaligned", "_evex_unaligned_erms")

_CAP = 96          # bytes of prologue to key on -- long enough to be distinctive, short enough
                   # that a recovered function whose tail boundary rizin got slightly wrong still
                   # matches on its head.
_MIN_UNMASKED = 16  # require at least this many non-variant bytes to agree, so a short/!generic
                    # prologue cannot collide its way to a false name.


def _canonical(name: str) -> Optional[str]:
    """Map a reference-archive symbol name to the canonical libc name we want, or None to skip."""
    n = name
    for p in _ALIAS_PREFIXES:
        while n.startswith(p):
            n = n[len(p):]
    for s in _VARIANT_SUFFIX:
        if n.endswith(s):
            n = n[: -len(s)]
            break
    return n if n in _WANTED else None


# ---- `ar` archive (libc.a) ----------------------------------------------------------------
def _ar_members(data: bytes):
    """Yield (name, bytes) for each member of a System V `ar` archive. The long-name table
    (`//`) and the symbol table (`/`) members are handled so real member names come through."""
    if data[:8] != b"!<arch>\n":
        return
    off = 8
    longnames = b""
    n = len(data)
    while off + 60 <= n:
        hdr = data[off:off + 60]
        if hdr[58:60] != b"`\n":
            break
        name = hdr[0:16].rstrip()
        try:
            size = int(hdr[48:58].strip() or b"0")
        except ValueError:
            break
        body = data[off + 60: off + 60 + size]
        if name == b"//":
            longnames = body                             # the long-name string table
        elif name in (b"/", b"/SYM64/"):
            pass                                         # the archive symbol index -- not a member
        else:
            if name.startswith(b"/"):                    # /<offset> into the long-name table
                try:
                    start = int(name[1:])
                    end = longnames.find(b"/\n", start)
                    if end < 0:
                        end = longnames.find(b"\n", start)
                    name = longnames[start:end]
                except ValueError:
                    pass
            else:
                name = name.rstrip(b"/")
            yield name.decode("latin-1", "replace"), body
        off += 60 + size + (size & 1)                    # members are 2-byte aligned


# ---- relocatable ELF64 `.o` parsing (self-contained) --------------------------------------
# A FLIRT signature from a .o is (masked bytes, mask): the function's code with the variant bytes
# (the operands the linker relocates) marked "ignore". We read that mask straight from the .o's
# relocation entries -- no disassembly, and exact rather than a heuristic.
_SHT_SYMTAB, _SHT_RELA = 2, 4
_STT_FUNC = 2
# x86-64 relocs that patch a 4-byte PC-relative operand (a call/jmp/lea target): the variant bytes.
_R_PC32_WIDTH = {2: 4, 4: 4, 1: 8, 9: 4, 10: 4, 11: 4}   # PC32/PLT32 -> 4; 64 -> 8; GOTPCREL... -> 4


def _o_signatures(obj: bytes, out: dict) -> None:
    """Add {canonical_name: [(sig, mask)]} from one relocatable ELF64 `.o` to `out`."""
    if len(obj) < 64 or obj[:4] != b"\x7fELF" or obj[4] != 2:   # ELFCLASS64 only
        return
    endc = "<" if obj[5] == 1 else ">"
    e_shoff = struct.unpack_from(endc + "Q", obj, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endc + "HHH", obj, 58)
    if not e_shoff or not e_shnum:
        return
    secs = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        if base + 64 > len(obj):
            break
        name, typ, _fl, _addr, sh_off, sh_size, sh_link, sh_info, _al, sh_ent = \
            struct.unpack_from(endc + "IIQQQQIIQQ", obj, base)
        secs.append({"type": typ, "off": sh_off, "size": sh_size, "link": sh_link,
                     "info": sh_info, "ent": sh_ent})
    symtab = next((s for s in secs if s["type"] == _SHT_SYMTAB), None)
    if not symtab or not symtab["ent"]:
        return
    strtab = secs[symtab["link"]] if symtab["link"] < len(secs) else None
    if not strtab:
        return
    strb = obj[strtab["off"]: strtab["off"] + strtab["size"]]

    def _str(o):
        end = strb.find(b"\x00", o)
        return strb[o:end].decode("latin-1", "replace") if o < len(strb) else ""

    # Per section: the variant-byte mask from its .rela.<section> (rela.info-> this section).
    masks: dict = {}          # section index -> set of masked byte offsets
    for s in secs:
        if s["type"] == _SHT_RELA and s["ent"] >= 24:
            tgt = s["info"]
            mset = masks.setdefault(tgt, set())
            for k in range(0, s["size"], s["ent"]):
                p = s["off"] + k
                if p + 24 > len(obj):
                    break
                r_offset, r_info = struct.unpack_from(endc + "QQ", obj, p)
                r_type = r_info & 0xFFFFFFFF
                w = _R_PC32_WIDTH.get(r_type, 4)
                for b in range(r_offset, r_offset + w):
                    mset.add(b)

    nsym = symtab["size"] // symtab["ent"]
    for i in range(nsym):
        p = symtab["off"] + i * symtab["ent"]
        if p + 24 > len(obj):
            break
        st_name, st_info, _st_other, st_shndx, st_value, st_size = \
            struct.unpack_from(endc + "IBBHQQ", obj, p)
        if (st_info & 0xF) != _STT_FUNC or not st_size or st_shndx >= len(secs):
            continue
        canon = _canonical(_str(st_name))
        if not canon:
            continue
        sec = secs[st_shndx]
        fstart = sec["off"] + st_value
        flen = min(st_size, _CAP)
        if fstart + flen > len(obj):
            continue
        code = bytearray(obj[fstart: fstart + flen])
        mask = bytearray(b"\xff") * flen
        for b in masks.get(st_shndx, ()):               # mask variant bytes relative to function
            rel = b - st_value
            if 0 <= rel < flen:
                code[rel] = 0
                mask[rel] = 0
        if sum(1 for m in mask if m) >= _MIN_UNMASKED:
            out.setdefault(canon, []).append((bytes(code), bytes(mask)))


def build_signatures(archive_bytes: bytes) -> dict:
    """{canonical_name: [(sig_bytes, mask_bytes)]} for the wanted sinks, from a libc.a archive."""
    sigs: dict = {}
    for _name, body in _ar_members(archive_bytes):
        try:
            _o_signatures(body, sigs)
        except Exception:                                # noqa: BLE001 -- one bad member must not
            continue                                     # sink the whole archive
    return sigs


# ---- matching against a target --------------------------------------------------------------
def _va_to_off(target: bytes, va: int):
    """File offset of a virtual address in an ELF, via its program headers (PT_LOAD)."""
    if len(target) < 64 or target[:4] != b"\x7fELF":
        return None
    is64 = target[4] == 2
    endc = "<" if target[5] == 1 else ">"
    if not is64:
        return None
    e_phoff = struct.unpack_from(endc + "Q", target, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from(endc + "HH", target, 54)
    for i in range(e_phnum):
        b = e_phoff + i * e_phentsize
        if b + 56 > len(target):
            break
        p_type, _fl, p_off, p_va, _pa, p_filesz = struct.unpack_from(endc + "IIQQQQ", target, b)
        if p_type == 1 and p_va <= va < p_va + p_filesz:     # PT_LOAD
            return p_off + (va - p_va)
    return None


def _matches_at(code: bytes, off: int, sig: bytes, mask: bytes) -> bool:
    if off < 0 or off + len(sig) > len(code):
        return False
    for i, m in enumerate(mask):
        if m and code[off + i] != sig[i]:
            return False
    return True


def _anchor(sig: bytes, mask: bytes):
    """A contiguous run of >=6 unmasked bytes to seed a fast bytes.find scan, with its offset in
    the signature. None when no run is long enough (then the signature is skipped for scanning --
    too generic to anchor safely)."""
    best = None
    i = 0
    n = len(mask)
    while i < n:
        if mask[i]:
            j = i
            while j < n and mask[j]:
                j += 1
            if best is None or (j - i) > (best[1] - best[0]):
                best = (i, j)
            i = j
        else:
            i += 1
    if best and (best[1] - best[0]) >= 6:
        a, b = best
        return sig[a:b], a
    return None


def _exec_ranges(target: bytes):
    """(file_off, va, size) for each executable PT_LOAD segment of an ELF64."""
    out = []
    if len(target) < 64 or target[:4] != b"\x7fELF" or target[4] != 2:
        return out
    endc = "<" if target[5] == 1 else ">"
    e_phoff = struct.unpack_from(endc + "Q", target, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from(endc + "HH", target, 54)
    for i in range(e_phnum):
        b = e_phoff + i * e_phentsize
        if b + 56 > len(target):
            break
        p_type, p_flags, p_off, p_va, _pa, p_filesz = struct.unpack_from(endc + "IIQQQQ", target, b)
        if p_type == 1 and (p_flags & 1):                    # PT_LOAD, executable
            out.append((p_off, p_va, p_filesz))
    return out


def identify(target_bytes: bytes, functions=None, signatures: dict = None) -> dict:
    """{function-address-string: canonical-name} for every place in the executable segments whose
    bytes match a reference signature -- NOT limited to recovered function starts, because the
    functions worth naming (IFUNC-resolved str/mem variants) are exactly the ones rizin reaches
    only through a resolver and never isolates. The signatures are long (up to 96 bytes) and
    anchored on a >=6-byte unmasked run, so a whole-segment scan still finds a match in milliseconds
    and a false positive is astronomically unlikely. `functions` is accepted and ignored (the scan
    supersedes a recovered-start-only match); kept for call compatibility."""
    found: dict = {}
    if not signatures:
        return found
    ranges = _exec_ranges(target_bytes)
    for name, variants in signatures.items():
        for sig, mask in variants:
            anc = _anchor(sig, mask)
            if not anc:
                continue
            anchor, aoff = anc
            for seg_off, seg_va, seg_size in ranges:
                seg = target_bytes[seg_off: seg_off + seg_size]
                pos = 0
                while True:
                    k = seg.find(anchor, pos)
                    if k < 0:
                        break
                    start = k - aoff
                    if _matches_at(seg, start, sig, mask):
                        found.setdefault(hex(seg_va + start), name)
                    pos = k + 1
    return found


_SIG_CACHE = None
# Names a recovery backend hands an unidentified function; only these (or an empty name) are
# overwritten -- a real symbol / dynamic import is never clobbered.
_GENERIC = ("fcn.", "loc.", "sub_", "func.", "unk.", "imp.", "sym.func.")


def _signatures() -> dict:
    global _SIG_CACHE
    if _SIG_CACHE is None:
        path = reference_archive()
        if not path:
            _SIG_CACHE = {}
        else:
            try:
                with open(path, "rb") as f:
                    _SIG_CACHE = build_signatures(f.read())
            except Exception:                            # noqa: BLE001
                _SIG_CACHE = {}
    return _SIG_CACHE


def _is_generic(name) -> bool:
    n = str(name or "")
    return (not n) or n.startswith(_GENERIC)


def relabel(target_bytes: bytes, funcs: list) -> int:
    """Name the security-relevant libc functions in a STRIPPED STATIC x86-64 target by matching its
    code against libc.a signatures, and propagate the names onto the call EDGES so the call-graph
    detectors (dangerous_api keys on dst_name) see `system`/`strcpy`/... instead of `fcn.XXXX`.

    Mutates `funcs` in place (each is a dict with `addr`, `name`, and `calls`=[{dst_addr, dst_name,
    ...}]); returns how many names were applied. A no-op -- so a dynamic/named target is untouched --
    when there is no reference archive, the target is not x86-64 ELF, or nothing matches. Only a
    generic/blank name is ever overwritten."""
    if (not target_bytes or len(target_bytes) < 5 or target_bytes[:4] != b"\x7fELF"
            or target_bytes[4] != 2):                    # ELFCLASS64 only (the signatures are x86-64)
        return 0
    sigs = _signatures()
    if not sigs:
        return 0
    named = identify(target_bytes, None, sigs)           # {hex_va: canonical name}
    if not named:
        return 0

    def _hx(a):
        try:
            return hex(int(str(a), 16) if str(a).lower().startswith("0x") else int(a))
        except (TypeError, ValueError):
            return None

    applied = 0
    have = set()
    for f in funcs:
        hx = _hx(f.get("addr"))
        if hx is not None:
            have.add(hx)
        if hx in named and _is_generic(f.get("name")):
            f["name"] = named[hx]
            applied += 1
        for c in f.get("calls", []) or []:
            dhx = _hx(c.get("dst_addr"))
            if dhx in named and _is_generic(c.get("dst_name")):
                c["dst_name"] = named[dhx]
                applied += 1
    # A matched libc function the backend never isolated (an IFUNC variant reached only through a
    # resolver) still deserves a row, so the symbol-driven exploit paths can resolve e.g. system's
    # address by name even with no recovered edge to it.
    for hx, name in named.items():
        if hx not in have:
            funcs.append({"addr": hx, "name": name, "size": None, "calls": [],
                          "flirt": True})
            applied += 1
    return applied


def reference_archive() -> Optional[str]:
    """Where to read the reference libc.a: an operator override, then the usual host locations.
    In the air-gap bundle the operator points LYKOS_REF_LIBC_A at the target distro's libc.a."""
    import os
    env = os.environ.get("LYKOS_REF_LIBC_A")
    cands = ([env] if env else []) + [
        "/usr/lib/x86_64-linux-gnu/libc.a", "/usr/lib/libc.a", "/usr/lib64/libc.a",
        "/usr/lib/x86_64-linux-gnu/libc_pic.a",
    ]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None
