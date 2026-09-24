"""Minimal multipart/form-data file extractor (stdlib cgi is gone in 3.13+).

Handles the common single-file upload shape produced by httpx/curl. Not a general parser.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional, Tuple

_FILENAME = re.compile(rb'filename="([^"]*)"')
_CHUNK = 1 << 20


def parse_boundary(content_type: str) -> Optional[bytes]:
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("boundary="):
            return part[len("boundary="):].strip('"').encode()
    return None


def extract_file(content_type: str, body: bytes) -> Tuple[Optional[str], Optional[bytes]]:
    boundary = parse_boundary(content_type)
    if not boundary:
        return None, None
    delim = b"--" + boundary
    for part in body.split(delim):
        if b"Content-Disposition" in part and b"filename=" in part:
            header, _, data = part.partition(b"\r\n\r\n")
            if not data:
                continue
            data = data[:-2] if data.endswith(b"\r\n") else data  # trailing CRLF before next delim
            m = _FILENAME.search(header)
            filename = m.group(1).decode("utf-8", "replace") if m else "upload.bin"
            return filename, data
    return None, None


def extract_file_to(content_type: str, src: Path, dest: Path,
                    *, head: int = 1 << 16) -> Optional[str]:
    """Extract the single uploaded file from a multipart body already streamed to `src`, copying
    its bytes to `dest` WITHOUT loading the whole body into memory. Returns the filename, or None
    when the file part cannot be located cheaply (the caller then falls back to the in-memory
    `extract_file`). Targets the common single-file shape: the file part's headers sit near the
    start and its closing boundary is the last one in the body.
    """
    boundary = parse_boundary(content_type)
    if not boundary:
        return None
    delim = b"--" + boundary
    size = src.stat().st_size
    with open(src, "rb") as f:
        window = f.read(head)                       # the part headers live near the start
        fn_at = window.find(b"filename=")
        if fn_at == -1:
            return None
        hdr_end = window.find(b"\r\n\r\n", fn_at)   # blank line ending the part's headers
        if hdr_end == -1:
            return None
        data_start = hdr_end + 4
        part_start = window.rfind(delim, 0, fn_at)
        m = _FILENAME.search(window[max(0, part_start):data_start])
        filename = m.group(1).decode("utf-8", "replace") if m else "upload.bin"
        # The data ends at the closing boundary. For a single file part that is the LAST
        # `\r\n--boundary` in the body, found from a bounded tail window.
        tail_len = min(size, head + len(delim) + 8)
        f.seek(size - tail_len)
        tail = f.read(tail_len)
        end_rel = tail.rfind(b"\r\n" + delim)
        if end_rel == -1:
            return None
        data_end = (size - tail_len) + end_rel
        if data_end < data_start:
            return None
        # Copy [data_start, data_end) to dest in chunks.
        f.seek(data_start)
        remaining = data_end - data_start
        with open(dest, "wb") as out:
            while remaining > 0:
                chunk = f.read(min(_CHUNK, remaining))
                if not chunk:
                    break
                out.write(chunk)
                remaining -= len(chunk)
    return filename
