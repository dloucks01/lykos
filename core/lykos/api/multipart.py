"""Minimal multipart/form-data file extractor (stdlib cgi is gone in 3.13+).

Handles the common single-file upload shape produced by httpx/curl. Not a general parser.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

_FILENAME = re.compile(rb'filename="([^"]*)"')


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
