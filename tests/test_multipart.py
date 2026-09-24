"""Multipart extraction: the in-memory parser and the streaming (large-upload) parser must agree."""
from lykos.api.multipart import extract_file, extract_file_to


def _body(boundary: str, filename: str, data: bytes) -> bytes:
    b = boundary.encode()
    return (b"--" + b + b"\r\n"
            b'Content-Disposition: form-data; name="file"; filename="' + filename.encode()
            + b'"\r\n' + b"Content-Type: application/octet-stream\r\n\r\n"
            + data + b"\r\n--" + b + b"--\r\n")


def test_stream_extract_matches_inmemory(tmp_path):
    boundary = "X-BOUND-abc123"
    payload = bytes(range(256)) * 700          # ~180 KB of binary, incl. CR/LF bytes
    ctype = f"multipart/form-data; boundary={boundary}"
    body = _body(boundary, "firmware.bin", payload)
    src = tmp_path / "body.bin"; src.write_bytes(body)
    dest = tmp_path / "out.bin"

    fn = extract_file_to(ctype, src, dest)
    assert fn == "firmware.bin"
    assert dest.read_bytes() == payload        # streamed bytes are exact

    fn2, data2 = extract_file(ctype, body)     # and agree with the in-memory parser
    assert fn2 == "firmware.bin" and data2 == payload


def test_stream_extract_returns_none_when_no_file_part(tmp_path):
    boundary = "B"
    ctype = f"multipart/form-data; boundary={boundary}"
    # a field-only body (no filename=) -> streaming extractor declines, caller falls back
    body = b"--B\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nvalue\r\n--B--\r\n"
    src = tmp_path / "b.bin"; src.write_bytes(body)
    assert extract_file_to(ctype, src, tmp_path / "o.bin") is None
