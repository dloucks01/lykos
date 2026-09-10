"""Phase 6/A — hard-coded-secret PoC packaging (`synthesize_secret`).

The stage turns a static CWE-798/CWE-321 finding into a verified, self-contained PoC without
executing the target: it locates the secret's byte offset in the binary, re-extracts it to
verify, and bundles a pure-stdlib offline reproducer. These tests exercise the extraction/
verification helpers, the bundle + its shipped reproducer roundtrip, and detection parity with
the static detector.
"""
import io
import subprocess
import sys
import tarfile

import pytest
from lykos.analyze.detect.detectors import _secret
from lykos.analyze.poc import bundle
from lykos.analyze.poc import secret_stage as ss

_SEC_C = (
    '#include <stdio.h>\n#include <string.h>\n'
    'static const char *API_KEY = "api_key=AKIAIOSFODNN7EXAMPLE";\n'
    'static const char *DBPASS  = "db_password=S3cr3t_Pa55w0rd!";\n'
    'int main(int c,char**v){char b[16];if(c>1)strcpy(b,v[1]);\n'
    '  if(c>1&&!strcmp(v[1],API_KEY))printf("%s\\n",DBPASS);return 0;}\n'
)


def test_secret_predicate_parity():
    # the stage reuses the detector's exact predicate, so dedup keys line up and the finding
    # is promoted (not duplicated).
    assert _secret("api_key=AKIAIOSFODNN7EXAMPLE")[0] == "CWE-798"
    assert _secret("-----BEGIN PRIVATE KEY-----")[0] == "CWE-321"
    assert _secret("just a normal string here") is None


def test_file_offset_and_verify_roundtrip():
    blob = b"\x00\x00header" + b"db_password=hunter2xyz\x00" + b"tail"
    off = ss._file_offset(blob, "db_password=hunter2xyz")
    assert off is not None
    assert b"db_password=hunter2xyz" in ss._cstr_at(blob, off)
    # a value not present is not locatable (so it never becomes a false PoC)
    assert ss._file_offset(blob, "nonexistent_secret_value") is None


def test_bundle_reproducer_reextracts_offline(tmp_path):
    blob = b"pad" + b"api_key=AKIAABCDEFGHIJKLMNOP\x00" + b"xx" + b"token=Zzsecretvalue123\x00"
    secrets = []
    for v in ("api_key=AKIAABCDEFGHIJKLMNOP", "token=Zzsecretvalue123"):
        off = ss._file_offset(blob, v)
        hit = _secret(v)
        secrets.append({"value": v, "cwe": hit[0] if hit else "CWE-798",
                        "severity": "high", "title": "secret", "file_offset": off})
    data = bundle.build_secret(blob, secrets, {"target_sha256": "x", "arch": "x86-64"})
    # the bundle carries the expected files
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        names = set(t.getnames())
    assert {"poc/target.bin", "poc/extract.py", "poc/secrets.json",
            "poc/runner.sh", "poc/README.txt"} <= names
    # the shipped reproducer re-derives both secrets from target.bin alone (no target execution)
    d = tmp_path / "poc"
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        t.extractall(tmp_path)
    r = subprocess.run([sys.executable, str(d / "extract.py"), str(d / "target.bin")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "AKIAABCDEFGHIJKLMNOP" in r.stdout and "Zzsecretvalue123" in r.stdout
    assert "2/2 secret(s)" in r.stdout


def test_reproducer_fails_on_wrong_binary(tmp_path):
    """A tampered/different binary that lacks the secret makes the reproducer report failure —
    the PoC is falsifiable, not a rubber stamp."""
    blob = b"pad" + b"api_key=AKIAABCDEFGHIJKLMNOP\x00"
    off = ss._file_offset(blob, "api_key=AKIAABCDEFGHIJKLMNOP")
    data = bundle.build_secret(blob, [{"value": "api_key=AKIAABCDEFGHIJKLMNOP",
                                       "cwe": "CWE-798", "severity": "high",
                                       "title": "secret", "file_offset": off}],
                              {"target_sha256": "x", "arch": "x86-64"})
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        t.extractall(tmp_path)
    other = tmp_path / "other.bin"
    other.write_bytes(b"a binary without the secret at all")
    r = subprocess.run([sys.executable, str(tmp_path / "poc" / "extract.py"), str(other)],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "NOT found" in r.stdout


def test_on_real_binary(gcc, tmp_path):
    """A real compiled binary with two planted secrets: both are locatable and verify."""
    c = tmp_path / "s.c"; c.write_text(_SEC_C)
    b = tmp_path / "sec"
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(b)],
                      capture_output=True).returncode:
        pytest.skip("build failed")
    blob = b.read_bytes()
    found = {}
    for v in ("api_key=AKIAIOSFODNN7EXAMPLE", "db_password=S3cr3t_Pa55w0rd!"):
        assert _secret(v) is not None
        off = ss._file_offset(blob, v)
        assert off is not None
        assert v.encode()[:16] in ss._cstr_at(blob, off)   # verify re-extraction
        found[v] = off
    assert len(found) == 2 and len(set(found.values())) == 2   # distinct offsets
