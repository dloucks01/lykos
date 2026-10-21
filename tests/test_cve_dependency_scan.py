"""N-day fingerprinting (doc 46 #2): a dynamically-linked target's component versions live in its
DEPENDENCY libraries, not the main binary. `_needed_sonames` reads the DT_NEEDED bill of materials
(present even when stripped), and `_dependency_blobs` gathers the supplied .so files to scan."""
from __future__ import annotations

import subprocess

from lykos.analyze.fingerprint.stage import _dependency_blobs, _needed_sonames


def test_needed_sonames_reads_dt_needed(gcc, tmp_path):
    src = tmp_path / "t.c"
    src.write_text("int main(void){return 0;}")
    exe = tmp_path / "t"
    subprocess.run([gcc, str(src), "-o", str(exe)], check=True)
    sonames = _needed_sonames(exe.read_bytes())
    assert any(s.startswith("libc.so") for s in sonames), sonames


def test_dependency_blobs_gathers_companions(store, case):
    from tests.factories import make_target
    # a fake dependency blob stored as a companion of the target
    dep = b"\x7fELF" + b"...libfoo version 1.2.3..." + b"\x00" * 64
    sha, _rel, _sz = store.content.put_bytes(dep)
    t = make_target(store, case.id)
    t.deps = {"usr/lib/libfoo.so.1": sha}               # as a directory ingest would record it

    class _Ctx:
        content = store.content
    got = _dependency_blobs(_Ctx(), t, ["libfoo.so.1", "libbar.so.2"])
    assert [(s, b == dep) for s, b in got] == [("libfoo.so.1", True)]
