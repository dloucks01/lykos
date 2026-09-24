"""MemorySanitizer path (CWE-457): a source target compiles to a second MSan binary at ingest, and
detonating an input that reads uninitialized memory against it yields a corroborated CWE-457 finding.
Guards the three integration bugs found the hard way: detonation lives on the sandbox-fuzz path (not
coverage_fuzz, which skips ASan builds); MSan runs with symbolize=0 (llvm-symbolizer deadlocks under
captured pipes) and the source line comes from addr2line; and ctx.put_artifact returns the sha str."""
import shutil
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("clang") is None, reason="clang (MSan) not installed")

# reads 15 bytes; on 'U' it write()s an uninitialized buffer -- a syscall the compiler cannot elide,
# so MSan reliably reports use-of-uninitialized-value (unlike a foldable `if(x==const)`).
_SRC = ("#include <unistd.h>\n"
        "int main(void){char in[16];int n=read(0,in,15);if(n<=0)return 0;"
        "char secret[8];if(in[0]=='U')write(1,secret,8);return 0;}\n")


class _Ctx:
    """Minimal stage context: exactly what msan_detonate touches."""
    def __init__(self, store, cid, scratch):
        self.conn, self.content, self.case_id = store.conn, store.content, cid
        self._store, self._scratch = store, scratch

    def scratch(self):
        return self._scratch

    def put_artifact(self, kind, data=None):
        return self._store.put_artifact(self.case_id, kind, data=data).sha256

    def emit(self, *a, **k):
        pass


def test_msan_detonate_finds_uninitialized_read(store, case):
    from lykos.analyze.fuzz.stage import msan_detonate
    from lykos.analyze.ingest import ingest
    from lykos.db.dao import ArtifactDAO, FindingDAO

    d = Path(tempfile.mkdtemp())
    src = d / "u.c"; src.write_text(_SRC)
    target = ingest(store, case.id, src, filename="u.c")
    # ingest built + stored the MSan binary alongside the ASan target
    kinds = {a.kind for a in ArtifactDAO(store.conn).list_by_case(case.id)}
    assert "msan-blob" in kinds, "ingest must build a MemorySanitizer binary for source targets"

    ctx = _Ctx(store, case.id, d)
    n = msan_detonate(ctx, target, [b"U1234567", b"x1234567"], "stdin", exec_timeout=5)
    assert n == 1, "the 'U' input triggers the uninitialized read; the other does not"

    findings = FindingDAO(store.conn).list_by_target(target.id)
    uninit = [f for f in findings if f.cwe == "CWE-457"]
    assert uninit, "a CWE-457 finding must be filed"
    f = uninit[0]
    assert f.state == "corroborated" and f.detector == "msan"
    detail = " ".join(e.get("detail", "") for e in (f.evidence or []))
    assert "u.c:" in detail, detail  # addr2line-recovered source line in the evidence
