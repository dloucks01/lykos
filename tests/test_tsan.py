"""ThreadSanitizer path (CWE-362): a source target compiles to a third TSan binary at ingest, and
detonating an input that drives the racy threaded path against it yields a corroborated CWE-362
data-race finding -- the concurrency class none of ASan/UBSan/MSan can see. Also unit-checks that the
shared sanitizer classifier recognises ThreadSanitizer (CWE-362) and LeakSanitizer (CWE-401)."""
import shutil
import tempfile
from pathlib import Path

import pytest

from lykos.analyze.debug.rootcause import parse_asan_report


def test_parse_asan_report_recognises_tsan_and_lsan():
    assert parse_asan_report("WARNING: ThreadSanitizer: data race (pid=1)")["cwe"] == "CWE-362"
    assert parse_asan_report("SUMMARY: ThreadSanitizer: lock-order-inversion x")["cwe"] == "CWE-362"
    lk = parse_asan_report("==1==ERROR: LeakSanitizer: detected memory leaks\n"
                           "Direct leak of 7 byte(s) in 1 object(s)")
    assert lk["cwe"] == "CWE-401"
    assert parse_asan_report("nothing to see here") is None


_HAS_TSAN = shutil.which("gcc") or shutil.which("clang")

# two threads write the same global with no lock -> a data race TSan reports on a single run. The
# read(2) gates it on input so a fuzz corpus (not just crashes) is what drives the threaded path.
_SRC = ("#include <pthread.h>\n#include <unistd.h>\n"
        "static int g;\n"
        "static void* w(void* a){ g++; return 0; }\n"
        "int main(void){ char b[8]; if(read(0,b,8)<=0) return 0; pthread_t t1,t2;\n"
        " pthread_create(&t1,0,w,0); pthread_create(&t2,0,w,0);\n"
        " pthread_join(t1,0); pthread_join(t2,0); return 0; }\n")


class _Ctx:
    """Minimal stage context: exactly what tsan_detonate touches."""
    def __init__(self, store, cid, scratch):
        self.conn, self.content, self.case_id = store.conn, store.content, cid
        self._store, self._scratch = store, scratch

    def scratch(self):
        return self._scratch

    def put_artifact(self, kind, data=None):
        return self._store.put_artifact(self.case_id, kind, data=data).sha256

    def emit(self, *a, **k):
        pass


@pytest.mark.skipif(not _HAS_TSAN, reason="no C compiler with ThreadSanitizer")
def test_tsan_detonate_finds_data_race(store, case):
    from lykos.analyze.fuzz.stage import tsan_detonate
    from lykos.analyze.ingest import ingest
    from lykos.db.dao import ArtifactDAO, FindingDAO

    d = Path(tempfile.mkdtemp())
    src = d / "race.c"; src.write_text(_SRC)
    target = ingest(store, case.id, src, filename="race.c")
    kinds = {a.kind for a in ArtifactDAO(store.conn).list_by_case(case.id)}
    if "tsan-blob" not in kinds:
        pytest.skip("ThreadSanitizer build unavailable in this toolchain")

    ctx = _Ctx(store, case.id, d)
    n = tsan_detonate(ctx, target, [b"xxxxxxxx", b"AAAA"], "stdin", exec_timeout=8)
    assert n >= 1, "the threaded input must surface the data race"

    race = [f for f in FindingDAO(store.conn).list_by_target(target.id) if f.cwe == "CWE-362"]
    assert race, "a CWE-362 finding must be filed"
    assert race[0].state == "corroborated" and race[0].detector == "tsan"
