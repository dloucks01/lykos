"""T2 #3 harness stage (doc 46): rank -> harness-fuzz -> file a function-level finding, end to end,
with honest provenance."""
from __future__ import annotations

import subprocess

import pytest

from lykos.analyze.harness.emulate import available
from lykos.analyze.harness.harness_stage import harness_stage
from lykos.db.dao import CallEdgeDAO, FindingDAO, FunctionDAO

pytestmark = pytest.mark.skipif(not available(), reason="unicorn not installed")

_SRC = r"""
#include <string.h>
static int t[8] = {1,2,3,4,5,6,7,8};
int lookup(char *buf, int len){ int idx=0; memcpy(&idx, buf, 4); return t[idx]; }
int main(void){ char z[4]={0}; return lookup(z,4); }
"""


class _Ctx:
    def __init__(self, store, target_id, case_id, params):
        self.conn = store.conn
        self.content = store.content
        self.params = params

        class _R:
            pass
        self.run = _R()
        self.run.target_id = target_id
        self.run.case_id = case_id
        self.target_id = target_id

    def emit(self, *a, **k):
        pass

    def progress(self, *a, **k):
        pass

    def put_artifact(self, kind, *, data=None, **k):
        import hashlib
        return hashlib.sha256(data or b"").hexdigest()


def test_harness_stage_files_a_function_level_finding(store, case, gcc, tmp_path):
    s = tmp_path / "t.c"
    s.write_text(_SRC)
    exe = tmp_path / "t"
    subprocess.run([gcc, "-no-pie", "-O0", "-w", "-fno-builtin", str(s), "-o", str(exe)], check=True)
    addr = size = None
    for line in subprocess.run(["nm", "--print-size", str(exe)],
                               capture_output=True, text=True).stdout.splitlines():
        p = line.split()
        if p and p[-1] == "lookup":
            addr = int(p[0], 16)
            size = int(p[1], 16) if len(p) == 4 else 200
    assert addr
    data = exe.read_bytes()
    sha, _rel, _sz = store.content.put_bytes(data)
    t = store.targets.upsert(case.id, filename="t", sha256=sha, size=len(data),
                             arch="x86-64", bits=64)
    FunctionDAO(store.conn).replace_for_target(t.id, [
        {"addr": hex(addr), "name": "lookup", "size": size, "blocks": 4, "edges": 5,
         "params": [{"type": "char *", "name": "buf"}, {"type": "int", "name": "len"}]}])
    CallEdgeDAO(store.conn).replace_for_target(t.id, [{"src_addr": hex(addr), "dst_name": "memcpy"}])

    ctx = _Ctx(store, t.id, case.id, {"harness_execs": 12000, "harness_seconds": 40})
    res = harness_stage(ctx)
    assert res.get("findings", 0) >= 1, res
    harness_finds = [f for f in FindingDAO(store.conn).list_by_case(case.id)
                     if f.detector == "harness"]
    assert harness_finds
    f = harness_finds[0]
    assert f.cwe == "CWE-125"                          # the OOB read
    assert "function-level" in (f.title or "")
