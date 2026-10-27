"""Win32 static dangerous-import detector (detect/detectors.py windows_dangerous_imports).

rizin does not resolve a PE's IAT thunks into named call edges, so the call-graph `dangerous_api`
detector misses WinExec/wsprintf/ShellExecute/... on a PE even though the import plainly says the
program can call them. This reads the import table straight from the image and files each high-signal
sink import as an honest candidate -- the static twin of the dynamic winmonitor set.
"""
import re
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.detect import enqueue_detect
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _mingw(tmp_path, src: str, out: str):
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if not cc:
        pytest.skip("no mingw cross compiler")
    c = tmp_path / (out + ".c")
    c.write_text(src)
    o = tmp_path / out
    r = subprocess.run([cc, "-O1", "-w", str(c), "-o", str(o), "-lkernel32", "-luser32"],
                       capture_output=True, timeout=180)
    if r.returncode != 0:
        pytest.skip("mingw cannot link here: " + r.stderr.decode(errors="replace")[:200])
    return o


def _apis(store, t, pool, q):
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(120)
    apis = set()
    for f in FindingDAO(store.conn).list_by_target(t.id):
        if f.detector != "windows_dangerous_imports":
            continue
        for e in f.evidence:
            m = re.search(r"PE imports (\w+)\(\)", e.get("detail", ""))
            if m:
                apis.add(m.group(1))
    return apis


_BAD = (
    "#include <windows.h>\n"
    "int main(int argc, char **argv){ char buf[64];\n"
    "  wsprintfA(buf, \"v=%s/%d\", argv[1], argc);\n"   # unbounded format write (not a pure copy)
    "  WinExec(argv[1], SW_SHOW);\n"            # command execution -> CWE-78
    "  lstrcpyA(buf, argv[1]);\n"               # unbounded copy -> CWE-120
    "  return (int)(size_t)buf[0]; }\n")
_SAFE = (
    "#include <windows.h>\n#include <strsafe.h>\n"
    "int main(int argc, char **argv){ char buf[64];\n"
    "  StringCchCopyA(buf, sizeof buf, argv[1]);\n"   # bounded; no dangerous import
    "  return (int)(size_t)buf[0]; }\n")


def test_pe_dangerous_win32_imports_flagged(store, case, pool, tmp_path):
    """A PE that imports WinExec / wsprintfA / lstrcpyA is flagged (CWE-78 + CWE-120), where the
    call-graph detector saw nothing (the IAT thunks are unnamed)."""
    exe = _mingw(tmp_path, _BAD, "win_bad.exe")
    t = ingest(store, case.id, exe, filename="win_bad.exe")
    apis = _apis(store, t, pool, JobQueue(store.conn))
    assert {"WinExec", "wsprintfA", "lstrcpyA"} <= apis, apis


def test_pe_without_dangerous_imports_is_silent(store, case, pool, tmp_path):
    """A PE whose only string copy is a bounded StrSafe call imports no dangerous sink -> silent
    (no false positive)."""
    exe = _mingw(tmp_path, _SAFE, "win_safe.exe")
    t = ingest(store, case.id, exe, filename="win_safe.exe")
    assert _apis(store, t, pool, JobQueue(store.conn)) == set()
