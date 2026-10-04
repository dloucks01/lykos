"""PIE ret2win with NO leak, via a PARTIAL OVERWRITE of the saved return address.

PIE randomises only the page base, so the low 12 bits of every address are fixed. Overwriting just
the low byte(s) of the saved return address redirects it to win() without an information leak -- the
case the leak-first PIE path cannot reach on a binary that prints no pointer. x86-64, native.
"""
import shutil
import subprocess

import pytest
from lykos.analyze.dynamic import sandbox

pytestmark = pytest.mark.skipif(
    sandbox.host_arch() != "x86-64" or not shutil.which("gcc"),
    reason="PIE ret2win partial-overwrite fixture + detonation are native x86-64 only")


def _src(read_call: str) -> str:
    """A PIE binary with a win() that spawns a shell and a vuln() that owns the overflow. The win
    and the return site sit in the same page, so a 1-byte partial overwrite redirects with no leak.
    Parameterised ONLY by the read, so the positive and its negative control are byte-identical but
    for the call that overflows."""
    return (
        '#include <stdlib.h>\n#include <unistd.h>\n#include <stdio.h>\n'
        'void win(void){ system("/bin/sh"); }\n'
        'void vuln(void){ char b[64]; ' + read_call + '; }\n'
        'int main(void){ setbuf(stdout,0); puts("go"); vuln(); return 0; }\n')


def _build(tmp_path_factory, name, read_call):
    gcc = shutil.which("gcc") or shutil.which("cc")
    d = tmp_path_factory.mktemp(name)
    (d / "v.c").write_text(_src(read_call))
    exe = d / "v"
    if subprocess.run([gcc, "-fPIE", "-pie", "-fno-stack-protector", "-w",
                       str(d / "v.c"), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("cannot build PIE ret2win fixture")
    return exe


@pytest.fixture
def win_bin(tmp_path_factory):
    return _build(tmp_path_factory, "po", "read(0,b,512)")            # overflow: the bug


@pytest.fixture
def win_safe_bin(tmp_path_factory):
    return _build(tmp_path_factory, "po_safe", "read(0,b,sizeof b)")  # bounds-fixed: no bug


@pytest.fixture
def _stage(store):
    from lykos.analyze import register
    from lykos.jobs import JobConfig, WorkerPool
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _drive(store, pool, exe):
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobQueue
    t = ingest(store, store.cases.create("po").id, exe, filename="v")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)
    TargetDAO(store.conn).update_triage(t.id, arch="x86-64", bits=64, endianness="little",
                                        linking="dynamic", stripped=False,
                                        mitigations={"pie": "on"}, file_type="elf")
    # offset = buf(64) + saved rbp(8); strategy=ret2win drives the partial-overwrite path.
    run = enqueue_exploit(q, t, params={"strategy": "ret2win", "offset": 72})
    assert pool.wait_idle(120) and q.runs.get(run.id).status == "done"
    return [pc for pc in PocDAO(store.conn).list_by_target(t.id)
            if pc.level == "L3" and pc.verified]


def test_files_l3_pie_ret2win_partial_overwrite(store, _stage, win_bin):
    """A PIE binary with a win() and a return-address overflow reaches a confirmed L3 by overwriting
    the low byte(s) of the saved return address -- no leak, no gadgets -- proven by a spawned shell
    evaluating the forgery-proof marker."""
    assert _drive(store, _stage, win_bin), "no confirmed L3 PIE partial-overwrite PoC"


def test_declines_the_patched_target(store, _stage, win_safe_bin):
    """Negative control: the SAME binary with the overflow removed must NOT yield a confirmed L3 --
    byte-identical but for the read length, so the decline is the missing overflow alone (win() and
    the return-address shape are unchanged)."""
    assert not _drive(store, _stage, win_safe_bin), "patched target wrongly credited an L3"


# ---- file channel: the overflow arrives from a FILE, not stdin -----------------------------
def _src_file(read_call: str) -> str:
    """A PIE binary whose vuln() reads the overflow from a FILE named by argv[1] (open/read -- no
    FILE* local to corrupt before the function returns). The spawned shell still talks over the
    inherited stdin, so a leak-free partial overwrite must weaponize a file-reading target too."""
    return (
        '#include <stdlib.h>\n#include <unistd.h>\n#include <stdio.h>\n#include <fcntl.h>\n'
        'void win(void){ system("/bin/sh"); }\n'
        'void vuln(const char*p){ char b[64]; int fd=open(p,O_RDONLY); ' + read_call + '; }\n'
        'int main(int c,char**v){ setbuf(stdout,0); if(c>1) vuln(v[1]); return 0; }\n')


def _build_file(tmp_path_factory, name, read_call):
    gcc = shutil.which("gcc") or shutil.which("cc")
    d = tmp_path_factory.mktemp(name)
    (d / "v.c").write_text(_src_file(read_call))
    exe = d / "v"
    if subprocess.run([gcc, "-fPIE", "-pie", "-fno-stack-protector", "-w", str(d / "v.c"),
                       "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build PIE file-ret2win fixture")
    return exe


@pytest.fixture
def win_file_bin(tmp_path_factory):
    return _build_file(tmp_path_factory, "pof", "if(fd>=0) read(fd,b,512)")    # overflow


@pytest.fixture
def win_file_safe_bin(tmp_path_factory):
    return _build_file(tmp_path_factory, "pof_safe", "if(fd>=0) read(fd,b,sizeof b)")  # no bug


def _drive_file(store, pool, exe):
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobQueue
    t = ingest(store, store.cases.create("pof").id, exe, filename="v")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)
    TargetDAO(store.conn).update_triage(t.id, arch="x86-64", bits=64, endianness="little",
                                        linking="dynamic", stripped=False,
                                        mitigations={"pie": "on"}, file_type="elf")
    # file channel: input_mode=file + argv `@@` tells the stage to deliver the overflow as a file.
    # offset = buf(64) + fd/padding + saved rbp = 88 for this frame (0x60).
    run = enqueue_exploit(q, t, params={"strategy": "ret2win", "offset": 88,
                                        "input_mode": "file", "argv": ["@@"]})
    assert pool.wait_idle(180) and q.runs.get(run.id).status == "done"
    return [pc for pc in PocDAO(store.conn).list_by_target(t.id)
            if pc.level == "L3" and pc.verified]


def test_files_l3_pie_ret2win_partial_overwrite_from_a_file(store, _stage, win_file_bin):
    """A PIE binary that reads its overflow from a FILE reaches a confirmed L3 with no leak -- the
    partial overwrite is now mode-aware, so a file parser is weaponized exactly like a stdin reader."""
    assert _drive_file(store, _stage, win_file_bin), "no confirmed L3 for the file-reading target"


def test_declines_the_patched_file_target(store, _stage, win_file_safe_bin):
    """Negative control: the same file-reading binary with the overflow removed yields no L3."""
    assert not _drive_file(store, _stage, win_file_safe_bin), "patched file target wrongly L3"
