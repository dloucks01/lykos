"""SymQEMU in STDIN mode must actually receive the seed.

Under a job context, run_once passed stdin=PIPE to ctx.run_subprocess and never wrote to it: the
target blocked on read() until the timeout and no stdin-mode seed ever produced an input, so the
symqemu backend was a silent no-op for every stdin target driven by the concolic stage."""
import base64
import subprocess
import sys

import pytest
from lykos.analyze import register
from lykos.analyze.ingest import ingest
from lykos.analyze.symbolic import enqueue_concolic, symqemu
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


class _Ctx:
    """The ctx.run_subprocess contract (Popen kwargs, stdin defaults to /dev/null)."""
    def run_subprocess(self, cmd, timeout=None, **kw):
        kw.setdefault("stdin", subprocess.DEVNULL)
        return subprocess.run(cmd, timeout=timeout, capture_output=True, check=False, **kw)

    def should_cancel(self):
        return False


def _echo_symqemu(tmp_path):
    """A fake symqemu: copies its stdin (or SYMCC_INPUT_FILE) into SYMCC_OUTPUT_DIR as a case."""
    sq = tmp_path / "symqemu-x86_64"
    sq.write_text(f"#!{sys.executable}\n"
                  "import os, sys\n"
                  "src = os.environ.get('SYMCC_INPUT_FILE')\n"
                  "data = open(src, 'rb').read() if src else sys.stdin.buffer.read()\n"
                  "os.makedirs(os.environ['SYMCC_OUTPUT_DIR'], exist_ok=True)\n"
                  "open(os.path.join(os.environ['SYMCC_OUTPUT_DIR'], 'case0'), 'wb')"
                  ".write(b'got:' + data)\n")
    sq.chmod(0o755)
    return sq


@pytest.mark.parametrize("ctx", [None, _Ctx()], ids=["no-ctx", "ctx"])
@pytest.mark.parametrize("mode", ["stdin", "file"])
def test_run_once_feeds_the_seed(tmp_path, ctx, mode):
    sq = _echo_symqemu(tmp_path)
    out = tmp_path / "work" / "out"
    rc = symqemu.run_once(sq, tmp_path / "target", b"SEED", out, mode=mode, timeout=10, ctx=ctx)
    assert rc == 0
    assert symqemu.harvest(out) == [b"got:SEED"]


def test_run_once_places_the_input_and_output_placeholders(tmp_path):
    sq = tmp_path / "symqemu-x86_64"
    log = tmp_path / "argv.txt"
    sq.write_text(f"#!{sys.executable}\nimport sys\nopen({str(log)!r}, 'w').write('\\n'.join(sys.argv[2:]))\n")
    sq.chmod(0o755)
    symqemu.run_once(sq, tmp_path / "t", b"x", tmp_path / "w" / "out", mode="file",
                     base_argv=["-i", "@@", "-o", "@@out"], timeout=10)
    got = log.read_text().splitlines()
    assert got[0] == "-i" and got[1].endswith("seed.cur") and got[2:] == ["-o", "lykos.out"]


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=120, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


@pytest.mark.skipif(symqemu.locate_symqemu() is None, reason="symqemu not installed")
def test_symqemu_real_solves_a_stdin_gate_and_confirms(store, case, pool, gcc, tmp_path):
    src = ("#include <unistd.h>\n"
           "void win(void){ volatile char*p=0; *p=1; }\n"
           "int main(void){ char b[8]={0}; int n=read(0,b,8);"
           " if(n>=4 && b[0]=='M'&&b[1]=='A'&&b[2]=='G'&&b[3]=='C') win(); return 0; }\n")
    c = tmp_path / "sg.c"
    c.write_text(src)
    b = tmp_path / "sg"
    if subprocess.run([gcc, "-O0", "-no-pie", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    q = JobQueue(store.conn)
    run = enqueue_concolic(q, target, params={
        "backend": "symqemu", "input_mode": "stdin", "max_seconds": 90, "exec_timeout": 2,
        "rounds": 6, "seeds": [base64.b64encode(b"AAAAAAAA").decode()]})
    assert pool.wait_idle(180) and q.runs.get(run.id).status == "done"
    confirmed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
                 if f.state == "confirmed" and f.detector == "concolic"]
    assert confirmed, "expected SymQEMU to solve the stdin gate and confirm a crash"
