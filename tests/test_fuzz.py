"""Phase 5 — black-box fuzzing: mutator + a campaign that finds a crash and confirms it."""
import random
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.fuzz.mutator import Mutator
from lykos.analyze.fuzz.stage import enqueue_fuzz
from lykos.analyze.ingest import ingest
from lykos.db.dao import DynResultDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# crashes if any 'A' appears in the input -> a seed of "AAAA" hits almost immediately
_CRASH_ON_A = ("#include <unistd.h>\nint main(){char b[64];int n=read(0,b,63);"
               "for(int i=0;i<n;i++) if(b[i]=='A'){volatile int*p=0;*p=1;}return 0;}\n")
_OK = "#include <unistd.h>\nint main(){char b[64];read(0,b,63);return 0;}\n"


@pytest.fixture(scope="module")
def bins(gcc, tmp_path_factory):
    d = tmp_path_factory.mktemp("fuzzbins")
    out = {}
    for name, src in (("crash", _CRASH_ON_A), ("ok", _OK)):
        c = d / (name + ".c"); c.write_text(src)
        b = d / name
        if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True).returncode == 0:
            out[name] = b
    return out


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=60, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_mutator_deterministic_and_bounded():
    m1 = Mutator(random.Random(42), [b"admin", b"%n"])
    m2 = Mutator(random.Random(42), [b"admin", b"%n"])
    corpus = [b"seed", b"AAAA"]
    outs1 = [m1.mutate(b"AAAA", corpus) for _ in range(50)]
    outs2 = [m2.mutate(b"AAAA", corpus) for _ in range(50)]
    assert outs1 == outs2                       # same seed -> same sequence
    assert all(isinstance(o, bytes) and len(o) <= 8192 for o in outs1)


def test_fuzz_finds_crash_and_confirms(store, case, pool, bins):
    if "crash" not in bins:
        pytest.skip("build failed")
    import base64
    target = ingest(store, case.id, bins["crash"])
    q = JobQueue(store.conn)
    run = enqueue_fuzz(q, target, params={
        "input_mode": "stdin", "max_execs": 400, "max_seconds": 20, "exec_timeout": 1,
        "seeds": [base64.b64encode(b"AAAA").decode()]})
    assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"

    crashes = [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed]
    assert crashes and crashes[0].signal_name == "SIGSEGV"
    # at least one crash was minimized to a tiny reproducer (the one that became a finding)
    inputs = [store.content.get_bytes(d.input_sha) for d in crashes]
    assert any(b"A" in ci and len(ci) <= 4 for ci in inputs)
    assert any(d.note and "minimized" in d.note for d in crashes)

    confirmed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
                 if f.state == "confirmed"]
    assert confirmed and confirmed[0].detector == "fuzz"


def test_fuzz_clean_binary_no_crash(store, case, pool, bins):
    if "ok" not in bins:
        pytest.skip("build failed")
    target = ingest(store, case.id, bins["ok"])
    q = JobQueue(store.conn)
    run = enqueue_fuzz(q, target, params={
        "input_mode": "stdin", "max_execs": 150, "max_seconds": 15, "exec_timeout": 1})
    assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"
    assert not [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed]
    assert not [f for f in FindingDAO(store.conn).list_by_target(target.id)
                if f.state == "confirmed"]
