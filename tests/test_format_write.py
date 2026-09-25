"""Format-string exploitation: the %hhn write-what-where primitive (fmt.fmtstr_payload), argument
offset recon (fmt.find_fmt_offset), and the end-to-end `format` L3 strategy that overwrites a
post-sink GOT slot with a win function."""
from __future__ import annotations

import struct
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.poc import fmt
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.analyze.poc import enqueue_exploit
from lykos.db.dao import FindingDAO, PocDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def test_find_fmt_offset():
    out = b"AAAAAAAA|0x7ffe0001 0x78 0x4141414141414141 0x1"
    assert fmt.find_fmt_offset(out) == 3            # the marker word is the 3rd printed value
    assert fmt.find_fmt_offset(b"0x1 0x2 0x3") is None


def test_fmtstr_payload_layout_and_convergence():
    # a single 3-byte write; the address table must follow the (NUL-padded) format directives, and
    # the positional index must point at the first table word.
    p = fmt.fmtstr_payload(6, {0x404008: 0x401196})
    assert b"$hhn" in p and p.count(b"$hhn") == 3      # three byte writes (0x96,0x11,0x40)
    # trailing table holds the packed addresses 0x404008..0x40400a
    assert struct.pack("<Q", 0x404008) in p and struct.pack("<Q", 0x40400a) in p
    # directives reference indices >= arg_offset (6); table starts after the format words
    assert b"$hhn" in p


def test_fmtstr_payload_multiple_addresses_converge():
    p = fmt.fmtstr_payload(8, {0x601018: 0xdead, 0x601030: 0xbeef})
    assert p.count(b"$hhn") == 4                        # two 2-byte values
    assert struct.pack("<Q", 0x601018) in p and struct.pack("<Q", 0x601030) in p


# ---------------------------------------------------------------- end-to-end (compiled) --------
@pytest.fixture
def x86_64_only():
    if sandbox.host_arch() != "x86-64":
        pytest.skip("format-string %n write is x86-64 native only")


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


@pytest.fixture
def fmt_bin(gcc, tmp_path_factory, x86_64_only):
    d = tmp_path_factory.mktemp("fmt")
    (d / "v.c").write_text(
        "#include <stdio.h>\n#include <unistd.h>\n"
        "void win(void){ puts(\"WIN-SHELL-LYKOS\"); fflush(stdout); }\n"
        "int main(void){ char buf[200]; int n;\n"
        "  while ((n = read(0, buf, sizeof buf - 1)) > 0) { buf[n] = 0; printf(buf); fflush(stdout); }\n"
        "  return 0; }\n")
    out = d / "fmtwin"
    # partial RELRO (writable .got.plt), no-PIE -- the classic format-string challenge shape
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-Wl,-z,norelro",
                       str(d / "v.c"), "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot build format-string target")
    return out


def test_format_write_confirms_l3(store, case, pool, fmt_bin):
    t = ingest(store, case.id, fmt_bin, filename="fmtwin")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(40)
    run = enqueue_exploit(q, t, params={"input_mode": "stdin", "strategy": "format",
                                        "fmt_got": "fflush", "fmt_win": "win",
                                        "success_regex": "WIN-SHELL-LYKOS"})
    assert pool.wait_idle(90) and q.runs.get(run.id).status == "done"
    assert any(pc.level == "L3" and pc.verified for pc in PocDAO(store.conn).list_by_target(t.id))
    pb = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.state == "poc-backed"]
    assert any("format-string" in e.get("detail", "") for f in pb for e in f.evidence)
