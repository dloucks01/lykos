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


def test_read_at_payload_places_addr_at_known_slot():
    """The %N$s leak: the address must land at arg_offset + pad/word so the slot is deterministic."""
    p = fmt.read_at_payload(6, 0x404010, pad=16)
    assert p.startswith(b"%8$s")                        # slot 6 + 16/8 = 8
    assert struct.pack("<Q", 0x404010) == p[16:24]      # address at byte 16 (slot 8)


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


@pytest.fixture
def fmt_bin_fullrelro(gcc, tmp_path_factory, x86_64_only):
    d = tmp_path_factory.mktemp("fmtrelro")
    (d / "v.c").write_text(
        "#include <stdio.h>\n#include <unistd.h>\n"
        "void win(void){ puts(\"WIN-SHELL-LYKOS\"); fflush(stdout); }\n"
        "int main(void){ char buf[200]; int n;\n"
        "  while ((n = read(0, buf, sizeof buf - 1)) > 0) { buf[n] = 0; printf(buf); fflush(stdout); }\n"
        "  return 0; }\n")
    out = d / "fmtwin_relro"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-Wl,-z,relro,-z,now",
                       str(d / "v.c"), "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot build full-RELRO format-string target")
    return out


@pytest.fixture
def fmt_loop_bin(gcc, tmp_path_factory, x86_64_only):
    """A LOOPING printf(user) sink, no-PIE, partial RELRO, NO win() -- the fully-auto format target."""
    d = tmp_path_factory.mktemp("fmtloop")
    (d / "v.c").write_text(
        "#include <stdio.h>\n#include <unistd.h>\n"
        "int main(void){ setbuf(stdout,0); char buf[512];\n"
        "  while(1){ int n=read(0,buf,sizeof buf-1); if(n<=0) break; buf[n]=0; printf(buf);"
        " fflush(stdout); } return 0; }\n")
    out = d / "fmtloop"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w",
                       str(d / "v.c"), "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot build looping format-string target")
    return out


def test_format_auto_got_to_shell(store, case, pool, fmt_loop_bin):
    """P-item: fully-AUTO format-string -> shell, no analyst params and no win. The stage leaks libc
    via a %s read of a GOT slot, overwrites printf@GOT with system, and sends "/bin/sh" so the loop's
    next printf becomes system("/bin/sh"). strategy=auto; confirmed by a spawned shell."""
    from lykos.analyze.poc import enqueue_exploit
    t = ingest(store, case.id, fmt_loop_bin, filename="fmtloop")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(40)
    run = enqueue_exploit(q, t, params={"input_mode": "stdin", "timeout": 25})   # NO analyst params
    assert pool.wait_idle(180) and q.runs.get(run.id).status == "done"
    assert any(pc.level == "L3" and pc.verified
               for pc in PocDAO(store.conn).list_by_target(t.id)), "no confirmed L3 format->shell"


def test_format_write_refuses_got_overwrite_under_full_relro(store, case, pool, fmt_bin_fullrelro):
    """Full RELRO / bind-now remaps the GOT read-only before main, so a %hhn GOT overwrite silently
    faulted. The stage must now REFUSE with an honest reason (GOT read-only -> use fmt_write_addr),
    not emit a 'confident' chain that never lands -- the exact failure lykos's gates exist to catch."""
    t = ingest(store, case.id, fmt_bin_fullrelro, filename="fmtwin_relro")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(40)
    assert (store.targets.get(t.id).mitigations or {}).get("bind_now") == "on"
    run = enqueue_exploit(q, t, params={"input_mode": "stdin", "strategy": "format",
                                        "fmt_got": "fflush", "fmt_win": "win",
                                        "success_regex": "WIN-SHELL-LYKOS"})
    assert pool.wait_idle(90) and q.runs.get(run.id).status == "done"
    assert not any(pc.level == "L3" and pc.verified
                   for pc in PocDAO(store.conn).list_by_target(t.id))
    # the refusal reason is surfaced (a job.progress msg), naming RELRO / read-only GOT
    msgs = " ".join((e.payload or {}).get("msg") or ""
                    for e in store.events.list(run_id=run.id, limit=400)
                    if e.type == "job.progress")
    assert "relro" in msgs.lower() or "read-only" in msgs.lower(), msgs[-300:]
