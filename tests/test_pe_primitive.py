"""Windows PE L2 primitive via Wine's `+seh` crash dump.

A PE is first-class through triage, static analysis, disassembly and L1 reproduction under Wine,
then used to fall off a cliff: `poc_primitive` is host ptrace, which cannot follow Win64 state
through wineserver, so every PE ran the whole stage and produced nothing. The PE path drives Wine
with `WINEDEBUG=+seh` and recovers the control offset from the guest register dump + walked SEH
frames (`make_wine_capture` / `_pe_ip_primitive`).

The soundness line this file guards: a frame-pointer-based (`leave`) epilogue smashed by a stack
overflow controls the SAVED FRAME POINTER and the Wine SEH registration frame -- confirmed exactly
with a sentinel -- but NOT the instruction pointer (the epilogue faults reading the corrupt frame
before any `ret` reaches a controlled address, and x64 SEH is table-based). So the primitive is
`seh-frame-control`, reported as a confirmed memory-corruption with the control-flow hijack filed
only as POTENTIAL -- never an over-claimed RIP hijack.
"""
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.analyze.poc import capture, primitive
from lykos.analyze.poc.exploit_stage import enqueue_exploit
from lykos.analyze.poc.primitive_stage import enqueue_primitive
from lykos.db.dao import FindingDAO, PocDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# char buf[32]; strcpy(buf, argv[1]) -- a textbook stack smash. -O0 keeps the frame-pointer
# epilogue (`leave; ret`), so the overflow controls the saved rbp + SEH frame at offset 32.
_POVF_C = (
    "#include <windows.h>\n#include <string.h>\n"
    "void vuln(const char *s){ char buf[32]; strcpy(buf, s); }\n"
    "int main(int argc, char **argv){ if(argc>1) vuln(argv[1]); return 0; }\n")


def _mingw_pe(tmp_path):
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if not cc:
        pytest.skip("no mingw cross compiler")
    if not sandbox._wine():
        pytest.skip("no wine to execute the PE")
    c = tmp_path / "povf.c"
    c.write_text(_POVF_C)
    exe = tmp_path / "povf.exe"
    r = subprocess.run([cc, "-O0", "-fno-stack-protector", "-w", str(c), "-o", str(exe)],
                       capture_output=True, timeout=180)
    if r.returncode != 0:
        pytest.skip("mingw cannot link here: " + r.stderr.decode(errors="replace")[:200])
    return exe


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=240, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_make_wine_capture_recovers_the_controlled_frame_offset(tmp_path):
    """The capture primitive, in isolation: a cyclic overflow through argv makes Wine's +seh dump
    report the saved rbp AND the SEH registration frame holding the pattern at offset 32, and a
    NUL-free sentinel at that offset lands back in both -- a confirmed frame-pointer primitive.

    The faulting PC is NOT the pattern: the `leave` epilogue faults on the corrupt frame before any
    `ret`, so this is honestly a frame/SEH primitive, not a RIP hijack."""
    exe = _mingw_pe(tmp_path)
    cap = capture.make_wine_capture(str(exe), "arg", ["@@"], 25.0)
    length = 400
    c0 = cap(primitive.cyclic(length))
    assert c0.get("ok") and c0.get("signal_name") == "SIGSEGV", c0.get("reason")
    # the saved frame pointer is controlled at offset 32 (buf[32]); the SEH frame holds it too
    regs = primitive.controlled_registers(c0, length, endian="little", word=8)
    assert regs.get("rbp") == 32, regs
    seh = c0.get("seh_frame")
    assert seh and primitive.cyclic_find(primitive._reg_window(seh, 8, "little", 4), length, 4) == 32
    # the PC is NOT the pattern -- no clean RIP control from this shape
    assert primitive.cyclic_find(primitive._reg_window(c0["pc"], 8, "little", 4), length, 4) == -1
    # confirm: a NUL-free sentinel at offset 32 reappears in the frame pointer / SEH frame
    control = primitive.pe_frame_control_input(32, length, 8)
    assert primitive.pe_frame_confirmed(cap(control), 8) in ("rbp", "seh_frame")


def test_pe_l2_seh_frame_control_is_confirmed_and_not_overclaimed(store, case, pool, tmp_path):
    """End to end: the `poc_primitive` stage files a CONFIRMED L2 `seh-frame-control` primitive for
    a PE strcpy smash -- where the host ptrace path produced nothing -- and does NOT claim RIP
    control (the effect is memory corruption; the hijack is potential)."""
    exe = _mingw_pe(tmp_path)
    q = JobQueue(store.conn)
    t = ingest(store, case.id, exe, filename="povf.exe")
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(60)
    t = store.targets.get(t.id)
    assert t.file_type == "pe"

    sha = store.put_artifact(case.id, "crash", data=b"A" * 200).sha256
    run = enqueue_primitive(q, t, params={"input_sha": sha, "input_mode": "arg", "timeout": 20})
    assert pool.wait_idle(240) and q.runs.get(run.id).status == "done"

    payload = next(e.payload for e in q.events.list(run_id=run.id, limit=80)
                   if e.type == "primitive.done")
    assert payload["primitive"] == "seh-frame-control", payload
    assert payload["confirmed"] and payload["level"] == "L2" and payload["offset"] == 32

    pocs = [p for p in PocDAO(store.conn).list_by_target(t.id) if p.verified]
    assert pocs and pocs[0].level == "L2"

    # honesty: the finding headlines memory corruption (CWE-121), and the control-flow hijack is
    # filed only as a POTENTIAL effect -- never a demonstrated RIP hijack / RCE.
    fs = FindingDAO(store.conn).list_by_target(t.id)
    hijack = [f for f in fs if "hijack" in (f.title or "").lower() and "demonstrated" in
              (f.title or "").lower() and "seh" not in (f.title or "").lower()]
    assert not hijack, [f.title for f in fs]
    corr = [f for f in fs if f.cwe == "CWE-121" or "stack buffer overflow" in (f.title or "").lower()]
    assert corr, [(f.title, f.cwe) for f in fs]


def test_pe_l3_declines_honestly_without_a_win64_weaponizer(store, case, pool, tmp_path):
    """`build_exploit` is entirely SysV/ELF, so it declines a PE with an honest reason naming the
    Win64 weaponizer -- rather than running ELF recipes that can only fail to confirm. The decline
    is explicit (PE declares ip_control=True, so it passes the generic substrate guard)."""
    exe = _mingw_pe(tmp_path)
    q = JobQueue(store.conn)
    t = ingest(store, case.id, exe, filename="povf.exe")
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(60)
    t = store.targets.get(t.id)

    sha = store.put_artifact(case.id, "crash", data=b"A" * 200).sha256
    run = enqueue_exploit(q, t, params={"input_sha": sha, "input_mode": "arg", "timeout": 20})
    assert pool.wait_idle(120) and q.runs.get(run.id).status == "done"
    payload = next(e.payload for e in q.events.list(run_id=run.id, limit=80)
                   if e.type == "exploit.done")
    assert payload["supported"] is False
    assert "Win64" in payload["note"] and "PE" in payload["note"]
