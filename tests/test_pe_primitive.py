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
from lykos.analyze.disassemble import enqueue_disassemble
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


def test_make_wine_capture_recovers_clean_rip_control(tmp_path):
    """The capture primitive, in isolation. A cyclic overflow through argv faults the PE AT the
    `ret` (the cyclic return address is non-canonical, so the CPU faults at the ret itself with the
    pattern nowhere in a register) -- Wine's +seh dump still leaks the saved rbp at offset 32. The
    real control is the RETURN ADDRESS at offset 40: placing the CANONICAL marker there with a
    short payload makes the `ret` land on it, pc == MARKER -- confirmed clean instruction-pointer
    control, the strong primitive."""
    exe = _mingw_pe(tmp_path)
    cap = capture.make_wine_capture(str(exe), "arg", ["@@"], 25.0)
    length = 400
    c0 = cap(primitive.cyclic(length))
    assert c0.get("ok") and c0.get("signal_name") == "SIGSEGV", c0.get("reason")
    # the cyclic faults at the ret: the saved rbp leaks the frame offset, the pc does not hold it
    assert primitive.controlled_registers(c0, length, endian="little", word=8).get("rbp") == 32
    assert primitive.cyclic_find(primitive._reg_window(c0["pc"], 8, "little", 4), length, 4) == -1
    # the return address at offset 40 is cleanly controllable: canonical marker -> pc == MARKER
    import struct
    m = primitive._ip_marker(8)
    assert cap(primitive.cyclic(40) + struct.pack("<Q", m)).get("pc") == m
    # and NOT at a wrong offset (32 does not reach the return slot -> no crash / not the marker)
    assert cap(primitive.cyclic(32) + struct.pack("<Q", m)).get("pc") != m


def test_pe_frame_sentinel_helpers_confirm_the_weaker_lead():
    """Unit coverage for the `seh-frame-control` fallback helpers (used when a `leave`-style
    epilogue faults on the corrupt frame before any `ret` reaches a controlled address, so only the
    saved frame pointer is controllable). The sentinel is NUL-free and not in the cyclic alphabet,
    and a slot holding it exactly is a confirmed frame primitive."""
    assert 0 not in primitive.pe_frame_sentinel(8).to_bytes(8, "little")
    assert primitive.pe_frame_sentinel(8).to_bytes(8, "little") not in primitive.cyclic(4096)
    ci = primitive.pe_frame_control_input(32, 200, 8)
    assert ci[32:40] == primitive.pe_frame_sentinel(8).to_bytes(8, "little")
    assert primitive.pe_frame_confirmed({"regs": {"rbp": primitive.PE_FRAME_SENTINEL}}, 8) == "rbp"
    assert primitive.pe_frame_confirmed({"seh_frame": primitive.PE_FRAME_SENTINEL}, 8) == "seh_frame"
    assert primitive.pe_frame_confirmed({"regs": {"rbp": 0x6161}}, 8) == ""


def test_pe_l2_instruction_pointer_control_is_confirmed(store, case, pool, tmp_path):
    """End to end: the `poc_primitive` stage files a CONFIRMED L2 instruction-pointer-control
    primitive for a PE strcpy smash -- where the host ptrace path produced nothing. The return
    address at offset 40 is the controlled slot (the frame-pointer rbp at 32 is the weaker view of
    the same overflow), and the control is confirmed by the planted marker landing in the PC."""
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
    assert payload["primitive"] == "instruction-pointer-control", payload
    assert payload["confirmed"] and payload["level"] == "L2" and payload["offset"] == 40

    pocs = [p for p in PocDAO(store.conn).list_by_target(t.id) if p.verified]
    assert pocs and pocs[0].level == "L2"
    # a confirmed RIP hijack headlines a control-flow hijack (critical) with RCE only POTENTIAL
    fs = FindingDAO(store.conn).list_by_target(t.id)
    hij = [f for f in fs if "control-flow hijack" in (f.title or "").lower()]
    assert hij and any(f.severity == "critical" for f in hij), [(f.title, f.severity) for f in fs]


def test_pe_l3_declines_honestly_when_there_is_no_win_target(store, case, pool, tmp_path):
    """A PE with a confirmable RIP primitive but NO reachable win function (and delivered via an
    argv/strcpy channel that cannot carry a NUL-bearing Win64 address) declines L3 with an honest
    reason naming the Win64 ROP weaponizer -- it does not run ELF recipes or fake a result."""
    exe = _mingw_pe(tmp_path)                             # povf: no win() function, argv channel
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


_RET2WIN_C = (
    "#include <windows.h>\n#include <stdio.h>\n"
    "void win(void){ DWORD w; WriteFile(GetStdHandle((DWORD)-11), \"PWNED_a1b2c3\\n\", 13, &w, 0);"
    " ExitProcess(0x1337); }\n"
    "void vuln(FILE *f){ char buf[32]; fread(buf, 1, 200, f); }\n"
    "int main(int argc, char **argv){ if(argc<2) return 2; FILE*f=fopen(argv[1],\"rb\");"
    " if(!f) return 3; vuln(f); return 0; }\n")


def _mingw_ret2win(tmp_path):
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if not cc:
        pytest.skip("no mingw cross compiler")
    if not sandbox._wine():
        pytest.skip("no wine to execute the PE")
    c = tmp_path / "rw.c"
    c.write_text(_RET2WIN_C)
    exe = tmp_path / "rw.exe"
    r = subprocess.run([cc, "-O1", "-fno-stack-protector", "-w", str(c), "-o", str(exe)],
                       capture_output=True, timeout=180)
    if r.returncode != 0:
        pytest.skip("mingw cannot link here: " + r.stderr.decode(errors="replace")[:200])
    return exe


def test_pe_l3_ret2win_confirmed_under_wine(store, case, pool, tmp_path):
    """End to end: a file-reading PE with a reachable `win()` reaches a CONFIRMED L3 ret2win. The
    `poc_primitive` stage confirms clean RIP control; `build_exploit` redirects it to win() under
    Wine and confirms win RAN by its stdout marker against a neutralised-slot negative control."""
    exe = _mingw_ret2win(tmp_path)
    q = JobQueue(store.conn)
    t = ingest(store, case.id, exe, filename="rw.exe")
    for enq in (enqueue_triage, enqueue_disassemble):
        enq(q, t, force=True)
        assert pool.wait_idle(180)
    t = store.targets.get(t.id)
    assert t.file_type == "pe"

    crash = store.put_artifact(case.id, "crash", data=b"A" * 200).sha256
    # L2: clean RIP control (file channel -- NUL-tolerant, which ret2win needs)
    pr = enqueue_primitive(q, t, params={"input_sha": crash, "input_mode": "file", "timeout": 20})
    assert pool.wait_idle(300) and q.runs.get(pr.id).status == "done"
    l2 = next(e.payload for e in q.events.list(run_id=pr.id, limit=80)
              if e.type == "primitive.done")
    assert l2["primitive"] == "instruction-pointer-control" and l2["confirmed"], l2

    # L3: ret2win -> win(), confirmed by its output under Wine
    xr = enqueue_exploit(q, t, params={"input_sha": crash, "input_mode": "file", "timeout": 20})
    assert pool.wait_idle(180) and q.runs.get(xr.id).status == "done"
    xp = next(e.payload for e in q.events.list(run_id=xr.id, limit=80)
              if e.type == "exploit.done")
    assert xp.get("confirmed") and xp.get("exploit") == "ret2win", xp

    l3 = [p for p in PocDAO(store.conn).list_by_target(t.id) if p.verified and p.level == "L3"]
    assert l3, "no verified L3 ret2win PoC filed"
    fs = FindingDAO(store.conn).list_by_target(t.id)
    assert any("ret2win" in (f.title or "").lower() and f.severity == "critical" for f in fs), \
        [(f.title, f.severity) for f in fs]


_ROP_WINEXEC_C = (
    "#include <windows.h>\n#include <stdio.h>\n"
    "void vuln(FILE *f){ char buf[32]; fread(buf, 1, 400, f); }\n"
    "int main(int argc, char **argv){ if(argc<2) return 2;\n"
    "  if(argc>9999) WinExec(argv[0], 0);\n"            # import WinExec (branch never taken)
    "  FILE*f=fopen(argv[1],\"rb\"); if(!f) return 3; vuln(f); return 0; }\n")


def _mingw_rop_winexec(tmp_path):
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if not cc:
        pytest.skip("no mingw cross compiler")
    if not sandbox._wine():
        pytest.skip("no wine to execute the PE")
    c = tmp_path / "we.c"
    c.write_text(_ROP_WINEXEC_C)
    exe = tmp_path / "we.exe"
    r = subprocess.run([cc, "-O1", "-fno-stack-protector", "-w", str(c), "-o", str(exe),
                        "-lkernel32"], capture_output=True, timeout=180)
    if r.returncode != 0:
        pytest.skip("mingw cannot link here: " + r.stderr.decode(errors="replace")[:200])
    return exe


def test_pe_l3_rop_winexec_runs_an_attacker_command(store, case, pool, tmp_path):
    """End to end: a PE that imports WinExec and has a stack overflow reaches a CONFIRMED L3 Win64
    ROP -> WinExec that runs an ATTACKER-CHOSEN command under Wine. The chain is `pop rcx; ret` ->
    &command (at a stable Wine stack address) -> the WinExec import thunk; confirmation is a unique
    token appearing in a marker file that a neutralised-sink negative control does not create."""
    exe = _mingw_rop_winexec(tmp_path)
    q = JobQueue(store.conn)
    t = ingest(store, case.id, exe, filename="we.exe")
    for enq in (enqueue_triage, enqueue_disassemble):
        enq(q, t, force=True)
        assert pool.wait_idle(180)
    t = store.targets.get(t.id)
    assert t.file_type == "pe"

    crash = store.put_artifact(case.id, "crash", data=b"A" * 200).sha256
    pr = enqueue_primitive(q, t, params={"input_sha": crash, "input_mode": "file", "timeout": 20})
    assert pool.wait_idle(300) and q.runs.get(pr.id).status == "done"
    l2 = next(e.payload for e in q.events.list(run_id=pr.id, limit=80)
              if e.type == "primitive.done")
    assert l2["primitive"] == "instruction-pointer-control" and l2["confirmed"], l2

    xr = enqueue_exploit(q, t, params={"input_sha": crash, "input_mode": "file", "timeout": 20})
    assert pool.wait_idle(240) and q.runs.get(xr.id).status == "done"
    xp = next(e.payload for e in q.events.list(run_id=xr.id, limit=80)
              if e.type == "exploit.done")
    assert xp.get("confirmed") and xp.get("exploit") == "rop-winexec", xp
    assert xp.get("sink") == "winexec"

    l3 = [p for p in PocDAO(store.conn).list_by_target(t.id) if p.verified and p.level == "L3"]
    assert l3, "no verified L3 ROP PoC filed"
    fs = FindingDAO(store.conn).list_by_target(t.id)
    rce = [f for f in fs if "remote code execution" in (f.title or "").lower()
           and f.severity == "critical"]
    assert rce, [(f.title, f.severity) for f in fs]
    # honesty: the RCE is confirmed under Wine's FIXED layout, and the finding must say so -- Wine
    # does not randomize, so the exploit's fixed addresses are not an ASLR defeat. No over-claim.
    ev = " ".join(e.get("detail", "") for f in rce for e in (f.evidence or []))
    assert "ASLR" in ev and "Wine" in ev and "leak" in ev.lower(), ev[:300]


_W32_RET2WIN_C = (
    "#include <windows.h>\n#include <stdio.h>\n"
    "void win(void){ DWORD w; WriteFile(GetStdHandle((DWORD)-11), \"PWNED32_ok\\n\", 11, &w, 0);"
    " ExitProcess(0x55); }\n"
    "void vuln(FILE *f){ char buf[32]; fread(buf, 1, 200, f); }\n"
    "int main(int argc, char **argv){ if(argc<2) return 2; FILE*f=fopen(argv[1],\"rb\");"
    " if(!f) return 3; vuln(f); return 0; }\n")


def _mingw32_ret2win(tmp_path):
    cc = shutil.which("i686-w64-mingw32-gcc")
    if not cc:
        pytest.skip("no i686 mingw cross compiler")
    if not sandbox._wine():
        pytest.skip("no wine to execute the PE")
    c = tmp_path / "rw32.c"
    c.write_text(_W32_RET2WIN_C)
    exe = tmp_path / "rw32.exe"
    r = subprocess.run([cc, "-O1", "-fno-stack-protector", "-w", str(c), "-o", str(exe)],
                       capture_output=True, timeout=180)
    if r.returncode != 0:
        pytest.skip("i686 mingw cannot link here: " + r.stderr.decode(errors="replace")[:200])
    return exe


def test_pe_wow64_32bit_l2_and_ret2win_l3(store, case, pool, tmp_path):
    """WoW64: a 32-bit PE reaches a confirmed L2 (clean EIP, recovered from the faulting address --
    Wine's dump shows the WoW64 wrapper in rip, but the guest's controlled EIP is the AV address)
    and a confirmed L3 ret2win to an in-image win() under 32-bit Wine."""
    exe = _mingw32_ret2win(tmp_path)
    q = JobQueue(store.conn)
    t = ingest(store, case.id, exe, filename="rw32.exe")
    for enq in (enqueue_triage, enqueue_disassemble):
        enq(q, t, force=True)
        assert pool.wait_idle(180)
    t = store.targets.get(t.id)
    assert t.file_type == "pe" and (t.bits or 64) == 32, (t.file_type, t.bits)

    crash = store.put_artifact(case.id, "crash", data=b"A" * 200).sha256
    pr = enqueue_primitive(q, t, params={"input_sha": crash, "input_mode": "file", "timeout": 30})
    assert pool.wait_idle(300) and q.runs.get(pr.id).status == "done"
    l2 = next(e.payload for e in q.events.list(run_id=pr.id, limit=80)
              if e.type == "primitive.done")
    assert l2["primitive"] == "instruction-pointer-control" and l2["confirmed"], l2
    assert l2["source"] == "eip"

    xr = enqueue_exploit(q, t, params={"input_sha": crash, "input_mode": "file", "timeout": 30})
    assert pool.wait_idle(240) and q.runs.get(xr.id).status == "done"
    xp = next(e.payload for e in q.events.list(run_id=xr.id, limit=80)
              if e.type == "exploit.done")
    assert xp.get("confirmed") and xp.get("exploit") == "ret2win", xp

    l3 = [p for p in PocDAO(store.conn).list_by_target(t.id) if p.verified and p.level == "L3"]
    assert l3, "no verified 32-bit L3 ret2win PoC filed"
    fs = FindingDAO(store.conn).list_by_target(t.id)
    assert any("ret2win (win32)" in (f.title or "").lower() and f.severity == "critical"
               for f in fs), [(f.title, f.severity) for f in fs]


_STRUCT_C = (
    "#include <windows.h>\n#include <stdio.h>\n#include <string.h>\n"
    "void win(void){ DWORD w; WriteFile(GetStdHandle((DWORD)-11),\"PWNEDHDR\\n\",9,&w,0);"
    " ExitProcess(0x66); }\n"
    "int vuln(char *s, int n){ char buf[32];\n"
    "  if (n < 8 || memcmp(s,\"HDR:\",4) || memcmp(s+n-4,\";END\",4)) return 0;\n"
    "  memcpy(buf, s+4, n-8); return buf[n%32]; }\n"
    "int main(int argc,char**argv){ if(argc<2) return 2;\n"
    "  FILE*f=fopen(argv[1],\"rb\"); if(!f) return 3;\n"
    "  char tmp[512]; int n=(int)fread(tmp,1,sizeof tmp,f); fclose(f); return vuln(tmp,n); }\n")


def _mingw_struct(tmp_path):
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if not cc:
        pytest.skip("no mingw cross compiler")
    if not sandbox._wine():
        pytest.skip("no wine to execute the PE")
    c = tmp_path / "struct.c"
    c.write_text(_STRUCT_C)
    exe = tmp_path / "struct.exe"
    r = subprocess.run([cc, "-O1", "-fno-stack-protector", "-w", str(c), "-o", str(exe)],
                       capture_output=True, timeout=180)
    if r.returncode != 0:
        pytest.skip("mingw cannot link here: " + r.stderr.decode(errors="replace")[:200])
    return exe


def test_pe_structured_overflow_frames_through_to_l3(store, case, pool, tmp_path):
    """Structure-preserving framing: a PE that overflows only when its record structure is intact
    (must start `HDR:` and end `;END`) -- a raw cyclic is rejected and never faults. The stage must
    recover the (prefix, suffix) from the crashing input, put the cyclic/marker/exploit where the
    filler was, and reach a confirmed L2 (clean RIP) AND a confirmed L3 ret2win, framing preserved."""
    exe = _mingw_struct(tmp_path)
    q = JobQueue(store.conn)
    t = ingest(store, case.id, exe, filename="struct.exe")
    for enq in (enqueue_triage, enqueue_disassemble):
        enq(q, t, force=True)
        assert pool.wait_idle(180)
    t = store.targets.get(t.id)

    # the crashing input HAS the structure (HDR: ... ;END) around a long filler run
    crash = store.put_artifact(case.id, "crash", data=b"HDR:" + b"A" * 200 + b";END").sha256
    pr = enqueue_primitive(q, t, params={"input_sha": crash, "input_mode": "file", "timeout": 25})
    assert pool.wait_idle(300) and q.runs.get(pr.id).status == "done"
    l2 = next(e.payload for e in q.events.list(run_id=pr.id, limit=80)
              if e.type == "primitive.done")
    assert l2["primitive"] == "instruction-pointer-control" and l2["confirmed"], l2
    # the measured framing is the record's header/trailer, carried on the L2 for L3 to reuse
    assert bytes.fromhex(l2.get("frame_prefix") or "") == b"HDR:"
    assert bytes.fromhex(l2.get("frame_suffix") or "") == b";END"

    xr = enqueue_exploit(q, t, params={"input_sha": crash, "input_mode": "file", "timeout": 25})
    assert pool.wait_idle(240) and q.runs.get(xr.id).status == "done"
    xp = next(e.payload for e in q.events.list(run_id=xr.id, limit=80)
              if e.type == "exploit.done")
    assert xp.get("confirmed") and xp.get("exploit") == "ret2win", xp
    assert [p for p in PocDAO(store.conn).list_by_target(t.id) if p.verified and p.level == "L3"]


_FMT_C = (
    "#include <stdio.h>\n"
    "int main(int argc, char **argv){ if(argc<2) return 2; printf(argv[1]); fflush(stdout);"
    " return 0; }\n")


def _mingw_fmt(tmp_path, cc_name="x86_64-w64-mingw32-gcc", out="fmt.exe"):
    cc = shutil.which(cc_name)
    if not cc:
        pytest.skip("no %s" % cc_name)
    if not sandbox._wine():
        pytest.skip("no wine to execute the PE")
    c = tmp_path / (out + ".c")
    c.write_text(_FMT_C)
    exe = tmp_path / out
    r = subprocess.run([cc, "-O1", "-w", str(c), "-o", str(exe)], capture_output=True, timeout=180)
    if r.returncode != 0:
        pytest.skip("mingw cannot link here: " + r.stderr.decode(errors="replace")[:200])
    return exe


@pytest.mark.parametrize("cc,out,tag", [
    ("x86_64-w64-mingw32-gcc", "fmt64.exe", "x64"),
    ("i686-w64-mingw32-gcc", "fmt32.exe", "wow64"),
])
def test_pe_format_string_address_leak_confirmed(store, case, pool, tmp_path, cc, out, tag):
    """A PE with a format-string bug (printf of attacker input) has a CONFIRMED information
    disclosure (CWE-200): `%p` specifiers leak live runtime addresses -- a code pointer (the image
    base) and stack pointers -- that a benign same-shape control does not. The sound half of an
    ASLR defeat, confirmed under Wine (64- and 32-bit); the finding says the end-to-end defeat is
    not exercised here."""
    exe = _mingw_fmt(tmp_path, cc, out)
    q = JobQueue(store.conn)
    t = ingest(store, case.id, exe, filename=out)
    for enq in (enqueue_triage, enqueue_disassemble):
        enq(q, t, force=True)
        assert pool.wait_idle(180)
    t = store.targets.get(t.id)

    dummy = store.put_artifact(case.id, "probe", data=b"x").sha256
    xr = enqueue_exploit(q, t, params={"input_sha": dummy, "input_mode": "arg", "timeout": 25})
    assert pool.wait_idle(180) and q.runs.get(xr.id).status == "done"
    leak = next((e.payload for e in q.events.list(run_id=xr.id, limit=80)
                 if e.type == "exploit.leak"), None)
    assert leak and leak.get("confirmed") and leak.get("kind") == "format-string", leak
    assert leak["leak"].get("image_base") and leak["leak"].get("code"), leak

    fs = FindingDAO(store.conn).list_by_target(t.id)
    lf = [f for f in fs if f.cwe == "CWE-200" and "format string" in (f.title or "").lower()]
    assert lf and lf[0].severity == "high", [(f.title, f.cwe) for f in fs]
    ev = " ".join(e.get("detail", "") for f in lf for e in (f.evidence or []))
    assert "image base" in ev and "ASLR" in ev and "not exercised here" in ev, ev[:200]
