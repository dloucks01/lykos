"""CVE -> exploit chain attribution (D4): when the cve_poc stage reproduces a crash from a matched
CVE and the exploit ladder then weaponizes that crash to L2/L3, the autopilot links the escalation
back to the CVE so the output shows a real CVE-to-exploit chain, not two disconnected findings.
These unit tests pin the attribution helpers; the full-pipeline chain is exercised by the autopilot
(and verified live in-session on a zlib-1.2.11-banner stack-smash fixture)."""
import pathlib
import shutil
import subprocess
import tempfile

import pytest
from lykos.analyze import orchestrate
from lykos.analyze.ingest import ingest
from lykos.db.dao import DynResultDAO, FindingDAO, PocDAO

_GCC = shutil.which("gcc") or shutil.which("cc")

# A target that (a) embeds a vulnerable zlib version banner so cve_scan matches CWE-787 CVEs and
# (b) is a classic no-canary / no-PIE stack overflow with a win() -> the matched CVE's cyclic
# CWE-class trigger reproduces a CONTROLLABLE crash the exploit ladder escalates to L2/L3.
_CVE_CHAIN_SRC = (
    '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n'
    'char banner[] = "deflate 1.2.11 Copyright 1995-2017";\n'   # zlib 1.2.11 -> CWE-787 CVEs
    'void win(void){ system("/bin/sh"); }\n'
    'void vuln(void){ char buf[64]; read(0, buf, 512); }\n'
    'int main(void){ write(1, banner, sizeof banner); vuln(); return 0; }\n')


def _target(store, case):
    p = pathlib.Path(tempfile.mkdtemp()) / "t.bin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 200)
    return ingest(store, case.id, p, filename="t.bin")


def test_cve_crash_origins_maps_input_to_cve(store, case):
    t = _target(store, case)
    dd = DynResultDAO(store.conn)
    # a cve_poc crash carries note "<label> trigger" with the CVE id; two formats (bespoke + class)
    dd.insert(t.id, case.id, input_sha="sha_bespoke", crashed=True, signal_name="SIGSEGV",
              note="CVE-2022-37434 trigger")
    dd.insert(t.id, case.id, input_sha="sha_class", crashed=True, signal_name="SIGSEGV",
              note="CVE-2018-25032 (CWE-787 class) trigger")
    dd.insert(t.id, case.id, input_sha="sha_fuzz", crashed=True, signal_name="SIGSEGV",
              note="fuzzer crash")                       # not a CVE trigger -> excluded
    dd.insert(t.id, case.id, input_sha="sha_nocrash", crashed=False, note="CVE-9999-1 trigger")
    origins = orchestrate._cve_crash_origins(store, t.id)
    assert origins == {"sha_bespoke": "CVE-2022-37434", "sha_class": "CVE-2018-25032"}


def test_max_verified_poc_level(store, case):
    t = _target(store, case)
    pd = PocDAO(store.conn)
    assert orchestrate._max_verified_poc_level(store, t.id) == 0          # none yet
    pd.insert(t.id, case.id, level="L1", verified=True)
    pd.insert(t.id, case.id, level="L3", verified=True)
    pd.insert(t.id, case.id, level="L2", verified=False)                  # unverified ignored
    assert orchestrate._max_verified_poc_level(store, t.id) == 3


def test_record_cve_weaponized_files_a_linked_finding(store, case):
    t = _target(store, case)
    orchestrate._record_cve_weaponized(store, t, "CVE-2018-25032", 3)
    chain = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "cve_chain"]
    assert chain, "no cve_chain finding recorded"
    f = chain[0]
    assert "CVE-2018-25032" in f.title and "L3" in f.title
    assert f.state == "poc-backed" and f.severity == "critical"
    assert f.dedup_key == f"cve-chain:CVE-2018-25032:{t.id}"
    # L2 escalation is high, not critical
    orchestrate._record_cve_weaponized(store, t, "CVE-2021-1", 2)
    f2 = next(f for f in FindingDAO(store.conn).list_by_target(t.id)
              if f.detector == "cve_chain" and "CVE-2021-1" in (f.title or ""))
    assert f2.severity == "high" and "L2" in f2.title


@pytest.mark.skipif(not _GCC, reason="needs a C compiler for the CVE-chain fixture")
def test_cve_crash_escalates_through_the_exploit_ladder(store, tmp_path):
    """End-to-end CVE -> exploit chain: a version-matched CWE-787 CVE (zlib 1.2.11 banner) whose
    cyclic CWE-class trigger reproduces a controllable crash is escalated by the exploit ladder to
    L2/L3, and the escalation is attributed back to the CVE. Drives the same stage sequence the
    autopilot runs (without its slow fuzz/concolic phases)."""
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = tmp_path / "v.c"; src.write_text(_CVE_CHAIN_SRC)
    exe = tmp_path / "v"
    if subprocess.run([_GCC, "-no-pie", "-fno-stack-protector", "-static", "-O0", "-w",
                       str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build the CVE-chain fixture")
    register()
    case = store.cases.create("cvechain")
    t = ingest(store, case.id, exe, filename="v")
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()

    def run(stage, **params):
        r = JobQueue(store.conn).enqueue(case.id, stage, target_id=t.id, params=params, force=True)
        assert pool.wait_idle(240), f"{stage} timed out"
        return JobQueue(store.conn).runs.get(r.id).status
    try:
        enqueue_triage(JobQueue(store.conn), t, force=True); assert pool.wait_idle(60)
        run("disassemble"); run("cve_scan"); run("cve_poc")
        origins = orchestrate._cve_crash_origins(store, t.id)
        assert origins, "cve_poc did not reproduce a matched-CVE crash"
        crashes = orchestrate._distinct_crashes(store, t.id)
        assert crashes, "no distinct crash from the CVE trigger"
        cve_best = {}
        for cr in crashes:
            cve = origins.get(cr.input_sha)
            lvl0 = orchestrate._max_verified_poc_level(store, t.id) if cve else 0
            run("root_cause", input_sha=cr.input_sha)
            run("build_poc", input_sha=cr.input_sha)
            run("poc_primitive", input_sha=cr.input_sha)
            after = orchestrate._max_verified_poc_level(store, t.id)
            if cve and after > lvl0 and after >= 2:
                cve_best[cve] = max(cve_best.get(cve, 0), after)
        cve0 = origins.get(crashes[0].input_sha)
        lvlb = orchestrate._max_verified_poc_level(store, t.id) if cve0 else 0
        run("build_exploit", input_sha=crashes[0].input_sha)
        after = orchestrate._max_verified_poc_level(store, t.id)
        if cve0 and after > lvlb and after >= 2:
            cve_best[cve0] = max(cve_best.get(cve0, 0), after)
    finally:
        pool.stop(grace=3.0)
    # the matched CVE's crash must have been weaponized past L1 (the cve_poc reproduction)
    assert cve_best, "the CVE crash did not escalate beyond L1 through the exploit ladder"
    best = max(cve_best.values())
    assert best >= 2
    for cve, lvl in cve_best.items():
        orchestrate._record_cve_weaponized(store, t, cve, lvl)
    chain = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "cve_chain"]
    assert chain and any("weaponized to L" in (f.title or "") for f in chain)
