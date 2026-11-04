#!/usr/bin/env python3
"""Launch a lykos analyze run and VERIFY it completed -- robustly, so a run is never misjudged.

Fixes the recurring operational failure: setsid/systemd-run reparent the work, so the PID seen at
launch is a short-lived wrapper, not the analysis python. Watching the wrapper returns instantly and
an empty case DB looks like "the run died". This tool instead (1) launches under a memory-capped
systemd scope, (2) finds the REAL python by its full cmdline (the one containing both 'lykos.cli
analyze' and the case-store path), waiting for it to appear, (3) waits until THAT pid exits, then
(4) VERIFIES completion against the case DB (a terminal stage ran + findings exist) and prints a
stage/finding/poc summary. Exit non-zero if the run did not genuinely complete.

Usage: run_and_verify.py <source_or_binary> <case_store_dir> [--budget N] [--name NAME] [--mem 28G]
"""
import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import time


def real_pid(case_store, timeout=90):
    """The analysis python pid (cmdline has 'lykos.cli analyze' AND the case store), not a wrapper."""
    dl = time.time() + timeout
    while time.time() < dl:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                cl = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\0", b" ").decode("latin-1")
            except OSError:
                continue
            if "lykos.cli analyze" in cl and case_store in cl and cl.strip().startswith(("python", "/")):
                head = cl.split("lykos.cli")[0].lower()
                if "python" in head:
                    return int(pid)
        time.sleep(0.5)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("case_store")
    ap.add_argument("--budget", type=int, default=1200)
    ap.add_argument("--name", default="run")
    ap.add_argument("--mem", default="28G")
    a = ap.parse_args()
    cs = os.path.abspath(a.case_store)
    os.makedirs(cs, exist_ok=True)
    out = os.path.join(cs, "run.out")
    err = os.path.join(cs, "run.err")
    core = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core")
    inner = (f"cd {core} && python3 -m lykos.cli analyze {a.target!r} --budget {a.budget} "
             f"--case-store {cs!r} --name {a.name} > {out!r} 2> {err!r}")
    unit = f"lykos-{a.name}-{int(time.time())}"
    if shutil.which("systemd-run"):
        cmd = ["systemd-run", "--user", "--scope", "-p", f"MemoryMax={a.mem}",
               "-p", "MemorySwapMax=0", "--unit", unit, "bash", "-c", inner]
    else:
        cmd = ["setsid", "bash", "-c", inner]
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     stdin=subprocess.DEVNULL)
    pid = real_pid(cs)
    if pid is None:
        print("FAIL: analysis python never appeared (check run.err)")
        return 2
    print(f"tracking real python pid={pid} (unit={unit})", flush=True)
    t0 = time.time()

    def _alive(p):
        # A zombie keeps /proc/<pid> until its (reparented) parent reaps it, so dir-existence
        # alone hangs forever on a completed run. Treat state Z (defunct) as exited.
        try:
            st = open(f"/proc/{p}/stat").read()
            state = st[st.rfind(")") + 2]
        except (OSError, IndexError):
            return False
        return state != "Z"

    while _alive(pid):
        time.sleep(15)
    dur = int(time.time() - t0)
    db = os.path.join(cs, "case.db")
    if not os.path.exists(db):
        print(f"FAIL: no case.db after {dur}s")
        return 3
    c = sqlite3.connect(db)
    runs = c.execute("select stage,status from analysis_run").fetchall()
    done = {s for s, st in runs if st == "done"}
    findings = c.execute("select count(*) from finding").fetchone()[0]
    pocs = c.execute("select count(*) from poc").fetchone()[0]
    terminal_ran = bool({"triage", "attack_path"} & done)
    print(f"duration={dur}s  stages_done={len(done)}  findings={findings}  pocs={pocs}  "
          f"terminal_stage_ran={terminal_ran}", flush=True)
    ok = terminal_ran and findings > 0
    print("VERIFIED COMPLETE" if ok else "INCOMPLETE/INVALID -- investigate", flush=True)
    return 0 if ok else 4


if __name__ == "__main__":
    sys.exit(main())
