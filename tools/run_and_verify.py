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
import shlex
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


def this_run_rows(db, prior_ids, launched_at):
    """(runs, done_stages, findings, pocs) for THIS run only: analysis_run rows not present before
    launch and created at/after it, and the findings/pocs those runs' cases created or re-touched
    since launch -- so a reused case store's earlier rows never vouch for a crashed run."""
    with sqlite3.connect(db) as c:
        runs = [(rid, case, st, status) for rid, case, st, status, created in c.execute(
            "select id, case_id, stage, status, created_at from analysis_run")
            if rid not in prior_ids and (created or 0) >= launched_at]
        done = {st for _rid, _case, st, status in runs if status == "done"}
        cases = sorted({case for _rid, case, _st, _status in runs})
        findings = pocs = 0
        if cases:
            marks = ",".join("?" * len(cases))
            findings = c.execute(f"select count(*) from finding where case_id in ({marks}) "
                                 f"and updated_at >= ?", (*cases, launched_at)).fetchone()[0]
            pocs = c.execute(f"select count(*) from poc where case_id in ({marks}) "
                             f"and created_at >= ?", (*cases, launched_at)).fetchone()[0]
    return runs, done, findings, pocs


def _configure_log() -> None:
    """Timestamped, module-tagged logging like every other tool (LYKOS_LOG sets the level)."""
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                      "core"))
    try:
        from lykos import observe
        observe.configure()
    except Exception:                                    # noqa: BLE001 -- the launcher still works
        pass


def main():
    _configure_log()
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
    q = shlex.quote                                          # POSIX-shell quoting (not Python repr)
    inner = (f"cd {q(core)} && python3 -m lykos.cli analyze {q(a.target)} --budget {int(a.budget)} "
             f"--case-store {q(cs)} --name {q(a.name)} > {q(out)} 2> {q(err)}")
    db = os.path.join(cs, "case.db")
    # A REUSED case store already holds a previous run's rows (incl. its triage/attack_path); the
    # verdict must be about THIS run only: snapshot the pre-existing run ids + the launch time.
    prior_ids = set()
    if os.path.exists(db):
        try:
            with sqlite3.connect(db) as c0:
                prior_ids = {r[0] for r in c0.execute("select id from analysis_run")}
        except sqlite3.Error:
            prior_ids = set()
    launched_at = int(time.time())
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
    if not os.path.exists(db):
        print(f"FAIL: no case.db after {dur}s")
        return 3
    runs, done, findings, pocs = this_run_rows(db, prior_ids, launched_at)
    terminal_ran = bool({"triage", "attack_path"} & done)
    print(f"this run: runs={len(runs)} (ignored {len(prior_ids)} prior)  duration={dur}s  "
          f"stages_done={len(done)}  findings={findings}  pocs={pocs}  "
          f"terminal_stage_ran={terminal_ran}", flush=True)
    ok = terminal_ran and findings > 0
    print("VERIFIED COMPLETE" if ok else "INCOMPLETE/INVALID -- investigate", flush=True)
    return 0 if ok else 4


if __name__ == "__main__":
    sys.exit(main())
