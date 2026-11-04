#!/usr/bin/env python3
"""OPT-IN long fuzzing campaign (NOT the default pipeline).

The default lykos flow is static analysis + SMART DIRECTED confirmation (concolic/symbolic solve
aimed at a specific finding), which is fast and precise. This tool is the opposite tool for when you
explicitly want a long, coverage-guided ASan campaign against a source tree's OWN parse/decode
harnesses -- the OSS-Fuzz-style hammer that can surface novel memory bugs blind fuzzing alone finds.
Run it deliberately; it can take a long time.

Harnesses run IN PARALLEL (each in its own workdir), and each uses `fork` libFuzzer sub-processes, so
a machine's cores are actually used -- a real campaign, not a single-core crawl. Concurrency is
BOUNDED (min(#harnesses, cpu_count//4), or 4 when that is unknown), and each harness's libFuzzer runs
under a memory-capped `systemd-run --user --scope -p MemoryMax=...` when available, plus libFuzzer's
own -rss_limit_mb per process -- N ASan harnesses x `fork` children can otherwise exhaust RAM.
Crashes go through lykos's run_libfuzzer pipeline (replay + fault-signature dedup), not a raw harvest.

Usage:
  python3 tools/deep_decoder_fuzz.py <source_tree> [harness_substrings] [seconds_per_harness] [out_dir] [fork_per_harness]
  e.g.  python3 tools/deep_decoder_fuzz.py /path/freerdp-clean codec,Core,Common 7200 /tmp/deepfuzz 4
"""
import glob
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# make `lykos` importable no matter the cwd (a script run by absolute path does not get core/ on path)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core"))
from lykos.analyze import libfuzzer as LF   # noqa: E402


def _mem_total_mb():
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 8192


def _concurrency(n_built):
    cpus = os.cpu_count() or 0
    return max(1, min(n_built, (cpus // 4) or 4))


def _memcap_launcher(scope_mb):
    """argv prefix running a process in a MemoryMax-capped transient user scope, or [] (graceful
    fallback: libFuzzer's -rss_limit_mb still applies) when systemd-run/a user manager is absent."""
    if not shutil.which("systemd-run"):
        return []
    probe = ["systemd-run", "--user", "--scope", "-q", "-p", f"MemoryMax={scope_mb}M", "true"]
    try:
        if subprocess.run(probe, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          timeout=20).returncode != 0:
            return []
    except (OSError, subprocess.TimeoutExpired):
        return []
    return ["systemd-run", "--user", "--scope", "-q", "-p", f"MemoryMax={scope_mb}M",
            "-p", "MemorySwapMax=0"]


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    root = Path(sys.argv[1]).resolve()
    want = sys.argv[2].split(",") if len(sys.argv) > 2 else ["codec", "Core", "Common"]
    secs = int(sys.argv[3]) if len(sys.argv) > 3 else 600
    outdir = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("/tmp/deepfuzz")
    fork = int(sys.argv[5]) if len(sys.argv) > 5 else 4
    outdir.mkdir(parents=True, exist_ok=True)

    seeds = []
    for pat in ("**/test/*.bmp", "**/test/*.png", "**/*.bin", "**/test/*.ppm"):
        for f in glob.glob(str(root / pat), recursive=True)[:40]:
            try:
                seeds.append(open(f, "rb").read())
            except OSError:
                pass
    print(f"[deepfuzz] {len(seeds)} seeds", flush=True)

    plans = LF.plan_harnesses(root, limit=30)
    chosen = [s for s in plans
              if any(w.lower() in (s.get("id", "") + s.get("entry", "")).lower() for w in want)]
    print(f"[deepfuzz] {len(chosen)}/{len(plans)} harnesses: {[s.get('id') for s in chosen]}", flush=True)

    cache = LF.BuildCache(outdir / "cache") if hasattr(LF, "BuildCache") else None
    # Build sequentially (cache hits are fast and a shared BuildCache is not thread-safe), then FUZZ
    # all harnesses in parallel -- each in its own workdir with `fork` libFuzzer sub-processes.
    built = []
    for spec in chosen:
        hid = spec.get("id", "?")
        out = outdir / f"fuzz_{hid[-40:].replace('/', '_')}.bin"
        print(f"[deepfuzz] building {hid} ...", flush=True)
        t0 = time.time()
        b = LF.build_libfuzzer(root, out, spec=spec, timeout=1200, cache=cache)
        if not b.get("ok"):
            print(f"[deepfuzz]   BUILD FAILED {hid}: {str(b.get('log'))[-200:]}", flush=True)
            continue
        print(f"[deepfuzz]   built {hid} in {int(time.time()-t0)}s", flush=True)
        built.append((spec, out, b))

    workers = _concurrency(len(built))
    # memory: give the concurrent campaigns ~60% of RAM between them; each scope holds the libFuzzer
    # parent + `fork` children, so libFuzzer's per-process cap is the scope budget split fork+1 ways
    scope_mb = max(1024, int(_mem_total_mb() * 0.6) // workers)
    rss_mb = max(512, min(2048, scope_mb // (max(1, fork) + 1)))
    launcher = _memcap_launcher(scope_mb)
    print(f"\n[deepfuzz] fuzzing {len(built)} harnesses, {workers} at a time, {secs}s each, fork={fork}, "
          f"MemoryMax={scope_mb}M/harness{'' if launcher else ' (systemd-run unavailable: rss-limit only)'}, "
          f"rss_limit_mb={rss_mb}\n", flush=True)

    def _runone(spec, out, b):
        hid = spec.get("id", "?")
        wd = outdir / ("run_" + hid[-40:].replace("/", "_"))
        wd.mkdir(parents=True, exist_ok=True)
        binary = b.get("binary") or out        # build returns the runnable path; `out` isn't created
        r = LF.run_libfuzzer(binary, wd, seconds=secs, corpus=seeds or None,
                             lib_dirs=b.get("lib_dirs"), keep_going=True, fork=fork,
                             rss_limit_mb=rss_mb, launcher=launcher)
        return spec, r

    total = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(_runone, *x) for x in built]
        for fut in as_completed(futs):
            spec, r = fut.result()
            hid = spec.get("id", "?")
            cr = r.get("crashes") or []
            print(f"[deepfuzz] {hid}: execs={r.get('execs')} crashes={len(cr)}", flush=True)
            for i, c in enumerate(cr):
                ipath = outdir / f"crash_{hid[-20:].replace('/','_')}_{i}.bin"
                try:
                    open(ipath, "wb").write(c.get("input") or b"")
                except Exception:                                    # noqa: BLE001
                    pass
                print(f"[deepfuzz]   *** CRASH {hid} #{i} ({c.get('kind')}): {ipath}\n"
                      f"{(c.get('report') or '')[:700]}\n", flush=True)
                total += 1
    print(f"\n[deepfuzz] DONE. total distinct crashes = {total}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
