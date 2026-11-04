#!/usr/bin/env python3
"""OPT-IN long fuzzing campaign (NOT the default pipeline).

The default lykos flow is static analysis + SMART DIRECTED confirmation (concolic/symbolic solve
aimed at a specific finding), which is fast and precise. This tool is the opposite tool for when you
explicitly want a long, coverage-guided ASan campaign against a source tree's OWN parse/decode
harnesses -- the OSS-Fuzz-style hammer that can surface novel memory bugs blind fuzzing alone finds.
Run it deliberately; it can take a long time.

Harnesses run IN PARALLEL (each in its own workdir), and each uses `fork` libFuzzer sub-processes, so
a machine's cores are actually used -- a real campaign, not a single-core crawl. Crashes go through
lykos's run_libfuzzer pipeline (replay + fault-signature dedup), not a raw harvest.

Usage:
  python3 tools/deep_decoder_fuzz.py <source_tree> [harness_substrings] [seconds_per_harness] [out_dir] [fork_per_harness]
  e.g.  python3 tools/deep_decoder_fuzz.py /path/freerdp-clean codec,Core,Common 7200 /tmp/deepfuzz 4
"""
import glob
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# make `lykos` importable no matter the cwd (a script run by absolute path does not get core/ on path)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core"))
from lykos.analyze import libfuzzer as LF   # noqa: E402


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

    print(f"\n[deepfuzz] fuzzing {len(built)} harnesses in parallel, {secs}s each, fork={fork}\n", flush=True)

    def _runone(spec, out, b):
        hid = spec.get("id", "?")
        wd = outdir / ("run_" + hid[-40:].replace("/", "_"))
        wd.mkdir(parents=True, exist_ok=True)
        r = LF.run_libfuzzer(out, wd, seconds=secs, corpus=seeds or None,
                             lib_dirs=b.get("lib_dirs"), keep_going=True, fork=fork)
        return spec, r

    total = 0
    with ThreadPoolExecutor(max_workers=max(1, len(built))) as ex:
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
