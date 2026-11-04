#!/usr/bin/env python3
"""OPT-IN long fuzzing campaign (NOT the default pipeline).

The default lykos flow is static analysis + SMART DIRECTED confirmation (concolic/symbolic solve
aimed at a specific finding), which is fast and precise. This tool is the opposite tool for when you
explicitly want a long, coverage-guided ASan campaign against a source tree's OWN parse/decode
harnesses -- the OSS-Fuzz-style hammer that can surface novel memory bugs blind fuzzing alone finds.
Run it deliberately; it can take a long time.

Usage:
  python3 tools/deep_decoder_fuzz.py <source_tree> [harness_substrings] [seconds_per_harness] [out_dir]
  e.g.  python3 tools/deep_decoder_fuzz.py /path/freerdp-clean codec,Core 1800 /tmp/deepfuzz
"""
import glob
import os
import sys
import time
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

    cache = LF.BuildCache() if hasattr(LF, "BuildCache") else None
    total = 0
    for spec in chosen:
        hid = spec.get("id", "?")
        out = outdir / f"fuzz_{hid[-40:].replace('/', '_')}.bin"
        print(f"\n[deepfuzz] building {hid} ...", flush=True)
        t0 = time.time()
        b = LF.build_libfuzzer(root, out, spec=spec, timeout=1200, cache=cache)
        if not b.get("ok"):
            print(f"[deepfuzz]   BUILD FAILED: {str(b.get('log'))[-200:]}", flush=True)
            continue
        print(f"[deepfuzz]   built in {int(time.time()-t0)}s -> fuzzing {secs}s", flush=True)
        r = LF.run_libfuzzer(out, outdir, seconds=secs, corpus=seeds or None,
                             lib_dirs=b.get("lib_dirs"), keep_going=True)
        cr = r.get("crashes") or []
        print(f"[deepfuzz]   execs={r.get('execs')} crashes={len(cr)}", flush=True)
        for i, c in enumerate(cr):
            ipath = outdir / f"crash_{hid[-20:].replace('/','_')}_{i}.bin"
            try:
                open(ipath, "wb").write(c.get("input") or b"")
            except Exception:
                pass
            print(f"[deepfuzz]   *** CRASH {i}: {ipath}\n{(c.get('report') or '')[:600]}\n", flush=True)
            total += 1
    print(f"\n[deepfuzz] DONE. total crashes = {total}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
