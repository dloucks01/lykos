#!/usr/bin/env python3
"""Aim the DIRECTED concolic confirmer at ONE finding's sink: build the codec harness twice
(non-ASan for angr to explore, ASan for replay), steer angr at the sink functions, and report
whether it synthesized an input that faults under ASan. Static-finding + directed solve, bounded."""
import os, sys, time
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core"))
from lykos.analyze import libfuzzer as LF
from lykos.analyze.symbolic import directed_confirm as DC
from lykos import observe

observe.configure()                         # timestamped, module-tagged log (LYKOS_LOG sets level)

root = Path(sys.argv[1]).resolve()
syms = sys.argv[2].split(",") if len(sys.argv) > 2 else ["clear_decompress_residual_data", "clear_resize_buffer"]
secs = int(sys.argv[3]) if len(sys.argv) > 3 else 240
wd = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("/tmp/dc1"); wd.mkdir(parents=True, exist_ok=True)

plans = LF.plan_harnesses(root, limit=30)
spec = next((s for s in plans if "codec" in (s.get("id","")+s.get("entry","")).lower()), None)
if not spec: print("no codec harness"); sys.exit(1)
print(f"[dc] harness: {spec.get('id')}", flush=True)
cache = LF.BuildCache(wd/"cache") if hasattr(LF,"BuildCache") else None
print("[dc] building ASan (replay) ...", flush=True); t=time.time()
asan = LF.build_libfuzzer(root, wd/"codec_asan.bin", spec=spec, timeout=1200, cache=cache, sanitize=True)
print(f"[dc]   asan ok={asan.get('ok')} ({int(time.time()-t)}s) {('' if asan.get('ok') else str(asan.get('log'))[-200:])}", flush=True)
print("[dc] building explore (no ASan) ...", flush=True); t=time.time()
expl = LF.build_libfuzzer(root, wd/"codec_expl.bin", spec=spec, timeout=1200, cache=cache, sanitize=False)
print(f"[dc]   explore ok={expl.get('ok')} ({int(time.time()-t)}s) {('' if expl.get('ok') else str(expl.get('log'))[-200:])}", flush=True)
if not (asan.get("ok") and expl.get("ok")): print("[dc] build failed -> cannot run directed confirm"); sys.exit(2)
print(f"[dc] directed concolic_confirm steered at {syms} (timeout {secs}s) ...", flush=True)
# structure-valid seeds: argv[5] (or LYKOS_DC_SEEDS) = a directory of seed files. The driver pins
# each seed's gate-byte PREFIX and leaves the rest of the buffer symbolic.
seed_dir = sys.argv[5] if len(sys.argv) > 5 else os.environ.get("LYKOS_DC_SEEDS", "")
seeds = []
if seed_dir and Path(seed_dir).is_dir():
    seeds = [p.read_bytes() for p in sorted(Path(seed_dir).iterdir()) if p.is_file()][:8]
print(f"[dc] {len(seeds)} seed(s)", flush=True)
r = DC.concolic_confirm(expl["binary"], asan["binary"], target_syms=syms,
                        lib_dirs=asan.get("lib_dirs"), seeds=seeds or None, timeout=secs)
print(f"[dc] RESULT confirmed={r.get('confirmed')} class={r.get('class')} rung={r.get('rung')} reason={r.get('reason')}", flush=True)
if r.get("confirmed"):
    open(wd/"poc_input.bin","wb").write(r.get("input") or b"")
    print(f"[dc] *** PoC input -> {wd/'poc_input.bin'}\n{(r.get('report') or '')[:600]}", flush=True)
