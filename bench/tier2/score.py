#!/usr/bin/env python3
"""Tier-2 scorer: measure the loop on REAL bugs in REAL third-party source (doc 56/57).

Each target dir holds vuln.h + fixed.h (a real library version pair spanning a real bug-fix),
harness.c (#include "target.h"), seeds/, and meta.json. Ground truth is the vuln/fixed DIFFERENTIAL:
a crashing input counts as a real bug only when it crashes the vulnerable build AND the fixed build
SURVIVES it (so it is the bug the fix addressed, not an incidental defect in both). Candidate
crashing inputs come from BOTH engines -- the directed symbolic solver and the AFL++/CmpLog fuzz
fallback seeded with the target's real-input corpus -- exactly as the loop runs them.

Unlike Tier-0 these are not our bugs; unlike Tier-1 (CGC) the source pipeline (afl+cmplog build,
ASan oracle) applies directly and no protocol harness is needed. This is the first non-self-
referential number.

usage: score.py [--fuzz-seconds S] [target-id ...]
"""
import argparse
import glob
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "core"))

ASAN = ["-O0", "-g", "-w", "-fsanitize=address,undefined", "-fno-sanitize-recover=undefined",
        "-fno-omit-frame-pointer"]
ASAN_ENV = {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:symbolize=1:allocator_may_return_null=1",
            "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1"}


def _build(cc, out, src, inc, extra, env=None):
    e = {**os.environ, **env} if env else None
    flags = ASAN if "asan" in str(out) else ["-O0", "-g", "-w"]
    r = subprocess.run([cc, "-I", inc, *flags, "-o", str(out), str(src), *extra],
                       capture_output=True, text=True, env=e)
    return out if (r.returncode == 0 and out.exists()) else None


def score_target(tid, fuzz_seconds):
    from lykos.hypo import engine
    from lykos.hypo.validate import Target, replay
    from lykos.analyze.fuzz.aflpp import locate_afl, run_campaign
    tdir = HERE / tid
    meta = json.loads((tdir / "meta.json").read_text())
    extra = meta.get("extra_flags", [])
    mode = meta.get("mode", "file")
    argv = meta.get("argv", ["@@"])
    work = Path(tempfile.mkdtemp(prefix=f"t2-{tid}-"))
    # symlink target.h to each version in its own include dir, then build the variants
    def inc_for(ver):
        d = work / ver
        d.mkdir(exist_ok=True)
        (d / "target.h").unlink(missing_ok=True)
        (d / "target.h").symlink_to(tdir / f"{ver}.h")
        return str(d)
    vi, fi = inc_for("vuln"), inc_for("fixed")
    afl = locate_afl()
    v_plain = _build("gcc", work / "vuln_plain", tdir / "harness.c", vi, extra)
    v_asan = _build("gcc", work / "vuln_asan", tdir / "harness.c", vi, extra, env=None)
    f_asan = _build("gcc", work / "fixed_asan", tdir / "harness.c", fi, extra)
    v_afl = _build("afl-clang-fast", work / "vuln_afl", tdir / "harness.c", vi, extra)
    v_cmplog = _build("afl-clang-fast", work / "vuln_cmplog", tdir / "harness.c", vi, extra,
                      env={"AFL_LLVM_CMPLOG": "1"})
    if not (v_plain and v_asan and f_asan):
        return {"id": tid, "error": "build failed", "real": 0, "crashes": 0}
    cand = []
    # directed engine (reaches/solves what it can on the plain build)
    try:
        out = engine.run_driver(str(v_plain), argv=argv, input_mode=mode, budget=60,
                                input_size=4096)
        for h in engine.hypotheses_from(out, str(v_plain)):
            cand += [s.data for s in h.solutions]
    except Exception:
        pass
    # fuzz fallback (AFL+CmpLog) seeded with the target's real corpus
    if afl and v_afl:
        od = work / "fuzzout"
        try:
            run_campaign(afl, str(v_afl), str(tdir / "seeds"), str(od), seconds=int(fuzz_seconds),
                         mode=mode, qemu=False, cmplog=Path(v_cmplog) if v_cmplog else None)
            for c in sorted(glob.glob(str(od / "**" / "crashes" / "id*"), recursive=True)):
                try:
                    cand.append(Path(c).read_bytes())
                except OSError:
                    pass
        except Exception:
            pass
    # DIFFERENTIAL: crashes vuln, survives fixed -> a real bug the fix addressed
    env = {**os.environ, **ASAN_ENV}
    real, seen, incidental = 0, set(), 0
    for data in cand:
        vb, verr = _run(v_asan, data, mode, argv, env)
        if not vb:
            continue
        frames = [l for l in verr.split(b"\n") if b"#1 " in l or b"#2 " in l][:2]
        sig = hashlib.sha1(b"\n".join(frames) or verr[:60]).hexdigest()[:12]
        if sig in seen:
            continue
        seen.add(sig)
        fb, _ = _run(f_asan, data, mode, argv, env)
        if fb:
            incidental += 1
        else:
            real += 1
    import shutil
    shutil.rmtree(work, ignore_errors=True)
    return {"id": tid, "real": real, "incidental": incidental, "crashes": len(cand)}


def _run(exe, data, mode, argv, env):
    tmp = tempfile.mkdtemp()
    try:
        if mode == "file":
            p = os.path.join(tmp, "in")
            Path(p).write_bytes(data)
            av = [str(exe)] + [p if a == "@@" else a for a in argv]
            r = subprocess.run(av, capture_output=True, env=env, timeout=10)
        else:
            r = subprocess.run([str(exe)], input=data, capture_output=True, env=env, timeout=10)
        return (b"Sanitizer" in r.stderr or r.returncode < 0), r.stderr
    except Exception:
        return False, b""
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fuzz-seconds", type=int, default=300)
    ap.add_argument("targets", nargs="*")
    a = ap.parse_args()
    ids = a.targets or sorted(d.name for d in HERE.iterdir()
                              if (d / "meta.json").exists())
    tot_real = tot_inc = 0
    for tid in ids:
        r = score_target(tid, a.fuzz_seconds)
        tot_real += r.get("real", 0)
        tot_inc += r.get("incidental", 0)
        print(f"{r['id']:<16} real-bugs={r.get('real',0)} incidental={r.get('incidental',0)} "
              f"candidates={r.get('crashes',0)} {r.get('error','')}")
    print(f"\nTIER-2 {tot_real} real bug(s) found (vuln crashes / fixed survives), "
          f"{tot_inc} incidental, across {len(ids)} target(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
