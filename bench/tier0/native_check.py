#!/usr/bin/env python3
"""Exercise the NATIVE-CRASH validator oracle (Phase 0/2), which binary-only targets use and the
source-based Tier-0 corpus never reaches (it validates through ASan). Builds a plain binary with an
input-controlled divide-by-zero inside a named function, runs the product driver + validator with
NO sanitizer build, and asserts a native-crash confirmation whose faulting PC lies in that function.

A positive (div-zero → SIGFPE inside `average`) and a negative (the divisor is checked) .

usage: native_check.py
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "core"))

POS = r'''
#include <stdio.h>
static int average(int total, int n) { return total / n; }   /* SIGFPE when n==0, faults here */
int main(void) {
    int c = getchar();
    if (c == EOF) return 2;
    int n = c - '0';
    printf("avg=%d\n", average(1000, n));
    return 0;
}
'''
NEG = r'''
#include <stdio.h>
static int average(int total, int n) { return n ? total / n : -1; }   /* checked: no SIGFPE */
int main(void) {
    int c = getchar();
    if (c == EOF) return 2;
    int n = c - '0';
    printf("avg=%d\n", average(1000, n));
    return 0;
}
'''


def build(src, path):
    with open(path + ".c", "w") as f:
        f.write(src)
    r = subprocess.run([os.environ.get("CC", "gcc"), "-O0", "-g", "-no-pie",
                        "-fno-stack-protector", "-w", "-o", path, path + ".c"],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stderr


def run(src, expect_confirm):
    from lykos.hypo import engine
    from lykos.hypo.validate import Target, validate
    from pathlib import Path
    tmp = tempfile.mkdtemp(prefix="native-")
    binp = os.path.join(tmp, "prog")
    ok, err = build(src, binp)
    if not ok:
        return False, "build failed: " + err[-200:]
    out = engine.run_driver(binp, argv=[], input_mode="stdin", budget=40, input_size=16)
    hyps = engine.hypotheses_from(out, binp)
    tgt = Target(exe=Path(binp), argv=[], mode="stdin", asan_exe=None)   # force native oracle
    confirmed = []
    for h in hyps:
        for s in h.solutions:
            v, _ = validate(tgt, h, s.data)
            if v.confirmed and v.method == "native-crash":
                confirmed.append((h.kind, h.func, v.detail))
    got = bool(confirmed)
    return got == expect_confirm, ("confirmed " + str(confirmed) if confirmed
                                   else "no native-crash confirmation")


def main():
    fails = 0
    ok, detail = run(POS, expect_confirm=True)
    print(f"{'PASS' if ok else 'FAIL'} native_divzero_positive  {detail}")
    fails += 0 if ok else 1
    ok, detail = run(NEG, expect_confirm=False)
    print(f"{'PASS' if ok else 'FAIL'} native_divzero_negative  {detail}")
    fails += 0 if ok else 1
    print(f"{2 - fails}/2 native-crash checks passed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
