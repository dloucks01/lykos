#!/usr/bin/env python3
"""Step 4 (B3) check: the hunt loop climbs a confirmed format-string hypothesis to a write-what-
where primitive, and auto-confirms L3 when an overwrite has an observable effect.
  * fmt bug + a writable global that gates observable output -> expect L3 (write-what-where)
  * fmt bug with no observable global                        -> expect L2 (primitive available)

Builds each no-PIE (fixed write addresses), runs the PRODUCT loop, checks the exploit on the
format-string hypothesis.

usage: fmt_check.py
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "core"))

OBSERVABLE = r"""
#include <stdio.h>
#include <string.h>
int authorized = 0;                 /* a %n write can flip this, gating observable output */
int main(void){
    char line[256];
    if(!fgets(line,sizeof line,stdin)) return 0;
    line[strcspn(line,"\r\n")]=0;
    printf(line);                   /* CWE-134 */
    printf("\n");
    puts(authorized ? "ACCESS GRANTED" : "denied");
    return 0;
}
"""
NO_TARGET = r"""
#include <stdio.h>
#include <string.h>
int main(void){
    char line[256];
    if(!fgets(line,sizeof line,stdin)) return 0;
    line[strcspn(line,"\r\n")]=0;
    printf(line);                   /* CWE-134, but nothing observable to overwrite */
    printf("\n");
    return 0;
}
"""

SHAPES = [("fmt_www_observable", OBSERVABLE, "L3"),
          ("fmt_www_no_target", NO_TARGET, "L2")]


def run_shape(name, src, expect, budget):
    from lykos.hypo import loop
    tmp = tempfile.mkdtemp(prefix=f"fmt-{name}-")
    binp = os.path.join(tmp, "prog")
    with open(binp + ".c", "w") as f:
        f.write(src)
    r = subprocess.run([os.environ.get("CC", "gcc"), "-O0", "-g", "-no-pie",
                        "-fno-stack-protector", "-w", "-o", binp, binp + ".c"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return False, "build failed: " + r.stderr[-200:]
    rep = loop.hunt(binp, mode="stdin", budget=budget, input_size=300,
                    out_dir=os.path.join(tmp, "out"), log=lambda _m: None)
    ex = None
    for res in rep["results"]:
        for h in res["hypotheses"]:
            if h.kind == "format-string" and getattr(h, "exploit", None):
                ex = h.exploit
    level = (ex or {}).get("level")
    ok = level == expect
    return ok, f"exploit={level} target={(ex or {}).get('target')}"


def main():
    budget = float(os.environ.get("FMT_BUDGET", "120"))
    fails = 0
    for name, src, expect in SHAPES:
        ok, detail = run_shape(name, src, expect, budget)
        print(f"{'PASS' if ok else 'FAIL'} {name:<22} expect={expect} {detail}")
        fails += 0 if ok else 1
    print(f"{len(SHAPES) - fails}/{len(SHAPES)} fmt write-what-where checks passed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
