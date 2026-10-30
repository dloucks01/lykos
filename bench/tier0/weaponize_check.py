#!/usr/bin/env python3
"""Step 4 check: the hunt loop climbs a control-flow-hijack to a confirmed ret2win L3, across
several overflow SHAPES so the weaponizer is not overfit to one:
  * stdin read()-overflow, win found by the name `win`         -> expect L3
  * argv strcpy()-overflow, win found by the name `give_shell` -> expect L3
  * bounded copy (no overflow)                                 -> expect NO exploit

Builds each as a no-PIE binary (a fixed win address is the ret2win precondition) and runs the
PRODUCT loop on the binary.

usage: weaponize_check.py
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "core"))

READ_WIN = """
#include <stdio.h>
#include <unistd.h>
void win(void){ puts("LYKOS_PWNED"); fflush(stdout); _exit(0); }
void greet(void){ char name[64]; ssize_t n=read(0,name,512); if(n<0) return; printf("hi %s\\n",name); }
int main(void){ greet(); return 0; }
"""
ARG_STRCPY = """
#include <stdio.h>
#include <string.h>
#include <unistd.h>
void give_shell(void){ puts("SHELL"); fflush(stdout); _exit(0); }
void handle(const char *s){ char buf[48]; strcpy(buf,s); printf("hi %s\\n",buf); }
int main(int argc,char**argv){ if(argc<2) return 2; handle(argv[1]); return 0; }
"""
BOUNDED = """
#include <stdio.h>
#include <string.h>
#include <unistd.h>
void win(void){ puts("LYKOS_PWNED"); fflush(stdout); _exit(0); }
void greet(void){ char name[64]; ssize_t n=read(0,name,sizeof name-1); if(n<0) return; name[n]=0; printf("hi %s\\n",name); }
int main(void){ greet(); return 0; }
"""

SHAPES = [
    ("read_overflow_stdin", READ_WIN, [], "stdin", True),
    ("strcpy_overflow_argv", ARG_STRCPY, ["@@"], "arg", True),
    ("bounded_no_overflow", BOUNDED, [], "stdin", False),
]


def run_shape(name, src, argv, mode, expect_l3, budget):
    from lykos.hypo import loop
    tmp = tempfile.mkdtemp(prefix=f"wpn-{name}-")
    binp = os.path.join(tmp, "prog")
    with open(binp + ".c", "w") as f:
        f.write(src)
    r = subprocess.run([os.environ.get("CC", "gcc"), "-O0", "-g", "-no-pie",
                        "-fno-stack-protector", "-w", "-o", binp, binp + ".c"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return False, "build failed: " + r.stderr[-200:]
    argv_opt = argv or None
    mode_opt = mode
    rep = loop.hunt(binp, argv=argv_opt, mode=mode_opt, budget=budget, input_size=300,
                    out_dir=os.path.join(tmp, "out"), log=lambda _m: None)
    best = None
    for res in rep["results"]:
        for h in res["hypotheses"]:
            ex = getattr(h, "exploit", None)
            if ex and (best is None or ex.get("level", "") > best.get("level", "")):
                best = ex
    level = (best or {}).get("level")
    if expect_l3:
        ok = level == "L3" and (best or {}).get("confirmed")
        return ok, f"exploit={level} win={(best or {}).get('win')}"
    return (best is None or level != "L3"), f"exploit={level or 'none'}"


def main():
    budget = float(os.environ.get("WPN_BUDGET", "120"))
    fails = 0
    for name, src, argv, mode, expect in SHAPES:
        ok, detail = run_shape(name, src, argv, mode, expect, budget)
        print(f"{'PASS' if ok else 'FAIL'} {name:<24} {detail}")
        fails += 0 if ok else 1
    print(f"{len(SHAPES) - fails}/{len(SHAPES)} weaponization checks passed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
