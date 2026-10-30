#!/usr/bin/env python3
"""Exercise the SOURCE-PROJECT (directory) hunt path (Phase 1), which the file-based Tier-0 corpus
never covers: a multi-file Makefile project, built twice (plain for angr + ASan/UBSan oracle), with
the bug in a DIFFERENT translation unit than main() -- so it also checks multi-file DWARF
attribution and that confirmed locations map back to the operator's tree, not the temp build copy.

usage: sourcedir_check.py
"""
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "core"))

MAKEFILE = "CC ?= gcc\nCFLAGS ?= -O0 -g\napp: a.c b.c\n\t$(CC) $(CFLAGS) -o app a.c b.c\n"
A_C = ("#include <stdio.h>\nvoid parse(const char *s);\n"
       "int main(void){ char line[256]; if(!fgets(line,sizeof line,stdin)) return 0; "
       "parse(line); return 0; }\n")
B_C = ("#include <string.h>\n#include <stdio.h>\n"
       "void parse(const char *s){\n"
       "    char buf[32];\n"
       "    strcpy(buf, s);          /* CWE-121 stack overflow */\n"
       "    printf(\"%s\\n\", buf);\n}\n")


def main():
    from lykos.hypo import loop
    d = tempfile.mkdtemp(prefix="srcdir-")
    for name, body in (("Makefile", MAKEFILE), ("a.c", A_C), ("b.c", B_C)):
        with open(os.path.join(d, name), "w") as f:
            f.write(body)
    try:
        rep = loop.hunt(d, budget=120, input_size=300, log=lambda _m: None)
        if rep["kind"] != "source-project":
            print(f"FAIL sourcedir  prepared as {rep['kind']!r}, expected source-project")
            return 1
        hit = None
        for r in rep["results"]:
            for h in r["hypotheses"]:
                if (h.status == "confirmed" and h.kind == "stack-write"
                        and (h.location or "").replace("\\", "/").endswith("b.c:5")
                        and h.func == "parse"):
                    hit = h
        if hit and str(d) in (hit.location or ""):      # mapped back to the operator's tree
            print(f"PASS sourcedir  CONFIRMED {hit.kind} at {hit.location} in {hit.func}")
            return 0
        conf = [(h.kind, h.location, h.func) for r in rep["results"]
                for h in r["hypotheses"] if h.status == "confirmed"]
        print(f"FAIL sourcedir  no stack-write confirmed in parse@b.c:5; confirmed: {conf}")
        return 1
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
