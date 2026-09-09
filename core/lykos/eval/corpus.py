"""A bundled, compilable good/bad micro-corpus (Juliet-style) + a directory loader.

Each `Case` is a small, self-contained C program with a ground-truth label: a `bad` case
contains a real instance of its CWE (expect the platform to flag that CWE), a `good` case is
the safe variant that deliberately uses NO dangerous API for that class (expect no flag). The
corpus is small but real -- every case is actually compiled and analyzed by the harness.

Point the loader at a directory of `<cwe>__<name>__<good|bad>.c` files (or a manifest) to
score a larger drop (e.g. a Juliet subset) with the same harness.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_FLAGS = ["-O0", "-fno-stack-protector", "-no-pie", "-w"]


@dataclass
class Case:
    name: str
    cwe: str                       # ground-truth CWE class
    verdict: str                   # "bad" | "good"
    source: str = ""               # inline source (bundled corpus); may be empty for files=
    cflags: list = field(default_factory=lambda: list(_FLAGS))
    note: str = ""
    files: list = field(default_factory=list)          # extra .c source paths (multi-file)
    include_dirs: list = field(default_factory=list)   # -I dirs (Juliet support headers)
    defines: list = field(default_factory=list)        # -D macros (OMITGOOD/OMITBAD/…)


# ---------------------------------------------------------------- bundled micro-corpus
# NB: `good` variants use only non-flagged libc (write/fputs/fgets/strlen/strcmp/getenv);
# they must not call any function in detect/catalog.py:DANGEROUS, or they would (correctly)
# be flagged and count as a false positive.
_CASES: list[Case] = [
    # ---- CWE-120: buffer copy without bounds ----
    Case("strcpy_overflow", "CWE-120", "bad", r"""
#include <string.h>
#include <unistd.h>
static void copy(const char*s){ char b[64]; strcpy(b, s); write(1, b, strlen(b)); }
int main(int c, char**v){ if(c>1) copy(v[1]); return 0; }
""", note="unbounded strcpy into a 64-byte stack buffer"),
    Case("strcpy_bounded", "CWE-120", "good", r"""
#include <unistd.h>
static void copy(const char*s){ char b[64]; unsigned n=0;
  while(s[n] && n+1 < sizeof b){ b[n]=s[n]; n++; } b[n]=0; write(1, b, n); }
int main(int c, char**v){ if(c>1) copy(v[1]); return 0; }
""", note="manual bounds-checked copy, no dangerous API"),
    Case("sprintf_overflow", "CWE-120", "bad", r"""
#include <stdio.h>
int main(int c, char**v){ char b[64]; if(c>1) sprintf(b, "arg=%s", v[1]); return 0; }
""", note="unbounded sprintf into a fixed buffer"),
    Case("sprintf_manual", "CWE-120", "good", r"""
#include <unistd.h>
static void put_uint(unsigned x){ char b[16]; int i=0;
  if(!x){ write(1,"0",1); return; } while(x){ b[i++]='0'+x%10; x/=10; }
  while(i--) write(1, &b[i], 1); }
int main(int c, char**v){ (void)v; put_uint((unsigned)c); return 0; }
""", note="manual integer formatting, no sprintf/snprintf"),

    # ---- CWE-78: OS command injection ----
    Case("system_inject", "CWE-78", "bad", r"""
#include <stdlib.h>
int main(int c, char**v){ if(c>1) system(v[1]); return 0; }
""", note="argv passed straight to system()"),
    Case("system_none", "CWE-78", "good", r"""
#include <unistd.h>
#include <string.h>
int main(int c, char**v){ if(c>1) write(1, v[1], strlen(v[1])); return 0; }
""", note="echoes input, executes no command"),
    Case("popen_inject", "CWE-78", "bad", r"""
#include <stdio.h>
int main(int c, char**v){ if(c>1){ FILE*p=popen(v[1], "r"); if(p) pclose(p);} return 0; }
""", note="argv passed straight to popen()"),
    Case("popen_none", "CWE-78", "good", r"""
#include <stdio.h>
int main(void){ char line[128]; FILE*f=fopen("/etc/hostname", "r");
  if(f && fgets(line, sizeof line, f)) fputs(line, stdout); if(f) fclose(f); return 0; }
""", note="reads a fixed file, spawns no shell"),

    # ---- CWE-134: uncontrolled format string ----
    Case("printf_tainted", "CWE-134", "bad", r"""
#include <stdio.h>
int main(int c, char**v){ if(c>1) printf(v[1]); return 0; }
""", note="attacker-controlled printf format string"),
    Case("printf_safe", "CWE-134", "good", r"""
#include <stdio.h>
int main(int c, char**v){ if(c>1) fputs(v[1], stdout); return 0; }
""", note="fputs, no format string"),

    # ---- CWE-798: hard-coded credentials ----
    Case("hardcoded_secret", "CWE-798", "bad", r"""
#include <string.h>
#include <unistd.h>
static const char *KEY = "password=S3cr3t_Hunter2_admin_key";
int main(int c, char**v){ if(c>1 && strcmp(v[1], KEY)==0) write(1, "ok", 2); return 0; }
""", note="credential compiled into the binary as a string literal"),
    Case("env_secret", "CWE-798", "good", r"""
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
int main(int c, char**v){ const char*k=getenv("APP_CFG");
  if(c>1 && k && strcmp(v[1], k)==0) write(1, "ok", 2); return 0; }
""", note="credential read from the environment, no literal"),
]


# -------------------------------------------- dynamic (confirmed-stage) crash corpus
# Memory-safety bugs reached over a whole-program vector (stdin) that the fuzzer reproduces
# as a real crash -> a Confirmed finding. Each `bad` faults deterministically on a single
# interesting trigger byte (so the seeded fuzzer finds it in a bounded budget); each `good`
# is the safe variant that never faults (the confirmed-stage FP check, which should be ~0).
_DYN_FLAGS = ["-O0", "-fno-stack-protector", "-no-pie", "-w"]


def _dcase(name, cwe, verdict, source, note=""):
    return Case(name, cwe, verdict, source, list(_DYN_FLAGS), note)


_DYN_CASES: list[Case] = [
    # ---- CWE-476: NULL-pointer dereference ----
    _dcase("nullderef_crash", "CWE-476", "bad", r"""
#include <unistd.h>
int main(void){ char b[128]; int n=read(0,b,sizeof b-1);
  for(int i=0;i<n;i++) if(b[i]=='A'){ volatile int*p=0; *p=1; } return 0; }
""", "derefs NULL when the input contains 'A'"),
    _dcase("nullderef_safe", "CWE-476", "good", r"""
#include <unistd.h>
int main(void){ char b[128]; int n=read(0,b,sizeof b-1); int s=0;
  for(int i=0;i<n;i++) s+=b[i]; return s & 1; }
""", "sums the bytes, never dereferences NULL"),

    # ---- CWE-787: out-of-bounds write ----
    _dcase("oobwrite_crash", "CWE-787", "bad", r"""
#include <unistd.h>
#include <stdlib.h>
int main(void){ char b[128]; int n=read(0,b,sizeof b-1);
  for(int i=0;i<n;i++) if(b[i]=='Z'){ char*p=malloc(16); p[0x4000000]=1; } return 0; }
""", "writes 64 MB past a heap allocation (unmapped) when the input contains 'Z'"),
    _dcase("oobwrite_safe", "CWE-787", "good", r"""
#include <unistd.h>
#include <stdlib.h>
int main(void){ char b[128]; int n=read(0,b,sizeof b-1);
  char*p=malloc(16); if(p && n>0){ p[0]=b[0]; free(p);} return 0; }
""", "bounded heap write, then frees"),

    # ---- CWE-121: stack-based buffer overflow ----
    _dcase("stacksmash_crash", "CWE-121", "bad", r"""
#include <unistd.h>
#include <string.h>
int main(void){ char b[128]; int n=read(0,b,sizeof b-1);
  for(int i=0;i<n;i++) if(b[i]=='*'){ char big[512]; memset(big,0x2a,512);
    char small[16]; memcpy(small,big,512); return small[0]; } return 0; }
""", "overflows a 16-byte stack buffer (return address) when the input contains '*'"),
    _dcase("stacksmash_safe", "CWE-121", "good", r"""
#include <unistd.h>
int main(void){ char small[16]; int n=read(0,small,sizeof small-1);
  if(n>0) small[n<15?n:15]=0; return 0; }
""", "bounded stack read, no overflow"),
]


def bundled() -> list[Case]:
    """The built-in labeled micro-corpus for STATIC (candidate-stage) detection."""
    return list(_CASES)


def bundled_dynamic() -> list[Case]:
    """The built-in crash corpus for DYNAMIC (confirmed-stage) reproduction via fuzzing."""
    return list(_DYN_CASES)


# ---------------------------------------------- LAVA-M style injected-bug corpus
# LAVA-M measures bug-finding RECALL: a program carries many injected bugs, each gated by a
# magic value in the input and self-reporting "Successfully triggered bug N" (then corrupting
# memory) when hit. Recall = unique bugs found / total. LAVA-M is built to defeat coverage-
# blind fuzzers, so magic-gated bugs are hard for a black-box mutator -- the honest result is
# partial recall (easy single-byte gates found, 4-byte magic gates mostly missed).
@dataclass
class LavaProgram:
    name: str
    bug_ids: list                                     # ground-truth injected bug IDs
    source: str = ""                                  # synthetic: compile this C
    binary: str = ""                                  # real drop: path to a prebuilt binary
    argv: list = field(default_factory=lambda: ["@@"])   # "@@" = the input file path
    input_mode: str = "stdin"                         # stdin | file | arg
    seeds: list = field(default_factory=lambda: [b"the quick brown fox jumps\n"])
    dictionary: list = field(default_factory=list)
    cflags: list = field(default_factory=lambda: list(_DYN_FLAGS))


# a faithful miniature: bugs gated by triggers of varying difficulty (single byte -> 4-byte
# magic), each self-reporting like real LAVA before corrupting memory.
_LAVA_TRIGGERS = [
    (11, r'"A",1'), (12, r'"Z",1'), (13, r'"*",1'), (14, r'"~",1'),     # single byte (easy)
    (21, r'"lava",4'), (22, r'"0wn3",4'),                               # 4 printable (medium)
    (31, r'"\xde\xad\xbe\xef",4'), (32, r'"\x00\x13\x37\xff",4'),       # 4-byte magic (hard)
]


def _lava_source():
    checks = "\n".join(
        f'  if(memmem(b,n,{tok})){{ fprintf(stderr,"Successfully triggered bug {bid}\\n"); '
        f'*(volatile int*)0=1; }}'
        for bid, tok in _LAVA_TRIGGERS)
    return ("#define _GNU_SOURCE\n#include <stdio.h>\n#include <string.h>\n#include <unistd.h>\n"
            "int main(void){ char b[512]; int n=read(0,b,sizeof b-1); if(n<0)n=0; b[n]=0;\n"
            + checks + "\n  return 0; }\n")


def bundled_lava() -> list[LavaProgram]:
    """The built-in LAVA-M-style miniature (one stdin program with graded injected bugs)."""
    return [LavaProgram("mini", [bid for bid, _ in _LAVA_TRIGGERS], source=_lava_source())]


# known LAVA-M program input conventions (the buggy binaries take the input as a file arg)
_LAVA_ARGV = {"base64": ["-d", "@@"], "md5sum": ["-c", "@@"], "uniq": ["@@"], "who": ["@@"]}


def load_lava(root: str | Path, *, limit=None) -> list[LavaProgram]:
    """Adapt an unpacked NIST LAVA-M drop into `LavaProgram`s.

    Convention (LAVA-M's own layout): each program lives in a subdir holding a `validated_bugs`
    file (whitespace-separated bug IDs) and its buggy binary (``bin/<name>`` or ``<name>``);
    optional seed inputs under ``seeds/``, ``inputs/`` or ``fuzzed/``. Input goes in as a file
    argument (``@@``), per program's known argv. The suite is large and separately licensed;
    point this at an unpacked drop.
    """
    root = Path(root)
    out: list[LavaProgram] = []
    for vb in sorted(root.rglob("validated_bugs")):
        pdir = vb.parent
        name = pdir.name
        try:
            ids = [int(x) for x in vb.read_text().split()]
        except ValueError:
            continue
        binp = next((p for p in (pdir / "bin" / name, pdir / name,
                                 *pdir.rglob(f"bin/{name}")) if p.exists()), None)
        if not binp or not ids:
            continue
        seeds = []
        for sd in ("seeds", "inputs", "fuzzed"):
            d = pdir / sd
            if d.is_dir():
                seeds = [f.read_bytes()[:4096] for f in sorted(d.glob("*"))[:8] if f.is_file()]
                if seeds:
                    break
        out.append(LavaProgram(name, ids, binary=str(binp),
                               argv=_LAVA_ARGV.get(name, ["@@"]), input_mode="file",
                               seeds=seeds or [b"AAAA\n"]))
        if limit and len(out) >= limit:
            break
    return out


_FNAME = re.compile(r"^(CWE-\d+)__([A-Za-z0-9_.-]+)__(good|bad)\.c$")


# NIST Juliet testcase filename: CWE<NNN>_<Name>__<variant>_<NN>[<letter>].c
_JULIET = re.compile(r"^(CWE\d+)_.*?__.*_(\d+)([a-z]?)\.c$")
_JULIET_SUPPORT = {"io.c", "main.c", "std_thread.c"}          # shared support .c files
# Juliet C support headers/sources live in a `testcasesupport` dir; io.c defines printLine etc.
_JULIET_FLAGS = ["-O0", "-fno-stack-protector", "-no-pie", "-w", "-DINCLUDEMAIN"]


def _juliet_support(root: Path):
    """Locate Juliet's testcasesupport: the include dir (has std_testcase.h) and io.c."""
    hdr = next(iter(sorted(root.rglob("std_testcase.h"))), None)
    io = next(iter(sorted(root.rglob("io.c"))), None)
    inc = hdr.parent if hdr else None
    return inc, io


def load_juliet(root: str | Path, *, cwes=None, limit=None) -> list[Case]:
    """Adapt a NIST Juliet C test-suite drop into scored good/bad `Case`s.

    Each testcase compiles TWICE from the same sources: `-DOMITGOOD` builds a binary whose
    main() exercises only the flaw (the `bad` case), `-DOMITBAD` builds the fixed variant (the
    `good` case). Multi-file testcases (``…_01a.c`` / ``…_01b.c``) are grouped and compiled
    together with Juliet's shared support (io.c + testcasesupport headers). `cwes` filters to a
    set of CWE ids; `limit` caps the number of testcases (drops are huge).

    The real suite is large and separately licensed; point this at an unpacked drop. The
    on-disk conventions it follows are Juliet's, so it also scores a faithful miniature.
    """
    root = Path(root)
    inc, io = _juliet_support(root)
    include_dirs = [str(inc)] if inc else []
    support = [io] if io else []

    groups: dict = {}
    for f in sorted(root.rglob("CWE*.c")):
        if f.name in _JULIET_SUPPORT:
            continue
        m = _JULIET.match(f.name)
        if not m:
            continue
        cwe = "CWE-" + m.group(1)[3:]                     # "CWE121" -> "CWE-121"
        if cwes and cwe not in cwes:
            continue
        base = f.name[:m.start(3)] if m.group(3) else f.name[:-2]   # strip trailing letter/.c
        groups.setdefault((cwe, base), []).append(f)

    cases: list[Case] = []
    for (cwe, base), srcs in sorted(groups.items()):
        if limit and len(cases) >= 2 * limit:
            break
        name = base.rstrip("_")
        common = dict(files=[str(s) for s in srcs] + [str(p) for p in support],
                      include_dirs=include_dirs + [str(srcs[0].parent)])
        cases.append(Case(name, cwe, "bad", cflags=list(_JULIET_FLAGS) + ["-DOMITGOOD"],
                          note="Juliet testcase (bad variant)", **common))
        cases.append(Case(name, cwe, "good", cflags=list(_JULIET_FLAGS) + ["-DOMITBAD"],
                          note="Juliet testcase (good variant)", **common))
    return cases


def load_dir(path: str | Path) -> list[Case]:
    """Load cases from `<CWE-NNN>__<name>__<good|bad>.c` files under `path`.

    Lets a larger external drop (e.g. a Juliet subset, licensing permitting) be scored by the
    same harness with no code change. `.flags` sidecar file (one flag per line) is optional.
    """
    d = Path(path)
    out: list[Case] = []
    for f in sorted(d.glob("*.c")):
        m = _FNAME.match(f.name)
        if not m:
            continue
        cwe, name, verdict = m.groups()
        flags = list(_FLAGS)
        side = f.with_suffix(".flags")
        if side.exists():
            flags = [ln.strip() for ln in side.read_text().splitlines() if ln.strip()]
        out.append(Case(name, cwe, verdict, f.read_text(), flags, note=f"loaded from {f.name}"))
    return out
