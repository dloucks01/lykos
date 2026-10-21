#!/usr/bin/env python3
"""End-to-end pipeline conformance harness.

Builds one tiny synthetic target per bug-class / weaponization capability and runs each through the
REAL autopilot (run_case_autopilot, with a live worker pool and a fixed time budget), asserting the
expected demonstrated effect is actually produced. This catches the class of bug that unit tests
miss: a capability that works in isolation but is never INVOKED by the orchestration, or is reached
only outside a realistic time budget. Run as a script for a table; a thin pytest wrapper marks it slow.

No external targets -- every binary is compiled here from a C string with gcc; skips if gcc is absent.
"""
from __future__ import annotations

import io
import json
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

CORE = Path(__file__).resolve().parent.parent / "core"
import sys

# The path insert has to come BEFORE the first `lykos` import, and it did not: the observe round
# added `from lykos import observe` at the top of this block, above the two lines that make
# `lykos` importable at all, so running the gate the way its own usage line says --
# `python3 tools/pipeline_conformance.py <case>` -- died with ModuleNotFoundError. The insert
# below was dead code and the tool only worked for a caller who had already set PYTHONPATH.
# A gate that cannot be started is a gate nothing runs.
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

from lykos import observe  # noqa: E402,I001



# A plain unbounded-%s stack overflow. Shared by the build-realism and ARCHITECTURE cases so those
# differ ONLY in how they are compiled -- the point of those cases is the toolchain/ISA, not the bug.
_OVERFLOW_SRC = r"""#include <stdio.h>
int main(void){ char b[64]; printf("in: ");
  if(scanf("%s", b) != 1) return 0;
  printf("hi %s\n", b); return 0; }"""


# A MULTI-CALL binary: one image that is several programs, selected by the first positional
# argument, with the bug behind one of them. busybox is the real article -- 345 programs in a
# 1 MB static ELF, and the most common binary in the firmware this tool carves -- and the
# pipeline used to fuzz the IMAGE, which parses nothing and prints its usage. The listing it
# offers (`--list`) and the wrapped block under `Currently defined functions:` are both here
# because the discovery reads whichever it finds. `reboot` is in the list and must never be
# invoked: the campaign is allowed to drive a program only when its shape says it reads one
# input, so a name nobody classified is left alone rather than fired with a mutated argv.
_MULTICALL_SRC = r"""#include <stdio.h>
#include <string.h>
static void usage(void){
  printf("FAKEBOX v1.0 (2026-10-16) multi-call binary.\n\n"
         "Usage: fakebox [function [arguments]...]\n   or: fakebox --list\n\n"
         "Currently defined functions:\n\tunlzma, reboot, cat\n"); }
static void do_unlzma(void){
  char buf[64]; char in[4096]; size_t n = fread(in, 1, sizeof in - 1, stdin);
  in[n] = 0; strcpy(buf, in); printf("decoded %zu\n", strlen(buf)); }
int main(int c, char **v){
  if(c < 2){ usage(); return 1; }
  if(!strcmp(v[1], "--list")){ printf("unlzma\nreboot\ncat\n"); return 0; }
  if(!strcmp(v[1], "unlzma")){ do_unlzma(); return 0; }
  if(!strcmp(v[1], "cat")){ int ch; while((ch = getchar()) != EOF) putchar(ch); return 0; }
  usage(); return 1; }"""


# The shape a real binary presents, and the one every planted L3 case here avoids: a container
# header the input must satisfy, an unvalidated index taken from that header, a READ rather than
# a write, and no `win()` to return to. Those three properties are what put a ceiling on every
# real-corpus finding this project has: the De Bruijn pattern the L2 control experiment uses is
# not a valid container, so it never reaches the defect; a read has no saved return address to
# control; and a single observation cannot tell "the attacker chooses the address" from "a wild
# pointer landed at 0". The magic is a memcmp literal so the comparison-dictionary miner can
# find it -- the fuzzer has to get through the gate on its own, which is the point of the case.
_INDEXED_READ_SRC = r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){
  unsigned char *p = malloc(32);
  unsigned char hdr[16];
  if (fread(hdr, 1, 8, stdin) != 8) return 0;
  if (memcmp(hdr, "LZMA", 4) != 0) { puts("bad magic"); return 1; }
  size_t idx = (size_t)hdr[5] * 0x100000;               /* unvalidated index from the header */
  printf("%02x\n", p[idx]);                             /* OOB read: address = f(input) */
  return 0; }"""


@dataclass
class Case:
    name: str
    src: str
    cflags: list[str]
    want_level: int                      # minimum VERIFIED poc level the pipeline must reach (1/2/3)
    want_cwe: tuple[str, ...]            # or: a non-static poc-backed finding carrying one of these
    note: str = ""
    budget: float = 300.0
    # A PRECISION case: this target has no bug, so the run must demonstrate NOTHING. Static pattern
    # detectors may still fire (that is "detected", not "demonstrated") and are ignored, exactly as
    # they are when scoring a positive case.
    clean: bool = False
    # Every ENTRY here must be demonstrated, not just one of them -- for a binary carrying SEVERAL
    # distinct bugs, which is what "find every crash" actually claims. An entry may be a tuple of
    # acceptable alternatives, because one defect maps to several CWEs depending on which stage
    # files it (a stack overflow lands as CWE-121, -787 or -119).
    want_all_cwe: tuple = ()
    # Make `want_level` BINDING. `_scored` is `lvl_ok or bool(demod)`, which exists so a case can
    # also pass on a demonstrated want_cwe finding from a weaker stage -- and that quietly makes a
    # RAISED want_level unenforceable: a case can demand L2, reach L1, and pass green on its CWE
    # arm **[measured on format_read_leak: PASS at L1 against want_level=2]**. A case whose whole
    # point is the rung it reaches sets this, and then the level is the only way through. (A case
    # with no want_cwe is already strict by construction, since there is nothing else to pass on.)
    strict_level: bool = False
    # A case whose evidence can only ever be STATIC. "Detected is not demonstrated" is the right
    # rule for memory corruption -- a pattern match is not a crash -- and for a credential in
    # .rodata, a predictable PRNG seed or an insecure temp-file name there is nothing to run: the
    # static fact IS the finding. Those cases had no way to be asserted at all (`_verdict`
    # excludes every static detector, so want_cwe can never match and want_level=0 means no level
    # is claimed), which is why they came back FAIL with the detector that found them printed in
    # the reason column. Satisfied when a STATIC detector names one of these, in any state.
    want_static_cwe: tuple = ()
    # A case that records a MEASURED HOLE. Some fixtures carry a real defect that nothing in this
    # pipeline can state today -- a plaintext credential compared with strcmp, a leak that needs
    # an input the oracle's probe list does not contain, two bytes past a stack buffer that land
    # in padding. Such a case has no honest verdict: `clean` claims the opposite (that there is
    # nothing to find), a want_* demand makes it permanently RED, and dropping the case loses both
    # the fixture and the measurement. It reports GAP, is excluded from the pass count and from
    # the exit status, and its note says what is missing -- so the hole is visible every run
    # instead of being remembered. The moment a detector lands, the case gets a real demand.
    known_gap: bool = False
    # Toolchain prefix for a cross-architecture case ("aarch64-linux-gnu-"); the case SKIPS when the
    # cross compiler is absent rather than failing the gate on a machine that cannot build it.
    cross: str = ""
    # What the defect IS, for `tools/coverage_matrix.py`, which otherwise reads the mechanism off
    # `want_cwe`. A case that asserts a LEVEL and nothing else carries no CWE arm on purpose
    # (`_scored` is `lvl_ok or bool(demod)`), and so fell into the matrix's "(level only)" row --
    # the two cases that took heap-overflow from L0 to L3 were invisible on the heap-overflow row
    # they had just moved. Only needed when `want_cwe` is empty.
    mechanism: str = ""
    # FRONT-END check: triage must identify the container as this file_type. With want_level 0 and no
    # want_cwe it is the WHOLE assertion, and the case then needs only ingest+triage -- no autopilot --
    # which is both the honest claim (these formats demonstrate no effect yet) and nearly free to run.
    want_file_type: str = ""
    # How the artifact is produced, when a C compiler cannot: (argv-list, output-name). Runs in the
    # case directory; SKIPS when the first command is unavailable.
    build: tuple = ()
    # Headers (absolute paths) or executables (bare names) this case needs. Missing any of them
    # SKIPS the case rather than failing it: a sink that cannot be built here is untested, which is
    # not the same as a capability that does not work, and conflating the two invents fake gaps.
    requires: tuple = ()
    # Ingest the SOURCE rather than a binary we compiled. The platform builds such a target itself
    # with ASan+UBSan, which is the only way several defects are observable at all -- an off-by-one
    # or an uninitialised read does not fault in a plain build, so a binary-only case can never
    # demonstrate one however good the pipeline is. The mission is "binaries AND source", and
    # nothing covered the source half.
    as_source: bool = False
    # EXECUTE the bundle this case ships: unpack it in a fresh directory and run its own
    # `runner.sh`, requiring it to report the crash through its EXIT STATUS. Nothing in this gate
    # did that, and three defects lived in the gap -- see `_bundle_reproduces`. Set it on a case
    # whose PoC is a CRASH (the 128+signum convention); a JVM bundle exits 1 and an L3
    # shell-spawning reproducer reports its own outcome, so neither is scored this way.
    want_bundle: bool = False


# ---- .NET assemblies for the two dotnet cases ---------------------------------------------
#
# Compiled with the SDK's Roslyn (csc) directly rather than `dotnet build`. MSBuild drags in a
# NuGet restore and spawns worker nodes: it took five seconds idle and TEN MINUTES under load.
# csc alone takes under a second and needs no network. The artifact is leaner too -- no
# runtimeconfig.json and no deps.json -- which is what an INGESTED assembly actually looks
# like, so the case exercises more of the path rather than less.
_CSC_PRELUDE = """set -e
ROOT=$(dirname "$(readlink -f "$(command -v dotnet)")")
CSC=$(ls "$ROOT"/sdk/*/Roslyn/bincore/csc.dll | tail -1)
FW=$(ls -d "$ROOT"/shared/Microsoft.NETCore.App/* | tail -1)
cat > Program.cs <<'XEOF'
%s
XEOF
dotnet "$CSC" -nologo -nostdlib -target:exe -out:%s \
  -r:"$FW/System.Runtime.dll" -r:"$FW/System.Console.dll" \
  -r:"$FW/System.Private.CoreLib.dll" -r:"$FW/System.Runtime.Extensions.dll" Program.cs
"""

# An array indexed by argv's COUNT: no input needed, so this one only has to be identified.
_CS_FMT = """using System;
public static class Program {
    static readonly string[] Names = {"alpha", "beta"};
    public static int Main(string[] a) {
        Console.WriteLine(Names[a.Length]);
        return 0;
    }
}"""

# An array indexed by the input's LENGTH. The index is the length, not a parsed number, for the
# reason spelled out on jvm_oob_index: an int.Parse() guard would test the mutator's luck
# instead of the pipeline. Any line of four characters or more reaches it.
_CS_OOB = """using System;
public static class Program {
    public static int Main(string[] a) {
        string s = Console.In.ReadLine() ?? "";
        int[] t = {1, 2, 3, 4};
        Console.WriteLine("slot {0} = {1}", s.Length, t[s.Length]);
        return 0;
    }
}"""


def _csc_build(source: str, out: str):
    """A (argv, output-glob) build pair that compiles one C# file with the SDK's csc."""
    return (["sh", "-c", _CSC_PRELUDE % (source, out)], out)


#: Keep a FAILING case's store on disk instead of deleting it (`--keep-failed`).
#: `corpus_regression.py` already does this ("case kept for diagnosis"); this gate did not, so a
#: failure left nothing behind to look at -- the only evidence of WHY a case fell short is its
#: event log, and the event log went with the directory. Measured the hard way: a case that
#: reached L2 instead of L3 got diagnosed from a stale directory belonging to a different run,
#: and the conclusion drawn from it was wrong.
KEEP_FAILED = False

#: Run every case to the END of its budget instead of stopping the moment its criterion is met
#: (`--ceiling`). The early stop is right for a gate -- a case that has demonstrated what it
#: asserts is done -- but it makes the level in the PROFILE column the level we STOPPED at, so
#: `coverage_matrix.py --measured` reads a want_level=0 case as L0 no matter what the ladder could
#: actually have reached on it. Nothing in the repo could answer "how far does this mechanism get",
#: which is the only question worth asking before deepening one: the matrix showed bad-index at L2
#: and integer-overflow at L0 purely because that is what their cases demand.
CEILING = False

#: The integer overflow that is WORTH something: the size arithmetic wraps, so the allocation is
#: undersized, and the copy length is recomputed from the saved count -- by a separate option, in
#: 64-bit -- so the fill runs off the chunk with CONTENT WE CHOSE. `int_overflow_alloc` wraps too
#: but memsets 'A's over its own heap with no neighbour worth reaching, which is why that case
#: measures L1 and stops: a magnitude verdict, nothing to aim.
SRC_INT_OVERFLOW_FNPTR = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void win(void){ execl("/bin/sh","sh",(char*)0); }
struct rec { void (*show)(struct rec *); char text[]; };
static void plain(struct rec *r){ printf("%s\n", r->text); }
struct rec *db[16]; long cnt[16];
static long rl(void){ char b[32]; int i=0,c; while(i<31){ c=getchar(); if(c<0||c=='\n')break; b[i++]=c; } b[i]=0; return strtol(b,0,10); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  while(1){ printf("1.add 2.fill 3.show 4.exit\n> ");
    long o=rl();
    if(o==1){ printf("idx: "); long i=rl(); printf("records: "); long n=rl();
              if(i>=0&&i<16&&n>0){ unsigned sz=(unsigned)(n*16);      /* 32-bit multiply WRAPS */
                                   db[i]=malloc(sizeof(void(*)(struct rec*))+sz);
                                   if(db[i]){ db[i]->show=plain; cnt[i]=n; } } }
    else if(o==2){ printf("idx: "); long i=rl(); printf("data: ");
              if(i>=0&&i<16&&db[i]){ size_t n=(size_t)cnt[i]*16, k=0; int c;    /* the REAL size */
                while(k<n){ c=getchar(); if(c<0||c=='\n') break; db[i]->text[k++]=(char)c; } } }
    else if(o==3){ printf("idx: "); long i=rl(); if(i>=0&&i<16&&db[i]) db[i]->show(db[i]); }
    else return 0; } }'''


#: The TRUNCATION twin of SRC_INT_OVERFLOW_FNPTR: the size computation is correct in 64 bits and
#: then stored into 16, so a count four orders of magnitude lower under-allocates. Same weapon,
#: completely different threshold -- which is why the primer values are a family per arithmetic
#: and not one list of "big numbers".
SRC_INT_TRUNC_FNPTR = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void win(void){ execl("/bin/sh","sh",(char*)0); }
struct rec { void (*show)(struct rec *); char text[]; };
static void plain(struct rec *r){ printf("%s\n", r->text); }
struct rec *db[16]; long cnt[16];
static long rl(void){ char b[32]; int i=0,c; while(i<31){ c=getchar(); if(c<0||c=='\n')break; b[i++]=c; } b[i]=0; return strtol(b,0,10); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  while(1){ printf("1.add 2.fill 3.show 4.exit\n> ");
    long o=rl();
    if(o==1){ printf("idx: "); long i=rl(); printf("records: "); long n=rl();
              if(i>=0&&i<16&&n>0){ unsigned short sz=(unsigned short)(n*16);  /* TRUNCATED to 16 */
                                   db[i]=malloc(sizeof(void(*)(struct rec*))+sz);
                                   if(db[i]){ db[i]->show=plain; cnt[i]=n; } } }
    else if(o==2){ printf("idx: "); long i=rl(); printf("data: ");
              if(i>=0&&i<16&&db[i]){ size_t n=(size_t)cnt[i]*16, k=0; int c;   /* the real size */
                while(k<n){ c=getchar(); if(c<0||c=='\n') break; db[i]->text[k++]=(char)c; } } }
    else if(o==3){ printf("idx: "); long i=rl(); if(i>=0&&i<16&&db[i]) db[i]->show(db[i]); }
    else return 0; } }'''


#: The menu notebook whose edit overflows an inline buffer into the object's OWN callback.
#: Kept beside the case list rather than inline, like the other multi-line sources here.
SRC_HEAP_FNPTR = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void win(void){ execl("/bin/sh","sh",(char*)0); }
struct note { char text[32]; void (*show)(struct note *); };
static void plain(struct note *n){ printf("%s\n", n->text); }
struct note *db[16];
static long rl(void){ char b[32]; int i=0,c; while(i<31){ c=getchar(); if(c<0||c=='\n')break; b[i++]=c; } b[i]=0; return strtol(b,0,10); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  while(1){ printf("1.add 2.edit 3.show 4.free 5.exit\n> ");
    long o=rl();
    if(o==1){ printf("idx: "); long i=rl();
              if(i>=0&&i<16){ db[i]=malloc(sizeof(struct note));
                              if(db[i]){ db[i]->show=plain; strcpy(db[i]->text,"new"); } } }
    else if(o==2){ printf("idx: "); long i=rl(); printf("len: "); long n=rl(); printf("data: ");
              if(i>=0&&i<16&&db[i]&&n>0) read(0, db[i]->text, (size_t)n); }  /* len unbounded */
    else if(o==3){ printf("idx: "); long i=rl(); if(i>=0&&i<16&&db[i]) db[i]->show(db[i]); }
    else if(o==4){ printf("idx: "); long i=rl(); if(i>=0&&i<16){ free(db[i]); db[i]=0; } }
    else return 0; } }'''


#: The same hijack with NO win function: the callback takes the object, and `system` is
#: imported for an ordinary reason (`4.date`).
SRC_FNPTR_SYSTEM = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct cmd { char arg[32]; void (*run)(struct cmd *); };
static void echo_arg(struct cmd *c){ printf("%s\n", c->arg); }
struct cmd *db[8];
static long rl(void){ char b[32]; int i=0,c; while(i<31){ c=getchar(); if(c<0||c=='\n')break; b[i++]=c; } b[i]=0; return strtol(b,0,10); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  while(1){ printf("1.new 2.set 3.run 4.date 5.exit\n> ");
    long o=rl();
    if(o==1){ printf("idx: "); long i=rl();
              if(i>=0&&i<8){ db[i]=malloc(sizeof(struct cmd));
                             if(db[i]){ db[i]->run=echo_arg; strcpy(db[i]->arg,"hi"); } } }
    else if(o==2){ printf("idx: "); long i=rl(); printf("len: "); long n=rl(); printf("arg: ");
              if(i>=0&&i<8&&db[i]&&n>0) read(0, db[i]->arg, (size_t)n); }   /* len unbounded */
    else if(o==3){ printf("idx: "); long i=rl(); if(i>=0&&i<8&&db[i]) db[i]->run(db[i]); }
    else if(o==4){ system("date"); }      /* the legitimate `system` import -- no win() anywhere */
    else return 0; } }'''


#: The PIE form: the object's own dump leaks the callback, which is a code pointer, so the
#: hijack address can be RELOCATED. Every address in this one is runtime-dependent.
SRC_FNPTR_PIE = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct note { char text[32]; void (*show)(struct note *); };
static void plain(struct note *n){ printf("%s\n", n->text); }
void win(void){ execl("/bin/sh","sh",(char*)0); }
struct note *db[8];
static long rl(void){ char b[32]; int i=0,c;
  while(i<31){ c=getchar(); if(c<0||c=='\n')break; b[i++]=c; }
  b[i]=0; return strtol(b,0,10); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  while(1){ printf("1.new 2.edit 3.show 4.dump 5.exit\n> ");
    long o=rl();
    if(o==1){ printf("idx: "); long i=rl();
              if(i>=0&&i<8){ db[i]=malloc(sizeof(struct note));
                             if(db[i]){ db[i]->show=plain; strcpy(db[i]->text,"new"); } } }
    else if(o==2){ printf("idx: "); long i=rl(); printf("len: "); long n=rl(); printf("data: ");
              if(i>=0&&i<8&&db[i]&&n>0) read(0, db[i]->text, (size_t)n); }   /* len unbounded */
    else if(o==3){ printf("idx: "); long i=rl(); if(i>=0&&i<8&&db[i]) db[i]->show(db[i]); }
    else if(o==4){ printf("idx: "); long i=rl();
              if(i>=0&&i<8&&db[i]) fwrite(db[i],1,sizeof(struct note),stdout); }  /* leaks show */
    else return 0; } }'''


_CASES: list[Case] = [
    Case("no_pie_ret2win",
         r'''#include <stdio.h>
#include <unistd.h>
void win(void){ execl("/bin/sh","sh",(char*)0); }
void vuln(void){ char b[32]; read(0,b,200); }
int main(void){ setvbuf(stdout,0,2,0); vuln(); return 0; }''',
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-121", "CWE-787"),
         note="classic overflow + win -> ret2win L3"),

    Case("pie_canary_ret2win",
         r'''#include <stdio.h>
#include <unistd.h>
void win(void){ execl("/bin/sh","sh",(char*)0); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  void (*fp)()=win; (void)fp;
  int age; puts("age?"); if(scanf("%d",&age)!=1) return 0; getchar();
  char b[64]; puts("bio?"); read(0,b,64); write(1,b,256);
  puts("cmd?"); read(0,b,256); return 0; }''',
         ["-pie", "-fPIE", "-fstack-protector-all", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-121", "CWE-200", "CWE-787"),  # raised L2->L3: --ceiling measured a
         # verified L3 PoC (build_exploit/CWE-121) on this PIE+canary+full-RELRO target, so the gate now
         # enforces the achievable rung on a fully-hardened shape rather than passing at a stale L2.
         note="gated PIE+canary over-read leak -> ret2win / info-leak"),

    Case("format_fullrelro_ret2win",
         r'''#include <stdio.h>
#include <unistd.h>
void win(void){ execl("/bin/sh","sh",(char*)0); }
void vuln(void){ char b[256];
  for(int i=0;i<2;i++){ ssize_t n=read(0,b,255); if(n<=0) return; b[n]=0; printf(b); fflush(stdout); } }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0); vuln(); return 0; }''',
         ["-pie", "-fPIE", "-Wl,-z,relro,-z,now", "-fstack-protector-all", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-134", "CWE-121"),
         note="full-RELRO format %n -> saved return -> shell"),

    Case("pie_canary_nowin_leak",
         r'''#include <stdio.h>
#include <unistd.h>
#include <string.h>
struct rec { char a[16]; char b[16]; void *anchor; };
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  struct rec s; memset(&s,0,sizeof s); s.anchor=(void*)&main;
  char c;
  puts("a?"); for(int i=0;i<=15;i++){ if(read(0,&c,1)<1) break; if(c=='\n') break; s.a[i]=c; }
  puts("b?"); for(int i=0;i<=15;i++){ if(read(0,&c,1)<1) break; if(c=='\n') break; s.b[i]=c; }
  printf("summary: %s | %s\n", s.a, s.b); return 0; }''',
         ["-pie", "-fPIE", "-fstack-protector-all", "-O0", "-w"],
         want_level=2, want_cwe=("CWE-200",),
         note="char-loop %s-bridge leak -> demonstrated ASLR info-leak (L2)"),

    Case("heap_uaf_read",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
char *n[16];
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  while(1){ printf("1.add 2.view 3.free 4.exit\n> ");
    int o; if(scanf("%d",&o)!=1) return 0; getchar();
    if(o==1){ int i; printf("idx: "); if(scanf("%d",&i)!=1)return 0; getchar();
              printf("sz: "); int sz; if(scanf("%d",&sz)!=1)return 0; getchar();
              printf("data: "); char d[1024]; int m=0,c; while(m<1023){ if(read(0,&c,1)<1)break; if(c=='\n')break; d[m++]=c; }
              if(i>=0&&i<16){ n[i]=malloc(sz>0?sz:0x80); if(n[i]) memcpy(n[i],d,(size_t)(m<sz?m:sz)); } }
    else if(o==2){ int i; printf("idx: "); if(scanf("%d",&i)!=1)return 0; getchar();
                   if(i>=0&&i<16&&n[i]) fwrite(n[i],1,0x20,stdout), putchar('\n'); }
    else if(o==3){ int i; printf("idx: "); if(scanf("%d",&i)!=1)return 0; getchar(); if(i>=0&&i<16) free(n[i]); }
    else return 0; } }''',
         ["-fPIE", "-pie", "-O0", "-w"],
         want_level=2, want_cwe=("CWE-416","CWE-200"),
         note="notebook UAF read -> heap/libc disclosure (L2)"),

    Case("heap_uninit_reuse_yn",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
char *n[16]; long sz_[16]; int cnt=0;
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  char nm[48]; printf("what is your name?\n> "); if(read(0,nm,47)<=0) return 0;
  while(1){ printf("1.create 2.view 3.delete 4.exit\n> ");
    int o; if(scanf("%d",&o)!=1) return 0; getchar();
    if(o==1){ char yn[8]; printf("save this note? (y/n): "); if(scanf("%7s",yn)!=1)return 0; getchar();
              if(yn[0]!='y'&&yn[0]!='Y') continue;
              long sz; printf("size: "); if(scanf("%ld",&sz)!=1)return 0; getchar();
              printf("data: "); char d[512]; int m=0,c; while(m<511){ if(read(0,&c,1)<1)break; if(c=='\n')break; d[m++]=c; }
              if(cnt<16){ n[cnt]=malloc(sz>0?sz:0x80); sz_[cnt]=sz>0?sz:0x80;
                          if(n[cnt]) memcpy(n[cnt],d,(size_t)(m<sz?m:sz)); printf("placed at %d\n",cnt); cnt++; } }
    else if(o==2){ int i; printf("idx: "); if(scanf("%d",&i)!=1)return 0; getchar();
                   if(i>=0&&i<16&&n[i]){ long k=sz_[i]<0x40?sz_[i]:0x40; fwrite(n[i],1,k,stdout); putchar('\n'); } }
    else if(o==3){ int i; printf("idx: "); if(scanf("%d",&i)!=1)return 0; getchar(); if(i>=0&&i<16) free(n[i]); }
    else return 0; } }''',
         ["-fPIE", "-pie", "-O0", "-w"],
         want_level=2, want_cwe=("CWE-416","CWE-200"),
         note="name-gate + y/n + char-loop + uninit-reuse -> libc leak (L2)"),

    # HEAP OVERFLOW -> an adjacent CODE POINTER -> shell. The class with the most real-world
    # CVEs behind it (libtiff, libsndfile and openjpeg all carry heap-overflow CVEs) demanded
    # only L0 in the coverage matrix, while the lifetime cases beside it reach L3: every heap
    # case here was a double-free, a UAF or an uninitialised reuse. The CHAIN for it already
    # exists -- `heap_trace` reports CWE-122 and `chain_primitive` overwrites an adjacent code
    # pointer with a win address and confirms control reached it -- and nothing measured it.
    #
    # The shape is the common one and not a contrived one: a struct with an inline buffer
    # followed by a callback (`struct note { char text[32]; void (*show)(...); }`), an edit that
    # takes its own length, and a separate option that INVOKES the callback. Two properties make
    # it a real test of the chain rather than of a crash finder: the corrupting write and the
    # detonation are DIFFERENT menu operations, so nothing faults until the right pair is driven
    # in the right order; and the pointer is overwritten in place, so the fault PC is whatever
    # bytes we wrote -- control, not a wild read.
    Case("heap_fnptr_hijack",
         SRC_HEAP_FNPTR,
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         # want_cwe is EMPTY on purpose, for the reason spelled out on `oob_leak_pie_ret2win`:
         # `_scored` is `lvl_ok or bool(demod)`, so a CWE arm passes the case the moment any
         # matching poc-backed finding appears. Measured: with ("CWE-122","CWE-787","CWE-119")
         # this case passed at **L1** -- the crash was found and verified and the hijack never
         # ran. The LEVEL is the whole claim here; the crash itself is gated by other cases.
         mechanism='heap-overflow',
         want_level=3, want_cwe=(), budget=420.0,
         note="menu notebook, heap overflow past an inline buffer into the object's own callback "
              "-> call it -> shell (L3). no-PIE so the win address is static: the PIE form of "
              "this needs a leak, which is a different case. `free` NULLs its slot on purpose: "
              "the first version did not, and the accidental use-after-free was the EASIER bug "
              "-- every crash the campaign found was `add(i); free(i); show(i)`, three tokens "
              "long, and the overflow this case exists for was never driven **[measured]**. The "
              "lifetime classes are gated by the heap_fsop cases beside it"),

    # ...and the same hijack with NO WIN FUNCTION, which is the case every real target is.
    # `find_win` is deliberately strict (a suggestive name, or a local function that calls a
    # shell-spawner) and that strictness is why L3 was unreachable on real binaries: ncompress has
    # a reachable overflow and confirmed IP control and no function called `win`. Here `system` is
    # imported for an ordinary reason -- a `4.date` menu option -- and `main` is excluded from the
    # win search by name, so nothing in the tree is a win.
    #
    # An indirect call gives ONE jump and no return address, so every stack recipe (pop-rdi + system,
    # SROP, ret2csu) is unavailable. What IS available is the convention: `obj->run(obj)` hands the
    # callee the object, whose first bytes are ours -- so "/bin/sh" at offset 0 and `system@plt` at
    # the control offset is the entire exploit. Filed only on a spawned shell, because arrival at
    # `system` proves the overwrite while the ARGUMENT is what the shell proves.
    Case("heap_fnptr_system",
         SRC_FNPTR_SYSTEM,
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         mechanism='heap-overflow',
         want_level=3, want_cwe=(), budget=420.0,
         note="menu notebook, heap overflow into the object's own callback with NO win function "
              "-> system(\"/bin/sh\") through the hijacked object pointer -> shell (L3)"),

    # ...and the PIE form, which is what every modern binary is. The two cases above are no-PIE,
    # so `win`/`system@plt` are link-time constants; here NOTHING is known until the process runs.
    # The object's own `4.dump` prints it raw, and the first thing in it past the buffer is the
    # callback -- a CODE pointer, so a disclosure of 8 bytes is a defeat of ASLR:
    # `base = leaked - offset(plain)`, and the hijack address follows.
    #
    # Measured by hand (2026-10-17): dump leaks `plain()` at 0x55da45e9b1b9, the base resolves,
    # `win` relocates to base+0x11d4, and the same overflow-then-call sequence spawns a shell. What
    # the autopilot has to do is exactly that: provoke the leak, resolve it against the symbol
    # layout (`leak.disclosed_bases` -- the low 12 bits are page-invariant), and rebuild the
    # payload at the relocated address.
    Case("heap_fnptr_pie_leak",
         SRC_FNPTR_PIE,
         ["-fPIE", "-pie", "-fno-stack-protector", "-O0", "-w"],
         mechanism="heap-overflow",
         want_level=3, want_cwe=(), budget=600.0,
         note="PIE menu notebook: dump leaks the object's callback (a code pointer) -> resolve the "
              "PIE base -> overflow the buffer into the callback with the RELOCATED win address "
              "-> call it -> shell (L3)"),

    Case("heap_fsop_shell",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
char *ptr[32]; long sz[32];
static long rl(void){ char b[32]; int i=0,c; while(i<31){ c=getchar(); if(c<0||c=='\n')break; b[i++]=c; } b[i]=0; return strtol(b,0,10); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  while(1){ printf("1.add 2.free 3.view 4.edit 5.exit\n> ");
    long o=rl();
    if(o==1){ printf("idx: "); long i=rl(); printf("size: "); long s=rl();
              if(i>=0&&i<32&&s>0&&s<0x1000){ ptr[i]=malloc(s); sz[i]=s; printf("data: "); read(0,ptr[i],s); } }
    else if(o==2){ printf("idx: "); long i=rl(); if(i>=0&&i<32&&ptr[i]) free(ptr[i]); }          /* no NULL -> UAF */
    else if(o==3){ printf("idx: "); long i=rl(); if(i>=0&&i<32&&ptr[i]) write(1,ptr[i],sz[i]); }  /* UAF read */
    else if(o==4){ printf("idx: "); long i=rl(); printf("data: "); if(i>=0&&i<32&&ptr[i]) read(0,ptr[i],sz[i]); } /* UAF write */
    else return 0; } }''',
         ["-fPIE", "-pie", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-416",), budget=420.0,
         note="menu notebook, UAF edit -> tcache poison _IO_2_1_stdout_ + House of Apple 2 -> shell (L3)"),

    Case("heap_fsop_noncanon",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
char *ptr[32]; long sz[32];
static long rl(void){ char b[32]; int i=0,c; while(i<31){ c=getchar(); if(c<0||c=='\n')break; b[i++]=c; } b[i]=0; return strtol(b,0,10); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  while(1){ printf("[1] show [2] alloc [3] wipe [4] change [0] quit\n> ");
    long o=rl();                                        /* non-canonical: add=2 free=3 view=1 edit=4 */
    if(o==2){ printf("idx: "); long i=rl(); printf("size: "); long s=rl();
              if(i>=0&&i<32&&s>0&&s<0x1000){ ptr[i]=malloc(s); sz[i]=s; printf("data: "); read(0,ptr[i],s); } }
    else if(o==3){ printf("idx: "); long i=rl(); if(i>=0&&i<32&&ptr[i]) free(ptr[i]); }
    else if(o==1){ printf("idx: "); long i=rl(); if(i>=0&&i<32&&ptr[i]) write(1,ptr[i],sz[i]); }
    else if(o==4){ printf("idx: "); long i=rl(); printf("data: "); if(i>=0&&i<32&&ptr[i]) read(0,ptr[i],sz[i]); }
    else if(o==0){ return 0; } } }''',
         ["-fPIE", "-pie", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-416",), budget=420.0,
         note="NON-canonical menu -> crawled op-model drives the FSOP chain (defaults would mis-drive) -> shell (L3)"),

    Case("heap_fsop_fixedwidth",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
char *ptr[32]; long sz[32];
/* FIXED-WIDTH protocol: every scalar is read(fd,buf,8) (no fgets/scanf), so a newline-delimited
   feed under-reads and desyncs every later field; the data read fills the chunk exactly. */
static long rn(void){ char b[9]; memset(b,0,9); if(read(0,b,8)<=0) exit(0); return strtol(b,0,10); }
static void readn(char *p, long n){ long g=0; while(g<n){ long r=read(0,p+g,n-g); if(r<=0) exit(0); g+=r; } }
int main(void){ setvbuf(stdout,0,2,0);
  while(1){ printf("1.add 2.free 3.view 4.edit 5.exit\n> ");
    long o=rn();
    if(o==1){ printf("idx: "); long i=rn(); printf("size: "); long s=rn();
              if(i>=0&&i<32&&s>0&&s<0x1000){ ptr[i]=malloc(s); sz[i]=s; printf("data: "); readn(ptr[i],s); } }
    else if(o==2){ printf("idx: "); long i=rn(); if(i>=0&&i<32&&ptr[i]) free(ptr[i]); }
    else if(o==3){ printf("idx: "); long i=rn(); if(i>=0&&i<32&&ptr[i]) write(1,ptr[i],sz[i]); }
    else if(o==4){ printf("idx: "); long i=rn(); if(i>=0&&i<32&&ptr[i]){ printf("data: "); readn(ptr[i],sz[i]); } }
    else return 0; } }''',
         ["-fPIE", "-pie", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-416",), budget=420.0,
         note="FIXED-WIDTH read(fd,buf,8) menu -> width-encoded FSOP chain -> shell (L3)"),

    Case("heap_fsop_capped",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
char *ptr[32]; long sz[32];
static long rl(void){ char b[32]; int i=0,c; while(i<31){ c=getchar(); if(c<0||c=='\n')break; b[i++]=c; } b[i]=0; return strtol(b,0,10); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  while(1){ printf("1.add 2.free 3.view 4.edit 5.exit\n> ");
    long o=rl();
    if(o==1){ printf("idx: "); long i=rl(); printf("size: "); long s=rl();
              /* SIZE CAP: refuses an above-tcache chunk, so one free never reaches a bin head and
                 the libc leak needs a tcache-FILL spill instead. */
              if(i>=0&&i<32&&s>0&&s<=0x400){ ptr[i]=malloc(s); sz[i]=s; printf("data: "); read(0,ptr[i],s); }
              else printf("bad size\n"); }
    else if(o==2){ printf("idx: "); long i=rl(); if(i>=0&&i<32&&ptr[i]) free(ptr[i]); }
    else if(o==3){ printf("idx: "); long i=rl(); if(i>=0&&i<32&&ptr[i]) write(1,ptr[i],sz[i]); }
    else if(o==4){ printf("idx: "); long i=rl(); printf("data: "); if(i>=0&&i<32&&ptr[i]) read(0,ptr[i],sz[i]); }
    else return 0; } }''',
         ["-fPIE", "-pie", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-416",), budget=420.0,
         note="SIZE-CAPPED notebook -> tcache-fill spill for the libc leak -> FSOP shell (L3)"),

    Case("heap_fsop_editlen",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
char *ptr[32]; long sz[32];
static long rl(void){ char b[32]; int i=0,c; while(i<31){ c=getchar(); if(c<0||c=='\n')break; b[i++]=c; } b[i]=0; return strtol(b,0,10); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  while(1){ printf("1.add 2.free 3.view 4.edit 5.exit\n> ");
    long o=rl();
    if(o==1){ printf("idx: "); long i=rl(); printf("size: "); long s=rl();
              if(i>=0&&i<32&&s>0&&s<0x1000){ ptr[i]=malloc(s); sz[i]=s; printf("data: "); read(0,ptr[i],s); } }
    else if(o==2){ printf("idx: "); long i=rl(); if(i>=0&&i<32&&ptr[i]) free(ptr[i]); }
    else if(o==3){ printf("idx: "); long i=rl(); if(i>=0&&i<32&&ptr[i]) write(1,ptr[i],sz[i]); }
    /* edit RE-ASKS the write length, and reads EXACTLY that many bytes -- a plain idx+data feed
       desyncs it (the payload is eaten as the length). */
    else if(o==4){ printf("idx: "); long i=rl(); printf("len: "); long n=rl();
              if(i>=0&&i<32&&ptr[i]&&n>0){ if(n>sz[i]) n=sz[i]; printf("data: "); read(0,ptr[i],n); } }
    else return 0; } }''',
         ["-fPIE", "-pie", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-416",), budget=420.0,
         note="edit RE-ASKS the write length -> length-declaring FSOP poison write -> shell (L3)"),

    Case("heap_fsop_slots17",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* SMALL slot table (17) AND a size cap: the libc leak needs a tcache-fill spill, which needs
   capacity+1 distinct chunks -- 17 on this glibc -- so the fill must size itself to the table
   exactly. Allocating past it is refused, and the refusal desyncs the menu and exits the target. */
char *ptr[17]; long sz[17];
static long rl(void){ char b[32]; int i=0,c; while(i<31){ c=getchar(); if(c<0||c=='\n')break; b[i++]=c; } b[i]=0; return strtol(b,0,10); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  while(1){ printf("1.add 2.free 3.view 4.edit 5.exit\n> ");
    long o=rl();
    if(o==1){ printf("idx: "); long i=rl(); printf("size: "); long s=rl();
              if(i>=0&&i<17&&s>0&&s<=0x400){ ptr[i]=malloc(s); sz[i]=s; printf("data: "); read(0,ptr[i],s); }
              else printf("bad size\n"); }
    else if(o==2){ printf("idx: "); long i=rl(); if(i>=0&&i<17&&ptr[i]) free(ptr[i]); }
    else if(o==3){ printf("idx: "); long i=rl(); if(i>=0&&i<17&&ptr[i]) write(1,ptr[i],sz[i]); }
    else if(o==4){ printf("idx: "); long i=rl(); printf("data: "); if(i>=0&&i<17&&ptr[i]) read(0,ptr[i],sz[i]); }
    else return 0; } }''',
         ["-fPIE", "-pie", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-416",), budget=480.0,
         note="17-slot table + size cap -> fill sized to the table -> FSOP shell (L3)"),

    Case("heap_fsop_slots8",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* TINY slot table (8) AND a size cap: too few slots to hold capacity+1 distinct chunks, so the
   libc leak can only come from re-entering ONE chunk into the tcache bin (clearing its key
   through the edit) until the bin overflows. */
char *ptr[8]; long sz[8];
static long rl(void){ char b[32]; int i=0,c; while(i<31){ c=getchar(); if(c<0||c=='\n')break; b[i++]=c; } b[i]=0; return strtol(b,0,10); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  while(1){ printf("1.add 2.free 3.view 4.edit 5.exit\n> ");
    long o=rl();
    if(o==1){ printf("idx: "); long i=rl(); printf("size: "); long s=rl();
              if(i>=0&&i<8&&s>0&&s<=0x400){ ptr[i]=malloc(s); sz[i]=s; printf("data: "); read(0,ptr[i],s); }
              else printf("bad size\n"); }
    else if(o==2){ printf("idx: "); long i=rl(); if(i>=0&&i<8&&ptr[i]) free(ptr[i]); }
    else if(o==3){ printf("idx: "); long i=rl(); if(i>=0&&i<8&&ptr[i]) write(1,ptr[i],sz[i]); }
    else if(o==4){ printf("idx: "); long i=rl(); printf("data: "); if(i>=0&&i<8&&ptr[i]) read(0,ptr[i],sz[i]); }
    else return 0; } }''',
         ["-fPIE", "-pie", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-416",), budget=480.0,
         note="8-slot table + size cap -> tcache-dup (re-enter one chunk) -> FSOP shell (L3)"),

    Case("heap_fsop_tightcap",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* TIGHT size cap (0x100): too small for the one-piece fake _IO_FILE, which needs 0x2A8 bytes. The
   fake _IO_wide_data and its jump table have to be parked in a chunk of the exploit's own, reached
   by a second tcache poison, so no single write exceeds the cap. */
char *ptr[16]; long sz[16];
static long rl(void){ char b[32]; int i=0,c; while(i<31){ c=getchar(); if(c<0||c=='\n')break; b[i++]=c; } b[i]=0; return strtol(b,0,10); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  while(1){ printf("1.add 2.free 3.view 4.edit 5.exit\n> ");
    long o=rl();
    if(o==1){ printf("idx: "); long i=rl(); printf("size: "); long s=rl();
              if(i>=0&&i<16&&s>0&&s<=0x100){ ptr[i]=malloc(s); sz[i]=s; printf("data: "); read(0,ptr[i],s); }
              else printf("bad size\n"); }
    else if(o==2){ printf("idx: "); long i=rl(); if(i>=0&&i<16&&ptr[i]) free(ptr[i]); }
    else if(o==3){ printf("idx: "); long i=rl(); if(i>=0&&i<16&&ptr[i]) write(1,ptr[i],sz[i]); }
    else if(o==4){ printf("idx: "); long i=rl(); printf("data: "); if(i>=0&&i<16&&ptr[i]) read(0,ptr[i],sz[i]); }
    else return 0; } }''',
         ["-fPIE", "-pie", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-416",), budget=600.0,
         note="0x100 size cap -> split fake FILE (wide data in our own chunk) -> FSOP shell (L3)"),

    # ---- PRECISION. Every other case asks "is the effect found?"; this one asks "does the tool stay
    # quiet when there is nothing to find?" Without it a precision regression is invisible.
    Case("clean_no_bug",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  char name[64], out[160];
  printf("name: "); if(!fgets(name,sizeof name,stdin)) return 0;
  name[strcspn(name,"\n")]=0;
  printf("count: "); long n; if(scanf("%ld",&n)!=1) return 0;
  if(n<0||n>16){ puts("out of range"); return 1; }
  snprintf(out,sizeof out,"hello %.32s x%ld",name,n);   /* bounded, no user-controlled format */
  puts(out);
  char *p=calloc((size_t)n+1,8); if(!p) return 1;
  memset(p,'A',(size_t)n*8); p[(size_t)n*8]=0; puts(p);
  free(p); p=NULL;                                      /* nulled: no use-after-free */
  return 0; }''',
         ["-fPIE", "-pie", "-fstack-protector-all", "-Wl,-z,relro,-z,now", "-O1", "-w"],
         want_level=0, want_cwe=(), clean=True, budget=240.0,
         note="PRECISION: bounded reads, no user format, no heap misuse -> nothing may be demonstrated"),

    # ---- INPUT CHANNELS. The pipeline has to find the bug through the channel the program actually
    # reads; every case above is stdin, so argv/file/env regressions cannot be seen.
    Case("argv_overflow",
         r'''#include <stdio.h>
#include <string.h>
int main(int argc, char **argv){ char b[64];
  if(argc<2){ puts("usage: prog ARG"); return 1; }
  strcpy(b, argv[1]);                                   /* unbounded copy from argv */
  printf("got %s\n", b); return 0; }''',
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=300.0,
         want_bundle=True,
         note="CHANNEL argv: the overflow is only reachable through argv[1]"),

    Case("file_overflow",
         r'''#include <stdio.h>
#include <string.h>
int main(int argc, char **argv){ char b[64];
  if(argc<2){ puts("usage: prog FILE"); return 1; }
  FILE *f = fopen(argv[1], "rb"); if(!f) return 1;
  size_t n = fread(b, 1, 512, f);                       /* 512 into a 64-byte buffer */
  fclose(f); printf("read %zu\n", n); puts(b); return 0; }''',
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=300.0,
         want_bundle=True,
         note="CHANNEL file: the overflow is only reachable by the contents of a named file"),

    Case("env_overflow",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ char b[64];
  char *e = getenv("APP_CONFIG"); if(!e){ puts("APP_CONFIG unset"); return 1; }
  strcpy(b, e);                                         /* unbounded copy from the environment */
  printf("cfg %s\n", b); return 0; }''',
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=300.0,
         want_bundle=True,
         note="CHANNEL env: the overflow is only reachable by setting APP_CONFIG. Was a known gap "
              "while capture.MODES was (stdin, file, arg) with no env delivery, so the prove loop "
              "could not replay an env-delivered input and no verified PoC was ever built; "
              "sandbox.run takes env_overrides now and this reaches a verified L1."),

    Case("socket_overflow",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
/* The receive buffer is GLOBAL and the handler RETURNS: the overflow therefore runs over the
   handler's saved return address (a fault on return) instead of over its own source buffer inside
   a main() that loops forever and never returns -- which would smash the frame observably but
   never actually fault. */
static char rxbuf[4096];
static void handle(int c){
  char small[64];
  ssize_t n = recv(c, rxbuf, sizeof rxbuf, 0);
  if(n > 0){ rxbuf[n < 4095 ? n : 4095] = 0; strcpy(small, rxbuf); printf("got %s\n", small); }
}
int main(void){ setvbuf(stdout,0,2,0);
  int s = socket(AF_INET, SOCK_STREAM, 0); if(s<0) return 1;
  int one=1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=0;  /* ephemeral */
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0) return 1;
  if(listen(s,4)<0) return 1;
  /* An EPHEMERAL port, not a fixed one: the fuzzer respawns this server hundreds of times, so one
     leaked instance holding a fixed port would make every later bind fail and the campaign report
     "no-listen". netfuzz discovers the port from /proc, so it need not be known in advance. */
  puts("listening");
  for(;;){ int c = accept(s,0,0); if(c<0) continue; handle(c); close(c); } }''',
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=900.0,
         want_bundle=True,
         note="CHANNEL socket: a TCP server that strcpy's its global recv buffer into a 64-byte "
              "stack buffer in a handler that RETURNS -- reachable only over a connection, and "
              "replayable only by spawning the server and sending (no exec-time carrier exists)"),

    #: The one shape where a stack canary is a WEAKNESS rather than a defence. No gate case had
    #: ever driven the forking-server BROP path at all, canary or not.
    Case("forking_server_canary_brute",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
void win(void){ system("/bin/sh"); }
/* The handler RETURNS and then answers, which is what gives a crash-vs-survived oracle: a wrong
   canary byte aborts in __stack_chk_fail and the reply never comes. */
static int vuln(int fd){ char b[64]; read(fd, b, 512); return 0; }
static void handle(int fd){ dup2(fd,0); dup2(fd,1); dup2(fd,2); vuln(fd); write(fd,"OK",2); }
int main(void){ setvbuf(stdout,0,2,0);
  signal(SIGCHLD, SIG_IGN);
  int s = socket(AF_INET, SOCK_STREAM, 0); if(s<0) return 1;
  int one=1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=0;
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0) return 1;
  if(listen(s,16)<0) return 1;
  puts("listening");
  /* fork() per connection: ASLR and the canary both roll ONCE, in the parent. */
  for(;;){ int c=accept(s,0,0); if(c<0) continue;
           if(fork()==0){ close(s); handle(c); _exit(0); } close(c); } }""",
         ["-fPIE", "-pie", "-fstack-protector-all", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=900.0,
         mechanism="stack-overflow",
         strict_level=True,
         note="BUG CLASS stack overflow over a socket, on the one target shape where a STACK "
              "CANARY makes exploitation EASIER. The dispatch used to say the opposite in a "
              "comment -- \"PIE + CANARY: the leak-free partial-overwrite / BROP paths below "
              "cannot work, the canary must be leaked and written back\" -- and for a one-shot "
              "process that is true. A server that fork()s per connection is the exception: the "
              "canary is generated once, at the PARENT's TLS setup, and every child inherits it, "
              "exactly as every child inherits the parent's ASLR layout. So the same "
              "crash-vs-survived oracle that BROP uses to read a saved return address reads the "
              "CANARY a byte at a time -- a wrong byte aborts in __stack_chk_fail and the "
              "handler's post-return reply never arrives -- at 7x256 connections worst case, "
              "glibc's own NUL low byte giving one of the eight away. Measured on this fixture: "
              "canary recovered in 1.4s, then a 1-byte partial overwrite reaches win() in 1.2s. "
              "Three things had to be measured rather than assumed. (1) The saved return "
              "address's slot cannot be found by probing for \"the first word past the canary "
              "whose corruption crashes\": that finds the saved RBP, because a wild rbp makes "
              "`leave` set rsp from garbage and the child dies too -- it was measured at 80 when "
              "the real answer was 88, and the partial overwrite silently missed. It is found by "
              "READING past the canary and telling the two apart by content (a stack pointer vs a "
              "main-image code pointer), which the byte-at-a-time read gives for free because it "
              "writes the canary back as it accumulates. (2) The survival oracle cannot key on a "
              "literal `OK`: the token is calibrated from the server's own reply to a harmless "
              "probe, or the path declines for want of an oracle. (3) The reproducer cannot bake "
              "the canary in -- a re-spawned server has a different one -- so it re-runs the "
              "read, which is the exploit anyway. The negative control that matters here is "
              "flipping one byte of the canary we wrote back: it spawns no shell, which is what "
              "proves the recovered canary was load-bearing."),

    Case("prompt_protocol_overflow",
         r"""#include <stdio.h>
#include <string.h>
#include <unistd.h>
/* A LINEAR PROMPT PROTOCOL: prompt, read a field, prompt, read a field, act. There is no menu,
   so `detect_menu` does not fire and `crawl_menu` has no option to select. The property that
   makes it a regression case is the one-line check: a BULK feed (one write of both lines, which
   is what every exec-time channel does) leaves the first read holding both lines, so the newline
   is not the last byte, the program rejects the input, and the second field never arrives at all.
   Only delivery paced one field per prompt reaches the overflow. Measured on the HTB target
   `replaceme`: 63,234 bulk executions found nothing; 1,015 prompted executions found the crash. */
/* The copy lives in a function that RETURNS, for the reason the socket case states: with the
   64-byte buffer among main's other locals the overflow runs upward into those locals and never
   reaches a saved return address -- measured here, clean at 500 bytes -- so the smash is real and
   nothing faults. This is doc 32 item 5(b) (frame layout decides reachability) biting on x86-64,
   not only on AArch64. */
static void use(const char *src){ char small[64]; strcpy(small, src); printf("ok %s\n", small); }
int main(void){ setvbuf(stdout,0,2,0);
  char first[128], second[512];
  printf("mode: ");
  ssize_t n = read(0, first, sizeof first - 1); if(n <= 0) return 0; first[n] = 0;
  if(memchr(first, '\n', n) != first + n - 1){ puts("one field per line, please"); return 1; }
  /* Field one is deliberately NOT content-checked. `replaceme` also demanded a magic prefix
     ("s/"), and an earlier version of this case copied that -- which made it unreachable for a
     second reason: the crawler cannot discover prompt TWO until something gets past prompt one,
     so the case silently asserted token mining as well, and failed at L0 with the prompted path
     never engaging. A gate case isolates ONE capability; token discovery has its own cases. */
  printf("data: ");
  n = read(0, second, sizeof second - 1); if(n <= 0) return 0; second[n] = 0;
  use(second);                                          /* unbounded copy into 64 bytes */
  return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=2, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=300.0,
         want_bundle=True,
         strict_level=True,
         note="CHANNEL prompt: a linear prompt protocol, reachable ONLY one field per prompt. "
              "Three halves are asserted here -- the pipeline must find it (which needs prompted "
              "delivery in the campaign), the shipped bundle must reproduce it (which needs a "
              "reproducer that paces the same way, not `< input.bin`), and the PRIMITIVE must be "
              "recoverable from it. A bulk feed desyncs and the program says so, which is why a "
              "half-fix reads as a verified L1 whose bundle does nothing. "
              "Raised from L1 to L2 once the capture path learned to pace, and the measurement "
              "behind that is the point: the campaign paced (`run_input_prompted`) and the bundle "
              "paced (`replay_prompt.py`), but the ptrace capture that the L2 primitive and the "
              "root-cause stage both drive had NO `prompt` branch and NO `else` -- so an input "
              "recorded as prompted left stdin unset, the child ran with NO INPUT AT ALL, and the "
              "helper honestly reported \"no fatal signal\". A real crash, a wrong setup, and "
              "nothing saying so; that silence is what held every prompt-paced defect at L1 "
              "however good the technique catalogue got. Measured with --ceiling after the fix: "
              "L2, primitive/CWE-119 + chain_primitive/CWE-787, 137s. L3 is NOT reached and the "
              "reason is a different seam: `_spawn_and_mark` already takes a paced LIST of "
              "writes, but the exploit recipes deliver their chain through `_measured_frame`, "
              "which builds one blob -- so weaponizing a prompt protocol needs that framing to "
              "pace too, and this case does not assert it yet."),

    # ---- BUILD REALISM. Real binaries are optimised and stripped; -O0 with symbols hides any
    # reliance on symbol names or on an unoptimised frame layout.
    Case("stripped_opt_overflow", _OVERFLOW_SRC,
         ["-no-pie", "-fno-stack-protector", "-O2", "-s", "-w"],
         want_level=2, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=300.0,
         note="BUILD: -O2 and STRIPPED -- no symbols to lean on, optimised frame. want_level raised "
              "L1->L2: --ceiling measured an L2 primitive (CWE-119/121/787) through the real autopilot, "
              "so the gate enforces that rung rather than under-demanding L1. L2 is the honest ceiling "
              "here (this fixture has no reachable win()/clean gadget for L3)."),

    # ---- ARCHITECTURE. Everything else is x86-64, so an aarch64 regression is invisible. Skips
    # cleanly when the cross toolchain is absent.
    Case("arm64_overflow", _OVERFLOW_SRC,
         ["-static", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"),
         cross="aarch64-linux-gnu-", budget=360.0,
         note="ARCH aarch64 (static, under qemu): the crash must still be found off x86-64"),

    # ---- MORE ARCHITECTURES. Same bug, same assertion, different ISA: these differ from the
    # x86-64 cases ONLY in the toolchain, so each one protects a whole instruction set's recovery
    # and crash detection. s390x is BIG-ENDIAN, which is the one most likely to catch a byte-order
    # assumption. Static links so no guest libraries are needed under qemu; each SKIPS cleanly when
    # its cross compiler is absent.
    Case("arm32_overflow", _OVERFLOW_SRC,
         ["-static", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"),
         cross="arm-linux-gnueabihf-", budget=420.0,
         note="ARCH arm32 (static, qemu-arm)"),

    Case("riscv64_overflow", _OVERFLOW_SRC,
         ["-static", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"),
         cross="riscv64-linux-gnu-", budget=420.0,
         note="ARCH riscv64 (static, qemu-riscv64) -- the backend mis-decodes RISC-V as x86 without "
              "the SLEIGH path, so this guards body recovery too"),

    Case("s390x_overflow", _OVERFLOW_SRC,
         ["-static", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"),
         cross="s390x-linux-gnu-", budget=420.0,
         note="ARCH s390x -- BIG-ENDIAN, the case that catches a byte-order assumption"),

    Case("ppc64le_overflow", _OVERFLOW_SRC,
         ["-static", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"),
         cross="powerpc64le-linux-gnu-", budget=420.0,
         note="ARCH ppc64le (static, qemu-ppc64le)"),

    # The five cross-arch cases above are aarch64, arm32 HF (little-endian), ppc64le, riscv64 and
    # s390x -- every one of which either needs no emulator discriminator or hits a branch that was
    # already implemented. So nothing asserted MIPS, and for MIPS the ELF e_machine is BOTH
    # endianness- and word-size-blind: EM_MIPS covers MIPS32 and MIPS64 and elf._MACHINES emits
    # "mips" for both, which makes `bits` the only way to reach qemu-mips64el. The router ignored
    # it, so every MIPS64 target ran under a 32-bit emulator and the two 64-bit MIPS emulators were
    # unreachable by any code path. SKIPs without the toolchain, which is the point: it closes the
    # coverage hole for anyone who has it.
    Case("mips64el_overflow", _OVERFLOW_SRC,
         ["-static", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"),
         cross="mips64el-linux-gnuabi64-", budget=420.0,
         note="ARCH mips64el: 64-bit little-endian MIPS, sharing its e_machine with MIPS32 -- the "
              "case that would have caught qemu-mips64el being unreachable"),

    # The MULTI-CALL case. Without the dispatch discovery this target is unfuzzable: every
    # execution of the bare image prints its usage and exits, which is a clean run against a
    # program carrying an unbounded strcpy one argument away. The gate asserts the whole chain
    # -- read the listing, allow-list by shape (so `reboot` is never invoked), verify the door
    # by running it, fuzz THROUGH it, and reach a verified PoC.
    Case("multicall_dispatch", _MULTICALL_SRC,
         ["-fno-stack-protector", "-O0", "-no-pie", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=300.0,
         note="DISPATCH multi-call: the bug is behind `unlzma`, and the image itself only "
              "dispatches -- busybox's shape, which is every firmware image's shape"),

    # A read-class defect behind a header gate, with the address the attacker's to choose. The
    # level asserted here is what it MEASURED on 2026-10-16, not what would be nice: see the
    # address-control verdict family in poc/primitive.py.
    Case("indexed_read_l2", _INDEXED_READ_SRC,
         ["-O0", "-w"],
         want_level=2, want_cwe=("CWE-125", "CWE-129", "CWE-119"), budget=420.0,
         note="REAL-SHAPED: header-gated parser, unvalidated index, read-class, no win() -- "
              "the L2 verdict comes from the faulting ADDRESS moving with the input"),

    # The SAME chain, from a BINARY. The case above is a source drop, so the platform builds its
    # own ASan twin and the over-read is measured from a sanitizer report. A third-party binary
    # has no such twin: the read is measured from the faulting ADDRESS (poc/primitive.py's
    # address-control family) and the disclosure from steering that address into mapped memory.
    # The leak is driven by an INDEX rather than a length for exactly that reason -- a length
    # over-read reads from the object's own start, which the sanitizer family already covers,
    # while an index chooses WHERE, which is what a stripped binary presents.
    Case("addr_leak_pie_ret2win",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void win(void){ setuid(0); execl("/bin/sh","sh",(char*)0); }
/* its OWN frame, so the saved return sits just above the buffer */
__attribute__((noinline)) static void greet(const char *d, size_t n){
  char name[64]; memcpy(name, d, n); puts(name); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  unsigned char *buf = (unsigned char*)malloc(64);
  void **nb = (void**)malloc(64);        /* the NEIGHBOUR the read runs into at index 0 */
  nb[0]=(void*)win; nb[1]=(void*)stdout; nb[2]=(void*)nb; nb[3]=(void*)win;
  memset(buf,'X',64);
  char line[512];
  for(;;){ ssize_t n = read(0,line,sizeof(line)-1); if(n<=0) return 0; line[n]=0;
    if(!strncmp(line,"dump=",5)){        /* the INDEX is the attacker's: it chooses WHERE */
      unsigned long i = strtoul(line+5,NULL,10);
      unsigned char tmp[128];
      memcpy(tmp, buf + i*0x1000, sizeof(tmp));   /* the PROCESS reads it, so a bad address faults */
      fwrite(tmp, 1, sizeof(tmp), stdout); fflush(stdout); continue; }
    if(!strncmp(line,"name=",5)){ greet(line+5,(size_t)n-5); continue; }
    return 0; } }''',
         # L3, MEASURED, three consecutive runs: 182s, 184s, 183s on 2026-10-18 (first reached
         # 132s/171s/169s on 2026-10-16, then REGRESSED to a deterministic L2 and was restored by
         # a three-part fix -- see docs/internal/39). The three defects, each of which alone caps
         # the case: (a) the fuzzer records these crashes with no fault PC, so `_distinct_crashes`
         # collapsed the `dump=` READ and the `name=` WRITE into one `(signal, None)` bucket and
         # the read often never reached the prove loop -- orchestrate now re-captures an in-code
         # fault PC to split them; (b) `address_primitive` bailed when a `name=` hijack sibling
         # faulted a page away, discarding the read verdict -- it now anchors to the base crash's
         # own fault page; (c) the `dump=<N>` lever is a DECIMAL field that cannot isolate as a
         # single byte, so disclosure only ever tried the far-OOB crash -- `_address_disclosure`
         # now steers the numeric field to zero (`dump=0` reads the neighbour chunk). The autopilot
         # reaches it UNAIDED from a stripped PIE binary with no source and therefore no
         # sanitizer twin, which is the shape that had capped every real finding in this project
         # at L1. What has to happen in those ~150 seconds, in order:
         #
         #   1. both branches of the dispatcher are entered -- `_dispatch_prefix_seeds` puts each
         #      mined `key=` token at offset 0, because once the `name=` overflow is found the
         #      corpus fills with inputs carrying that prefix and `dump=` is only ever inserted
         #      mid-line, where `strncmp(line,"dump=",5)` never matches;
         #   2. the `dump=` over-read faults -- and only because the guard-page allocator is on,
         #      so the L2 captures have to preload it too (`make_capture(guard_page=)`), or the
         #      crash is silent where it is re-run and the stage answers "did not fault";
         #   3. the ADDRESS is measured as the attacker's: 25 of 30 single-byte variants faulted
         #      across one routine (an unrolled memcpy faults at several PCs, so the unit is a
         #      code page, not an instruction) with the address moving;
         #   4. the same input, replayed UNGUARDED on the plain build, discloses 8 live pointers
         #      and `leak.disclosed_bases` resolves the PIE and libc bases with ASLR ON. The
         #      gate for a survivor is "it printed something", never "more than the baseline":
         #      the baseline is the input truncated to 8 bytes, which on a `dump=<n>` line is
         #      still a valid dump command, and comparing against it threw away a proved leak;
         #   5. the control offset (71) and the `name=\n` framing both come from the ONE payload
         #      that measured them -- a confirmed L2 with no offset must not answer for the
         #      framing (`_l2_control_run`);
         #   6. `build_exploit` replays the disclosure recipe live, relocates the payload to the
         #      base it just recovered, and pops a SHELL graded by a nonce challenge that comes
         #      back evaluated, which an echoing target cannot fake.
         ["-fno-stack-protector", "-w"], want_level=3, want_cwe=(), budget=600.0,
         note="BINARY out-of-bounds READ whose ADDRESS the attacker chooses, in a program that "
              "also has the write primitive to spend the ASLR defeat on. No source, so no "
              "sanitizer twin: the read is measured from the faulting address and the "
              "disclosure from steering that address back into mapped memory.\n"
              "The `memcpy` into a local is load-bearing and was measured: the first version of "
              "this fixture handed the out-of-bounds pointer straight to `fwrite` on an "
              "UNBUFFERED stream, so the read happened inside write(2) -- the kernel returns "
              "EFAULT rather than faulting the process, and `dump=99999999` exited 0 with the "
              "guard-page allocator preloaded. A crash-driven search cannot see that read at "
              "all, which is a real blind spot and not this case's subject: with the copy, the "
              "process touches the address itself."),

    # ---- FILE FORMATS / FRONT-ENDS. The platform parses PE, JVM, CPython bytecode, WASM and
    # UPX-packed ELF, but every case above is a plain ELF, so a front-end could stop recognising its
    # container entirely without the gate noticing. These assert the one property the probe shows
    # actually holds today: the container is identified and routed to the right triage. They
    # deliberately do NOT claim a demonstrated effect -- triage/disassemble/detect produce no
    # findings on these artifacts yet, so asserting one would just be a standing red mark. Each
    # needs only ingest+triage, so it costs seconds rather than a budget.
    Case("fmt_pe", _OVERFLOW_SRC,
         ["-fno-stack-protector", "-O0", "-w"],
         want_level=0, want_cwe=(), want_file_type="pe",
         cross="x86_64-w64-mingw32-", budget=120.0,
         note="FRONT-END PE (mingw): identified as a Windows PE, x86-64"),

    # Front-end identification is not analysis. This drives the SAME PE through the real autopilot
    # and demands a DEMONSTRATED memory-safety defect, which is what "works on Windows binaries"
    # has to mean. Wine is the substrate; a smashed stack there never prints "Unhandled exception
    # code" (the SEH chain is overwritten, so the exception cannot be dispatched at all) and used
    # to read as a clean run -- see sandbox._WINE_SEH_RE.
    Case("pe_overflow", _OVERFLOW_SRC,
         ["-fno-stack-protector", "-O0", "-w"],
         want_level=0, want_cwe=("CWE-121", "CWE-787", "CWE-119", "CWE-120", "CWE-125"),
         cross="x86_64-w64-mingw32-", requires=("wine",), budget=600.0,
         note="PE DYNAMIC: the Windows PE's stack overflow demonstrated through wine, not just "
              "identified as a PE"),

    Case("fmt_jvm_class", "",
         [], want_level=0, want_cwe=(), want_file_type="class", budget=120.0,
         build=(["sh", "-c",
                 "printf 'public class Boom{public static void main(String[] a){int[] x=new int[4];"
                 "System.out.println(x[Integer.parseInt(a.length>0?a[0]:\"9\")]);}}' > Boom.java && "
                 "javac Boom.java"], "Boom.class"),
         note="FRONT-END JVM: a .class is identified as JVM bytecode, not a native image"),

    # As with pe_overflow: drive JVM bytecode through the real autopilot and demand a DEMONSTRATED
    # defect. On this runtime an uncaught ArrayIndexOutOfBoundsException is the equivalent of a
    # signal (jvm.py maps it to CWE-129). The index is the input's LENGTH, so the defect is
    # reachable by a broad class of inputs.
    #
    # It deliberately is NOT `Integer.parseInt(line)` out of range. parseInt needs the WHOLE
    # trimmed string to be a valid integer, so a blind mutator essentially never produces one:
    # measured, that version found nothing in a full campaign. Normally directed/concolic search
    # solves such a predicate, but there is no bytecode-level instrumentation or concolic here
    # (disassembly recovers 0 functions from a .class), so a JVM defect behind a narrow parse
    # guard is an honest open gap -- and asserting it would test the mutator's luck, not this
    # pipeline. What IS tested: a JVM uncaught exception becoming a demonstrated finding.
    Case("jvm_oob_index", "",
         [], want_level=1, strict_level=True, want_cwe=("CWE-129", "CWE-125", "CWE-20"),
         requires=("javac", "java"), budget=420.0,
         build=(["sh", "-c",
                 "printf 'import java.io.*;\\npublic class Idx{public static void main(String[] a)"
                 "throws Exception{BufferedReader r=new BufferedReader(new InputStreamReader"
                 "(System.in));String s=r.readLine();if(s==null)s=\"\";int[] t=new int[4];"
                 "int i=s.length();"
                 "System.out.println(\"slot \"+i+\" = \"+t[i]);}}' > Idx.java && javac Idx.java"],
                "Idx.class"),
         note="JVM DYNAMIC: an array indexed by the unvalidated input length, demonstrated as an "
              "uncaught ArrayIndexOutOfBoundsException rather than merely identified as bytecode"
              " Measured with --ceiling: L1 (directed_fuzz/CWE-129, 247s). The matrix read L0 for this because the case demanded L0, not because the ladder stopped there -- and demanding the rung was unsafe until the bundle could carry it: the gate judged every reproducer by a NATIVE crash's exit status (>=128), and an uncaught JVM exception exits 1."),

    Case("fmt_pyc", "",
         [], want_level=0, want_cwe=(), want_file_type="pyc", budget=120.0,
         build=(["sh", "-c",
                 "printf 'import sys\nd={}\nprint(d[sys.argv[1]])\n' > m.py && "
                 "python3 -m py_compile m.py"], "m.*.pyc"),
         note="FRONT-END CPython bytecode: a .pyc is identified as pyc / cpython-bytecode"),

    # And the same demand as pe_overflow / jvm_oob_index: drive the bytecode through the real
    # autopilot and require a DEMONSTRATED defect. CPython is a managed runtime, so the ceiling
    # here is denial of service -- the interpreter bounds-checks every index and owns every
    # reference, which is a property of the runtime, not a gap in this pipeline. The index is the
    # input's LENGTH so a broad class of inputs reaches it, for the reason spelled out on
    # jvm_oob_index: a `int(line)` guard would test the mutator's luck instead of the pipeline.
    Case("pyc_oob_index", "",
         [], want_level=1, strict_level=True, want_cwe=("CWE-129", "CWE-125", "CWE-20"),
         requires=("python3",), budget=420.0,
         build=(["sh", "-c",
                 "printf 'import sys\ns = sys.stdin.readline()\nt = [1, 2, 3, 4]\n"
                 "print(\"slot\", len(s), \"=\", t[len(s)])\n' > oob.py && "
                 "python3 -m py_compile oob.py"], "oob.*.pyc"),
         note="PYC DYNAMIC: a list indexed by the unvalidated input length, demonstrated as an "
              "uncaught IndexError rather than merely identified as CPython bytecode"
              " Measured with --ceiling: L1 (fuzz/CWE-129 + root_cause/CWE-129, 218s). The deliverable was the blocker, not the ladder: `poc/stage` mapped only jar and class, so a .pyc fell through to the native branch and the reproducer said `./target.bin < ./input.bin` -- a file the shell cannot execute."),

    Case("fmt_wasm", "",
         [], want_level=0, want_cwe=(), want_file_type="wasm", budget=120.0,
         build=(["sh", "-c",
                 "printf 'static char buf[64];\n__attribute__((export_name(\"copy\"))) "
                 "void copy(const char *s,int n){for(int i=0;i<n;i++) buf[i]=s[i];}\n' > w.c && "
                 "clang --target=wasm32 -nostdlib -Wl,--no-entry -O0 -o w.wasm w.c"], "w.wasm"),
         note="FRONT-END WASM: a wasm32 module is identified as wasm (an unbounded copy inside)"),

    # And the dynamic demand, as for pe_overflow / jvm_oob_index / pyc_oob_index. A wasm module
    # is not an executable: no process, no argv, and (unless it is a WASI command) no entry
    # point at all, so "running" one means choosing how to hand it the input. This module is a
    # REACTOR -- built with --no-entry, exporting one function -- which the driver feeds by
    # staging the input in the module's own linear memory and calling the export as (ptr, len).
    #
    # The defect is an offset taken straight from the input bytes, NOT an unbounded copy. That
    # is deliberate: wasm linear memory is one flat array holding the module's globals, stack
    # and heap, so a copy that overruns a 64-byte buffer corrupts the neighbours and traps on
    # nothing. Only an access past the END of linear memory traps, which is this platform's
    # honest ceiling on this substrate and is recorded on wasm.TRAP_CWE.
    Case("wasm_oob_store", "",
         [], want_level=1, strict_level=True, want_cwe=("CWE-119", "CWE-787", "CWE-125", "CWE-129"),
         requires=("node", "clang"), budget=420.0,
         build=(["sh", "-c",
                 "printf 'static char buf[64];\n"
                 "__attribute__((export_name(\"parse\")))\n"
                 "int parse(const unsigned char *s, int n){\n"
                 "  if (n < 4) return -1;\n"
                 "  int off = (int)(s[0] | (s[1]<<8) | (s[2]<<16) | (s[3]<<24));\n"
                 "  buf[off] = (char)s[3];\n"
                 "  return off; }\n' > w2.c && "
                 "clang --target=wasm32 -nostdlib -Wl,--no-entry -O0 -o w2.wasm w2.c"],
                "w2.wasm"),
         note="WASM DYNAMIC: a store at an offset taken from the input, demonstrated as an "
              "out-of-bounds trap rather than merely identified as a wasm module"
              " Measured with --ceiling. A WASM module is not a process: the bundle ships the driver that instantiates it, and the verdict is report.json's status rather than an exit code, because node exits 0 whether the module trapped or not."),

    # The hijack a sandboxed substrate CAN have. The engine's own guard says it right: the
    # WebAssembly engine owns the instruction pointer and no linear-memory corruption gives it up,
    # so "control-flow hijack" in the native sense is not a claim this runtime supports. This is a
    # different claim. A C function pointer on wasm32 is a 4-byte INDEX into
    # __indirect_function_table, held in linear memory like any other field -- so an overflow
    # changes which function the module's own `call_indirect` dispatches to, with the engine's
    # type check still enforced and no further reach than the host's grants to this module.
    #
    # `win` executes `__builtin_trap()` precisely so the effect is unforgeable: the engine's trap
    # message becomes "unreachable", which `plain` (which returns) can never produce. The sweep
    # confirms against two controls -- the module's behaviour on a payload that never reaches the
    # pointer, and a benign table slot AT THE SAME OFFSET.
    Case("wasm_fnptr_hijack", "",
         [], want_level=3, want_cwe=(), mechanism="type-confusion",
         requires=("node", "clang"), budget=480.0,
         build=(["sh", "-c",
                 "printf 'typedef void (*cb_t)(void);\n"
                 "static void plain(void) { }\n"
                 "static void win(void)   { __builtin_trap(); }\n"
                 "__attribute__((used)) static cb_t handlers[2] = { plain, win };\n"
                 "struct obj { char buf[32]; cb_t cb; };\n"
                 "static struct obj o = { .cb = plain };\n"
                 "__attribute__((export_name(\"take\"))) void take(char *p, int n) {\n"
                 "  for (int i = 0; i < n; i++) o.buf[i] = p[i];\n"
                 "  o.cb(); }\n' > w3.c && "
                 "clang --target=wasm32 -O1 -nostdlib -Wl,--no-entry -Wl,--export-all "
                 "-o w3.wasm w3.c"],
                "w3.wasm"),
         note="WASM FUNCTION-POINTER HIJACK (CWE-787 -> an attacker-chosen indirect call). The "
              "overflow runs out of `buf` into `cb`, which on wasm32 is a table INDEX rather than "
              "an address -- so none of the native machinery applies: there is no PC to recover an "
              "offset from, and a wrong index does not fault anywhere near its own value. The "
              "table is small and the module enumerates it in its element section, so the search "
              "is a sweep rather than a leak. Hand-proved first: slot 1 (plain) leaves the module "
              "clean and slot 2 (win) traps with \"unreachable\", and the engine's own driver then "
              "found it in 35 runs. The sandbox is the ceiling and the finding says so: no native "
              "code executes and there is no shell -- the demonstrated effect is control of which "
              "function the module calls."),

    # CHANNEL x FORMAT, the cell no case covered. Every non-stdin case above is a native ELF and
    # every managed case is stdin-only, so nothing asked whether a channel the ranking OFFERS can
    # actually carry input on the substrate it offers it for. For wasm it could not: the driver
    # hardcoded `args: ['prog']`, so an argument never reached the module, and it granted no
    # filesystem preopens, so `file` was impossible by construction -- yet `arg` ranked FIRST for
    # every wasm target, on the slowest substrate measured here (11 exec/s).
    #
    # This module is a WASI COMMAND: it exports `_start`, so it has a process and therefore an
    # argv. Its defect is reachable ONLY through that argv (it reads no input at all otherwise),
    # so a clean verdict here means the channel delivered nothing -- which is precisely what the
    # ranking was spending its budget on before.
    Case("wasm_argv_trap", "",
         [], want_level=1, strict_level=True, want_cwe=("CWE-119", "CWE-787", "CWE-125"),
         requires=("node", "clang"), budget=300.0,
         build=(["sh", "-c",
                 "printf '__attribute__((import_module(\"wasi_snapshot_preview1\"), "
                 "import_name(\"args_sizes_get\")))\n"
                 "int args_sizes_get(int *argc, int *bufsize);\n"
                 "__attribute__((export_name(\"_start\")))\n"
                 "void _start(void){ int c = 0, s = 0; args_sizes_get(&c, &s);\n"
                 "  if (c >= 2) { volatile char *p = (volatile char *)0x7fff0000; "
                 "*p = (char)c; } }\n' > w3.c && "
                 "clang --target=wasm32 -nostdlib -Wl,--no-entry -O0 -o w3.wasm w3.c"],
                "w3.wasm"),
         note="WASM ARGV: a WASI command whose only input channel is argv, demonstrated as an "
              "out-of-bounds trap -- a clean verdict here means the channel delivered nothing"
              " Measured with --ceiling. Same deliverable shape as wasm_oob_store: the host travels with the bundle and the trap verdict comes back in a file."),

    # A .NET assembly IS a PE, so for as long as the dispatch asked only "is it a PE" this went
    # to WINE -- which cannot execute managed code without Wine Mono. Nothing ran, and the run
    # was reported crashed=False with no note: a CLEAN verdict on a target that never executed,
    # on a host carrying a full .NET SDK. This case pins the routing itself.
    Case("fmt_dotnet", "",
         [], want_level=0, want_cwe=(), want_file_type="dotnet", budget=180.0,
         requires=("dotnet",),
         build=_csc_build(_CS_FMT, 'fmtnet.dll'),
         note="FRONT-END .NET: a managed PE is identified as dotnet (CIL), NOT as a native PE"),

    # And the same demand as pe_overflow / jvm_oob_index / pyc_oob_index / wasm_oob_store: drive
    # the assembly through the real autopilot and require a DEMONSTRATED defect. The CLR is a
    # managed runtime, so the ceiling here is denial of service -- it bounds-checks every array
    # access and owns every pointer, which is a property of the runtime and not a gap in this
    # pipeline. The index is the input's LENGTH so a broad class of inputs reaches it, for the
    # reason spelled out on jvm_oob_index: an int.Parse() guard would test the mutator's luck
    # instead of the pipeline.
    #
    # Note what this case also proves incidentally: an ingested assembly arrives as a single
    # file under a generated name, with no runtimeconfig.json and no .dll extension, and the
    # `dotnet` muxer refuses both. If either were unhandled every execution would be a non-run.
    Case("dotnet_oob_index", "",
         [], want_level=1, strict_level=True, want_cwe=("CWE-129", "CWE-125", "CWE-20"),
         requires=("dotnet",), budget=480.0,
         build=_csc_build(_CS_OOB, 'oobnet.dll'),
         note="DOTNET DYNAMIC: an array indexed by the unvalidated input length, demonstrated "
              "as an unhandled IndexOutOfRangeException under the CLR rather than merely "
              "identified as a .NET assembly"
              " Measured with --ceiling. The deliverable needed two things an ingested assembly never has: a .dll filename (the muxer dispatches on the extension) and a generated runtimeconfig.json, both of which the bundle now writes in its setup."),

    Case("fmt_upx_packed", "",
         [], want_level=0, want_cwe=(), want_file_type="elf", budget=120.0,
         build=(["sh", "-c",
                 "printf '#include <stdio.h>\nint main(){char b[64];scanf(\"%%s\",b);"
                 "printf(\"%%s\",b);return 0;}\n' > u.c && "
                 "gcc -no-pie -fno-stack-protector -O0 -w u.c -o u_native && "
                 "upx -q -o u_packed u_native >/dev/null"], "u_packed"),
         note="FRONT-END UPX: a runtime-packed ELF is still identified as an ELF (the unpack stage "
              "then carves the real program out of the decompressor stub)"),

    # As with pe_overflow / jvm_oob_index: identification is not analysis. The same packed image,
    # driven through the real autopilot, must DEMONSTRATE the defect that is hidden inside the
    # compressed stream. Nothing static can: disassembling the stub recovers a decompressor, the
    # detectors see one high-entropy blob, and the vulnerable `scanf` is not even present as bytes
    # until the loader has run. So this asserts the unpack stage actually produces a child target
    # and that the child is then analysed like any other ELF -- the whole point of having the stage.
    Case("upx_overflow", "",
         [], want_level=0, want_cwe=("CWE-121", "CWE-787", "CWE-119", "CWE-120", "CWE-125"),
         requires=("upx", "gcc"), budget=420.0,
         build=(["sh", "-c",
                 "printf '#include <stdio.h>\nint main(){char b[64];printf(\"in: \");"
                 "if(scanf(\"%%s\",b)!=1) return 0;printf(\"hi %%s\\\\n\",b);return 0;}\n'"
                 " > u.c && "
                 "gcc -no-pie -fno-stack-protector -O0 -w u.c -o u_native && "
                 "upx -q -o u_packed u_native >/dev/null"], "u_packed"),
         note="UPX DYNAMIC: the overflow lives inside the compressed image, so it is demonstrable "
              "only if the unpack stage carves out a child target the ELF pipeline then drives"),

    # A FIRMWARE image is the other CONTAINER shape, and the one the platform is most pointed
    # at: an embedded device ships a filesystem, not a program. Nothing static can find the
    # defect -- the vulnerable binary is a region inside a compressed SquashFS, so disassembling
    # the image recovers nothing and the detectors see one high-entropy blob. The case therefore
    # asserts the whole container path: triage routes the image to firmware_carve, the carve
    # registers the embedded ELF as a child target, and the ELF pipeline then drives it.
    #
    # This case was impossible to pass before _verdict became case-scoped, for exactly the
    # reason upx_overflow was: a container's findings land on the CHILD target's id.
    Case("firmware_carve_overflow", "",
         [], want_level=0, want_cwe=("CWE-121", "CWE-787", "CWE-119", "CWE-120", "CWE-125"),
         requires=("mksquashfs", "unsquashfs", "gcc"), budget=600.0,
         build=(["sh", "-c",
                 "printf '#include <stdio.h>\nint main(){char b[64];printf(\"in: \");"
                 "if(scanf(\"%%s\",b)!=1) return 0;printf(\"hi %%s\\\\n\",b);return 0;}\n'"
                 " > f.c && "
                 "gcc -no-pie -fno-stack-protector -O0 -w f.c -o httpd && "
                 "mkdir -p root/usr/sbin root/etc && cp httpd root/usr/sbin/ && "
                 "printf 'admin:x:0:0:root:/:/bin/sh\n' > root/etc/passwd && "
                 "mksquashfs root fw.squashfs -noappend -quiet -no-progress"], "fw.squashfs"),
         note="FIRMWARE DYNAMIC: the vulnerable service lives inside a SquashFS root filesystem, "
              "so it is demonstrable only if the carve registers it as a child target"),

    # The OTHER firmware shape, and the one with no operating system at all: a bare-metal
    # Cortex-M image. There is no filesystem to carve, no ELF to extract and no process to run
    # -- the image IS the program, it boots from a reset vector, and its only input is a
    # peripheral register. So this exercises the path nothing else does: the headerless loader
    # identifies it from its vector table, and firmware_rehost runs it under Unicorn with a
    # modelled MMIO input until a device value drives it off the end of RAM.
    #
    # Built in pure Python from pre-assembled Thumb, deliberately -- the same style as the
    # rehost unit fixtures. The image is 166 bytes and needs no cross-toolchain, so the case
    # runs anywhere Unicorn does rather than skipping on most machines.
    #
    # Three details are load-bearing. The reset handler ZEROES .bss first, so the case also
    # covers the write-progress init loop a real RTOS image starts with (a long loop with no
    # new coverage that must not be mistaken for a stuck spin). Every IRQ vector points at a
    # weak `b .` handler, as a real startup file's does. And RAM is mapped only up to the
    # initial SP, which is why an index past the top of RAM faults instead of landing silently
    # inside an over-generously mapped SRAM region.
    Case("firmware_rehost_oob", "",
         [], want_level=0, want_cwe=("CWE-787", "CWE-119", "CWE-125", "CWE-129"),
         requires=("python3",), budget=600.0,
         build=(["python3", "-c",
                 "import struct;"
                 "code=bytes.fromhex('fee740204ff0005100220a6004310138fad1"
                 "4ff08040016889004ff00052521841231360fee7');"
                 "img=bytearray(0x80);"
                 "struct.pack_into('<I',img,0,0x20010000);"            # initial SP = top of RAM
                 "struct.pack_into('<I',img,4,0x08000083);"            # Reset -> code+2, Thumb
                 "[struct.pack_into('<I',img,o,0x08000081) for o in range(8,0x80,4)];"
                 "open('fw.bin','wb').write(bytes(img)+code)"], "fw.bin"),
         note="FIRMWARE REHOST: a bare-metal Cortex-M image indexes RAM with a value read "
              "straight off a peripheral register -- demonstrable only by rehosting it under "
              "Unicorn with a modelled MMIO input, since there is no process to run"),

    # ---- BUG CLASSES with no case of their own. Each is a distinct defect the platform claims to
    # find; without these only overflow/format/UAF were ever asserted.
    Case("double_free",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  char *p[8]; int n=0;
  for(;;){ printf("1.alloc 2.free 3.exit\n> ");
    int o; if(scanf("%d",&o)!=1) return 0; getchar();
    if(o==1){ if(n<8){ p[n]=malloc(0x80); memset(p[n],'A',8); n++; } }
    else if(o==2){ int i; printf("idx: "); if(scanf("%d",&i)!=1) return 0; getchar();
                   if(i>=0&&i<n) free(p[i]); }      /* not nulled: freeing twice is a double free */
    else return 0; } }""",
         ["-fPIE", "-pie", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-415", "CWE-416"), budget=300.0,
         strict_level=True,
         note="BUG CLASS double free (CWE-415): the slot is never nulled, so two frees of one "
              "index. L1 is this case's CEILING and the reason is the fixture's own interface, "
              "not a gap: `1.alloc` takes no size and no data and there is no view and no edit, "
              "so the program offers no way to WRITE a forged chunk and no way to READ one back. "
              "Every route past a double free needs one or both -- tcache poisoning needs the "
              "write, a libc leak needs the read -- so glibc's abort is the whole observable "
              "effect. Measured with --ceiling; the demand is L1 so that losing the abort is a "
              "regression, and the notebooks that DO have those options (heap_fsop_*) carry the "
              "L3 claim for this class."),

    Case("int_overflow_alloc",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  unsigned n; printf("count: ");
  if(scanf("%u",&n)!=1) return 0;
  /* n*16 wraps for a large n, so a huge count allocates a tiny buffer and the loop runs off it */
  char *p = malloc(n * 16);
  if(!p) return 1;
  for(unsigned i=0;i<n;i++) memset(p + i*16, 'A', 16);
  printf("ok %u\n", n); free(p); return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=0, want_cwe=("CWE-190", "CWE-131", "CWE-122", "CWE-787", "CWE-119"),
         budget=300.0,
         note="BUG CLASS integer overflow feeding an allocation (CWE-190/131). Was a known gap: "
              "the wrap needs a DECIMAL input above 2**28 and a byte mutator emits bytes, so it "
              "was unreachable by budget rather than expensive. textconf.numeric_boundary_seeds "
              "seeds the wrap thresholds 2**bits//elem_size (+1) verbatim -- note the type "
              "boundary a fuzzer would try does NOT work here, since 4294967295*16 wraps to a "
              "size malloc refuses and the program exits cleanly. Gated on a scanf/strtol-family "
              "import. It also needed the coverage_fuzz->fuzz fallback: afl-fuzz aborts its dry "
              "run on one timing-out seed, and a native target then got no fuzzing at all."),

    Case("int_overflow_fnptr", SRC_INT_OVERFLOW_FNPTR,
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=3, want_cwe=(), budget=480.0, mechanism="integer-overflow",
         note="BUG CLASS integer overflow (CWE-190) WEAPONIZED. Measured with --ceiling, the "
              "class stopped at L1: int_overflow_alloc's wrap memsets 'A's over its own heap, so "
              "there is nothing to aim and the verdict family is magnitude. Here the wrap "
              "under-allocates and a SEPARATE option recomputes the copy length from the saved "
              "count in 64-bit, so the fill runs off the chunk with content we choose, into the "
              "next record's callback -- CWE-190 -> CWE-122 -> control. Three things had to "
              "change, each measured on this fixture: `add(slot, count)` was not recognised as an "
              "allocator at all (a size into a slot table, with the buffer filled by another "
              "option); the named allocator's primer drove the same default id twice, so a slot "
              "table held one object and an overflow had no neighbour to reach; and only the "
              "WRITTEN object was ever detonated, which makes a `struct { void (*show)(); char "
              "text[]; }` layout invisible -- the overflow runs forward, past this record's "
              "pointer, into the next one's. The wrap thresholds are the only counts that do it: "
              "999 and 0x7FFFFFFF make malloc refuse rather than under-allocate."),
    Case("int_truncation_fnptr", SRC_INT_TRUNC_FNPTR,
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=3, want_cwe=(), budget=480.0, mechanism="integer-truncation",
         note="BUG CLASS integer TRUNCATION (CWE-197/681) weaponized. A mechanism the matrix did "
              "not name: the size arithmetic is correct in 64 bits and then STORED into 16, so the "
              "allocation is undersized for a count four orders of magnitude below the wrap "
              "thresholds an overflow needs -- 4096 records here, where int_overflow_fnptr needs "
              "268435456. One list of 'big numbers' cannot cover both, so `menu.alloc_primers` "
              "carries a family per arithmetic (32-bit product, 16-bit truncated product, zero) "
              "and the 32-bit family stays first because it is the common case."),
    Case("off_by_one",
         r"""#include <stdio.h>
#include <string.h>
int main(void){ char b[64]; int i;
  printf("in: ");
  for(i=0; i<=64; i++){ int c=getchar(); if(c<0||c=='\n') break; b[i]=(char)c; }
  b[i]=0;                                   /* <=64 writes one past the end, then NUL past that */
  printf("hi %s\n", b); return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=0, want_cwe=("CWE-787", "CWE-121", "CWE-119", "CWE-193"), budget=300.0,
         known_gap=True,
         note="BUG CLASS off-by-one / single-byte overflow (CWE-193/787). KNOWN GAP -- two bytes past a 64-byte buffer lands in padding or the saved frame pointer and does not fault, so there is no crash to find, and no static detector files CWE-193."),

    Case("oob_index_write",
         r"""#include <stdio.h>
long table[16];
int main(void){ setvbuf(stdout,0,2,0);
  for(;;){ printf("1.set 2.get 3.exit\n> ");
    int o; if(scanf("%d",&o)!=1) return 0;
    if(o==1){ long i,v; printf("idx: "); if(scanf("%ld",&i)!=1) return 0;
              printf("val: "); if(scanf("%ld",&v)!=1) return 0;
              table[i]=v; }                 /* index never bounded: an arbitrary relative write */
    else if(o==2){ long i; printf("idx: "); if(scanf("%ld",&i)!=1) return 0;
                   printf("%ld\n", table[i]); }
    else return 0; } }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-129", "CWE-787", "CWE-125", "CWE-119"), budget=420.0,
         mechanism="bad-index",
         strict_level=True,
         note="BUG CLASS out-of-bounds INDEX write (CWE-129): unbounded index into a global table "
              "-- and the WEAPONIZATION of a write-what-where with NOTHING to point it at. There "
              "is no win function here, no system() in the PLT and no controlled pointer argument "
              "at any call site, so the GOT overwrite _oob_write_hijack does needs a target that "
              "does not exist; measured with --ceiling, the class stopped at an L2 recipe saying a "
              "leak-based chain was analyst work. The two halves of the same bug finish it: the "
              "unchecked index READS a GOT slot (a resolved libc address) to recover the libc base "
              "under live ASLR, then WRITES five House-of-Apple-2 cells over _IO_2_1_stderr_ -- a "
              "FILE this program never touches, which is what makes a cell-at-a-time delivery "
              "possible when the target's own prompt runs between every write -- with the fake "
              "wide jump table placed inside `table` itself. exit() flushes the forged FILE and "
              "_IO_wfile_overflow calls system(\" /bin/sh\"). Confirmed by a shell."),

    #: The same bug, on a target that PROMPTS ON STDERR. That one change kills both FSOP plans
    #: that forge a FILE glibc owns -- the program reads `_IO_2_1_stderr_` between our cells, so a
    #: half-built FILE is executed -- and leaves only the route that forges nothing of glibc's.
    Case("house_of_cat_list_all",
         r"""#include <stdio.h>
long table[128];                              /* big enough to hold a whole fake FILE */
int main(void){ setvbuf(stdout,0,2,0);
  for(;;){ fprintf(stderr, "1.set 2.get 3.exit\n> ");   /* prompts on STDERR, so stderr is USED */
    int o; if(scanf("%d",&o)!=1) return 0;
    if(o==1){ long i,v; fprintf(stderr, "idx: "); if(scanf("%ld",&i)!=1) return 0;
              fprintf(stderr, "val: "); if(scanf("%ld",&v)!=1) return 0;
              table[i]=v; }                 /* index never bounded: an arbitrary relative write */
    else if(o==2){ long i; fprintf(stderr, "idx: "); if(scanf("%ld",&i)!=1) return 0;
                   printf("%ld\n", table[i]); }
    else return 0; } }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-129", "CWE-787", "CWE-125", "CWE-119"), budget=420.0,
         mechanism="bad-index",
         strict_level=True,
         note="BUG CLASS out-of-bounds INDEX write again, but on the shape that defeats every "
              "FSOP plan which forges a FILE glibc already owns. `oob_index_write` works because "
              "`_IO_2_1_stderr_` is a FILE the program never touches, so a cell-at-a-time "
              "delivery can leave it half-built between writes; prompt on stderr instead and the "
              "program's own next prompt runs THROUGH the half-built FILE. Measured: the "
              "setcontext plan fails, the system plan fails, and the run falls through to HOUSE "
              "OF CAT -- build the whole FILE, its _IO_wide_data and its fake _wide_vtable inside "
              "`table`, then write ONE pointer, `_IO_list_all := &table`, so exit()'s stream "
              "flush walks a FILE that is entirely ours. It needs the FEWEST leaks of the three "
              "plans (no _wide_data read-back, no _flags read) and it takes the setcontext "
              "finish, so the effect is execve(\"/bin/sh\", NULL, NULL). The `_mode` field is "
              "what makes a self-built FILE work at all: _IO_flush_all's narrow test reads "
              "_IO_write_base/_IO_write_ptr at 0x20/0x28, which a blob delivered at a heap chunk "
              "address cannot choose, so _mode is set to 1 and the WIDE pair -- inside the blob "
              "-- carries the test instead."),

    #: The same bug again, on the shape that defeats EVERY plan that forges a FILE: the program
    #: closes stderr (so the FILE the other plans forge is unlinked from `_IO_list_all` and never
    #: flushed) and its table is too small to hold a FILE of our own. What is left is the stack.
    Case("environ_saved_return",
         r"""#include <stdio.h>
long table[64];                               /* 512 bytes: too small for a whole fake FILE */
int main(void){ setvbuf(stdout,0,2,0);
  fclose(stderr);                             /* a daemon-shaped program: stderr is gone */
  for(;;){ printf("1.set 2.get 3.exit\n> ");
    int o; if(scanf("%d",&o)!=1) return 0;
    if(o==1){ long i,v; printf("idx: "); if(scanf("%ld",&i)!=1) return 0;
              printf("val: "); if(scanf("%ld",&v)!=1) return 0;
              table[i]=v; }                 /* index never bounded: an arbitrary relative write */
    else if(o==2){ long i; printf("idx: "); if(scanf("%ld",&i)!=1) return 0;
                   printf("%ld\n", table[i]); }
    else return 0; } }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-129", "CWE-787", "CWE-125", "CWE-119"), budget=420.0,
         mechanism="bad-index",
         strict_level=True,
         note="BUG CLASS out-of-bounds INDEX write for the third time, on the shape where no FSOP "
              "plan can work at all -- and the one that needs nothing of libc's internals. "
              "`fclose(stderr)` runs `_IO_un_link`, so the FILE that `oob_index_write` forges is "
              "no longer on `_IO_list_all` and exit() never flushes it; `table` is 512 bytes, "
              "under House of Cat's 0x390, so a FILE of our own does not fit beside the bug. "
              "Measured on this fixture: the setcontext plan's 9 cells all land and the trigger "
              "does nothing (exit 0), the system plan's 5 cells land and the trigger does nothing, "
              "House of Cat is excluded for room -- and the `stack` plan spawns a shell. It works "
              "because libc EXPORTS `environ`, whose value is the envp array the kernel left on "
              "the stack, so one read turns the arbitrary read into a stack address; main's saved "
              "return address is then the first libc code pointer below it that is not inside "
              "`__libc_start_main` (the two libc return addresses above main's belong to frames "
              "that are never returned from, and main's own points into `__libc_start_call_main`, "
              "which no libc exports -- so one exported symbol decides it). A "
              "system(\"/bin/sh\") chain goes over that slot and returning from main runs it. "
              "Two things had to be measured rather than read: a saved return address is told from "
              "a code pointer in a local by the bytes BEFORE it decoding as a `call`, which no "
              "register allocation can change; and the chain is written at BOTH rsp parities "
              "because `system`'s prologue has a `movaps` -- one parity segfaults (-11) and the "
              "other spawns a shell."),

    Case("format_read_leak",
         r"""#include <stdio.h>
int main(void){ setvbuf(stdout,0,2,0);
  char f[128]; char secret[32] = "SECRET-ON-THE-STACK";
  printf("say: ");
  if(!fgets(f,sizeof f,stdin)) return 0;
  printf(f);                                 /* user-controlled format: %p/%s READ, not a write */
  printf("\n"); return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=2, want_cwe=("CWE-134", "CWE-200"), budget=300.0,
         mechanism="format-string",
         strict_level=True,
         note="BUG CLASS format-string READ/disclosure (CWE-134/200) -- the gate only had the %n "
              "WRITE. Measured with --ceiling, the class stopped at L1: the probe confirmed the "
              "bug and filed the leaked words, and nothing asked what they were WORTH, so a %p "
              "dump that defeats ASLR ranked with one that prints padding. Two things were wrong. "
              "`disclosed_bases` harvested only the RAW-WORD rendering -- it claimed hex text too "
              "and parsed none of it -- so a printed pointer was invisible to the one function "
              "that can resolve it; and the recon payload asked for eight %p, which confirms the "
              "bug and resolves nothing, because the pointers that anchor a base sit deeper than "
              "the eighth varargs slot (8 and 12 directives proved a base 0/4 runs, 24 proved it "
              "4/4 -- see format_read_leak_pie). `-no-pie` means there is no image base to "
              "disclose here, so what the dump has to anchor is a LIBC pointer -- which it does, "
              "attributed: `ASLR defeated by a format string (discloses the libc base) "
              "(demonstrated): L2 primitive`. Driven standalone outside the autopilot the same "
              "payload anchors nothing 3/3 runs, which is the class's real texture: whether a "
              "varargs dump reaches an anchorable pointer depends on what the stack happens to "
              "hold under that environment. There is no L3 either, and that is the target too: "
              "one printf, one shot, no second call site to redirect."),

    #: The same read, PIE. This is where "the leak defeats ASLR" is a claim about something: the
    #: image base is randomised, two leaked slots anchor it, and the measurement is 4/4 runs.
    Case("format_read_leak_pie",
         r"""#include <stdio.h>
int main(void){ setvbuf(stdout,0,2,0);
  char f[128]; char secret[32] = "SECRET-ON-THE-STACK";
  printf("say: ");
  if(!fgets(f,sizeof f,stdin)) return 0;
  printf(f);                                 /* user-controlled format: %p/%s READ, not a write */
  printf("\n"); return 0; }""",
         ["-fPIE", "-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=2, want_cwe=("CWE-134", "CWE-200"), budget=300.0,
         mechanism="format-string", strict_level=True,
         note="BUG CLASS format-string READ, weaponized to the rung it earns: an L2 DISCLOSURE "
              "PRIMITIVE. The probe confirmed the bug and filed the leaked words, and nothing "
              "asked what they were WORTH, so a dump that defeats ASLR ranked with one that prints "
              "padding. Three measurements shaped the fix, all under the sandbox the probe uses "
              "(sandbox.run, ASLR off), 4 runs each, counting only PLAUSIBLE bases: `disclosed_"
              "bases` parsed no hex text at all, so a PRINTED pointer was invisible to the one "
              "function that can resolve it; the recon payload asked for eight %p, and 24 "
              "directives proved a base 0/4 while 32 and 40 proved it 4/4; and the hex-text "
              "candidates needed the same POINTER SHAPE test the raw-word scan applies by "
              "construction -- without it a stack ASCII word (0x4f2d544552434553 is \"SECRET-O\") "
              "is a 64-bit candidate with a 1-in-4096 chance of matching any curated anchor's page "
              "offset, and a 32-directive dump duly \"proved\" libc base 0x1f7f6b000."),

    Case("uninit_stack_read",
         r"""#include <stdio.h>
#include <string.h>
static void fill(void){ char pad[64]; memset(pad,'S',sizeof pad); }
static void leak(void){ char b[64]; printf("%.64s\n", b); }   /* never initialised */
int main(void){ setvbuf(stdout,0,2,0); fill(); leak(); return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=0, want_cwe=("CWE-457", "CWE-200", "CWE-908"), budget=240.0,
         note="BUG CLASS use of uninitialised stack memory (CWE-457/908) -> disclosure. Was a known gap: the read never faults, so every crash-centric stage is blind to it, and a DIFFERENTIAL oracle cannot see it either -- fill() overwrites any pre-seeded pattern microseconds before leak() reads it, and the program takes no input, so there is no knob. The `mem_oracle` stage runs valgrind memcheck, whose shadow memory sees the read itself and distinguishes undefined bytes reaching a WRITE syscall (CWE-200, the disclosure, an effect that actually happened) from a merely internal uninitialised read (CWE-457)."),

    # ---- MECHANISMS WITH NO CASE. `coverage_matrix.MECHANISM` has named null-deref,
    # div-by-zero, race and resource-exhaustion since it was written, and not one of them had a
    # fixture -- so the row did not exist and the matrix read as if the taxonomy stopped at the
    # classes someone happened to write a case for. These are the measurement, not the claim:
    # each lands with want_level=0 / want_cwe=() so it cannot fail, is measured with --ceiling,
    # and only then demands what it reached.
    Case("null_deref",
         r"""#include <stdio.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  char line[64]; char *p = 0;
  printf("name: "); if(!fgets(line,sizeof line,stdin)) return 0;
  if(line[0]=='a') p = line;               /* only ONE branch initialises it */
  printf("len %zu\n", strlen(p)); return 0; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=1, want_cwe=(), budget=240.0, mechanism="null-deref", strict_level=True,
         note="BUG CLASS null-pointer dereference (CWE-476). A branch leaves the pointer NULL and "
              "the next read of it faults -- the cheapest crash there is, and the mechanism had no "
              "case. Note printf(\"%s\", NULL) is NOT it: glibc prints \"(null)\" and the program "
              "survives, so the fixture dereferences through strlen."),

    Case("div_by_zero",
         r"""#include <stdio.h>
int main(void){ setvbuf(stdout,0,2,0);
  int n; printf("n: "); if(scanf("%d",&n)!=1) return 0;
  printf("%d\n", 100/n); return 0; }       /* n == 0 -> SIGFPE */""",
         ["-no-pie", "-O0", "-w"],
         want_level=1, want_cwe=(), budget=240.0, mechanism="div-by-zero", strict_level=True,
         note="BUG CLASS divide by zero (CWE-369) -> SIGFPE. A different SIGNAL from every other "
              "case here, which is the point: the ladder's fault classification is signal-driven "
              "and nothing asserted that a non-SEGV fault is reproduced and levelled at all."),

    Case("stack_exhaustion",
         r"""#include <stdio.h>
#include <string.h>
static long rec(long n){ char pad[4096]; memset(pad,n&0xff,sizeof pad);
  return n<=0 ? pad[0] : rec(n-1)+pad[1]; }   /* depth from the input: unbounded recursion */
int main(void){ setvbuf(stdout,0,2,0);
  long n; printf("depth: "); if(scanf("%ld",&n)!=1) return 0;
  printf("%ld\n", rec(n)); return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=(), budget=300.0, mechanism="stack-exhaustion", strict_level=True,
         note="BUG CLASS uncontrolled recursion (CWE-674): the depth comes from the input, each "
              "frame is 4 KiB, and the guard page below the stack ends it. The fault address is "
              "the stack guard rather than anything the attacker chose, which is exactly why this "
              "is a denial of service and not a write primitive. Measured, the verdict machinery "
              "did NOT say so: a write fault in the guard page came back `root_cause/CWE-787`, "
              "\"invalid write\", severity high -- an out-of-bounds write lead for an address the "
              "input never chose. `classify` now recognises a fault immediately below the "
              "[stack] mapping as CWE-674 and `exploitability` offers it no write primitive."),

    Case("alloc_size_dos",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  unsigned long n; printf("size: "); if(scanf("%lu",&n)!=1) return 0;
  char *p = malloc(n);                      /* attacker-chosen allocation, unbounded */
  if(!p){ printf("alloc failed\n"); return 1; }
  memset(p,'A',1); printf("ok %lu\n", n); free(p); return 0; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=1, want_cwe=(), budget=300.0, mechanism="resource-exhaustion",
         strict_level=True,
         note="BUG CLASS allocation size from untrusted input (CWE-789/770). Measured with "
              "--ceiling: L1 -- the fuzzer drives the size past what malloc will serve, the "
              "unchecked NULL turns the memset that follows into a write through it, and the "
              "crash reproduces. The magnitude family: "
              "the attacker chooses how much memory the process asks for, and there is nothing to "
              "hijack -- the honest ceiling for this class is a reproduced resource fault, and the "
              "measurement is what sets the demand."),

    Case("memory_leak",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  char line[64];
  while(fgets(line,sizeof line,stdin)){
    char *p = malloc(4096);                 /* one per request, never freed */
    if(!p) return 1;
    strncpy(p,line,16);
    if(line[0]=='q') break; }
  printf("done\n"); return 0; }""",
         [], as_source=True,
         want_level=1, want_cwe=("CWE-401",), budget=300.0, mechanism="resource-exhaustion",
         strict_level=True,
         note="BUG CLASS memory leak (CWE-401): an allocation per request that is never freed. "
              "Never crashes, so crash-centric stages are blind to it, and valgrind (the classic "
              "oracle) is glibc-version coupled. CLOSED by a dedicated LeakSanitizer build, so the "
              "case is ingested AS SOURCE (like the MSan/TSan cases) -- the -fsanitize=leak build is "
              "only made on a source drop. ingest compiles a `-fsanitize=leak` binary with a baked "
              "`__lsan_default_options` (symbolize=0, so the replay does not deadlock the symbolizer); "
              "LSAN_OPTIONS governs it, so the pipeline-wide ASAN_OPTIONS detect_leaks=0 does not "
              "silence it. `lsan_detonate` drives the corpus -- plus a guaranteed-allocating probe -- "
              "against it, so a benign input reaches the malloc and LSan reports the leak at exit; "
              "parse_asan_report classifies it CWE-401, filed 'corroborated'. The leak run is tagged "
              "isolation=lsan, so `replay_exe_for` replays against the LSan build and `build_poc` "
              "verifies the report (a code-23 exit, not a signal) into an L1 PoC."),

    Case("invalid_free",
         r"""#include <stdio.h>
#include <stdlib.h>
int main(void){ setvbuf(stdout,0,2,0);
  char buf[64]; char *p = buf;
  int n; printf("n: "); if(scanf("%d",&n)!=1) return 0;
  if(n>0){ p = malloc(64); if(!p) return 1; }
  free(p);                                  /* n <= 0 frees a STACK pointer */
  printf("freed\n"); return 0; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=1, want_cwe=(), budget=300.0, mechanism="lifetime", strict_level=True,
         note="BUG CLASS free of a non-heap pointer (CWE-590). glibc detects it and aborts, so the "
              "signal is SIGABRT with an allocator message -- the lifetime family's third member "
              "(after use-after-free and double free) and the one with no case. `memoracle` "
              "already maps it; nothing asserted it end to end."),

    Case("int_underflow_alloc",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  char hdr[32]; printf("len: ");
  if(!fgets(hdr,sizeof hdr,stdin)) return 0;
  size_t len = (size_t)strtoul(hdr,0,10);
  char *p = malloc(64);
  if(!p) return 1;
  size_t pad = 16 - len;                    /* len > 16 UNDERFLOWS to a huge count */
  memset(p,'A',pad);                        /* ...and the copy runs off the end */
  printf("padded %zu\n", pad); free(p); return 0; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=1, want_cwe=(), budget=300.0, mechanism="integer-overflow", strict_level=True,
         note="BUG CLASS integer UNDERFLOW (CWE-191). The mirror of int_overflow_alloc and a "
              "different weaponization story: a wrap in the ALLOCATION under-allocates and can be "
              "aimed (see int_overflow_fnptr), while a wrap in a LENGTH produces a count near "
              "SIZE_MAX, so the copy faults at once and there is nothing to place. L1 is the "
              "honest ceiling for this shape, and recording that is the point of the case."),

    Case("unchecked_malloc",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  char line[128]; printf("size: ");
  if(!fgets(line,sizeof line,stdin)) return 0;
  size_t n = (size_t)strtoull(line,0,10);
  char *p = malloc(n);                       /* return value never checked */
  printf("data: "); if(!fgets(line,sizeof line,stdin)) return 0;
  size_t k = strlen(line); if(k > n) k = n;  /* the COPY is bounded: no overflow here */
  memcpy(p,line,k);                          /* p is NULL when the allocation was refused */
  printf("%zu\n", k); free(p); return 0; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=1, want_cwe=(), budget=300.0, mechanism="unchecked-return", strict_level=True,
         note="BUG CLASS unchecked return value (CWE-252/391): malloc's NULL is never tested, so "
              "an allocation the attacker makes fail turns the next copy into a write through "
              "NULL. The copy is deliberately BOUNDED by the allocation: the first version of "
              "this fixture used `strcpy` and the fuzzer found the unbounded copy instead, "
              "reporting CWE-122 -- a real defect, and not the one the case is for. What the "
              "pipeline reports now is the dereference (CWE-476), which is the manifestation; "
              "naming the missing CHECK would need the allocation and the fault tied together, "
              "and that is a labelling gap this case pins rather than closes."),

    Case("hardcoded_secret",
         r"""#include <stdio.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  char pw[64]; printf("password: ");
  if(!fgets(pw,sizeof pw,stdin)) return 0;
  pw[strcspn(pw,"\n")]=0;
  if(!strcmp(pw,"s3cr3t-admin-9931")){      /* the credential is IN the binary */
    printf("LYKOS{access-granted}\n"); return 0; }
  printf("denied\n"); return 1; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=0, want_cwe=(), want_static_cwe=("CWE-798",), budget=300.0,
         mechanism="hardcoded-secret", known_gap=True,
         note="BUG CLASS hardcoded credential (CWE-798). No memory is corrupted and nothing "
              "crashes: the defect IS the string in .rodata, and the demonstrated effect is the "
              "authentication it passes. Unlike every other case here the win needs no exploit at "
              "all -- just reading the binary and typing what it says -- which is precisely why a "
              "crash-centric pipeline can miss it entirely. MEASURED HOLE: `hardcoded_secrets` "
              "files nothing here. It looks for a secret-SHAPED value (an assignment to a "
              "password-ish name, high-entropy base64/hex), and a plaintext credential compared "
              "with `strcmp` against a string literal has neither shape -- the evidence is the "
              "COMPARISON, not the string. Nothing else in the pipeline reads it either, so the "
              "case records the hole: the fixture, and the measurement that the detector misses it."),

    Case("race_counter",
         r"""#include <stdio.h>
#include <pthread.h>
static int counter;                          /* no mutex, no atomics */
static void *bump(void *a){ for(int i=0;i<200000;i++) counter++; return 0; }
int main(void){ setvbuf(stdout,0,2,0);
  pthread_t t[4];
  for(int i=0;i<4;i++) pthread_create(&t[i],0,bump,0);
  for(int i=0;i<4;i++) pthread_join(t[i],0);
  printf("%d\n", counter); return 0; }""",
         ["-lpthread"], as_source=True,
         want_level=1, want_cwe=("CWE-362",), budget=360.0, mechanism="race", strict_level=True,
         note="BUG CLASS data race (CWE-362): four threads increment one unsynchronised counter. "
              "TSAN is the only oracle that sees it -- the program never crashes and prints a "
              "plausible-looking number -- so this is handed over as SOURCE for the platform's own "
              "sanitizer build. Measured: `tsan/CWE-362` at L1, which is the family's ceiling by "
              "construction -- a race is a scheduling fact, not an attacker-chosen write."),

    # THE CHAIN THAT DOES NOT FIT. Every L2->L3 route in this engine puts its chain where the
    # overflow lands, and a `read` with a fixed count that stops just after the frame leaves room
    # for the return address and nothing else: a 3-word system("/bin/sh") chain cannot be placed
    # there at any offset, so the honest verdict was an L2 primitive and no L3. The pivot moves
    # the stack instead of filling it.
    Case("stack_pivot_shell",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
char cmd[64] = "/bin/sh";            /* a command string at a fixed address (no-PIE) */
/* Writable space BELOW the chain, which is what the pivoted stack actually needs: measured,
   `system()` segfaults with 192, 448 or 960 bytes under it and spawns a shell with 1984. The
   slack does not have to be inside the buffer -- the stack keeps growing past the buffer's start
   into whatever is mapped writable there, which is what these 8 KiB of other globals are. */
static char pad[8192];
static char notes[256];              /* the buffer field ONE lands in: the chain's home */
/* A tiny -O0 binary contains no `pop rdi; ret` anywhere, while a real one has thousands of
   gadgets -- so the fixture plants the one the chain needs rather than making gadget scarcity
   the defect under test. */
__attribute__((naked, used)) void gadgets(void){ __asm__("pop %rdi; ret"); }
/* A framed read: exactly n bytes. A single `read` of a pipe returns whatever has arrived, which
   made the measured control offset differ run to run (3499, 2416, 2831); a fixed count does not. */
static void read_exact(char *p, size_t n){ size_t g = 0;
  while (g < n) { ssize_t r = read(0, p + g, n - g); if (r <= 0) break; g += (size_t)r; } }
static void use(const char *src){ char small[64]; memcpy(small, src, 80); printf("ok %.64s\n", small); }
int main(void){ setvbuf(stdout,0,2,0);
  system("true");                     /* a program that shells out once: system@plt is RESOLVED */
  pad[0] = 1;                         /* keep the padding global (and its writable pages) */
  printf("note: "); read_exact(notes, sizeof notes);   /* field 1: the chain's home */
  char line[128];
  printf("name: "); ssize_t m = read(0, line, sizeof line - 1);
  if(m <= 0) return 0;
  use(line);                           /* copies exactly 80 bytes into 64: 64 + rbp + ret */
  return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=3, want_cwe=(), budget=480.0, mechanism="stack-overflow",
         note="TECHNIQUE stack pivot (doc 38, item 1). `use()` copies exactly 80 bytes into a "
              "64-byte frame: the write reaches the saved return address and carries ONE word past "
              "it, so the chain it needs -- pop rdi, &\"/bin/sh\", system@plt -- cannot be placed "
              "there at any offset. The chain lives in `notes`, which field ONE fills, and "
              "`leave; ret` moves rsp there. Four things were measured the hard way. `offset` is "
              "the distance to the RETURN ADDRESS, so the saved RBP goes one word BELOW it -- "
              "writing it into the return slot returns to the buffer's own address and segfaults. "
              "The pivoted stack is used by every function the chain CALLS, so the chain sits high "
              "in the buffer with slack underneath: with it at the buffer's start the pivot "
              "worked, pop rdi and system@plt both ran, and the process died inside "
              "`_dl_runtime_resolve_xsavec`, which needs hundreds of bytes below the call and a "
              "64-byte-aligned save area -- which is also why this program calls `system(\"true\")` "
              "once at startup, so the slot is already resolved. And `system()` itself needs room: "
              "measured, 192, 448 and 960 bytes of slack all segfault and 1984 spawns a shell -- "
              "but the space that counts is WRITABLE MEMORY BELOW the chain rather than space "
              "inside the buffer, which is what the 8 KiB `pad` global supplies for a 256-byte "
              "`notes`. "
              "A single `read` of a pipe returns whatever has arrived, so field one is read by "
              "COUNT: with a partial read the measured offset differed run to run. And a "
              "newline-framed first field would need PACED delivery, which the L2 cyclic probe "
              "cannot do -- it tries stdin, file and arg, so a defect reachable only through "
              "paced fields never gets a primitive measured at all (that gap is doc 38's own "
              "next item, and this case deliberately does not depend on it)."),

    # ---- THE CONTROLLED INGREDIENT. Several classes sit at L1 only because the fixture withholds
    # the one thing that makes them exploitable, not because the class caps there. A write through
    # NULL is a denial of service; the same missing check with an attacker-chosen OFFSET is
    # address control. Bytes staged in an executable page are a TTP; the same page CALLED is code
    # execution. These cases supply the ingredient and demand the rung it buys.
    Case("unchecked_malloc_offset",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  char line[64];
  printf("size: "); if(!fgets(line,sizeof line,stdin)) return 0;
  size_t n = (size_t)strtoull(line,0,10);
  long *p = malloc(n);                       /* return value never checked */
  printf("slot: "); if(!fgets(line,sizeof line,stdin)) return 0;
  long i = strtol(line,0,10);                /* ...and the index is the attacker's */
  p[i] = 0x4141414141414141L;                /* so the faulting ADDRESS is chosen, not NULL */
  printf("ok\n"); return 0; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=2, want_cwe=(), budget=360.0, mechanism="unchecked-return",
         strict_level=True,
         note="BUG CLASS unchecked return + attacker-chosen offset (CWE-252 -> CWE-787). "
              "`unchecked_malloc` measures L1 because every fault is at address 0: a denial of "
              "service, and the address-control verdict correctly refuses to call a fixed address "
              "a primitive. Here the SAME missing check is paired with an index the input "
              "supplies, so the fault address moves with the input -- which is the definition the "
              "address-control verdict was built on, and the rung the pair earns."),

    Case("jit_page_executed",
         r"""#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
int main(void){ setvbuf(stdout,0,2,0);
  void *pg = mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if(pg == MAP_FAILED) return 1;
  char b[256]; printf("code: ");
  ssize_t n = read(0, b, sizeof b);
  if(n <= 0) return 0;
  memcpy(pg, b, (size_t)n);
  mprotect(pg, 0x1000, PROT_READ|PROT_EXEC);   /* a plugin/JIT loader: the page is made code... */
  ((void(*)(void))pg)();                       /* ...and CALLED */
  printf("returned\n"); return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=3, want_cwe=(), budget=420.0, mechanism="code-injection",
         strict_level=True,
         note="BUG CLASS code injection (CWE-94) where the program does the hard part itself: a "
              "plugin/JIT loader copies the input into a page it then makes executable AND CALLS. "
              "Every strategy in the stage was wrong for this shape. `_mprotect_shellcode` BUILDS "
              "this situation with a ROP chain and so needs gadgets, an overflow offset and an "
              "analyst-supplied page symbol -- none of which exist here, because the program "
              "already did the work; and everything else needs a saved return address to "
              "overwrite, when this program hands control over on purpose. Measured before the "
              "fix: L2. The pipeline found the input being executed (it crashes on whatever the "
              "fuzzer sent), classified the fault as a memory error and stopped, because nothing "
              "asked whether bytes WE choose would do something instead of crashing. The answer "
              "is 25 bytes of position-independent execve(\"/bin/sh\") on stdin -- no offset, no "
              "gadget, no leak -- so `_self_exec_exploit` runs before every strategy that needs "
              "an offset, gated on an mprotect/mmap import, and confirms with an int3 negative "
              "control at the same length so a target that merely echoes the marker cannot pass. "
              "Measured after: PASS L3, build_exploit/CWE-94, 103s."),

    # ---- SECOND WAVE: mechanisms whose DETECTOR may or may not exist. Each of these lands at
    # want_level=0 / want_cwe=() for the same reason as the wave above -- the case is the
    # measurement -- and for several of them the honest outcome is "nothing files this today",
    # which is a HOLE the matrix should show rather than a row it should omit.
    Case("untrusted_pointer",
         r"""#include <stdio.h>
#include <stdlib.h>
int main(void){ setvbuf(stdout,0,2,0);
  char line[64]; printf("addr: ");
  if(!fgets(line,sizeof line,stdin)) return 0;
  unsigned long a = strtoul(line,0,0);
  unsigned long *p = (unsigned long *)a;   /* an ADDRESS straight from the input */
  printf("%lu\n", *p); return 0; }         /* ...dereferenced */""",
         ["-no-pie", "-O0", "-w"],
         want_level=2, want_cwe=(), budget=300.0, mechanism="untrusted-pointer",
         strict_level=True,
         note="BUG CLASS untrusted pointer dereference (CWE-822/823): the input IS the address. "
              "The strongest shape of attacker control there is -- no overflow, no groom, the "
              "faulting address is chosen outright -- which is exactly what the address-control "
              "verdict was built to recognise, and no case asserted it. Measured with --ceiling: "
              "L2 -- `primitive/CWE-476` plus `tainted_deref/CWE-125`, an address-control "
              "primitive confirmed from the fault address across input variants. L3 would need "
              "somewhere worth pointing it, and a read of one word is not a write."),

    Case("toctou_access",
         r"""#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(void){ setvbuf(stdout,0,2,0);
  char name[128], path[256]; char buf[256];
  printf("file: "); if(!fgets(name,sizeof name,stdin)) return 0;
  name[strcspn(name,"\n")]=0;
  snprintf(path,sizeof path,"/tmp/lykos_toctou/%s", name);
  if(access(path, R_OK) != 0){ printf("denied\n"); return 1; }   /* check... */
  FILE *f=fopen(path,"rb");                                      /* ...then use: a race */
  if(!f){ printf("gone\n"); return 1; }
  size_t n=fread(buf,1,sizeof buf-1,f); buf[n]=0; fclose(f);
  printf("%s", buf); return 0; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=0, want_cwe=(), budget=300.0, mechanism="race", known_gap=True,
         note="BUG CLASS TOCTOU file race (CWE-367): the path is checked with access() and then "
              "opened, so a symlink swapped in between gets the open. Winning it needs a second "
              "process the prober does not have, which is the point of the case: the DETECTION "
              "has to come from the pattern (check-then-use on the same path), not from a crash. "
              "MEASURED HOLE: nothing files it. `toctou` and `toctou_race` are in the static "
              "detector set and both read SOURCE; this is a binary, and no stage looks for the "
              "access()-then-open() pair in a disassembly. The only finding is `dangerous_api`, "
              "which does not name this defect."),

    Case("temp_file",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  char tmpl[] = "/tmp/lykosXXXXXX";
  char *name = mktemp(tmpl);               /* predictable name, race to create it */
  if(!name || !*name) return 1;
  FILE *f = fopen(name,"w");               /* no O_EXCL: an attacker can pre-create it */
  if(!f) return 1;
  char line[64]; printf("note: ");
  if(fgets(line,sizeof line,stdin)) fputs(line,f);
  fclose(f); printf("wrote %s\n", name); remove(name); return 0; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=0, want_cwe=(), want_static_cwe=("CWE-377",), budget=240.0,
         mechanism="temp-file",
         note="BUG CLASS insecure temporary file (CWE-377): mktemp hands back a name and the open "
              "that follows has no O_EXCL, so the window between them is the bug. mktemp is a "
              "libc function the linker itself warns about, so the import alone is evidence -- "
              "this measures whether anything in the pipeline says so."),

    Case("weak_prng_token",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main(void){ setvbuf(stdout,0,2,0);
  srand((unsigned)time(0));                /* seeded from the clock: guessable */
  printf("token %d\n", rand());            /* ...and used as a secret */
  char line[64]; printf("guess: ");
  if(!fgets(line,sizeof line,stdin)) return 0;
  printf("%s\n", atoi(line)==rand() ? "LYKOS{predicted}" : "no"); return 0; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=0, want_cwe=(), want_static_cwe=("CWE-330",), budget=240.0,
         mechanism="weak-crypto",
         note="BUG CLASS cryptographically weak PRNG used for a secret (CWE-338/330). Nothing "
              "crashes and no memory is touched: the defect is that rand() seeded from time() is "
              "predictable, so the token can be computed rather than brute-forced. Detecting it "
              "is an IMPORT question (srand/rand reaching a value treated as a secret) and "
              "demonstrating it needs a predictor, which is a capability this measures the "
              "absence of."),

    Case("search_path_hijack",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  char line[64]; printf("mode: ");
  if(!fgets(line,sizeof line,stdin)) return 0;
  if(line[0]=='l') system("ls /tmp >/dev/null");   /* RELATIVE program name: PATH decides */
  else system("date >/dev/null");
  printf("ran\n"); return 0; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=0, want_cwe=(), budget=240.0, mechanism="search-path", known_gap=True,
         note="BUG CLASS untrusted search path (CWE-426/427): system() with a relative program "
              "name resolves through PATH, so whoever controls the environment chooses the "
              "binary. The input does not even have to be attacker-controlled for this to be a "
              "finding, which is why it is a different mechanism from command injection -- the "
              "same sink, a different thing wrong with it. MEASURED HOLE: the only evidence is "
              "`dangerous_api/CWE-78` -- \"system() is dangerous\" -- which is the SINK and not "
              "this defect: it does not distinguish a relative program name (whoever controls "
              "PATH chooses the binary, with no attacker input at all) from an injected argument. "
              "Asserting CWE-78 here would be asserting the wrong mechanism."),

    Case("redos_regex",
         r"""#include <stdio.h>
#include <string.h>
#include <regex.h>
int main(void){ setvbuf(stdout,0,2,0);
  regex_t re;
  if(regcomp(&re, "^(a+)+$", REG_EXTENDED)) return 1;   /* nested quantifier */
  char line[256]; printf("subject: ");
  if(!fgets(line,sizeof line,stdin)) return 0;
  line[strcspn(line,"\n")]=0;
  printf("%s\n", regexec(&re,line,0,0,0)==0 ? "match" : "no match");
  regfree(&re); return 0; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=0, want_cwe=(), budget=300.0, mechanism="redos", known_gap=True,
         note="BUG CLASS catastrophic backtracking (CWE-1333): a nested quantifier against a long "
              "non-matching subject takes exponential time, so the input makes the program HANG "
              "rather than crash. A timeout is the only oracle, and a timeout is the one outcome "
              "a fuzzer is built to discard as flaky -- this measures which way that goes. "
              "MEASURED HOLE: it goes the discarding way. 300s of the real autopilot produced no "
              "finding for the hang; the only one filed is `dangerous_api/CWE-134`, which is "
              "about printf-family calls and not about this at all."),

    # ---- THIRD WAVE. Each of these is a mechanism whose WEAPONIZATION story differs from its
    # nearest neighbour, which is the test for being its own row: a negative index reaches what
    # lies BEFORE a buffer (saved registers, the canary, the preceding global) where an unchecked
    # positive one reaches what lies after; a signed length that becomes huge is a different fix
    # from a product that wraps; a function pointer read out of a FILE needs no corruption at all.
    Case("deserialize_fnptr",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void win(void){ execl("/bin/sh","sh",(char*)0); }
struct state { void (*render)(void); char name[32]; };
static void plain(void){ printf("plain\n"); }
int main(int argc, char **argv){ setvbuf(stdout,0,2,0);
  struct state s; s.render = plain; strcpy(s.name,"new");
  if(argc > 1){ FILE *f = fopen(argv[1],"rb");
    if(f){ fread(&s, 1, sizeof s, f); fclose(f); } }   /* a FUNCTION POINTER out of the file */
  printf("%.32s\n", s.name);
  s.render();                                          /* ...and called */
  return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=0, want_cwe=(), budget=420.0, mechanism="deserialization",
         note="BUG CLASS unsafe deserialisation (CWE-502) in C, which is what `fread` of a struct "
              "IS: the saved state carries a function pointer and the file restores it. No "
              "overflow, no groom, no leak -- the control value is a field, and the only thing "
              "between the input and the call is that someone trusted the file. The channel is a "
              "FILE rather than stdin, which is also the point: a cache or session file is the "
              "classic place this is forgotten."),

    Case("buffer_underwrite",
         r"""#include <stdio.h>
long before = 0x1234;                        /* what lies BEFORE the table */
long table[8];
int main(void){ setvbuf(stdout,0,2,0);
  long i, v;
  printf("idx: "); if(scanf("%ld",&i)!=1) return 0;
  printf("val: "); if(scanf("%ld",&v)!=1) return 0;
  if(i < 8) table[i] = v;                    /* bound on the HIGH side only */
  printf("before=%ld table0=%ld\n", before, table[0]); return 0; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=0, want_cwe=(), budget=300.0, mechanism="buffer-underwrite",
         note="BUG CLASS buffer underwrite (CWE-124/786): the index is bounded on the HIGH side "
              "only, so a negative one writes BEFORE the array. A different weaponization story "
              "from the unchecked positive index: what lies before a buffer is the saved frame, "
              "the canary or the preceding global, and the reach is backwards -- which is why the "
              "boundary values an index probe drives have to include negatives at all."),

    Case("signedness_length",
         r"""#include <stdio.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  char dst[64]; char src[256]; memset(src,'A',sizeof src);
  int n; printf("len: "); if(scanf("%d",&n)!=1) return 0;
  if(n < 64) memcpy(dst, src, (size_t)n);    /* n == -1 passes the check, then becomes huge */
  printf("copied %d\n", n); return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=0, want_cwe=(), budget=300.0, mechanism="signedness",
         note="BUG CLASS signed-to-unsigned conversion (CWE-195/196). The bound check is SIGNED "
              "and the copy length is UNSIGNED, so a negative value passes the check and arrives "
              "at memcpy as something near SIZE_MAX. Distinct from an overflow in a product: the "
              "arithmetic is correct, the TYPE is wrong, and the fix is a different line."),

    Case("stack_address_return",
         r"""#include <stdio.h>
#include <string.h>
static char *make(const char *in){ char buf[64]; strncpy(buf,in,63); buf[63]=0; return buf; }
int main(void){ setvbuf(stdout,0,2,0);
  char line[64]; printf("name: ");
  if(!fgets(line,sizeof line,stdin)) return 0;
  char *p = make(line);                      /* a pointer to a DEAD frame */
  printf("hi %.63s\n", p); return 0; }""",
         [], as_source=True,
         want_level=0, want_cwe=(), budget=420.0, mechanism="dangling-stack",
         note="BUG CLASS return of a stack address (CWE-562) -> use after return. The frame is "
              "gone the moment `make` returns, and whether the bytes survive to the printf is a "
              "matter of what the next call reuses -- so the plain build often prints the right "
              "answer and the defect is invisible. ASan's `detect_stack_use_after_return` is the "
              "oracle, which is why this is handed over as SOURCE."),

    Case("decompression_bomb",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
int main(void){ setvbuf(stdout,0,2,0);
  static unsigned char in[1<<16]; size_t n = fread(in,1,sizeof in,stdin);
  if(!n) return 0;
  z_stream z; memset(&z,0,sizeof z);
  if(inflateInit(&z) != Z_OK) return 1;
  z.next_in = in; z.avail_in = (unsigned)n;
  unsigned long total = 0;
  static unsigned char out[1<<16];
  for(;;){ z.next_out = out; z.avail_out = sizeof out;
    int r = inflate(&z, Z_NO_FLUSH);
    total += sizeof out - z.avail_out;       /* no cap on the OUTPUT size */
    if(r == Z_STREAM_END || r < 0) break;
    if(z.avail_in == 0 && z.avail_out != 0) break; }
  inflateEnd(&z);
  printf("inflated %lu\n", total); return 0; }""",
         ["-no-pie", "-O0", "-w", "-lz"], requires=("/usr/include/zlib.h",),
         want_level=0, want_cwe=(), budget=300.0, mechanism="decompression-bomb",
         note="BUG CLASS decompression bomb (CWE-409): the inflate loop has no cap on the output "
              "it will produce, so a small input decides how much work the process does. The "
              "defect is a RATIO, not a fault -- nothing is corrupted and nothing crashes -- so "
              "the oracle has to be resource accounting rather than a signal."),

    Case("cert_validation",
         r"""#include <stdio.h>
#include <openssl/ssl.h>
int main(void){ setvbuf(stdout,0,2,0);
  SSL_library_init();
  SSL_CTX *c = SSL_CTX_new(TLS_client_method());
  if(!c) return 1;
  SSL_CTX_set_verify(c, SSL_VERIFY_NONE, 0);  /* the peer's certificate is never checked */
  printf("ctx ready\n"); SSL_CTX_free(c); return 0; }""",
         ["-no-pie", "-O0", "-w", "-lssl", "-lcrypto"],
         requires=("/usr/include/openssl/ssl.h",),
         want_level=0, want_cwe=(), budget=240.0, mechanism="cert-validation",
         note="BUG CLASS improper certificate validation (CWE-295): the context is told not to "
              "verify the peer. Nothing crashes, nothing leaks locally, and there is no input at "
              "all -- the defect is a CONSTANT passed to one call, which makes it the cleanest "
              "test of whether this platform can say anything about a configuration defect."),

    # ---- INJECTION. A whole bug family the platform has probes for (command, path, SQL, XXE,
    # SSRF) and which nothing asserted: these need no memory corruption at all, so none of the
    # crash machinery above would ever surface them.
    Case("uninit_pointer_leak",
         r"""#include <stdio.h>
#include <string.h>
static void greet(void){ puts("hello"); }
struct session { void (*cb)(void); char name[24]; long id; };
static void setup(void){ struct session s; s.cb=greet; strcpy(s.name,"admin"); s.id=7;
  printf("session %ld ready\n", s.id); }          /* the frame dies here, with its pointer in it */
static void dump(void){ char b[64]; fwrite(b,1,sizeof b,stdout); }   /* never initialised */
int main(void){ setvbuf(stdout,0,2,0); setup(); dump(); return 0; }""",
         # PIE on purpose: a leaked code pointer only MEANS something where the image base is
         # randomised, and that is the claim -- ASLR defeated by a read that never faults.
         ["-fPIE", "-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=2, want_cwe=("CWE-457", "CWE-200", "CWE-908"), budget=300.0,
         mechanism="uninitialised",
         strict_level=True,
         note="BUG CLASS uninitialised read WEAPONIZED (CWE-457/908 -> CWE-200 -> L2). Measured "
              "with --ceiling, uninit_stack_read stops at L0: memcheck proves undefined bytes "
              "reached a write syscall, and that was the end of what could be said. The whole L2 "
              "disclosure ladder hangs off a FAULT -- an MSan build aborts in the read, which is "
              "how the src_uninit_* cases reach L2 -- so on a plain binary the class had no path "
              "to a primitive however good the leaked bytes were. The difference that decides it "
              "is WHAT the residue is: `setup`'s dead frame holds a code pointer, `dump` writes "
              "the frame out raw, and leak.disclosed_bases recovers the image base from it -- "
              "validated against this binary's own symbol layout, not against a second run "
              "(residue cannot be told from residue that way). A padding leak still files as "
              "CWE-200 and stays there, which is a result, not a failure."),

    Case("cmd_injection",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  char host[128], cmd[256];
  printf("host: "); if(!fgets(host,sizeof host,stdin)) return 0;
  host[strcspn(host,"\n")]=0;
  snprintf(cmd,sizeof cmd,"ping -c1 %s", host);   /* user text spliced into a shell command */
  return system(cmd); }""",
         ["-no-pie", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-78", "CWE-77", "CWE-88"), budget=300.0,
         mechanism="command-injection",
         strict_level=True,
         note="INJECTION command (CWE-78): user input spliced into system(). L3, and measured at "
              "L1 before this round: the probe's oracle requires the marker to appear WITHOUT the "
              "literal `echo <marker>` in the output, so the only way it fires is that the shell "
              "RAN our command -- demonstrated remote code execution. Everything here was filed "
              "L1 because the ladder was built around crashes, where L1 is a verified crash and "
              "the effect is two rungs further on; for an injection the oracle IS the effect."),

    Case("path_traversal",
         r"""#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
int main(void){ setvbuf(stdout,0,2,0);
  char name[128], path[256]; char buf[256];
  /* The base directory must EXIST, or no ../ can resolve THROUGH it and the traversal is
     undemonstrable no matter how good the prober is (open() needs every component to exist). */
  mkdir("/tmp/lykos_pt_data", 0755);
  printf("file: "); if(!fgets(name,sizeof name,stdin)) return 0;
  name[strcspn(name,"\n")]=0;
  snprintf(path,sizeof path,"/tmp/lykos_pt_data/%s", name);   /* no ../ rejection */
  FILE *f=fopen(path,"rb"); if(!f){ printf("no such file\n"); return 1; }
  size_t n=fread(buf,1,sizeof buf-1,f); buf[n]=0; fclose(f);
  printf("%s", buf); return 0; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-22", "CWE-23", "CWE-36"), budget=300.0,
         mechanism="path-traversal",
         strict_level=True,
         note="INJECTION path traversal (CWE-22): user name concatenated into a path under a base "
              "directory that EXISTS, so ../ actually resolves and the read can be demonstrated. "
              "L3, and measured at L1 before this round: the oracle is /etc/passwd's own content "
              "coming back, which is the attacker's end goal -- an arbitrary file read -- and not "
              "a step toward one. A memory leak is levelled differently and deliberately: "
              "pointer-shaped words out of a stack are chain material, so the format string is "
              "levelled by what its leak RESOLVES."),

    Case("sql_injection",
         r"""#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
int main(void){ setvbuf(stdout,0,2,0);
  sqlite3 *db; if(sqlite3_open(":memory:", &db)) return 1;
  sqlite3_exec(db, "CREATE TABLE users(name TEXT, pw TEXT);"
                   "INSERT INTO users VALUES('admin','s3cret');", 0, 0, 0);
  char user[128], q[384];
  printf("user: "); if(!fgets(user,sizeof user,stdin)) return 0;
  user[strcspn(user,"\n")]=0;
  snprintf(q,sizeof q,"SELECT pw FROM users WHERE name='%s'", user);   /* unescaped */
  char *err=0; sqlite3_exec(db, q, 0, 0, &err);                        /* recognised SQL sink */
  printf("done%s%s\n", err?": ":"", err?err:""); sqlite3_close(db); return 0; }""",
         ["-no-pie", "-O0", "-w", "-lsqlite3"],
         want_level=0, want_cwe=("CWE-89", "CWE-943"), budget=300.0,
         requires=("/usr/include/sqlite3.h",),
         note="The L3 rule applies here too and could NOT be measured on this host (sqlite3 headers absent, so the case SKIPs): the demand stays at the level that was measured. INJECTION SQL (CWE-89) through sqlite3_exec, a sink the prober recognises. SKIPS "
              "where sqlite3 headers are absent -- an untested sink is not a broken one"),

    Case("xxe_injection",
         r"""#include <stdio.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
int main(void){ setvbuf(stdout,0,2,0);
  static char doc[8192];
  size_t n = fread(doc, 1, sizeof doc - 1, stdin); doc[n] = 0;
  /* NOENT|DTDLOAD enables external entity expansion: an entity pointing at a local file is read
     and echoed back, which is the XXE disclosure. */
  xmlDocPtr d = xmlReadMemory(doc, (int)n, "in.xml", NULL,
                              XML_PARSE_NOENT | XML_PARSE_DTDLOAD | XML_PARSE_NONET);
  if(!d){ printf("parse failed\n"); return 1; }
  xmlNodePtr r = xmlDocGetRootElement(d);
  xmlChar *txt = r ? xmlNodeGetContent(r) : NULL;
  printf("content: %s\n", txt ? (char*)txt : "(none)");
  if(txt) xmlFree(txt);
  xmlFreeDoc(d); xmlCleanupParser(); return 0; }""",
         ["-no-pie", "-O0", "-w", "-I/usr/include/libxml2", "-lxml2"],
         want_level=3, want_cwe=("CWE-611", "CWE-827", "CWE-200"),
         mechanism="xxe", budget=300.0,
         requires=("/usr/include/libxml2/libxml/parser.h",),
         strict_level=True,
         note="L3, measured at L1 before this round: the oracle is /etc/passwd's own content arriving through a SYSTEM entity, which is the file read itself and not a step toward one. INJECTION XXE (CWE-611) through xmlReadMemory with entity expansion enabled"),

    #: XInclude is NOT an XXE variant. This parser applies the standard XXE fix -- no
    #: XML_PARSE_NOENT, so external entities are never substituted -- and is still exposed.
    Case("xinclude_disclosure",
         r"""#include <stdio.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/xinclude.h>
#include <libxml/tree.h>
int main(void){ setvbuf(stdout,0,2,0);
  static char doc[8192];
  size_t n = fread(doc, 1, sizeof doc - 1, stdin); doc[n] = 0;
  /* NO XML_PARSE_NOENT: external entities are NOT substituted, which is the accepted XXE fix.
     XInclude is a separate feature and reads files anyway. */
  xmlDocPtr d = xmlReadMemory(doc, (int)n, "in.xml", NULL, XML_PARSE_NONET);
  if(!d){ printf("parse failed\n"); return 1; }
  xmlXIncludeProcess(d);
  xmlChar *out = NULL; int len = 0;
  xmlDocDumpMemory(d, &out, &len);
  printf("doc: %.*s\n", len, out ? (char*)out : "");
  if(out) xmlFree(out);
  xmlFreeDoc(d); xmlCleanupParser(); return 0; }""",
         ["-no-pie", "-O0", "-w", "-I/usr/include/libxml2", "-lxml2"],
         want_level=3, want_cwe=("CWE-611", "CWE-827", "CWE-200"),
         mechanism="xxe", budget=300.0,
         requires=("/usr/include/libxml2/libxml/xinclude.h",),
         strict_level=True,
         note="INJECTION XInclude file disclosure (CWE-611) -- and the reason it is a probe of its "
              "own rather than another xxe payload. The accepted fix for XXE is to parse without "
              "XML_PARSE_NOENT so a SYSTEM entity is never substituted. This fixture does exactly "
              "that, and `xxe_injection`'s entity payload comes back with the entity UNEXPANDED "
              "(measured). XInclude is a separate libxml2 feature with its own file-reading power, "
              "so `<xi:include href=\"file:///etc/passwd\" parse=\"text\"/>` returns the file "
              "regardless -- measured on the same binary, same run. `parse=\"text\"` is load "
              "bearing: the default parse=\"xml\" tries to parse /etc/passwd AS XML and fails. The "
              "oracle is the file's own content, so this is L3 by the same reasoning as xxe: the "
              "disclosure IS the effect, not a step toward one."),

    #: Command execution in a binary with no `system` and no `popen` anywhere in it.
    Case("wordexp_command_substitution",
         r"""#include <stdio.h>
#include <string.h>
#include <wordexp.h>
int main(void){ setvbuf(stdout,0,2,0);
  char in[512]; printf("path: ");
  if(!fgets(in, sizeof in, stdin)) return 0;
  in[strcspn(in, "\n")] = 0;
  /* a "safe" path expander: no system(), no popen() -- but wordexp() performs the shell's own
     command substitution, so $(...) and backticks RUN. */
  wordexp_t we;
  if(wordexp(in, &we, 0) != 0){ printf("bad pattern\n"); return 1; }
  for(size_t i = 0; i < we.we_wordc; i++) printf("word: %s\n", we.we_wordv[i]);
  wordfree(&we); return 0; }""",
         ["-no-pie", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-78", "CWE-77"),
         mechanism="command-injection", budget=300.0,
         strict_level=True,
         note="INJECTION command execution with NO command-execution sink in the binary. The "
              "`command-injection` probe keys on system/popen/exec*; this target imports none of "
              "them, so nothing fired. `wordexp()` performs the shell's own expansions -- command "
              "substitution among them -- which makes it a command-execution sink that reads like "
              "a path utility. The payload set has to be its own, measured: `$(echo MARK)` and "
              "the backtick form both run, while the cmdi set's `; echo MARK` is REJECTED by "
              "wordexp as a syntax error (\"bad pattern\"), so reusing that payload list would "
              "have confirmed nothing. The oracle is the existing one and the right one -- the "
              "marker appears because the injected `echo` ran, and the literal `echo MARK` does "
              "not appear, which is what separates execution from an echo of our own input."),

    #: Query control proven by the evaluator's own error. CAPABILITY, not EFFECT -- see the note.
    Case("xpath_injection",
         r"""#include <stdio.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
static const char *DOC =
  "<users><user><name>alice</name><public>hello</public><secret>S3CRET-A</secret></user>"
  "<user><name>bob</name><public>world</public><secret>S3CRET-B</secret></user></users>";
int main(void){ setvbuf(stdout,0,2,0);
  char in[512]; printf("user: ");
  if(!fgets(in, sizeof in, stdin)) return 0;
  in[strcspn(in, "\n")] = 0;
  xmlDocPtr d = xmlReadMemory(DOC, (int)strlen(DOC), "d.xml", NULL, 0);
  xmlXPathContextPtr c = xmlXPathNewContext(d);
  char q[1024];
  /* the expression is CONCATENATED, so the input is part of the query, not a value in it */
  snprintf(q, sizeof q, "/users/user[name='%s']/public", in);
  xmlXPathObjectPtr o = xmlXPathEvalExpression((const xmlChar*)q, c);
  if(!o){ printf("xpath failed\n"); return 1; }
  if(o->nodesetval)
    for(int i = 0; i < o->nodesetval->nodeNr; i++){
      xmlChar *t = xmlNodeGetContent(o->nodesetval->nodeTab[i]);
      printf("row: %s\n", t ? (char*)t : ""); if(t) xmlFree(t); }
  xmlXPathFreeObject(o); xmlXPathFreeContext(c); xmlFreeDoc(d);
  xmlCleanupParser(); return 0; }""",
         ["-no-pie", "-O0", "-w", "-I/usr/include/libxml2", "-lxml2"],
         want_level=2, want_cwe=("CWE-643", "CWE-91"),
         mechanism="xpath-injection", budget=300.0,
         requires=("/usr/include/libxml2/libxml/xpath.h",),
         strict_level=True,
         note="INJECTION XPath (CWE-643), and a deliberate CAPABILITY verdict rather than an "
              "effect one. The expression is concatenated, so `x'] | //* | //a[name='` unions in "
              "node sets the original could never reach -- measured on this fixture, a lookup "
              "restricted to `public` returned every `secret` element in the document. But the "
              "generic oracle cannot be that: a probe does not know what the document holds, and "
              "XPath 1.0 gives an injected expression no way to make the engine emit a marker of "
              "OUR choosing -- `|` unions node sets and cannot introduce a literal, and there is "
              "no `document()` outside XSLT. So the confirmation is the evaluator's own error on "
              "an unbalanced quote (\"XPath error : Invalid predicate\"), which proves the string "
              "reaches the expression parser and which a target that binds or escapes its value "
              "never produces. That is control of the query -- L2 -- and the same rung, for the "
              "same reason, as error-based SQL injection's branch in `sqli_confirm`. Claiming "
              "demonstrated disclosure off a generic payload would be a guess about the document."),

    Case("ssrf_injection",
         r"""#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
int main(void){ setvbuf(stdout,0,2,0);
  char url[256];
  printf("url: "); if(!fgets(url,sizeof url,stdin)) return 0;
  url[strcspn(url,"\n")]=0;
  CURL *c = curl_easy_init(); if(!c) return 1;
  curl_easy_setopt(c, CURLOPT_URL, url);        /* user-controlled destination: SSRF */
  curl_easy_perform(c); curl_easy_cleanup(c); return 0; }""",
         ["-no-pie", "-O0", "-w", "-lcurl"],
         want_level=0, want_cwe=("CWE-918",), budget=300.0,
         requires=("/usr/include/curl/curl.h",),
         note="The L3 rule applies here too and could NOT be measured on this host (libcurl headers absent, so the case SKIPs): the demand stays at the level that was measured. INJECTION SSRF (CWE-918): a user-controlled URL handed to curl. SKIPS without curl "
              "headers"),

    # ---- ALTERNATE WEAPONIZATION. Only ret2win, format-%n and heap FSOP were ever asserted. These
    # are the no-leak / no-win shapes that force a different technique: a static binary with no
    # dynamic libc (ret2syscall / SROP), a dynamic one with no win() and no leak call
    # (ret2dlresolve), and an mprotect-reachable one (shellcode). want_level 2 asks for a
    # demonstrated PRIMITIVE (control of execution) rather than a full shell, which is the honest
    # bar for these: reaching L3 depends on gadget availability in the specific binary.
    Case("static_no_libc_overflow",
         r"""#include <stdio.h>
#include <unistd.h>
int main(void){ char b[64]; printf("in: ");
  if(scanf("%s", b) != 1) return 0;          /* no win(), no system(), statically linked */
  write(1, b, 8); return 0; }""",
         ["-static", "-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=1200.0,
         note="TTP static+no-PIE, no win/system: the ret2syscall / SROP shape (a dynamic ret2libc "
              "has no PLT to lean on here)"),

    #: SROP driven to L3. read() (not scanf) so the binary sigreturn frame -- NULs and all --
    #: actually reaches the buffer; static + no system + no "/bin/sh" so every earlier auto route
    #: (ret2system, execve-rop, shellcode-stack) is starved and SROP is the one left.
    Case("srop_execve_plant",
         r"""#include <unistd.h>
/* A stack overflow delivered by read(), statically linked, with no system(), no "/bin/sh" in the
   image, and NX on. ret2system has no PLT, execve-rop has no "/bin/sh", shellcode-stack has no
   executable stack -- so the auto dispatch falls through to SROP, which forges a sigreturn frame,
   PLANTS "/bin/sh" into .bss with a first syscall, then execve()s it. The statically-linked libc
   supplies the `syscall` and `pop rax; ret` gadgets. */
int main(void){ char buf[64]; read(0, buf, 512); return 0; }""",
         ["-static", "-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=1200.0,
         mechanism="stack-overflow", strict_level=True,
         note="TTP SROP to a live shell. The existing static_no_libc_overflow names this shape "
              "but caps at L1 because it delivers with scanf %s, which stops at whitespace and "
              "cannot carry a ~248-byte binary sigreturn frame (NULs, spaces); read() can. Forced "
              "as the route: static (no system PLT, no puts leak), no /bin/sh in the image "
              "(execve-rop needs one), NX on (no shellcode-stack) -- so the auto dispatch reaches "
              "SROP. rop.srop_feasible finds the syscall gadget, a pop-rax gadget and a writable "
              ".bss; with no /bin/sh present the plant path forges a frame that read()s /bin/sh "
              "into .bss, then a second frame execve()s it. Confirmed by a shell. SROP bypasses "
              "ASLR with no leak (the frame sets every register at once) and needs only the one "
              "syscall gadget."),

    #: ORW (open/read/write) to L3: a seccomp filter kills execve, so a shell finisher dies with
    #: SIGSYS and the autopilot must DISCLOSE a file instead -- leak libc via puts, then open/read/
    #: write a chain. The oracle is the disclosure (a random marker in a file the strategy plants).
    Case("orw_seccomp_disclose",
         r'''__asm__(".text\n.globl lykos_gadgets\nlykos_gadgets:\n.byte 0x5f,0xc3\n.byte 0x5e,0xc3\n.byte 0x5a,0xc3\n.byte 0xc3\n");
#include <stdio.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <linux/audit.h>
#include <stddef.h>
#include <errno.h>
/* A seccomp filter that KILLS execve/execveat, so a shell finisher dies with SIGSYS and the
   autopilot must disclose the flag with an open/read/write chain instead. open/read/write stay
   allowed. puts() is imported so the ORW path can leak libc exactly as ret2libc does. */
static void sandbox(void){
  struct sock_filter f[] = {
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 59, 1, 0),   /* execve */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 322, 0, 1),  /* execveat */
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog p = { .len = sizeof f/sizeof f[0], .filter = f };
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p);
}
int main(void){ setvbuf(stdout,0,2,0); sandbox();
  puts("go");                                   /* puts import -> leakable libc */
  char buf[64]; read(0, buf, 512); return 0; }  /* overflow */
''',
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=900.0,
         mechanism="stack-overflow", strict_level=True,
         note="TTP ORW (open/read/write) to a demonstrated file disclosure. A seccomp filter "
              "KILLS execve/execveat, so every shell finisher dies with SIGSYS -- the auto "
              "dispatch is gated on seccomp=on to take the ORW route instead. It leaks libc "
              "through puts() (lazy GOT, ASLR on) exactly as ret2libc would, then builds an "
              "open/read/write chain that opens a file the strategy plants (a random marker, "
              "absolute path because bwrap runs with cwd=/tmp), reads it, and writes it to "
              "stdout. Confirmation is the marker coming back -- the disclosure IS the effect, "
              "the same reasoning as the injection oracles. The pop rdi/rsi/rdx gadgets are "
              "present in the image (a real exploitable binary has them; a minimal one on glibc "
              "2.34+ does not, since the CSU gadgets were removed, so the fixture carries an "
              "explicit gadget block)."),

    #: ret2dlresolve to L3: no system PLT, no "/bin/sh", no leak -- forge a relocation and resolve
    #: system() through the dynamic linker. Lazy binding (partial/no RELRO) is the precondition.
    Case("ret2dlresolve_nolibc",
         r'''__asm__(".text\n.globl lykos_gadgets\nlykos_gadgets:\n.byte 0x5f,0xc3\n.byte 0x5e,0xc3\n.byte 0x5a,0xc3\n.byte 0xc3\n");
#include <unistd.h>
/* Dynamic, no-PIE, lazy binding (partial RELRO), a read() overflow, and NO puts/printf that
   leaks libc and NO system() -- so ret2libc-leak and ret2system both fail and the autopilot must
   forge a relocation and resolve system() through the dynamic linker with no leak. The global
   array gives a .bss large enough to hold the forged Rela/Sym/string structures. */
char scratch[512];
int main(void){ char buf[64]; read(0, buf, 512); scratch[0] = buf[0]; return 0; }
''',
         ["-no-pie", "-fno-stack-protector", "-Wl,-z,norelro", "-Wl,-z,lazy", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=900.0,
         mechanism="stack-overflow", strict_level=True,
         note="TTP ret2dlresolve to a live shell with NO leak at all. Dynamic, no-PIE, lazily "
              "bound (linked -z norelro -z lazy), a read() overflow, no system() in the PLT and "
              "no puts/printf that leaks libc -- so ret2system, execve-rop and ret2libc-leak all "
              "fail and the auto dispatch falls through to dlresolve. The strategy uses read() to "
              "plant forged Elf64_Rela/Elf64_Sym/string structures in writable memory, then "
              "returns into the PLT stub with an index that makes _dl_runtime_resolve resolve and "
              "call system(\"/bin/sh\"). The pop rdi/rsi/rdx gadgets must be in the IMAGE "
              "(there is no leak to borrow libc gadgets), and glibc 2.34+ removed the CSU gadgets "
              "a minimal binary used to carry, so the fixture provides an explicit gadget block, and a 512-byte global gives a .bss large enough (>=0x100) to hold the forged structures -- "
              "which a real exploitable target of this shape would have. Confirmed by a shell."),

    Case("nowin_dynamic_overflow",
         r"""#include <stdio.h>
#include <unistd.h>
int main(void){ char b[64]; printf("in: ");
  if(scanf("%s", b) != 1) return 0;          /* no win(), and nothing that leaks an address */
  write(1, "ok\n", 3); return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=420.0,
         note="TTP no win(), no leak primitive: the ret2dlresolve shape (resolve system through the "
              "linker without ever leaking libc)"),

    Case("mprotect_shellcode",
         r"""#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
int main(void){ setvbuf(stdout,0,2,0);
  /* A writable+executable page the program itself maps: the shellcode shape. */
  void *pg = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if(pg == MAP_FAILED) return 1;
  char b[64]; printf("in: ");
  if(scanf("%s", b) != 1) return 0;
  memcpy(pg, b, 64);
  mprotect(pg, 0x1000, PROT_READ|PROT_EXEC);
  printf("staged\n"); return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119", "CWE-94"), budget=420.0,
         note="TTP attacker bytes copied into a page the program makes executable (mprotect / "
              "shellcode), plus a stack overflow to reach it"),

    # ---- C++ . Every case so far is C: mangled symbols, vtables and operator new/delete are a
    # different recovery problem, and the platform has a C++ UAF -> vtable-hijack path.
    Case("cpp_uaf_vtable", "",
         [], want_level=2, want_cwe=("CWE-416", "CWE-843", "CWE-824"), budget=420.0,
         mechanism="type-confusion",
         build=(["sh", "-c",
                 "cat > t.cpp <<'EOF'\n"
                 "#include <cstdio>\n#include <cstring>\n#include <cstdlib>\n#include <unistd.h>\n"
                 "struct Base { virtual void speak(){ puts(\"base\"); } virtual ~Base(){} char buf[32]; };\n"
                 "struct Derived : Base { void speak() override { puts(\"derived\"); } };\n"
                 "int main(){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);\n"
                 "  Base *o = new Derived();\n"
                 "  for(;;){ printf(\"1.use 2.del 3.write 4.exit\\n> \");\n"
                 "    int c; if(scanf(\"%d\",&c)!=1) return 0; getchar();\n"
                 "    if(c==1) o->speak();                 /* virtual call, usable after delete */\n"
                 "    else if(c==2) delete o;              /* pointer not nulled: UAF */\n"
                 "    else if(c==3){ printf(\"data: \"); read(0, o, 48); }  /* overwrite the vtable ptr */\n"
                 "    else return 0; } }\nEOF\n"
                 "g++ -fno-stack-protector -O0 -w t.cpp -o cpp_uaf"], "cpp_uaf"),
         strict_level=True,
         note="C++ use-after-free into a virtual call (CWE-416/843): delete leaves the pointer live, "
              "then the vtable pointer is overwritten and the next virtual call dispatches through "
              "it. L2 is this case's CEILING, measured with --ceiling, and it is the fixture's "
              "doing: g++ builds PIE, and the program discloses no pointer and contains no win "
              "function, so there is no address to aim the forged vtable at -- `_cpp_vtable_uaf` "
              "builds its fake table inline at the reclaimed chunk, which needs the chunk address, "
              "and that is only deterministic with ASLR off. The confirmed lifetime primitive "
              "(offset-in-chunk + chunk size) is the honest rung here. stdin is unbuffered for "
              "the same reason as cpp_uaf_vtable_win: with the default full buffering the first "
              "scanf drains fd 0 into stdio and the `read(0, obj, 48)` writes nothing at all, so "
              "the fixture would be asserting a ceiling for an overwrite that never happened."),

    #: The same defect with the two things the PIE case cannot have: a reachable win and a fixed
    #: image. `_cpp_vtable_uaf` has been able to finish this chain all along and NOTHING gated it:
    #: the only C++ case in the table is PIE and win-less, so the matrix read type-confusion at the
    #: level that fixture can reach and the capability went untested.
    Case("cpp_uaf_vtable_win", "",
         [], want_level=3, want_cwe=(), budget=420.0, mechanism="type-confusion",
         build=(["sh", "-c",
                 "cat > w.cpp <<'EOF'\n"
                 "#include <cstdio>\n#include <cstring>\n#include <cstdlib>\n#include <unistd.h>\n"
                 "struct Base { virtual void speak(){ puts(\"base\"); } virtual ~Base(){} char buf[32]; };\n"
                 "struct Derived : Base { void speak() override { puts(\"derived\"); } };\n"
                 "extern \"C\" void win(){ execl(\"/bin/sh\",\"sh\",(char*)0); }\n"
                 "static Base *o = 0;\n"
                 "int main(){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);\n"
                 "  for(;;){ printf(\"1.new 2.del 3.write 4.use 5.exit\\n> \");\n"
                 "    int c; if(scanf(\"%d\",&c)!=1) return 0; getchar();\n"
                 "    if(c==1) o = new Derived();        /* the allocating option */\n"
                 "    else if(c==2) delete o;            /* pointer not nulled: UAF */\n"
                 "    else if(c==3){ if(o){ printf(\"data: \"); read(0, o, 48); } }\n"
                 "    else if(c==4){ if(o) o->speak(); } /* the dangling virtual call */\n"
                 "    else return 0; } }\nEOF\n"
                 "g++ -no-pie -fno-stack-protector -O0 -w w.cpp -o cpp_uaf_win"], "cpp_uaf_win"),
         note="C++ use-after-free -> VTABLE HIJACK to a win (CWE-416/843 -> control flow). Same "
              "defect as cpp_uaf_vtable, which measures L2 because g++ builds PIE and that fixture "
              "has no win: there is no address to aim a forged vtable at. Non-PIE and with a win "
              "reachable, the fake table is built INLINE in the reclaimed chunk (slot 0 -> "
              "chunk+8, every following word -> win), so a `mov rax,[obj]; call [rax+N]` dispatch "
              "enters win for every small N with no leak and no fixture gadget. The engine could "
              "already do this and nothing in the table demanded it. The menu is the shape "
              "`_cpp_vtable_uaf` documents and SEARCHES for -- an option that allocates, then the "
              "rest permuted as (free, edit, use). Measured: with the allocation done once at "
              "startup instead (cpp_uaf_vtable's shape) the search cannot succeed, because the "
              "only `use` option is needed as the detonator and `new` then has to be the quit "
              "entry, which ends the process before the sequence starts. stdin is UNBUFFERED on "
              "purpose: with the default full buffering the first `scanf` slurps a 4 KiB block "
              "off fd 0 into stdio, so the `read(0, obj, 48)` that follows finds the descriptor "
              "already drained and writes nothing -- the overwrite silently never happens, which "
              "is what the first version of this fixture measured."),

    # ---- PARAMETER-DRIVEN. A tool that refuses to run without its flags is a channel of its own:
    # nothing happens on any input until the required option is supplied.
    Case("required_flag_overflow",
         r"""#include <stdio.h>
#include <string.h>
int main(int argc, char **argv){ setvbuf(stdout,0,2,0);
  const char *mode = NULL;
  for(int i=1;i<argc;i++) if(!strcmp(argv[i],"-m") && i+1<argc) mode = argv[++i];
  if(!mode){ printf("usage: %s -m parse < input\n", argv[0]); return 2; }  /* refuses without -m */
  if(strcmp(mode,"parse")){ printf("unknown mode %s\n", mode); return 2; }
  char b[64]; printf("data: ");
  if(scanf("%s", b) != 1) return 0;
  printf("parsed %s\n", b); return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=420.0,
         note="PARAMETER-DRIVEN: the bug is unreachable until `-m parse` is supplied. The usage "
              "string names both the flag AND its valid value, so discovery is possible -- demanding "
              "a magic value that appears nowhere would test nothing but luck"),

    # ---- STRUCTURED INPUT -> L3. Every L3 case above hands the target a payload that is nothing
    # but filler, so the ladder could reach a shell while being completely unable to inherit what
    # L2 had learned -- and it was. `_l2_offset` paged a poc_primitive run's events with
    # `limit=60`, the `primitive.done` carrying the confirmed offset is second-to-last of ~131, so
    # the lookup returned None every time, the "prefer the confirmed L2 offset" branch was dead
    # code, and build_exploit fell back to its own bare-cyclic probe.
    #
    # On an unstructured target that fallback works, which is why `no_pie_ret2win` stayed green
    # and the defect shipped. Here it cannot work at all: the sink is behind a `key=value` parse,
    # so a payload that is not a `name=` line never reaches the strcpy and nothing faults. The
    # only route to L3 is to inherit the offset, the channel and the framing that L2 measured.
    #
    # Deliberately the EASIEST possible L3 otherwise -- no PIE, no canary, partial RELRO, an
    # in-binary win() that execve's a shell -- so a failure here is about the handoff and nothing
    # else.
    Case("structured_l3_ret2win",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void win(void){ setuid(0); execl("/bin/sh","sh",NULL); }
static void parse(const char *line){
  char value[64];
  const char *eq = strchr(line, '=');
  if(!eq){ puts("no '=' in that line"); return; }
  strcpy(value, eq + 1);                 /* unbounded: only reachable through a key=value line */
  printf("set %s\n", value); }
int main(void){ char line[512]; setvbuf(stdout,0,2,0);
  while(fgets(line, sizeof line, stdin)) parse(line);
  return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=3, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=420.0,
         note="STRUCTURED INPUT to L3: the overflow sits behind a `key=value` parse, so the raw "
              "cyclic pattern build_exploit falls back to cannot fault at all. Reaching L3 means "
              "inheriting the offset, the channel AND the framing that poc_primitive confirmed"),

    # ---- SOURCE INPUT. The mission is "binaries AND source" and nothing covered the source half.
    # It also matters for capability, not just coverage: the platform builds a source target with
    # ASan+UBSan, and these three defects are exactly the ones that do NOT fault in a plain build,
    # so the binary-only versions of them above cannot be demonstrated however good the pipeline is.
    # Same sources, handed over as source instead of compiled by the harness.
    Case("src_off_by_one",
         r"""#include <stdio.h>
int main(void){ char b[64]; int i;
  printf("in: ");
  for(i=0; i<=64; i++){ int c=getchar(); if(c<0||c=='\n') break; b[i]=(char)c; }
  b[i]=0;                                   /* one past the end; ASan sees it, a plain build does not */
  printf("hi %s\n", b); return 0; }""",
         [], want_level=0,
         want_cwe=("CWE-787", "CWE-121", "CWE-119", "CWE-193", "CWE-125"),
         as_source=True, budget=420.0,
         note="SOURCE off-by-one: built with ASan by the platform, so the single-byte overflow is "
              "observable where the plain-binary case cannot fault"),

    Case("src_uninit_disclosure",
         r"""#include <unistd.h>
/* The shape a real uninitialised disclosure takes: one call reads input into its frame and
   returns, a later call at the same stack depth reads its own frame -- which it never wrote --
   and sends it out. Nothing faults, nothing goes out of bounds, and the bytes that leave are
   whatever the previous call left behind, i.e. the attacker's input. */
static void take(void){ char buf[128]; ssize_t n = read(0, buf, sizeof buf); (void)n; }
static void emit(void){ char b[128]; write(1, b, 128); }
int main(void){ take(); emit(); return 0; }""",
         [], want_level=2, want_cwe=("CWE-200", "CWE-457"),
         as_source=True, budget=420.0,
         note="SOURCE uninitialised DISCLOSURE, and the whole chain for it: the MSan build "
              "reports it, the fuzz pass RECORDS it as a run (it used to file a finding and "
              "nothing else, so the ladder could never see it), and the primitive verdict then "
              "measures the escape -- which output call, how many bytes, which origin -- and "
              "plants a marker in the input to establish WHOSE bytes left the process. L2 is "
              "earned only by that last step. Note the limit this case respects: the escape is "
              "an intercepted `write`, because a disclosure laundered through uninstrumented "
              "libc formatting (printf(\"%.64s\", uninit)) loses its shadow and MSan stays "
              "silent on it -- see src_uninit_read's note."),

    Case("src_uninit_read",
         r"""#include <stdio.h>
static void fill(void){ volatile char pad[64]; for(int i=0;i<64;i++) pad[i]='S'; }
static int leak(void){ int b[16]; return b[7]; }      /* never initialised */
int main(void){ setvbuf(stdout,0,2,0);
  char name[32]; printf("name: ");
  if(scanf("%31s", name)!=1) return 0;
  fill();
  int v = leak();                                     /* uninitialised read */
  if(v == 0x53535353) printf("hi %s: match\n", name);
  else printf("hi %s: %d\n", name, v);
  return 0; }""",
         [], want_level=0, want_cwe=("CWE-457", "CWE-908", "CWE-200", "CWE-824"),
         as_source=True, budget=420.0,
         note="SOURCE uninitialised read: nothing faults in a plain build, so only the MSan build "
              "can demonstrate it. The uninitialised value is BRANCHED ON, which is the shape MSan "
              "reports; a measured open gap is the pure-disclosure shape (printf(\"%.64s\", uninit)) "
              "-- MSan stays silent on it at every -O level even though it visibly prints the "
              "previous frame's bytes, so catching that needs a differential oracle, not MSan"),

    Case("src_int_overflow",
         r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  unsigned n; printf("count: ");
  if(scanf("%u",&n)!=1) return 0;
  char *p = malloc(n * 16);                 /* n*16 wraps: UBSan flags the overflow itself */
  if(!p) return 1;
  for(unsigned i=0;i<n;i++) memset(p + i*16, 'A', 16);
  printf("ok %u\n", n); free(p); return 0; }""",
         [], want_level=0,
         want_cwe=("CWE-190", "CWE-131", "CWE-122", "CWE-787", "CWE-119"),
         as_source=True, budget=420.0,
         note="SOURCE integer overflow into an allocation: UBSan reports the wrap directly rather "
              "than waiting for a fault that may never come"),

    # ---- THE LEAK -> ROP CHAIN. An out-of-bounds READ can never reach L3 by itself: it gives
    # DISCLOSURE, and control-flow hijack needs a WRITE. So the honest chain is read -> ASLR
    # defeat -> an existing write primitive -> ROP, and it only closes if four things cross the
    # L2/L3 boundary together: the control offset, the input channel, the FRAMING, and the input
    # that provokes the disclosure. The recovered base itself must NOT cross -- it belongs to a
    # process that has already exited.
    #
    # Both defects are behind a structured command, which is the point: the generic leak sweep
    # (`%p` dumps, runs of `A`) finds neither, and a bare cyclic reaches neither sink. And the
    # program loops, because the disclosure and the overflow have to happen in the SAME process
    # or the base is stale before it is used.
    #
    # `as_source`, which makes this the first case to demand L3 of a SOURCE drop. That path was
    # structurally impossible until ingest kept an uninstrumented build: the ingested target is
    # the ASan+UBSan build, which aborts at the copy before the corrupted return is reached, and
    # aborts inside the over-read before the program prints anything.
    Case("oob_leak_pie_ret2win",
         r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void win(void){ setuid(0); execl("/bin/sh","sh",(char*)0); }
/* its OWN frame, so the saved return sits just above the buffer */
__attribute__((noinline)) static void greet(const char *d, size_t n){
  char name[64]; memcpy(name, d, n); puts(name); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  char *buf = (char*)malloc(64);
  void **nb = (void**)malloc(64);        /* the NEIGHBOUR a forward over-read runs into */
  nb[0]=(void*)win; nb[1]=(void*)stdout; nb[2]=(void*)nb; nb[3]=(void*)win;
  memset(buf,'X',64);
  char line[512];
  for(;;){ ssize_t n = read(0,line,sizeof(line)-1); if(n<=0) return 0; line[n]=0;
    if(!strncmp(line,"show=",5)){        /* over-read: the LENGTH is the attacker's */
      long w=strtol(line+5,NULL,10); if(w>0) fwrite(buf,1,(size_t)w,stdout);
      fflush(stdout); continue; }
    if(!strncmp(line,"name=",5)){ greet(line+5,(size_t)n-5); continue; }
    return 0; } }''',
         # want_cwe is EMPTY on purpose. `_scored` is `lvl_ok or bool(demod)`, so a case that
         # lists CWEs passes the moment any matching poc-backed finding turns up, whatever level
         # it reached -- this case passed twice at L2 while its source said `want_level=3`
         # **[measured]**. With no CWE arm, only the level can satisfy it, and the level is the
         # whole point here: every CWE this target carries is already gated by another case.
         [], mechanism='oob-read',
         want_level=3, want_cwe=(),
         as_source=True, budget=600.0,
         note="SOURCE out-of-bounds READ whose disclosure defeats ASLR, in a program that also "
              "has the write primitive to spend it on. Driven with the two inputs SUPPLIED, the "
              "whole chain is confirmed end to end: the read's own output recovers the true PIE "
              "and libc bases (10/10 runs, checked against /proc/<pid>/maps), poc_primitive "
              "confirms IP control at offset 88 on the uninstrumented build in the `name=` "
              "framing, and build_exploit replays the disclosure recipe live, relocates the "
              "payload and pops a SHELL -- graded by a nonce challenge that comes back evaluated, "
              "which an echoing target cannot fake [measured 2026-10-16]. The level asserted here "
              "is L3 and the AUTOPILOT reaches it UNAIDED: 422s of this 600s budget, measured "
              "2026-10-16. Getting there took four defects that all had to fall, and each was "
              "invisible until the one before it was fixed:\n"
              "        (1) a source drop's ingested target IS the ASan build, which aborts "
              "inside the over-read (nothing reaches stdout) and at the overflow copy (the "
              "corrupted return is never reached) -- so ingest keeps a `plain-blob` and the two "
              "stages split the roles;\n"
              "        (2) corpus distillation dropped the boundary seed, because `show=<big>` "
              "covers the same blocks as `show=0` and coverage cannot see VALUES -- 121 seeds to "
              "1. Value seeds are forced-keep now (`fuzz.stage.value_seeds_for`);\n"
              "        (3) verb mining discarded `show=`, matching pure-alpha tokens only, so "
              "the dispatch literal was never a verb and 16 symbol fragments filled the cap;\n"
              "        (4) the seed budget went entirely to the triple enumeration "
              "(n*(n-1)*(n-2) = 3,360 against a 96 cap), starving the argument-bearing and "
              "single families to zero.\n"
              "        A length argument's productive magnitude is MODERATE, not maximal: 65 "
              "through 4294967295 all fault here and -1/LONG_MAX/SIZE_MAX fault NOTHING, "
              "because the C library rejects an operation that large before touching memory. "
              "Keep `want_cwe` empty: `_scored` is `lvl_ok or bool(demod)`, so a CWE arm would "
              "let this pass at L2 and hide a regression in the whole chain."),

    # ---- MULTIPLE DEFECTS. Every case above asserts ONE effect on one target; the mission claim is
    # "find EVERY crash", so this binary carries two unrelated bugs behind a menu and both must be
    # demonstrated.
    Case("multi_bug",
         r'''#include <stdio.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  char b[64], fmt[64];
  printf("1.echo 2.report\n> ");
  int o; if(scanf("%d",&o)!=1) return 0; getchar();
  if(o==1){ printf("data: "); if(scanf("%s",b)!=1) return 0; printf("%s\n",b); }  /* overflow */
  else if(o==2){ printf("label: "); if(!fgets(fmt,sizeof fmt,stdin)) return 0;
                 printf(fmt); }                          /* user-controlled format string */
  return 0; }''',
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=0, want_cwe=(),
         want_all_cwe=(("CWE-121", "CWE-787", "CWE-119"), ("CWE-134",)), budget=420.0,
         note="MULTI: a stack overflow AND a format string, each behind its own menu branch. Was a "
              "known gap while the run stopped at the first defect; synthesize_injection reaches "
              "the format sink on the OTHER branch, so both are reported (CWE-134 and CWE-119) and "
              "'find every crash' holds for several defects in one binary."),
]


@dataclass
class Result:
    name: str
    ok: bool
    profile: str = ""
    findings: list = field(default_factory=list)
    elapsed: int = 0
    reason: str = ""
    gap: bool = False                        # a measured hole: see Case.known_gap


def _verdict(s, target, case):
    """(max verified poc level, demonstrated findings matching want_cwe, all demonstrated findings,
    the CWEs STATIC detectors named).

    The SINGLE definition of "this case succeeded", used both to poll for early completion and to
    score the run, so the two can never disagree. A demonstrated finding is one from a non-static
    detector carrying an expected CWE (an info-leak files as a finding, not always a leveled poc).

    Scored over every target in the CASE, not just the ingested one. A CONTAINER -- a UPX-packed
    executable, a firmware image -- is analysed by registering what it holds as a CHILD target, and
    the real program's findings land there, on a different target id. Scoring only the ingested
    target made every such case unpassable by construction: the UPX case reported nothing but the
    unpack notice while its child had been driven to a demonstrated overflow. Each case here ingests
    exactly one artifact, so "the case" and "that artifact plus what was carved out of it" are the
    same set."""
    # STATIC_DETECTORS is imported, not restated. Restating it here is how the gate came to
    # hold three STAGE names that match no finding's detector, so "detected is not
    # demonstrated" was enforced for one detector out of fourteen and static evidence could
    # score a case green.
    from lykos.db.dao import FindingDAO, PocDAO, TargetDAO
    from lykos.db.models import STATIC_DETECTORS as _STATIC_DETECTORS
    tids = [t.id for t in TargetDAO(s.conn).list_by_case(target.case_id)] or [target.id]
    pocs = [pc for tid in tids for pc in PocDAO(s.conn).list_by_target(tid)]
    maxlvl = max((int(pc.level[1]) for pc in pocs
                  if getattr(pc, "verified", False) and pc.level and pc.level[0] == "L"), default=0)
    # The state ladder is poc-backed > confirmed > corroborated > candidate (the ordering
    # FindingDAO.sites sorts by). `confirmed` was MISSING here while the weaker `corroborated`
    # was accepted, so a crash the pipeline reproduced dynamically -- the project's own
    # definition of demonstrated, `corroborate._DEMO_STATES = {confirmed, poc-backed}` -- did
    # not count. That is what made firmware_carve_overflow read FAIL while its carved child had
    # a `directed_fuzz` CWE-119 finding in exactly that state.
    #
    # `corroborated` is deliberately still admitted even though it is NOT in `_DEMO_STATES`, so
    # this filter is looser than the project's own definition of demonstrated. Tightening it is
    # a separate change: it could only ever turn cases red, and a case that passes on
    # corroboration alone is worth seeing as a case to strengthen rather than hiding by
    # narrowing the filter in the same commit that fixes the omission.
    fs = [f for f in FindingDAO(s.conn).list_by_case(target.case_id)
          if f.state in ("poc-backed", "confirmed", "corroborated")]
    wanted = list(case.want_cwe)
    for req in case.want_all_cwe:                        # an entry may be a group of alternatives
        wanted += list(req) if isinstance(req, (tuple, list)) else [req]
    demod = [(f.detector, f.cwe, (f.title or "")[:40]) for f in fs
             if f.detector not in _STATIC_DETECTORS and any(w in (f.cwe or "") for w in wanted)]
    # What the STATIC detectors named, in ANY state (`hardcoded_secrets` deliberately leaves its
    # findings at `candidate`, so the state filter above would drop the only evidence a
    # want_static_cwe case can ever have).
    statics = {f.cwe for f in FindingDAO(s.conn).list_by_case(target.case_id)
               if f.detector in _STATIC_DETECTORS and f.cwe}
    return maxlvl, demod, fs, statics


def _bundle_reproduces(s, target, case, timeout: float = 120.0):
    """Unpack the bundle this case shipped into a FRESH directory and run its own `runner.sh`.

    Returns (ok, why). The assertion is the operator's: a PoC bundle is a deliverable, and the
    only thing that makes it one is that it reproduces on a machine that is not ours, from the
    files it carries, driven by the script inside it. Everything else this gate checks is read
    back out of our own database -- which is precisely how three defects survived it:

      * `poc/stage.py` replayed a prompt-protocol crash in BULK, so the database said L0 for a
        crash that was confirmed and reproducible;
      * the bundle's `runner.sh` fed that input in bulk too, so a replay-only fix would have
        filed a verified L1 whose bundle did nothing for the operator;
      * `runner.sh` ended on `echo "exit status: $rc"`, so EVERY bundle ever shipped exited 0,
        crash or clean -- the one machine-readable thing a bundle carries, reporting the opposite
        of the truth.

    The third is the reason this reads the STATUS and not the output. The script PRINTS
    "exit status: 139" in both the working and the broken case; only `$?` tells them apart.

    A crash reproducer exits 128+signum (the shell's convention for a signal-killed child), so
    >=128 is the bar FOR A NATIVE TARGET. It is the wrong bar for every other runtime, and that
    was the fourth defect of exactly this shape: an uncaught JVM or CPython exception exits 1, a
    .NET abort exits 134 or 1, and a WASM module that trapped leaves node exiting 0 with the
    verdict in report.json -- so this check would have called a perfectly good managed reproducer
    broken, which is a reason not to demand a bundle for one, which is how the managed substrates
    stayed at identification. The bundle now records which runtime made it and what counts as
    success (`meta.json`'s `runtime`/`verdict`), so the bar is the runtime's own.
    """
    from lykos.db.dao import PocDAO, TargetDAO
    tids = [t.id for t in TargetDAO(s.conn).list_by_case(target.case_id)] or [target.id]
    pocs = [pc for tid in tids for pc in PocDAO(s.conn).list_by_target(tid)
            if getattr(pc, "verified", False) and pc.bundle_sha]
    if not pocs:
        return False, "no verified PoC bundle to execute"
    blob = s.content.get_bytes(pocs[-1].bundle_sha)
    out = Path(tempfile.mkdtemp(prefix="conf-bundle-"))
    try:
        tf = tarfile.open(fileobj=io.BytesIO(blob))      # noqa: SIM115 -- closed in the finally
        try:
            tf.extractall(out, filter="data")            # py>=3.12; the bundle is our own tar
        except TypeError:                                # noqa: PERF203 -- older tarfile
            tf.extractall(out)
        roots = [d for d in out.iterdir() if (d / "runner.sh").exists()]
        if not roots:
            return False, "bundle ships no runner.sh (%s)" % sorted(x.name for x in out.iterdir())
        try:
            r = subprocess.run(["sh", "./runner.sh"], cwd=str(roots[0]),
                               capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return False, "bundle runner.sh did not finish in %gs" % timeout
        # The runtime's own criterion, read from the bundle rather than assumed.
        verdict, runtime = {}, "native"
        try:
            _m = json.loads((roots[0] / "meta.json").read_text())
            verdict = _m.get("verdict") or {}
            runtime = str(_m.get("runtime") or "native")
        except Exception:                                # noqa: BLE001 -- fall back to the native bar
            pass
        want_exit = str(verdict.get("exit") or "signal")
        blob_out = (r.stdout + r.stderr).decode("utf-8", "replace")
        tail = blob_out.strip().splitlines()
        if want_exit == "signal":
            if r.returncode >= 128:
                return True, ""
            return False, "bundle ran but exited %d (want >=128, a signal): %s" % (
                r.returncode, (tail or [""])[-1][:70])
        if want_exit == "nonzero":
            marker = str(verdict.get("stderr") or "")
            if r.returncode != 0 and (not marker or marker in blob_out):
                return True, ""
            return False, ("bundle ran under %s and exited %d%s: %s" % (
                runtime, r.returncode,
                "" if not marker else " without %r in its output" % marker,
                (tail or [""])[-1][:70]))
        if want_exit == "any":                           # the verdict is in a file the host wrote
            name = str(verdict.get("file") or "report.json")
            want = str(verdict.get("contains") or "")
            try:
                got = (roots[0] / name).read_text()
            except OSError as e:
                return False, f"bundle ran under {runtime} but wrote no {name} ({e})"
            if want and want.replace(" ", "") not in got.replace(" ", ""):
                return False, (f"bundle ran under {runtime} and {name} does not say {want!r}: "
                               f"{got[:70]}")
            return True, ""
        return False, f"bundle declares an unknown success criterion {want_exit!r}"
    finally:
        shutil.rmtree(out, ignore_errors=True)


def _scored(maxlvl, demod, case, file_type=None, statics=()):
    """Did this case pass, and is it finished? `done` gates the early stop, so it must never be true
    before the case has shown everything it asserts -- otherwise the run is cut short of its own
    claim (which is how an earlier version let a format case 'pass' at L1)."""
    if case.want_file_type:                              # front-end: did triage route it correctly?
        ft_ok = (file_type or "").lower() == case.want_file_type.lower()
        if not (case.want_level or case.want_cwe):
            return ft_ok, ft_ok                          # identification IS the whole assertion
        if not ft_ok:
            return False, False
    if case.clean:                                       # precision: nothing may be demonstrated
        return (maxlvl == 0 and not demod), False        # never stop early -- absence needs the time
    # A static-only claim IS the whole claim when the case makes no other: see want_static_cwe.
    if case.want_static_cwe and not (case.want_level or case.want_cwe or case.want_all_cwe):
        hit = bool({c for c in (statics or ()) if c} & set(case.want_static_cwe))
        return hit, hit
    if case.want_all_cwe:                                # every listed defect must be demonstrated
        got = {c for _, c, _ in demod}
        def _met(req):
            alts = req if isinstance(req, (tuple, list)) else (req,)
            return any(a in g for a in alts for g in got)
        hit = all(_met(r) for r in case.want_all_cwe)
        return hit, hit
    # A want_level of 0 means "no level is claimed; judge this case by its want_cwe" -- it must NOT
    # satisfy the level test, or `maxlvl >= 0` makes every such case pass unconditionally (which
    # silently turned three bug-class cases green while they produced nothing but STATIC findings).
    lvl_ok = bool(case.want_level) and maxlvl >= case.want_level
    # `strict_level` makes the level the only way through; see the field's own note for the
    # measurement that asked for it.
    ok = lvl_ok if (case.want_level and case.strict_level) else (lvl_ok or bool(demod))
    # Stop early only on the LEVEL when one is claimed: a demonstrated want_cwe finding often turns
    # up earlier and from a weaker stage, and stopping on it would cut the case short of its own
    # claim. With no level claimed, the want_cwe finding IS the claim, so stop on it.
    return ok, lvl_ok if case.want_level else bool(demod)


def _run_case(case: Case, gcc: str) -> Result:
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.orchestrate import run_case_autopilot
    from lykos.casestore import CaseStore
    from lykos.db.dao import TargetDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    d = Path(tempfile.mkdtemp(prefix="conf-"))
    keep = False                                 # set below when a FAILING case is worth keeping
    (d / "t.c").write_text(case.src)
    exe = d / case.name
    for need in case.requires:
        ok_need = Path(need).exists() if need.startswith("/") else bool(shutil.which(need))
        if not ok_need:
            return Result(case.name, True, profile="SKIP", reason="missing %s" % need)
    if case.as_source:                                   # hand over the SOURCE; the platform builds it
        src = d / (case.name + ".c")
        src.write_text(case.src)
        exe = src
    cc = gcc
    if case.as_source:
        pass                                             # nothing to compile here
    elif case.build:                                       # produced by something other than a C compiler
        argv, out = case.build
        if not shutil.which(argv[0]):
            return Result(case.name, True, profile="SKIP", reason="no %s" % argv[0])
        made = subprocess.run(list(argv), capture_output=True, cwd=str(d))
        if made.returncode:
            err = (made.stderr or made.stdout or b"").decode("utf-8", "replace").strip()
            return Result(case.name, False, reason="BUILD FAILED (%s): %s" % (
                argv[0], (err.splitlines() or [""])[-1][:90]))
        produced = sorted(d.rglob(out))
        if not produced:
            return Result(case.name, False, reason="BUILD produced no %s" % out)
        exe = produced[0]
    else:
        if case.cross:                                   # cross-arch case: needs its own toolchain
            cc = shutil.which(case.cross + "gcc") or ""
            if not cc:
                return Result(case.name, True, profile="SKIP", reason="no %sgcc" % case.cross)
        # Libraries must follow the objects: `gcc -lxml2 t.c` leaves xmlInitParser undefined,
        # while `gcc t.c -lxml2` links. Splitting them here keeps a case's cflags order-agnostic.
        libs = [f for f in case.cflags if f.startswith("-l")]
        flags = [f for f in case.cflags if not f.startswith("-l")]
        built = subprocess.run([cc, *flags, str(d / "t.c"), "-o", str(exe), *libs],
                               capture_output=True)
        if built.returncode:
            return Result(case.name, False,
                          reason="BUILD FAILED: " + (built.stderr or b"").decode(
                              "utf-8", "replace").strip().splitlines()[-1][:90])
        if not exe.exists() and exe.with_suffix(".exe").exists():
            exe = exe.with_suffix(".exe")                # mingw appends .exe to a bare -o name
    register()
    s = CaseStore.open(d / "case"); c = s.cases.create(case.name)
    pool = WorkerPool(s.db_path, s.content, JobConfig(workers=3, poll_interval=0.02)); pool.start()
    t0 = time.time()
    try:
        # ingest dispatches source-vs-binary on the FILENAME SUFFIX (ingest.is_source), so a
        # source case has to arrive named ".c" or the platform treats it as an unknown blob.
        t = ingest(s, c.id, exe,
                   filename=case.name + ".c" if case.as_source else case.name)
        q = JobQueue(s.conn); enqueue_triage(q, t, force=True); pool.wait_idle(60)
        tg = TargetDAO(s.conn).get(t.id); mit = tg.mitigations or {}
        prof = "%s pie=%s can=%s relro=%s" % ((tg.arch or "?")[:7], mit.get("pie", "?"),
                                              mit.get("canary", "?"), (mit.get("relro", "?") or "?")[:4])
        if case.want_file_type and not (case.want_level or case.want_cwe):
            ok, _ = _scored(0, [], case, file_type=tg.file_type)
            return Result(case.name, ok, "%s %s" % (prof, tg.file_type),
                          [("triage", tg.file_type or "?", tg.arch or "?")],
                          int(time.time() - t0),
                          "" if ok else "want file_type %r; triaged as %r" % (
                              case.want_file_type, tg.file_type))
        status = {}; stop = threading.Event()
        # The case's budget is the autopilot's budget. Passing it is what makes the phase
        # reserves mean anything here: with the default the orchestrator would divide a 900s
        # clock while this harness stops the run at `case.budget`, so a single stage could still
        # eat a short case -- the very pathology the budget exists to prevent.
        th = threading.Thread(target=run_case_autopilot,
                              args=(d / "case", c.id, [t.id], status, stop, case.budget),
                              daemon=True)
        th.start()
        # Stop once the case has demonstrated its STATED LEVEL, instead of burning the whole budget:
        # an FSOP shell is filed long before fuzz and concolic finish spending their time, so the
        # tail was pure waiting.
        #
        # The bar here is deliberately want_level and NOT the full pass criterion. Passing also
        # admits a demonstrated want_cwe finding, which often appears much earlier and from a weaker
        # stage -- stopping on that let format_fullrelro_ret2win "pass" at L1 off an inject_synth
        # finding without ever proving the L3 format-%n chain the case exists for. A case that can
        # only ever pass on that weaker evidence simply runs to budget, because nothing tells us
        # sooner that it is done.
        early = False
        while th.is_alive() and time.time() - t0 < case.budget:
            time.sleep(1.0)
            try:
                ml, dm, _, st = _verdict(s, t, case)
            except Exception:                            # noqa: BLE001 -- a transient DB lock; retry
                continue
            if _scored(ml, dm, case, file_type=tg.file_type, statics=st)[1]:
                early = True
                if not CEILING:                          # --ceiling: keep going, measure the max
                    break
        if th.is_alive():
            stop.set(); th.join(timeout=60)
        maxlvl, demod, fs, statics = _verdict(s, t, case)
        ok, _ = _scored(maxlvl, demod, case, file_type=tg.file_type, statics=statics)
        shown = demod or [(f.detector, f.cwe, (f.title or "")[:30]) for f in fs]
        # The bundle check runs LAST and can only turn a case red, never green: a case has to
        # earn its level first, and then its deliverable has to work. It is deliberately able to
        # fail a case the database called a verified L1 -- that divergence IS the finding, and it
        # is the one this gate could not see before (see `_bundle_reproduces`).
        bundle_why = ""
        if ok and case.want_bundle:
            b_ok, bundle_why = _bundle_reproduces(s, t, case)
            if not b_ok:
                ok = False
        if ok:
            why = ""
        elif bundle_why:
            why = "L%d verified but the BUNDLE does not reproduce: %s" % (maxlvl, bundle_why)
        elif case.clean:
            why = "CLEAN target but %d demonstrated finding(s) / L%d" % (len(demod), maxlvl)
        elif case.want_all_cwe:
            why = "want ALL of %s demonstrated; got %s" % (case.want_all_cwe,
                                                           sorted({c for _, c, _ in demod}))
        elif case.want_static_cwe and not (case.want_level or case.want_cwe):
            why = "want a STATIC detector to name one of %s; got %s" % (
                list(case.want_static_cwe), sorted(c for c in statics if c) or "no static findings")
        else:
            why = "want L%d / %s demonstrated; got L%d" % (case.want_level, case.want_cwe, maxlvl)
        if case.known_gap:
            # No verdict to give: the case exists to keep the fixture and the measurement, and
            # its note says what is missing. Reported, counted apart, never red.
            return Result(case.name, True, "%s L%d%s" % (prof, maxlvl, "*" if early else ""),
                          shown, int(time.time() - t0),
                          "KNOWN GAP (nothing here states this defect yet) -- " + (why or "")
                          .strip(), gap=True)
        if not ok and KEEP_FAILED:
            keep = True
            why += f" -- case kept for diagnosis: {d}"
        return Result(case.name, ok, "%s L%d%s" % (prof, maxlvl, "*" if early else ""), shown,
                      int(time.time() - t0), why)
    finally:
        pool.stop(grace=5.0); s.close()
        if not keep:
            shutil.rmtree(d, ignore_errors=True)


def verify_op_model_sharing(gcc: str) -> bool:
    """Prove the cross-stage op-model artifact composes two stages: heap_trace crawls the live menu
    once and PERSISTS the op-model; a later, separate stage (oob_index) LOADS it instead of re-driving
    the binary. Run serially (workers=1) so heap_trace finishes before oob_index starts and the proof
    is deterministic. Reuses the heap_uaf_read menu target (a global array table so oob_index applies).
    PASS requires both: the artifact was persisted, and oob_index emitted the 'reused' signal."""
    from lykos.analyze import register
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.dynamic import enqueue_heap_trace, enqueue_oob_index
    from lykos.analyze.dynamic.heap_discover import _OP_MODEL_KIND
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.casestore import CaseStore
    from lykos.db.dao import ArtifactDAO, EventDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    src = next(c.src for c in _CASES if c.name == "heap_uaf_read")
    d = Path(tempfile.mkdtemp(prefix="conf-share-"))
    (d / "t.c").write_text(src)
    exe = d / "share_menu"
    if subprocess.run([gcc, "-fPIE", "-pie", "-O0", "-w", str(d / "t.c"), "-o", str(exe)],
                      capture_output=True).returncode:
        print("%-24s | %-4s | build failed (skip)" % ("op_model_sharing", "SKIP"))
        return True
    register()
    s = CaseStore.open(d / "case"); c = s.cases.create("share")
    pool = WorkerPool(s.db_path, s.content, JobConfig(workers=1, poll_interval=0.02)); pool.start()
    try:
        t = ingest(s, c.id, exe, filename="share_menu")
        q = JobQueue(s.conn)
        enqueue_triage(q, t, force=True); pool.wait_idle(60)
        enqueue_disassemble(q, t, force=True); pool.wait_idle(60)          # populates StringDAO -> opts
        enqueue_heap_trace(q, t); pool.wait_idle(180)                      # crawls + persists the op-model
        persisted = any(a.kind == _OP_MODEL_KIND and (a.meta or {}).get("target") == t.sha256
                        for a in ArtifactDAO(s.conn).list_by_case(c.id))
        run = enqueue_oob_index(q, t); pool.wait_idle(180)                 # should LOAD, not re-crawl
        rid = getattr(run, "id", None)
        evs = EventDAO(s.conn).list(run_id=rid, limit=2000) if rid else []
        reused = any("reused shared crawl" in ((e.payload or {}).get("msg") or "") for e in evs)
        ok = persisted and reused
        print("%-24s | %-4s | persisted=%s reused-by-oob_index=%s" %
              ("op_model_sharing", "PASS" if ok else "FAIL", persisted, reused))
        return ok
    finally:
        pool.stop(grace=5.0); s.close(); shutil.rmtree(d, ignore_errors=True)


def verify_determinism(gcc: str, case_name: str = "argv_overflow", runs: int = 3) -> bool:
    """Run ONE case repeatedly and require the verdict to be the same every time.

    Every other case here runs once, which cannot distinguish "this capability works" from
    "this capability worked that time". The pipeline is full of races by construction -- a live
    worker pool, per-class concurrency caps, wall-clock budgets, and an early stop that fires
    the moment a criterion is met -- so a capability can pass on a quiet machine and fail on a
    busy one, and a single green run hides it completely.

    FAILS only on a verdict that disagrees across runs. The LEVEL is reported but not asserted:
    a case whose criterion is a demonstrated CWE stops as soon as it sees one, so how much
    further the ladder happened to get before the stop is genuinely timing-dependent -- measured
    on upx_overflow, L1 on one run and L2 on the next, both correct. Asserting the level would
    turn that into a false alarm; printing it says plainly which part is and is not stable.
    """
    case = next((c for c in _CASES if c.name == case_name), None)
    if case is None:
        print("%-24s | %-4s | no such case %r" % ("determinism", "SKIP", case_name))
        return True
    verdicts, levels, elapsed = [], [], []
    for _i in range(runs):
        r = _run_case(case, gcc)
        if r.profile == "SKIP":
            print("%-24s | %-4s | %s skipped (%s)" % ("determinism", "SKIP", case_name, r.reason))
            return True
        verdicts.append(r.ok)
        levels.append(r.profile.rsplit(" ", 1)[-1].rstrip("*"))
        elapsed.append(r.elapsed)
    # Agreement AND agreement on PASS. A case that fails every single time is perfectly
    # consistent, and reporting "determinism PASS" beside its own FAIL row would be a true
    # statement that reads as reassurance.
    ok = len(set(verdicts)) == 1 and verdicts[0]
    note = "%s x%d: %s" % (case_name, runs,
                           " ".join("PASS" if v else "FAIL" for v in verdicts))
    if len(set(verdicts)) == 1 and not verdicts[0]:
        note += " -- consistent, but consistently failing"
    if len(set(levels)) > 1:
        note += " (levels %s -- the early stop is timing-dependent, which is expected)" % (
            "/".join(levels))
    print("%-24s | %-4s | %s [%ds]" % ("determinism", "PASS" if ok else "FAIL", note,
                                       sum(elapsed)))
    return ok


#: The CI subset. The full table is 63 cases and ~400 minutes of declared budget, which is a
#: release gate, not a push gate -- so this harness ran by hand, which is to say it ran rarely,
#: which is how a `limit=60` in the L2 -> L3 handoff survived in `main`.
#:
#: Chosen to cover the JOINS rather than the bug classes: the classes have unit tests, and every
#: defect this harness has ever caught lived between two stages. Measured wall clock on a
#: 16-thread laptop, 2026-10-16:
#:
#:   no_pie_ret2win     10s   the whole ladder, detect -> L1 -> L2 -> L3, end to end
#:   argv_overflow     113s   L1 + the shipped bundle actually re-running elsewhere
#:   clean_no_bug      172s   the precision control: a good target must demonstrate NOTHING
#:   fmt_pyc             0s   front-end routing; triage only, no autopilot
#:   fmt_wasm            0s     "
#:   fmt_jvm_class       0s     "   (SKIPs without a JDK, which CI does not install)
#:   fmt_upx_packed      0s     "
#:
#: ~5 minutes, and it fails rather than skips on a missing compiler. Keep it under ten: the
#: moment this is slow enough to be worth skipping, it will be.
SMOKE = (
    "no_pie_ret2win",
    "argv_overflow",
    "clean_no_bug",
    "fmt_pyc",
    "fmt_wasm",
    "fmt_jvm_class",
    "fmt_upx_packed",
)


def run_all(names=None) -> list[Result]:
    # This harness is a diagnostic instrument, so its diagnostics have to be readable. With
    # nothing configured, a `_log.warning` from inside the engine reaches stderr through
    # `logging.lastResort` -- no timestamp, no module, no line. `LYKOS_LOG` selects the level, so
    # the default stays quiet; `LYKOS_LOG=debug` prints every absorbed step with its traceback.
    observe.configure()
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        print("no C compiler; skipping"); return []
    cases = [c for c in _CASES if not names or c.name in names]
    results = []
    print("%-24s | %-4s | %-26s | %s" % ("CASE", "OK", "PROFILE", "FINDINGS / REASON"))
    print("-" * 110)
    for case in cases:
        r = _run_case(case, gcc); results.append(r)
        f = "; ".join("%s/%s" % (d, cw) for d, cw, _ in r.findings) if r.findings else r.reason
        # A FAILING case must print WHY, even when it has findings to show. The bundle check made
        # this visible: a case can now fail with its level earned and six healthy-looking findings
        # listed, and the old line dropped the one sentence that said the deliverable is broken.
        if not r.ok and r.reason:
            f = r.reason if not r.findings else "%s -- found %s" % (r.reason, f)
        print("%-24s | %-4s | %-26s | %s [%ds]" % (
            r.name, "GAP" if r.gap else ("PASS" if r.ok else "FAIL"), r.profile, f, r.elapsed))
    print("-" * 110)
    gaps = [r for r in results if r.gap]
    npass = sum(1 for r in results if r.ok and not r.gap)
    if gaps:
        print("MEASURED HOLES (reported, not graded): %s" % ", ".join(r.name for r in gaps))
    print("CONFORMANCE: %d/%d bug-classes demonstrated end-to-end through the real autopilot "
          "(%ds total; * = %s)"
          % (npass, len(results) - len(gaps), sum(r.elapsed for r in results),
             "criterion met, then run on to the end of the budget anyway (--ceiling): the level "
             "shown is the CEILING" if CEILING
             else "stopped as soon as the case's criterion was met"))
    # Infrastructure check (not a bug class): the cross-stage op-model artifact actually composes two
    # stages. Only when the full run exercised the shared crawl, i.e. not a name-filtered subset.
    if not names:
        print("-" * 110)
        verify_op_model_sharing(gcc)
        # Repeat ONE case: a single green run cannot tell "this works" from "this worked that
        # time", and every stage here races a live worker pool against a wall-clock budget.
        verify_determinism(gcc)
    return results


if __name__ == "__main__":
    import sys as _s

    # Exit status, which this never had: the harness printed a FAIL table and exited 0, so no
    # Makefile target or CI job could gate on it -- and none did, so it ran by hand, which is to
    # say rarely. A named case that does not exist is an error too, rather than a silent 0/0
    # PASS: `--only=typo` used to print an empty table and succeed, which is exactly the
    # decorative-gate failure this repo's Makefile warns about everywhere else.
    _argv = _s.argv[1:]
    _known = {c.name for c in _CASES}

    if "--list" in _argv:
        for _c in _CASES:
            print("%-26s budget=%-5.0f %s" % (_c.name, _c.budget,
                                              "[smoke]" if _c.name in SMOKE else ""))
        print("\n%d cases, %d in the smoke subset" % (len(_CASES), len(SMOKE)))
        _s.exit(0)

    if "--keep-failed" in _argv:
        KEEP_FAILED = True
        _argv = [a for a in _argv if a != "--keep-failed"]

    if "--ceiling" in _argv:
        CEILING = True
        _argv = [a for a in _argv if a != "--ceiling"]

    _FLAGS = {"--list", "--smoke", "--keep-failed", "--ceiling"}
    _unknown = [a for a in _argv if a.startswith("--") and a not in _FLAGS]
    if _unknown:
        # Silently ignoring a flag is how a typo passes for a working option: `--case foo` was
        # accepted and dropped, and only the positional `foo` did anything.
        print("unknown option(s): %s\nknown: --list, --smoke, --keep-failed, --ceiling"
              % ", ".join(_unknown))
        _s.exit(2)

    if "--smoke" in _argv:
        _names = list(SMOKE)
        _argv = [a for a in _argv if a != "--smoke"]
        _missing = [n for n in _names if n not in _known]
        if _missing:
            # A renamed case must not silently shrink the subset into nothing.
            print("SMOKE names a case that no longer exists: %s" % ", ".join(_missing))
            _s.exit(2)
    else:
        _names = [a for a in _argv if not a.startswith("--")] or None

    if _names:
        _bad = [n for n in _names if n not in _known]
        if _bad:
            print("unknown case(s): %s\nknown: %s" % (", ".join(_bad),
                                                      ", ".join(sorted(_known))))
            _s.exit(2)
    _results = run_all(_names)
    if not _results:
        print("NO CASES RAN -- not a pass")
        _s.exit(2)
    _s.exit(1 if any(not r.ok for r in _results) else 0)
