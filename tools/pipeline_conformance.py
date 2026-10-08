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

import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

CORE = Path(__file__).resolve().parent.parent / "core"
import sys
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))




# A plain unbounded-%s stack overflow. Shared by the build-realism and ARCHITECTURE cases so those
# differ ONLY in how they are compiled -- the point of those cases is the toolchain/ISA, not the bug.
_OVERFLOW_SRC = r"""#include <stdio.h>
int main(void){ char b[64]; printf("in: ");
  if(scanf("%s", b) != 1) return 0;
  printf("hi %s\n", b); return 0; }"""


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
    # Toolchain prefix for a cross-architecture case ("aarch64-linux-gnu-"); the case SKIPS when the
    # cross compiler is absent rather than failing the gate on a machine that cannot build it.
    cross: str = ""
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
         want_level=2, want_cwe=("CWE-121", "CWE-200", "CWE-787"),
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
         note="CHANNEL socket: a TCP server that strcpy's its global recv buffer into a 64-byte "
              "stack buffer in a handler that RETURNS -- reachable only over a connection, and "
              "replayable only by spawning the server and sending (no exec-time carrier exists)"),

    # ---- BUILD REALISM. Real binaries are optimised and stripped; -O0 with symbols hides any
    # reliance on symbol names or on an unoptimised frame layout.
    Case("stripped_opt_overflow", _OVERFLOW_SRC,
         ["-no-pie", "-fno-stack-protector", "-O2", "-s", "-w"],
         want_level=1, want_cwe=("CWE-121", "CWE-787", "CWE-119"), budget=300.0,
         note="BUILD: -O2 and STRIPPED -- no symbols to lean on, optimised frame"),

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
         [], want_level=0, want_cwe=("CWE-129", "CWE-125", "CWE-20"),
         requires=("javac", "java"), budget=420.0,
         build=(["sh", "-c",
                 "printf 'import java.io.*;\\npublic class Idx{public static void main(String[] a)"
                 "throws Exception{BufferedReader r=new BufferedReader(new InputStreamReader"
                 "(System.in));String s=r.readLine();if(s==null)s=\"\";int[] t=new int[4];"
                 "int i=s.length();"
                 "System.out.println(\"slot \"+i+\" = \"+t[i]);}}' > Idx.java && javac Idx.java"],
                "Idx.class"),
         note="JVM DYNAMIC: an array indexed by the unvalidated input length, demonstrated as an "
              "uncaught ArrayIndexOutOfBoundsException rather than merely identified as bytecode"),

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
         [], want_level=0, want_cwe=("CWE-129", "CWE-125", "CWE-20"),
         requires=("python3",), budget=420.0,
         build=(["sh", "-c",
                 "printf 'import sys\ns = sys.stdin.readline()\nt = [1, 2, 3, 4]\n"
                 "print(\"slot\", len(s), \"=\", t[len(s)])\n' > oob.py && "
                 "python3 -m py_compile oob.py"], "oob.*.pyc"),
         note="PYC DYNAMIC: a list indexed by the unvalidated input length, demonstrated as an "
              "uncaught IndexError rather than merely identified as CPython bytecode"),

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
         [], want_level=0, want_cwe=("CWE-119", "CWE-787", "CWE-125", "CWE-129"),
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
              "out-of-bounds trap rather than merely identified as a wasm module"),

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
         [], want_level=0, want_cwe=("CWE-129", "CWE-125", "CWE-20"),
         requires=("dotnet",), budget=480.0,
         build=_csc_build(_CS_OOB, 'oobnet.dll'),
         note="DOTNET DYNAMIC: an array indexed by the unvalidated input length, demonstrated "
              "as an unhandled IndexOutOfRangeException under the CLR rather than merely "
              "identified as a .NET assembly"),

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
         want_level=0, want_cwe=("CWE-415", "CWE-416"), budget=300.0,
         note="BUG CLASS double free (CWE-415): the slot is never nulled, so two frees of one index"),

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
         want_level=0, want_cwe=("CWE-129", "CWE-787", "CWE-125", "CWE-119"), budget=300.0,
         note="BUG CLASS out-of-bounds INDEX write (CWE-129): unbounded index into a global table"),

    Case("format_read_leak",
         r"""#include <stdio.h>
int main(void){ setvbuf(stdout,0,2,0);
  char f[128]; char secret[32] = "SECRET-ON-THE-STACK";
  printf("say: ");
  if(!fgets(f,sizeof f,stdin)) return 0;
  printf(f);                                 /* user-controlled format: %p/%s READ, not a write */
  printf("\n"); return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=0, want_cwe=("CWE-134", "CWE-200"), budget=300.0,
         note="BUG CLASS format-string READ/disclosure (CWE-134/200) -- the gate only had the %n WRITE"),

    Case("uninit_stack_read",
         r"""#include <stdio.h>
#include <string.h>
static void fill(void){ char pad[64]; memset(pad,'S',sizeof pad); }
static void leak(void){ char b[64]; printf("%.64s\n", b); }   /* never initialised */
int main(void){ setvbuf(stdout,0,2,0); fill(); leak(); return 0; }""",
         ["-no-pie", "-fno-stack-protector", "-O0", "-w"],
         want_level=0, want_cwe=("CWE-457", "CWE-200", "CWE-908"), budget=240.0,
         note="BUG CLASS use of uninitialised stack memory (CWE-457/908) -> disclosure. Was a known gap: the read never faults, so every crash-centric stage is blind to it, and a DIFFERENTIAL oracle cannot see it either -- fill() overwrites any pre-seeded pattern microseconds before leak() reads it, and the program takes no input, so there is no knob. The `mem_oracle` stage runs valgrind memcheck, whose shadow memory sees the read itself and distinguishes undefined bytes reaching a WRITE syscall (CWE-200, the disclosure, an effect that actually happened) from a merely internal uninitialised read (CWE-457)."),

    # ---- INJECTION. A whole bug family the platform has probes for (command, path, SQL, XXE,
    # SSRF) and which nothing asserted: these need no memory corruption at all, so none of the
    # crash machinery above would ever surface them.
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
         want_level=0, want_cwe=("CWE-78", "CWE-77", "CWE-88"), budget=300.0,
         note="INJECTION command (CWE-78): user input spliced into system()"),

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
         want_level=0, want_cwe=("CWE-22", "CWE-23", "CWE-36"), budget=300.0,
         note="INJECTION path traversal (CWE-22): user name concatenated into a path under a base "
              "directory that EXISTS, so ../ actually resolves and the read can be demonstrated"),

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
         note="INJECTION SQL (CWE-89) through sqlite3_exec, a sink the prober recognises. SKIPS "
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
         want_level=0, want_cwe=("CWE-611", "CWE-827", "CWE-200"), budget=300.0,
         requires=("/usr/include/libxml2/libxml/parser.h",),
         note="INJECTION XXE (CWE-611) through xmlReadMemory with entity expansion enabled"),

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
         note="INJECTION SSRF (CWE-918): a user-controlled URL handed to curl. SKIPS without curl "
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
         [], want_level=0, want_cwe=("CWE-416", "CWE-843", "CWE-824"), budget=420.0,
         build=(["sh", "-c",
                 "cat > t.cpp <<'EOF'\n"
                 "#include <cstdio>\n#include <cstring>\n#include <cstdlib>\n#include <unistd.h>\n"
                 "struct Base { virtual void speak(){ puts(\"base\"); } virtual ~Base(){} char buf[32]; };\n"
                 "struct Derived : Base { void speak() override { puts(\"derived\"); } };\n"
                 "int main(){ setvbuf(stdout,0,2,0);\n"
                 "  Base *o = new Derived();\n"
                 "  for(;;){ printf(\"1.use 2.del 3.write 4.exit\\n> \");\n"
                 "    int c; if(scanf(\"%d\",&c)!=1) return 0; getchar();\n"
                 "    if(c==1) o->speak();                 /* virtual call, usable after delete */\n"
                 "    else if(c==2) delete o;              /* pointer not nulled: UAF */\n"
                 "    else if(c==3){ printf(\"data: \"); read(0, o, 48); }  /* overwrite the vtable ptr */\n"
                 "    else return 0; } }\nEOF\n"
                 "g++ -fno-stack-protector -O0 -w t.cpp -o cpp_uaf"], "cpp_uaf"),
         note="C++ use-after-free into a virtual call (CWE-416/843): delete leaves the pointer live, "
              "then the vtable pointer is overwritten and the next virtual call dispatches through it"),

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


def _verdict(s, target, case):
    """(max verified poc level, demonstrated findings matching want_cwe, all demonstrated findings).

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
    return maxlvl, demod, fs


def _scored(maxlvl, demod, case, file_type=None):
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
    ok = lvl_ok or bool(demod)
    # Stop early only on the LEVEL when one is claimed: a demonstrated want_cwe finding often turns
    # up earlier and from a weaker stage, and stopping on it would cut the case short of its own
    # claim. With no level claimed, the want_cwe finding IS the claim, so stop on it.
    return ok, lvl_ok if case.want_level else bool(demod)


def _run_case(case: Case, gcc: str) -> Result:
    from lykos.casestore import CaseStore
    from lykos.analyze import register
    from lykos.analyze.ingest import ingest, enqueue_triage
    from lykos.analyze.orchestrate import run_case_autopilot
    from lykos.db.dao import FindingDAO, TargetDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    d = Path(tempfile.mkdtemp(prefix="conf-"))
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
        th = threading.Thread(target=run_case_autopilot, args=(d / "case", c.id, [t.id], status, stop),
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
                ml, dm, _ = _verdict(s, t, case)
            except Exception:                            # noqa: BLE001 -- a transient DB lock; retry
                continue
            if _scored(ml, dm, case, file_type=tg.file_type)[1]:
                early = True
                break
        if th.is_alive():
            stop.set(); th.join(timeout=60)
        maxlvl, demod, fs = _verdict(s, t, case)
        ok, _ = _scored(maxlvl, demod, case, file_type=tg.file_type)
        shown = demod or [(f.detector, f.cwe, (f.title or "")[:30]) for f in fs]
        if ok:
            why = ""
        elif case.clean:
            why = "CLEAN target but %d demonstrated finding(s) / L%d" % (len(demod), maxlvl)
        elif case.want_all_cwe:
            why = "want ALL of %s demonstrated; got %s" % (case.want_all_cwe,
                                                           sorted({c for _, c, _ in demod}))
        else:
            why = "want L%d / %s demonstrated; got L%d" % (case.want_level, case.want_cwe, maxlvl)
        return Result(case.name, ok, "%s L%d%s" % (prof, maxlvl, "*" if early else ""), shown,
                      int(time.time() - t0), why)
    finally:
        pool.stop(grace=5.0); s.close()
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


def run_all(names=None) -> list[Result]:
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
        print("%-24s | %-4s | %-26s | %s [%ds]" % (r.name, "PASS" if r.ok else "FAIL", r.profile, f, r.elapsed))
    print("-" * 110)
    npass = sum(1 for r in results if r.ok)
    print("CONFORMANCE: %d/%d bug-classes demonstrated end-to-end through the real autopilot "
          "(%ds total; * = stopped as soon as the case's criterion was met)"
          % (npass, len(results), sum(r.elapsed for r in results)))
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
    run_all(_s.argv[1:] or None)
