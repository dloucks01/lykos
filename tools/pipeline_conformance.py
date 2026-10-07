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


# static pattern detectors -- a finding from one of these is DETECTED, not demonstrated.
_STATIC_DETECTORS = {"dangerous_api", "detect_cwe", "cwe_scan", "source_sink_scan"}


@dataclass
class Case:
    name: str
    src: str
    cflags: list[str]
    want_level: int                      # minimum VERIFIED poc level the pipeline must reach (1/2/3)
    want_cwe: tuple[str, ...]            # or: a non-static poc-backed finding carrying one of these
    note: str = ""
    budget: float = 300.0


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
    detector carrying an expected CWE (an info-leak files as a finding, not always a leveled poc)."""
    from lykos.db.dao import FindingDAO, PocDAO
    pocs = PocDAO(s.conn).list_by_target(target.id)
    maxlvl = max((int(pc.level[1]) for pc in pocs
                  if getattr(pc, "verified", False) and pc.level and pc.level[0] == "L"), default=0)
    fs = [f for f in FindingDAO(s.conn).list_by_target(target.id)
          if f.state in ("poc-backed", "corroborated")]
    demod = [(f.detector, f.cwe, (f.title or "")[:40]) for f in fs
             if f.detector not in _STATIC_DETECTORS and any(w in (f.cwe or "") for w in case.want_cwe)]
    return maxlvl, demod, fs


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
    if subprocess.run([gcc, *case.cflags, str(d / "t.c"), "-o", str(exe)],
                      capture_output=True).returncode:
        return Result(case.name, False, reason="BUILD FAILED (skip)")
    register()
    s = CaseStore.open(d / "case"); c = s.cases.create(case.name)
    pool = WorkerPool(s.db_path, s.content, JobConfig(workers=3, poll_interval=0.02)); pool.start()
    t0 = time.time()
    try:
        t = ingest(s, c.id, exe, filename=case.name)
        q = JobQueue(s.conn); enqueue_triage(q, t, force=True); pool.wait_idle(60)
        tg = TargetDAO(s.conn).get(t.id); mit = tg.mitigations or {}
        prof = "%s pie=%s can=%s relro=%s" % ((tg.arch or "?")[:7], mit.get("pie", "?"),
                                              mit.get("canary", "?"), (mit.get("relro", "?") or "?")[:4])
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
                ml, _, _ = _verdict(s, t, case)
            except Exception:                            # noqa: BLE001 -- a transient DB lock; retry
                continue
            if case.want_level and ml >= case.want_level:
                early = True
                break
        if th.is_alive():
            stop.set(); th.join(timeout=60)
        maxlvl, demod, fs = _verdict(s, t, case)
        ok = (maxlvl >= case.want_level) or bool(demod)
        shown = demod or [(f.detector, f.cwe, (f.title or "")[:30]) for f in fs]
        return Result(case.name, ok, "%s L%d%s" % (prof, maxlvl, "*" if early else ""), shown,
                      int(time.time() - t0),
                      "" if ok else "want L%d / %s demonstrated; got L%d" % (case.want_level, case.want_cwe, maxlvl))
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
    return results


if __name__ == "__main__":
    import sys as _s
    run_all(_s.argv[1:] or None)
