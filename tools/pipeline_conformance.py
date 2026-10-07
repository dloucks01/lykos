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
]


@dataclass
class Result:
    name: str
    ok: bool
    profile: str = ""
    findings: list = field(default_factory=list)
    elapsed: int = 0
    reason: str = ""


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
        while th.is_alive() and time.time() - t0 < case.budget:
            time.sleep(1.0)
        if th.is_alive():
            stop.set(); th.join(timeout=60)
        from lykos.db.dao import PocDAO
        pocs = PocDAO(s.conn).list_by_target(t.id)
        maxlvl = max((int(pc.level[1]) for pc in pocs
                      if getattr(pc, "verified", False) and pc.level and pc.level[0] == "L"), default=0)
        fs = [f for f in FindingDAO(s.conn).list_by_target(t.id)
              if f.state in ("poc-backed", "corroborated")]
        # a DEMONSTRATED finding carrying an expected CWE from a non-static detector (an info-leak
        # files as a finding, not always a leveled poc)
        demod = [(f.detector, f.cwe, (f.title or "")[:40]) for f in fs
                 if f.detector not in _STATIC_DETECTORS and any(w in (f.cwe or "") for w in case.want_cwe)]
        ok = (maxlvl >= case.want_level) or bool(demod)
        shown = demod or [(f.detector, f.cwe, (f.title or "")[:30]) for f in fs]
        return Result(case.name, ok, "%s L%d" % (prof, maxlvl), shown, int(time.time() - t0),
                      "" if ok else "want L%d / %s demonstrated; got L%d" % (case.want_level, case.want_cwe, maxlvl))
    finally:
        pool.stop(grace=5.0); s.close()
        shutil.rmtree(d, ignore_errors=True)


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
    print("CONFORMANCE: %d/%d bug-classes demonstrated end-to-end through the real autopilot"
          % (npass, len(results)))
    return results


if __name__ == "__main__":
    import sys as _s
    run_all(_s.argv[1:] or None)
