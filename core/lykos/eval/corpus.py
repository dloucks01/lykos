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
    source: str
    cflags: list = field(default_factory=lambda: list(_FLAGS))
    note: str = ""


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


def bundled() -> list[Case]:
    """The built-in labeled micro-corpus (deterministic order)."""
    return list(_CASES)


_FNAME = re.compile(r"^(CWE-\d+)__([A-Za-z0-9_.-]+)__(good|bad)\.c$")


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
