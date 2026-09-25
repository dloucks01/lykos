# 19 — CWE Coverage Matrix (Comprehensive)

**Scope decision:** consider the *entire* CWE corpus, but be explicit about what is detectable in a
**compiled binary** with offensive tooling. MITRE CWE has 900+ entries; many are source-only, web-app,
design, or process weaknesses invisible in a binary. This doc partitions the corpus into **in-scope
families** (with detection strategy + channel + feasibility) and an **out-of-scope** list, so the tool
claims coverage honestly and never reports what it cannot actually see.

## How we organize coverage
- We import the MITRE CWE catalog offline (doc 11) and attach to each in-scope CWE: primary **channel(s)**
  (doc 05: `pattern` / `taint` / `symbolic` / `dynamic`), a **feasibility** rating, and remediation text.
- We anchor priority on the **CWE Top 25** and the **hardware view (CWE-1194)** for firmware, but coverage
  is family-based, not a fixed list — a new detector maps to whichever CWEs its evidence pattern implies.
- **Feasibility ratings:** `HIGH` reliably detectable + confirmable · `MED` detectable with some FP/FN ·
  `LOW` heuristic/assistive only · `DYN` needs execution to confirm · `MANUAL` rule/heuristic hint that
  requires analyst reverse-engineering to judge (no AI — decision doc 15).
- Detectors run on the architecture-neutral IR (doc 18), so a family's detection logic is written once.

## Implemented native detectors (as of 2026-09)
The families below are the *planned* corpus; these are the detectors that concretely **ship today**
for native/ELF + source, each promoted to `corroborated` only when the taint or reachability channel
agrees the attacker controls the relevant argument (a bare call stays low-confidence inventory):
- **CWE-120/121/787** unbounded/stack copies (`dangerous_api` + bounds + stack-frame gate) and the
  **width-bounded scanf off-by-one** (`%16s` into a 16-byte buffer → the +1 NUL, `scanf_bounded_overflow`).
- **CWE-134** format string · **CWE-78** command execution (system/popen/exec, + Go/Rust below).
- **CWE-22** path traversal (fopen/open/openat/unlink/… with a tainted path).
- **CWE-789** uncontrolled/overflowing allocation size (malloc/calloc/realloc with a tainted size).
- **CWE-89** SQL injection (sqlite3_exec/mysql_query/PQexec/… with a tainted query).
- **CWE-822** indirect call through a function pointer in a heap object (`heap_fptr_call`).
- **CWE-327/328/330/321/798/259/377/367/693** crypto/random/temp/TOCTOU/hardening.
- **Go / Rust language-aware** (`lang_sinks`, gated on the detected source language): **CWE-78**
  (`os/exec.Command`, `std::process::Command`), **CWE-22** (`os.Open*`/`std::fs`), **CWE-89**
  (`database/sql`), **CWE-918** SSRF (`net/http`) — corroborated by call-graph reachability from an
  untrusted-input source, since the C data-flow taint does not model the Go/Rust ABI.

The taint channel propagates through x86/x86-64 **sub-registers**, so a value assembled from a
tainted buffer's bytes (a length field read as `buf[0]`, or bytes combined with shifts/ORs) stays
tainted to the sink — not only whole-word direct flows.

---

## A. Memory buffer errors (the core of binary offense)
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 119 | Improper restriction of ops within bounds (class) | taint+dynamic | HIGH |
| 120 | Classic buffer overflow (unbounded copy) | pattern+taint+dynamic | HIGH |
| 121 | Stack-based buffer overflow | taint+dynamic(QASan/RetroWrite) | HIGH |
| 122 | Heap-based buffer overflow | dynamic(QASan)+symbolic | HIGH |
| 124/127 | Buffer underwrite/underread | dynamic+taint | MED |
| 125 | Out-of-bounds read | dynamic(sanitizer)+symbolic | HIGH |
| 787 | Out-of-bounds write | dynamic(sanitizer)+taint | HIGH |
| 786/788 | Access before start / past end of buffer | dynamic | MED |
| 805/806 | Buffer access with incorrect length value | taint+symbolic | MED |
| 822/823/824/825 | Untrusted/uninitialized/expired pointer deref | dynamic+symbolic | MED |
| 466 | Return of pointer outside buffer bounds | symbolic | LOW |
| 170 | Improper null termination | pattern+dynamic | MED |

## B. Lifetime / use-after-free / free errors
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 416 | Use after free | dynamic(QASan)+symbolic | HIGH(DYN) |
| 415 | Double free | dynamic(QASan) | HIGH(DYN) |
| 590 | Free of memory not on heap | dynamic+pattern | MED |
| 761/762/763 | Free of wrong/mismatched pointer | dynamic | MED |
| 401 | Missing release (memory leak) | dynamic+static | MED |
| 404/459 | Improper resource shutdown / incomplete cleanup | dynamic | MED |

## C. Uninitialized / pointer / type
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 457 | Use of uninitialized variable | dynamic(msan-style)+symbolic | MED |
| 824 | Access of uninitialized pointer | dynamic+symbolic | MED |
| 908/909 | Use of uninitialized/unset resource | dynamic | MED |
| 476 | NULL pointer dereference | symbolic+dynamic+pattern | HIGH |
| 690 | Unchecked return → NULL deref | taint+symbolic | MED |
| 843 | Type confusion (access with incompatible type) | symbolic+dynamic | MED(hard) |
| 704/588 | Incorrect type conversion / cast of struct pointer | symbolic | LOW |

## D. Numeric errors (feed overflows)
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 190 | Integer overflow/wraparound | taint+symbolic | HIGH |
| 191 | Integer underflow | taint+symbolic | HIGH |
| 192/194/195/196/197 | Integer coercion / signedness / truncation / sign-extension | symbolic+pattern | MED |
| 193 | Off-by-one | symbolic+dynamic | MED |
| 128 | Wrap-around in size math | taint+symbolic | MED |
| 369 | Divide by zero | symbolic+dynamic | HIGH |
| 469 | Pointer subtraction to determine size | pattern+symbolic | LOW |
| 681 | Incorrect conversion between numeric types | symbolic | MED |

## E. Input validation → injection (native binaries)
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 20 | Improper input validation (class) | taint | MED |
| 134 | Uncontrolled format string | pattern+taint | HIGH |
| 78 | OS command injection (system/exec* with tainted arg) | taint→sink | HIGH |
| 88 | Argument injection | taint→exec | MED |
| 77 | Command injection (general) | taint | MED |
| 114 | Process control (untrusted library/exec path) | taint+pattern | MED |
| 94/95 | Code injection / eval of untrusted input | taint | MED(rare in native) |
| 470 | Unsafe reflection | taint | LOW(mostly managed) |
| 502 | Deserialization of untrusted data | taint+pattern | MED(mostly managed) |

## F. Path / link / resource resolution
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 22 | Path traversal | taint→file API | HIGH |
| 23/36/40 | Relative/absolute path traversal, path equivalence | taint | MED |
| 59 | Link following (symlink) | taint+dynamic | MED |
| 73 | External control of file name/path | taint | MED |
| 41/162 | Improper path/resolution equivalence | taint | LOW |

## G. Concurrency / race conditions
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 362 | Race condition (general) | dynamic+static | MED(hard) |
| 367 | TOCTOU (time-of-check/use) | pattern(access→use pairs)+dynamic | MED |
| 364/366 | Signal handler race / race in switch | pattern+dynamic | LOW |
| 401/415 via race | double-free/UAF via race | dynamic(stress)+sanitizer | MED |
| 543/609 | Missing/incorrect synchronization | static | LOW |

## H. Resource management / DoS
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 400 | Uncontrolled resource consumption | dynamic+symbolic | MED |
| 674 | Uncontrolled recursion (stack exhaustion) | static(callgraph cycles)+dynamic | HIGH |
| 835 | Loop with unreachable exit (infinite loop) | symbolic+dynamic | MED |
| 770/771/772/775 | Missing limits / lost resource / missing release | dynamic+static | MED |
| 789 | Memory alloc with excessive size (tainted) | taint+symbolic | MED |
| 405/407 | Asymmetric resource consumption / algorithmic complexity | dynamic(fuzz timing) | LOW |

## I. Error handling / checks
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 252 | Unchecked return value | pattern(def-use of retval) | HIGH |
| 253 | Incorrect check of return value | pattern+symbolic | MED |
| 754/755 | Improper check/handling of exceptional conditions | pattern+symbolic | MED |
| 390/391 | Error condition without action / unchecked error | pattern | MED |
| 703 | Improper handling of exceptional conditions (class) | pattern | LOW |

## J. Cryptography
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 327 | Broken/risky crypto algorithm (DES/RC4/MD5…) | const-based crypto-ID | HIGH |
| 328 | Use of weak hash | const-based ID | HIGH |
| 326/327 | Inadequate encryption strength | const+pattern | MED |
| 330/331/335/338 | Insufficient randomness / weak PRNG / predictable seed | pattern(rand/srand/time)+dynamic | MED |
| 347 | Improper verification of cryptographic signature | taint+symbolic | MED |
| 780 | RSA without OAEP | const+pattern | LOW |
| 323/325 | Reuse of nonce/IV, missing crypto step | pattern+dynamic | LOW |

## K. Credentials / secrets / storage
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 798 | Hardcoded credentials | string+entropy+pattern | HIGH |
| 259/321 | Hardcoded password / cryptographic key | string+entropy+const | HIGH |
| 312/316 | Cleartext storage of sensitive info (mem/disk) | taint+dynamic | MED |
| 256 | Plaintext storage of password | pattern+taint | MED |
| 526/214 | Sensitive info in env var / process listing | pattern+dynamic | LOW |
| 200/209/532 | Info exposure / error-message / log exposure | taint+pattern | MED |

## L. Auth / authorization / privilege (mostly logic → analyst-driven)
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 306 | Missing authentication for critical function | MANUAL+dynamic | LOW |
| 287/288/290/294 | Improper/auth-bypass/spoofing | MANUAL+symbolic | LOW |
| 862/863 | Missing / incorrect authorization | MANUAL | LOW |
| 250/269/271 | Execution with unnecessary privileges / improper priv mgmt | pattern(setuid/caps)+dynamic | MED |
| 732/276 | Incorrect permission assignment / default perms | pattern(chmod/umask)+dynamic | MED |
| 639/566 | Authorization bypass via user-controlled key | taint+MANUAL | LOW |

## M. Firmware / hardware (CWE-1194 view — for the embedded track, doc 17.5)
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 1277 | Firmware not updateable / no update integrity | pattern+MANUAL | MED |
| 1329 | Reliance on hardcoded component in firmware | string+const | MED |
| 1240 | Use of a risky cryptographic primitive (hw) | const-based ID | MED |
| 1189/1191 | Improper isolation / exposed debug (JTAG/SWD) | pattern(debug regs)+MANUAL | LOW |
| 1231-1234 | Improper lock-bit / register protection | MANUAL+dynamic(rehost) | LOW |
| 1256/1300 | Info exposure through power / physical side channel | out-of-band | N/A(no HW) |
| 1326 | Missing immutable root of trust | MANUAL | LOW |
| 787/125 in firmware | classic memory bugs in firmware | rehost+fuzz+fault | MED(DYN) |

## N. Bytecode/managed-VM targets (JVM/.NET/Dalvik/WASM — doc 18)
Managed memory removes most memory-safety CWEs but adds others:
- Applicable: 502 deserialization, 470 unsafe reflection, 78/88 command injection, 22 path traversal,
  327/328/798 crypto+secrets, 862/863 authz, 89/90/611 injection (when the query/parser is visible).
- Not applicable: 121/122/416/787 memory-safety (VM-managed) — do not report on pure managed bytecode.

---

## Explicitly OUT OF SCOPE for binary-only offensive analysis (do not claim)
These are real CWEs but generally invisible in a compiled binary or belong to other tool classes:
- **Web/app-layer without a visible parser:** 79 XSS, 89 SQLi, 352 CSRF, 601 open redirect, 918 SSRF,
  611 XXE — only in scope when the binary itself constructs/parses the relevant string and data is tainted.
- **Design / process / governance:** 1053, 1059, most "pillar/class" abstract entries, CWE-CATEGORY nodes,
  supply-chain-process, documentation, and configuration-of-external-systems weaknesses.
- **Source-only constructs** lost at compile time: many style/maintainability weaknesses.
- **Physical/side-channel** (power/EM/timing hardware) — needs instrumentation we don't have air-gapped.
We record these as "known-not-covered" in the taxonomy engine so the UI shows *gaps*, not false silence.

## Coverage methodology & honesty
1. **Detectability, not enumeration.** We track which CWE *families* our detectors and channels actually
   cover, and at what feasibility, rather than pretending to "support 900 CWEs."
2. **Confirmed-first reporting.** For any DYN/HIGH family, a finding reaches an analyst as *Confirmed* only
   after reproduction (doc 05). LOW/MANUAL families are surfaced as clearly-labeled leads for analyst review, never as confirmed findings.
3. **Per-CWE benchmark tracking.** Detection precision/recall per family is measured on Juliet (labeled by
   CWE), LAVA-M, Magma, and CGC (doc 14), and shown as a live coverage/quality dashboard in-app.
4. **Architecture independence.** Because detectors run on IR (doc 18), a family's coverage holds across all
   supported architectures; only DYN confirmation depends on per-arch emulation/sanitizer availability.
5. **Extensible.** New CWE detectors register via the plugin API (doc 02) mapping evidence → CWE IDs.
