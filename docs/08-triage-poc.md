# 08 — Crash Triage, Root Cause, PoC Synthesis & Reporting

**Implemented L3 strategies (`build_exploit`, 2026-09).** Each is confirmed by a live shell echoing a
marker, a breakpoint reached with a negative control, or the win path's observable output — never
asserted:
- `ret2win` (ISA-neutral, incl. 32-bit stack args) · `rop`/`ret2system` · `execve`-syscall ROP ·
  `srop` (one-shot + 2-stage `/bin/sh` plant) · `ret2csu`.
- `ret2libc` — no-PIE puts-leak, PIE pure-libc, and a **one-gadget** fallback (`rop.find_one_gadgets`,
  no external tool) · `canary` (leak the canary → ret2libc), with a self-contained live re-driver.
- `magic` — overwrite a magic-checked local to reach a gated flag path (no leak/gadgets, PIE-safe).
- `format` — a positional `%hhn` write-what-where over a post-sink GOT slot.
- `heap` — automated glibc heap → shell (unsorted-bin leak → tcache poison of `_IO_2_1_stdout_` →
  House of Apple 2), driven by menu op templates, with a standalone re-driver in the bundle.
- `mprotect` shellcode · `shellcode` — inject `execve("/bin/sh")` into an executable input buffer the
  target jumps to, with a **bad-char XOR encoder** (`shellcode.encode_avoiding`) for filtered input.

The PoC bundle is inspectable in the workbench (Reproduce / Payload hexdump / Technique / Files),
served by `GET /artifacts/{sha}/bundle`.

## 8.1 Crash triage
- **De-duplication:** cluster crashes by normalized stack hash / faulting-IP + call context. Thousands of
  fuzzer crashes → a handful of unique bugs. Use **CASR** (crash analysis + dedup) as the engine.
- **Minimization:** shrink each crashing input (afl-tmin) to the smallest reliable reproducer.
- **Classification:** signal type, read vs write, near-null vs wild, sanitizer verdict (heap-overflow / UAF /
  double-free / stack-overflow), and an **exploitability score** (CASR / `!exploitable`-style heuristics:
  PC control? corrupted return addr? controllable write target?).
- Attach each crash to its finding (doc 05) and promote the finding to **Confirmed**.

## 8.2 Root-cause analysis
- **Backward slicing / time-travel:** from the faulting instruction, walk the recorded execution trace
  (doc 06) back to the tainted input bytes and the originating bug (e.g., the missing bounds check).
- **Symbolic replay:** re-run the crashing input under angr/Triton to recover the exact constraint that
  makes it fail and to identify controllable bytes (the basis for the PoC ladder below).
- **Analyst explanation (templated):** the tool renders the slice + decompiled context + evidence into a
  structured root-cause + remediation writeup from templates; the analyst edits. No LLM narration.

## 8.3 PoC ladder (define what "PoC" means — Gap H)
Each level is a **demonstrable bundle**; the tool claims only the level it actually achieved.
**Commitment [DECIDED, doc 15]:** L0+L1 are the guaranteed product baseline; L2 is supported best-effort and
proves impact; L3 is a scoped, analyst-in-the-loop research track, never advertised as push-button.
| Level | Demonstrates | How produced | Feasibility |
|---|---|---|---|
| **L0 Repro** | input reaches the vulnerable state | symbolic/directed input | high |
| **L1 Crash** | memory-safety crash + sanitizer report | fuzzer + sanitizer minimized input | high |
| **L2 Primitive** | control of a primitive (PC control, write-what-where, leak) | symbolic analysis of controllable bytes; heap-primitive detection (DEPA/AAHEG-style) | medium |
| **L3 Exploit** | working exploit (ROP→shell, etc.) | template-driven AEG, scoped | **frontier / stretch** |

## 8.4 PoC synthesis engine
- **Input-generating PoC (L0/L1):** the symbolic/concolic solver's satisfying input, minimized, plus the
  harness + environment needed to fire it.
- **Primitive PoC (L2):** identify controllable bytes → offsets, compute overflow offset to saved return
  address / function pointer, detect heap layout primitives (**MAZE** Dig&Fill for layout, **ARCHEAP**/
  **AAHEG** for fastbin/unlink strategies, doc 16). Demonstrate control, e.g., set PC to a chosen value.
- **Exploit PoC (L3, scoped):** template library (ret2win, ret2libc/ROP with a bundled gadget finder like
  ROPgadget/ropper, format-string write) + pwntools-style scripting. Honest ceiling: even DARPA CGC fully
  auto-exploited only one heap bug. Provide *assisted* exploitation with analyst-in-the-loop, not push-button.
- **Bundle contents (every PoC):** input file(s), harness, environment/rootfs spec, a self-contained **runner
  script**, the expected observable (crash signature / controlled register / popped shell), a recorded
  **asciinema/video** of it firing, and the isolation tier it was validated in. Re-runnable offline, standalone.
- **Verification:** every PoC is re-executed from its bundle in a clean sandbox before it's marked valid —
  no PoC is trusted until it reproduces from scratch.

## 8.6 End-effect model — what the defect can *achieve*, and whether we proved it
A crash is the entry point, not the conclusion. Every crash finding carries a structured list of
the **end effects** an attacker can drive it toward, each with a truthful status and, when
demonstrated, the **artifact that proves it**:

| Effect | Kind | Demonstrated by | Proof |
|---|---|---|---|
| **Denial of service** | `dos` | any reproducible crash | the crashing input |
| **RCE / control-flow hijack** | `rce` | poc_primitive confirms instruction-pointer control (L2), or build_exploit lands a working exploit (L3) | the L2 primitive bundle / L3 exploit bundle |
| **Memory corruption (arbitrary write)** | `memory-corruption` | poc_primitive confirms write-what-where | the L2 bundle |
| **Information disclosure (memory leak)** | `info-disclosure` | a format-string probe leaks live memory (its bytes, incl. secrets, captured) | the leaked-bytes artifact |
| **Command / code injection** | `injection` | synthesize_injection runs an injected command | the PoC bundle |

Status is **`demonstrated`** (a PoC achieves it, with a downloadable proof) or **`potential`**
(the defect class can reach it, but it was not demonstrated — e.g. ASan aborts a source build
before control can be seized, so RCE stays potential and DoS is demonstrated). Effects only ever
**promote** across the pipeline (root_cause files the ceiling → poc_primitive/build_exploit mark
what they achieve), and the finding **headlines the most severe achievable effect** rather than
"reproduced crash". Derived deterministically from the root-cause class + confirmed primitives
(`analyze/debug/exploitability.py`); never over-claimed.

## 8.5 Reporting & export
- **Analyst report:** per-finding — CWE mapping, severity/CVSS vector, root cause, evidence trail (which
  channels fired, coverage, solved constraints), remediation, and the PoC bundle + recording. HTML + PDF,
  fully offline templating.
- **SARIF export** for interop with other tooling/pipelines.
- **Machine-readable case export** (JSON) of all findings/artifacts for archival or transfer.
- Reports embed tool + signature-DB + model versions and input hashes so results are reproducible (doc 12).
