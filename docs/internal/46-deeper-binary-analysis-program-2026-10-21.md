# 46 — Going deeper: reaching the real attack surface + novel vuln-discovery techniques (2026-10-21)

Follows the round-3 engagement work (doc [45]) and the availability/L3-breadth analysis (doc [44]).
Those closed *silent-failure* and *classification* gaps. This doc is about the next tier: **finding
the vulnerabilities we currently cannot reach**, and inventing techniques grounded in how software
and binaries actually work — not bolting on more generic fuzzing.

## The evidence that set the agenda

Run on **asterisk** (real PBX, 4.56 MB, stripped, dynamically-linked, 16 libs): **4,675 functions
recovered, 37 static findings, 0 demonstrated.** And the controlled **fileparser** experiment
(stripped, dynamic, parser behind a `parse <file>` subcommand):

| run | crashes | result |
|---|---|---|
| no invocation | 0 | 0 demonstrated — static only |
| `--argv 'parse @@'` | 14 | **L2 control-flow hijack demonstrated** |

Two lessons:
1. **We don't reach the real attack surface.** A daemon's bugs live in its protocol/config parsers
   (`ast_sip_*`, SIP/RTP/IAX, config readers), reachable by *speaking the protocol* or *calling the
   parser* — not by feeding `main()` stdin/argv. Our fuzzers drive `main()`'s channels; for a daemon
   that reaches startup and nothing else. The invocation fix helps CLI tools; it does nothing for a
   function buried behind `accept()`.
2. **We flag but do not demonstrate.** 37 static sinks, 0 driven to a crash. Nothing *solves for an
   input that reaches a specific sink*.

## The organizing idea — vulnerabilities are broken contracts

A bug is a place where the program's **implicit contract** can be violated by input: a length is
assumed `<=` a buffer, a pointer is assumed valid, an index is assumed in range, a state transition
is assumed legal, an allocation size is assumed sane. The program ENFORCES some contracts (a bounds
check) and merely ASSUMES others. **A vulnerability is an assumed-but-unenforced contract reachable
from input.** This reframes discovery from "mutate bytes and hope" to: *recover the contracts →
find the unenforced ones on an input path → drive input to violate them.* Every technique below is
an instance of this.

## Gap inventory — everything we are missing (grounded)

| # | Gap | Why it matters | Have today |
|---|-----|----------------|-----------|
| G1 | **Function-level / in-process harnessing of a binary** | fuzz a parser `f(buf,len)` directly, bypassing the daemon/setup | libFuzzer for SOURCE only; nothing for a stripped binary |
| G2 | **Static→dynamic reachability** | demonstrate the 37 sinks instead of listing them | directed fuzz + concolic exist, but not *sink-goal-directed* from a harness |
| G3 | **Protocol / stateful driving** | reach SIP/HTTP parsers; drive message *sequences* | single-shot stdin/argv/file/env only |
| G4 | **Input grammar/structure inference** | get past structured-format front doors | format-aware seeds (shallow) |
| G5 | **Richer oracles than SIGSEGV** | leaks, unbounded growth, state corruption, logic bugs | crash/sanitizer/valgrind only |
| G6 | **Allocator/heap-state modeling** | heap grooming on the target's *own* allocator | traces the allocator (asterisk: `ast_stream_alloc`), does not model its layout |
| G7 | **Contract/invariant recovery** | the organizing idea above — find unenforced assumptions | implicit in taint/bounds detectors, not first-class |

## Novel techniques (software-knowledge-driven), and how they compose

**T1 — Fuzz-worthiness ranking.** *(first increment; pure static, low risk)*
Score every recovered function by attack-surface signal we ALREADY have: takes a `pointer+length`
(from recovered params/calling-convention), contains loops / array-indexing (pcode), reachable from
an input SOURCE over the call graph (`detect.catalog.SOURCES`), calls a DANGEROUS sink, carries a
`tainted_deref` reach. Output: a ranked list of "fuzz here" targets. Turns a 4,675-function daemon
into a handful of worth-driving units. Reuses FunctionDAO/CallEdgeDAO/taint — no new capture.

**T2 — Auto-harness synthesis + emulated function fuzzing.** *(the big lever; builds on T1)*
Take a top-ranked `f(buf,len)`, and drive it DIRECTLY under **unicorn/qemu**: set a minimal
register/stack context, point the arg at a fuzzed buffer, execute just that function, catch faults,
loop — thousands of execs/sec, no daemon, no network. A *binary libFuzzer*. Coverage feedback from
the emulator steers it; the existing L1→L3 ladder escalates whatever it finds. We already vendor
unicorn + angr; this assembles them. Risk: argument-shape inference and context setup — start with
the unambiguous `(char*, size_t)` / `(char*)` shapes T1 is most confident about.

**T3 — Sink-directed concolic (reachability certificates).** *(closes G2)*
For each static finding, run concolic from the harness entry with the finding's site as the GOAL:
either SOLVE for a concrete input that reaches+triggers it (→ demonstrated L1+), or report it
unreachable (→ drop the false positive). Turns "37 flagged, 0 shown" into "N demonstrated, M proven
unreachable, K analyst-gated". Reuses angr/symqemu.

**T4 — Constant- and contract-guided input.** *(deepens G4)*
We already recover the binary's own comparison constants (`extract_secrets`) and bounds checks.
Feed them back as a fuzzing dictionary + structural grammar (magic values, length fields, opcodes),
and derive the *invariants* (field ≤ size) to target. Gets past magic-value/length gates a blind
mutator never will — using the program's own knowledge of its format.

**T5 — Richer oracles.** *(closes G5)*
Beyond SIGSEGV: per-request memory-growth (unbounded allocation / leak → DoS, we have the
availability ladder), new-syscall / new-edge anomalies, allocator-invariant violations, and
differential oracles (same input, instrumented vs not). More true positives than "it segfaulted."

**T6 — State-machine / sequence driving.** *(closes G3)*
Recover the parse dispatch (the switch on message type/opcode) and drive *sequences* of messages,
modelling the target as the protocol engine it is. The hard, later tier.

**Composed engine:** `recover → T1 rank → T2 harness the top units → coverage-fuzz + T4 structure →
T3 concolic to pierce hard checks → T5 oracles → demonstrate → existing L1→L3 ladder.` Each piece is
useful alone; together they reach bugs in daemons/libraries/parsers we currently cannot touch.

## Roadmap (incremental, each lands green through conformance)

1. **T1 fuzz-worthiness ranker** — static, self-contained, immediately useful (a ranked target list
   on asterisk). No execution, fully reversible. **← start here.**
2. **T2 emulated single-function harness** — the capability unlock; validate on fileparser's
   `parse_file` (we know its shape and its bug) before asterisk.
3. **T3 sink-directed concolic** on the ranked targets.
4. **T4 constant/grammar feedback**, **T5 oracles**, **T6 sequences** — later tiers.

Each increment is proven end-to-end through `tools/pipeline_conformance.py` with the existing cases
held green (no capability lost), as doc 44/45 did. Related: [[engagement-large-binary-round]],
[[airgap-engagement-gaps]], [[lykos-project]].

## Progress (2026-10-21)

- **T1 ranker** — DONE (`harness/rank.py`), demonstrated on asterisk's 4,675 functions.
- **T2 executor + libc stubs + fuzz loop** — DONE (`harness/emulate.py`, `harness/fuzz.py`): drives
  one function under unicorn, finds the OOB from a benign seed. 7 harness tests.
- **T2 #3 `harness` stage** — DONE (`harness/harness_stage.py`): rank -> harness-fuzz -> file a
  function-level finding with honest provenance. Registered + in the orchestrator stage map, but
  DELIBERATELY NOT in the default autopilot plan (operator steer: stop adding fuzzing to every run).

## Phase 2 -- the NON-fuzzing program (operator steer, 2026-10-21)

"We just keep adding more fuzzing -- there are other things that bring about exploits." Correct:
fuzzing is one corner of DISCOVER, and only crash-shaped bugs. The asterisk run produced real
NON-fuzz findings -- `popen`/`execvp` (CWE-78), `sqlite3_prepare` (CWE-89), weak crypto, predictable
PRNG, an indirect call through a function pointer (CWE-822), an OOB index (CWE-129) -- and
demonstrated ZERO. Closing that is the work. Avenues, most-grounded first:

1. **Dataflow / taint-to-sink proof (injection & logic).** THE gap is in the code: injection sinks
   are corroborated by CALL-GRAPH REACHABILITY, explicitly "not data flow" (`detect/detectors.py`
   ~line 1056). Add argument-origin data flow at the sink call site: is the sink's key argument a
   CONSTANT string literal (safe -- `popen("/bin/df")`) or DERIVED from untrusted input (the real
   injection)? Reuse the pcode abstract-interpreter already in `detect/bounds.py` (it tracks
   register/stack values through COPY/INT_ADD/... over a function's P-Code). First increment:
   classify each flagged injection sink's arg0 as literal-vs-computed and adjust the finding
   (constant -> downgrade/suppress, a precision win on asterisk's over-flagging; tainted -> a
   data-flow-CONFIRMED injection surface). Pure static, no fuzzing.
2. **N-day / CVE identification by fingerprinting (not version strings).** asterisk's CVE scan found
   nothing (stripped of version banners) yet it IS Asterisk 22.5.2 with known SIP-parser CVEs.
   Function-level structural/FLIRT-style fingerprinting identifies the component version even
   stripped -> maps to a CVE -> a precise weaponizable lead. Most pentests land N-days.
3. **Structural static queries over the decompilation (CodeQL-for-binaries).** Query the recovered
   IR for bug SHAPES (tainted length into a copy, missing bounds check, free-then-use, uninit read)
   without running. weggli does this for source; apply it to the binary's decompilation.
4. **Logic / auth / state-machine bugs.** Auth bypass, access control, type confusion, protocol
   state violations -- the program doing the WRONG thing, not crashing. Needs intended-vs-actual
   modeling; the hardest tier.
5. **Exploit composition.** Turn a bug into an exploit without fuzzing: ROP/ret2libc, heap grooming,
   leak->ASLR-defeat->control. Concrete grounded gap: ret2system on a STRIPPED binary did not find a
   `pop rdi; ret` gadget that provably EXISTS (fp2) -- `build_exploit` / `rop.find_gadget` under-finds.

Order: start with #1 (most code-grounded), then #2 (highest real-engagement value), then #3-#5.

### Update (2026-10-21, after investigation)

- **#1 static dataflow is WALLED by a fundamental engine limit.** `taint.py` is register-granularity
  by its own docstring -- "no precise memory/points-to model, so buffer taint via pointer args is
  not tracked." So it catches register-level flows (`system(getenv(x))`) but NOT the daemon-parser
  case (`recv(buf); popen(cmd_built_from_buf)`), and seeding a buffer POINTER would not taint the
  bytes. Confirming daemon-parser injections statically needs a MEMORY/POINTS-TO taint model -- a
  major engine upgrade (operator steer: do this AFTER #2). The dynamic routes (T2 harness, concolic)
  model memory and are the near-term way to reach these.
- **#2 N-day -- FIRST INCREMENT DONE.** `cve_scan` now also scans the target's DT_NEEDED DEPENDENCY
  libraries (companions or `LYKOS_QEMU_SYSROOT`) -- a dynamically-linked binary's component versions
  live in `libssl.so`/`libxml2.so`/... , not the main binary -- and emits the DT_NEEDED soname BOM
  (the component surface, present even when stripped). Measured on asterisk: 16-soname BOM, and
  `libcrypto.so.3` -> OpenSSL 3.5.5 -> 27 CVEs, which the main-binary scan found zero of. NEXT for
  #2: function-level structural fingerprinting (identify the product version of the MAIN binary --
  e.g. Asterisk 22.5.2 -> its SIP CVEs -- even stripped, no banner).
- **AGREED NEXT after #2: upgrade the taint engine to a memory/points-to model** (unblocks #1-static
  for buffer-content injections -- the daemon-parser class).

### Engine-extension design (scoped 2026-10-21, ready to build as a FOCUSED effort)

`taint.py` is NOT memory-blind: it already taints STACK SLOTS (STORE/LOAD of a value into/out of a
`[base+const]` frame slot, kill-on-overwrite, line ~321/341) and HEAP REGIONS (a tainted STORE
through a known heap-pointer slot taints `("hmem",base,off)`, and a LOAD from it comes back tainted;
`_region_slots`/`heap_regions`). The precise gap is the DAEMON-PARSER shape: a buffer received via a
POINTER PARAMETER (`handle(char *buf, size_t n)`), whose bytes live in the caller/heap -- the callee
has no frame slot for them, so its `*buf` LOADs are not resolved to a tracked region and taint stops.

EXTENSION (mirror the heap-region machinery, do not invent a new one):
1. a new seed kind -- "param i points to ATTACKER-CONTROLLED memory" (a buffer-pointer seed), seeded
   for the ranked parser entry functions (T1) and for the direct SOURCES whose out-buffer is a
   pointer (`fread(buf,..)`, `recv(buf,..)`);
2. register that pointer as a tainted region (like a heap region), so a LOAD through it -- and
   through pointer arithmetic derived from it (`_origins` already spans PTRADD/PTRSUB/COPY) -- returns
   taint;
3. propagate the buffer-pointer-taint across the inter-procedural fixpoint (a tainted buffer passed
   to a callee seeds the callee's corresponding param as a buffer-pointer).

PRECISION IS THE WHOLE RISK: over-tainting fabricates injection findings. Guards: keep it as
CONSERVATIVE as the heap-region path (only seeded/known buffer pointers, not any pointer); gate it
behind a param so it can be A/B'd; and hold the FULL conformance suite green (a spurious injection on
any existing case = over-taint, fail). Validate it CONFIRMS a stack/pointer-buffer parser injection a
register-only run misses. This is a focused build, not a marathon-tail edit.
