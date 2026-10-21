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
