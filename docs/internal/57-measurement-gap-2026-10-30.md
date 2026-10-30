# 57 — The real finding: our ground-truth measurement isn't wired (2026-10-30)

Trying to get the first Tier-1 number (doc 56's "face the real number") surfaced something more
important than any engine result: **the north-star metric is not operational on real targets.** We
have only ever measured against Tier-0 — our own planted bugs — which is the "loop measured against
itself" risk doc 56 §3 named.

## What the sweep actually showed

Running the directed engine + CB-scoping on 8 CGC binaries: **CB-scoping works** — ~150–270 own
functions, 75–135 hypotheses per binary, not the 3,145-hypothesis libc flood. That result is real
and worth keeping. The reported **0/8 is NOT a valid engine number**, because:

## Tier-1 (CGC): the harness was built on a wrong assumption

`bench/tier1/score_cgc.py` fed each challenge's `.pov` file to the binary as **raw stdin** and
checked for a crash (vuln/patched differential). Both halves are wrong:
- A CGC `.pov` is **itself an ELF driver program** (`7f 45 4c 46`), not an input file. It is run by
  `tools/cb-replay-pov.py` / `cb-test.py` over a type-1/type-2 negotiation.
- cb-multios CBs are **socket-driven**, not raw-stdin.

So feeding the POV as stdin never reproduces the bug (exit 247, no signal), the differential never
fires, and 0/8 reflects the wrong input model — not engine weakness. The harness is flagged INVALID
in-tree.

**A correct Tier-1 harness exists to be built from cb-multios's own tooling:** `cb-replay-pov.py`
(replay a POV against a CB; a SIGSEGV/SIGILL/SIGBUS = confirmed crash = ground truth) and the
`poller/` sample traffic (valid protocol seeds). Steps: (1) replay each POV to confirm the vuln CB
crashes and the patched one does not — the real ground truth and the count of crashable challenges
here; (2) drive our loop through the CB's real channel (the socket / the port's stdin wrapper),
seeded from pollers; (3) measure validated crashes. This is real work, not a tweak.

## Tier-2 (Magma/ARVO): air-gap collision

`bench/external/{arvo,arvo-meta,magma}` are **metadata and build recipes**, not drop-in
source+crash pairs. ARVO reconstructs each bug by building the exact OSS-Fuzz target from a fix
commit (Docker + network); Magma is a Docker fuzzing benchmark. Neither is usable under the
air-gap constraint without first assembling a small set of **pre-built source targets + checked-in
crashing inputs** by hand.

## Why this matters more than CCBSE / more oracles

The engine debate (directed vs fuzz, CCBSE depth, more classes) is premature while we cannot measure
on real ground truth. Everything green is green against bugs we designed. The honest priority is to
**make one real-ground-truth tier measurable**, then let that number drive engine work.

Our engine is **source-strong, binary-weak** (instrumented AFL + CmpLog + ASan/MSan/LSan validation
all need source or at least instrumentation; on a bare binary we have only directed SE + native-crash
+ flaky qemu-fuzz). CGC is binary + protocol — our *weakest* surface. That argues for a small
air-gap-friendly **source** tier (a handful of real OSS-Fuzz-style bugs, pre-built with their
crashing inputs committed) as the near-term real metric, over the CGC-protocol harness.

## The fork (for the operator)

- **A — build the CGC Tier-1 harness** (cb-replay-pov + pollers + socket channel). Measures our
  weakest surface honestly, uses the corpus we have.
- **B — build a small air-gap source Tier-2** (pre-built real bugs + committed crashing inputs).
  Plays to the engine's strengths; needs us to assemble the corpus by hand (no live Docker).
- **C — accept Tier-0 as the operating metric for now** and keep hardening the engine, explicitly
  acknowledging it is self-referential until A or B exists.

Recommendation: **B**, then **A**. A real source number is both achievable air-gapped and the truest
test of the loop we actually built.
