# 61 — Advanced-TTP research: deepen every phase toward L3 (2026-11-03)

Operator ask: "Deepen all of our phases. Research additional advanced techniques or ways to create
our own novel TTPs to find new vulnerabilities and weaponize them. These should all be L3s or as
close as they can get."

Constraint (firm): lykos is **LLM-free and air-gapped**. Every technique below is deterministic /
symbolic / algorithmic — no model in the loop. SOTA comparisons use non-LLM work only.

## What lykos already has (audit — do NOT rebuild)

**Discovery:** coverage sweep (every fn × every static CWE), CodeQL CPG + interprocedural dataflow,
wire_flow + param_sink (wire→sink, intra- and inter-procedural), typestate lifecycle (UAF/double-free),
int signedness/width, callback-table reachability, directed_fuzz, concolic↔fuzz hybrid, stateful net
session fuzzing, reach-gating + plateau-bail.

**Weaponization (control-flow L3):** ret2win, ret2libc, ret2csu, ret2system, one_gadget, stack pivot,
SROP, **ret2dlresolve** (no-leak, wired+detonated+tested), format-string %n write-what-where, heap
tcache-poison + House of Apple 2 / House of Cat FSOP, **leak→groom→control** (ASLR-defeat adjacent
overflow, auto op-model discovery), cross-arch LR/execve ROP (riscv64/aarch64), WASM indirect-call
hijack, PE ret2win/ROP (Wine+SEH).

**Composition:** the attack-path capability graph (entry→objective, each edge a finding; staged
detonation dispatch), weaponize_plan TTP planners.

So the control-flow exploitation column is already deep. The frontier is **paradigms lykos does not
have**, and **discovery that reaches code current detectors/fuzzers can't**.

## Novel-TTP backlog (prioritised)

### P0 — Data-Oriented Programming (DOP) — LANDED (66c3303)
Reach impact by corrupting DATA, not control flow (Hu S&P'16; FlowStitch USENIX'15). Overwrite a
security-decision variable so the program's own code takes the privileged path — CFI-immune, leak-
free, and applicable when a write can't reach a code pointer. Built `poc/dop.py` (plan_flag_flip +
forgery-proof differential oracle + distance sweep), the attack-path `WRITE→AUTH` DOP edge (a write
unlocks post-auth sinks data-only), proven e2e on a flag-flip fixture. **Next:** auto-discover the
security-decision variable (a global flag gating a privileged sink) + its marker on a real target
(the discovery half); extend to bounds/length and path/command-buffer DOP targets; general DOP
gadget/data-flow stitching (FlowStitch) for Turing-complete data-only chains.

### P1 — Input-to-State (REDQUEEN, NDSS'19) — coverage breakthrough
Observe where input bytes appear (nearly) unmodified in comparison operands at run time; patch the
input to satisfy magic bytes / nested checksums automatically — a lightweight alternative to taint
or symbolic that scales to big binaries. This is how we reach bugs behind format gates and checksums
that the reach-gated fuzzer and concolic solver stall on. Build: an I2S colorization pass feeding the
directed fuzzer's mutator (deterministic, per-target). Finds NEW bugs; the weaponizers then take them
to L3.

### P2 — Leakless modern-glibc heap (House of Water / Tangerine)
Safe-linking (2.32+) mangles tcache/fastbin fd, so the current heap chain needs a heap leak. House of
Water abuses `tcache_perthread_struct` (NOT safe-linked) for a leakless primitive; House of Tangerine
modernizes House of Orange for 2.34/2.39. Extends the heap column to the no-leak case on the glibc
lykos actually faces (2.39/2.43). Pairs with House of Apple 2 (already built) for leakless FSOP RCE.

### P3 — Partial-pointer overwrite / low-byte ASLR bypass
When no leak exists, a 1–2 byte overwrite of a saved pointer reaches a chosen target within the same
page/segment (deterministic) or with 1/16–1/4096 brute (probabilistic L3). Turns some no-leak write
primitives into control without a full leak.

### P4 — TOCTOU / double-fetch + uninitialized-use detection (discovery)
Static typestate beyond UAF: a value fetched-checked-refetched across a trust boundary (double
fetch), and a read of memory on a path with no preceding initialization. New vuln classes; the
double-fetch then drives a race PoC, the uninit a disclosure.

### P5 — ret2dlresolve for Full-RELRO alternatives / BROP generalization
ret2dlresolve dies under Full RELRO. Where a leak is impossible and RELRO is full, BROP (blind ROP,
already partly present for servers) + stack-reading generalization is the fallback. Lower priority.

## Principle for "novel TTPs we create"
Each new TTP is a capability EDGE in the attack-path graph: it states its precondition capabilities
and the capability/objective it gains, with a deterministic planner and a forgery-proof oracle. DOP's
`WRITE→AUTH` is the template — a paradigm that opens new PATHS (discovery) and new L3s (weaponization)
at once. Build order: P0 (done) → P1 (most new bugs) → P2/P3 (more no-leak L3) → P4 → P5.
