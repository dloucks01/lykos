# 44 — The availability (DoS) L3 track + four L3-breadth escalations (2026-10-21)

Follows doc [43](43-autopilot-crossarch-l3-2026-10-19.md). That doc closed the cross-arch
memory-corruption→shell L3 path through the Autopilot. This doc opens a track the ladder never
had — **availability / denial-of-service** — and drives four more CWE classes from L1/L2 to L3.

Starting point (commit `fe0c090`): memory leak (CWE-401) reaches **L1** — a leak is detected by a
dedicated `-fsanitize=leak` build and verified as a reproducer. The project's levelling is
**impact-based** (doc convention + `bundle._LEVEL_MEANING`): L2 = an exploitation *primitive*,
L3 = the attacker's *end goal realised*. For the memory-corruption and injection families L3 is
mature (35 conformance cases). Two families top out early:

- **Availability**: `memory_leak`, `alloc_size_dos` (resource-exhaustion), `stack_exhaustion`,
  `null_deref`, `div_by_zero`, `int_underflow_alloc` — **no L3 anywhere**. A leak's real end goal
  (resource exhaustion → DoS) was never demonstrated.
- **A few primitives one hop short of L3**: `double_free`/`invalid_free` (lifetime),
  `untrusted_pointer` (write primitive), `format_read_leak` (info-leak), `int_underflow_alloc`.

## Design — the availability ladder (both tracks)

A leak/exhaustion finding is levelled by what its growth *resolves to*:

- **L2 — amplification primitive.** Quantify the defect as an attacker-controllable, **unbounded**
  resource grant: bytes (or frames, or fds) consumed per attacker request, confirmed to scale with
  request count with **no ceiling** (N and 2N requests leak ~1× and ~2×). This is the availability
  analogue of "attacker controls a write": attacker controls unbounded allocation.
- **L3 — impact realised, host-safe.** Drive the target under a **bounded** memory/time budget
  (`RLIMIT_AS` / `RLIMIT_STACK`, or a cgroup) until it reaches a terminal availability failure:
  an allocation returns NULL and the program takes its own failure path, the kernel OOM-kills it
  (SIGKILL under the cap), or it stops making progress past a multiple of its baseline. The cap is
  what makes this safe to run in the gate and in a delivered bundle — "OOM" is a controlled
  allocation failure inside the capped child, never the host.
- **Disclosure branch (the second track).** When the bytes a leak/uninitialised-read path exposes
  carry **pointer-shaped words or secret-looking material**, additionally file a CWE-200 disclosure
  finding — availability and confidentiality are not exclusive, and a leak that also discloses an
  address is chain material.

## Work items

| # | Item | From → To | Status |
|---|------|-----------|--------|
| A | Availability ladder: L2 amplification + L3 bounded-DoS impact, + disclosure branch. `memory_leak` **done**; `alloc_size_dos`, `stack_exhaustion` next. | L1 → L2/L3 | **memory_leak L3 [measured]** |
| B | Lifetime: `double_free`/`invalid_free` → tcache/fastbin poisoning → write-what-where (L2) → hijack (L3). | L1 → L3 | planned |
| C | `untrusted_pointer` → aim the attacker write at a saved return / GOT → control hijack. | L2 → L3 | planned |
| D | `format_read_leak_pie` → leaked address defeats ASLR → chain into ret2win. | L2 → L3 | planned |
| E | `int_underflow_alloc` → undersized alloc + oversized write → heap overflow → fnptr hijack. | L1 → L3 | planned |

Every promotion is proven **end to end through the real Autopilot** (`run_case_autopilot` + a live
`WorkerPool`) via `tools/pipeline_conformance.py`, with the existing sanitizer/overflow cases held
green (no capability lost). Each item lands as its own commit with a `[measured]` result here.

## Gap analysis (measured 2026-10-21, after memory_leak)

Not every "L1/L2" case is a true L3 gap -- several are DELIBERATE fixture ceilings whose CWE is
already demonstrated at L3 by a richer fixture, so driving the bare one to L3 only duplicates:
- `double_free` (CWE-415): co-CWE CWE-416 is L3 in `heap_fsop_*`; the bare fixture has no write/read
  primitive by design. SKIP.
- `format_read_leak` (CWE-134/200): both CWEs are L3 via the format-WRITE ret2win cases; the read
  fixture is a deliberate L2 disclosure. SKIP.

TRUE gaps (no L3 anywhere for the CWE):
- **Availability family** (`alloc_size_dos`, `stack_exhaustion`): both already reach L1 -- but
  MISCLASSIFIED. Measured: `alloc_size_dos` driven with a huge size faults under the guard-page
  allocator and is filed `fuzz/CWE-119 "Control-flow hijack (SIGSEGV)"` -- a critical-hijack label
  on a resource-exhaustion DoS (the `CWE-789` static flag is corroborated alongside). The real task
  is to RECLASSIFY the huge-alloc / deep-recursion SIGSEGV as resource-exhaustion (CWE-400/789/674),
  NOT a hijack, and then level it on the availability ladder -- delicate (must not relabel genuine
  hijacks: gate on the CWE-789/static signal + the crashing input being an oversized count + the
  fault site being in the allocator/recursion, not a return-address overwrite).
- **`int_overflow_alloc` / `int_underflow_alloc`** (CWE-190/122/131): int overflow -> undersized
  alloc -> heap overflow -> fnptr hijack. The fnptr-hijack end exists (`int_overflow_fnptr` is L3);
  the gap is the alloc-overflow chain + a fixture with a clobberable target.
- **`untrusted_pointer`** (arbitrary read, L2): level by what the read RESOLVES -- read a chosen
  sensitive address (ASLR defeat / planted secret) = disclosure realised (L3), mirroring the
  path-traversal/SQLi "effect realised" rung. Needs the poc path to pick a meaningful target addr.

Each is per-class exploitation/classification engineering with its own autopilot-verified rung --
a deliberate program, not a quick sweep. memory_leak was the clean one (LSan directly observes it).

## Progress log

- **A — availability ladder, memory_leak → L3 [measured].** `poc/dos.py` (new) `escalate()` hangs
  off `build_poc` the moment a leak verifies to L1 (`res.signal_name == "memory-leak"`). L2:
  measured ~4096 bytes/request leaked, linear at N and 2N on the LSan build (unbounded). L3: under a
  32 MB `RLIMIT_AS`, a 4-request run exits 0 ("done") while a ~16 384-request run takes its
  allocation-failure path (exit 1, no "done") — the differential, through `sandbox.run` and the real
  Autopilot. `memory_leak` PASS **L3** (`dos/CWE-401`), 195 s. The three sanitizer cases are
  untouched (the hook is gated to leaks; `is_sanitizer_build` broadening already validated green).
- (pending) A — `alloc_size_dos`, `stack_exhaustion` (own escalation triggers: not leak-shaped).
