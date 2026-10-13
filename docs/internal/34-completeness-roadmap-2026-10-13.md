# 34 — What a complete tool still needs (2026-10-13)

The mission statement this is measured against: *identify all vulnerabilities in a black-box
binary and produce weaponized PoCs/exploits that produce effect.*

Every claim below is labelled **[measured]** (a number from a run in this repo),
**[observed]** (read directly in the code or a run's own output) or **[inferred]** (reasoned, not
yet measured). Nothing here is aspirational description of work already done — docs 32 and 33
cover that. Items are ordered by how much they block the mission, not by effort.

---

## Where the tool actually stands

Two verbs, very different scores.

**Identify.** Strong on static and N-day: 108 CVEs fingerprinted on libtiff 4.0.3, 54 on expat
2.1.0, plus `dangerous_api`/`oob_index`/`tainted_deref`/`stack_frame` **[measured]**. 20/20
format detection top-1 **[measured]**.

**Demonstrate.** Weak on real libraries. Across 9 real targets and ~170k executions: **zero
crash-derived findings** **[measured]**. The L1/L2/L3 ladder works and is verified end to end —
but on CTF-shaped binaries (`quack_quack`, `el_pipo`, `replaceme`), not on library CVEs
**[measured]**.

The ladder itself is in good shape: a crash now becomes a verified PoC through the channel it was
found on, including prompted delivery, and the shipped bundle reproduces in a fresh directory
**[measured]**. **The bottleneck is not the PoC machinery. It is that real libraries do not
produce crashes to feed it.**

---

## 1. Blockers — not a complete tool without these

### 1.1 Memory-corruption crashes on real libraries

In-process fuzzing now builds, picks the library's real entry point, and runs at **3,780 exec/s
against 42.1/s external** — 714,465 executions in 420 s, finding 2 genuine libtiff UB defects
**[measured]**. But **zero ASan memory-corruption findings**, because the synthesized harness
calls `TIFFOpen`/`TIFFClose` only: that parses the directory and stops at the decoder's door
**[measured]**. libtiff 4.0.3's CVEs are in the codec decode paths.

What is missing:
- **A read path in the harness.** After opening, call the library's own "read it all" entry
  (`TIFFReadRGBAImage`, `TIFFReadEncodedStrip`). Needs a generic rule for "the function that
  consumes the opened handle", which is a real design problem, not a table of names.
- **One harness per public entry point**, not one per project. A library has many doors.
- **A persistent corpus.** Every run starts cold today **[observed]**. Coverage-guided fuzzing
  compounds across runs; discarding the corpus throws away the compounding. Probably the single
  cheapest large win in this document.
- **A dictionary for libFuzzer.** `fuzz/cmpdict.py` mines comparison constants already and
  libFuzzer takes `-dict=` **[observed]**.

### 1.2 One binary per source project

`_ingest_built_project` stores only `built["primary"]` — the biggest executable **[observed]**.
libtiff builds ~20 tools; 1 is analysed. Each is a different parser entry with a different
attack surface.

### 1.3 The budget divides TIME, not EXECUTIONS

ASan runs at 20.5/s where a plain build runs at 105/s, and both get the same wall clock
**[measured]** — so the only configuration whose oracle can see a heap OOB read gets ~5× less
work than the one that cannot. `budget.py` already carries the measured per-target rate table;
nothing divides by it **[observed]**. Doc 33 item 5.

### 1.4 Stages that consume the clock and produce nothing

From one 900 s ASan libtiff run **[measured]**: `detect_cwe` 131.3 s then **cancelled**;
`build_exploit` errored after 27 s on a crashless target (doc 32 item 4, still open);
`directed_fuzz` timed out 3×. Each is a precondition that should decline in milliseconds, or a
stage that should checkpoint rather than lose its work when cancelled.

### 1.5 A stage that ran but did less than it should still looks fine

Partly closed today: the scorecard now separates *did work* / *declined, with the reason* /
*errored* / *never scheduled*, and the CLI prints it **[measured]**. Still missing:
- **per-stage work counters** (executions, artifacts, findings) so "ran" implies a quantity;
- a **degraded** state: `concolic` sizes symbolic input from recovered frames and, without them,
  deadends in 2.07 s of a 180 s slice while reporting success **[measured]**.

---

## 2. Honesty and correctness gaps

- **A version match is not a reachability proof.** 108 `corroborated` CVEs on libtiff with 0
  demonstrated **[measured]**. `cve_fingerprint` findings need a tier that says "this build
  contains the vulnerable version; we did not reach it here".
- **CVE→PoC is a table of one.** `poc/cve_triggers.py` holds exactly **1** authored trigger
  (zlib CVE-2022-37434) **[measured]**, so `cve_poc` declines on essentially every target.
- **`off_by_one` is still the one deliberate gate gap** — no static single-byte-overflow
  detector, no layout-aware oracle **[observed]**. Doc 32 items 5(b)/6.
- **Frame layout decides reachability and the tool does not say so.** Measured again today
  while writing a gate fixture: a 64-byte buffer among `main`'s locals did not fault at any
  filler size to 500 bytes on x86-64 **[measured]**. The tool should state "on this ISA, with
  this frame, the saved return address is not above this buffer" instead of reporting clean.

---

## 3. Coverage gaps — the "all vulnerabilities" half

- **Per-codec seeding exists only for TIFF.** Added today: 10 codec seeds, each entering its own
  decoder **[measured]**. The same trick is unimplemented for PNG filter types, JPEG progressive
  vs baseline, ZIP compression methods, and gzip/bzip2 block variants **[observed]**.
- **Formats with no model:** SQLite, protobuf, ASN.1/DER, MP4/MKV, TTF/OTF, PCAP, DWARF.
- **13 ISAs, one bug class.** The arch gate compiles the same 64-byte `memcpy` for 13
  architectures, so each row measures that bug, not that architecture **[observed]**. Doc 32
  item 5.
- **Source languages:** the source-build and libFuzzer paths are C/C++ only **[observed]**. Rust,
  Go and Java source projects are not built or instrumented.
- **No DEX/Android**, and firmware coverage is carve+rehost with thin bug-finding on top.
- **Cross-arch heap checking is unattempted, not blocked** — doc 32 item 5(a), with a measured
  note that a cross-built shim detects an aarch64 UAF under qemu today.

---

## 4. Weaponization gaps — the "produce effect" half

- **Leak-free PIE, no in-binary `win()`, no forking server**: no path today; BROP needs one or
  the other **[observed]**. Doc 32 item 7.
- **Socket-offset autodiscovery** for networked weaponizers.
- **Create-as-write** (allocate path, no edit path) and **OOB-index write** as first-class heap
  primitives.
- **Exploitability scoring.** A crash should carry how close it is to control (corrupted return
  address? controlled pointer? sanitizer-only?). Today the ordering heuristic added for
  multi-crash exploitation is the only such signal **[observed]**.
- **Multiple exploits per target** — closed today: L3 now runs per distinct crash, ranked by what
  each crash demonstrated, instead of once on `crashes[0]` **[measured]**.

---

## 5. Engineering, measurement and UX

- **The gate now executes shipped bundles** (5 cases, negative control verified) **[measured]**.
  What it still cannot assert: that an ENGINE did work. A case where `libfuzzer` is required to
  reach a bug would have caught today's four harness defects months ago.
- **A real-corpus regression benchmark.** The recall benchmark covers planted fixtures (4/4). The
  equivalent for real libraries with known CVEs and ASan builds does not exist, which is why "we
  identify but do not demonstrate" went unnoticed **[observed]**.
- **Report/UI parity**: the capability ledger landed in the CLI today; the web UI and the report
  model do not show it yet **[observed]**.
- **Determinism** is verified for one gate case **[observed]**; a race-prone pipeline needs more.
- **Suite cost**: 2,421 tests in 26 min **[measured]**; the conformance gate is minutes per case.
  Neither fits a tight CI loop without tiering.

---

## 6. Capabilities that do not exist at all

- **Patch/version diffing (1-day hunting).** Given two versions, diff them to locate the fix and
  aim the campaign at it. This is how most real bug-hunting works and nothing here does it.
- **Corpus distillation across runs** (see 1.1) and cross-target corpus sharing for one format.
- **Coverage feedback for the native engine.** AFL++ is wired but aborted on a timing-out seed
  and a native target then got no fuzzing at all **[measured]**; the built-in engine's coverage
  is bolt-on breakpoints.
- **Sanitizer matrix for projects.** MSan/TSan builds exist for single-file source drops only
  **[observed]**; a source PROJECT gets ASan+UBSan and nothing else, so the uninitialised-read
  and data-race classes are unreachable on exactly the targets that matter.
- **Attack-surface inventory**: which entry points exist, which were fuzzed, which were not.
- **Triage quality**: crash dedup is signal+PC (+ASan defect key) **[observed]**; no stack-hash
  bucketing, no minimization across a campaign's whole crash set.

---

## The shortest path to "complete", if it has to be ordered

1. Harness read-path + one harness per entry point + persistent corpus (1.1) — this is what turns
   0 memory-corruption findings into some.
2. Execution-aware budget (1.3) and precondition declines (1.4) — stop paying for nothing.
3. All entry points of a source project (1.2).
4. A real-corpus regression benchmark (5) — otherwise 1–3 regress silently.
5. The reachability tier for version-matched CVEs (2) — stop overstating what is known.

*Baselines at this date: unit suite 2,421 passed / 18 skipped, `ruff check core tests` 972,
conformance gate includes 5 bundle-executing cases.*
