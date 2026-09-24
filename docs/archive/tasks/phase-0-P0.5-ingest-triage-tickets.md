# Phase 0 · P0.5 Ingest & Triage Worker — Ticket-Level Breakdown

Expands epic **P0.5** (`tasks/phase-0-foundations.md`) into implementation-ready tickets. This is the first
real **stage**, registered through the stage registry (JE-23) and run via the job context (JE-24). It is
**deterministic, LIEF-based, no disassembly**. It turns a raw file into a validated **triage record** stored
as a content-addressed artifact, streaming progress/log events to the UI.


> **BUILD STATUS (implemented):** IT-00..IT-22 done — `core/lykos/analyze/` (elf/triage/ingest/filetype) + the registered `ingest_triage` stage. 53 tests green; parser cross-checked against `file(1)`/`readelf` and real system binaries.
> **DEVIATION (accepted):** LIEF is NOT used — ELF parsing is **pure stdlib** (no deps, works on Python 3.14; LIEF has no wheels here). PE/Mach-O are detected only, with a `parse_errors` note; a LIEF-backed parser for those formats is a follow-up behind the same seam. ELF (the exit-demo target + full multi-arch matrix) is fully covered.

## Effort legend
`S` ≤½ day · `M` ~1 day · `L` 2–3 days.

## Guardrail (applies to every ticket)
**Never crash the worker on a hostile/malformed/foreign binary.** Parsing is best-effort: catch per-field
errors, record them in `parse_errors[]`, emit whatever *was* parseable, and finish `done` (not `error`)
unless the file could not be read at all. A truncated or garbage file yields a partial record, never a stack
trace that kills the worker process.

## The output contract: triage record schema v1 (deliverable of IT-00)
Stored as a JSON artifact; the `target` row is a denormalized subset. **No wall-clock timestamp inside this
object** — timestamps live on the run row, so identical input+tool_version yields byte-identical output and
the result cache (JE-16) works.
```jsonc
{
  "schema_version": 1,
  "sha256": "...", "md5": "...", "sha1": "...", "size": 123456,
  "file_type": "elf|pe|macho|raw|other",
  "detected": "ELF 64-bit LSB pie executable, ARM aarch64, dynamically linked, stripped",
  "arch": "aarch64", "bits": 64, "endianness": "little",
  "linking": "dynamic|static|unknown", "stripped": true,
  "entry_point": "0x640", "interpreter": "/lib/ld-musl-aarch64.so.1",
  "sections": [ { "name": ".text", "size": 4096, "entropy": 6.1, "perms": "r-x" } ],
  "imports": { "libraries": ["libc.so"], "functions_count": 42 },
  "exports_count": 0,
  "toolchain_hint": "gcc | clang | go | rust | msvc | unknown",
  "mitigations": { "nx":"on","pie":"on","relro":"partial","canary":"on","fortify":"off" },
  "entropy": { "overall": 6.3, "packed_hint": false, "packer": null, "reasons": [] },
  "format_details": { "elf": { /* or pe / macho */ } },
  "parse_errors": [],
  "tool": "lief", "tool_version": "0.x.y"
}
```
Mitigation values are a small enum: `on | off | partial | unknown`.

---

## A. Worker scaffolding & contract
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **IT-00** | Triage schema v1 + validator | schema above as a typed model + JSON-schema validator; version field enforced | — | M |
| **IT-01** | Register `ingest_triage` stage | registered via JE-23 (`resource_class=quick`, `tool="lief"`, `tool_version=lief.__version__`); reads `ctx.input`, writes triage artifact, emits events | JE-23, JE-24 | S |
| **IT-02** | Robust-parse harness | decorator/util wrapping every parse step: catch → append to `parse_errors[]`, continue; fuzzed with garbage never crashes worker | IT-00 | M |

## B. Ingest
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **IT-03** | Intake + streaming hashes | copy target into artifact store; streaming md5/sha1/sha256 + size; base `target` row | P0.4 | S |
| **IT-04** | File-type detection | magic-based family id (ELF/PE/Mach-O/raw/other) *before* format parse; non-exec input → `file_type` set, binary parse skipped cleanly | IT-03 | S |
| **IT-05** | Per-case dedup by sha256 | identical content links existing blob; target row still created | IT-03 | S |

## C. Format & architecture parsing (LIEF)
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **IT-06** | Format dispatch | route ELF/PE/Mach-O; **fat/universal Mach-O** → per-slice records; unknown → `raw` | IT-04, IT-02 | M |
| **IT-07** | Arch / bits / endianness | machine type → normalized arch enum (x86, x86-64, arm, aarch64, mips, ppc, riscv, sparc, …), bits, endianness | IT-06 | M |
| **IT-08** | Sections/segments summary | name, size, perms, per-section entropy (feeds IT-16/17) | IT-06 | S |
| **IT-09** | Imports/exports/symbols | imported libs+funcs, exports, **symbol presence → `stripped`**, **dynamic vs static linking** | IT-06 | M |
| **IT-10** | Entry & load info | entry point, base, PIE/ET_DYN, ELF interpreter, relevant load addrs | IT-06 | S |
| **IT-11** | Toolchain fingerprint (light) | compiler hint from `.comment`/producer; Go/Rust/.NET indicators (seeds doc-04 runtime-metadata later) | IT-06 | S |

## D. Security mitigations
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **IT-12** | ELF mitigations | NX (`GNU_STACK`), PIE (`ET_DYN`+`DF_1_PIE`), RELRO full/partial (`GNU_RELRO`+`BIND_NOW`), canary (`__stack_chk_fail`), FORTIFY (`*_chk`), RPATH/RUNPATH | IT-06 | M |
| **IT-13** | PE mitigations | ASLR (`DYNAMIC_BASE`), DEP (`NX_COMPAT`), SafeSEH, CFG (`GUARD_CF`), high-entropy VA, Authenticode-signed? (best-effort GS) | IT-06 | M |
| **IT-14** | Mach-O mitigations | PIE, stack canary, ARC, encryption (`LC_ENCRYPTION_INFO`), code-signature presence, restrict segment | IT-06 | M |
| **IT-15** | Normalize mitigations | unify all three into the common `mitigations` object (`on/off/partial/unknown`); format-specific keys allowed | IT-12/13/14 | S |

## E. Entropy & packing
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **IT-16** | Entropy computation | overall + per-section Shannon entropy | IT-08 | S |
| **IT-17** | Packer heuristics | UPX section names, high-entropy code section, few imports+high entropy → `packed_hint`+`packer`+`reasons`; **no unpacking** (later phase) | IT-16, IT-09 | S |

## F. Output & events
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **IT-18** | Assemble + validate record | build schema object, validate (IT-00), write JSON artifact, link as run **output** (run_artifact), update denormalized `target` fields | IT-07…IT-17, P0.4 | M |
| **IT-19** | Progress + log events | emit `job.progress`/`job.log` per phase (ingest→parse→mitigations→entropy→emit); check `ctx.should_cancel()` between phases | IT-01, P0.6 | S |
| **IT-20** | Deterministic output | sorted keys, no in-object timestamps/paths; identical input+tool_version → byte-identical artifact (verifies cache JE-16) | IT-18 | S |

## G. Quality
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **IT-21** | Golden corpus | small, license-clean set: x86-64/AArch64/PPC ELF, a **stripped**, a **static**, a **UPX-packed**, a PE, a Mach-O (incl. fat), a Go binary, a **truncated/garbage** file — with expected triage JSON | IT-18 | M |
| **IT-22** | Ground-truth cross-check | mitigations/arch/linking compared to `checksec`/`readelf`/`file` on the corpus | IT-21 | S |
| **IT-23** | Fault/robustness suite | zero-byte, truncated, wrong-magic, huge, non-exec, deliberately corrupt → **no crash**, partial record + populated `parse_errors[]` | IT-02, IT-21 | M |

---

## Build order (within the epic)
```
IT-00 ─► IT-01 ─► IT-02 ─► IT-03 ─► IT-04 ─► IT-05
                                   └► IT-06 ─► IT-07/08/09/10/11
                                              └► IT-12/13/14 ─► IT-15
                                              └► IT-16 ─► IT-17
                                                          └► IT-18 ─► IT-19 ─► IT-20
IT-21 ─► IT-22 · IT-23   (tests; continuous, hard-gate before epic close)
```
**Internal milestones:**
1. **M-1 (bytes in):** IT-00…IT-05 — file ingested, hashed, typed, stored; empty triage record emitted.
2. **M-2 (it parses):** IT-06…IT-11 — arch/format/linking/stripped/sections/imports on a plain ELF.
3. **M-3 (mitigations):** IT-12…IT-17 — full mitigation set + entropy/packer across ELF/PE/Mach-O.
4. **M-4 (contract + live):** IT-18…IT-20 — validated deterministic artifact + streamed events.
5. **M-5 (proven):** IT-21…IT-23 — golden + ground-truth + fault suites green.

## Definition of Done (P0.5)
- A registered `ingest_triage` stage produces a **schema-valid** triage record for ELF/PE/Mach-O across at
  least x86-64/AArch64/PPC, matching `checksec`/`readelf` on the golden set.
- **Stripped**, **static**, and **UPX-packed** samples are correctly flagged; a Go binary is toolchain-hinted.
- A **truncated/garbage** file yields a partial record + `parse_errors[]` and **never crashes** the worker.
- Output is **deterministic** (byte-identical for same input+tool_version) so the result cache hits on re-run.
- Progress and log **events stream** to the UI; the triage artifact is retrievable by hash.

## Notes & guardrails
- **LIEF only in Phase 0** — no disassembly/Ghidra (that is Phase 1). Keep this worker fast and pure-parse.
- **`tool_version = LIEF version`** flows into the cache key (JE-16): a LIEF upgrade correctly invalidates.
- Everything here seeds later phases — arch/endianness pick the emulator (doc 06/18), linking+stripped pick
  the naming stack (doc 04), mitigations feed exploitability (doc 08) — so keep the fields clean and honest.
- Prefer reporting `unknown` over guessing; a wrong mitigation flag is worse than an honest gap.
