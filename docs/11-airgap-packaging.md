# 11 — Air-Gap Packaging, Bundled Data & Offline Updates

Air-gap is a hard constraint on *every* component. Nothing may fetch at runtime.

## 11.1 The installer bundle (single, verifiable, offline)
- Ships **all** binaries/toolchains (Ghidra, QEMU, AFL++/LibAFL, angr + wheels, GDB, CASR, etc.), the
  desktop app, and all data below. Distributed as a signed archive / offline package repo (Nix closure or
  `apt`/Podman offline mirror) so installation itself needs no network.
- Pin **exact versions** of everything; record them so findings are reproducible (doc 12).
- Verify integrity on install (detached signature + hash manifest).

## 11.2 Bundled data packs (versioned + dated)
| Pack | Contents | Why dated matters |
|---|---|---|
| Signatures | FLIRT/FunctionID/zignatures across libc/toolchain/opt combos | recognition coverage |
| libc DB | libc build → offset tables | exploitation offsets |
| CWE catalog | MITRE CWE (offline) | mapping + guidance |
| CVE/vuln refs | offline CVE data + known-vuln function corpus | known-bug matching; **explicitly show the data's date** |
| Signature DBs | FID/FLIRT/zignatures across compiler×version×opt×arch | stripped fn naming (doc 04) |
| Prototype/type archives | library header prototypes + data-type archives | typing + taint (doc 04/05) |
| Symbolized diff corpus | OSS builds compiled *with* symbols | BinDiff name transfer + known-vuln match (doc 04.4) |
| Detection rules | dangerous-API catalog, taint rules, Semgrep/Weggli rulesets | CWE detection (doc 05) |
| Benchmarks | Juliet, LAVA-M, Magma, CGC | self-validation (doc 14) |
| Exploit assets | gadget DBs, PoC/exploit templates | PoC synthesis |

## 11.3 Offline update channel (sneakernet)
- Updates ship as **signed, incremental data-pack / tool bundles** carried in on removable media.
- The app verifies signature + version lineage, applies atomically, and records the new versions per case.
- **Staleness is a first-class UI concept:** the app always shows how old the CVE/signature/rule packs are,
  because in an air-gapped deployment they silently rot. Never imply "up to date."
- No telemetry, no phone-home, ever. A hard architectural rule enforced by having zero network bindings and,
  ideally, running the whole stack in a network-isolated namespace.

## 11.4 Hardware & footprint
- Document minimum vs recommended: cores (fuzzing parallelism), RAM (Ghidra + VMs + fuzzers), disk (bundles
  + signature DBs + diff corpus + corpora can be tens of GB). **No GPU required** (zero-AI, doc 15).
- Target: Kali VM ~32 GB RAM, 4+ cores, nested virt (doc 10/15). Provide a "lite" install (no diff
  corpus/benchmarks) and a "full" install.
