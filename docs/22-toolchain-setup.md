# 22 — Optional toolchain setup (per-host)

Lykos's core is stdlib-only and runs offline. The heavy analysis engines are **optional**:
each stage locates its tool, runs it, parses the result, and fails clearly (or falls back)
when it is absent. This note records how the toolchain was provisioned and real-run tested on
the Kali development VM, and the one engine that is a from-source build.

## Installed via apt (Kali)

    sudo apt-get install -y gdb afl++ ghidra default-jdk qemu-user qemu-user-binfmt

- **Ghidra 12.1.3** — headless at `/usr/share/ghidra/support/analyzeHeadless`; the locator
  finds it automatically. Ghidra 11.3+/12 dropped bundled Jython for PyGhidra (whose jpype
  wheels stop at CPython 3.13), so the export post-script is a **Java** GhidraScript
  (`ExportAnalysis.java`), which Ghidra compiles on the fly and which works on every Ghidra
  version. No PyGhidra/Jython setup required.
- **AFL++** — `afl-fuzz` plus the instrumenting compilers (`afl-cc`). The `coverage_fuzz`
  stage uses qemu-mode (`-Q`) by default; if `afl-qemu-trace` is not packaged, pass
  `params.qemu=false` and compile the target with `afl-cc` (instrumented mode).
- **GDB** — the primary `root_cause` backend (fault address via `$_siginfo`, mappings, and
  faulting-instruction bytes). The pure-stdlib ptrace helper is the fallback.
- **QEMU user** — cross-architecture execution in the sandbox.

## angr (vendored venv)

angr is Python but heavy; it runs in its own interpreter via the standalone driver. Provision
a venv the locator checks automatically (`vendor/angr-venv/bin/python`), or set
`LYKOS_ANGR_PYTHON`:

    python3 -m venv vendor/angr-venv
    vendor/angr-venv/bin/pip install angr

`vendor/` is gitignored (machine-specific). angr 9.3.4 works on CPython 3.14 (the unicorn
engine is disabled, which our directed exploration does not require).

## SymQEMU (from source — not packaged)

SymQEMU has no distribution package; it is a QEMU fork plus the SymCC runtime. On the current
Kali toolchain the from-source build is blocked by version skew: SymCC's runtime CMake needs a
Z3 CMake config (Debian's `libz3-dev` ships none) and predates **LLVM 21** (Kali's default;
only 19/21 are available). Building it therefore requires a supported LLVM (≈15–17) and a Z3
with CMake support, on a pinned toolchain.

Because the backend is a graceful option, this does not block anything: the `concolic` stage's
SymQEMU path is fully integrated and covered by a stubbed end-to-end test, and its real-engine
test is skipped until a `symqemu-<arch>` binary is present (via `LYKOS_SYMQEMU`, a vendored
copy, or `PATH`). angr remains the default, real-tested concolic backend.

## Test status after provisioning

    make -C .. test      # or: python3 -m pytest tests

148 passed, 1 skipped (the real SymQEMU engine). Real-run tests now exercised: Ghidra headless
decompilation, AFL++ coverage fuzzing, angr branch-solving, and GDB root-cause capture.
