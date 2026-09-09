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

## SymQEMU (built from source, vendored)

SymQEMU has no distribution package and, on the current Kali toolchain, its from-source build
is blocked by version skew (SymCC's runtime CMake needs Z3's CMake config, which Debian's
`libz3-dev` omits, and it predates Kali's default LLVM 21). It is therefore built in an
**Ubuntu 22.04 container** (the authors' known-good toolchain: LLVM 14 + Z3) and the resulting
emulator vendored:

    ./packaging/build-symqemu.sh      # docker build in 22.04, extract to vendor/symqemu/

This produces `vendor/symqemu/symqemu-x86_64` (the SymQEMU-patched `qemu-x86_64`, 9.1.1) plus
its `libSymCCRtShared.so`; the locator finds them and the runner sets `LD_LIBRARY_PATH` to the
vendored directory so the runtime library resolves. `vendor/` is gitignored; the Dockerfile
(`packaging/symqemu.Dockerfile`) and build script are committed for reproducibility.

Verified working: from a non-magic seed, SymQEMU flips the branch constraints of a 4-byte file
gate and generates `MAGC…`, which crashes the target in the sandbox -> a Confirmed concolic
finding. angr remains the default backend; `params.backend=symqemu` selects this engine.


## Test status after provisioning

    make -C .. test      # or: python3 -m pytest tests

150 passed, 0 skipped. Real-run tests now exercised end-to-end: Ghidra headless
decompilation, AFL++ coverage fuzzing, angr branch-solving, GDB root-cause capture, and
SymQEMU concolic solving.
