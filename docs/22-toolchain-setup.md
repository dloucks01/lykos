# 22 — Optional toolchain setup (per-host)

Lykos's core is stdlib-only and runs offline. The heavy analysis engines are **optional**:
each stage locates its tool, runs it, parses the result, and fails clearly (or falls back)
when it is absent. This note records how the toolchain was provisioned and real-run tested on
the Kali development VM, and the one engine that is a from-source build.

## What is actually required

Only two things are hard requirements. Everything else buys a capability, and its absence is
reported rather than hidden -- the workbench greys the control and names the reason, and the
stage declines with the same text if you launch it anyway.

| | Needed for | Without it |
|---|---|---|
| **python3** | the platform | — (runtime is stdlib-only; no pip packages) |
| **bubblewrap** (`bwrap`) | every sandboxed execution | the sandbox drops to rlimits-only: no network namespace, no read-only root. It still runs, which is the problem -- this is the one degradation you do not want silent when the binary is hostile |
| **rizin + rz-ghidra + pypcode** | `disassemble`, and so `detect_cwe`, taint, bounds, integer overflow, directed fuzzing (the default RE backend, no JVM; Ghidra headless is an optional alternate via `LYKOS_DECOMPILER=ghidra`) | the whole static half. Fuzzing still finds crashes; nothing explains one |
| **qemu-user** | executing any non-host binary | cross-architecture targets cannot run at all |
| **gcc/cc** | building the eval corpus and real-gate fixtures | `make eval-gate` / `real-gate` skip |
| **gdb** | `root_cause` detail, `multi_debug`, runtime monitor | root_cause falls back to the stdlib ptrace helper; multi_debug declines |
| **afl-fuzz** + a per-guest `afl-qemu-trace` | `coverage_fuzz` | black-box `fuzz` only -- measured 40x slower on ARM (see below) |
| **java** | JAR/class targets | Java targets triage and analyse statically but cannot be run |
| **wine** | Windows PE execution | PE analyses statically; `synthesize_poc` still derives an overflow from the frame |
| **symqemu**, **angr**, **Unicorn** | `concolic`, `firmware_rehost` | those stages decline |

Python: verified on 3.14 here. The code uses no 3.10+ syntax and no third-party packages, so
older 3.x very likely works -- but that is inference, not a tested claim.

## Installed via apt (Kali)

    # the default RE backend + the dynamic toolset
    sudo apt-get install -y rizin rz-ghidra gdb afl++ qemu-user qemu-user-binfmt wine
    # pypcode (P-Code IR) via pip; on the air-gap bundle it is vendored under vendor/pysite
    pip install pypcode
    # OPTIONAL: only if you want the Ghidra headless alternate (LYKOS_DECOMPILER=ghidra)
    sudo apt-get install -y ghidra default-jdk

- **Ghidra 12.1.3** (optional alternate backend) — headless at `/usr/share/ghidra/support/analyzeHeadless`; the locator
  finds it automatically. Ghidra 11.3+/12 dropped bundled Jython for PyGhidra (whose jpype
  wheels stop at CPython 3.13), so the export post-script is a **Java** GhidraScript
  (`ExportAnalysis.java`), which Ghidra compiles on the fly and which works on every Ghidra
  version. No PyGhidra/Jython setup required.
- **AFL++** — `afl-fuzz` plus the instrumenting compilers (`afl-cc`). The `coverage_fuzz`
  stage uses qemu-mode (`-Q`) by default. See **one emulator per guest** below: a distribution
  package ships at most one `afl-qemu-trace`, and which architecture it can run is not what
  `file` says. If none matches, pass `params.qemu=false` and compile the target with `afl-cc`
  (instrumented mode), or use the black-box `fuzz` stage.
- **GDB** — the primary `root_cause` backend (fault address via `$_siginfo`, mappings, and
  faulting-instruction bytes). The pure-stdlib ptrace helper is the fallback.
- **QEMU user** — cross-architecture execution in the sandbox.

## angr (vendored venv)

angr is Python but heavy; it runs in its own interpreter via the standalone driver. Provision
a venv the locator checks automatically (`vendor/angr-venv/bin/python`), or set
`LYKOS_ANGR_PYTHON`:

    python3 -m venv vendor/angr-venv
    vendor/angr-venv/bin/pip install 'angr==9.3.4'

`vendor/` is gitignored (machine-specific). Pin **angr 9.3.4**: it works on CPython 3.14 (the
unicorn engine is disabled, which our directed exploration does not require), whereas the current
unpinned release (angr 10.x) changes the exploration API and the concolic driver no longer solves —
the stage runs but confirms nothing. The venv interpreter must match the core interpreter's ABI
(3.14) so the vendored cp314 `pypcode` on `PYTHONPATH` loads inside the driver.

## Unicorn + Keystone (vendored venv) — firmware rehosting

The `firmware_rehost` stage runs a bare-metal ARM Cortex-M image under the Unicorn CPU
emulator (Fuzzware-style MMIO modelling) via a standalone driver, keeping the core
stdlib-only. Provision a venv the locator checks automatically
(`vendor/unicorn-venv/bin/python`), or set `LYKOS_UNICORN_PYTHON`:

    python3 -m venv vendor/unicorn-venv
    vendor/unicorn-venv/bin/pip install unicorn keystone-engine

`unicorn` (2.1.4, an abi3 wheel — any CPython ≥3.7) does the emulation; `keystone-engine`
is only used by the test suite to assemble sample Cortex-M firmware. Absent Unicorn, the
stage reports rehosting unavailable and everything else still works.

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


## One emulator per guest (afl-qemu-trace)

`afl-qemu-trace` is an emulator. It is always built for the **host**, and the **guest** it can
run is fixed at build time by `CPU_TARGET`. So `file afl-qemu-trace` reporting "ELF 64-bit
x86-64" tells you nothing about which binaries it can execute. Ask qemu:

    $ afl-qemu-trace --version
    qemu-aarch64 version 5.2.50

That distinction is not academic. The packaged `afl-qemu-trace` on this host emulates
**aarch64**, so `coverage_fuzz` worked on ARM64 targets and aborted at the fork-server
handshake on x86-64 ones -- the reverse of what the file command suggests.

Lykos therefore resolves one **per target**: an arch-suffixed neighbour
(`afl-qemu-trace-arm`) or an explicit `LYKOS_AFL_QEMU_<ARCH>`, and it verifies the guest from
that version banner before using it. Naming a file `-arm` does not make it emulate ARM, and an
unverified one aborts mid-campaign. When nothing matches, the stage declines and prints the
build command instead of running a campaign that cannot work.

Build one per architecture you care about:

    examples/afl-qemu/build.sh arm        # -> /usr/local/bin/afl-qemu-trace-arm
    examples/afl-qemu/build.sh x86_64     # -> /usr/local/bin/afl-qemu-trace-x86-64
    examples/afl-qemu/build.sh aarch64

Build-time only (not needed at runtime): `ninja`, `meson`, `bison`, `flex`,
`libglib2.0-dev`, `libpixman-1-dev`, `python3-dev`. Note that qemu's configure does not get on
with very new CPython, so the script pins `/usr/bin/python3` -- if your `python3` is a venv,
that matters.

Why bother, measured on jhead:

| path | exec/s |
|---|---|
| black-box `fuzz` through qemu-user, coverage armed | ~39 |
| `coverage_fuzz`, AFL++ fork server (32-bit ARM) | **~1,965** |

The fork server is the whole difference: it removes process startup from every execution,
which is ~50% of a cross-architecture run. Batching the sandbox instead was measured at +20%
and is not implemented for that reason.


## Test status after provisioning

    make ci              # lint + typecheck + GUI harnesses + tests
    make release         # the above, plus the packaged artifact and every quality gate

718 passed, 14 skipped at the time of writing. The skips are the stages whose tool is absent
on the host running them -- that is the intended behaviour, not a gap. Real-run tests exercise
end to end: Ghidra headless decompilation, AFL++ coverage fuzzing (per-guest qemu), angr
branch-solving, GDB root-cause capture, SymQEMU concolic solving, and the JVM path.

A count in a document goes stale the moment someone adds a test; `make ci` is the answer that
cannot.
