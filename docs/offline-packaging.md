# Offline Packaging & Install

---

## Offline Packaging, Bundled Data & Offline Updates

Running offline is a hard constraint on *every* component. Nothing may fetch at runtime.

### 11.1 The installer bundle (single, verifiable, offline)
- Ships the optional engines (Ghidra, QEMU-user, AFL++, GDB, Wine, cross compilers, the
  angr/Unicorn venvs) plus the data below. The stdlib-only core and the desktop UI travel with
  the repo itself, not the bundle. Built on a connected machine whose glibc is ≤ the
  target's and distributed as one `.tar.zst`, so installation needs no network.
- Pin **exact versions** of everything; record them so findings are reproducible (`architecture.md`). The
  bundle's `manifest/BUNDLE.txt` records the target distro, glibc, Python and build date.
- Verify integrity on setup. **Current state:** the bundle carries an *unsigned* `SHA256SUMS`
  manifest; `setup.sh` checks every listed file's hash and refuses any file present but not
  listed, so the guarantee is corruption-resistance and no-added-files — not authenticity. Carry
  the bundle over a trusted channel. **Planned:** sign `SHA256SUMS` and verify the signature at
  setup time, upgrading the guarantee to authenticity.

### 11.2 Bundled data packs (versioned + dated)
| Pack | Contents | Why dated matters |
|---|---|---|
| Signatures | FLIRT/FunctionID/zignatures across libc/toolchain/opt combos | recognition coverage |
| libc DB | libc build → offset tables | exploitation offsets |
| CWE catalog | MITRE CWE (offline) | mapping + guidance |
| CVE/vuln refs | offline CVE data + known-vuln function corpus | known-bug matching; **explicitly show the data's date** |
| Signature DBs | FID/FLIRT/zignatures across compiler×version×opt×arch | stripped fn naming (`pipeline.md`) |
| Prototype/type archives | library header prototypes + data-type archives | typing + taint (`pipeline.md`, `pipeline.md`) |
| Symbolized diff corpus | OSS builds compiled *with* symbols | BinDiff name transfer + known-vuln match (`pipeline.md`.4) |
| Detection rules | dangerous-API catalog, taint rules, Semgrep/Weggli rulesets | CWE detection (`pipeline.md`) |
| Benchmarks | Juliet, LAVA-M, Magma, CGC | self-validation (`coverage.md`) |
| Exploit assets | gadget DBs, PoC/exploit templates | PoC synthesis |

**CVE data packs (built connected, carried offline).** The offline CVE database is built on a
connected machine by `python tools/build_cvedb.py --sqlite --json --clibs`. It produces three
tiers: a small **committed JSON subset** (the curated high-profile seed, travels in the repo), a
large **OSV match index** (`cvedb.sqlite`) for component→CVE matching, and an **NVD reference
pack** (`cve.sqlite`) for CPE/version lookups. The two SQLite packs are large and **git-ignored**,
so they travel with the package alongside the toolchain bundle rather than in the repo. Runtime
discovery of all three lives in `core/lykos/analyze/fingerprint/cvedb.py` (`LYKOS_CVEDB` overrides
the location); the packs are a point-in-time snapshot and age like every other data pack.

### 11.3 Offline update channel (sneakernet)
- Updates ship as **signed, incremental data-pack / tool bundles** carried in on removable media.
- The app verifies signature + version lineage, applies atomically, and records the new versions per case.
- **Staleness is a first-class UI concept:** the app always shows how old the CVE/signature/rule packs are,
  because in an offline deployment they silently rot. Never imply "up to date."
- No telemetry, no phone-home, ever. A hard architectural rule enforced by having zero network bindings and,
  ideally, running the whole stack in a network-isolated namespace.

### 11.4 Hardware & footprint
- Document minimum vs recommended: cores (fuzzing parallelism), RAM (Ghidra + VMs + fuzzers), disk (bundles
  + signature DBs + diff corpus + corpora can be tens of GB). **No GPU required** — the engines are CPU-only (`overview.md`).
- Target: Kali VM ~32 GB RAM, 4+ cores, nested virt (`architecture.md`, `overview.md`). Provide a "lite" install (no diff
  corpus/benchmarks) and a "full" install.

---

## Optional toolchain setup (per-host)

Lykos's core is stdlib-only and runs offline. The heavy analysis engines are **optional**:
each stage locates its tool, runs it, parses the result, and fails clearly (or falls back)
when it is absent. This note records how the toolchain was provisioned and real-run tested on
the Kali development VM, and the one engine that is a from-source build.

### What is actually required

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

### Installed via apt (Kali)

    # the default RE backend + the dynamic toolset
    sudo apt-get install -y rizin rz-ghidra gdb afl++ qemu-user qemu-user-binfmt wine
    # pypcode (P-Code IR) via pip; on the offline bundle it is vendored under vendor/pysite
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

### angr (vendored venv)

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

### Unicorn + Keystone (vendored venv) — firmware rehosting

The `firmware_rehost` stage runs a bare-metal ARM Cortex-M image under the Unicorn CPU
emulator (Fuzzware-style MMIO modelling) via a standalone driver, keeping the core
stdlib-only. Provision a venv the locator checks automatically
(`vendor/unicorn-venv/bin/python`), or set `LYKOS_UNICORN_PYTHON`:

    python3 -m venv vendor/unicorn-venv
    vendor/unicorn-venv/bin/pip install unicorn keystone-engine

`unicorn` (2.1.4, an abi3 wheel — any CPython ≥3.7) does the emulation; `keystone-engine`
is only used by the test suite to assemble sample Cortex-M firmware. Absent Unicorn, the
stage reports rehosting unavailable and everything else still works.

### SymQEMU (built from source, vendored)

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


### One emulator per guest (afl-qemu-trace)

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


### Test status after provisioning

    make ci              # lint + typecheck + GUI harnesses + tests
    make release         # the above, plus the packaged artifact and every quality gate

718 passed, 14 skipped at the time of writing. The skips are the stages whose tool is absent
on the host running them -- that is the intended behaviour, not a gap. Real-run tests exercise
end to end: Ghidra headless decompilation, AFL++ coverage fuzzing (per-guest qemu), angr
branch-solving, GDB root-cause capture, SymQEMU concolic solving, and the JVM path.

A count in a document goes stale the moment someone adds a test; `make ci` is the answer that
cannot.

---

## Offline setup runbook (no install)

Doc 11 is the design position on running offline. This is the procedure. The recommended path
(§ "How it is delivered" below) folds everything into **one** extract-and-run package; the table
here names the two pieces it is built from, which you can also carry separately (the "lean
alternative").

| | What | Size | How it travels |
|---|---|---|---|
| **the repo** | lykos itself — stdlib-only, no pip packages | ~1 MB | inside the package (or `git archive` on its own) |
| **the toolchain bundle** | rizin + rz-ghidra + pypcode (the RE backend), a matching Python interpreter, qemu-user, GDB, AFL++, Wine, the angr/Unicorn venvs | ~1.5 GB | inside the package (or its own `.tar.zst`) |

The default `./package` output is a single `lykos-offline-<date>-<arch>` archive (split into
disc-sized volumes when it does not fit one disc) carrying both. The two can also move separately
— the repo changes constantly and the toolchain almost never does, so re-cutting the ~1 MB repo is
cheap while re-carrying ~1.5 GB is not.

**Neither package is installed on the offline side. Both run in place.** The repo runs
straight from its extracted directory (`./start`, or `./lykos ...`). The toolchain
bundle is a relocatable tree: the debs are extracted into `toolchain/` on the connected
machine, and on arrival that tree is placed under the repo's `vendor/` directory — no package
manager, no `dpkg`, no root, nothing written to a system path.

**The laptop's own libraries are never touched.** Nothing is overwritten, symlinked, or
removed, and — this is the part that matters — the bundle's shared libraries are never put on a
process-wide search path. lykos prepends only the vendored `toolchain/`'s executable directory
to its own `PATH` (which selects *which program* a name runs, not how any program finds its
libraries). Each vendored tool gets its own libraries through a per-tool wrapper `setup.sh`
writes under `vendor/toolchain/.wrappers`: the wrapper sets `LD_LIBRARY_PATH` for that one
process and execs the real binary, so the bundle's libraries stay private to the bundle's own
tools and no system binary is ever relinked against them. This is the failure that made the
previous (`dpkg`-based) approach dangerous — it is designed out here, not merely avoided.

**The repo alone is a working platform.** Extract it and the dynamic half runs: ingest, triage,
black-box fuzzing, the sandbox, crash triage, PoC synthesis, secret extraction, the whole GUI.
What the bundle adds is the static half (the rizin + rz-ghidra + pypcode RE backend, and everything downstream of it),
cross-architecture execution (qemu-user), and the coverage-guided and symbolic engines.

---

### How it is delivered — one extract-and-run package

Build **one** self-contained package on a connected machine, carry it (one file, or a few
disc-sized volumes), extract it on the offline laptop with a script that needs only `tar` + `xz`,
and run it in place. No install, no `setup.sh` step, nothing written outside the folder — the
`vendor/` tree is already fully populated inside the package.

| Build (connected machine) | Carry | Extract on the laptop | Run |
|---|---|---|---|
| `make toolchain-bundle` then `./package` | `dist/lykos-offline-<date>-<arch>.*` (the `.tar.xz` **or** its `.part-NN` volumes, plus `.sha256` and `.EXTRACT.sh`) | `sh lykos-offline-*.EXTRACT.sh` | `cd lykos && ./start` |

`./package` wraps `packaging/make-runnable.sh`. It writes an xz-compressed archive and, when the
archive is larger than one optical disc, **splits it into ≤4600 MiB volumes** (override with
`LYKOS_SPLIT_MB`) so each fits a 4.7 GB disc, alongside a self-contained `*.EXTRACT.sh` that
reassembles, verifies the `.sha256`, and extracts — using only `tar` and `xz`, which ship on every
Kali/Debian base, so the laptop needs nothing bundled to unpack it. (`LYKOS_XZ=-4` trades ratio
for a faster build when you are iterating; the default `-9` is for the disc you burn.)

The package is self-contained for **Python**: it vendors its own interpreter (ABI-matched to the
pypcode wheel and the engine venvs), so the laptop needs no particular `python3` of its own.

**Glibc independence (runs on an OLDER laptop than the build host).** The vendored native binaries
are linked against the build host's glibc, so a bundle built on today's Kali would normally refuse
to load on a laptop whose glibc is older. The package defeats this: on the **first run**
(`./lykos …` or `./start`, also after the folder is copied off a disc) the launcher runs
`packaging/relink-bundle.sh`, which repoints every bundled ELF's interpreter and rpath at the
bundle's **own** loader and libraries (a static `patchelf` ships for this, since it must run before
the bundle's glibc is usable). After that one-time relink — a few seconds, stamped so it is a no-op
afterwards — the tools resolve only the bundle's libraries and the laptop's glibc is never
consulted. So you still build on a convenient modern machine, and it runs on the older air-gapped
VM with **no capability loss**. See `relink-bundle.sh` and the "never touches host libraries" note
below. (A plain `git clone` with no `vendor/toolchain` skips the relink entirely.)

---

### 1. On a connected machine — build the one package

```sh
git clone <lykos> && cd lykos
make test                       # confirm the repo is sound before packaging anything
make toolchain-bundle           # collect engines inside a container matching the target distro
## (Kali rolling by default; needs podman or docker. Pass --target native to collect from an
##  ABI-identical host, but prefer the container -- a native collect misses already-installed deps.)
## -> dist/lykos-toolchain-<distro>-<date>-<arch>.tar.zst  (+ its sha256)

./package                       # fold the working tree + a fully-populated vendor/ into one package
## -> dist/lykos-offline-<date>-<arch>.tar.xz           (one file if it fits a disc)
##    dist/lykos-offline-<date>-<arch>.tar.xz.part-NN   (volumes, if larger than one disc)
##    dist/lykos-offline-<date>-<arch>.sha256           (checksums)
##    dist/lykos-offline-<date>-<arch>.EXTRACT.sh       (reassemble + verify + extract script)
```

`./package` (a thin wrapper over `packaging/make-runnable.sh`) snapshots the **working tree**, not
`HEAD` — so uncommitted fixes ship — and bakes the collected toolchain into `vendor/` so the
package is complete with no later placement step. It reuses the newest
`dist/lykos-toolchain-*.tar.zst`, so re-cut a package after a code change without re-collecting the
toolchain (which almost never changes). The optional heavy extras — the cross-compilers, LLVM,
MinGW, Node — ride along only when you pass `LYKOS_FULL=1`; the default package already runs every
stage for the common host-arch workflow.

Everything is written to `dist/`, which is **gitignored** — build artifacts, never committed, carried
by sneakernet. Burn (or copy) **everything named `lykos-offline-<date>-<arch>.*`**: the `.tar.xz`
*or* all its `.part-NN` volumes, the `.sha256`, and the `.EXTRACT.sh`.

**Lean alternative (two tarballs).** If you would rather carry the ~1 MB repo and the ~1.5 GB
toolchain separately — e.g. you re-cut the repo often — `make repo-tarball` writes
`dist/lykos-repo.tar.gz` and the toolchain bundle is placed on the far side by its own `setup.sh`
(`LYKOS_ROOT=$PWD /tmp/lt/setup.sh`, which verifies the manifest and copies `toolchain/` under
`vendor/`). The combined `./package` output above is the recommended path; this one trades a larger
re-carry for a smaller repo refresh.

### 2. On the offline workstation — extract and run

Copy all the package files off the disc(s) into **one empty, writable** directory (not the
read-only disc), then:

```sh
sh lykos-offline-<date>-<arch>.EXTRACT.sh   # verifies .sha256, reassembles volumes, extracts ./lykos/
                                            # needs only tar + xz (present on every Kali/Debian)
cd lykos
./lykos doctor                              # FIRST run self-relinks the bundled tools (a few seconds)
```

Nothing is installed and nothing is written outside `./lykos`. The first `./lykos` (or `./start`)
invocation runs `packaging/relink-bundle.sh` once — repointing the bundled binaries at the bundle's
own glibc so they load on this (older) laptop — then stamps it done. `doctor` prints what this host
can now do; a tool it still names as missing is a bundle gap, not an environment problem.

### 3. Start the console

```sh
./start                                     # local server, loopback only -> http://127.0.0.1:8787
```

`./start` (or `./RUN.sh`) brings up the web UI; `./lykos analyze <binary> --budget 600` runs the
same pipeline from the shell. Both use the bundle's own vendored Python — the laptop needs no
`python3` of its own.

### 4. Confirm (optional, on a machine with the quality gate)

```sh
./lykos doctor --strict   # exit 1 if a REQUIRED tool is missing
make test                 # stages whose tool is absent skip, and say so
```

`make test` skipping is the designed behaviour, not a gap: a stage whose engine is absent declines
with a reason. `lykos doctor` is how you tell the two apart. The bundle's `SHA256SUMS`/`.sha256`
manifests are **unsigned** — they prove the package arrived un-corrupted and un-added-to, not that
it is authentic — so carry it over a trusted channel.

---

### What each tool buys, and what its absence costs

`lykos doctor` prints this for **your** host, with a fallback line for anything missing.
The table below is the same data, for planning before you build the bundle.

| Tier | Tool | Unlocks | Without it |
|---|---|---|---|
| required | Python 3 | the platform | nothing runs |
| required | bubblewrap | the sandbox tier used for every execution | drops to rlimits-only: no network namespace, no read-only root. It still **runs**, which is the problem |
| required | rizin + rz-ghidra | the default `disassemble`/`decompile` backend (CFG, xrefs, decompiled C) — **no JVM** | no default RE engine; disassembly falls back to Ghidra only if the heavy profile is installed |
| required | pypcode | the Ghidra P-Code IR that `detect_cwe` taint/bounds/int-overflow consume (Ghidra SLEIGH, no JVM; vendored under `vendor/pysite`) | the native backend still decompiles, but P-Code-based memory-safety detection degrades |
| optional | Ghidra (not bundled) | an alternative RE backend with stronger auto-analysis on some stripped/optimized binaries, via `LYKOS_DECOMPILER=ghidra` | the native rizin backend is used instead. **Replaced by rizin/rz-ghidra + pypcode and not shipped in the bundle**; install Ghidra separately only if a hard binary analyses poorly |
| recommended | qemu-user | executing any non-host-architecture binary | cross-arch targets cannot run at all |
| recommended | GDB | `root_cause` detail, `multi_debug`, the runtime monitor, dynamic taint | `root_cause` falls back to the stdlib ptrace helper; the others decline |
| recommended | C compiler | building the eval corpus and real-gate fixtures | those gates skip; analysis of supplied binaries is unaffected |
| optional | AFL++ | `coverage_fuzz` | black-box `fuzz` only — measured ~40× slower on ARM |
| optional | afl-qemu-trace (per guest) | `coverage_fuzz` on a non-host architecture | declines for those guests, and prints the build command |
| optional | JDK / Java | building and running JAR targets | Java targets analyse statically but cannot execute |
| optional | Wine | PE execution, behaviour trace, Win32 monitor | PE analyses statically; `synthesize_poc` still derives an overflow from the frame |
| optional | cross compilers | the architecture gate's fixtures | `make arch-gate` covers fewer architectures. **Not in the default `./package` bundle; add with `LYKOS_FULL=1 ./package`** — the pipeline compiles source only natively and *executes* foreign-arch binaries under qemu-user (which stays, with each arch's runtime libs), so it never cross-compiles; only the arch-gate self-test needs them, so the default package omits them and `LYKOS_FULL=1` folds them (plus LLVM, MinGW, Node) back in |
| optional | angr / SymQEMU | `concolic` | the stage declines |
| optional | Unicorn | `firmware_rehost` | declines; carving and headerless ID still work |
| optional | Node.js | `make gui` harnesses | that target fails; the UI is unaffected |

### Things that bite

**A venv is not portable by default.** The bundled angr and Unicorn venvs record the
interpreter they were built against. `install.sh` rewrites `pyvenv.cfg` to this host's
`python3` and then checks the venv actually runs — if the Python versions are too far apart it
says so rather than leaving you an engine that fails at first use. Build the bundle on a host
whose Python matches the target where you can.

**`afl-qemu-trace` is an emulator, and `file` lies about it.** It is always built for the
host; the *guest* it can run is fixed at build time. `file` reporting "ELF 64-bit x86-64" tells
you nothing about which binaries it executes — only `afl-qemu-trace --version` does, which
prints e.g. `qemu-aarch64 version 5.2.50`. `lykos doctor` reports the guest, not the file
type. Build one per architecture with `examples/afl-qemu/build.sh <arch>`.

**The JVM (for JAR/class targets, and the optional Ghidra backend) needs a JDK, not just a JRE**,
and it is among the largest items in the bundle. The default RE backend (rizin + rz-ghidra +
pypcode) needs no JVM at all.

**No telemetry, ever.** Nothing in the platform opens an outbound connection. To prove it
rather than trust it, run under a network namespace:

```sh
bwrap --ro-bind / / --unshare-net --dev /dev --proc /proc --chdir "$PWD" \
      -- ./lykos doctor
```

**Data packs rot silently.** The bundled CVE fingerprint database is a point-in-time snapshot
(`LYKOS_CVEDB` overrides it). An offline deployment has no way to notice it has aged, so
treat the bundle's `manifest/BUNDLE.txt` date as the age of your CVE data and re-cut the
bundle on a schedule you decide.
