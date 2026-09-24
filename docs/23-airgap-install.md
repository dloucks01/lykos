# 23 — Air-gap setup runbook (no install)

Doc 11 is the design position on air-gap. This is the procedure.

Two things move to the air-gapped workstation, and they are deliberately separate:

| | What | Size | How it travels |
|---|---|---|---|
| **the repo** | lykos itself — stdlib-only, no pip packages | ~1 MB | one tarball (`git archive`), built on a connected machine |
| **the toolchain bundle** | rizin + rz-ghidra + pypcode (the RE backend), a matching Python interpreter, qemu-user, GDB, AFL++, Wine, the angr/Unicorn venvs | ~1.5 GB | one tarball, built on a connected machine |

They are separate because the repo changes constantly and the toolchain almost never does.
Re-cutting the ~1 MB repo tarball is cheap; re-carrying 3 GB is not.

**Neither package is installed on the air-gapped side. Both run in place.** The repo runs
straight from its extracted directory (`PYTHONPATH=core python3 -m lykos ...`). The toolchain
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

## Two ways to deliver it — pick by what the laptop can run

| | Build | Carry | Run on laptop | Portability |
|---|---|---|---|---|
| **Container image** (recommended) | `make container` (needs podman/docker + network) | one `dist/lykos-container-*.tar.zst` | `podman load` + `podman run` | **Runs on any distro.** Carries its own libc/`ld-linux`/Python/tools; only the kernel is shared |
| **Unzip-and-run folder** | `make runnable` (needs the toolchain bundle) | one `dist/lykos-airgapped-*.zip` | `unzip -o` + `./RUN.sh` | Coupled to the laptop's **glibc** — build on a base whose glibc is **≤** the laptop's, or the binaries won't load |

Both are fully self-contained for **Python**: the folder now vendors its own interpreter (matching
the pypcode wheel and the engine venvs, which are ABI-locked to one Python minor), so it no longer
needs the laptop to have any particular `python3`; the container obviously carries its own. The
**only** thing the folder cannot escape is glibc skew — the vendored native binaries are linked
against the build host's glibc. The container escapes that too, which is why it is the default
recommendation. If the laptop has no container runtime, use the folder and build it on the oldest
glibc you must support.

### Container: build, carry, run

```sh
# on a CONNECTED machine
make container                                  # -> dist/lykos-container-YYYYMMDD-<arch>.tar.zst (+ .sha256)

# on the AIR-GAPPED laptop (podman shown; docker is identical)
sha256sum -c lykos-container-*.tar.zst.sha256
zstd -dc lykos-container-*.tar.zst | podman load
mkdir -p cases
podman run --rm -p 127.0.0.1:8787:8787 -v "$PWD/cases:/cases" lykos:latest
# then open http://127.0.0.1:8787
```

Rootless podman needs no daemon and no root — ideal for a locked-down box. The container is a
strong isolation boundary in its own right; lykos's internal `bwrap` detonation sandbox may
degrade to rlimits-only inside it (nested user namespaces), which is an acceptable trade for the
portability. `-v "$PWD/cases:/cases"` persists analyses on the host between runs.

---

## 1. On a connected machine

```sh
git clone <lykos> && cd lykos
make test                       # confirm the repo is sound before packaging anything
bash packaging/collect-toolchain.sh
# collects inside a container matching the target distro (Kali rolling by default; needs
# podman or docker), or pass --target native to collect from an ABI-identical host.
# -> dist/lykos-toolchain-<distro>-<date>-<arch>.tar.zst  (+ its sha256)

git archive --format=tar.gz --prefix=lykos/ -o dist/lykos-repo.tar.gz HEAD
# the repo's tracked files at HEAD, no .git history, no build artifacts. -> dist/lykos-repo.tar.gz
( cd dist && sha256sum lykos-repo.tar.gz > lykos-repo.tar.gz.sha256 )
```

`make repo-tarball` runs both lines above; `make toolchain-bundle` runs the collector. The
toolchain collector prints the bundle's sha256 for you; the `git archive` line does not, so the
`repo-tarball` target cuts the repo tarball's checksum for you as shown.

Both tarballs are written to `dist/`, which is **gitignored** — they are build artifacts, never
committed to the repo. They travel to the air-gapped side by sneakernet, not by `git`. The repo
tarball is a point-in-time snapshot with no history: it runs in place but cannot `git log`, diff,
or pull updates. Carry a `git bundle` instead (`git bundle create dist/lykos.bundle --all`) only
if you need version control on the far side.

The collector takes its package list from `lykos.toolchain` — the same table `lykos doctor`
reports and this document describes — so a tool cannot be added in one place and forgotten in
the others.

Carry both tarballs to the air-gapped side, **each with the sha256 you printed** (verify them on
arrival, not just on departure — the point of the checksum is the journey):

* `lykos-toolchain-<distro>-<date>-<arch>.tar.zst`
* `lykos-repo.tar.gz`

## 2. On the air-gapped workstation

```sh
tar xzf lykos-repo.tar.gz                   # creates ./lykos/
cd lykos
PYTHONPATH=core python3 -m lykos doctor     # what works right now, before the toolchain is placed
```

Then the toolchain. Nothing is installed: `setup.sh` places the extracted tree under the
repo's `vendor/` and lykos runs it from there.

```sh
mkdir -p /tmp/lt && tar xf lykos-toolchain-*.tar.zst -C /tmp/lt
/tmp/lt/setup.sh --verify-only              # checksums only, places nothing
LYKOS_ROOT=$PWD /tmp/lt/setup.sh            # verifies, places under vendor/, then re-runs doctor
```

`setup.sh` verifies before it places anything: every file the manifest lists must match its
hash, **and** the set of files in the bundle must equal the set the manifest names — an
unlisted file (one an attacker added to ride along when the `toolchain/` tree is copied) is
refused, not placed. It uses no `sudo` and no package manager; it copies `toolchain/` to
`vendor/toolchain`, the `angr`/`unicorn` venvs to `vendor/`, and (only if the collect image
packaged the optional Ghidra) Ghidra to `vendor/ghidra`, then finishes by printing the capability
report — so the outcome is a list of what you can now do, not a claim that it worked.

If you extract the bundle directly at `<repo>/vendor` (rename the extracted directory to
`vendor`), even `setup.sh` is optional: lykos finds `vendor/toolchain` on its own. `setup.sh`
is still worth running, because it repoints the venvs at this host's `python3` and runs the
verification. Point lykos at a toolchain in a non-default location with `LYKOS_VENDOR=<dir>`
or `LYKOS_TOOLCHAIN=<dir>/toolchain`.

The manifest (`SHA256SUMS`) is **unsigned**: it proves the bundle arrived un-corrupted and
un-added-to, not that it is authentic. An attacker who can rewrite the whole bundle can rewrite
the manifest to match, so carry the bundle over a trusted channel. (Future step: sign
`SHA256SUMS` and verify the signature here.)

## 3. Confirm

```sh
PYTHONPATH=core python3 -m lykos doctor --strict   # exit 1 if a REQUIRED tool is missing
make test                                          # stages whose tool is absent skip, and say so
make release                                       # the full quality gate, ~25 min
```

`make test` skipping is the designed behaviour, not a gap: a stage whose engine is absent
declines with a reason. `lykos doctor` is how you tell the two apart.

---

## What each tool buys, and what its absence costs

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
| optional | cross compilers | the architecture gate's fixtures | `make arch-gate` covers fewer architectures. **Not shipped in the `make runnable` bundle** — the pipeline compiles source only natively and *executes* foreign-arch binaries under qemu-user (which stays, with each arch's runtime libs), so it never cross-compiles; only the arch-gate self-test needs them |
| optional | angr / SymQEMU | `concolic` | the stage declines |
| optional | Unicorn | `firmware_rehost` | declines; carving and headerless ID still work |
| optional | Node.js | `make gui` harnesses | that target fails; the UI is unaffected |

## Things that bite

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
      -- env PYTHONPATH=core python3 -m lykos doctor
```

**Data packs rot silently.** The bundled CVE fingerprint database is a point-in-time snapshot
(`LYKOS_CVEDB` overrides it). An air-gapped deployment has no way to notice it has aged, so
treat the bundle's `manifest/BUNDLE.txt` date as the age of your CVE data and re-cut the
bundle on a schedule you decide.
