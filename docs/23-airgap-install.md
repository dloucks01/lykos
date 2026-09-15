# 23 — Air-gap install runbook

Doc 11 is the design position on air-gap. This is the procedure.

Two things move to the air-gapped workstation, and they are deliberately separate:

| | What | Size | How it travels |
|---|---|---|---|
| **the repo** | lykos itself — stdlib-only, no pip packages | ~1 MB | `git clone` (a bundle, a mirror, or a USB copy of the working tree) |
| **the toolchain bundle** | Ghidra, qemu-user, GDB, AFL++, Wine, the angr/Unicorn venvs | ~1–3 GB | one tarball, built on a connected machine |

They are separate because the repo changes constantly and the toolchain almost never does.
Re-cloning is cheap; re-carrying 3 GB is not.

**The repo alone is a working platform.** Clone it and the dynamic half runs: ingest, triage,
black-box fuzzing, the sandbox, crash triage, PoC synthesis, secret extraction, the whole GUI.
What the bundle adds is the static half (Ghidra, and everything downstream of it),
cross-architecture execution (qemu-user), and the coverage-guided and symbolic engines.

---

## 1. On a connected machine

```sh
git clone <lykos> && cd lykos
make test                       # confirm the repo is sound before bundling anything
bash packaging/collect-toolchain.sh
# collects inside a container matching the target distro (Kali rolling by default; needs
# podman or docker), or pass --target native to collect from an ABI-identical host.
# -> dist/lykos-toolchain-<distro>-<date>-<arch>.tar.zst  (+ its sha256)
```

The collector takes its package list from `lykos.toolchain` — the same table `lykos doctor`
reports and this document describes — so a tool cannot be added in one place and forgotten in
the others.

Carry to the air-gapped side:

* the bundle tarball **and the sha256 you printed** (verify it on arrival, not just on
  departure — the point of the checksum is the journey)
* the repo, as a `git bundle` if you want history:
  `git bundle create lykos.bundle --all`

## 2. On the air-gapped workstation

```sh
git clone lykos.bundle lykos        # or copy the working tree
cd lykos
PYTHONPATH=core python3 -m lykos doctor     # what works right now, before any install
```

Then the toolchain:

```sh
mkdir -p /tmp/lt && tar xf lykos-toolchain-*.tar.zst -C /tmp/lt
/tmp/lt/install.sh --verify-only            # checksums only, installs nothing
LYKOS_ROOT=$PWD /tmp/lt/install.sh          # verifies, installs, then re-runs doctor
```

`install.sh` verifies before it installs: every file the manifest lists must match its hash,
**and** the set of files in the bundle must equal the set the manifest names — an unlisted file
(one an attacker added to ride along on the `debs/*.deb` install) is refused, not installed. It
then finishes by printing the capability report, so the outcome of an install is a list of what
you can now do — not a claim that it worked.

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

`lykos doctor` prints this for **your** host, with the install line for anything missing.
The table below is the same data, for planning before you build the bundle.

| Tier | Tool | Unlocks | Without it |
|---|---|---|---|
| required | Python 3 | the platform | nothing runs |
| required | bubblewrap | the sandbox tier used for every execution | drops to rlimits-only: no network namespace, no read-only root. It still **runs**, which is the problem |
| required | Ghidra | `disassemble` and everything downstream: `detect_cwe`, taint, bounds, directed fuzzing | the whole static half. Fuzzing still finds crashes; nothing explains one |
| recommended | qemu-user | executing any non-host-architecture binary | cross-arch targets cannot run at all |
| recommended | GDB | `root_cause` detail, `multi_debug`, the runtime monitor, dynamic taint | `root_cause` falls back to the stdlib ptrace helper; the others decline |
| recommended | C compiler | building the eval corpus and real-gate fixtures | those gates skip; analysis of supplied binaries is unaffected |
| optional | AFL++ | `coverage_fuzz` | black-box `fuzz` only — measured ~40× slower on ARM |
| optional | afl-qemu-trace (per guest) | `coverage_fuzz` on a non-host architecture | declines for those guests, and prints the build command |
| optional | JDK / Java | building and running JAR targets | Java targets analyse statically but cannot execute |
| optional | Wine | PE execution, behaviour trace, Win32 monitor | PE analyses statically; `synthesize_poc` still derives an overflow from the frame |
| optional | cross compilers | the architecture gate's fixtures | `make arch-gate` covers fewer architectures |
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

**Ghidra needs a JDK, not just a JRE**, and it is the single largest item in the bundle.

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
