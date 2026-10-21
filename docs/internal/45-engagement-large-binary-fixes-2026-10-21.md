# 45 — Real-engagement failures on a 20–100 MB native ELF: fixes (2026-10-21)

An operator ran the `20261021` air-gap bundle against a real **C/C++ native, dynamically-linked
x86-64 ELF** (20 MB, with 100 MB targets also in scope) and got **only static findings** — the same
shape as the earlier air-gap engagement ([[offline-bundle-tool-gaps]]), but on a large real binary
rather than a planted fixture. Reported symptoms, mapped to cause:

| Symptom | Cause |
|---|---|
| Coverage fuzzing: "afl-fuzz aborted, fork server handshake failed" | afl qemu-mode set no fork-server init timeout / `-t`; a big binary is far slower to reach the fork point under qemu than the gate's tiny ELF, so the handshake times out. |
| Directed fuzzing cut short; 10% coverage | 900 s default budget spent on recon before fuzzing got a slice. |
| Concolic: angr "can't handle sim file" TypeError | angr whole-program on a large image fails/OOMs; also a `SimFile` setup bug. |
| Env fuzzing: "getenv used but no environment strings recovered" | env-name recovery is a blind all-caps string scan with no link to the getenv call site; misses on a stripped/large binary. |
| Missing libqasan | `make-runnable.sh` never injected it (built by `build-engines.sh`, to a path the afl-qemu inject does not pick up). |
| Missing weggli | inject silently skips when `engines.env` was not sourced; irrelevant to a binary-only target anyway. |
| "Would like progress for doctor" | `doctor` computes every probe before printing. |

## Fixes

**Done + measured:**

- **afl qemu-mode handshake hardening** (`fuzz/aflpp.py`): a size-scaled `AFL_FORKSRV_INIT_TMOUT`
  (120 s + 3 s/MB, cap 600 s), `AFL_SKIP_BIN_CHECK=1`, and an auto-extending `-t 5000+` exec
  timeout — all `setdefault`, so an operator's env still wins. (Not reproducible on the dev host:
  its `afl-fuzz`↔`afl-qemu-trace` are a mismatched build — the "host-qemu masking trap" from
  [[airgap-crossarch-qemu-fix]] — so this is verified in the bundle's cold-container gate, not here.)
- **Large-binary mode** (`analyze/orchestrate.py`) — **purely additive; no lane is ever dropped by
  size** (operator constraint: a large binary must lose NO capability). A size flag
  (`_LARGE_BINARY_MB=40`, `_HUGE_BINARY_MB=90`) emits an `autopilot.large_binary` event and gives
  the scoped lanes a longer slice + a size-scaled budget. The expensive lanes are kept tractable by
  SCOPING, not skipping: concolic runs at every size (angr already loads `auto_load_libs=False` and
  explores from a bounded state/step budget; measured below it handles a 95MB image in ~2s / 324MB),
  and structural analysis prioritises the attack surface (doc 40 roadmap). An earlier revision
  skipped concolic past HUGE — reverted, because skipping is degradation.
  **[measured]** through the real Autopilot on inflated native ELFs:
  - 45 MB & 95 MB: `large_binary` fired, 11 findings each, planted overflow driven to **L2**
    (~180–200 s) — even with afl-qemu down on the dev host (directed-fuzz + crashless
    overflow-synth carried it), i.e. NOT a silent "static only".
  - angr_driver on the 95 MB binary: ok, 1 input generated, 324MB RSS, 2.0s — large binaries do
    NOT need the symbolic lane skipped.
- **Concolic resilience** (`symbolic/angr_driver.py`): the stdin `SimFile` model varies by angr
  version — a plain `SimFile` as `stdin=` raised "can't handle sim file" (TypeError) on the bundle's
  angr and took the whole lane down. Now it falls back SimFile → SimFileStream → default symbolic
  stdin, so a version/model quirk degrades the binding at worst, never the lane. Verified the
  primary path is unchanged on angr 9.2.217 (95MB + small binary both still generate inputs).

**Build-time (packaging):**

- **libqasan inject** (`make-runnable.sh`): copy `$LYKOS_QASAN` to `usr/lib/afl/libqasan.so` (where
  `vendorenv.py` auto-sets `LYKOS_QASAN`). Loud warnings when any optional engine (afl-qemu/symqemu/
  weggli/qasan) is not injected, so a gap is visible at build time, not on the air-gapped laptop.

**Still to land:** env-name recovery (backward slice from the getenv call site to its `.rodata`
arg), the angr `SimFile` bug + size-gating, a doctor progress stream, a **budget field in the web
Autopilot UI** (today the button sends no budget → 900 s default; CLI `--budget` or a one-line
`DEFAULT_TARGET_BUDGET` edit is the current workaround), and **hardening `make verify-e2e` with a
large binary** so the handshake/large-binary paths are gated.

## Operator workarounds on the shipped `20261021` disc (no rebuild)

- Coverage: `export AFL_FORKSRV_INIT_TMOUT=300000 AFL_SKIP_BIN_CHECK=1 AFL_SKIP_CPUFREQ=1` before
  launching (lykos inherits and does not override these).
- Budget: CLI `./lykos analyze <bin> --budget 21600 --seed <good_input>`; or edit
  `core/lykos/analyze/budget.py` `DEFAULT_TARGET_BUDGET` for the web default; restart `serve`.
- Heap triage by hand: bundled valgrind (works on the target's glibc 2.42-5).

Related: [[offline-bundle-tool-gaps]], [[airgap-engagement-gaps]], [[airgap-crossarch-qemu-fix]].
