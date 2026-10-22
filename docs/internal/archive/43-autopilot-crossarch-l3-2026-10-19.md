# 43 — The Autopilot reaches cross-arch L3 (crashless `build_exploit` runs first) (2026-10-19)

Follows docs [41](41-weaponization-breadth-2026-10-19.md) and
[42](42-strategy-expansion-2026-10-19.md). Those delivered the cross-arch **ret2libc → `system`**
ladder (8 arches) and the execstack ret2shellcode ladder (7 arches) in the `build_exploit` stage
itself. This doc records a production-path defect found while air-gap-validating the bundle: the
capability existed but the **Autopilot did not reach it** for cross-arch targets.

Every claim is **[measured]** — a number from a run here — against the air-gap fixtures
(`vuln_<arch>`, built `-O1 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -no-pie
-static`), driven through `orchestrate.run_case_autopilot` with a live `WorkerPool` (the same entry
point the webgui server calls) at a 300 s/target budget.

---

## Symptom

The air-gap webgui+Autopilot run reached only **L1** on `aarch64` / `s390x` while the bundle's
exploit stage, driven directly (`enqueue_exploit(strategy="auto")`), reached a verified **L3 shell
in ~1 s** on every buildable ISA **[measured: aarch64 1.1 s, s390x 1.0 s, ppc 0.9 s, riscv64 0.9 s,
loongarch64 1.3 s]**. So the weaponization worked; the orchestration never ran it.

## Root cause

`build_exploit(strategy="auto")` has a **crashless** path: it recovers its own IP-control offset
with a deterministic cyclic probe and drives ret2win / ret2libc / the cross-arch ret2libc chain with
no fuzzer crash required. The pipeline placed that call **last in the `recover` phase**, behind the
heavy recon stages. On a real static cross-arch binary those stages spend the phase's 30 % allowance
— `disassemble` alone recovered **1057 functions** and `detect_cwe` **timed out** — so by the time
`build_exploit` was reached `budget.slice()` returned 0 and the stage was **skipped "no budget left
in the recover phase" on every run**. The overflow→L3 auto path never executed.

For a target where the qemu-user fuzzer happens to land the overflow crash, the *crash-driven*
`build_exploit` later in the pass still reaches L3 — which is why `s390x` (19 crashes) passed and
`aarch64` (1 crash) did not. L3 through the Autopilot was therefore a **lottery on the fuzzer's
crash yield**, not a property of the target.

## Fix

`core/lykos/analyze/orchestrate.py`: the crashless `build_exploit(strategy="auto")` now runs
**first in the `recover` phase**, before `dynamic_run` (which blocks waiting on a stdin-reading
target and waits out its whole slice) and `disassemble`. At the top of the phase the full recover
allowance is available, the stage gets a real slice, and it spends only the ~1 s it needs. It is
gated on `< L3` (a target already weaponized pays nothing) and self-gates per arch/mitigation
(PIE-emulated, managed runtimes, no gadget → a cheap honest decline). The old starved end-of-phase
call is removed; nothing else moved.

## Result — valid in-process `run_case_autopilot`, 300 s budget **[measured 2026-10-19]**

| arch | baseline (worker live) | with fix | fuzzer crashes |
|---|---|---|---|
| aarch64 | **L1** | **L3** | 1 |
| s390x | L3 | L3 | 19 |
| x86-64 | L2 | L2 (unchanged) | 37 |
| ppc32 (BE) | — | **L3** (7 PoCs) | 25 |
| riscv64 | — | **L3** | **0** |

`riscv64` is the proof: **zero** fuzzer crashes, yet a verified L3 shell — the deterministic early
path no longer depends on the fuzzer. `aarch64` climbed L1→L3. No arch regressed; `x86-64` holds at
its pre-existing fixture ceiling (its L3 here is a format-string write-what-where the crashless path
honestly declines, so the crash-driven L2 stands).

## A measurement footgun, recorded so it is not repeated

The first several in-process reproductions here were **invalid**: the harness stopped the
`WorkerPool` before calling `run_case_autopilot`, so no worker executed the enqueued stages and every
stage "timed out"/"skipped" waiting on an empty queue. `run_case_autopilot` only *enqueues and
waits*; a pool must stay alive for the whole run (the server starts one — `api/server.py`). The
defect and the fix above were re-confirmed only after the harness kept the pool running; the earlier
"dynamic_run/disassemble timeout" specifics were harness noise, but the net starvation of the
recover-phase `build_exploit` is real and reproduces with a live worker.

## Addendum (2026-10-20) — the deeper cause: a flaky qemu-gdbstub capture

Running the FULL bundle through the webgui Autopilot under `bwrap --unshare-net` surfaced a second,
independent defect the placement fix alone did not cover: cross-arch L3 was still
**non-deterministic** (aarch64 L1 one run, L3 the next, with identical inputs). Instrumenting the
cyclic probe showed why — `debug/qemu_gdb.capture` gave the gdbstub a flat **5 s** to accept a
connection and returned an empty `{note: "gdbstub did not accept a connection"}` when it did not.
`build_exploit` read that empty capture as *"the cyclic did not fault on any channel"* and declined
L3 — a **capture failure misread as a program that did not crash** **[measured 2026-10-20]**. Two
situations triggered it: the FIRST qemu invocation in a fresh server process pays a cold start
(binfmt, a relinked loader, a cold TB cache) over 5 s; and the prove-phase crash-driven
`build_exploit` runs after the fuzz campaigns have saturated the host. A direct `enqueue_exploit`
(warm, no load) always reached L3 — which is why the capability looked present but the Autopilot
delivered it only by luck.

Two bounded fixes:

* **`debug/qemu_gdb.capture`** — the connect deadline is now `max(12 s, timeout)` (cold start), and a
  failed connect **respawns on a fresh port only when qemu actually died** (it lost the
  `_free_port`->bind race); a qemu that is alive-but-slow under saturation **fails fast** after one
  wait rather than burning repeated deadlines (an earlier 4x10 s retry *wedged* the stage past its
  worker deadline — bounded-on-death is the fix). Benefits every caller (L2 `poc_primitive`,
  `root_cause`, the cross-arch ret2libc confirmation), not only `build_exploit`.
* **`poc/exploit_stage` cyclic probe** — a capture that could not RUN (a connection / did-not-stop
  note, no `ok`) is now told apart from a clean run with no signal: the connection note is retried
  once and otherwise reported honestly ("the overflow probe could not run … re-run, or the
  crash-driven path covers it"); only a clean miss sweeps the other channels. An empty capture can
  no longer read as "did not fault".

Result — three consecutive in-process bundle Autopilot runs on `vuln_aarch64` at 300 s: **L3, L3,
L3**, no wedge **[measured 2026-10-20]**. Air-gap (fresh server under `bwrap`) validation follows.

## Addendum 2 (2026-10-20) — the REAL blocker: the relink corrupted every vendored qemu-user

The two fixes above are correct but were not the reason cross-arch stayed at L1 through the webgui
Autopilot. Driving the FRESH-SERVER bundle (`./lykos serve`) under `bwrap --unshare-net` still gave
cross-arch L1, with `build_exploit` reporting the gdbstub never came up. Instrumenting the capture
showed qemu dying with **rc=-11 (SIGSEGV)** at startup, empty stderr -- and only in the server.

The trap: on this dev box the host has `/usr/bin/qemu-*`, and `sandbox._qemu_for` fell back to it
whenever the vendored one was not resolved, so every in-process test (and `airgap_capability.py`)
quietly used the **host** qemu and reported L3. The webgui launcher puts the bundle's own
`.wrappers/qemu-*` first, so the server used the **vendored** qemu -- which is broken:

* pristine `qemu-aarch64` from the toolchain tarball (static-PIE): **0/5 SIGSEGV** -- works.
* the same binary after the bundle's first-run relink (`patchelf --set-rpath`): **8/8 SIGSEGV**.
* every vendored arch (x86_64/s390x/riscv64/ppc/…) is static-PIE and all 3/3 SIGSEGV after relink.

`packaging/relink-bundle.sh` walked every ELF and ran `patchelf --set-rpath` on it. patchelf
rewriting the program headers of a **static-PIE** executable breaks the self-relocation it performs
before `main`, so it faults at startup. A static-PIE binary has no glibc dependency to repoint in
the first place, so the relink was both unnecessary and destructive for it. On an air-gapped host
with no system qemu to mask it, this made ALL cross-arch analysis and exploitation non-functional --
which no in-process test caught, because they used the host qemu.

Fix: `relink-bundle.sh` now skips any ELF with no PT_INTERP **and** no NEEDED libraries (a
static / static-PIE executable -- self-contained), while a `.so` (no interp but has NEEDED) is still
given its rpath. Since the relink runs at first-run `./lykos doctor` from the shipped script, a
rebuilt bundle carries the fix and ships a working qemu.

**Lesson for the test harness:** validate the vendored engine explicitly (e.g. assert
`_qemu_for` resolved under `vendor/` and that `qemu-<arch> <exe>` does not fault) so a host-tool
fallback can never again make a broken bundle look healthy.
