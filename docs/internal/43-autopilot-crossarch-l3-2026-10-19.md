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
