# 31 — RTOS task-level execution: feasibility spike & decision

**Doc 30 Phase 4.1.** Time-boxed spike. **Decision: documented out of scope for the lightweight
Unicorn rehoster; task-level execution is a separate heavy-profile effort (QEMU-system or Renode)
to be opened only if a concrete need justifies the board-modeling cost.**

## Goal

Run code *inside* a scheduled FreeRTOS task on a real Cortex-M image — not just the pre-scheduler
boot path the rehoster reaches today — so the dynamic firmware analysis sees task logic, not only
init and driver setup.

## What the rehoster reaches today

The Unicorn-based rehoster (`firmware/unicorn_driver.py`, hardened this session) runs a real
Cortex-M3 FreeRTOS image from reset through:

1. the C-runtime init (bss-zero / data-copy loop — recognised as *progress*, not a stuck spin, see
   [[firmware-rehost-init-loop]]),
2. driver/peripheral setup (unmodelled MMIO reads answered from a controllable peripheral model;
   the SCS window — SysTick/NVIC/SCB — left as system control with VTOR pinned to the image base,
   never fuzzed, so a wild `[VTOR+0x2C]` cannot fabricate a crash), and
3. `vTaskStartScheduler()`, which starts the first task with an `svc`.

At that `svc` the run halts **cleanly** at a recognised *scheduler boundary* (`st["svc_boundary"]`)
rather than reporting an emulation artifact as a firmware fault.

## Why task-level is blocked on Unicorn (2.1.4)

Starting the first task is an M-profile exception entry (`svc` → SVCall) whose handler does a
context switch and returns via a magic `EXC_RETURN` value that *unstacks* an exception frame and
resumes in thread mode on the task's stack. Unicorn does not model this faithfully:

- it enters the exception by **fetching the handler from the vector table** at `VTOR + 4*excnum`,
  and with no modeled vector table that fetch reads an unmapped/zero slot — a spurious read, not a
  firmware bug (hence the clean boundary halt);
- it raises `UC_ERR_EXCEPTION` on an `EXC_RETURN` branch (the magic `0xFFFFFFFx` target is not a
  real address), so the context-switch return cannot complete;
- it exposes **no controllable NVIC/SysTick** to drive pre-emption, and the SCS is shadowed when
  mapped as RAM, so a hand-fed exception frame has nothing to return *through*.

Faithful task entry therefore needs an M-profile **exception/return + NVIC model**, which is
exactly the board model the lightweight rehoster exists to avoid.

## Options evaluated

| Option | What it buys | Cost |
|---|---|---|
| **(a) Hand-rolled M-profile exception model over Unicorn** | stays in-process; reuses the current peripheral model | re-implement exception stacking/unstacking, `EXC_RETURN` decode, NVIC/SysTick, VTOR dispatch — a partial CPU; high bug surface, and Unicorn's own `UC_ERR_EXCEPTION` fights it |
| **(b) QEMU-system with an SVD-derived machine** | QEMU already models M-profile exceptions, NVIC, SysTick correctly | needs a machine definition (memory map + peripherals) per target SoC, derived from an SVD; heavyweight, per-chip, and a new execution substrate alongside the rehoster |
| **(c) Renode** | purpose-built for RTOS/SoC emulation, scriptable platforms, large peripheral library | a second external dependency and platform-description effort; another substrate to drive and contain |

## Decision & rationale

**Out of scope for the Unicorn rehoster.** (a) is a partial-CPU rewrite with a poor effort/soundness
ratio; (b) and (c) are genuine board models — the very thing the rehoster was built to sidestep —
and each is a new execution substrate, not a change to the existing one. None is justified by a
present need: the rehoster's value today is the **pre-scheduler** firmware (init, driver code,
reset-vector reachability) plus static analysis of the whole image, and the clean scheduler-boundary
halt is the honest stopping point.

If task-level execution is later prioritized, **option (b) QEMU-system with an SVD-derived machine**
is the recommended direction — it reuses a correct, maintained M-profile model and the SVD is the
standard, per-chip description we would need regardless — opened as its own heavy-profile effort
with its own containment and provisioning, not folded into the lightweight path.

*Acceptance:* this memo, with the first task's entry reached (`svc` scheduler boundary) on a real
CM3 FreeRTOS image and the precise reason task entry does not proceed under Unicorn. ✅
