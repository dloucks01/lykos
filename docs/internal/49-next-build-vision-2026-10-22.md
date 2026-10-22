# Next-build vision — code, GUI, report, and the path between things (2026-10-22)

Captured from the operator's own words:

> For future builds would like to see how we can optimize the code, reorganize and restructure if
> needed to make things run better and smoother. Would also like to overhaul the gui. Can rethink
> completely how we would like to have everything presented on the webgui. Rethink the report. I
> think we also need more diagrams and figures if possible. More things that can link or show a path
> from one thing to the next.

This is the roadmap for the **next** build, not a change to the one just shipped (the gate-verified
`dist/lykos-offline-20261022-x86_64` bundle). Nothing here is applied yet. It is written to be
**driven** — each item is anchored to a real file, prioritized, and sized — so the next session can
start at the top and go.

There is one unifying idea under all four of the operator's asks: **lykos already knows the path
from a target to a proven exploit — target → recover → search → prove → finding → L0→L1→L2→L3 → PoC
— but nothing in the product shows that path.** The code buries it across parallel lists, the GUI
renders a flat finding list, the report renders flat sections. The whole of this roadmap is: make
the path that already exists in the data visible, navigable, and the organizing spine of the code,
the GUI, and the report. "More things that link or show a path from one thing to the next" is not a
fifth item — it is the point of the other four.

## Guiding constraints (unchanged, carried into every item)

- **Precision is paramount** — never fabricate a finding, never hide a real one. Any restructure
  preserves the two-source CONFIRMED gate, the asymmetric demote-don't-assert doctrine, and the
  channels-can-only-raise honesty invariant. A prettier report that overstates an L-level is a
  regression, not a feature.
- **Additive, never degrade** — large binaries and every current capability keep working. A refactor
  that drops a capability for cleanliness is rejected.
- **Core stays stdlib-only**; heavy engines stay under `vendor/`. No new runtime dep in core, incl.
  the GUI (still Preact + htm, no build step).
- **Web GUI does everything the CLI does** — every restructure keeps or widens parity. The operator
  works from the web GUI only; a capability that only the CLI can reach is a bug.
- **Air-gap first** — every diagram, figure, font, and asset renders offline. No CDN, no web font,
  no external request at report- or GUI-render time.

---

## Theme 1 — Code: optimize, reorganize, restructure

The codebase is disciplined (audit doc 48) but has a handful of **god modules** and a **parallel-list
disease** that both cost velocity and cause real bugs.

### 1a. Single source of truth for pipeline stages (do first — highest leverage)
Today a stage's identity is spread across at least five parallel structures that must be hand-kept in
sync: `orchestrate._TARGET` / `_CASE` / `_PLAN_STAGES`, `api/server._TARGET_STAGES`, and
`directed._TARGET_DETECTORS`. The `patch_diff` regression fixed in `583f1fe` was exactly this: the
stage was registered in some lists and not others, and a scheduling invariant test caught it only
after the fact. **Fix:** one declarative stage registry — a list of stage descriptors
`{name, module, enqueue_fn, kind: plan|target|case|on_demand, detectors, gui_toggle, exempt}` — and
derive every one of those five structures from it. This kills a whole bug class, makes "add a stage"
a one-line change, and gives the GUI/report a real catalog to render the pipeline from (feeds
Themes 2 and 4 directly). Keep the scheduling invariant test; it becomes "every descriptor is
internally consistent."

### 1b. Break the god modules
Ranked by pain (size × churn × audit-follow-up density):
- **`poc/exploit_stage.py` (6219 lines)** — the largest file in the tree. Split by technique family
  into an `exploit/` package (ret2win / ret2libc / ROP-chain / shellcode / format-GOT / leak-pivot),
  over a shared confirm base that *every* technique inherits: breakpoint-reach + arg-register +
  `markers.proves()` + the `int3`/benign-echo negative control. This directly absorbs the audit's
  top precision follow-up (the 9 `leak.py` sites + `_pivot_exploit`/`_spawn_and_mark` still lack the
  negative control their siblings have) — do the split and the confirm-hardening in one motion so no
  site can be forgotten.
- **`poc/leak.py` (3013 lines)** — folds into the same `exploit/` package; it is the confirm family
  that most needs the shared base.
- **`orchestrate.py` (2297 lines)** — extract the per-target body (~1653–2268) into a function with
  its own try/except + continue (audit robustness follow-up: today an exception proving target #3
  aborts #4..N). `_staged` stays the one scheduling chokepoint; pull budget/pause bookkeeping into a
  small `RunClock` object so the pause-doesn't-burn-budget logic lives in one testable place.
- **`dynamic/sandbox.py` (2589 lines)** — isolate the `isolate_prefix` / rlimit / loader-detection
  core from the per-fuzzer plumbing, so net_fuzz / env_fuzz / afl can route through one hardened
  entry (audit sandbox-safety follow-up: those three still run targets with rlimits only, no bwrap).

### 1c. Performance — stop re-analyzing the same binary
`native_re.analyze()` is the expensive step and today patch-diff, bounds, taint, and the detectors
each trigger analysis of the same target. **Fix:** one content-addressed analysis cache
(keyed by file sha + arch) that every consumer reads, computed once per target per run. Also make
`detect_cwe`'s per-detector loop (already isolated per audit fix #2) run detectors concurrently —
they are pure over a shared immutable analysis, so this is free latency on multi-core and a no-op on
the air-gap single-core box.

### 1d. GUI code structure (prerequisite for Theme 2)
`app.js` is a 1283-line god component (`App()`); `components.js` is 1603 lines. Before the GUI
overhaul, decompose `App()` into feature components (RunBar, PipelineRail, FindingList,
FindingDetail, DiffTab, ReportTab) over a tiny observable store (plain JS, no dep) so run state has
one owner instead of a dozen `useState`s threaded through props. This is the refactor that *makes*
Theme 2 affordable; doing Theme 2 on top of the god component would just grow it.

---

## Theme 2 — GUI overhaul: rethink how everything is presented

Today: a left rail of pipeline items (the static-rendering bug is fixed) and a tabbed main pane. It
is a *control panel*. The operator asked us to rethink it completely. The reframe: **the GUI is a map
of one engagement, and the operator navigates by following the path.**

### 2a. The engagement map (new primary view)
A single always-visible diagram of the run as a left-to-right flow:

```
 target ─▶ recover ─▶ search ─▶ prove ─▶ findings ─▶ L0 ─ L1 ─ L2 ─ L3 ─▶ PoC
             │          │         │
          (stages light up live, show status, ETA, and what they produced)
```

Each node is live (pending / running / done / skipped / error, driven by `s.state` — the field the
left-rail bug taught us to trust), clickable, and shows its yield (how many leads, which findings).
This is the "path from one thing to the next" made literal and is the home screen.

### 2b. Finding-centric navigation with visible provenance
Click a finding and see its **full provenance chain as a path**, not a flat card:
`stage that found it → detector → corroborating evidence (taint source→sink, CVE match, bounds
witness) → L-ladder rung with the justification for that rung → the PoC and its reproduction`.
Every hop is a link. This is where precision becomes legible: the operator can *see* why a finding
is CONFIRMED vs candidate, and what would raise it.

### 2c. The L-ladder as a first-class, visible progression
Per finding, render L0→L1→L2→L3 as a rung diagram: which rungs are reached, the evidence at each,
and (honestly) why a rung is *not* reached — "drained vs cutoff" for concolic, "no second witness"
for bounds. This turns the honesty invariants into a feature the operator can read.

### 2d. Keep every control, make them contextual
All the run controls shipped this cycle (per-phase/stage budget, sysroot/libs, deep-seed, per-stage
toggles, black-box, pause/resume/continue) stay — but attach them to the map node they affect
(budget on the phase nodes, engine toggles on the search node) instead of a wall of fieldsets. Parity
with the CLI is preserved and the controls become discoverable.

---

## Theme 3 — Rethink the report

The report is already structured (`report/model.py` `build_report` → html / pdf / sarif / casejson),
with a scorecard, diagnostics, engines, and evidence. The rethink is **organize the report around
the same path as the GUI**, so a reader who never saw the GUI still follows target → finding →
evidence → L-level → PoC.

- **Lead with an evidence ladder per finding**, not a flat list of CWEs. Each finding shows its rung,
  the one-sentence why for that rung, and the single most load-bearing piece of evidence inline.
- **Provenance in the report** — the same finding→stage→detector→corroboration→PoC chain from GUI
  2b, rendered as a figure (Theme 4). An operator pastes one finding's page into their engagement
  report and it stands alone.
- **Reproduction is the payload** — exact command, input (or how the autopilot derived the seed), the
  observed crash/PC, and the PoC, formatted to copy-run. This is what an authorized-pentest client
  actually needs.
- **Honesty surfaced** — a short "what we did NOT prove and why" per finding (ceiling_why already
  exists in the model). A report that says where it stopped is more trustworthy than one that implies
  completeness.
- **One model, all renderers** — keep html/pdf/sarif/casejson deriving from the single
  `build_report` model so the restructure lands in all four at once. SARIF stays
  machine-faithful (no prose-driven severity drift).

---

## Theme 4 — Diagrams, figures, and the connective tissue

The operator asked for more diagrams/figures *and* "more things that link or show a path from one
thing to the next." Same engine serves both: a small, offline, deterministic **SVG figure library**
in core (stdlib-only — we emit SVG strings; no graphviz runtime dep) that both the GUI and the report
render from the same data.

Figures to build, each doubling as a navigation surface in the GUI and a static image in the report:
1. **Pipeline/engagement DAG** — the Theme-2a map; nodes link to stage detail.
2. **Taint path** — source → … → sink, the actual propagation the taint engine already computes;
   nodes link to code locations.
3. **Call graph / CFG slice** around a finding or a patched function (native_re already has the CFG).
4. **L-ladder rung diagram** — Theme 2c, per finding.
5. **Patch-diff map** — changed functions ranked by how much the body moved (patchdiff.diff already
   returns `changed[].moved` + new/dropped callees); the figure makes "this is the fix" obvious.
6. **Finding provenance chain** — the spine of GUI 2b and report provenance.

Deterministic layout (no physics sim — layered DAG, fixed seed) so a report figure is byte-stable
across runs and reviewable in git. Every figure is a plain inline `<svg>` that works in the air-gap
browser and embeds in the PDF.

---

## Suggested phase order (what to do first)

1. **1a stage registry** — unlocks the catalog the GUI/report render from and kills the parallel-list
   bug class. Small, high leverage, do first.
2. **1d GUI decomposition + 4 figure library** — the substrate for the whole GUI/report overhaul.
3. **2a engagement map + 2b provenance** — the visible-path payoff; the operator sees it immediately.
4. **3 report restructure** over the same model + figures.
5. **1b/1c god-module splits + analysis cache + confirm-hardening** — interleave as the touched areas
   come up (do the exploit_stage split *with* the audit's confirm-hardening so no site is missed).
6. **2c L-ladder view + 2d contextual controls** — polish that makes precision legible.

## Explicitly not in scope here (tracked elsewhere)
- GAP C (bounds-OOB promotion, 2–4h) — doc 48 / memory.
- The remaining audit follow-ups (doc 48) fold into 1b/1c where they touch the same code; the rest
  (batch-runner loader-failure detection, netfuzz stderr drain, relink-move corruption,
  symqemu doctor probe) stay on the doc-48 list.

Related: [[drive-the-roadmap-proactively]], [[webgui-cli-parity]], the codebase audit
(`docs/internal/48-codebase-audit-2026-10-22.md`).
