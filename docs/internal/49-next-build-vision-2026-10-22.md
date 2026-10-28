# Next-build vision — code, GUI, report, and the path between things (2026-10-22)

Captured from the operator's own words:

> For future builds would like to see how we can optimize the code, reorganize and restructure if
> needed to make things run better and smoother. Would also like to overhaul the gui. Can rethink
> completely how we would like to have everything presented on the webgui. Rethink the report. I
> think we also need more diagrams and figures if possible. More things that can link or show a path
> from one thing to the next.

This is the roadmap for the **next** build, not a change to the one just shipped (the gate-verified
`dist/lykos-offline-20261022-x86_64` bundle). It is written to be **driven** — each item is anchored
to a real file, prioritized, and sized — so the next session can start at the top and go.

## Progress (updated as items land)

- **1a — single stage registry: DONE.** `core/lykos/analyze/stages.py` is the one declarative
  source; `orchestrate` derives `_TARGET`/`_CASE`/`_ON_DEMAND`/`_NO_PARAMS`/`_PLAN_STAGES` from it
  (byte-identical to the old literals, verified against a pre-refactor oracle). `stages.check_consistency()`
  fails loud on an inconsistent descriptor; `tests/test_stage_registry.py` pins that the declared
  dispatchable set equals the job registry. (`directed._TARGET_DETECTORS` left as-is — it is a
  finding-source steering set, not a stage list.)
- **2b — finding-centric cross-links: mostly already shipped** (opportunistically, in 4984123):
  `FindingCard` hops to the code view (`viewCode`), the call-graph node (`showInGraph`), the
  per-channel evidence trail, and the PoC downloads; the evidence modal links onward. The remaining
  spine piece was provenance, below.
- **Finding→stage provenance: DONE.** `finding.stage` (migration 19) records WHICH stage discovered
  a finding, stamped authoritatively by the worker from the running run's stage via a per-thread
  contextvar (`db/provenance.py`); the discoverer keeps the credit (mirrors `detector`), and unknown
  provenance stays NULL (never guessed). Exposed in the API + report model (`stage` + `stage_label`
  from the registry) and shown on the finding card ("found by <stage>"). `tests/test_finding_stage_provenance.py`
  pins the stamping, the discoverer rule, the blank-when-unknown rule, and the worker wiring
  end-to-end. Remaining within 2b: make the "found by" chip and the pipeline rail clickable (a
  finding↔stage navigation hop) — deferred because the GUI interaction cannot be execution-verified
  in this environment.
- **Theme 4 figure library (phase 3): STARTED.** `core/lykos/report/figures.py` — a stdlib,
  deterministic, air-gap-safe, theme-robust SVG engine (a general layered-DAG layout +
  `call_graph_svg` + `coverage_bars_svg`; byte-stable, escaped, node-capped). Wired into the HTML
  report (`model.build_report` attaches a per-target call-graph figure focused on the worst finding's
  function, and a case-level coverage figure; `html.to_html` embeds them). This closes the explicit
  "call graph + coverage are GUI-only, absent from the air-gap report" gap. `tests/test_report_figures.py`
  (11: determinism, XML well-formedness, content, the node cap, no-external-request, escaping, cycle
  safety). SARIF stays machine-faithful (ignores `figures`).
- **Theme 4 provenance + reachability figures: DONE.** Added `chain_svg` (a linear `a→b→c` pill
  chain) and two per-finding figures wired into the report finding card: (6) the **provenance chain**
  — `found-by stage → detector → N evidence signals → verified rung` — drawn from the finding model
  ONLY (authoritative); and (2) the **source-reachability path** — the shortest call path from a
  function that reads external input (SOURCES vocabulary) to the finding's function. The reachability
  figure is labelled "control-flow reachability, not verified dataflow" and is omitted (never faked)
  when no such path exists — an honest rendering of figure 2 at the call-graph level, not a claim of
  byte-level taint. +6 tests.
- **Theme 4 patch-diff map (figure 5): DONE.** `figures.patch_diff_map_svg` draws the changed
  functions ranked by moved-score as a bar map (warm-toned top third = where the fix most likely
  lives). The patch_diff stage now records the numbers as a STRUCTURED `patch-diff-map` evidence
  channel (JSON, like `effects`) alongside the existing prose, so the report draws from numbers,
  never by re-parsing the sentence. `model.build_report` attaches a per-target `figures.patch_diff`;
  `html.to_html` renders it. +7 tests (figure determinism/ranking/cap/escaping + report integration;
  the stage integration test asserts the structured channel end-to-end). All three Theme-4 figure
  families (call-graph+coverage, provenance+reachability, patch-diff) now render in the HTML report.
- **Theme 4 PDF figure embedding: DONE — Theme 4 COMPLETE.** `pdf.py` now translates each figure's
  SVG (a known, self-generated subset: rect / cubic+line path / text) straight into PDF vector
  operators via stdlib `minidom` — no rasterizer, no new dep, air-gap preserved, one geometry source
  (the SVG). A `_Figure` flow block the paginator treats as one unit (scaled to the content width and
  page height, never split); a per-point coordinate transform keeps text upright; the figures' theme
  CSS vars resolve to a fixed light palette for the PDF. All five figures (call-graph, coverage,
  provenance, reachability, patch-diff) now render in BOTH the HTML and the PDF. `test_report.py`
  pins that the PDF embeds vector ops + node labels and stays structurally valid (xref intact,
  deterministic). **Theme 4 (the figure library + all its figures in both renderers) is done.**
- **Theme 2a engagement map (figure 1): DONE (report).** `figures.engagement_map_svg` draws the
  analysis path — Recover → Detect → Search → Prove → Report — each phase a node showing what it
  produced for this case, reached phases solid and unreached ones MUTED (so the figure shows
  honestly how far the run got, never implying a phase ran). `model.build_report` derives the phases
  from the case totals; it leads the executive summary in HTML and the summary in PDF (via the same
  SVG→PDF translator). +3 tests. NOTE: the audit confirm-hardening (doc-48 follow-up) is already
  DONE — verified every leak.py shell confirm uses make_code_markers()+markers.proves and
  test_exploit_confirm_hardening.py (21) is green; the stale roadmap text is corrected in memory.
- **Theme 2a engagement map — LIVE in the GUI: DONE.** `EngagementMap` (components.js) renders the
  path Recover → Detect → Search → Prove as clickable phase nodes in the findings tab; each reached
  node jumps to the tab where that phase's evidence lives (Recover→functions, Detect→findings,
  Search→coverage/crashes, Prove→exploits), and an unreached phase is muted and inert. Phases are
  computed per active target from live data (functions, findings, coverage/crashes, verdict level).
  VERIFIED by driving the running build in the browser: all four nodes render with correct state
  (Prove correctly MUTED "no PoC"), and clicking Search navigated to the Crashes panel.
- **1b god-module split: STARTED (exploit_stage.py).** First extraction: the cross-architecture
  ret2libc family (AArch64 incl. its execve-syscall variant, ARM, RISC-V64, PPC64, PPC32,
  LoongArch64, s390x, SH4) + the qemu register-offset helpers → `poc/exploit_crossarch.py`
  (exploit_stage.py 7479 → 6821 lines, −658). The cluster was cohesive but reached two things in the
  shared confirm base (`_try_shell_effect`, `TOOL_VERSION`); rather than move that base (used by every
  family) it is reached lazily via `_es` (an `exploit_stage` module alias), which avoids an import
  cycle because both are touched only at call time. exploit_stage imports the drivers back for its
  arch dispatch. SAFE-EXTRACTION RECIPE (reusable for the remaining families — PE, format-GOT,
  shellcode, leak-pivot): move a cohesive cluster, rewrite its references into the shared base to
  `_es.`, and GATE on `pyflakes` (zero undefined names proves no reference was silently missed — the
  real risk, since the per-arch paths need qemu/cross-toolchains and don't execute in CI here).
  Verified: pyflakes clean on both modules, no import cycle, dispatch + lazy refs resolve, the
  build_exploit stage still registers, and the exploit/crossarch/afl suites pass.
- **Theme 5a capability track: STARTED — LoongArch64 ret2shellcode.** Filled the named 5a hole
  "shellcode stubs for loongarch64 / sh4 (ret2libc-only today)" for LoongArch64:
  `shellcode.execve_binsh_loongarch64` (20B code + "/bin/sh\0", `pcaddi` PIC) and
  `write_marker_loongarch64` (length patched into the `ori $a2,$zero,len` immediate) — both ASSEMBLED
  with the real `loongarch64-linux-gnu-as` (guaranteed-correct encoding) and run under qemu to prove
  a real shell spawns / the marker is written; `rop.find_br_gadgets_loongarch64` (the `jr $rN` =
  `jirl $zero,$rN,0` jump-reg gadget); and the `_shellcode_emu_exploit` arch gate + cfg branch.
  LoongArch64 now reaches shellcode-based L3 on NX-off targets, not just ret2libc. VERIFIED end-to-end:
  the auto pipeline drives a loongarch64 execstack overflow (`jr $t0` gadget) to a confirmed, verified
  L3 (injected execve spawns a real shell under qemu-user + negative control). +1 test; all 50
  shellcode-arch tests green. REMAINING 5a: the same for SH4; the cross-arch info-leak primitive (the
  big PIE/ASLR unlock); generalize the ROP builders. (mips stays unbuildable here — no compiler.)

There is one unifying idea under all four of the operator's asks: **lykos already knows the path
from a target to a proven exploit — target → recover → search → prove → finding → L0→L1→L2→L3 → PoC
— and the current GUI already *draws* most of the pieces of that path; what it does not yet do is
let you walk it as one connected flow.** The whole of this roadmap is: take the pieces that already
exist and weave them into one navigable spine, across the code, the GUI, and the report. "More
things that link or show a path from one thing to the next" is not a fifth item — it is the point of
the other four.

## Live-GUI reality check (2026-10-22) — what already exists

An earlier draft of this doc said "nothing in the product shows the path." After driving the running
build live (case `hdemo2` on `127.0.0.1:8799`, every tab + the evidence drill-down), that framing was
**too harsh and is corrected here.** The current build is a polished dark-theme *workbench* with a
real design-token system, a `Classic UI` fallback (so this modern view is already the default), and —
importantly — most of the visualization this roadmap wanted **already shipped**:

- **L0→L1→L2→L3 weaponization ladder** — a header widget on every finding/overview.
- **A live, rendered call graph** (Code tab: `main → parse_record → memcpy/puts`, drag/zoom/click),
  plus Disassembly and Strings subtabs and "Deep function fuzzing".
- **Evidence trails** — each finding has "HOW IT CAN BE EXPLOITED — click any line to go deeper" and
  an evidence-trail modal with "View code at 0x…" + raw JSON.
- **Per-binary coverage** bars with drill-in (Dynamic tab).
- **Honesty surfaced already** — findings state their ceiling ("demonstrated at the FUNCTION level …
  Not a program-level verified PoC"); a **Fuzzing engine health** table says why each engine
  ran/skipped/n-a; a **"What this run did"** panel frames the null result by the work behind it
  (219,980 executions). This is precision-as-UX and it is live today.
- **Full run controls** (budget slider + "to convergence", 5 engine toggles + deep-seed, invocation
  libs/argv/channel, black-box, Continue run, pause/resume) and **HTML/SARIF/JSON export**.

So the honest gap is **not** "build visualization" — it is that these pieces live in **separate tabs
and modals and do not cross-link**. From a finding you cannot yet click through to *its* node in the
call graph → *its* coverage → *its* ladder rung as one motion. The code's parallel-list disease
(Theme 1a) is real and unchanged. The revised roadmap below reflects this: the GUI theme becomes
"weave the existing surfaces into one clickable spine," and the figure library becomes "add the
*missing* figures + a shared cross-link layer," not a from-scratch build.

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

## Theme 2 — GUI: weave the existing surfaces into one navigable spine

Today (verified live, see the reality check above): a left rail of pipeline items with live status, a
run bar, and a rich tabbed main pane — Overview (severity / top-CWE / L-ladder / findings), Exploits
(chain narrative), Code (**live call graph** + disassembly + strings), Dynamic (coverage), Diff,
Console — with evidence-trail modals, the engine-health table, and the honest "what this run did"
panel. It is already far past a "control panel." The gap is **connective tissue**: the surfaces don't
cross-link, so the operator can't *walk* a finding through them. The reframe: **the GUI is a map of
one engagement, and every surface links to the next step on the path.** The overhaul is mostly
cross-linking + one new map view, not rebuilding the tabs.

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

### 2b. Finding-centric navigation with visible provenance (upgrade the existing evidence trail)
The evidence-trail modal already exists ("click any line to go deeper" → EVIDENCE TRAIL + "View code
at 0x…"). The upgrade: turn that modal into a **cross-linked inline path**, not a dead-end popup —
`stage that found it → detector → corroborating evidence (taint source→sink, CVE match, bounds
witness) → the function's node in the Code call graph → its coverage row → L-ladder rung with the
justification → the PoC and its reproduction`. Every hop is a real link that actually navigates the
other tabs (today "View code at 0x…" is the only working hop). This is where precision becomes
legible: the operator *sees* why a finding is CONFIRMED vs candidate, and what would raise it.

### 2c. The L-ladder as a first-class progression (extend the existing header widget)
The L0→L1→L2→L3 ladder widget already renders per finding/overview, and the honest ceilings already
appear in the finding prose and the engine-health table. The extension: make the ladder itself a
**per-rung diagram** — which rungs are reached, the evidence *at* each rung, and (honestly) why a
rung is *not* reached ("drained vs cutoff" for concolic, "no second witness" for bounds) — wired into
the 2b path so clicking a rung jumps to its evidence. This promotes honesty data that is today spread
across prose + the engine-health table into one readable rung view.

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
thing to the next." The GUI already renders a live **call graph** (Code tab) and **coverage** bars,
but those are GUI-only (interactive JS) and don't appear in the HTML/PDF report, and nothing emits
the other figures. So the figure engine has two jobs: (a) add the **missing** figures, and (b) give
every figure a **shared cross-link layer** + a **static-SVG renderer** so the same data draws in both
the interactive GUI and the air-gap report. A small, offline, deterministic **SVG figure library** in
core (stdlib-only — we emit SVG strings; no graphviz runtime dep) serves both.

Figures, each doubling as a GUI navigation surface and a static report image (status noted):
1. **Pipeline/engagement DAG** — the Theme-2a map; nodes link to stage detail. *(new)*
2. **Taint path** — source → … → sink, the propagation the taint engine already computes; nodes link
   to code locations. *(data exists, not drawn)*
3. **Call graph / CFG slice** around a finding or patched function. *(call graph already renders live
   in the Code tab — add the CFG slice, the static-SVG report version, and the finding→node link)*
4. **L-ladder rung diagram** — Theme 2c. *(ladder widget exists; make it a per-rung diagram)*
5. **Patch-diff map** — changed functions ranked by how much the body moved (`patchdiff.diff` already
   returns `changed[].moved` + new/dropped callees); the figure makes "this is the fix" obvious. *(new)*
6. **Finding provenance chain** — the spine of GUI 2b and report provenance. *(new; promotes the
   existing evidence-trail modal into a drawn, linkable path)*
7. **Coverage** — already drawn in the GUI; add the static-SVG report version. *(GUI-only today)*

Deterministic layout (no physics sim — layered DAG, fixed seed) so a report figure is byte-stable
across runs and reviewable in git. Every figure is a plain inline `<svg>` that works in the air-gap
browser and embeds in the PDF.

---

## Theme 5 — Architecture, Windows, and scale (the capability-depth track)

Operator ask (2026-10-22): *"other architectures at this level of depth … go further L0→L3 … go
deeper with Windows binaries … analyze larger binaries 100 MB and up without issues, especially
Windows applications."* These are **capability-depth** tracks, orthogonal to the GUI/report/code
themes above, each targeting a specific gap catalogued in `50-current-state`. All additive — they
never degrade the depth that already works (x86-64 full L3, the 8-arch ret2libc set, the honest
degradation posture).

### 5a. Architecture → full L3 depth (not just ret2libc)
Today non-x86 L3 is the cross-arch **ret2libc** driver only; the chain algebra is x86-64-only, so the
8 synth arches are confined to **no-PIE / fixed-address** targets, and mips + the capture-only arches
don't synthesize at all. The lever is the existing `archmodel.ArchModel` abstraction — extend it
past ret2libc:
- **A cross-arch info-leak / ASLR-defeat primitive** — the single biggest unlock. `leak.py` is
  entirely x86-64 pop-gadget + rsp-alignment; without a per-arch leak, non-x86 L3 can't touch a PIE
  target. Build it behind `ArchModel`.
- **Generalize the ROP-chain builders** (`rop.py`: ret2csu / dlresolve / SROP / one-gadget) behind
  per-arch gadget vocabularies, instead of the x86-64 byte patterns.
- **Fill the obvious holes:** shellcode stubs for **loongarch64 / sh4** (ret2libc-only today); a
  **mips gadget decoder + `_mips_ret2libc`** (mips already has full L1/L2 capture — "infra present,
  synthesis missing").
- Target metric: raise N arches from ret2libc-only to **leak + ROP L3** against PIE targets.

### 5b. Deeper Windows / PE (break the L2/L3 wall)
A PE reaches **L1** (Wine crash, incl. SEH) but stops dead at L2/L3 (doc 50). Two walls + finishing
work:
- **L2 — RIP capture under Wine.** `ptrace_capture.py` can't follow Win64 state through wineserver.
  Need a Wine-aware confirmation channel: parse the Wine crash **context** (registers at fault) from
  the unhandled-exception report, or attach via Wine's debug interface, to confirm IP control.
- **L3 — a Win64 weaponizer.** `build_exploit` is ELF + System V only. Add a **Windows ABI model**
  (rcx/rdx/r8/r9 + 32-byte shadow space) in `archmodel`, **SEH-overwrite** exploitation, and
  **WinExec / VirtualProtect / LoadLibrary** gadget synthesis + Windows shellcode. Gate on it the way
  the ELF path gates on SysV.
- **Finishing work:** populate PE **exports / TLS callbacks / resources / relocations** (`pe.py`); a
  **Windows static sink catalog** (`wsprintf`, Win32 copy/format APIs — today only generic libc
  names match); and a **coverage lane for PE** that isn't 1-exec/s Wine (a PE instrumentation or
  emulation path), without which large Windows targets have no execution-based depth.
- Target: PE reaches **L2**, then **L3** on a straightforward stack-overflow Windows target.

### 5c. 100 MB+ without degradation (especially Windows)
The "large/huge" modes are advisory; the real ceiling is ~24 MB where whole-program `aaa` stops
finishing (doc 50). Make big binaries first-class:
- **Gate `aaa` by size** — use `aa`+`aac` or the batched per-function path for **pass 1** too (today
  the batched path only governs pass 2), so function/call-graph recovery survives above ~24 MB.
- **Replace the taint hard-drop** (`detect/taint.py` returns zero dataflow above 6000 functions) with
  a **ranked top-N** over sink-adjacent / reachable functions — degrade gracefully, don't disable.
- **Streaming / mmap reads** instead of whole-file `read_bytes` (three sites add the full file to RSS).
- **Scope concolic** to a function/region instead of whole-image load (angr OOMs on 90 MB+).
- **Large PE specifically** assumes-ELF for its execution depth and collapses to static+concolic — it
  needs 5b's PE coverage lane to have any dynamic depth at 100 MB+.
- Preserve the honesty posture: every remaining cap stays **reported, never silent**.
- Target: a 100 MB native ELF **and** a 100 MB PE both get real function/call-graph recovery + taint
  within budget.

---

## Suggested phase order (what to do first)

Reordered after the live-GUI reality check: the GUI surfaces already exist, so the cheapest
high-value win is **cross-linking them**, which moves ahead of the figure library.

1. **1a stage registry** — unlocks the catalog the GUI/report render from and kills the parallel-list
   bug class. Small, high leverage, do first. (Unchanged.)
2. **2b cross-link the existing surfaces** — wire the evidence-trail modal → the function's call-graph
   node → its coverage row → its ladder rung into real navigation (today only "View code at 0x…"
   works). Highest value-per-effort because it builds on surfaces that already render; pairs with a
   first slice of 1d (a small shared store so a click in one tab can drive another).
3. **1d GUI decomposition + figure library** — decompose `App()` (1283L) into feature components;
   build the figure library scoped to the *missing* figures + the static-SVG renderer + the shared
   cross-link layer (not a from-scratch viz build — call graph & coverage already render).
4. **2a engagement map + the new figures** — the pipeline DAG home view, plus taint-path, provenance
   chain, and patch-diff map (figures 1, 2, 5, 6).
5. **3 report restructure** — reorganize around the path and pull the static-SVG figures (incl. the
   call-graph and coverage versions that are GUI-only today) into HTML/PDF, all from the one model.
6. **1b/1c god-module splits + analysis cache + confirm-hardening** — interleave as the touched areas
   come up (do the exploit_stage split *with* the audit's confirm-hardening so no site is missed).
7. **2c ladder rung diagram + 2d contextual controls** — polish that makes precision legible.

**Theme 5 (capability depth) runs as a parallel track**, prioritized by engagement value rather than
the GUI sequence above: **5c (100 MB+ reliability)** and **5b (Windows L2→L3)** unblock real targets,
so they lead; **5a (arch depth)** follows. Each is additive and measured against the current-state
baseline in `50-current-state`.

## Explicitly not in scope here (tracked elsewhere)
- GAP C (bounds-OOB promotion, 2–4h) — doc 48 / memory.
- The remaining audit follow-ups (doc 48) fold into 1b/1c where they touch the same code; the rest
  (batch-runner loader-failure detection, netfuzz stderr drain, relink-move corruption,
  symqemu doctor probe) stay on the doc-48 list.

Related: [[drive-the-roadmap-proactively]], [[webgui-cli-parity]], the current-state reference
(`docs/internal/50-current-state-2026-10-22.md`) and the codebase audit
(`docs/internal/48-codebase-audit-2026-10-22.md`).
