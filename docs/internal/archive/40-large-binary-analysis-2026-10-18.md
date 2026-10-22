# Large-binary analysis: measured gaps, fixes, and the TTP roadmap (2026-10-18)

Testing the autopilot on large real binaries (a 22MB `chromedriver`, a 109MB `libllvmlite.so`, a
136MB `nuclei`) surfaced three problems the small planted fixtures never do. Two are fixed; the
third is a genuine research area, scoped here with a roadmap grounded in the current literature.

## What broke, measured

1. **A heap-discovery stage blew the whole budget.** `chromedriver` ran 966s on a 420s budget:
   `heap_trace` had no registered timeout (it inherited the 3600s hang-ceiling) and the discovery
   batch passed no budget slice, so on a target that bundles its own allocator (libffi's
   `ffi_closure_alloc`) it drove ~40 operation-sequences and a single uncooperative ptrace-helper
   drive ran it past its deadline until the reaper reclaimed it -- shown as an ERROR. **Fixed**
   (commit `9b63c5a`): budget-sliced discovery batch, an explicit `heap_trace` timeout, a crawl
   deadline + option cap, a sequence cap, and a clean "skipped" path for non-terminating targets.

2. **A cut-short run looked like a hang or a crash.** The plan panel showed `running` with no
   elapsed, so a stage grinding for 500s was indistinguishable from a wedge, and a budget stop was
   reported as an ERROR. **Fixed** (commit `31818cc`): per-stage live elapsed, and a distinct
   `timeout` ("cut short -- out of budget") state separate from `error`.

3. **A large binary reported zero findings and read as clean.** `chromedriver` and `libllvmlite`
   both produced 0 findings. Root cause: rizin's full auto-analysis (`aaa`) does not finish on a
   24MB+ binary within any reasonable budget, and `native_re.analyze` ran the cheap strings/imports
   extraction (`izj`/`iij`) *behind* `aaa` in the same invocation -- so when `aaa` was cut off,
   strings and imports were lost too and every detector was starved. Measured: disassemble ran the
   full 600s and persisted 0 functions, 0 strings. **Partially fixed** (this round): the disassemble
   stage now extracts and persists strings/imports in a fast pass FIRST (`native_re.quick_facts`,
   no `aaa`) and, when the structural analysis is cut short by the budget, keeps those, runs the
   string-keyed detectors on them, and emits a clear truncation note -- so a big binary is never a
   silent "clean 0 findings". Deep function/call-graph recovery on a huge binary is the roadmap
   below.

## What the literature says (and how it maps here)

- **Selective / prioritized decompilation.** Decompilation times out past ~50MB; the practical
  move is to find high-value functions first and analyse those, not the whole image
  ([Ghidra RE techniques](https://sesamedisk.com/ghidra-advanced-reverse-engineering-techniques/),
  and a [Ghidra-MCP workflow write-up](https://dailyaiworld.com/workflow/build-ghidra-mcp-reverse-engineering-workflow-binary-analysis)
  reporting 120s decompile timeouts >50MB and advising pre-processing to rank functions). lykos
  today analyses every discovered function (or caps at `LYKOS_MAX_FUNCS`); it does not yet RANK and
  analyse a budget-bounded subset.
- **Work from imports / strings / call-graph when symbols are stripped.** COTS/stripped binaries
  force reconstruction from imports, strings and the call graph; auto-named `sub_*` functions carry
  no signal ([agentic COTS analysis](https://arxiv.org/pdf/2605.05000),
  [cross-build dataset](https://arxiv.org/pdf/2605.21615)). This is exactly why the strings-first
  fix matters: strings+imports are the one cheap, size-independent signal.
- **Signature-based function identification** recovers names/types in stripped Rust/C++ and could
  re-enable the type-aware detectors (RustSigGen recognises large parts of stripped Rust binaries,
  [TUM](https://www.insec.cit.tum.de/i20/student-work/rust-in-translation-unwinding-the-layers-of-rust-binary-reverse-engineering);
  FLIRT/BSim-style matching, [survey](https://arxiv.org/pdf/2503.20244)).
- **Fuzzing large/stateful targets:** narrow the harness to critical components, stub external
  interactions, avoid cross-iteration state, and use snapshot/forkserver execution (Nyx/Snapchange/
  wtf) to skip expensive init ([SRLabs harness guide](https://www.srlabs.de/blog/unlocking-secrets-effective-fuzzing-harness),
  [rev.ng](https://rev.ng/blog/fuzzing-binaries)); auto-discover fuzzable functions with static
  heuristics ([Fuzzable](https://pypi.org/project/fuzzable)). lykos already shortens the per-exec
  timeout for non-terminating baselines; snapshotting and function-targeted harnesses are not yet
  in.
- **Per-binary job queues / persistent projects** avoid per-call setup and lock contention
  ([Ghidra-MCP write-up](https://dailyaiworld.com/workflow/build-ghidra-mcp-reverse-engineering-workflow-binary-analysis)).
  lykos re-crawls the live menu per stage but already shares an op-model artifact across stages; the
  analogous win for the structural pass is an incremental/persisted analysis.

## Roadmap (ordered by leverage)

1. **Incremental persistence + lighter analysis for large images.** Gate `aaa` by size: above a
   threshold use `aa`+`aac` (functions + calls, no emulation) so disassemble COMPLETES and persists
   functions + call edges + strings -- which re-enables the call-site detectors (`dangerous_api`),
   not just the string ones. Persist as each pass finishes, so a cut-off never discards a completed
   pass. (Biggest win for #3 above; the strings-first fix is the floor, this is the next storey.)
2. **Prioritized function subset.** When over the function/taint cap, rank by proximity to input
   sources and dangerous sinks (and by export/entry reachability) and analyse the top-N instead of
   bailing to zero (`detect/taint.py` `_MAX_FUNCS` currently returns nothing over the cap).
3. **Signature-based symbol recovery** (FLIRT/Rust-sig) to un-strip library and runtime functions,
   restoring the type-aware bounds detectors on release builds.
4. **Snapshot / function-targeted harnesses** for large stateful targets, so fuzzing reaches deep
   parsers without paying full-process init each exec.

Every item keeps the standing transparency rule: whatever is skipped, capped, or truncated is
REPORTED as a coverage note, never inferred from a small number.

## End-to-end to a demonstrable PoC on a large binary (research, 2026-10-18)

Measured while writing this: rizin's whole-binary `aaa` on the 136MB `nuclei` (a Go binary) runs at
100% CPU with RSS climbing past 2.4GB in the first 45s -- it is WORKING, not frozen, but
whole-image analysis is CPU- and memory-bound to the point of being the wrong tool. The literature
is unanimous on the alternative: **you do not analyse a huge binary whole to reach a PoC; you
harness a component.** That is how OSS-Fuzz, the AIxCC teams, and essentially all practical
large-target work operate.

The end-to-end chain for a large target, and where lykos stands on each link:

1. **Attack-surface identification -- from cheap facts, not full CFG.** Pick the input-handling
   component from imports, strings, exports and the entry path (the strings-first fix already
   recovers these on a huge binary). lykos does import/string/export triage today; it does not yet
   RANK components by attacker-reachability to choose a harness target.

2. **Targeted harness around that component** -- the single highest-leverage capability.
   * *Source or known library present:* a libFuzzer-style harness that calls the component
     directly. lykos already has this lane (`plan_harnesses` + `BuildCache`, one harness per
     library). LLM-assisted harness generation is now strong where source exists -- HarnessAgent
     reports ~81-87% three-shot success across 243 OSS-Fuzz targets and 15 new vulnerabilities
     ([arXiv:2512.03420](https://arxiv.org/pdf/2512.03420)), coverage-feedback steering the next
     harness toward under-explored regions ([FuzzAgent](https://arxiv.org/pdf/2605.14431)); the
     known failure mode is generic harnesses that crash on wrong input constraints
     ([SAFuzz](https://arxiv.org/pdf/2602.11209)).
   * *Binary-only (our large-binary case):* **snapshot fuzzing** -- snapshot the process deep past
     initialization at the parser entry and fuzz the register/memory state. Nyx/Nyx-Net (KVM
     snapshots, stateful targets, [arXiv:2111.03013](https://arxiv.org/pdf/2111.03013)), AWS
     Snapchange, and `wtf` (closed-source Windows/Linux, [appsec.guide](https://appsec.guide/docs/fuzzing/snapshot-fuzzing/))
     are the tools. "No source" does NOT mean "no harness": each needs a fuzzer module defining how
     to inject input and detect a crash, and a chosen snapshot point past init. This lane does not
     exist in lykos yet and is the main thing we need to BUILD to go end-to-end on a stripped large
     binary.

3. **Directed fuzzing toward a recovered sink** -- reach deep bugs without exhaustively fuzzing.
   AFLGo scores seed distance to a target site and powers seeds closer to it, and can reproduce a
   crash from a bug report even without the original input
   ([AFLGo](https://acmccs.github.io/papers/p2329-bohmeAemb.pdf)); CAFL adds ordered sink +
   data-condition constraints and reports 2.88x faster crash reproduction
   ([CAFL, USENIX Sec '21](https://www.usenix.org/system/files/sec21fall-lee-gwangmu.pdf)); LeoFuzz
   coordinates multiple target sequences ([arXiv:2206.14977](https://arxiv.org/pdf/2206.14977)).
   lykos has a `directed_fuzz` stage; it needs sinks recovered by a LIGHT analysis of the component
   (step 1), not the memory-exploding whole-image pass.

4. **Crash -> primitive -> exploit.** This is the one link lykos already does well end-to-end (the
   address-leak case reaches a real L3 shell). A harness/snapshot crash feeds the same
   root_cause -> poc_primitive -> build_exploit chain; execution-state-aware reasoning is the
   current research frontier for turning a crash into a proof-of-vulnerability
   ([arXiv:2602.13574](https://arxiv.org/html/2602.13574v1)).

**What we need to BUILD, in order of leverage:**
1. A **component attack-surface ranker** over the cheap facts (imports/strings/exports/entry), to
   pick a harness target without whole-CFG recovery.
2. A **binary-only snapshot-fuzzing lane** (Nyx or Snapchange, or a qemu-snapshot driver) that
   snapshots at the chosen component entry and fuzzes from there -- the missing piece for a
   stripped large binary. For targets with source/a known library, extend the existing libFuzzer
   harness lane with coverage-steered (optionally LLM-assisted) harness generation.
3. **Light, component-scoped analysis** (lighter rizin modes on the component only) to feed
   `directed_fuzz` the sinks to steer toward -- never `aaa` on the whole image.
4. Reuse the existing **crash -> primitive -> exploit** chain unchanged.

The honest summary: lykos can already go crash -> L3 exploit; the large-binary gap is entirely in
REACHING a crash in a huge image, and the answer is component harnessing + snapshot/directed
fuzzing, not better whole-binary analysis.
