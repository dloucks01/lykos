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
