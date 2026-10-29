"""Single source of truth for the analysis pipeline's stages (doc 49, Theme 1a).

A stage's identity used to be spread across at least five hand-synced structures in
``orchestrate`` -- ``_TARGET`` / ``_CASE`` / ``_ON_DEMAND`` / ``_NO_PARAMS`` /
``_PLAN_STAGES`` -- plus the API server's copies. Keeping them in step by hand is exactly how
``patch_diff`` fell out of the schedule (regression fixed in 583f1fe): it was added to some
lists and not the others, and a scheduling-invariant test caught it only after the fact.

This module declares each stage ONCE, as an ordered list of :class:`StageSpec` descriptors, and
``orchestrate`` derives every one of those structures from it (see ``_derive`` consumers there).
Adding a stage is now a single append here; it cannot fall out of sync because there is nothing
to sync. It also gives the GUI and the report a real catalogue to render the pipeline from
(doc 49, Themes 2 and 4) instead of each re-deriving an ad-hoc list.

Design notes carried from the structures this replaces:

* The LIST ORDER is the operator-facing plan order -- the sequence the pipeline rail shows and
  ``_PLAN_STAGES`` reproduces exactly. Stages that are dispatchable but deliberately absent from
  an autopilot run (``on_demand``) are listed last, out of the plan.
* ``module``/``enqueue`` are strings resolved lazily (``orchestrate._enqueue_fn``), so importing
  this module pulls in nothing heavy -- it stays safe to import from the scheduler's top level.
* ``no_params`` means the autopilot runs the stage with NO params. It is a narrower question than
  "the enqueue helper requires no params": a stage that merely *reads* ``max_seconds`` (libfuzzer,
  fuzz, coverage_fuzz, concolic) must NOT set it, or the budget's time slice never reaches it and
  it runs its own default -- the "30-second smoke test" defect. And ``root_cause`` / ``build_poc``
  / ``poc_primitive`` require ``params["input_sha"]`` (the crashing input the prove loop threads
  in), so they are likewise not ``no_params``. The pins for both live in
  ``tests/test_autopilot_scheduling.py``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class StageSpec:
    """One pipeline stage, declared once.

    scope:   "target" (per-executable) | "case" (per-case) | "plan" (a plan-only marker with no
             enqueue function, e.g. the final false-positive review).
    in_plan: appears in the plan the operator watches, with ``label`` at this position.
    no_params: the autopilot enqueues it with no params (see the module docstring).
    on_demand: non-empty => dispatchable via the API/CLI but deliberately NOT autopilot-scheduled;
               the string is the reason shown to the operator. Implies ``in_plan is False``.
    """
    name: str
    label: str
    scope: str
    module: Optional[str] = None
    enqueue: Optional[str] = None
    in_plan: bool = True
    no_params: bool = False
    on_demand: str = ""


# The pipeline, in plan order. Grouped by phase with the same narrative the rail shows.
STAGES: tuple[StageSpec, ...] = (
    # --- Ingest & recovery -------------------------------------------------------------------
    # ingest_triage is normally run by the ingest path before any autopilot exists for the case;
    # it is here so the pass can triage executables a source project also builds. dynamic_run is
    # the FLOOR: one execution before any analysis.
    StageSpec("ingest_triage", "Triage", "target", "..analyze.ingest", "enqueue_triage", no_params=True),
    StageSpec("unpack", "Unpack (packed executable)", "target", "..analyze.unpack", "enqueue_unpack"),
    StageSpec("firmware_carve", "Carve firmware image", "target", "..analyze.firmware", "enqueue_firmware", no_params=True),
    StageSpec("firmware_rehost", "Rehost firmware", "target", "..analyze.firmware", "enqueue_rehost"),
    StageSpec("dynamic_run", "Baseline execution", "target", "..analyze.dynamic", "enqueue_dynamic"),
    StageSpec("disassemble", "Disassemble", "target", "..analyze.disassemble", "enqueue_disassemble", no_params=True),
    StageSpec("detect_cwe", "Static detectors", "target", "..analyze.detect", "enqueue_detect", no_params=True),
    # --- Case-scoped linking (interleaved in the plan where it runs) --------------------------
    StageSpec("whole_system", "Whole-system emulation", "case", "..analyze.link", "enqueue_whole_system"),
    StageSpec("ipc_model", "IPC model", "case", "..analyze.link", "enqueue_ipc", no_params=True),
    StageSpec("link_case", "Link related targets", "case", "..analyze.link", "enqueue_link", no_params=True),
    StageSpec("cross_taint", "Cross-component taint", "case", "..analyze.link", "enqueue_cross_taint", no_params=True),
    # --- Known-vuln / dependency / config scans -----------------------------------------------
    StageSpec("cve_scan", "Known-CVE scan", "target", "..analyze.fingerprint", "enqueue_cve_scan"),
    StageSpec("source_cve_scan", "Dependency-CVE scan", "target", "..analyze.fingerprint", "enqueue_source_cve_scan", no_params=True),
    StageSpec("embedded_audit", "RTOS config audit", "target", "..analyze.fingerprint", "enqueue_embedded_audit", no_params=True),
    StageSpec("int_overflow_scan", "Int-overflow allocs", "target", "..analyze.fingerprint", "enqueue_int_overflow_scan", no_params=True),
    StageSpec("uaf_scan", "Use-after-free scan", "target", "..analyze.fingerprint", "enqueue_uaf_scan", no_params=True),
    StageSpec("assert_guard_scan", "Assert-only bounds checks", "target", "..analyze.fingerprint", "enqueue_assert_guard_scan", no_params=True),
    StageSpec("oob_write_scan", "Out-of-bounds index writes", "target", "..analyze.fingerprint",
              "enqueue_oob_write_scan", no_params=True),
    StageSpec("grounding", "Ground findings (precision + peer reachability)", "target",
              "..analyze.grounding_stage", "enqueue_grounding", no_params=True),
    StageSpec("confirm", "Confirm real+reachable findings, then weaponize", "target",
              "..analyze.verify_stage", "enqueue_verify", no_params=True),
    StageSpec("source_sink_scan", "Tainted-sink scan", "target", "..analyze.fingerprint", "enqueue_source_sink_scan", no_params=True),
    StageSpec("cpg_scan", "Per-CWE source/sink queries", "target", "..analyze.fingerprint", "enqueue_cpg_scan", no_params=True),
    # extract_secrets feeds itself a probe input when given none; synthesize_secret reads static
    # findings and never executes -- both take no params.
    StageSpec("extract_secrets", "Recover gate values", "target", "..analyze.debug", "enqueue_extract", no_params=True),
    StageSpec("synthesize_secret", "Secret PoC", "target", "..analyze.poc", "enqueue_secret", no_params=True),
    # --- Search / fuzzing ---------------------------------------------------------------------
    # net_fuzz/env_fuzz decline for themselves when they do not apply; boundary_fuzz discovers its
    # own IPC channel. libfuzzer reads max_seconds, so it must NOT be no_params (see module doc).
    StageSpec("net_fuzz", "Network fuzzing", "target", "..analyze.fuzz", "enqueue_net_fuzz", no_params=True),
    StageSpec("boundary_fuzz", "IPC boundary fuzzing", "target", "..analyze.link", "enqueue_boundary", no_params=True),
    StageSpec("libfuzzer", "libFuzzer harness", "target", "..analyze.libfuzzer_stage", "enqueue_libfuzzer"),
    StageSpec("source_confirm", "Directed source confirmation", "target",
              "..analyze.source_confirm_stage", "enqueue_source_confirm"),
    StageSpec("uc_symbolic", "Under-constrained symbolic exec (undriven code)", "target",
              "..analyze.symbolic.uc_stage", "enqueue_uc_symbolic"),
    StageSpec("synth_confirm", "Synthesized-driver confirmation", "target",
              "..analyze.synth_confirm_stage", "enqueue_synth_confirm"),
    StageSpec("env_fuzz", "Env-var fuzzing", "target", "..analyze.fuzz", "enqueue_env_fuzz", no_params=True),
    StageSpec("cve_poc", "CVE weaponization", "target", "..analyze.poc", "enqueue_cve_poc", no_params=True),
    StageSpec("cve_corroborate", "CVE corroboration", "target", "..analyze.fingerprint", "enqueue_cve_corroborate", no_params=True),
    StageSpec("synthesize_injection", "Injection probes", "target", "..analyze.poc", "enqueue_inject"),
    StageSpec("fuzz", "Black-box fuzzing", "target", "..analyze.fuzz", "enqueue_fuzz"),
    StageSpec("coverage_fuzz", "Coverage fuzzing", "target", "..analyze.fuzz", "enqueue_coverage_fuzz"),
    StageSpec("directed_fuzz", "Directed fuzzing", "target", "..analyze.fuzz", "enqueue_directed_fuzz"),
    # --- Memory-safety probes -----------------------------------------------------------------
    StageSpec("heap_check", "Heap checks", "target", "..analyze.dynamic", "enqueue_heap_check"),
    StageSpec("heap_trace", "Heap primitives", "target", "..analyze.dynamic", "enqueue_heap_trace", no_params=True),
    StageSpec("oob_index", "Array-index probes", "target", "..analyze.dynamic", "enqueue_oob_index", no_params=True),
    # mem_oracle picks its own probe inputs (a recorded crash if there is one, else an empty probe).
    StageSpec("mem_oracle", "Uninitialised-memory oracle", "target", "..analyze.dynamic", "enqueue_mem_oracle", no_params=True),
    StageSpec("chain_primitive", "Primitive chaining", "target", "..analyze.poc", "enqueue_chain", no_params=True),
    StageSpec("concolic", "Concolic execution", "target", "..analyze.symbolic", "enqueue_concolic"),
    StageSpec("synthesize_poc", "Synthesize PoC", "target", "..analyze.poc", "enqueue_synthesize", no_params=True),
    # --- Prove: root-cause and the exploit ladder ---------------------------------------------
    # root_cause/build_poc/poc_primitive require params["input_sha"] (the crashing input), so they
    # are NOT no_params -- listing them would drop that input and every one would fail.
    StageSpec("root_cause", "Root-cause", "target", "..analyze.debug", "enqueue_root_cause"),
    StageSpec("build_poc", "Build PoC", "target", "..analyze.poc", "enqueue_build_poc"),
    StageSpec("poc_primitive", "PoC primitive", "target", "..analyze.poc", "enqueue_primitive"),
    StageSpec("build_exploit", "Build exploit", "target", "..analyze.poc", "enqueue_exploit"),
    # --- Observation & regression -------------------------------------------------------------
    # multi_debug is the only follow-fork/exec capture in the engine; it needs the crashing input,
    # so it must NOT be no_params.
    StageSpec("behavior_trace", "Behaviour trace", "target", "..analyze.debug", "enqueue_behavior_trace"),
    StageSpec("dynamic_taint", "Dynamic taint", "target", "..analyze.debug", "enqueue_taint"),
    StageSpec("multi_debug", "Follow fork/exec", "target", "..analyze.debug", "enqueue_multi_debug"),
    StageSpec("debug_monitor", "Runtime monitor", "target", "..analyze.debug", "enqueue_monitor"),
    StageSpec("poc_diff", "Regression diff", "target", "..analyze.poc", "enqueue_poc_diff"),
    # A plan-only terminal marker: the false-positive review has no enqueue function of its own.
    StageSpec("verify", "False-positive review", "plan", in_plan=True),

    # --- On demand: dispatchable via the API/CLI, deliberately NOT autopilot-scheduled --------
    # Each needs an operator decision a run does not have. Listed (out of the plan) so they are
    # dispatchable and so a stage cannot fall out of the catalogue unseen.
    StageSpec("harness", "", "target", "..analyze.harness", "enqueue_harness", in_plan=False,
              on_demand="started from the Code tab's function view on the functions the operator picks"),
    StageSpec("patch_diff", "", "target", "..analyze.patch_diff_stage", "enqueue_patch_diff", in_plan=False,
              on_demand="needs a second build chosen as the baseline to diff against"),
    StageSpec("variant_scan", "", "target", "..analyze.scan_stages", "enqueue_variant_scan", in_plan=False,
              on_demand="needs the vulnerable function named by the operator (from the Scans panel)"),
    StageSpec("weggli_scan", "", "target", "..analyze.scan_stages", "enqueue_weggli_scan", in_plan=False,
              on_demand="an operator source-pattern scan, started from the Scans panel"),
    StageSpec("diff_test", "", "case", "..analyze.scan_stages", "enqueue_diff_test", in_plan=False,
              on_demand="needs the operator to pick 2+ implementations of the same thing to compare"),
)


def _by_name() -> dict:
    return {s.name: s for s in STAGES}


def label_for(name: Optional[str]) -> Optional[str]:
    """A human label for a stage name (for the GUI/report provenance link). Uses the declared plan
    label; falls back to a titleised name for the on-demand stages (whose plan label is empty) and
    returns the name unchanged for anything not in the registry. None maps to None."""
    if not name:
        return None
    s = _by_name().get(name)
    if s is None:
        return name
    return s.label or name.replace("_", " ").capitalize()


def check_consistency() -> None:
    """Internal-consistency invariants of the registry (pinned by the scheduling-invariant test).

    These replace "did someone remember to add it to all five lists?" with a single structural
    check that cannot be satisfied by a half-registered stage.
    """
    seen = set()
    for s in STAGES:
        assert s.name not in seen, f"duplicate stage {s.name!r}"
        seen.add(s.name)
        assert s.scope in ("target", "case", "plan"), f"{s.name}: bad scope {s.scope!r}"
        if s.scope == "plan":
            assert s.module is None and s.enqueue is None, f"{s.name}: plan-only stage must have no enqueue"
        else:
            assert s.module and s.enqueue, f"{s.name}: {s.scope} stage needs module+enqueue"
        if s.on_demand:
            assert not s.in_plan, f"{s.name}: on-demand stage must not be in the plan"
        if s.in_plan:
            assert s.label, f"{s.name}: a planned stage needs a label"
        else:
            assert s.scope != "plan", f"{s.name}: a plan-only stage must be in the plan"
