"""Nothing in this engine may fail quietly without leaving a trace.

Three separate holes were measured before these tests existed.

1. **Nothing configured logging.** The root logger sat at its default WARNING with no handlers,
   so all 58 `_log.debug(..., exc_info=True)` calls in the tree -- each written precisely so a
   swallowed error would leave evidence -- were discarded before reaching anything, and a
   `_log.warning` escaped only through `logging.lastResort`, with no timestamp, module or line.

2. **Most handlers did not even try.** Of 457 broad `except` handlers in core, 187 were silent
   AND carried no comment saying why silence was right. One of them hid the defect that made L3
   unreachable: `_l2_offset` wrapped its body in `except Exception: pass`, so when it began
   returning None for every target, nothing anywhere said so.

3. **Nobody reads a debug log.** So `observe.absorbed` also COUNTS, keyed on the caller's own
   frame, and the autopilot scorecard reports the number. "absorbed nothing" is then a claim the
   run makes, not an absence anyone has to notice.
"""
from __future__ import annotations

import ast
import inspect
import pathlib

CORE = pathlib.Path(__file__).resolve().parents[1] / "core" / "lykos"
_BROAD = {"Exception", "BaseException"}

#: These run as standalone scripts -- the parent copies each into a scratch dir and runs it with
#: a bare `python3`, two of them under the vendored angr/unicorn venvs -- so `lykos` is NOT
#: importable from them. They keep their own `_absorbed()` list and ship it in the JSON result
#: they already return; the parent folds it in with `observe.absorbed_remote`.
_STANDALONE = {
    "analyze/dynamic/heaptrace.py",
    "analyze/firmware/angr_mmio.py",
    "analyze/firmware/unicorn_driver.py",
    "analyze/fuzz/batch_runner.py",
    "analyze/poc/attribution_trace.py",
    "analyze/poc/ptrace_capture.py",
    "analyze/pcode_worker.py",
    "analyze/symbolic/angr_driver.py",
}


def _is_broad(h: ast.ExceptHandler) -> bool:
    t = h.type
    if t is None:
        return True
    if isinstance(t, ast.Name):
        return t.id in _BROAD
    if isinstance(t, ast.Tuple):
        return any(isinstance(e, ast.Name) and e.id in _BROAD for e in t.elts)
    return False


def _handlers():
    """(relpath, handler, source-lines) for every broad handler in core."""
    for p in sorted(CORE.rglob("*.py")):
        src = p.read_text()
        try:
            tree = ast.parse(src)
        except SyntaxError:                               # pragma: no cover
            continue
        lines = src.splitlines()
        for h in (n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler) and _is_broad(n)):
            yield str(p.relative_to(CORE)), h, lines, src


def _leaves_a_trace(h, lines, src) -> bool:
    start = h.body[0].lineno
    end = h.body[-1].end_lineno or h.body[-1].lineno
    body = "\n".join(lines[start - 1:end])
    if any(k in body for k in ("_log.", "logger.", "observe.absorbed", "_absorbed(",
                               "ctx.progress", "ctx.emit", "warn")):
        return True
    if any(isinstance(n, ast.Raise) for n in ast.walk(h)):
        return True
    # Records the caught exception into data the caller can see (`info.errors.append(repr(e))`).
    if h.name and any(isinstance(n, ast.Name) and n.id == h.name
                      for st in h.body for n in ast.walk(st)):
        return True
    return False


def _explained(h, lines) -> bool:
    """Is there a comment on, or inside, this handler?

    The window starts at the `except` line, not at the first body statement: a comment written
    between the two -- which is the natural place for "why silence is correct here" -- lives in
    exactly that gap, and a slice from the body start skips it.
    """
    end = h.body[-1].end_lineno or h.body[-1].lineno
    window = lines[h.lineno - 1:end]
    return any("#" in ln for ln in window[:1]) or any(
        ln.lstrip().startswith("#") for ln in window)


def test_no_broad_handler_is_both_silent_and_unexplained():
    """The invariant. A handler may swallow -- plenty should -- but then it either leaves a trace
    or says in a comment why silence is the right answer. 187 did neither."""
    offenders = []
    for rel, h, lines, src in _handlers():
        if _leaves_a_trace(h, lines, src) or _explained(h, lines):
            continue
        offenders.append(f"{rel}:{h.lineno}")
    assert not offenders, (
        "%d broad handler(s) swallow an error with no trace and no explanation: %s"
        % (len(offenders), offenders[:20]))


def test_every_module_that_counts_absorptions_can_reach_the_counter():
    """`observe.absorbed(_log, ...)` needs both names bound at module level. The bulk edit that
    introduced them placed the imports by regex at first, and on two modules the regex matched a
    line inside an embedded source string -- one of them the Java fixture in realgate -- so the
    name looked imported and was not."""
    missing = []
    for p in sorted(CORE.rglob("*.py")):
        src = p.read_text()
        if "observe.absorbed(" not in src:
            continue
        tree = ast.parse(src)
        has_observe = any(
            isinstance(n, ast.ImportFrom) and any(a.name == "observe" for a in n.names)
            for n in tree.body)
        has_log = any(
            isinstance(n, ast.Assign) and any(getattr(t, "id", None) == "_log" for t in n.targets)
            for n in tree.body)
        if not (has_observe and has_log):
            missing.append(f"{p.relative_to(CORE)} (observe={has_observe} _log={has_log})")
    assert not missing, "module-level bindings missing: %s" % missing


def test_the_standalone_drivers_do_not_import_the_package():
    """They run under a bare (or vendored-venv) python with no `lykos` on the path. An import
    added here does not fail a test -- it fails at runtime, inside a subprocess, as an empty
    result the parent reports as "no crash observed"."""
    offenders = []
    for rel in sorted(_STANDALONE):
        p = CORE / rel
        if not p.exists():
            continue
        tree = ast.parse(p.read_text())
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and (node.level or 0) > 0:
                offenders.append(f"{rel}: relative import of {node.module or '.'}")
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("lykos"):
                offenders.append(f"{rel}: imports {node.module}")
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.startswith("lykos"):
                        offenders.append(f"{rel}: imports {a.name}")
    assert not offenders, "a standalone driver cannot import the package: %s" % offenders


def test_each_standalone_driver_ships_what_it_absorbed():
    """The drivers that have a single JSON result hand their absorbed list back in it, and the
    parent folds it in. A tracer that quietly skips a step is exactly what turns a real
    use-after-free into "no heap error observed", so this is the one place the counter must not
    have a blind spot."""
    shipping = {"analyze/dynamic/heaptrace.py", "analyze/firmware/angr_mmio.py",
                "analyze/firmware/unicorn_driver.py", "analyze/poc/attribution_trace.py",
                "analyze/poc/ptrace_capture.py"}
    for rel in sorted(shipping):
        src = (CORE / rel).read_text()
        assert "_ABSORBED" in src, f"{rel} keeps no absorbed list"
        assert '"absorbed"' in src, f"{rel} does not ship its absorbed list in its result"
    folded = "".join((CORE / f).read_text() for f in (
        "analyze/poc/capture.py", "analyze/poc/attribution.py", "analyze/firmware/rehost.py",
        "analyze/dynamic/oob_index.py", "analyze/dynamic/heap_discover.py"))
    for driver in ("ptrace_capture", "attribution_trace", "angr_mmio", "unicorn_driver",
                   "heaptrace"):
        assert "absorbed_remote(\"lykos.analyze" in folded and driver in folded, \
            f"nothing folds {driver}'s absorbed list into the counter"


def test_both_entry_points_connect_the_log():
    """A logger with no handler is not a trace. The CLI and the API server are the two ways into
    the engine, and `observe.configure` has to run on both or everything above is theatre."""
    from lykos import cli
    from lykos.api import server
    assert "observe.configure(" in inspect.getsource(cli.main), "the CLI does not configure logging"
    assert "observe.configure(" in inspect.getsource(server.serve), "serve() does not configure"
    assert "--log" in inspect.getsource(cli.build_parser), "no way to ask for a louder log"


def test_every_diagnostic_instrument_connects_the_log():
    """The gates and probes in tools/ are the things you run WHEN something is wrong, so they are
    the last place a log should be unreadable. None of them configured it, and a real gate run
    printed `run <uuid> is past its deadline and unresponsive` through `logging.lastResort` --
    no timestamp, no module, no line, no way to tell which stage said it."""
    import pathlib as _p
    tools = _p.Path(__file__).resolve().parents[1] / "tools"
    missing = [t.name for t in sorted(tools.glob("*.py"))
               if t.name not in ("corpus_run.py", "build_cvedb.py")
               and "observe.configure()" not in t.read_text()]
    assert not missing, "these instruments leave the log unconfigured: %s" % missing


def test_no_cleanup_block_kills_a_child_without_closing_its_pipes():
    """An unraisable BrokenPipeError is the worst shape an error can take here: it escapes the
    `except` that was written for it, cannot be caught at the call site, and surfaces later at
    GC time with a traceback pointing at whatever line happened to trigger collection.

    A real-corpus run over `/usr/bin/*` and a set of HTB pwn binaries printed dozens of them, all
    blaming `interaction._drive`, which did `finally: p.kill()` and nothing else. `leak._kill`
    and `menu._kill` had already documented the right order; three blocks had not got it. They
    now share `sandbox.kill_quietly`, which also makes the group-kill decision safe -- it
    signals the group only when the child actually leads one, because signalling the group of a
    child spawned without `start_new_session` kills the worker pool."""
    import ast
    import re

    offenders = []
    for path in sorted(CORE.rglob("*.py")):
        src = path.read_text()
        try:
            tree = ast.parse(src)
        except SyntaxError:                               # pragma: no cover
            continue
        lines = src.splitlines()
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Try) and node.finalbody):
                continue
            lo = node.finalbody[0].lineno
            hi = node.finalbody[-1].end_lineno or node.finalbody[-1].lineno
            text = "\n".join(lines[lo - 1:hi])
            if re.search(r"\b\w+\.kill\(\)", text) and not re.search(
                    r"\.close\(\)|_kill\(|_killpg\(|kill_quietly\(", text):
                offenders.append(f"{path.relative_to(CORE)}:{lo}")
    assert not offenders, (
        "these kill a child without closing its pipes first: %s -- use sandbox.kill_quietly"
        % offenders)


def test_the_group_kill_is_conditional_on_leading_a_group():
    """Signalling the process group of a child that was NOT spawned with start_new_session
    signals our own group, which kills the worker pool. The helper decides this itself so no
    caller has to get it right."""
    import inspect

    from lykos.analyze.dynamic import sandbox
    src = inspect.getsource(sandbox.kill_quietly)
    assert "os.getpgid(pid) == pid" in src, \
        "kill_quietly must group-kill only a session leader"
    assert src.index("stream.close()") < src.index("killpg"), \
        "the pipes must be closed before the kill, which is the whole point"


def test_a_wedged_or_unresponsive_stage_is_named():
    """A real-corpus run on `/usr/bin/*` printed exactly two diagnostics, and neither was usable:

        run c7bbd521c45045bbb54399e1303dfdff is past its deadline and unresponsive; ...
        worker-2 wedged past its hard deadline; reclaimed its concurrency slot ...

    A run uuid and a worker index. The question a reader actually has is "WHICH STAGE hangs on
    this target", and answering it meant taking the uuid to the database. Both records now carry
    the stage, because a stage that wedges on real material is the single most valuable thing
    this log can tell anyone."""
    import inspect

    from lykos.jobs import worker
    assert "stage" in worker._Active.__slots__, "_Active cannot name what wedged"
    assert "stage" in inspect.signature(worker._Heartbeat.__init__).parameters, \
        "_Heartbeat cannot name what went unresponsive"
    sup = inspect.getsource(worker)
    assert "wedged in stage %s (run %s)" in sup, "the wedge message does not name the stage"
    assert "stage %s (run %s) is past its deadline" in sup, \
        "the unresponsive-lease message does not name the stage"
    # ...and the records are actually populated at the call site, not just able to hold it.
    assert "_Active(slot, hard, stage=run.stage, run_id=run_id)" in sup
    assert "stage=run.stage)" in sup


def test_the_scorecard_reports_what_the_run_absorbed():
    """The number is the point: nobody reads a debug log, so a run has to say out loud that it
    absorbed nothing -- or that it absorbed forty, and where."""
    from lykos.analyze import orchestrate
    src = inspect.getsource(orchestrate._scorecard)
    assert "absorbed_since" in src, "the scorecard does not diff the absorbed counter"
    assert 'card["absorbed"]' in src
    from lykos import cli as _cli
    printed = inspect.getsource(_cli._print_scorecard)
    assert "absorbed" in printed, "the scorecard is recorded but never shown"


def test_the_absorbed_baseline_is_taken_per_target():
    """The counter is process-wide, so a per-target figure is a difference -- and the baseline
    has to be re-taken inside the target loop. Taken once per case, the second target's
    scorecard reports the first target's absorptions on top of its own, and firmware carving
    registers a child target per component, so several targets per case is the normal shape."""
    import inspect

    from lykos.analyze import orchestrate
    src = inspect.getsource(orchestrate.run_case_autopilot)
    loop = src.index("while wi < len(worklist)")
    base = src.index("absorbed_base = observe.absorbed_counts()")
    assert base > loop, "the absorbed baseline is taken once per case, not per target"


def test_the_counter_is_keyed_on_the_site_not_on_the_message():
    """A hand-written key would have to stay unique across ~190 call sites. The caller's frame is
    unique by construction, so `module.function:line` needs no maintenance -- and that is what
    makes the per-site counts in the scorecard trustworthy."""
    import logging

    from lykos import observe
    observe.reset_absorbed()
    log = logging.getLogger("lykos.test.sites")

    def one():
        try:
            raise ValueError("a")
        except ValueError:
            observe.absorbed(log, "answering None")

    def two():
        try:
            raise ValueError("b")
        except ValueError:
            observe.absorbed(log, "answering None")

    one(); one(); two()
    counts = observe.absorbed_counts()
    assert len(counts) == 2, counts            # same message, different sites -> two entries
    assert sorted(counts.values()) == [1, 2], counts
    assert all(":" in k for k in counts), counts
    observe.reset_absorbed()


def test_a_driver_list_folds_in_without_trusting_it():
    """The list crosses a process boundary from a subprocess that may have been killed
    mid-write, so a malformed one must count for nothing rather than raise."""
    from lykos import observe
    observe.reset_absorbed()
    assert observe.absorbed_remote("d", [{"what": "x"}, {"what": "x"}, "junk", None, 7]) == 2
    assert observe.absorbed_total() == 2
    assert observe.absorbed_remote("d", "not a list") == 0
    assert observe.absorbed_remote("d", None) == 0
    observe.reset_absorbed()


# ------------------------------------------------------------- a stage must watch its own clock
# Both of these were recorded as `error` by the worker on real HTB binaries, and the real-corpus
# gate rejects an error outright: "no stage ERRORED -- an error is never an acceptable outcome, a
# decline is". Neither was a defect in the analysis; both were a loop that did not stop.


def test_env_fuzz_polls_its_own_deadline():
    """`fuzz_env` bounded itself only by `max_execs`, and `max_execs` is sized from a MEASURED
    exec/s rate -- which does not hold on an interactive target, where every run blocks for the
    full timeout instead of milliseconds. On `power_greed` the stage ran so far past its deadline
    that the heartbeat stopped renewing and the reaper reclaimed the row: `error: lease
    expired`."""
    import inspect

    from lykos.analyze.fuzz import env_stage, envfuzz
    assert "should_stop" in inspect.signature(envfuzz.fuzz_env).parameters, \
        "fuzz_env cannot be told to stop"
    loop = inspect.getsource(envfuzz.fuzz_env)
    assert loop.count("if stop():") >= 2, \
        "the poll must happen in both the outer and the inner loop, or one pass still overruns"
    caller = inspect.getsource(env_stage)
    assert "ctx.should_cancel() or ctx.timed_out()" in caller, \
        "the stage does not hand fuzz_env its deadline"


def test_env_fuzz_stops_on_the_poll_and_says_so(tmp_path):
    """And the stop is REPORTED: a run that stopped early is not a run that found nothing."""
    from lykos.analyze.fuzz import envfuzz
    seen = {"n": 0}

    def never(_ov):
        seen["n"] += 1
        return (False, 0, None)

    r = envfuzz.fuzz_env("/bin/true", ["FOO"], max_execs=100000, run=never,
                         should_stop=lambda: seen["n"] >= 5)
    assert r.execs <= 8, f"ran {r.execs} executions past a poll that tripped at 5"
    assert "stopped after" in (r.note or ""), f"the early stop is not reported: {r.note!r}"


def test_an_afl_abort_declines_rather_than_erroring():
    """afl-fuzz can abort having produced no queue and no crashes and STILL exit 0, so the
    detection has to stay -- without it a campaign that never executed the target reports a
    clean "0 crashes". But RAISING made the stage an error. Measured on `portaloo`: `Fork server
    handshake failed` at afl-forkserver.c:2205, which is a fact about what afl can instrument on
    that binary, not a defect here. The decline carries the same information."""
    import inspect

    from lykos.analyze.fuzz import coverage
    src = inspect.getsource(coverage.coverage_stage)
    i = src.index("campaign_failed(proc)")
    window = src[i:i + 1800]
    assert "raise RuntimeError" not in window, "an afl abort still raises instead of declining"
    assert '"supported": False' in window and '"aborted": True' in window
    assert "NOT a clean" in window, "the decline must still refuse to read as a clean run"
    # ...and the gate must be able to tell whose fault it is.
    from lykos.analyze.capabilities import classify_decline
    assert classify_decline("afl-fuzz aborted: Fork server handshake failed. No inputs were "
                            "executed, so this is NOT a clean 'no crashes' result.") == "target"
