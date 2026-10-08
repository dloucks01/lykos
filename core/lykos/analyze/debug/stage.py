"""Phase 6 — the `root_cause` stage: explain a confirmed crash. Uses GDB when installed,
otherwise the pure-stdlib ptrace helper; produces a structured root-cause report (fault
classification + backtrace + a static call-graph/taint slice), stores it as an artifact, and
attaches a root-cause evidence line to the crash finding. Cross-arch targets are captured
via qemu-user's gdbstub."""
from __future__ import annotations

import json
import os
import shutil
import sys

from ...db.dao import CallEdgeDAO, DynResultDAO, FindingDAO, FunctionDAO, TargetDAO
from ...jobs.registry import register_stage
from .. import elf
from ..dynamic import sandbox
from ..dynamic.stage import crash_dedup_key
from ..fuzz.runner import place
from ..poc.capture import MODES, how_to_feed, make_capture, make_qemu_capture, materialize_helper
from . import gdb, qemu_gdb, rootcause

ROOT_CAUSE_STAGE = "root_cause"
TOOL = "rootcause"
TOOL_VERSION = "rootcause-1"


def _hex(v):
    """Addresses reach the finding table as hex strings; the slice carries them as ints."""
    return None if v is None else (v if isinstance(v, str) else hex(v))


# ---- managed runtimes: the backtrace arrives with the fault ------------------------------
#
# One code path for every runtime that reports a fault as an uncaught exception, because the
# shape of the work is identical and only the vocabulary differs. Each entry says how to parse
# that runtime's trace, how to render a frame, and what the ceiling is -- a runtime that owns
# the instruction pointer cannot be escalated to control-flow hijack, and claiming otherwise
# would be a fabricated level.
_MANAGED_FILE_TYPES = {"jar": "jvm", "class": "jvm", "jvm": "jvm", "pyc": "cpython",
                       "wasm": "wasm"}


def _managed_runtime(kind: str):
    if kind == "jvm":
        return {
            "name": "the JVM", "backend": "jvm",
            "parse": lambda r: sandbox.jvm_exception(r.stderr, r.exit_code, r.stdout),
            "blame": sandbox.app_frame,
            "frame": lambda fr: f"{fr[0]}({fr[1]})",
            "checks": "the JVM checks every array access and owns every pointer",
            "lang": "Java",
        }
    if kind == "wasm":
        # A trap carries no call stack out of the engine -- only the message and the export it
        # trapped in, both of which the sandbox has already classified. There is nothing to
        # re-parse, so this descriptor reads the result instead of the stderr.
        return {
            "name": "the WebAssembly engine", "backend": "wasm",
            "parse": lambda r: (r.signal_name, r.note, []),
            "blame": lambda frames: None,
            "frame": lambda fr: str(fr),
            "checks": "the engine bounds-checks every memory access and owns every pointer",
            "lang": "WebAssembly",
        }
    return {
        "name": "CPython", "backend": "cpython",
        "parse": lambda r: sandbox.python_exception(r.stderr, r.exit_code, r.stdout),
        "blame": sandbox.app_frame_py,
        "frame": lambda fr: f"{fr[0]}:{fr[1]}" + (f" in {fr[2]}" if len(fr) > 2 and fr[2] else ""),
        "checks": "CPython bounds-checks every index and owns every reference",
        "lang": "Python",
    }


def _root_cause_managed(ctx, target, input_sha, base_argv, mode, timeout, runtime) -> dict:
    """Root cause on a managed runtime -- where the runtime hands it to you.

    The native path attaches a debugger to recover a backtrace from a fault address. A managed
    fault arrives with the backtrace already attached, symbolised, with line numbers, and
    naming the exception class: `Svc.setOpt(Svc.java:14)` or `svc.py:14 in parse` is strictly
    more than the native channel can produce even when it works. What it does NOT have is an
    address, so the finding is keyed on the APPLICATION frame instead -- and on the application
    frame rather than the top one, because `Integer.parseInt("abc")` throws three JDK frames
    deep (and `int("abc")` from inside no Python frame at all), so blaming the top frame blames
    the runtime and merges every such defect in the program into one finding.

    Without this the stage declined with "no qemu gdbstub layout for jvm", which is true of
    qemu and irrelevant here: nothing needed emulating.
    """
    import json as _json

    from ..fuzz.runner import place
    from ..runtime_fault import managed_fault
    rt = _managed_runtime(runtime)
    input_bytes = ctx.content.get_bytes(input_sha)
    exe = ctx.scratch() / "target.bin"
    ctx.content.stage_target(target, exe.parent, exe.name)
    wf = ctx.scratch() / "input.bin"
    wf.write_bytes(input_bytes)
    tried = []
    res = None
    for m in [mode] + [x for x in MODES if x != mode]:
        argv, stdin = (place(base_argv, str(wf)), b"") if m != "stdin" else (
            list(base_argv), input_bytes)
        ctx.progress(msg=f"reproducing under {rt['name']} ({m})")
        res = sandbox.run(exe, argv=argv, stdin=stdin, timeout=timeout)
        tried.append(m)
        if res.crashed:
            mode = m
            break
    if res is None or not res.crashed:
        # Distinguish "ran and did not fault" from "never ran". A managed runtime refusing the
        # program -- bytecode built for another interpreter version, a missing import -- fails
        # identically on every input, and reporting that as "no fault" hides a capability gap
        # behind a result that looks like a clean program.
        why = (res.note if res is not None and "not-runnable" in (res.isolation or "")
               else None)
        note = (f"{rt['name']} could not run this program, so nothing was tested: {why}" if why
                else f"the input did not fault under {rt['name']} via any of " + ", ".join(tried))
        ctx.emit("rootcause.done", payload={
            "supported": True, "backend": rt["backend"], "input_modes_tried": tried,
            "ran": not why, "note": note})
        ctx.progress(pct=100, msg=note[:80])
        return {}

    kind, detail, frames = rt["parse"](res)
    blame = rt["blame"](frames)
    hit = managed_fault(kind)
    cwe, sev = (hit[0], hit[1]) if hit else ("CWE-248", "medium")
    summary = detail or f"uncaught {kind}"
    stack = [rt["frame"](fr) for fr in frames]
    blame_frame = rt["frame"](blame) if blame else None
    report = {
        "backend": rt["backend"], "signal": kind, "summary": summary,
        "classification": {"cwe": cwe, "class": kind, "severity": sev},
        "stack": stack,
        "blame_frame": blame_frame,
        "input_mode": mode, "stderr": (res.stderr or b"")[:4000].decode("utf-8", "replace"),
        # Say what this level of evidence is and is not. The runtime owns the instruction
        # pointer, so no amount of work here produces L2/L3 -- that is the runtime, not a gap.
        "exploitability": {
            "rating": "denial-of-service", "score": 35,
            "reasons": ["an uncaught exception terminates the process, which for a service is "
                        "denial of service",
                        f"{rt['checks']}, so this cannot be escalated to control-flow hijack "
                        f"(no L2/L3 for {rt['lang']})"]},
    }
    report_sha = ctx.put_artifact("root-cause", data=_json.dumps(
        report, indent=2, sort_keys=True).encode(), meta={"cwe": cwe})
    FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
        "cwe": cwe, "title": f"Root cause: uncaught {kind}", "severity": sev,
        "state": "confirmed", "confidence": 0.9, "detector": "root_cause",
        "site_addr": blame_frame, "function_addr": None,
        "dedup_key": crash_dedup_key(kind, res.fault_pc),
        "evidence": [{"channel": "root-cause", "detail": summary},
                     {"channel": "stack", "detail": " <- ".join(stack[:6])}]})
    ctx.emit("rootcause.done", payload={
        "supported": True, "backend": rt["backend"], "cwe": cwe, "classification": kind,
        "summary": summary, "input_mode": mode, "blame_frame": blame_frame,
        "exploitability": "denial-of-service", "report": report_sha})
    ctx.progress(pct=100, msg=summary[:80])
    return {"output_shas": [report_sha], "output_kind": "root-cause"}


def _sanitizer_report(exe, mode, base_argv, data, scratch, timeout, target) -> str:
    """Re-run a known-crashing input once with sanitizer symbolization on, and return its stderr
    (the AddressSanitizer/UBSan report). Native-arch only; delivered the way the crash was."""
    import subprocess as _sp
    if target.arch and target.arch != sandbox.host_arch():
        return ""                                     # can't natively run a cross-arch build
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "symbolize=1:abort_on_error=1:halt_on_error=1:detect_leaks=0"
    env["UBSAN_OPTIONS"] = "symbolize=1:print_stacktrace=1:halt_on_error=1"
    argv = [str(exe)] + list(base_argv)
    stdin = b""
    if mode == "stdin" or mode == "none":
        stdin = data
    elif mode == "arg":
        # An argv element is NUL-terminated by execve, so the program only ever sees up to the
        # first NUL -- truncate there (matching how the crash was actually delivered). Passing the
        # NUL through would make subprocess.run raise ValueError('embedded null byte') and lose the
        # sanitizer report for a real crash whose input happened to contain a NUL.
        arg = data.split(b"\x00", 1)[0].decode("latin-1", "ignore")
        argv = [str(exe)] + place(list(base_argv), arg)
    elif mode == "file":
        f = scratch / "asan-in.bin"
        f.write_bytes(data)
        argv = [str(exe)] + place(list(base_argv), str(f))
    try:
        r = _sp.run(argv, input=stdin, capture_output=True, timeout=max(4.0, float(timeout)), env=env)
    except (OSError, ValueError, _sp.SubprocessError):
        return ""
    return (r.stderr or b"").decode("latin-1", "ignore")


def root_cause_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("root_cause requires a target_id")
    p = ctx.params or {}
    input_sha = p.get("input_sha")
    if not input_sha:
        raise ValueError("root_cause requires params.input_sha (a crashing input)")
    timeout = float(p.get("timeout", 10))
    mode, base_argv, mode_why = how_to_feed(ctx.conn, target, input_sha, p)

    managed = _MANAGED_FILE_TYPES.get((target.file_type or "").lower())
    if managed:
        return _root_cause_managed(ctx, target, input_sha, base_argv, mode, timeout, managed)

    host = sandbox.host_arch()
    emulated = bool(target.arch and target.arch != host)
    if emulated and not qemu_gdb.supported(target.arch):
        ctx.emit("rootcause.done", payload={"supported": False,
                 "note": f"root-cause for cross-arch {target.arch}: no qemu gdbstub layout "
                         f"(host {host})"})
        ctx.progress(pct=100, msg="root-cause not supported for this cross-arch target")
        return {}

    input_bytes = ctx.content.get_bytes(input_sha)
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / "target.bin"
    ctx.content.stage_target(target, exe.parent, exe.name)
    exe.chmod(0o755)

    # capture the fault: qemu-user gdbstub (cross-arch), else GDB, else the ptrace helper
    gpath = None if emulated else gdb.locate_gdb(p.get("gdb_path"))
    helper_dir = None
    helper = None
    if not emulated and gpath is None:
        helper = materialize_helper()
        helper_dir = helper.parent
    backend = ("qemu-gdbstub" if emulated else "gdb" if gpath is not None else "ptrace")

    def _capture_with(m):
        if emulated:
            return make_qemu_capture(exe, target.arch, m, base_argv, timeout,
                                     endianness=target.endianness,
                                     bits=target.bits)(input_bytes)
        if gpath is not None:
            stdin_file = None
            argv = list(base_argv)
            if m == "stdin":
                stdin_file = str(ctx.scratch() / "stdin.bin")
                (ctx.scratch() / "stdin.bin").write_bytes(input_bytes)
            elif m == "arg":
                argv = place(argv, input_bytes.decode("latin-1"))
            elif m == "file":
                (ctx.scratch() / "input.bin").write_bytes(input_bytes)
                argv = place(argv, str(ctx.scratch() / "input.bin"))
            return gdb.run_gdb(gpath, exe, argv, stdin_file, ctx=ctx, timeout=int(timeout))
        return make_capture(ctx, helper, exe, m, base_argv, timeout, sys.executable)(
            input_bytes)

    # Try the mode we believe in, then the others. A crashing input fed the wrong way looks
    # exactly like an input that does not crash, and reporting that as "no fault reproduced"
    # turns a wrong setup into what reads as a clean negative result.
    order = [mode] + [m for m in MODES if m != mode]
    tried = []
    for m in order:
        ctx.progress(msg=f"capturing fault under {backend} ({m})")
        cap = _capture_with(m)
        tried.append(m)
        if cap.get("ok") and cap.get("signal_name"):
            if m != mode:
                mode_why = f"{mode_why}, but it only faulted via {m}"
            mode = m
            break

    try:
        if not cap.get("ok") or not cap.get("signal_name"):
            ctx.emit("rootcause.done", payload={"supported": True, "backend": backend,
                     "input_modes_tried": tried,
                     "note": ("input did not fault under the debugger via any of "
                              + ", ".join(tried) + ": " + str(cap.get("reason", "")))})
            ctx.progress(pct=100, msg="no fault reproduced (tried %s)" % ", ".join(tried))
            return {}

        functions = FunctionDAO(ctx.conn).list_by_target(target.id)
        call_edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
        # Exclude the crash rows themselves: a previous root_cause run leaves a finding at
        # the faulting address, which would otherwise attribute the crash to itself.
        findings = [f for f in FindingDAO(ctx.conn).list_by_target(target.id)
                    if not (f.dedup_key or "").startswith("dynamic-crash:")]
        sites_by_finding = FindingDAO(ctx.conn).sites_by_target(target.id)
        elf_entry = None
        try:
            elf_entry = elf.parse(target_bytes).entry
        except Exception:
            pass                                  # not an ELF, or unreadable: match absolutely
        report = rootcause.analyze(cap, functions, call_edges, findings,
                                   str(exe), target.arch or host, sites_by_finding, elf_entry)
        report["backend"] = backend

        # Sanitizer build (the source-code path): a bare SIGABRT is uninformative, but the
        # sanitizer's own report names the exact defect and (symbolized) the source line. Re-run
        # the crashing input once with symbolization on, parse it, and let it OVERRIDE the
        # generic classification -- turning "detected-corruption-abort" into e.g.
        # "heap-buffer-overflow at heap_ovf.c:8". Safe: the input is known to abort immediately.
        from ..fuzz.aflpp import is_sanitizer_build
        if is_sanitizer_build(target_bytes):
            try:
                asan_text = _sanitizer_report(exe, mode, base_argv, input_bytes,
                                              ctx.scratch(), timeout, target)
                parsed = rootcause.parse_asan_report(asan_text)
            except Exception:
                parsed = None
            if parsed:
                report["classification"] = parsed
                report["sanitizer_report"] = asan_text[-1200:]
                report["summary"] = parsed["detail"]
                # exploitability is re-rated against the specific class where it helps.
                report["exploitability"]["reasons"] = (
                    [f"sanitizer-confirmed {parsed['class'].replace('-', ' ')}"
                     + (f" at {parsed['source']}" if parsed.get("source") else "")]
                    + list(report["exploitability"].get("reasons", [])))
                # ...and the end-effect list is re-derived from the specific ASan class, so a
                # sanitizer-confirmed use-after-free reads as RCE-capable, not just "a crash".
                from . import exploitability as _expl
                report["exploitability"]["effects"] = _expl.effects(parsed, cap)
        elif not emulated:
            # Stripped / non-sanitizer NATIVE binary: the generic classification is signal-based
            # ("a SIGSEGV somewhere"). Valgrind memcheck names the exact heap defect -- OOB
            # read/write, use-after-free, double-free -- on a binary with no source ASan, so re-run
            # the crashing input once under memcheck and let a concrete verdict SHARPEN the
            # classification the same way the sanitizer report does for the source path. Declines
            # silently (leaves the generic verdict) when valgrind is absent or finds nothing.
            _VG_ASAN = {"heap-oob-write": "heap-buffer-overflow",
                        "heap-oob-read": "heap-buffer-overflow",
                        "use-after-free": "heap-use-after-free", "double-free": "double-free"}
            try:
                from ..dynamic import memoracle
                vg = memoracle.valgrind_triage(exe, input_bytes, mode=mode, base_argv=base_argv,
                                               timeout=min(120.0, max(30.0, timeout * 12)))
            except Exception:
                vg = None
            if vg:
                klass = _VG_ASAN.get(vg["kind"], vg["kind"])
                report["classification"] = {"cwe": vg["cwe"], "class": klass,
                                            "severity": vg["severity"],
                                            "detail": f"valgrind memcheck: {vg['detail']}"}
                report["memcheck"] = vg
                report["summary"] = f"valgrind-confirmed {vg['kind'].replace('-', ' ')}"
                report["exploitability"]["reasons"] = (
                    [f"valgrind-confirmed {vg['kind'].replace('-', ' ')}"]
                    + list(report["exploitability"].get("reasons", [])))
                from . import exploitability as _expl
                report["exploitability"]["effects"] = _expl.effects(report["classification"], cap)

        report_sha = ctx.put_artifact("root-cause", data=json.dumps(report, indent=2,
                                      sort_keys=True, default=str).encode(),
                                      meta={"cwe": report["classification"]["cwe"]})
        # attach root-cause + exploitability evidence to the crash finding
        v = report["classification"]
        ex = report["exploitability"]
        ex_line = (f"exploitability: {ex['rating']} ({ex['score']}/100) -- "
                   + "; ".join(ex["reasons"]))
        # Headline the finding with the END EFFECT the defect can reach, not just "a crash":
        # the most severe achievable effect and whether the PoC has demonstrated it yet.
        from . import exploitability as _expl
        effs = ex.get("effects") or _expl.effects(v, cap)
        # The denial of service IS demonstrated -- its proof is the crashing input itself.
        for e in effs:
            if e["kind"] == "dos":
                e["proof"] = {"type": "input", "sha": input_sha,
                              "note": "the crashing input reliably terminates the process"}
        prim_eff = _expl.primary_effect(effs)
        eff_title = (f"{prim_eff['title']}"
                     + (" (demonstrated)" if prim_eff["status"] == "demonstrated"
                        else " (potential)")) if prim_eff else f"Root cause: {v['class']}"
        crash_fn = (report["slice"].get("crash_function") or {})
        fdao = FindingDAO(ctx.conn)
        # from the run that FOUND the input, not from this capture, so every stage that files
        # a crash finding derives the same key and they merge instead of multiplying
        _fault_pc = DynResultDAO(ctx.conn).fault_pc_for(target.id, input_sha)
        fdao.upsert(target.id, target.case_id, {
            "cwe": v["cwe"], "title": f"{eff_title}: {v['class']}",
            "severity": v["severity"],
            "state": "confirmed", "confidence": 0.9, "detector": "root_cause",
            # The crash is now locatable, and the key carries WHERE it faulted so two
            # defects that both segfault stay two findings. The address comes from the run
            # that found the input, not from this capture, so every stage derives the same key.
            "site_addr": _hex(crash_fn.get("static_addr")),
            "function_addr": crash_fn.get("func_addr"),
            "dedup_key": crash_dedup_key(cap["signal_name"], _fault_pc),
            # root_cause is the authoritative classifier: its specific class (from the debugger,
            # and on a sanitizer build from ASan's own report) replaces the generic signal-derived
            # class the fuzz/dynamic stage first filed the crash under.
            "authoritative": True,
            "evidence": [{"channel": "root-cause", "detail": report["summary"]},
                         {"channel": "exploitability", "detail": ex_line},
                         {"channel": "effects", "detail": json.dumps(effs)}]})

        # Attribute the crash to the static findings it actually demonstrates. Without this a
        # verified PoC sits beside the static inventory instead of ranking it: on jhead, one
        # crash next to 38 unknown copy sites, several in the faulting function.
        by_id = {f.id: f for f in findings}
        promoted = 0
        for a in report["slice"].get("attributed") or []:
            f = by_id.get(a["finding_id"])
            if f is None:
                continue
            fdao.upsert(target.id, target.case_id,
                        rootcause.attribution_upsert(f, a, cap["signal_name"]))
            promoted += a["tier"] == "fault-site"

        ctx.emit("rootcause.done", payload={
            "supported": True, "backend": backend, "cwe": v["cwe"],
            "classification": v["class"], "summary": report["summary"],
            "input_mode": mode, "input_mode_why": mode_why,
            "attributed": len(report["slice"].get("attributed") or []),
            "poc_backed": promoted,
            "exploitability": ex["rating"], "exploit_score": ex["score"],
            "reachable_from_source": report["slice"]["reachable_from_source"],
            "report": report_sha})
        ctx.progress(pct=100, msg=report["summary"][:80])
        return {"output_shas": [report_sha], "output_kind": "root-cause"}
    finally:
        if helper_dir is not None:
            shutil.rmtree(helper_dir, ignore_errors=True)


def register() -> None:
    register_stage(ROOT_CAUSE_STAGE, root_cause_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_root_cause(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, ROOT_CAUSE_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
