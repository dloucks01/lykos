"""Phase 6 — the `heap_check` stage: detect heap-memory errors the crash-only pipeline misses.

Runs the target with an LD_PRELOAD guard-page allocator shim (heappoison.c) that makes heap
bugs fault at the exact offending access and reports them structurally:
  * use-after-free (CWE-416), double-free (CWE-415), invalid/wild free (CWE-590),
  * heap buffer overflow (CWE-122), and -- opt-in -- memory leaks (CWE-401).

These are silent corruptions that usually don't SIGSEGV on their own, so fuzzing-by-crash never
sees them. Deterministic; native-arch only (the shim is host-arch, and LD_PRELOAD needs a
dynamically-linked target). Cross-arch via a per-arch shim under qemu is future work (doc 20).
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..fuzz.runner import place
from ..poc.capture import how_to_feed
from . import sandbox

HEAP_STAGE = "heap_check"
TOOL = "heap"
TOOL_VERSION = "heap-1"
_SHIM_SRC = "heappoison.c"

# shim error kind -> (cwe, severity, title)
_MAP = {
    "use-after-free":       ("CWE-416", "critical", "Use-after-free"),
    "double-free":          ("CWE-415", "high", "Double free"),
    "invalid-free":         ("CWE-590", "high", "Free of a non-heap / invalid pointer"),
    "heap-buffer-overflow": ("CWE-122", "critical", "Heap buffer overflow"),
    "memory-leak":          ("CWE-401", "low", "Memory leak"),
}


def _shim_source() -> bytes:
    try:
        from importlib import resources
        return (resources.files("lykos.analyze.dynamic") / _SHIM_SRC).read_bytes()
    except Exception:
        return (Path(__file__).parent / _SHIM_SRC).read_bytes()


def _build_shim(workdir: Path):
    """Compile the LD_PRELOAD shim for the host. Returns the .so path or None (no cc)."""
    import shutil
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        return None
    src = workdir / _SHIM_SRC
    src.write_bytes(_shim_source())
    so = workdir / "heappoison.so"
    r = subprocess.run([cc, "-shared", "-fPIC", "-O2", str(src), "-o", str(so), "-ldl"],
                       capture_output=True)
    return so if r.returncode == 0 and so.exists() else None


def heap_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("heap_check requires a target_id")
    p = ctx.params or {}
    host = sandbox.host_arch()
    if target.arch and target.arch != host:
        ctx.emit("heap.done", payload={"ok": False, "supported": False,
                 "note": f"heap check is native-arch only (target {target.arch}, host {host}); "
                         f"a per-arch shim under qemu is future work"})
        ctx.progress(pct=100, msg="heap check not supported for this cross-arch target")
        return {}

    # mask the case store inside the sandbox; the target is copied out to workdir before it runs.
    sandbox.protect_dir(getattr(ctx.content, "root", None))
    workdir = Path(tempfile.mkdtemp(prefix="lykos-heap-"))
    try:
        so = _build_shim(workdir)
        if not so:
            ctx.emit("heap.done", payload={"ok": False, "note": "no C compiler to build the "
                     "heap shim (cc/gcc/clang)"})
            ctx.progress(pct=100, msg="no compiler for the heap shim")
            return {}

        exe = workdir / "target.bin"
        ctx.content.stage_target(target, exe.parent, exe.name)
        os.chmod(exe, 0o755)

        mode = how_to_feed(ctx.conn, target, p.get("input_sha"), p)[0]
        argv = list(p.get("argv") or [])
        timeout = float(p.get("timeout", 15))
        data = ctx.content.get_bytes(p["input_sha"]) if p.get("input_sha") else b"A" * 128
        run_argv = argv + [data.decode("latin-1")] if (mode == "arg" and data) else argv
        stdin = data if mode == "stdin" else b""
        if mode == "file":
            (workdir / "input.bin").write_bytes(data)
            run_argv = place(argv, str(workdir / "input.bin"))

        report = workdir / "heap.json"
        # Minimal env for hostile code: the shim needs LD_PRELOAD + its report path; the host
        # environment is NOT forwarded (it can carry credentials/tokens). Keep only locale so
        # locale-sensitive parsing behaves as it would natively.
        env = {"LD_PRELOAD": str(so), "LYKOS_HEAP_REPORT": str(report),
               "PATH": "/usr/bin:/bin", "HOME": "/tmp"}
        for k in ("LANG", "LC_ALL", "LC_CTYPE", "TZ"):
            if k in os.environ:
                env[k] = os.environ[k]
        if p.get("leaks"):
            env["LYKOS_HEAP_LEAKS"] = "1"

        ctx.progress(msg="running under the guard-page heap allocator")
        # Detonate the (hostile) target with real containment: bwrap read-only root with
        # /home,/root masked (net unshared -- the shim needs no network) + rlimits so a fork
        # bomb / disk fill / runaway CPU cannot take the host down. The workdir holds the target,
        # the shim .so, the input and the shim's JSON report, so it is bound WRITABLE. On timeout
        # run_reaped kills the whole process group / namespace, so no forked child is orphaned.
        # AS is deliberately NOT capped: the guard-page allocator maps a guard region per
        # allocation, and an address-space ceiling would make its mmaps fail and mask real bugs.
        inner = [str(exe), *run_argv]
        cmd = sandbox.isolate_prefix(str(workdir), net=False, rw_binds=[str(workdir)]) + inner
        timed_out = False
        try:
            sandbox.run_reaped(cmd, input=stdin, capture_output=True, timeout=timeout,
                               env=env, cwd=str(workdir),
                               preexec_fn=sandbox._rlimits(2048, int(timeout) + 5, set_as=False))
        except subprocess.TimeoutExpired:
            timed_out = True
        except OSError as e:
            # Reachable only on the unwrapped fallback (bwrap unusable): a non-ELF target hits
            # execve's "Exec format error". Give the honest, actionable answer, not the errno.
            note = f"could not run target: {e}"
            if e.errno == 8:
                note = (f"this target is {(target.file_type or 'not an ELF').upper()}, and the "
                        f"guard-page heap checker is a Linux/ELF LD_PRELOAD shim -- it cannot "
                        f"load into it. Nothing was checked.")
            ctx.emit("heap.done", payload={"ok": False, "applicable": False, "note": note})
            return {}

        # The shim's constructor opens (O_CREAT) the report the instant it loads, so the report's
        # ABSENCE proves the shim never loaded -- the target did not execute under instrumentation
        # (statically linked, or it failed to exec inside the sandbox). That is NOT a clean bill
        # of health: nothing was checked, which is not the same as nothing found.
        if not report.exists():
            static = (target.linking or "").lower() == "static"
            note = ("this target is statically linked, so the LD_PRELOAD guard-page allocator "
                    "never loaded -- nothing was checked, which is not the same as nothing "
                    "found. Use a dynamically-linked build.") if static else (
                    "the guard-page allocator never loaded (the target did not execute under it"
                    + (" before the timeout" if timed_out else "") + ") -- nothing was checked, "
                    "which is not the same as nothing found.")
            ctx.emit("heap.done", payload={"ok": False, "applicable": False, "errors": 0,
                     "findings": 0, "kinds": [], "note": note})
            ctx.progress(pct=100, msg="heap check did not run: instrumentation never loaded")
            return {"metrics": {"applicable": False}}

        errors = []
        for line in report.read_text("latin-1").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                errors.append(json.loads(line))
            except ValueError:
                pass

        fd = FindingDAO(ctx.conn)
        seen, findings = set(), 0
        for e in errors:
            kind = e.get("error")
            if kind not in _MAP:
                continue
            cwe, sev, title = _MAP[kind]
            key = f"{cwe}:heap:{kind}:{e.get('size')}"    # dedup identical reports
            if key in seen:
                continue
            seen.add(key)
            addr = e.get("addr")
            detail = (f"{title} observed at runtime under the guard-page allocator "
                      f"(access/site {addr}, {e.get('size')}-byte allocation)")
            fd.upsert(target.id, target.case_id, {
                "cwe": cwe, "title": title, "severity": sev, "detector": "heap_monitor",
                "evidence": [{"channel": "heap-monitor", "detail": detail}],
                "function_addr": None, "site_addr": None,
                "dedup_key": key, "state": "corroborated", "confidence": 0.9})
            findings += 1

        # The report exists, so the shim loaded and the target DID run under instrumentation.
        # (The "statically linked / never loaded" case is handled above by report absence.)
        note = None
        if timed_out:
            note = ("the target was still running when the timeout expired; the heap inventory "
                    "may be incomplete")
        elif not errors:
            note = "no heap errors observed on this input (try other inputs)"
        ctx.emit("heap.done", payload={"ok": True, "errors": len(errors), "findings": findings,
                 "kinds": sorted({e.get("error") for e in errors if e.get("error") in _MAP}),
                 "timed_out": timed_out, "note": note})
        ctx.progress(pct=100, msg=f"{len(errors)} heap error(s), {findings} finding(s)")
        return {}
    finally:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)


def register() -> None:
    register_stage(HEAP_STAGE, heap_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_heap_check(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, HEAP_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
