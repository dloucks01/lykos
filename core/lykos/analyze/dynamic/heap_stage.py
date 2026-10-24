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

import logging
import os
import re
import secrets
import subprocess
import tempfile
from pathlib import Path

from ... import observe
from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from .. import substrate
from ..fuzz.runner import place
from ..poc.capture import how_to_feed
from . import sandbox

_log = logging.getLogger(__name__)

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
        observe.absorbed(_log, "falling back")
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


def _open_report():
    """A report channel the target cannot reach by PATH: a file in a fresh private directory
    OUTSIDE the target's (writable) workdir -- under the sandbox's tmpfs /tmp it does not exist at
    all -- handed to the shim as an inherited WRITE descriptor. The file is then made write-only
    (0200) and its directory search-only (0100), so a target that recovers the path from
    /proc/self/fd can neither read the report back (and lift the nonce from a genuine line) nor
    create anything beside it. Returns (dir, write_fd, read_fd)."""
    d = Path(tempfile.mkdtemp(prefix="lykos-heaprep-"))
    path = d / "heap.jsonl"
    wfd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND | os.O_EXCL, 0o600)
    rfd = os.open(path, os.O_RDONLY)
    os.chmod(path, 0o200)
    os.chmod(d, 0o100)
    return d, wfd, rfd


def _read_fd(fd: int, cap: int = 4 << 20) -> bytes:
    out = bytearray()
    while len(out) < cap:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        out += chunk
    return bytes(out)


#: One authenticated shim line. Matched ANYWHERE in the stream rather than per line: a target that
#: writes a partial line to the report descriptor must not be able to glue a genuine line onto its
#: own junk and so suppress it.
_ERR_RE = re.compile(rb'\{"error":"([a-z-]{1,32})","addr":"0x([0-9a-f]{1,16})","size":([0-9]{1,20}),'
                     rb'"func":"([a-z_]{0,16})","n":"([0-9a-f]{1,64})"\}')
_LOADED_RE = re.compile(rb'\{"loaded":1,"n":"([0-9a-f]{1,64})"\}')


def parse_report(raw: bytes, nonce: str) -> tuple:
    """(loaded, errors, forged) from the raw report bytes: only lines carrying THIS run's nonce
    count. `forged` counts heap-error-shaped lines that did not -- written by the target, not the
    shim -- which are ignored and reported as such."""
    n = nonce.encode()
    loaded = any(m.group(1) == n for m in _LOADED_RE.finditer(raw or b""))
    errors, forged = [], 0
    for m in _ERR_RE.finditer(raw or b""):
        if m.group(5) != n:
            forged += 1
            continue
        errors.append({"error": m.group(1).decode(), "addr": "0x" + m.group(2).decode(),
                       "size": int(m.group(3)), "func": m.group(4).decode()})
    # an error-looking object with NO nonce field at all is a forgery too
    forged += max(0, (raw or b"").count(b'"error"') - len(errors) - forged)
    return loaded, errors, forged


def heap_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("heap_check requires a target_id")
    p = ctx.params or {}
    why = substrate.native_only_reason(target.file_type, "the guard-page heap checker")
    if why:
        ctx.emit("heap.done", payload={"ok": False, "supported": False, "note": why})
        ctx.progress(pct=100, msg=why[:90])
        return {}
    host = sandbox.host_arch()
    why = substrate.foreign_cpu_reason(target.arch, target.file_type, host,
                                       "the guard-page heap checker")
    if why:
        ctx.emit("heap.done", payload={"ok": False, "supported": False,
                 "note": why + " A per-arch shim under qemu is future work."})
        ctx.progress(pct=100, msg="heap check not supported for this cross-arch target")
        return {}

    # mask the case store inside the sandbox; the target is copied out to workdir before it runs.
    sandbox.protect_dir(getattr(ctx.content, "root", None))
    workdir = Path(tempfile.mkdtemp(prefix="lykos-heap-"))
    report_fds: list = []                    # [dir, write fd, read fd] once opened; closed in finally
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
        # LD_PRELOAD is read by the dynamic loader, so a statically linked target never loads the
        # shim -- and would be handed the run's nonce in its environment, unerased. Decided from
        # the ELF itself (no PT_INTERP) BEFORE anything runs: nothing was checked, which is not
        # the same as nothing found.
        if not sandbox._interp_of(exe):
            note = ("this target is statically linked, so the LD_PRELOAD guard-page allocator "
                    "cannot load into it -- nothing was checked, which is not the same as nothing "
                    "found. Use a dynamically-linked build.")
            ctx.emit("heap.done", payload={"ok": False, "applicable": False, "errors": 0,
                     "findings": 0, "kinds": [], "note": note})
            ctx.progress(pct=100, msg="heap check did not run: statically linked target")
            return {"metrics": {"applicable": False}}

        mode = how_to_feed(ctx.conn, target, p.get("input_sha"), p, content=ctx.content)[0]
        argv = list(p.get("argv") or [])
        timeout = float(p.get("timeout", 15))
        data = ctx.content.get_bytes(p["input_sha"]) if p.get("input_sha") else b"A" * 128
        run_argv = argv + [data.decode("latin-1")] if (mode == "arg" and data) else argv
        stdin = data if mode == "stdin" else b""
        if mode == "file":
            (workdir / "input.bin").write_bytes(data)
            run_argv = place(argv, str(workdir / "input.bin"))

        # The REPORT IS EVIDENCE, and it used to live in the workdir the target can write: any
        # target could append `{"error":"use-after-free",...}` and have a critical CWE-416 filed
        # against itself (or bury a real one). Now: an inherited descriptor to a file outside
        # anything the target can reach by path, and a per-run nonce only the shim in the
        # target's process reads, before main() -- a line without it is ignored (see
        # `parse_report`).
        nonce = secrets.token_hex(16)
        repdir, wfd, rfd = _open_report()
        report_fds[:] = [repdir, wfd, rfd]
        # The nonce goes over a PIPE, never the environment: bwrap's init (pid 1 of the sandbox)
        # keeps the environment it was started with, and the target can read /proc/1/environ.
        # The shim's read consumes the pipe, so afterwards the nonce exists only inside the shim.
        nr, nw = os.pipe()
        os.write(nw, nonce.encode())
        os.close(nw)
        report_fds.append(nr)
        # Minimal env for hostile code: the shim needs LD_PRELOAD + its report fd + the nonce;
        # the host environment is NOT forwarded (it can carry credentials/tokens). Keep only
        # locale so locale-sensitive parsing behaves as it would natively.
        # LYKOS_HEAP_TARGET: only the target's own process takes the nonce, never a launcher the
        # sandbox execs it through (setarch), which loads the shim too.
        env = {"LD_PRELOAD": str(so), "LYKOS_HEAP_FD": str(wfd), "LYKOS_HEAP_NONCE_FD": str(nr),
               "LYKOS_HEAP_TARGET": os.path.realpath(exe),
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
        # the shim .so and the input, and is bound WRITABLE (the report is NOT in it). On timeout
        # run_reaped kills the whole process group / namespace, so no forked child is orphaned.
        # AS is deliberately NOT capped: the guard-page allocator maps a guard region per
        # allocation, and an address-space ceiling would make its mmaps fail and mask real bugs.
        inner = [str(exe), *run_argv]
        cmd = sandbox.isolate_prefix(str(workdir), net=False, rw_binds=[str(workdir)]) + inner
        timed_out = False
        try:
            sandbox.run_reaped(cmd, input=stdin, capture_output=True, timeout=timeout,
                               env=env, cwd=str(workdir), pass_fds=(wfd, nr),
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

        os.close(wfd)
        report_fds[1] = None
        raw = _read_fd(rfd)
        loaded, errors, forged = parse_report(raw, nonce)
        if forged:
            ctx.emit("heap.forged", level="warn", payload={
                "lines": forged, "note": (
                    f"{forged} heap-error line(s) in the report did not carry this run's nonce -- "
                    f"written by the target, not by the guard-page allocator -- and were ignored")})
        # The shim's constructor writes an authenticated `loaded` line the instant it loads, so
        # its ABSENCE proves the shim never loaded -- the target did not execute under
        # instrumentation (it failed to exec inside the sandbox). That is NOT a clean bill of
        # health: nothing was checked, which is not the same as nothing found.
        if not loaded:
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

        # The authenticated `loaded` line is there, so the shim loaded and the target DID run
        # under instrumentation. (The "never loaded" case is handled above.)
        note = None
        if timed_out:
            note = ("the target was still running when the timeout expired; the heap inventory "
                    "may be incomplete")
        elif not errors:
            note = "no heap errors observed on this input (try other inputs)"
        ctx.emit("heap.done", payload={"ok": True, "errors": len(errors), "findings": findings,
                 "kinds": sorted({e.get("error") for e in errors if e.get("error") in _MAP}),
                 "timed_out": timed_out, "forged_ignored": forged, "note": note})
        ctx.progress(pct=100, msg=f"{len(errors)} heap error(s), {findings} finding(s)")
        return {}
    finally:
        import shutil
        if report_fds:
            _close_report(*report_fds)
        shutil.rmtree(workdir, ignore_errors=True)


def _close_report(repdir, wfd, rfd, *more) -> None:
    import shutil
    for fd in (wfd, rfd, *more):
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    try:
        os.chmod(repdir, 0o700)
    except OSError:
        pass
    shutil.rmtree(repdir, ignore_errors=True)


def register() -> None:
    register_stage(HEAP_STAGE, heap_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_heap_check(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, HEAP_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
