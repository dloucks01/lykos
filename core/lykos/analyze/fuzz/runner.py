"""Shared target-invocation helper for the fuzzing stages."""
from __future__ import annotations

import logging

from ... import observe
from ..dynamic import sandbox
from ..invocation import INPUT_PLACEHOLDER, OUTPUT_PLACEHOLDER

_log = logging.getLogger(__name__)


def _sub_output(argv, workfile):
    """Replace the converter OUTPUT placeholder with a writable scratch path next to the input, so
    `tool [opts] INPUT OUTPUT` targets (tiffcp, ffmpeg) run instead of printing usage and exiting."""
    if OUTPUT_PLACEHOLDER not in argv:
        return argv
    outp = "lykos.out"  # relative -> writable cwd
    return [outp if a == OUTPUT_PLACEHOLDER else a for a in argv]


def place(argv, carrier: str) -> list:
    """Put the input carrier where argv says it goes -- the one definition of the `@@` rule.

    Every replay stage used to hand-roll `argv + [path]`, which silently broke the whole PoC
    ladder for any target that takes its input behind a flag. The recorded prefix for such a
    target is `["-c", "@@"]`, so appending produced `target -c @@ /tmp/input.bin`: the program
    opens a file literally named `@@`, fails, does not crash, and root_cause, build_poc,
    primitive and the rest all filed "the input did not fault" -- a wrong invocation wearing
    the clothes of a clean negative, in eight places at once.
    """
    out = [str(a) for a in argv or []]
    if INPUT_PLACEHOLDER in out:
        return [carrier if a == INPUT_PLACEHOLDER else a for a in out]
    return out + [carrier]


def invocation(mode, workfile, d: bytes, base_argv=()):
    """(argv, stdin) for one execution, with the input placed where the TARGET expects it.

    `@@` in `base_argv` is replaced by the thing carrying the input; without it the carrier is
    appended, which is the old behaviour. The placeholder is what makes a real service
    invocable at all: `-c @@` puts the config path immediately after its flag, where appending
    would produce `-c -v <path>` the moment any other flag was present, and `-c` would eat the
    flag instead of the file.
    """
    argv = _sub_output([str(a) for a in base_argv or []], workfile)
    if mode == "arg":
        carrier = d.decode("latin-1")
    elif mode == "file":
        workfile.write_bytes(d)
        carrier = str(workfile)
    else:                                               # stdin
        # `-c @@` and stdin are not incompatible: /dev/stdin IS the path of the input. Leaving
        # a literal `@@` in argv would have the program open a file of that name instead.
        if INPUT_PLACEHOLDER in argv:
            return place(argv, "/dev/stdin"), d
        return argv, d
    return place(argv, carrier), b""


def run_input(exe, mode, workfile, timeout, arch, d: bytes, *, endianness=None, bits=None,
              base_argv=(), blocks=(), guard_page: bool = False):
    """One execution. `base_argv` is the option prefix the campaign is running under: a crash
    found with an option has to be re-run with it to mean anything. `blocks` asks for coverage,
    which on an emulated target comes from qemu's own block log. `guard_page` asks for the
    guard-page heap allocator, which turns a silent heap out-of-bounds into a SIGSEGV; the
    sandbox decides whether it can apply and records in the isolation tag whether it did."""
    argv, stdin = invocation(mode, workfile, d, base_argv)
    return argv, sandbox.run(exe, argv=argv, stdin=stdin, timeout=timeout, arch=arch,
                             endianness=endianness, bits=bits, blocks=blocks,
                             guard_page=guard_page)


def run_input_prompted(exe, d: bytes, *, timeout: float, fields=(), idle: float = 0.08):
    """One execution of a PROMPT-DRIVEN target: the blob's LINES go in one per prompt.

    A program that reads its fields with separate `read(0, buf, N)` calls cannot be fed one blob.
    `read` returns whatever is AVAILABLE, so a bulk write hands the whole blob to field one --
    which then holds the bytes meant for field two, and field two reaches EOF. Measured on the
    HTB target `replaceme`: 63,234 executions, every one rejected at the first gate with
    "Missing 's/' at the beginning", because the sed expression belonging to field two arrived
    inside field one. The same bytes delivered one line per prompt reach the parser, and the
    192-byte stack buffer behind it overflows.

    This is the delivery `heap_discover._op_writes` already does for a numbered MENU, for exactly
    the same reason, applied to a linear protocol -- a menu minus the dispatch.

    Returns `(argv, RunResult)` like `run_input`, so it drops into `fuzz_campaign` as its
    `run_fn`. Costs a drain per field (~`idle` seconds each), so it is only worth choosing when
    the target really is prompt-driven; `fuzz_campaign` disables input batching for any runner
    that is not `run_input`, which is correct here -- these executions cannot be batched.
    """
    import selectors
    import subprocess
    import time
    from pathlib import Path

    from ..dynamic import heap_discover
    from . import menu

    t0 = time.monotonic()
    deadline = t0 + max(0.5, float(timeout))
    proc, out, sel = None, bytearray(), None
    # Say what containment this run really had: `_spawn_menu` wraps in bubblewrap only when it
    # is usable, and the label used to claim "bwrap+netns" either way. "prompted" stays in it --
    # the replay paths look for that word to re-deliver one field per prompt.
    iso = ("bwrap+netns" if sandbox._bwrap_usable() else "rlimits-only") + "/prompted"
    try:
        proc = heap_discover._spawn_menu(Path(exe).parent, Path(exe))
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)

        def _pump():
            chunk, alive = menu._drain(proc, sel, idle=idle,
                                       deadline=min(deadline, time.monotonic() + idle * 6))
            out.extend(chunk.encode("latin-1", "ignore"))
            return alive

        alive = _pump()                                  # the first prompt
        # One line per prompt. A blob with FEWER lines than the target has fields simply stops
        # feeding -- stdin is then closed, which is what makes the target proceed or exit rather
        # than block until the deadline.
        # `capture.paced_chunks` is the ONE definition of this split, because the ptrace capture
        # has to pace identically: a crash found with one split and replayed with another is a
        # crash that does not reproduce.
        from ..poc.capture import paced_chunks
        for chunk in paced_chunks(d):
            if not alive or time.monotonic() >= deadline:
                break
            try:
                proc.stdin.write(chunk)
                proc.stdin.flush()
            except (OSError, ValueError):                # the target is gone: that is a result
                break
            alive = _pump()
        try:
            proc.stdin.close()
        except (OSError, ValueError):
            pass
        rc, timed_out = None, False
        try:
            rc = proc.wait(timeout=max(0.2, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            # Kill BEFORE reading what is left: a bare `stdout.read()` on a process that is still
            # running blocks until it exits -- a target spinning in a loop never does, and the
            # per-execution timeout this path promises was not enforced at all.
            from . import menu as _m
            _m._kill(proc, close=False)
        if rc is None and not timed_out:
            rc = proc.poll()
        out.extend(_read_rest(proc, sel, budget=0.5))   # whatever it said on the way out
        crashed, sig, signame, code = sandbox.classify_rc(rc)
        if not crashed and not timed_out and sandbox._exec_failed(rc, bytes(out[:4096])):
            # stderr is merged into stdout here; a loader that refused the image ("error while
            # loading shared libraries", exit 127) means nothing ran -- the same `/not-runnable`
            # verdict `sandbox.run` gives, never a clean exit.
            iso += "/not-runnable"
        return [], sandbox.RunResult(
            isolation=iso, crashed=crashed, timed_out=timed_out,
            exit_code=code, signal=sig, signal_name=signame, stdout=bytes(out[:65536]),
            duration_ms=int((time.monotonic() - t0) * 1000),
            note=f"delivered {len(d.split(chr(10).encode()))} field(s) one per prompt")
    except Exception as e:                               # noqa: BLE001 -- a failed run is a run
        # ...but only once the process exists. A spawn that raised ran NOTHING, and a result
        # with crashed=False and no suffix read as a clean execution.
        return [], sandbox.RunResult(isolation=iso + ("" if proc is not None
                                                      else "/not-runnable"),
                                     stdout=bytes(out[:65536]),
                                     note=f"prompted delivery failed: {type(e).__name__}: {e}")
    finally:
        if proc is not None:
            try:
                from . import menu as _m
                _m._kill(proc)
            except Exception:
                observe.absorbed(_log, "continuing")


def _read_rest(proc, sel, *, budget: float) -> bytes:
    """What is left on the target's stdout, read WITHOUT blocking past `budget` seconds. A
    descendant that outlived the target (an unwrapped run, a daemonised child) can hold the pipe
    open forever, and a blocking read() would wait on it."""
    import time
    if proc is None or proc.stdout is None or sel is None:
        return b""
    buf = bytearray()
    end = time.monotonic() + budget
    while time.monotonic() < end and len(buf) < 65536:
        try:
            ready = sel.select(max(0.0, min(0.05, end - time.monotonic())))
            if not ready:
                if proc.poll() is not None:
                    break                   # it is gone and nothing more is pending
                continue
            chunk = proc.stdout.read1(65536)
        except (OSError, ValueError):
            break
        if not chunk:
            break                           # EOF
        buf += chunk
    return bytes(buf)


def prompted_runner(fields=(), *, idle: float = 0.08):
    """`run_fn` for `fuzz_campaign` that delivers one field per prompt. Ignores `mode` (a prompt
    protocol is stdin by construction) and the coverage/arch keywords, which the interactive
    path cannot carry."""
    def _run(exe, mode, workfile, timeout, arch, d, **_kw):
        return run_input_prompted(exe, d, timeout=timeout, fields=fields, idle=idle)
    return _run
