"""Whole-system detonation + cross-boundary blame (doc 17.3).

Runs a component *set* together in one isolation domain so real IPC/linking happens: the
service components are launched first (a server binds, a FIFO reader waits), then the entry
component receives the test input and does its real work -- talking to the services over
their actual channels. If any component crashes, the crash is attributed back to the input
that entered the entry component (**cross-boundary blame**): input into A crashes B.

This is process-group detonation under the rlimits domain (shared fs/loopback so real IPC
works) -- NOT full-system QEMU/microVM snapshotting, which needs bundled VM images and is the
future isolated path (doc 17.3). Native-arch (or per-arch qemu-user) only.
"""
from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from ..dynamic import sandbox


@dataclass
class CompOutcome:
    target_id: Optional[str]
    filename: str
    role: str                      # "service" | "entry"
    crashed: bool = False
    signal: Optional[int] = None
    signal_name: Optional[str] = None
    exit_code: Optional[int] = None
    timed_out: bool = False


@dataclass
class DetonateResult:
    outcomes: list = field(default_factory=list)
    blame: Optional[dict] = None
    isolation: str = "rlimits-only(system)"
    note: Optional[str] = None

    @property
    def cross_boundary(self) -> bool:
        return bool(self.blame and self.blame.get("cross_boundary"))


def _wait_ready(channel, deadline):
    """Give services a moment to start listening (poll the socket path/port if we know it)."""
    if not channel:
        time.sleep(0.3)
        return
    fam, key = channel.get("family"), channel.get("key")
    if fam == "unix" and key:
        while not os.path.exists(key) and time.time() < deadline:
            time.sleep(0.02)
    elif fam in ("tcp", "socket") and key:
        host, _, port = str(key).rpartition(":")
        host = host or "127.0.0.1"
        while time.time() < deadline:
            s = socket.socket()
            try:
                s.settimeout(0.1)
                s.connect((host, int(port)))
                s.close()
                return
            except OSError:
                s.close()
                time.sleep(0.03)
    else:
        time.sleep(0.3)


def _emu_prefix(arch, host):
    if arch and host and arch != host:
        emu = sandbox._qemu_for(arch)
        return ([emu], None) if emu else (None, f"no qemu-user for {arch} on {host}")
    return ([], None)


def _run_once(*, emu, services, entry, channel, entry_input, timeout, readiness, grace,
              preexec) -> list:
    """One launch of the whole component set with `entry_input` fed to the entry on stdin.
    Returns the CompOutcome list; every process it starts is reaped before it returns."""
    procs = []       # (comp, Popen)

    def _launch(comp, stdin_pipe):
        cmd = emu + [str(comp["exe"])] + [str(a) for a in comp.get("argv", [])]
        return subprocess.Popen(
            cmd, stdin=(subprocess.PIPE if stdin_pipe else subprocess.DEVNULL),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, preexec_fn=preexec)

    ep = None
    try:
        for svc in services:
            procs.append((svc, _launch(svc, False)))
        _wait_ready(channel, time.time() + readiness)
        ep = _launch(entry, True)
        procs.append((entry, ep))

        # feed the entry input on stdin (best-effort; the entry may also read a channel)
        derr = [None]

        def _feed():
            try:
                ep.stdin.write(entry_input)
                ep.stdin.close()
            except Exception as e:
                derr[0] = repr(e)
        th = threading.Thread(target=_feed, daemon=True)
        th.start()

        # wait for the entry to finish, then give services a grace to react + crash
        _wait_proc(ep, timeout)
        deadline = time.time() + grace
        for comp, p in procs:
            if p is ep:
                continue
            _wait_proc(p, max(0.05, deadline - time.time()))
        th.join(timeout=0.3)
    finally:
        for _comp, p in procs:
            if p.poll() is None:
                sandbox._killpg(p)
        for _comp, p in procs:
            try:
                p.wait(timeout=2)
            except Exception:
                pass

    outcomes = []
    for comp, p in procs:
        rc = p.returncode
        crashed, sig, signame, exit_code = sandbox.classify_rc(rc)
        outcomes.append(CompOutcome(
            target_id=comp.get("target_id"), filename=comp.get("filename", "?"),
            role=("entry" if comp is entry else "service"),
            crashed=crashed, signal=sig, signal_name=signame, exit_code=exit_code,
            timed_out=(rc is None)))
    return outcomes


def detonate(components: list, *, channel=None, entry_input: bytes = b"",
             timeout: float = 8.0, arch: Optional[str] = None, host: Optional[str] = None,
             readiness: float = 1.5, grace: float = 1.5, baseline: bool = True,
             baseline_input: bytes = b"") -> DetonateResult:
    """Launch services then the entry component together; deliver entry_input to the entry
    on stdin; detect any crash and blame it on the entry input.

    `components` is an ordered list of dicts: {exe, target_id, filename, role, argv?}.
    Services (role != "entry") are launched first; exactly one entry is expected last.

    Cross-boundary blame is only earned when a service crash is CAUSED by the test input, not
    merely coincident with it. So when `baseline` is set (default) the set is first detonated
    with a benign `baseline_input`; a service that crashes there crashes regardless of the test
    input and is therefore never attributed to it -- only a service crash present with the test
    input and ABSENT in the baseline is blamed cross-boundary. Callers that run detonate in a
    tight search loop can pass baseline=False for speed and re-confirm the final hit with it.
    """
    host = host or sandbox.host_arch()
    emu, err = _emu_prefix(arch, host)
    if err:
        return DetonateResult(isolation="unsupported-arch", note=err)

    made_fifo = None
    if channel and channel.get("family") == "fifo" and channel.get("key"):
        key = channel["key"]
        try:
            if not os.path.exists(key):
                os.mkfifo(key, 0o600)
                made_fifo = key
        except OSError as e:
            return DetonateResult(note=f"mkfifo failed: {e!r}")

    services = [c for c in components if c.get("role") != "entry"]
    entries = [c for c in components if c.get("role") == "entry"]
    if not entries:
        if made_fifo:
            _rm(made_fifo)
        return DetonateResult(note="no entry component")
    entry = entries[0]

    preexec = sandbox._rlimits(2048, int(timeout) + 2, set_as=(not emu))
    note = None
    try:
        # BASELINE: a service that also crashes on a benign input is not something the test
        # input caused. Run the set once with baseline_input and remember which services die,
        # so those crashes cannot be mis-blamed on the test input below.
        baseline_crashers: set = set()
        if baseline and services and entry_input != baseline_input:
            base = _run_once(emu=emu, services=services, entry=entry, channel=channel,
                             entry_input=baseline_input, timeout=timeout,
                             readiness=readiness, grace=grace, preexec=preexec)
            baseline_crashers = {o.filename for o in base
                                 if o.crashed and o.role == "service"}
            if baseline_crashers:
                note = ("baseline (benign input) already crashed "
                        + ", ".join(sorted(baseline_crashers))
                        + "; those crashes are not attributed to the test input")
        outcomes = _run_once(emu=emu, services=services, entry=entry, channel=channel,
                             entry_input=entry_input, timeout=timeout,
                             readiness=readiness, grace=grace, preexec=preexec)
    finally:
        if made_fifo:
            _rm(made_fifo)

    blame = _blame(entry, outcomes, baseline_crashers)
    return DetonateResult(outcomes=outcomes, blame=blame, note=note)


def _blame(entry, outcomes, baseline_crashers=frozenset()):
    crashers = [o for o in outcomes if o.crashed]
    if not crashers:
        return None
    # A cross-boundary blame needs a SERVICE crash the benign baseline did NOT show -- a
    # service that dies regardless of input was not crashed BY this input. Prefer such an
    # eligible service (cross-boundary); else the entry crashing directly is attributable
    # because the entry is what received the input.
    svc = next((o for o in crashers
                if o.role == "service" and o.filename not in baseline_crashers), None)
    entry_crash = next((o for o in crashers if o.role == "entry"), None)
    victim = svc or entry_crash
    if victim is None:
        # the only crashers are services that also crashed on the benign baseline: nothing
        # here is attributable to the test input.
        return None
    return {"entry": entry.get("filename"), "entry_target": entry.get("target_id"),
            "crashed": victim.filename, "crashed_target": victim.target_id,
            "signal": victim.signal_name, "cross_boundary": victim.role == "service"}


def _wait_proc(p, timeout):
    try:
        p.wait(timeout=max(0.01, timeout))
    except subprocess.TimeoutExpired:
        pass


def _rm(path):
    try:
        os.unlink(path)
    except OSError:
        pass
