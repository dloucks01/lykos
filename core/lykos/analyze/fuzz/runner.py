"""Shared target-invocation helper for the fuzzing stages."""
from __future__ import annotations

from ..dynamic import sandbox


def invocation(mode, workfile, d: bytes):
    if mode == "arg":
        return [d.decode("latin-1")], b""
    if mode == "file":
        workfile.write_bytes(d)
        return [str(workfile)], b""
    return [], d                                        # stdin


def run_input(exe, mode, workfile, timeout, arch, d: bytes, *, endianness=None, bits=None,
              base_argv=()):
    """One execution. `base_argv` is the option prefix the campaign is running under: a crash
    found with an option has to be re-run with it to mean anything."""
    argv, stdin = invocation(mode, workfile, d)
    argv = list(base_argv) + argv
    return argv, sandbox.run(exe, argv=argv, stdin=stdin, timeout=timeout, arch=arch,
                             endianness=endianness, bits=bits)
