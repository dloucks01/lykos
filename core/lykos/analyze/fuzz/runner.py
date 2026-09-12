"""Shared target-invocation helper for the fuzzing stages."""
from __future__ import annotations

from ..dynamic import sandbox

INPUT_PLACEHOLDER = "@@"


def invocation(mode, workfile, d: bytes, base_argv=()):
    """(argv, stdin) for one execution, with the input placed where the TARGET expects it.

    `@@` in `base_argv` is replaced by the thing carrying the input; without it the carrier is
    appended, which is the old behaviour. The placeholder is what makes a real service
    invocable at all: `-c @@` puts the config path immediately after its flag, where appending
    would produce `-c -v <path>` the moment any other flag was present, and `-c` would eat the
    flag instead of the file.
    """
    argv = list(base_argv)
    if mode == "arg":
        carrier = d.decode("latin-1")
    elif mode == "file":
        workfile.write_bytes(d)
        carrier = str(workfile)
    else:                                               # stdin
        return argv, d
    if INPUT_PLACEHOLDER in argv:
        return [carrier if a == INPUT_PLACEHOLDER else a for a in argv], b""
    return argv + [carrier], b""


def run_input(exe, mode, workfile, timeout, arch, d: bytes, *, endianness=None, bits=None,
              base_argv=(), blocks=()):
    """One execution. `base_argv` is the option prefix the campaign is running under: a crash
    found with an option has to be re-run with it to mean anything. `blocks` asks for coverage,
    which on an emulated target comes from qemu's own block log."""
    argv, stdin = invocation(mode, workfile, d, base_argv)
    return argv, sandbox.run(exe, argv=argv, stdin=stdin, timeout=timeout, arch=arch,
                             endianness=endianness, bits=bits, blocks=blocks)
