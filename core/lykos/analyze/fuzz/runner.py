"""Shared target-invocation helper for the fuzzing stages."""
from __future__ import annotations

from ..dynamic import sandbox
from ..invocation import INPUT_PLACEHOLDER, OUTPUT_PLACEHOLDER


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
              base_argv=(), blocks=()):
    """One execution. `base_argv` is the option prefix the campaign is running under: a crash
    found with an option has to be re-run with it to mean anything. `blocks` asks for coverage,
    which on an emulated target comes from qemu's own block log."""
    argv, stdin = invocation(mode, workfile, d, base_argv)
    return argv, sandbox.run(exe, argv=argv, stdin=stdin, timeout=timeout, arch=arch,
                             endianness=endianness, bits=bits, blocks=blocks)
