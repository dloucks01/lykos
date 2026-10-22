"""afl-qemu-trace wrapper resolution (air-gap fuzzing fix).

The air-gap bundle ships each tool as a relocatable `.wrappers/<name>` shell script that execs the
real ELF. afl-fuzz `-Q` execs its trace as the fork-server QEMU and speaks a pipe protocol over
fixed descriptors, so a shell wrapper in between aborts at "Fork server handshake failed" -- which
killed EVERY coverage_fuzz (afl qemu-mode) run from the bundle. stage_qemu_trace must therefore link
afl at the real ELF, never the wrapper."""
from __future__ import annotations

from pathlib import Path

from lykos.analyze.fuzz import aflpp

# the bundle's actual wrapper shape (packaging/setup-toolchain.sh gen_wrappers)
_WRAPPER = (
    "#!/bin/sh\n"
    "# lykos relocatable wrapper\n"
    'r=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)\n'
    'exec "$r/usr/local/bin/afl-qemu-trace-x86-64" "$@"\n'
)


def _bundle(tmp_path):
    """A minimal bundle layout: .wrappers/<name> script + usr/local/bin/<name> ELF."""
    tc = tmp_path / "toolchain"
    (tc / ".wrappers").mkdir(parents=True)
    (tc / "usr/local/bin").mkdir(parents=True)
    real = tc / "usr/local/bin/afl-qemu-trace-x86-64"
    real.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56)   # an ELF header is enough
    real.chmod(0o755)
    wrap = tc / ".wrappers/afl-qemu-trace-x86-64"
    wrap.write_text(_WRAPPER)
    wrap.chmod(0o755)
    return wrap, real


def test_resolve_follows_wrapper_to_real_elf(tmp_path):
    wrap, real = _bundle(tmp_path)
    assert aflpp._resolve_trace_binary(wrap).resolve() == real.resolve()


def test_resolve_leaves_a_real_elf_alone(tmp_path):
    _, real = _bundle(tmp_path)
    assert aflpp._resolve_trace_binary(real).resolve() == real.resolve()


def test_stage_links_the_real_elf_not_the_wrapper(tmp_path):
    wrap, real = _bundle(tmp_path)
    ap = aflpp.stage_qemu_trace(wrap, tmp_path / "wd")
    staged = (Path(ap) / "afl-qemu-trace").resolve()
    assert staged == real.resolve()
    assert staged.read_bytes()[:4] == b"\x7fELF"       # afl -Q will exec an ELF, not a shell script


def test_resolve_is_graceful_when_wrapper_target_missing(tmp_path):
    # a wrapper whose exec target does not exist -> return the wrapper unchanged, never crash
    tc = tmp_path / "tc"
    (tc / ".wrappers").mkdir(parents=True)
    wrap = tc / ".wrappers/afl-qemu-trace-x86-64"
    wrap.write_text(_WRAPPER)
    assert aflpp._resolve_trace_binary(wrap) == wrap
