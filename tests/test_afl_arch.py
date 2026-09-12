"""Which architecture can AFL++'s qemu-mode actually drive here?

Not "the host". afl-qemu-trace is an EMULATOR: it is always built for the host and targets one
guest architecture chosen at build time. Reading `file` output and seeing "ELF 64-bit x86-64"
describes the emulator, not what it emulates -- and concluding otherwise blocked
coverage-guided fuzzing on the one architecture the installed trace binary could drive
(aarch64) while permitting it on the one that aborts at the fork-server handshake (x86-64, the
host). Measured on this machine before the fix:

    afl-qemu-trace <aarch64 binary>  -> runs it, prints the parsed JPEG
    afl-qemu-trace <x86-64 binary>   -> "Invalid ELF image for this architecture"
    coverage_fuzz on the x86-64 host -> RuntimeError, "Fork server handshake failed"

and after it, on the aarch64 target the gate used to refuse outright:

    coverage.done {"crash_inputs": 1, "unique": 1, "confirmed": 1}
"""
import inspect

from lykos.analyze.fuzz import aflpp
from lykos.analyze.fuzz.coverage import _unsupported


class _T:
    def __init__(self, file_type="elf", arch=None):
        self.file_type, self.arch = file_type, arch


def test_the_guest_arch_comes_from_qemus_own_version_banner(monkeypatch, tmp_path):
    fake = tmp_path / "afl-qemu-trace"
    fake.write_text("")

    class _R:
        stdout = b"qemu-aarch64 version 5.2.50 (v5.0.0-8838-g3f571d0272)\n"
        stderr = b""
    monkeypatch.setattr(aflpp.subprocess, "run", lambda *a, **k: _R())
    aflpp._guest_cache.clear()
    assert aflpp.qemu_trace_arch(fake) == "aarch64"

    class _R2:
        stdout = b"qemu-x86_64 version 5.2.50\n"
        stderr = b""
    monkeypatch.setattr(aflpp.subprocess, "run", lambda *a, **k: _R2())
    aflpp._guest_cache.clear()
    assert aflpp.qemu_trace_arch(fake) == "x86-64"


def test_an_unreadable_trace_binary_says_nothing_rather_than_guessing(monkeypatch, tmp_path):
    fake = tmp_path / "afl-qemu-trace"
    fake.write_text("")

    def _boom(*a, **k):
        raise OSError("nope")
    monkeypatch.setattr(aflpp.subprocess, "run", _boom)
    aflpp._guest_cache.clear()
    assert aflpp.qemu_trace_arch(fake) is None
    # ...and an unknown guest must not block a target: the gate only refuses on a KNOWN
    # mismatch, so a qemu we cannot interrogate is allowed to try rather than be assumed wrong
    monkeypatch.setattr(aflpp, "locate_afl", lambda _c: fake)
    monkeypatch.setattr(aflpp, "locate_qemu_trace", lambda _a: fake)
    assert _unsupported(_T(arch="aarch64")) is None


def test_the_gate_compares_the_guest_arch_not_the_host(monkeypatch, tmp_path):
    fake = tmp_path / "afl-qemu-trace"
    fake.write_text("")
    monkeypatch.setattr(aflpp, "locate_afl", lambda _c: fake)
    monkeypatch.setattr(aflpp, "locate_qemu_trace", lambda _a: fake)
    monkeypatch.setattr(aflpp, "qemu_trace_arch", lambda _t: "aarch64")

    # the architecture the emulator targets is available, whatever the host is
    assert _unsupported(_T(arch="aarch64")) is None
    # ...and the HOST architecture is not, when the emulator targets something else
    why = _unsupported(_T(arch="x86-64"))
    assert why and "emulates aarch64" in why and "x86-64" in why
    assert "CPU_TARGET=x86_64" in why, "say how to fix it, not just that it is broken"


def test_missing_afl_and_missing_trace_are_different_answers(monkeypatch, tmp_path):
    monkeypatch.setattr(aflpp, "locate_afl", lambda _c: None)
    assert "AFL++ not found" in _unsupported(_T(arch="aarch64"))
    fake = tmp_path / "afl-fuzz"
    fake.write_text("")
    monkeypatch.setattr(aflpp, "locate_afl", lambda _c: fake)
    monkeypatch.setattr(aflpp, "locate_qemu_trace", lambda _a: None)
    assert "build_qemu_support.sh" in _unsupported(_T(arch="aarch64"))


def test_the_gate_no_longer_asks_the_host_architecture():
    """The regression guard. `host_arch()` is the wrong question for an emulator, and asking
    it is what produced a gate that was exactly inverted."""
    src = inspect.getsource(_unsupported)
    assert "host_arch" not in src, "the guest architecture is what decides this"
    assert "qemu_trace_arch" in src
