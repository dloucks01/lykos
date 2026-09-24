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
import pathlib

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


def test_a_machine_can_hold_one_emulator_per_guest(monkeypatch, tmp_path):
    """afl-qemu-trace targets a single guest chosen at build time, so covering ARM and AArch64
    and x86-64 means three binaries. AFL++ installs them all under the same name, so looking
    only for the bare name finds whichever was installed last -- and the advice this platform
    prints ("build a matching one and point LYKOS_AFL at it") was not actionable, because
    nothing selected per architecture."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    afl = bindir / "afl-fuzz"
    afl.write_text("")
    for guest in ("aarch64", "arm"):
        (bindir / f"afl-qemu-trace-{guest}").write_text("")
    monkeypatch.setattr(aflpp, "qemu_trace_arch",
                        lambda t: str(t).rsplit("-", 1)[-1] if "trace-" in str(t) else None)
    aflpp._guest_cache.clear()
    assert aflpp.locate_qemu_trace_for(afl, "aarch64").name == "afl-qemu-trace-aarch64"
    assert aflpp.locate_qemu_trace_for(afl, "arm").name == "afl-qemu-trace-arm"
    assert aflpp.locate_qemu_trace_for(afl, "mips") is None


def test_an_override_pointing_at_the_wrong_guest_is_refused(monkeypatch, tmp_path):
    """Naming a file afl-qemu-trace-arm does not make it emulate ARM. An unverified override
    would abort at the fork-server handshake, which is the failure this path exists to
    avoid."""
    afl = tmp_path / "afl-fuzz"
    afl.write_text("")
    wrong = tmp_path / "some-trace"
    wrong.write_text("")
    monkeypatch.setenv("LYKOS_AFL_QEMU_ARM", str(wrong))
    monkeypatch.setattr(aflpp, "qemu_trace_arch", lambda t: "aarch64")
    aflpp._guest_cache.clear()
    assert aflpp.locate_qemu_trace_for(afl, "arm") is None


def test_the_chosen_emulator_is_staged_where_afl_fuzz_looks(tmp_path):
    """afl-fuzz looks for its helper under the single name `afl-qemu-trace`, so the selected
    one is linked under that name in a private directory and AFL_PATH points at it."""
    real = tmp_path / "afl-qemu-trace-aarch64"
    real.write_text("#!/bin/sh\n")
    ap = aflpp.stage_qemu_trace(real, tmp_path / "work")
    link = pathlib.Path(ap) / "afl-qemu-trace"
    assert link.exists()
    assert link.resolve() == real.resolve()
    # staging twice must not fail on the existing link
    assert aflpp.stage_qemu_trace(real, tmp_path / "work") == ap


def test_campaign_stats_distinguish_a_quiet_run_from_a_dead_one(tmp_path):
    """"0 crashes" after 41,562 executions and "0 crashes" after none are opposite
    conclusions, and the event could not tell them apart."""
    out = tmp_path / "out"
    (out / "default").mkdir(parents=True)
    (out / "default" / "fuzzer_stats").write_text(
        "start_time : 1\nexecs_done : 41562\nexecs_per_sec : 923.17\n"
        "corpus_count : 341\ncycles_done : 0\n")
    got = aflpp.campaign_stats(out)
    assert got["execs_done"] == "41562"
    assert got["execs_per_sec"] == "923.17"
    assert aflpp.campaign_stats(tmp_path / "nothing") == {}
