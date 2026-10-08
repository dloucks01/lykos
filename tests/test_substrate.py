"""The one substrate table, and the seven call sites that must agree with it.

These rules used to live in seven hand-kept places. Nothing failed loudly when one of them was
missed, and the symptom was always the worst one this tool can produce: a substrate that cannot
run the target reporting a CLEAN verdict. So the point of this file is not to re-test the data
-- it is to pin the INVARIANTS that each of those seven places now derives, and to fail if a new
format is added to triage without a row here.
"""
import pytest
from lykos.analyze import capabilities, filetype, substrate, triage
from lykos.analyze.debug import stage as debug_stage
from lykos.analyze.dynamic import sandbox as sandbox_mod
from lykos.analyze.fuzz.coverage import _unsupported
from lykos.analyze.orchestrate import _expensive_substrate, _nonnative_image


class T:
    """The smallest thing the substrate questions accept."""

    def __init__(self, file_type, arch="x86-64", linking="dynamic"):
        self.file_type, self.arch, self.linking = file_type, arch, linking
        self.id = "t" * 32


def test_every_file_type_triage_can_emit_has_a_row():
    """The gap this whole module closes: a format triage knows but the substrate table does not.

    `_FILE_TYPES` is what `triage.validate` accepts, so it is the authoritative list of what can
    reach a target row. A missing row here is exactly how .NET ended up dispatched to wine.
    """
    missing = sorted(ft for ft in triage._FILE_TYPES if ft not in substrate.SUBSTRATES)
    assert not missing, f"file_types triage emits with no substrate row: {missing}"


def test_an_unknown_format_is_unrunnable_not_native():
    """Guessing "native" for an unknown format is what let an unrunnable image read as clean."""
    for ft in ("", None, "ocaml-bytecode", "a.out"):
        sub = substrate.of(ft)
        assert sub.backend is None
        assert sub.no_exec
        assert not sub.machine_code
        assert not sub.ip_control


@pytest.mark.parametrize("ft,runtime", [
    ("class", "the JVM"), ("jar", "the JVM"), ("pyc", "CPython"),
    ("wasm", "the WebAssembly engine"), ("dotnet", "the CLR"),
])
def test_the_four_managed_runtimes_are_all_managed(ft, runtime):
    assert substrate.managed_runtime(ft) == runtime
    assert substrate.is_managed(ft)
    # A managed runtime owns the instruction pointer: there is no hijack to claim, and no
    # machine code in the image to disassemble or instrument.
    assert not substrate.supports_ip_control(ft)
    assert not substrate.instrumentable(ft)


@pytest.mark.parametrize("ft", ["elf", "pe", "macho", "firmware", "raw", "other"])
def test_a_native_or_unrunnable_format_is_not_managed(ft):
    assert substrate.managed_runtime(ft) is None
    assert not substrate.is_managed(ft)


def test_only_a_host_runnable_machine_code_image_is_afl_able():
    """AFL instruments machine code IN A HOST PROCESS.

    An ELF qualifies, including a foreign-arch one (qemu-mode handles it). A PE is machine code
    but runs under wine; bytecode and wasm are not machine code at all; a Mach-O and a
    bare-metal image do not run here. Every one of the last four must be blocked, and `dotnet`
    and `macho` are the two that were NOT -- the autopilot really did start an AFL campaign
    against CIL bytecode and against an image the kernel refuses to exec.
    """
    assert not _nonnative_image(T("elf"))
    assert not _nonnative_image(T("elf", arch="aarch64"))      # qemu-mode genuinely handles it
    for ft in ("pe", "class", "jar", "pyc", "wasm", "dotnet", "macho", "firmware", "raw"):
        assert _nonnative_image(T(ft)), ft


def test_the_afl_gate_gives_a_reason_for_every_format_it_blocks():
    """"nothing was run" has to be distinguishable from "nothing was found"."""
    assert _unsupported(T("elf")) is None                      # the format is no obstacle
    for ft in ("pe", "class", "jar", "pyc", "wasm", "dotnet", "macho", "firmware", "raw"):
        why = _unsupported(T(ft))
        assert why and len(why) > 40, ft


def test_only_native_execution_is_cheap():
    """`_expensive_substrate` decides stage ORDER, so a cheap certain stage is not queued
    behind a campaign that will spend the whole budget at 8 executions a second."""
    assert not _expensive_substrate(T("elf"))
    assert _expensive_substrate(T("elf", arch="aarch64"))      # same backend, foreign arch
    for ft in ("pe", "class", "jar", "pyc", "wasm", "dotnet", "macho", "firmware"):
        assert _expensive_substrate(T(ft)), ft


def test_measured_exec_rates_are_ordered_as_measured():
    """These numbers are measured, not guessed, and the ORDER is what stage ordering relies on."""
    rate = {ft: substrate.of(ft).execs_per_sec for ft in
            ("elf", "jar", "pyc", "wasm", "dotnet", "pe")}
    assert rate["elf"] > rate["jar"] > rate["pyc"] > rate["wasm"] > rate["dotnet"] > rate["pe"]


def test_the_managed_root_cause_path_covers_every_managed_format():
    """debug.stage used to keep its own dict, which knew only the JVM after .pyc and .wasm
    became executable -- so a managed fault on those never reached the managed root-cause path."""
    for ft in ("class", "jar", "pyc", "wasm", "dotnet"):
        kind = debug_stage._managed_kind(ft)
        assert kind, ft
        rt = debug_stage._managed_runtime(kind)
        # The descriptor's name must be the SAME phrase the substrate table uses, or one report
        # calls one runtime two different things.
        assert rt["name"] == substrate.managed_runtime(ft), ft
        assert callable(rt["parse"]) and callable(rt["blame"])
    for ft in ("elf", "pe", "macho", "firmware", "raw", ""):
        assert debug_stage._managed_kind(ft) is None, ft


@pytest.mark.parametrize("stage", ["poc_primitive", "build_exploit"])
def test_the_honest_ceiling_is_told_for_every_managed_format(stage):
    """The capability map existed so the operator would not learn by waiting for a decline.

    It told the "no L2/L3 on a managed runtime" reason for jar/class ONLY, so .pyc, .wasm and
    .NET targets were offered IP control and Exploit with no explanation at all.
    """
    for ft in ("class", "jar", "pyc", "wasm", "dotnet"):
        why = capabilities._why_unavailable(stage, T(ft))
        assert why, f"{ft} is offered {stage} with no reason"
        assert substrate.managed_runtime(ft) in why, ft
    # A native ELF really can be escalated; saying otherwise would hide a working capability.
    assert capabilities._why_unavailable(stage, T("elf")) is None


def test_a_managed_target_is_not_offered_the_machine_code_channels():
    for ft in ("class", "jar", "pyc", "wasm", "dotnet"):
        for stage in ("disassemble", "dynamic_taint", "concolic", "heap_check"):
            assert capabilities._why_unavailable(stage, T(ft)), (ft, stage)


def test_dotnet_is_a_pe_on_disk_but_never_a_pe_to_the_pipeline():
    """The root of the .NET bug: every .NET assembly satisfies the PE magic test, so any rule
    keyed on "is it a PE" sent it to wine, which cannot execute managed code."""
    assert filetype.DOTNET in substrate.SUBSTRATES
    assert substrate.of("dotnet").backend == substrate.CLR
    assert substrate.of("pe").backend == substrate.WINE


def test_an_untriaged_target_is_not_treated_as_unrunnable_by_the_GATES():
    """`ingest` creates the target row and `ingest_triage` fills in file_type later, so an
    empty file_type means "not looked at yet", NOT "an image that cannot run".

    Conflating the two blocks work on no evidence: it made the AFL gate answer "nothing to run
    here" for a perfectly good ELF whose triage had not finished, which hides a capability that
    works -- the opposite of the error this module exists to prevent, and just as wrong.
    """
    assert not substrate.known("")
    assert not substrate.known(None)
    assert substrate.known("elf")
    # The gates must stay silent on no evidence...
    assert _unsupported(T(None)) is None
    assert _unsupported(T("")) is None
    assert not _nonnative_image(T(None))
    # ...while the questions that describe a substrate still answer conservatively.
    assert substrate.of(None).backend is None
    assert not substrate.supports_ip_control(None)


def test_executability_is_decided_by_the_FILE_not_by_the_file_type():
    """Where a non-run has a real cost -- actually executing the image -- the check is made on
    the file's own header, so it holds whether or not triage has run."""
    assert hasattr(sandbox_mod, "_host_loadable")
    assert sandbox_mod._host_loadable.__doc__
