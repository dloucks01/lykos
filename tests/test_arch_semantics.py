"""`target.arch` names a CPU for a native image and a RUNTIME for a managed one.

triage writes "cil" / "jvm" / "cpython" / "wasm" into `target.arch`, because those targets have
no CPU to name. The pipeline's test for "a foreign architecture, reachable only under an
emulator" is `target.arch != host_arch()`, asked at 28 call sites -- and it is TRUE for every
managed target by accident of that field holding two different kinds of thing.

The conclusion usually coincided with the right answer, so the damage was in the REASON given to
the operator, which is the product here:

  * `poc_primitive` declined a .NET assembly with "L2 for cross-arch cil: no qemu gdbstub
    register layout (host x86-64)" -- naming a missing TOOL for something no tool can change.
    The CLR owns the instruction pointer; `substrate.no_ip_control_reason` already said so
    correctly, and the stage never asked;
  * `env_fuzz` declined with "cross-arch target (cil); env fuzzing needs a native host", which
    is the wrong reason AND the wrong conclusion -- see test_managed_env_channel.py;
  * five stages set `emulated=True` and took a qemu path for something that is not emulated.

Correcting the comparison alone would have been worse than leaving it: three stages (heap_check,
multi_debug, net_fuzz) had NO other guard, so a .NET assembly would have gone from a misleading
decline to an LD_PRELOAD shim and an execve() of bytecode. Each needed the reason that is
actually true, which is what `native_only_reason` states.
"""
import re
from pathlib import Path

import pytest
from lykos.analyze import substrate

_CORE = Path(__file__).resolve().parents[1] / "core" / "lykos"


# ---- the two readings of one field ---------------------------------------------------------

@pytest.mark.parametrize("arch,ftype", [
    ("cil", "dotnet"), ("jvm", "jar"), ("jvm", "class"), ("cpython", "pyc"), ("wasm", "wasm"),
])
def test_a_managed_targets_arch_is_not_a_cpu(arch, ftype):
    assert not substrate.names_a_cpu(arch, ftype)
    assert not substrate.foreign_cpu(arch, ftype, "x86-64"), \
        "a managed target is not reachable-only-under-an-emulator; it has no CPU to be foreign"


@pytest.mark.parametrize("arch", ["cil", "jvm", "cpython", "wasm"])
def test_a_runtime_name_is_recognised_without_the_file_type(arch):
    """The file_type is not always to hand (`sandbox.run` is given an arch and nothing else), so
    the token itself has to be enough."""
    assert not substrate.names_a_cpu(arch)
    assert not substrate.foreign_cpu(arch, None, "x86-64")


@pytest.mark.parametrize("arch,host,want", [
    ("aarch64", "x86-64", True), ("mips", "x86-64", True), ("x86-64", "x86-64", False),
    ("X86-64", "x86-64", False),                      # case is not a difference
])
def test_a_native_targets_arch_is_still_compared_as_before(arch, host, want):
    assert substrate.foreign_cpu(arch, "elf", host) is want


def test_a_macho_or_firmware_arch_is_a_real_cpu():
    """Not every non-runnable format is managed: a Mach-O and a bare-metal image both name a
    genuine CPU, and treating them as runtime names would lose the one thing `arch` tells us."""
    assert substrate.names_a_cpu("arm64", "macho")
    assert substrate.foreign_cpu("arm64", "macho", "x86-64")
    assert substrate.names_a_cpu("arm", "firmware")


def test_an_absent_arch_or_host_is_never_called_foreign():
    """Both are NULL until triage fills them in, and "unknown" must not read as "emulate it"."""
    assert not substrate.foreign_cpu(None, "elf", "x86-64")
    assert not substrate.foreign_cpu("", "elf", "x86-64")
    assert not substrate.foreign_cpu("aarch64", "elf", None)
    assert not substrate.foreign_cpu("aarch64", "elf", "")


def test_an_untriaged_target_with_a_foreign_arch_is_still_foreign():
    """An empty file_type means triage has not run yet. The arch came from somewhere, so honour
    it: refusing to emulate because we have not classified the file blocks work that works."""
    assert substrate.foreign_cpu("aarch64", None, "x86-64")
    assert substrate.foreign_cpu("aarch64", "", "x86-64")


# ---- one way to ask the question ----------------------------------------------------------

_DIRECT = re.compile(r"target\.arch\s*!=|arch\s*!=\s*sandbox\.host_arch\(\)")


def test_no_stage_compares_a_targets_arch_to_the_host_itself():
    """The drift guard. This question has to be asked in ONE place, because the answer depends on
    a fact about the FIELD that no call site can be expected to remember. 28 of them did.

    `sandbox.run` and the pure-arch helpers (`memoracle.runtime_tokens`, `qemu_gdb`) are not
    listed: they take an arch as an argument and have no target or file_type to consult -- their
    callers hold the obligation, which is exactly what this check enforces on them.
    """
    allowed = {"dynamic/sandbox.py", "dynamic/memoracle.py", "api/console.py",
               "link/harness.py", "link/detonate.py",
               "substrate.py"}            # where the helper lives and explains the field
    bad = []
    for f in sorted(_CORE.rglob("*.py")):
        rel = str(f.relative_to(_CORE / "analyze")) if "analyze" in f.parts else str(
            f.relative_to(_CORE))
        if rel in allowed:
            continue
        for i, line in enumerate(f.read_text().splitlines(), 1):
            code = line.split("#", 1)[0]
            if _DIRECT.search(code):
                bad.append(f"{rel}:{i}: {line.strip()}")
    assert not bad, "ask substrate.foreign_cpu() instead:\n" + "\n".join(bad)


def test_the_allowed_list_names_only_files_that_have_no_target():
    """A stage must not be added to the exemption list above to silence it: these five take an
    arch as a parameter, so they genuinely cannot consult a file_type."""
    for rel in ("dynamic/sandbox.py", "dynamic/memoracle.py", "link/harness.py",
                "link/detonate.py"):
        src = (_CORE / "analyze" / rel).read_text()
        assert "target.arch !=" not in src, f"{rel} has a target in scope after all"


# ---- what a stage says when it declines ---------------------------------------------------

@pytest.mark.parametrize("ftype,runtime", [
    ("dotnet", "the CLR"), ("jar", "the JVM"), ("pyc", "CPython"),
    ("wasm", "the WebAssembly engine"),
])
def test_the_ip_control_ceiling_names_the_runtime_and_not_a_missing_tool(ftype, runtime):
    why = substrate.no_ip_control_reason(ftype)
    assert runtime in why
    low = why.lower()
    assert "qemu" not in low and "gdbstub" not in low and "register layout" not in low, \
        f"an operator reading this would go looking for a tool: {why}"


@pytest.mark.parametrize("ftype,what", [
    ("dotnet", "the CLR"), ("jar", "the JVM"), ("pyc", "CPython"), ("wasm", "the WebAssembly"),
    ("pe", "wine"), ("macho", "macOS"),
])
def test_a_native_only_technique_says_why_it_cannot_reach_this_substrate(ftype, what):
    why = substrate.native_only_reason(ftype, "the guard-page heap checker")
    assert why and what in why
    assert "the guard-page heap checker" in why


def test_a_native_elf_is_not_declined_by_either_gate():
    assert substrate.no_ip_control_reason("elf") is None
    assert substrate.native_only_reason("elf", "anything") is None
    assert substrate.native_only_reason(None, "anything") is None, \
        "an untriaged target must not be refused on no evidence"


# ---- the two stages whose decline was the sharpest instance -------------------------------

class _Ctx:
    """The smallest ctx these two stages touch before they decide."""

    def __init__(self, conn, target_id, params):
        self.conn, self.target_id, self.params = conn, target_id, params
        self.run_id = None
        self.events = []

    def emit(self, name, payload=None):
        self.events.append((name, payload or {}))

    def progress(self, *a, **k):
        pass

    def notes(self):
        return " ".join(str(p.get("note") or "") for _n, p in self.events)


@pytest.fixture()
def dotnet_target(tmp_path):
    from lykos.casestore import CaseStore
    from lykos.db.dao import TargetDAO
    store = CaseStore.open(tmp_path / "case")
    cid = store.cases.create("arch").id
    t = TargetDAO(store.conn).upsert(cid, "app.bin", "d" * 64, size=512,
                                     file_type="dotnet", arch="cil", bits=32)
    return store, t


def test_poc_primitive_declines_a_dotnet_assembly_for_the_right_reason(dotnet_target):
    from lykos.analyze.poc.primitive_stage import primitive_stage
    store, t = dotnet_target
    ctx = _Ctx(store.conn, t.id, {"input_sha": "a" * 64})
    primitive_stage(ctx)
    note = ctx.notes()
    assert "the CLR" in note, note
    assert "qemu" not in note.lower() and "gdbstub" not in note.lower(), note


def test_build_exploit_declines_a_dotnet_assembly_for_the_right_reason(dotnet_target):
    """And it must DECLINE: with the arch comparison corrected and no substrate guard, this
    stage would have fallen through to "native x86-64" and tried to synthesize a ROP chain
    against a .NET assembly."""
    from lykos.analyze.poc.exploit_stage import build_exploit_stage
    store, t = dotnet_target
    ctx = _Ctx(store.conn, t.id, {"input_sha": "a" * 64})
    build_exploit_stage(ctx)
    note = ctx.notes()
    assert "the CLR" in note, note
    assert "qemu" not in note.lower(), note


@pytest.mark.parametrize("module,fn,params", [
    ("lykos.analyze.dynamic.heap_stage", "heap_stage", {}),
    ("lykos.analyze.fuzz.net_stage", "net_fuzz_stage", {}),
    ("lykos.analyze.debug.multidebug", "multi_debug_stage", {"input_sha": "a" * 64}),
])
def test_the_stages_with_no_other_guard_refuse_a_managed_target(module, fn, params,
                                                                dotnet_target):
    """These three had ONLY the arch comparison. Correcting it without adding a substrate reason
    would have turned a misleading decline into an LD_PRELOAD shim over bytecode, a localhost
    campaign against a program that cannot be exec'd, and a GDB session on a metadata blob."""
    import importlib
    store, t = dotnet_target
    ctx = _Ctx(store.conn, t.id, params)
    getattr(importlib.import_module(module), fn)(ctx)
    assert "the CLR" in ctx.notes(), ctx.notes()
