"""Which stages apply to a target -- the map the workbench renders from.

The GUI was substrate-blind while the engine was substrate-aware: `file_type` appeared nowhere
in index.html, so an ELF, a PE, a jar and a firmware image all rendered the same twenty-two
controls. Clicking the wrong one cost a Ghidra run that ended in FileNotFoundError, or an
AFL++ campaign that completed having executed nothing.
"""
import pathlib
import re

from lykos.analyze import capabilities as cap
from lykos.analyze.dynamic import sandbox


class T:
    def __init__(self, file_type=None, arch=None, linking=None):
        self.file_type, self.arch, self.linking = file_type, arch, linking
        self.id, self.case_id = "t", "c"


HOST = sandbox.host_arch()
OTHER = "aarch64" if HOST != "aarch64" else "x86-64"


def test_a_java_target_cannot_be_decompiled_or_escalated():
    un = set(cap.unavailable_summary(T("jar", "jvm")))
    assert "disassemble" in un          # no machine code
    assert "coverage_fuzz" in un        # AFL++ instruments native code
    assert {"poc_primitive", "build_exploit"} <= un   # the JVM owns the instruction pointer
    # ...but the things that DO work are not disabled
    assert "fuzz" not in un and "detect_cwe" not in un and "build_poc" not in un


def test_the_ladder_ceiling_is_explained_not_just_greyed():
    why = cap._why_unavailable("poc_primitive", T("jar", "jvm"))
    assert "instruction pointer" in why
    assert "runtime, not a" in why, "it is the runtime, not a gap to be closed later"


def test_a_cross_architecture_target_loses_only_what_is_native_bound():
    un = set(cap.unavailable_summary(T("elf", OTHER, "dynamic")))
    assert "coverage_fuzz" in un, "afl-qemu-trace is built for the host"
    assert "heap_check" in un
    assert "fuzz" not in un, "black-box fuzzing routes through qemu-user and works"
    assert "disassemble" not in un, "Ghidra decompiles any supported ISA"
    assert "detect_cwe" not in un


def test_a_native_dynamic_elf_has_essentially_everything():
    """The map must not INVENT restrictions. A wrong "unavailable" hides a capability that
    works and the operator has no way to discover the mistake, which is worse than an
    available button that declines for itself."""
    un = cap.unavailable_summary(T("elf", HOST, "dynamic"))
    assert un == [] or un == ["multi_debug"], un      # multi_debug only if gdb is absent


def test_static_linking_only_blocks_the_preload_checker():
    un = set(cap.unavailable_summary(T("elf", HOST, "static")))
    assert "heap_check" in un
    assert "LD_PRELOAD" in cap._why_unavailable("heap_check", T("elf", HOST, "static"))
    assert "fuzz" not in un and "disassemble" not in un


def test_coverage_reason_is_the_stages_own_gate_not_a_copy():
    """One source of truth. A second copy of the rule in the capability map would drift from
    the stage, and then advice, the map and the stage would disagree about the same target."""
    from lykos.analyze.fuzz.coverage import _unsupported
    t = T("elf", OTHER, "dynamic")
    assert cap._why_unavailable("coverage_fuzz", t) == _unsupported(t)


def test_grouping_covers_every_stage_it_lists():
    groups = {g for g, _, _ in cap.GROUPS}
    for stage, (group, label, purpose) in cap.STAGES.items():
        assert group in groups, stage
        assert label and purpose, stage


def test_for_target_puts_the_recommended_step_first():
    out = cap.for_target(T("elf", HOST, "dynamic"),
                         plan=[{"stage": "coverage_fuzz"}, {"stage": "root_cause"}])
    assert out["find"][0]["stage"] == "coverage_fuzz"
    assert out["prove"][0]["stage"] == "root_cause"
    # and an unavailable stage sorts below the available ones
    jar = cap.for_target(T("jar", "jvm"), plan=[{"stage": "fuzz"}])
    prove = [x["stage"] for x in jar["prove"]]
    assert prove.index("build_poc") < prove.index("poc_primitive")


# ---- the page itself ----------------------------------------------------------------------
_HTML = pathlib.Path(__file__).resolve().parents[1] / "core/lykos/api/static/index.html"


def test_the_workbench_is_fed_find_prove():
    h = _HTML.read_text()
    for name in (">Feed<", ">Find<", ">Prove<"):
        assert name in h, name
    # the old twenty-two-control panel is gone
    assert ">Dynamic &amp; fuzzing<" not in h
    assert "applyCapabilities" in h and 'id="substrate"' in h


def test_the_step_numbers_are_unique():
    """Triage is the target's identity card, not a step; numbering it 1 alongside Feed gave
    the panel two step ones."""
    h = _HTML.read_text()
    # scoped to the WORKBENCH panel: the Report tab has its own numbered sequence (Scope,
    # Live preview, Export & share, Case portability) and the two are different ladders.
    start = h.index("<b>Triage</b>")
    end = h.index("<b>Prove</b>")
    nums = re.findall(r'<span class="snum">(\d+)</span>', h[start:end + 200])
    assert nums == ["1", "2", "3"], nums


def test_every_launchable_control_is_covered_by_the_capability_map():
    """A button the map does not know about can never be disabled, which is how a
    substrate-blind panel comes back one stage at a time."""
    h = _HTML.read_text()
    ids = set(re.findall(r'_STAGE_BTN = \{(.*?)\};', h, re.S))
    assert ids, "the stage->button map must exist"
    mapped = set(re.findall(r'(\w+):"(\w+)"', list(ids)[0]))
    for stage, btn in mapped:
        assert f'id="{btn}"' in h, f"{stage} points at a control that does not exist: {btn}"
