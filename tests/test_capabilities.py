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


def test_a_windows_pe_loses_the_two_linux_only_channels():
    """The stages already knew: heap_check declines with "the guard-page heap checker is a
    Linux/ELF LD_PRELOAD shim" and dynamic_taint with "runs Linux ELF only". The map did not,
    so the workbench offered both on a PE and the operator found out by waiting for a
    decline -- the exact friction the map exists to remove."""
    un = set(cap.unavailable_summary(T("pe", "x86-64", "dynamic")))
    assert {"heap_check", "dynamic_taint"} <= un
    # ...but the two channels that DO cover Windows stay available: behaviour tracing and the
    # runtime monitor both have Wine relay paths
    assert "behavior_trace" not in un and "debug_monitor" not in un
    # and Ghidra decompiles PE, so the static half is intact
    assert "disassemble" not in un and "detect_cwe" not in un


def test_a_substrate_with_no_runner_loses_the_execution_channels():
    un = set(cap.unavailable_summary(T("macho", "x86-64")))
    assert {"behavior_trace", "debug_monitor", "dynamic_taint", "heap_check"} <= un
    why = cap._why_unavailable("behavior_trace", T("macho", "x86-64"))
    assert "ELF and PE only" in why


def test_a_cross_architecture_target_loses_only_what_is_native_bound():
    un = set(cap.unavailable_summary(T("elf", OTHER, "dynamic")))
    # coverage_fuzz is deliberately NOT asserted here: whether AFL++ can drive an
    # architecture depends on which guest the installed afl-qemu-trace was built for, and on
    # this machine that is aarch64 rather than the host. Asserting "cross-arch means no
    # coverage" is the belief that produced a gate blocking the one architecture that worked.
    assert "heap_check" in un
    assert "fuzz" not in un, "black-box fuzzing routes through qemu-user and works"
    assert "disassemble" not in un, "Ghidra decompiles any supported ISA"
    assert "detect_cwe" not in un


def test_a_native_dynamic_elf_loses_nothing_without_a_stated_reason():
    """The map must not INVENT restrictions. A wrong "unavailable" hides a capability that
    works and the operator has no way to discover the mistake, which is worse than an
    available button that declines for itself.

    The list is not hard-coded because two entries are properties of the MACHINE rather than
    of the target: gdb may not be installed, and whether AFL++ can drive this architecture
    depends on which guest its afl-qemu-trace was built for. What must hold is that every
    exclusion names a real, checkable reason."""
    t = T("elf", HOST, "dynamic")
    un = cap.unavailable_summary(t)
    assert set(un) <= {"multi_debug", "coverage_fuzz"}, un
    for stage in un:
        why = cap._why_unavailable(stage, t)
        assert why and len(why) > 40, (stage, why)


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


def test_the_board_groups_by_evidence_tier():
    """The sort has been evidence-first for a while, but 24 rows in one table give the reader
    no idea where demonstrated stops and pattern-matching starts -- and on a real parser the
    speculative tier IS the list (jhead: 1 confirmed, 7 corroborated, 16 candidates)."""
    h = _HTML.read_text()
    assert "const TIERS=" in h
    for label in ("Demonstrated", "Corroborated", "Unproven"):
        assert label in h, label
    # the unproven inventory starts collapsed; the demonstrated tier does not
    tiers = h[h.index("const TIERS="):h.index("const body = rows.length")]
    assert 'states:["candidate"], open:false' in tiers.replace(" ", "").replace("\n", "") \
        or 'open:false' in tiers
    assert "toggleTier" in h and "BOARD_OPEN" in h


def test_the_tier_toggle_is_an_override_not_another_or_term():
    """Written as `t.open || ... || BOARD_OPEN[k]` the two open-by-default tiers could never be
    collapsed: the first term short-circuits and the chevron does nothing."""
    h = _HTML.read_text()
    assert "(t.key in BOARD_OPEN) ? BOARD_OPEN[t.key] : dflt" in h
    assert "t.open || !!f.state || !!f.q || BOARD_OPEN" not in h


def test_cross_taint_says_what_stopped_it():
    """"cross_findings: 0" is the same answer whether there were no components, no resolved
    links, no tainted data reaching the boundary, or a boundary the callee simply does not
    misuse -- and those call for four different next actions. The only clue was
    `components_analyzed`, which reads as a count, not a diagnosis: on a program/library pair
    with a resolved edge it said 1, because the loop stopped before loading the callee."""
    from lykos.analyze.link.crosstaint import _why_nothing
    base = {"no_components": False, "no_links": False, "callers_without_ir": 0,
            "components_over_cap": 0,
            "edges_without_tainted_symbol": 0, "edges_with_clean_callee": 0}
    assert "only one component" in _why_nothing({**base, "no_components": True}, 0)
    assert "Run link_case" in _why_nothing({**base, "no_links": True}, 0)
    assert "no tainted argument" in _why_nothing(
        {**base, "edges_without_tainted_symbol": 2}, 0)
    # the case that is a RESULT rather than a gap, and must not read like one
    clean = _why_nothing({**base, "edges_with_clean_callee": 1}, 0)
    assert "real negative, not a missing analysis" in clean
    # The dangerous one: the data-flow engine returns empty above its function ceiling and
    # says nothing, so without this check the "real negative" message below could be printed
    # about an analysis that never ran -- a false negative stated with confidence, in a
    # message added to explain zeros. It has to outrank the negative claim.
    cap = _why_nothing({**base, "components_over_cap": 1, "edges_with_clean_callee": 1}, 0)
    assert "did not run" in cap and "not a negative result" in cap
    assert "real negative" not in cap, "the ceiling must outrank the clean-callee claim"
    # "not decompiled yet" is a different problem from "the data does not reach the
    # boundary", and only one of the two is actionable. Carved firmware components arrive
    # with no IR at all, and the message used to blame the data flow.
    noir = _why_nothing({**base, "callers_without_ir": 1}, 0)
    assert "not been decompiled" in noir and "Run disassemble" in noir
    # nothing to explain when something was found
    assert _why_nothing({**base, "no_components": True}, 3) is None


def test_a_firmware_container_is_recognised_not_dismissed():
    """A U-Boot image was `other`, so advice said "this file is not a recognised executable,
    library or firmware image, so there is nothing to run or decompile" -- about an image the
    carve stage then pulled two executables and an RSA private key out of. The plan underneath
    already said firmware_carve; the sentence above it disagreed, and the sentence is what
    gets read."""
    from lykos.analyze import filetype
    from lykos.analyze.advise import advise
    uimage = b"\x27\x05\x19\x56" + b"\x00" * 60
    assert filetype.detect(uimage) == filetype.FIRMWARE
    assert filetype.firmware_kind(uimage) == "U-Boot uImage"
    out = advise(imports=[], functions=0, findings=0, seeds=0, has_format=False,
                 afl_usable=False, executable=True, file_format="firmware")
    assert out["analysable"] is True
    assert out["backend"] == "firmware_carve"
    assert "container, not a program" in out["headline"]
    assert [p["stage"] for p in out["plan"]] == ["firmware_carve", "firmware_rehost"]


def test_the_firmware_magics_agree_with_what_carve_scans_for():
    """Two lists, one truth. filetype decides what a file IS (container magic at offset 0);
    carve scans for anything embedded at any offset, so it is a superset -- but every
    container magic must appear in both or a format is detectable and uncarvable, or the
    reverse."""
    from lykos.analyze import filetype
    from lykos.analyze.firmware.carve import SIGNATURES
    known = {m for m, _t, _d in SIGNATURES}
    for magic, desc in filetype.FIRMWARE_MAGICS:
        assert magic in known, f"{desc} is detected but carve does not scan for it"


def test_an_elf_is_still_an_elf():
    """The firmware check runs before the zip check and after the executable ones; a
    regression here would reclassify real binaries."""
    from lykos.analyze import filetype
    assert filetype.detect(b"\x7fELF" + b"\x00" * 60) == filetype.ELF
    assert filetype.detect(b"MZ" + b"\x00" * 62) == filetype.PE
    assert filetype.detect(b"PK\x03\x04" + b"\x00" * 60) == filetype.JAR


def test_the_builder_suggests_the_real_model_when_one_exists():
    """The builder derived magic and hunted a length field from the bytes alone, which for a
    JPEG produced two fields -- magic and a blob -- while builtin("jpeg") describes the segment
    chain and the nested IFD arrays and is what the campaign would choose anyway. Two places
    answered "what format is this" and the one the GUI called was the weaker."""
    from lykos.analyze.fuzz import structure
    jpeg = bytes.fromhex("ffd8ffe000104a46494600010100000100010000") + b"\xff" * 200
    got = structure.suggest_spec(jpeg)
    assert got["builtin"] == "jpeg"
    assert len(got["spec"]) > 5, got["spec"]
    assert "built-in model" in got["notes"][0]
    # JSON-safe: magic values are bytes in the model and must survive the response
    import json
    json.dumps(got)


def test_the_builder_says_a_text_config_is_not_a_byte_grammar():
    """A magic/length/blob spec cannot describe key=value text, and offering to build one
    invites the operator to make something that cannot work. This is the shape most
    config-driven targets take."""
    from lykos.analyze.fuzz import structure
    got = structure.suggest_spec(b"# cfg\nname=prod\nlisten=0.0.0.0:80\nworkers=4\n")
    assert got["builtin"] == "keyvalue"
    assert got["spec"] == []
    assert "not a byte grammar" in got["notes"][0]
    assert "automatically" in got["notes"][0]


def test_an_unknown_binary_still_gets_a_starting_spec():
    """The generic path has to survive: that is what the builder is FOR."""
    from lykos.analyze.fuzz import structure
    got = structure.suggest_spec(b"\x01\x02\x03\x04" + b"ZZZZ" * 40)
    assert got.get("builtin") is None
    assert [f["type"] for f in got["spec"]][:1] == ["magic"]
    assert got["notes"]
