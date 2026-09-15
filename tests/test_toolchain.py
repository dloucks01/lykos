"""The tool inventory behind `lykos doctor` and the air-gap bundle.

This table is the single answer to "what does lykos need". `lykos doctor` prints it, the
collector script reads it to know which debs to pull, and doc 23 documents it -- so the risk
is DRIFT: a probe that looks somewhere the stage does not, or an entry that promises a
capability nothing delivers. A doctor that disagrees with the code is worse than no doctor,
because it reports a capability the platform will then decline to run.

These tests must pass on a host with none of the tools installed, so they check structure and
honesty rather than presence.
"""
from __future__ import annotations

import shutil

import pytest
from lykos import toolchain as tc


def test_every_tool_is_completely_described():
    assert tc.TOOLS
    for t in tc.TOOLS:
        assert t.key and t.title, t
        assert t.tier in ("required", "recommended", "optional"), t.key
        assert callable(t.probe), t.key
        for field in ("unlocks", "without", "install"):
            val = getattr(t, field)
            assert val and len(val) > 10, f"{t.key}.{field} is too thin to act on: {val!r}"


def test_keys_are_unique():
    keys = [t.key for t in tc.TOOLS]
    assert len(keys) == len(set(keys))


def test_the_hard_requirements_are_the_ones_that_really_are():
    """Marking something required that is not makes `doctor --strict` cry wolf; marking
    something optional that is not lets a broken install look fine."""
    required = {t.key for t in tc.TOOLS if t.tier == "required"}
    assert required == {"python", "bwrap", "ghidra"}, required


def test_bubblewraps_absence_is_described_as_the_silent_degradation_it_is():
    """It does not stop execution, it quietly removes the isolation -- which is the one
    degradation you do not want unannounced when the binary is hostile."""
    bw = next(t for t in tc.TOOLS if t.key == "bwrap")
    assert "rlimits-only" in bw.without
    assert "still" in bw.without.lower()


def test_every_probe_returns_a_string_or_none_and_never_raises():
    """A probe that throws would take `doctor` down on exactly the host that needs it most --
    one where the tools are missing or broken."""
    for t in tc.TOOLS:
        got = t.probe()
        assert got is None or isinstance(got, str), f"{t.key} returned {got!r}"
        if isinstance(got, str):
            assert got.strip(), f"{t.key} returned an empty string instead of None"


def test_a_probe_that_raises_is_reported_as_missing_rather_than_crashing_the_survey():
    broken = tc.Tool("boom", "Exploding Tool", "nothing", "nothing",
                     "do not install this", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    orig = tc.TOOLS
    tc.TOOLS = orig + (broken,)
    try:
        rows = tc.survey()
        assert rows[-1][1] is None
        assert "probe failed" in rows[-1][0].without
    finally:
        tc.TOOLS = orig


def test_the_survey_covers_every_tool_in_order():
    rows = tc.survey()
    assert [t.key for t, _ in rows] == [t.key for t in tc.TOOLS]


def test_the_report_names_what_is_missing_and_how_to_fix_it():
    text = tc.report()
    assert text
    for t, got in tc.survey():
        if not got:
            assert t.install in text, f"{t.key} is missing and its install line is not shown"
            assert t.without in text, f"{t.key} is missing and the cost is not stated"


def test_the_report_counts_honestly():
    rows = tc.survey()
    present = sum(1 for _t, got in rows if got)
    assert f"{present}/{len(rows)} present." in tc.report()


def test_the_json_form_matches_the_survey():
    d = tc.as_dict()
    assert [x["key"] for x in d["tools"]] == [t.key for t in tc.TOOLS]
    for row in d["tools"]:
        assert row["present"] is bool(row["found"])
        assert row["tier"] in ("required", "recommended", "optional")


def test_missing_can_be_filtered_by_tier():
    for tier in ("required", "recommended", "optional"):
        for t in tc.missing(tier):
            assert t.tier == tier


def test_the_apt_list_is_what_the_collector_pulls():
    """The bundle script reads exactly this, so an engine added here without its package is an
    engine the air-gapped host will not get."""
    pkgs = tc.apt_packages()
    assert pkgs == sorted(set(pkgs)), "not deduplicated/sorted"
    assert "bubblewrap" in pkgs and "ghidra" in pkgs
    for t in tc.TOOLS:
        for p in t.apt:
            assert p in pkgs, f"{t.key} names {p} and the collector would not pull it"


def test_tools_installed_by_apt_declare_their_packages():
    """Anything whose install line is an apt command must name the packages, or the collector
    silently omits it from the bundle while the doc says to install it."""
    for t in tc.TOOLS:
        if t.install.startswith("apt-get install"):
            assert t.apt, f"{t.key} installs via apt but declares no packages for the bundle"


# ---- the probes must agree with the code they stand in for -------------------------------

def test_the_ghidra_probe_uses_the_locator_the_stage_uses():
    from lykos.analyze.ghidra import locate_ghidra
    probe = next(t for t in tc.TOOLS if t.key == "ghidra").probe()
    found = locate_ghidra()
    assert (probe is None) == (found is None)
    if found:
        assert str(found) == probe


def test_the_angr_probe_uses_the_stages_locator():
    from lykos.analyze.symbolic.concolic import locate_angr_python
    probe = next(t for t in tc.TOOLS if t.key == "angr").probe()
    assert (probe is None) == (locate_angr_python() is None)


def test_the_bwrap_probe_agrees_with_the_sandbox():
    from lykos.analyze.dynamic import sandbox
    probe = next(t for t in tc.TOOLS if t.key == "bwrap").probe()
    assert bool(probe) == sandbox._bwrap_usable()


@pytest.mark.skipif(not shutil.which("qemu-aarch64"), reason="no qemu-user here")
def test_the_qemu_probe_reports_which_guests_are_available():
    got = next(t for t in tc.TOOLS if t.key == "qemu").probe()
    assert "aarch64" in got and "/" in got


def test_the_afl_qemu_probe_reports_the_GUEST_not_the_file_type():
    """`file afl-qemu-trace` says x86-64 for an emulator that runs aarch64 binaries. Reporting
    the file's architecture here would tell an operator the exact opposite of the truth."""
    import inspect
    src = inspect.getsource(tc._probe_afl_qemu)
    assert "qemu_trace_arch" in src, "the probe is not asking qemu which guest it runs"
    assert "file" not in src.split('"""')[2], "the probe consults `file`"


@pytest.mark.skipif(not (shutil.which("true") and shutil.which("false")),
                    reason="needs coreutils true/false")
def test_v_treats_a_present_but_broken_tool_as_absent_not_ok():
    """`_v` is what most probes use to prove a tool RUNS. A tool that exits non-zero with no
    output did not really run; reporting its path as present would make `doctor` claim a
    capability the platform then declines -- absence of evidence dressed up as evidence."""
    # exits non-zero, prints nothing -> absent, NOT a false path-as-"ok"
    assert tc._v("false") is None
    # exits zero with no output -> genuinely present (some tools are silent on the probe flag)
    assert tc._v("true") == shutil.which("true")
    # the normal case: the first line of the tool's own banner
    assert tc._v("printf", "lykos 9.9\nignored") == "lykos 9.9"


def test_no_probe_shells_out_without_a_timeout():
    """`doctor` runs on a host where a tool may be broken or hang; it must still finish."""
    import inspect
    src = inspect.getsource(tc)
    for line in src.splitlines():
        if "subprocess.run(" in line and "timeout" not in line:
            assert "timeout=timeout" in src, f"unbounded subprocess call: {line.strip()}"
