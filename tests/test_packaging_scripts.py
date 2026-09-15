"""The air-gap packaging scripts and the docs that describe them.

The failure these guard against is drift, and it is expensive precisely because it is
invisible until someone is standing at an air-gapped machine with a bundle that is missing the
thing they came for. The package list lives in `lykos.toolchain`; the collector must read it
from there rather than keeping its own copy, and the runbook must not contradict it.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "packaging"
DOCS = ROOT / "docs"


def _sh(name):
    p = PKG / name
    assert p.exists(), f"{name} is missing"
    return p


@pytest.mark.parametrize("script", ["build.sh", "verify.sh", "collect-toolchain.sh",
                                    "install-toolchain.sh", "build-symqemu.sh"])
def test_every_packaging_script_is_valid_shell_and_executable(script):
    p = _sh(script)
    assert p.stat().st_mode & 0o111, f"{script} is not executable"
    r = subprocess.run(["bash", "-n", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, f"{script}: {r.stderr}"


@pytest.mark.parametrize("script", ["build.sh", "verify.sh", "collect-toolchain.sh",
                                    "install-toolchain.sh"])
def test_every_packaging_script_fails_fast(script):
    """Without `set -e` a failed step scrolls past and the script reports success -- which for
    a bundle means shipping an incomplete one to a machine that cannot fix it."""
    # the whole preamble, not a byte count: a long comment header is not a defect
    head = _sh(script).read_text().split("\n\n", 1)[0]
    assert re.search(r"set -[a-z]*e", head), f"{script} does not set -e"
    assert "pipefail" in head, f"{script} does not set pipefail"


def test_the_collector_takes_its_package_list_from_the_code():
    """A second copy of the list in shell would drift from `lykos doctor` silently, and the
    first symptom is a missing engine on the air-gapped side."""
    src = _sh("collect-toolchain.sh").read_text()
    assert "toolchain.apt_packages()" in src, \
        "the collector hard-codes its package list instead of reading lykos.toolchain"


def test_the_collector_bundles_the_installer_and_checksums_everything():
    src = _sh("collect-toolchain.sh").read_text()
    assert "install-toolchain.sh" in src, "the bundle ships without its installer"
    assert "sha256sum" in src and "SHA256SUMS" in src, "the bundle is not checksummed"


def test_the_installer_verifies_before_it_installs():
    """Order matters: a bundle that is corrupt or was tampered with in transit must be
    refused, not partially applied and then discovered."""
    src = _sh("install-toolchain.sh").read_text()
    verify_at = src.index("sha256sum")
    install_at = src.index("dpkg -i")
    assert verify_at < install_at, "the installer installs before it verifies"
    assert "--verify-only" in src, "there is no way to check a bundle without installing it"
    assert "|| die" in src or "|| exit" in src, "a failed checksum does not stop the install"


def test_the_installer_ends_by_reporting_capabilities_rather_than_claiming_success():
    """"Installed OK" is not a useful statement on an air-gapped host. What works is."""
    src = _sh("install-toolchain.sh").read_text()
    assert "lykos doctor" in src


def test_the_installer_repoints_a_venv_at_this_hosts_python():
    """A venv records the interpreter it was built against; copied to another machine it
    points at a path that may not exist. Silently, until the engine is first used."""
    src = _sh("install-toolchain.sh").read_text()
    assert "pyvenv.cfg" in src
    assert "WARNING" in src, "a venv that does not run here is not reported"


def test_the_airgap_runbook_exists_and_covers_both_sides():
    doc = (DOCS / "23-airgap-install.md").read_text()
    assert "collect-toolchain.sh" in doc
    # the bundle stages the installer as install.sh, so the runbook names that
    assert "install.sh" in doc
    assert "--verify-only" in doc
    assert "doctor" in doc


def test_the_runbook_documents_every_required_tool():
    from lykos import toolchain
    doc = (DOCS / "23-airgap-install.md").read_text().lower()
    for t in toolchain.TOOLS:
        if t.tier == "required":
            assert t.title.split()[0].lower() in doc, f"{t.title} is not in the runbook"


def test_the_runbook_states_the_afl_qemu_trap():
    """`file` reports the HOST architecture of an emulator whose guest is fixed at build time.
    Anyone provisioning coverage fuzzing air-gapped will hit this, and the symptom is a
    campaign that aborts at the fork-server handshake."""
    doc = (DOCS / "23-airgap-install.md").read_text()
    assert "afl-qemu-trace" in doc and "--version" in doc


def test_the_readme_indexes_every_doc():
    """The index is how anyone finds these; a doc missing from it is a doc nobody reads."""
    readme = (ROOT / "README.md").read_text()
    for p in sorted(DOCS.glob("*.md")):
        assert p.name in readme, f"docs/{p.name} is not in the README index"


def test_the_readme_documents_every_make_target():
    readme = (ROOT / "README.md").read_text()
    mk = (ROOT / "Makefile").read_text()
    targets = {m.group(1) for m in re.finditer(r"^([a-z][a-z-]*):", mk, re.M)}
    for t in targets - {"help"}:
        assert f"make {t}" in readme, f"`make {t}` is undocumented"


def test_the_readme_does_not_promise_a_ci_workflow_that_does_not_exist():
    readme = (ROOT / "README.md").read_text()
    if ".github/workflows" in readme:
        assert (ROOT / ".github" / "workflows").is_dir(), \
            "the README describes a CI workflow that is not in the repository"


@pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")
def test_the_installer_refuses_a_directory_that_is_not_a_bundle(tmp_path):
    r = subprocess.run(["bash", str(_sh("install-toolchain.sh")), "--verify-only"],
                       cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert r.returncode != 0
    assert "not a lykos toolchain bundle" in (r.stdout + r.stderr)


def _make_bundle(tmp_path):
    """A minimal but well-formed bundle: install.sh + one deb, checksummed the way the
    collector writes SHA256SUMS (paths like ./install.sh, ./debs/a.deb)."""
    import hashlib
    bundle = tmp_path / "bundle"
    (bundle / "debs").mkdir(parents=True)
    deb = bundle / "debs" / "a.deb"
    deb.write_bytes(b"a real, listed package")
    inst = bundle / "install.sh"
    shutil.copy2(_sh("install-toolchain.sh"), inst)

    def _h(p):
        return hashlib.sha256(p.read_bytes()).hexdigest()

    (bundle / "SHA256SUMS").write_text(
        f"{_h(inst)}  ./install.sh\n{_h(deb)}  ./debs/a.deb\n")
    return bundle, inst


@pytest.mark.skipif(not (shutil.which("bash") and shutil.which("comm")),
                    reason="needs bash + coreutils comm")
def test_the_installer_refuses_a_bundle_with_an_unlisted_file(tmp_path):
    """`sha256sum -c` only checks the files it names, so an added .deb would pass verification
    and then be swept into the `debs/*.deb` install. The installer must reject any file present
    but not listed -- otherwise the checksum is false assurance on the exact air-gap machine
    that cannot recover from a bad install."""
    bundle, inst = _make_bundle(tmp_path)
    # baseline: the well-formed bundle verifies clean
    r = subprocess.run(["bash", str(inst), "--verify-only"], cwd=bundle,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr

    # smuggle in an unlisted deb: every LISTED file still matches its checksum, but the SET does
    # not -- the glob would install this. Verification must now fail.
    (bundle / "debs" / "evil.deb").write_bytes(b"unlisted, would ride the glob")
    r = subprocess.run(["bash", str(inst), "--verify-only"], cwd=bundle,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode != 0, "an unlisted file passed verification"
    assert "not named in SHA256SUMS" in (r.stdout + r.stderr)
    assert "evil.deb" in (r.stdout + r.stderr)


def test_the_installer_asserts_the_file_set_matches_the_manifest():
    """Static guard so the set-equality check is not quietly dropped in a later edit."""
    src = _sh("install-toolchain.sh").read_text()
    assert "not named in SHA256SUMS" in src
    assert "comm -13" in src or "comm -3" in src


def test_the_installer_does_not_overclaim_tamper_resistance():
    """SHA256SUMS is unsigned; the wording must promise corruption-resistance, not authenticity,
    and point at signing as the future step."""
    src = _sh("install-toolchain.sh").read_text().lower()
    assert "unsigned" in src
    assert "sign" in src  # names signing as the future step


def test_the_zipapp_build_needs_no_network():
    """The runtime is stdlib-only, so the build must not fetch anything -- it is the artifact
    that goes to a machine with no network."""
    src = _sh("build.sh").read_text()
    for fetch in ("pip install", "curl", "wget", "git clone"):
        assert fetch not in src, f"build.sh reaches the network: {fetch}"
