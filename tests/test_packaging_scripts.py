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
                                    "setup-toolchain.sh", "make-runnable.sh", "build-symqemu.sh"])
def test_every_packaging_script_is_valid_shell_and_executable(script):
    p = _sh(script)
    assert p.stat().st_mode & 0o111, f"{script} is not executable"
    r = subprocess.run(["bash", "-n", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, f"{script}: {r.stderr}"


@pytest.mark.parametrize("script", ["build.sh", "verify.sh", "collect-toolchain.sh",
                                    "setup-toolchain.sh", "make-runnable.sh"])
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
    assert "toolchain.apt_packages(" in src, \
        "the collector hard-codes its package list instead of reading lykos.toolchain"


def test_the_collector_bundles_the_installer_and_checksums_everything():
    src = _sh("collect-toolchain.sh").read_text()
    assert "setup-toolchain.sh" in src, "the bundle ships without its installer"
    assert "sha256sum" in src and "SHA256SUMS" in src, "the bundle is not checksummed"


def test_setup_verifies_before_it_places_anything():
    """Order matters: a bundle that is corrupt or was tampered with in transit must be
    refused, not partially placed and then discovered."""
    src = _sh("setup-toolchain.sh").read_text()
    verify_at = src.index("sha256sum")
    place_at = src.index('cp -a "$HERE/toolchain"')
    assert verify_at < place_at, "setup places files before it verifies"
    assert "--verify-only" in src, "there is no way to check a bundle without placing it"
    assert "|| die" in src or "|| exit" in src, "a failed checksum does not stop setup"


def test_setup_installs_nothing_into_the_system():
    """The whole point of the run-in-place bundle: no root, no package manager, nothing in a
    system directory. A regression that reintroduced `sudo dpkg -i` or wrote to /usr would put
    the air-gapped host back in the exact state this design removed."""
    src = _sh("setup-toolchain.sh").read_text()
    for banned in ("sudo", "dpkg", "apt-get", "apt install"):
        assert banned not in src, f"setup touches the system via {banned!r}"
    # every destination it writes to is under $DEST (the repo's vendor/), never a bare system
    # path -- so no `install`/`cp` into /usr, /bin, /opt, /etc
    sys_write = re.compile(
        r'(?:install -m \S+|cp -a|mkdir -p) (?:"?\$\w+/)?("?/(?:usr|bin|opt|etc|lib)\S*)')
    for m in sys_write.finditer(src):
        raise AssertionError(f"setup writes to a system path: {m.group(1)}")
    # it places under the repo's vendor/, where lykos finds it on its own PATH
    assert "vendor" in src and "run" in src.lower()


def test_setup_never_puts_bundle_libraries_on_a_shared_search_path():
    """The failure the operator is guarding against: a bundle library shadowing the laptop's
    own, which is how a mismatched lib breaks system tooling (and, when it was dpkg, the boot).
    Setup must not export a process-wide LD_LIBRARY_PATH / LD_PRELOAD; bundle libraries are made
    reachable only through the per-tool scoped wrappers."""
    src = _sh("setup-toolchain.sh").read_text()
    # the only LD_LIBRARY_PATH mention allowed is the one written INTO a wrapper (indented under
    # gen_wrappers, via printf), never a bare top-level `export LD_LIBRARY_PATH=` for the whole
    # setup process
    for line in src.splitlines():
        s = line.strip()
        if s.startswith("export LD_LIBRARY_PATH") or s.startswith("export LD_PRELOAD"):
            raise AssertionError(f"setup exports a shared library path: {s!r}")
    assert "gen_wrappers" in src, "setup does not generate scoped wrappers"


def test_a_generated_wrapper_scopes_the_library_path_and_execs_the_real_binary(tmp_path):
    """Run the wrapper generator for real and inspect a wrapper: it must set LD_LIBRARY_PATH for
    its own process only (a plain `export` in a one-shot shim, inherited by nothing the laptop
    runs) and then exec the vendored binary."""
    tc = tmp_path / "toolchain"
    (tc / "usr" / "bin").mkdir(parents=True)
    (tc / "usr" / "lib" / "x86_64-linux-gnu").mkdir(parents=True)
    realtool = tc / "usr" / "bin" / "gdb"
    realtool.write_text("#!/bin/sh\necho real\n")
    realtool.chmod(0o755)
    # call just the gen_wrappers function out of the script
    script = _sh("setup-toolchain.sh").read_text()
    func = script[script.index("gen_wrappers() {"):script.index("# 1. The extracted")]
    r = subprocess.run(["bash", "-c", f'{func}\ngen_wrappers "$1"', "_", str(tc)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    wrapper = tc / ".wrappers" / "gdb"
    assert wrapper.exists(), "no wrapper was generated for the vendored gdb"
    body = wrapper.read_text()
    # RELOCATABLE: no absolute path baked in; the root is resolved from the wrapper location and
    # libs/exec are prefixed with $r. So the tree can be unzipped anywhere and just run.
    assert str(tc) not in body, "wrapper baked an absolute path (not relocatable)"
    assert "cd -- " in body and 'dirname -- "$0"' in body, "wrapper does not resolve its own root"
    assert 'export LD_LIBRARY_PATH="' in body
    assert "$r/usr/lib/x86_64-linux-gnu" in body, "wrapper omits the (relative) bundle libs"
    assert 'exec "$r/usr/bin/gdb" "$@"' in body, "wrapper does not exec the real binary via $r"
    # and it actually runs, resolving $r from its own location
    run = subprocess.run(["sh", str(wrapper)], capture_output=True, text=True, timeout=10)
    assert run.stdout.strip() == "real", run.stderr
    # relocation proof: copy the whole tree elsewhere and the wrapper still runs
    dst = tmp_path / "moved"
    shutil.copytree(tc, dst / "toolchain")
    run2 = subprocess.run(["sh", str(dst / "toolchain" / ".wrappers" / "gdb")],
                          capture_output=True, text=True, timeout=10)
    assert run2.stdout.strip() == "real", "wrapper broke after relocation: " + run2.stderr

def test_the_collector_extracts_debs_rather_than_shipping_them():
    """A dpkg install is what we removed. The collector must EXTRACT each deb into the
    relocatable toolchain/ tree; a bundle that still carried raw .deb files would invite the
    old install path back."""
    for name in ("collect-toolchain.sh", "_collect-here.sh"):
        src = _sh(name).read_text()
        assert "dpkg-deb -x" in src, f"{name} does not extract debs into toolchain/"
        assert "/stage/toolchain" in src or '"$WORK/toolchain"' in src, \
            f"{name} does not build a toolchain/ tree"


def test_the_installer_ends_by_reporting_capabilities_rather_than_claiming_success():
    """"Installed OK" is not a useful statement on an air-gapped host. What works is."""
    src = _sh("setup-toolchain.sh").read_text()
    assert "lykos doctor" in src


def test_the_installer_repoints_a_venv_at_this_hosts_python():
    """A venv records the interpreter it was built against; copied to another machine it
    points at a path that may not exist. Silently, until the engine is first used."""
    src = _sh("setup-toolchain.sh").read_text()
    assert "pyvenv.cfg" in src
    assert "WARNING" in src, "a venv that does not run here is not reported"


def test_the_offline_runbook_exists_and_covers_both_sides():
    doc = (DOCS / "offline-packaging.md").read_text()
    assert "collect-toolchain.sh" in doc
    # the bundle stages the setup script as setup.sh, so the runbook names that
    assert "setup.sh" in doc
    assert "--verify-only" in doc
    assert "doctor" in doc


def test_the_runbook_documents_every_required_tool():
    from lykos import toolchain
    doc = (DOCS / "offline-packaging.md").read_text().lower()
    for t in toolchain.TOOLS:
        if t.tier == "required":
            assert t.title.split()[0].lower() in doc, f"{t.title} is not in the runbook"


def test_the_runbook_states_the_afl_qemu_trap():
    """`file` reports the HOST architecture of an emulator whose guest is fixed at build time.
    Anyone provisioning coverage fuzzing offline will hit this, and the symptom is a
    campaign that aborts at the fork-server handshake."""
    doc = (DOCS / "offline-packaging.md").read_text()
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
    r = subprocess.run(["bash", str(_sh("setup-toolchain.sh")), "--verify-only"],
                       cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert r.returncode != 0
    assert "not a lykos toolchain bundle" in (r.stdout + r.stderr)


def _make_bundle(tmp_path):
    """A minimal but well-formed bundle: setup.sh + one file in the toolchain tree, checksummed
    the way the collector writes SHA256SUMS (paths like ./setup.sh, ./toolchain/usr/bin/x)."""
    import hashlib
    bundle = tmp_path / "bundle"
    (bundle / "toolchain" / "usr" / "bin").mkdir(parents=True)
    tool = bundle / "toolchain" / "usr" / "bin" / "x"
    tool.write_bytes(b"a real, listed binary")
    inst = bundle / "setup.sh"
    shutil.copy2(_sh("setup-toolchain.sh"), inst)

    def _h(p):
        return hashlib.sha256(p.read_bytes()).hexdigest()

    (bundle / "SHA256SUMS").write_text(
        f"{_h(inst)}  ./setup.sh\n{_h(tool)}  ./toolchain/usr/bin/x\n")
    return bundle, inst


@pytest.mark.skipif(not (shutil.which("bash") and shutil.which("comm")),
                    reason="needs bash + coreutils comm")
@pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")
def test_setup_verifies_a_bundle_with_a_backslash_in_a_filename(tmp_path):
    """Regression: the real toolchain pulls in systemd `\\x2d...` .slice units, whose names make
    sha256sum emit its backslash-escaped line format. A filename-parsing set-equality check
    mangles those and falsely rejects a good bundle. The count-based check must accept it."""
    bundle = tmp_path / "bundle"
    (bundle / "toolchain" / "usr" / "bin").mkdir(parents=True)
    normal = bundle / "toolchain" / "usr" / "bin" / "gdb"
    normal.write_bytes(b"a normal tool")
    # a name with a backslash -> sha256sum writes a `\`-prefixed, `\\`-escaped line
    weird = bundle / "toolchain" / "slice" / r"system-systemd\x2dfoo.slice"
    weird.parent.mkdir(parents=True)
    weird.write_bytes(b"a unit file with an odd name")
    inst = bundle / "setup.sh"
    shutil.copy2(_sh("setup-toolchain.sh"), inst)
    # generate SHA256SUMS exactly like the collector (sha256sum escapes the odd name itself)
    r = subprocess.run(
        "find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS",
        cwd=bundle, shell=True, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    # sanity: the manifest really does contain an escaped line, so this exercises the bug
    sums = (bundle / "SHA256SUMS").read_text()
    assert any(line.startswith("\\") for line in sums.splitlines()), \
        "test did not produce an escaped manifest line -- it is not exercising the bug"
    r = subprocess.run(["bash", str(inst), "--verify-only"], cwd=bundle,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"good bundle rejected: {r.stdout + r.stderr}"
    assert "no extras" in (r.stdout + r.stderr)


def test_setup_refuses_a_bundle_with_an_unlisted_file(tmp_path):
    """`sha256sum -c` only checks the files it names, so a file added under toolchain/ would
    pass verification and then be copied wholesale into vendor/ when the tree is placed. Setup
    must reject any file present but not listed -- otherwise the checksum is false assurance on
    the exact air-gap machine that cannot recover from a bad tree."""
    bundle, inst = _make_bundle(tmp_path)
    # baseline: the well-formed bundle verifies clean
    r = subprocess.run(["bash", str(inst), "--verify-only"], cwd=bundle,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr

    # smuggle in an unlisted binary: every LISTED file still matches its checksum, but the SET
    # does not -- the wholesale copy would carry this into vendor/. Verification must now fail.
    (bundle / "toolchain" / "usr" / "bin" / "evil").write_bytes(b"unlisted, would ride along")
    r = subprocess.run(["bash", str(inst), "--verify-only"], cwd=bundle,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode != 0, "an unlisted file passed verification"
    assert "not named in SHA256SUMS" in (r.stdout + r.stderr)
    assert "evil" in (r.stdout + r.stderr)


def test_the_installer_asserts_the_file_set_matches_the_manifest():
    """Static guard so the set-equality check is not quietly dropped in a later edit."""
    src = _sh("setup-toolchain.sh").read_text()
    assert "not named in SHA256SUMS" in src
    assert "comm -13" in src or "comm -3" in src


def test_the_installer_does_not_overclaim_tamper_resistance():
    """SHA256SUMS is unsigned; the wording must promise corruption-resistance, not authenticity,
    and point at signing as the future step."""
    src = _sh("setup-toolchain.sh").read_text().lower()
    assert "unsigned" in src
    assert "sign" in src  # names signing as the future step


def test_the_zipapp_build_needs_no_network():
    """The runtime is stdlib-only, so the build must not fetch anything -- it is the artifact
    that goes to a machine with no network."""
    src = _sh("build.sh").read_text()
    for fetch in ("pip install", "curl", "wget", "git clone"):
        assert fetch not in src, f"build.sh reaches the network: {fetch}"


# ---- the web UI ships intact ----------------------------------------------------------------
#
# make-runnable builds the package with `git add -A` + `git archive`, which SKIP git-ignored
# files. A too-broad `vendor/` ignore once matched core/lykos/api/static/vendor/ and shipped a
# blank UI: the import map pointed at a Preact runtime that was not in the zip. Every other test
# reads the working tree, where the files exist, so nothing caught it. These read git's own view.

_STATIC = ROOT / "core/lykos/api/static"
_UI_RUNTIME = [
    "core/lykos/api/static/vendor/preact.module.js",
    "core/lykos/api/static/vendor/hooks.module.js",
    "core/lykos/api/static/vendor/htm.module.js",
    "core/lykos/api/static/app/app.js",
]


@pytest.mark.parametrize("rel", _UI_RUNTIME)
def test_web_ui_runtime_is_not_git_ignored(rel):
    """A file git ignores is a file `git archive` drops from the air-gap package."""
    assert (ROOT / rel).exists(), f"{rel} is missing from the working tree"
    r = subprocess.run(["git", "check-ignore", "-q", rel], cwd=ROOT)
    # exit 0 == the path IS ignored (and would be dropped from the package); 1 == not ignored.
    assert r.returncode != 0, f"{rel} is git-ignored and would not ship in the package"


def test_web_ui_runtime_ships_via_git_archive():
    """End-to-end: the files the import map references must actually be inside a git archive of
    the working tree -- the exact mechanism make-runnable uses to assemble the package."""
    import tempfile
    import os
    with tempfile.TemporaryDirectory() as td:
        idx = os.path.join(td, "index")
        env = {**os.environ, "GIT_INDEX_FILE": idx}
        # Seed the temp index from HEAD so untracked-but-unignored files are added on top, the
        # way make-runnable does, without touching the real index or HEAD.
        subprocess.run(["git", "read-tree", "HEAD"], cwd=ROOT, env=env, check=True)
        subprocess.run(["git", "add", "-A"], cwd=ROOT, env=env, check=True)
        tree = subprocess.run(["git", "write-tree"], cwd=ROOT, env=env,
                              check=True, capture_output=True, text=True).stdout.strip()
        listing = subprocess.run(["git", "ls-tree", "-r", "--name-only", tree], cwd=ROOT,
                                 check=True, capture_output=True, text=True).stdout
    shipped = set(listing.splitlines())
    for rel in _UI_RUNTIME:
        assert rel in shipped, f"{rel} would not be in the packaged archive"
    # And the import map's targets all resolve to files that ship.
    html = (_STATIC / "index.html").read_text()
    imap = re.search(r'<script type="importmap">(.*?)</script>', html, re.S)
    assert imap, "index.html has no import map"
    import json
    for spec, target in json.loads(imap.group(1))["imports"].items():
        rel = "core/lykos/api/static/" + target.lstrip("./")
        assert rel in shipped, f'import map "{spec}" -> {target} is not in the packaged archive'
