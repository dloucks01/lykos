"""The offline e2e gate must be able to unpack a SPLIT (large, real-engagement) bundle.

make-runnable.sh splits a package bigger than one optical disc into *.tar.xz.part-NN volumes with a
.sha256 and an .EXTRACT.sh; test-offline-e2e.sh used to accept only a whole .tar.xz, so exactly the
bundles that matter were never functionally gated. This runs the gate's package-resolution and
extraction prefix (no container) against a miniature split package built the same way.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "packaging" / "test-offline-e2e.sh"
MAKER = ROOT / "packaging" / "make-runnable.sh"

pytestmark = pytest.mark.skipif(not (shutil.which("xz") and shutil.which("split")
                                     and shutil.which("sha256sum") and shutil.which("gcc")
                                     and shutil.which("bash")),
                                reason="needs xz, split, sha256sum, gcc, bash")


def _gate_prefix(tmp_path: Path) -> Path:
    """The gate up to (and including) locating the extracted launcher dir, then report it."""
    src = GATE.read_text()
    marker = '[ -n "$RD" ] && [ -d "$RD" ] || die'
    end = src.index("\n", src.index(marker))
    out = tmp_path / "gate-prefix.sh"
    out.write_text(src[:end] + '\necho "EXTRACTED=$RD"\n')
    return out


def _extract_script() -> str:
    src = MAKER.read_text()
    start = src.index("<<'XEOF'\n") + len("<<'XEOF'\n")
    return src[start:src.index("\nXEOF\n", start) + 1]


def _package(dist: Path, *, split_bytes=None, base="lykos-offline-20990101-x86_64"):
    stage = dist.parent / "stage"
    (stage / "lykos").mkdir(parents=True)
    launcher = stage / "lykos" / "lykos"
    launcher.write_text("#!/bin/sh\necho lykos\n")
    launcher.chmod(0o755)
    (stage / "lykos" / "blob.bin").write_bytes(os.urandom(64 * 1024))   # incompressible: >1 volume
    dist.mkdir()
    tar = dist / f"{base}.tar"
    with tarfile.open(tar, "w") as tf:
        tf.add(stage / "lykos", arcname="lykos")
    subprocess.run(["xz", "-0", str(tar)], check=True)
    if split_bytes:
        subprocess.run(["split", "-b", str(split_bytes), "-d", "-a", "2", f"{base}.tar.xz",
                        f"{base}.tar.xz.part-"], cwd=dist, check=True)
        (dist / f"{base}.tar.xz").unlink()
        parts = sorted(p.name for p in dist.glob(f"{base}.tar.xz.part-*"))
    else:
        parts = [f"{base}.tar.xz"]
    sums = subprocess.run(["sha256sum", *parts], cwd=dist, capture_output=True, text=True,
                          check=True).stdout
    (dist / f"{base}.sha256").write_text(sums)
    ex = dist / f"{base}.EXTRACT.sh"
    ex.write_text(_extract_script())
    ex.chmod(0o755)
    return base, parts


def _run_gate(script: Path, arg: Path):
    env = dict(os.environ, RT="true")                # no container needed for the prefix
    return subprocess.run(["bash", str(script), str(arg)], capture_output=True, text=True,
                          timeout=120, env=env)


def test_gate_extracts_a_split_package_through_its_extract_script(tmp_path):
    dist = tmp_path / "dist"
    base, parts = _package(dist, split_bytes=20000)
    assert len(parts) >= 3
    r = _run_gate(_gate_prefix(tmp_path), dist / parts[0])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SPLIT into" in r.stdout and "verifying checksums" in r.stdout
    assert "EXTRACTED=" in r.stdout


def test_gate_names_a_missing_volume(tmp_path):
    dist = tmp_path / "dist"
    base, parts = _package(dist, split_bytes=20000)
    (dist / parts[1]).unlink()
    r = _run_gate(_gate_prefix(tmp_path), dist / parts[0])
    assert r.returncode != 0 and parts[1] in r.stderr, r.stderr


def test_gate_still_takes_a_single_archive(tmp_path):
    dist = tmp_path / "dist"
    base, parts = _package(dist)
    r = _run_gate(_gate_prefix(tmp_path), dist / parts[0])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "single archive" in r.stdout and "EXTRACTED=" in r.stdout
