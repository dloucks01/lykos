"""P0.10 — the packaged zipapp builds offline and runs."""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_build_and_run_pyz(tmp_path):
    r = subprocess.run(["bash", str(ROOT / "packaging" / "build.sh")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    pyz = ROOT / "dist" / "lykos.pyz"
    assert pyz.exists()

    cs = tmp_path / "cs"
    init = subprocess.run([sys.executable, str(pyz), "db", "init", "--case-store", str(cs)],
                          capture_output=True, text=True)
    assert init.returncode == 0, init.stderr
    ver = subprocess.run([sys.executable, str(pyz), "db", "version", "--case-store", str(cs)],
                         capture_output=True, text=True)
    assert ver.returncode == 0, ver.stderr
    assert ver.stdout.strip().isdigit() and int(ver.stdout.strip()) >= 2
