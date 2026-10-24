"""vendored_python must pick the bundle's real interpreter, never python3.N-config."""
from lykos import vendorenv


def _exe(p):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("#!/bin/sh\n")
    p.chmod(0o755)


def test_vendored_python_ignores_config_scripts_and_sorts_minors_numerically(tmp_path):
    b = tmp_path / "usr" / "bin"
    for n in ("python3.9", "python3.13", "python3.13-config", "python3.13m"):
        _exe(b / n)
    assert vendorenv.vendored_python(tmp_path) == b / "python3.13"


def test_vendored_python_falls_back_to_python3(tmp_path):
    b = tmp_path / "usr" / "bin"
    _exe(b / "python3")
    _exe(b / "python3.14-config")
    assert vendorenv.vendored_python(tmp_path) == b / "python3"
