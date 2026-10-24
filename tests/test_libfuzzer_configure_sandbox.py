"""libFuzzer's `./configure` is the project's own -- untrusted -- shell script. It used to run
unconfined on the host while the build step beside it was sandboxed; it now runs under the same
confinement: only the project tree is writable, no network, a fresh /tmp."""
import os
import stat

import pytest
from lykos.analyze import libfuzzer as LF
from lykos.analyze.dynamic import sandbox


def _project(tmp_path, outside):
    root = tmp_path / "proj"
    root.mkdir()
    (root / "conf.h.in").write_text("#define X @X@\n")
    conf = root / "configure"
    # a hostile configure: tries to plant a file OUTSIDE the tree, then does its legitimate job
    conf.write_text("#!/bin/sh\n"
                    f"echo pwned > '{outside}' 2>/dev/null\n"
                    "echo '#define X 1' > conf.h\n"
                    "exit 0\n")
    conf.chmod(conf.stat().st_mode | stat.S_IXUSR)
    return root


@pytest.mark.skipif(not sandbox._bwrap_usable(), reason="bwrap unusable on this host")
def test_configure_cannot_write_outside_the_tree(tmp_path, monkeypatch):
    monkeypatch.delenv("LYKOS_BUILD_UNCONFINED", raising=False)
    outside = tmp_path / "planted.txt"
    root = _project(tmp_path, outside)
    rep: dict = {}
    assert LF.ensure_configured(root, timeout=60, report=rep) is True
    assert rep == {"ran": True, "confined": True, "rc": 0}
    assert (root / "conf.h").read_text().strip() == "#define X 1"    # its own job still done
    assert not outside.exists()                                       # ... and nothing else


def test_configure_unconfined_is_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("LYKOS_BUILD_UNCONFINED", "1")
    outside = tmp_path / "planted.txt"
    root = _project(tmp_path, outside)
    rep: dict = {}
    assert LF.ensure_configured(root, timeout=60, report=rep) is True
    assert rep["ran"] and rep["confined"] is False        # degradation is visible to the caller


def test_configure_not_run_when_configured(tmp_path):
    root = _project(tmp_path, tmp_path / "x")
    (root / "conf.h").write_text("#define X 1\n")
    rep: dict = {}
    assert LF.ensure_configured(root, report=rep) is False
    assert rep == {}
    assert os.path.exists(root / "conf.h")
