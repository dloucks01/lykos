"""include_dirs must add ANCESTOR dirs so a path-prefixed angle include (<freerdp/dvc.h>) resolves --
the bug that stopped FreeRDP's codec/channel fuzz harnesses from compiling (so nothing detonated)."""
import os
from pathlib import Path
from lykos.analyze.libfuzzer import include_dirs


def test_prefixed_angle_include_resolves_via_ancestor(tmp_path):
    (tmp_path / "include/freerdp").mkdir(parents=True)
    (tmp_path / "libfreerdp/codec").mkdir(parents=True)
    (tmp_path / "include/freerdp/dvc.h").write_text("int x;\n")
    (tmp_path / "libfreerdp/codec/clear.h").write_text("int y;\n")
    dirs = [str(d) for d in include_dirs(str(tmp_path))]
    assert str(tmp_path / "include") in dirs       # ancestor needed for <freerdp/dvc.h>
    assert str(tmp_path / "libfreerdp/codec") in dirs
