"""Copy the tools that are not apt-installable into a bundle staging directory.

Ghidra above all: it is a REQUIRED engine and a package only on Kali, so a bundle built from
the package list alone would arrive without the most important piece and say nothing about it
until the first `disassemble`. Called by collect-toolchain.sh; the path list comes from
lykos.toolchain so it cannot drift from what `lykos doctor` reports.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

from lykos import toolchain


def _size_mb(p: Path) -> float:
    if p.is_dir():
        return sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) / 1048576
    return p.stat().st_size / 1048576


def main(dest_arg: str) -> int:
    dest = Path(dest_arg)
    entries = toolchain.bundle_paths()
    if not entries:
        print("  none present on this host")
        return 0
    for key, paths in entries:
        d = dest / key
        d.mkdir(parents=True, exist_ok=True)
        for src in paths:
            src = Path(src)
            tgt = d / src.name
            if src.is_dir():
                shutil.copytree(src, tgt, dirs_exist_ok=True, symlinks=True)
            else:
                shutil.copy2(src, tgt)
            print(f"  {key}: {src} ({_size_mb(tgt):.0f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "extras"))
