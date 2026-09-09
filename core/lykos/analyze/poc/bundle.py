"""Self-contained PoC bundle builder (a .tar.gz an analyst can run offline)."""
from __future__ import annotations

import io
import json
import tarfile
import time


def _add(tar, name, data: bytes, mode=0o644):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(data))


def _runner(mode: str, argv, signal_name: str) -> bytes:
    if mode == "stdin":
        invoke = './target.bin < ./input.bin'
    elif mode == "file":
        invoke = './target.bin ./input.bin'
    elif mode == "arg":
        arg = argv[0] if argv else ""
        invoke = f'./target.bin {arg!r}'
    else:
        invoke = './target.bin'
    return ("#!/bin/sh\n"
            f"# PoC: reproduces {signal_name} in the target binary.\n"
            'cd "$(dirname "$0")"\n'
            "chmod +x ./target.bin\n"
            f"{invoke}\n"
            'rc=$?\n'
            f'echo "exit status: $rc (expected: crash by {signal_name}; '
            'shells report 128+signum)"\n').encode()


def _primitive_txt(prim: dict) -> bytes:
    lines = [
        "L2 exploitation primitive",
        "=========================",
        f"Primitive: {prim.get('type')}",
        f"Control offset: {prim.get('offset')} bytes",
        f"Sentinel: 0x{prim.get('marker', 0):x}",
        f"Observed program counter at fault: 0x{prim.get('observed_pc', 0):x}",
        f"Confirmed: {prim.get('confirmed')}",
        "",
        "input.bin places the sentinel address at the control offset. Under native execution",
        "the program counter is loaded with the sentinel, demonstrating full instruction-",
        "pointer control (not merely a crash). Register control (if any):",
    ]
    for reg, off in (prim.get("registers") or {}).items():
        lines.append(f"  {reg}: input offset {off}")
    lines.append("")
    return ("\n".join(lines)).encode()


def build(target_bytes: bytes, input_bytes: bytes, meta: dict, stderr: bytes,
          mode: str, argv, signal_name: str, primitive: dict | None = None) -> bytes:
    level = meta.get("level", "L1")
    extra = ""
    if primitive:
        extra = (f"\nL2 primitive: {primitive.get('type')} "
                 f"(control offset {primitive.get('offset')}, "
                 f"sentinel 0x{primitive.get('marker', 0):x}, "
                 f"confirmed={primitive.get('confirmed')}).\n"
                 "See PRIMITIVE.txt.\n")
    readme = (
        "Lykos PoC bundle\n"
        "====================\n"
        f"Level: {level}\n"
        f"Reproduces: {signal_name}\n"
        f"Target sha256: {meta.get('target_sha256')}\n"
        f"Arch: {meta.get('arch')}   Input mode: {mode}\n"
        f"{extra}\n"
        "Run:  ./runner.sh\n"
        "Files: target.bin (the binary), input.bin (the crashing input),\n"
        "       runner.sh, meta.json, stderr.txt (crash diagnostics).\n"
        "Authorized-use only.\n").encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        _add(tar, "poc/target.bin", target_bytes, mode=0o755)
        _add(tar, "poc/input.bin", input_bytes)
        _add(tar, "poc/runner.sh", _runner(mode, argv, signal_name), mode=0o755)
        _add(tar, "poc/meta.json", json.dumps(meta, indent=2, sort_keys=True).encode())
        _add(tar, "poc/stderr.txt", stderr or b"")
        if primitive:
            _add(tar, "poc/PRIMITIVE.txt", _primitive_txt(primitive))
        _add(tar, "poc/README.txt", readme)
    return buf.getvalue()
