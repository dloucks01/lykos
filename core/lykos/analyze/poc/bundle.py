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


def _runner(mode: str, argv, signal_name: str, run_cmd=None) -> bytes:
    if run_cmd:                                          # script-based reproducer (e.g. PIE)
        invoke = run_cmd
    elif mode == "stdin":
        invoke = './target.bin < ./input.bin'
    elif mode == "file":
        invoke = './target.bin ./input.bin'
    elif mode == "arg":
        arg = argv[0] if argv else ""
        invoke = f'./target.bin {arg!r}'
    else:
        invoke = './target.bin'
    return ("#!/bin/sh\n"
            f"# PoC reproducer. Expected result: {signal_name}. RUN IN A SANDBOX/VM --\n"
            "# this executes an untrusted binary. Authorized use only.\n"
            'cd "$(dirname "$0")"\n'
            "chmod +x ./target.bin\n"
            f"{invoke}\n"
            'rc=$?\n'
            f'echo "exit status: $rc (a crash by {signal_name} shows as 128+signum, '
            'e.g. 139=SIGSEGV)"\n').encode()


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


# what each level proves and what a successful run looks like
_LEVEL_MEANING = {
    "L0": "a crash reproducer -- the input makes the target fault",
    "L1": "a verified crash reproducer -- the crash is real and repeatable",
    "L2": "an exploitation PRIMITIVE -- attacker control of the instruction pointer or a "
          "memory read/write (not merely a crash); see PRIMITIVE.txt",
    "L3": "a working EXPLOIT -- control flow is hijacked to attacker-chosen code",
}


def build(target_bytes: bytes, input_bytes: bytes, meta: dict, stderr: bytes,
          mode: str, argv, signal_name: str, primitive: dict | None = None,
          extra_files: dict | None = None, run_cmd: str | None = None) -> bytes:
    level = meta.get("level", "L1")
    script = extra_files and "exploit.py" in extra_files
    prim_line = ""
    if primitive:
        prim_line = (f"\nPrimitive: {primitive.get('type')} at control offset "
                     f"{primitive.get('offset')} (confirmed={primitive.get('confirmed')}). "
                     "See PRIMITIVE.txt.\n")
    files = ["target.bin  - the exact analyzed binary (self-contained; runs anywhere)"]
    if script:
        files += ["exploit.py  - the reproducer: leaks a runtime address, defeats ASLR, and "
                  "delivers the exploit live (the payload is base-specific so it cannot be "
                  "a static file)"]
    else:
        files += ["input.bin   - the crafted input that triggers it"]
    files += ["runner.sh   - runs the reproducer for you",
              "meta.json   - machine-readable details (target hash, arch, offset, tool)",
              "PRIMITIVE.txt / stderr.txt - the primitive description and captured diagnostics"]
    what_success = ("the process is hijacked to the attacker-chosen code (you'll see its "
                    "marker output)" if level == "L3"
                    else f"the process dies with {signal_name} (a shell shows exit 128+signum)")
    readme = (
        "LYKOS PROOF-OF-CONCEPT BUNDLE\n"
        "=============================\n"
        f"Level {level}: {_LEVEL_MEANING.get(level, 'a demonstrated finding')}.\n"
        f"Target sha256: {meta.get('target_sha256')}    arch: {meta.get('arch')}\n"
        f"{prim_line}\n"
        "WHAT THIS IS\n"
        "  A self-contained, reproducible proof that this vulnerability is real. It carries the\n"
        "  exact binary and everything needed to demonstrate it, so anyone can verify it\n"
        "  offline, on any machine -- it is the evidence behind the finding.\n\n"
        "HOW TO RUN  (do this inside a VM or disposable sandbox -- it executes untrusted code)\n"
        "  $ tar -xzf <bundle>.tar.gz && cd poc && "
        + ("python3 ./exploit.py" if script else "sh ./runner.sh") + "\n"
        f"  Success = {what_success}.\n\n"
        "WHAT TO DO WITH IT\n"
        "  - Independently confirm the finding by running the reproducer above.\n"
        "  - Attach the whole poc/ folder to your report or ticket as the evidence.\n"
        "  - Hand it to a colleague; it needs nothing from this tool to reproduce.\n\n"
        "FILES\n  " + "\n  ".join(files) + "\n\n"
        "Authorized use only. Do not run against systems you are not authorized to test.\n"
    ).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        _add(tar, "poc/target.bin", target_bytes, mode=0o755)
        _add(tar, "poc/input.bin", input_bytes)
        for name, data in (extra_files or {}).items():
            _add(tar, f"poc/{name}", data, mode=0o755 if name.endswith(".py") else 0o644)
        _add(tar, "poc/runner.sh", _runner(mode, argv, signal_name, run_cmd), mode=0o755)
        _add(tar, "poc/meta.json", json.dumps(meta, indent=2, sort_keys=True).encode())
        _add(tar, "poc/stderr.txt", stderr or b"")
        if primitive:
            _add(tar, "poc/PRIMITIVE.txt", _primitive_txt(primitive))
        _add(tar, "poc/README.txt", readme)
    return buf.getvalue()
