"""SymQEMU concolic backend (alternate to angr), graceful when not installed.

SymQEMU is a QEMU-based concolic executor: it runs the target on a concrete seed and, along
that path, flips branch conditions and solves for new inputs, written to an output directory
(the SymCC interface: SYMCC_INPUT_FILE marks the symbolic file, SYMCC_OUTPUT_DIR collects the
generated test cases). It works directly on binaries (no source, no Python), which makes it a
fast seed-driven complement to angr for hybrid fuzzing. Located per-arch via LYKOS_SYMQEMU / a
vendored copy / PATH (`symqemu-<arch>`); the stage falls back cleanly when it is absent.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional

_ARCH_SUFFIX = {"x86-64": "x86_64", "x86": "i386", "aarch64": "aarch64", "arm": "arm",
                "mips": "mips", "mipsel": "mipsel", "ppc": "ppc", "ppc64": "ppc64",
                "riscv64": "riscv64"}


def locate_symqemu(config: Optional[str] = None, arch: str = "x86-64") -> Optional[Path]:
    suffix = _ARCH_SUFFIX.get(arch, "x86_64")
    name = f"symqemu-{suffix}"
    for cand in (config, os.environ.get("LYKOS_SYMQEMU")):
        if not cand:
            continue
        p = Path(cand)
        if p.is_file():
            return p
        hit = p / name
        if hit.exists():
            return hit
    vendor = Path(__file__).resolve().parents[3] / "vendor" / "symqemu" / name
    if vendor.exists():
        return vendor
    w = shutil.which(name) or shutil.which("symqemu")
    return Path(w) if w else None


def run_once(symqemu: Path, target: Path, seed: bytes, out_dir: Path, *, mode: str = "file",
             base_argv=(), timeout: int = 60, ctx=None) -> int:
    """Run SymQEMU once on `seed`; generated inputs land in `out_dir`. Returns the child rc."""
    out_dir.mkdir(parents=True, exist_ok=True)
    seed_file = out_dir.parent / "seed.cur"
    seed_file.write_bytes(seed)
    env = dict(os.environ)
    env["SYMCC_OUTPUT_DIR"] = str(out_dir)
    argv = list(base_argv)
    stdin = b""
    if mode == "file":
        env["SYMCC_INPUT_FILE"] = str(seed_file)
        argv = argv + [str(seed_file)]
    else:                                              # stdin: SymCC treats stdin as symbolic
        stdin = seed
    cmd = [str(symqemu), str(target)] + argv
    import subprocess
    if ctx is not None:
        proc = ctx.run_subprocess(cmd, timeout=timeout, env=env,
                                  stdin=subprocess.PIPE if stdin else None)
        return proc.returncode
    proc = subprocess.run(cmd, input=stdin or None, env=env, capture_output=True,
                          timeout=timeout, check=False)
    return proc.returncode


def harvest(out_dir: Path) -> list:
    """De-duplicated generated inputs from a SymQEMU output directory."""
    seen, inputs = set(), []
    if not out_dir.is_dir():
        return inputs
    for f in sorted(out_dir.iterdir()):
        if not f.is_file():
            continue
        try:
            data = f.read_bytes()
        except OSError:
            continue
        key = (len(data), data[:64])
        if key in seen:
            continue
        seen.add(key)
        inputs.append(data)
    return inputs


def run_campaign(symqemu: Path, target: Path, seeds: list, work: Path, *, mode="file",
                 base_argv=(), rounds: int = 2, timeout: int = 60, cap: int = 64,
                 ctx=None) -> list:
    """Iterative hybrid loop: expand seeds by feeding SymQEMU's generated inputs back in for a
    few rounds, returning the de-duplicated set of newly generated inputs."""
    worklist = list(seeds) or [b"\n"]
    seen = {(len(s), s[:64]) for s in worklist}
    generated = []
    out_dir = work / "symqemu-out"
    for _round in range(max(1, rounds)):
        new_this_round = []
        for seed in worklist:
            if ctx is not None and ctx.should_cancel():
                return generated
            if out_dir.exists():
                shutil.rmtree(out_dir, ignore_errors=True)
            try:
                run_once(symqemu, target, seed, out_dir, mode=mode, base_argv=base_argv,
                         timeout=timeout, ctx=ctx)
            except Exception:                          # noqa: BLE001  one seed failing is fine
                continue
            for data in harvest(out_dir):
                key = (len(data), data[:64])
                if key in seen:
                    continue
                seen.add(key)
                generated.append(data)
                new_this_round.append(data)
                if len(generated) >= cap:
                    return generated
        if not new_this_round:
            break
        worklist = new_this_round
    return generated
