"""Turn what the operator pointed at into Targets the loop can solve and validate.

  a binary            analysed as-is; validated by native, site-matched crashes
  a C/C++ source file built twice: plain -g -O0 (what angr walks) + ASan/UBSan (the oracle)
  a source project    the same two builds of every executable it produces, via the project's
                      own build system (source_project), each in its own copy of the tree
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .validate import Target

_SRC = {".c", ".cc", ".cpp", ".cxx", ".c++", ".C"}
_PLAIN = ["-g", "-O0", "-fno-omit-frame-pointer", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0",
          "-D_GNU_SOURCE", "-w", "-Wno-error=implicit-function-declaration",
          "-Wno-error=implicit-int", "-Wno-error=int-conversion"]


@dataclass
class Prepared:
    kind: str                                   # binary | source-file | source-project
    targets: list = field(default_factory=list)
    log: str = ""
    workdir: Optional[Path] = None              # temporary build trees (caller removes)


def _is_elf(p: Path) -> bool:
    try:
        with open(p, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def _elf_meta(p: Path) -> dict:
    from ..analyze import elf
    try:
        info = elf.parse(p.read_bytes())
    except Exception:            # noqa: BLE001 - not parseable: let the sandbox decide later
        return {}
    return {"arch": info.arch, "bits": info.bits, "endianness": info.endianness,
            "imports": list(getattr(info, "imported_symbols", None) or [])}


def infer_invocation(exe: Path, argv: Optional[list], mode: Optional[str]):
    """(argv, mode). Explicit operator choices win; otherwise the binary's imports decide
    (fopen/fread -> file, fgets/read/scanf -> stdin, else argv)."""
    if mode is None:
        from ..analyze.advise import _input_mode
        mode = _input_mode(_elf_meta(exe).get("imports") or [])[0] or "file"
    if argv is None:
        argv = [] if mode == "stdin" else ["@@"]
    return list(argv), mode


def _cc(cxx: bool) -> Optional[str]:
    return (shutil.which("g++") or shutil.which("clang++")) if cxx else \
        (shutil.which("gcc") or shutil.which("clang"))


# The validator build: -O0 like the analysis build. At -O1 the optimiser can delete the very UB
# being validated (and LSan needs -O0); abort-on-error comes from the replay environment.
_SAN = ["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]
# MemorySanitizer (uninitialised reads, CWE-457/908) is a SEPARATE, clang-only build: it cannot
# coexist with ASan, and needs every frame instrumented -- fine for a single translation unit,
# since MSan ships its own libc interceptors. track-origins gives the use site a clean frame.
_MSAN = ["-fsanitize=memory", "-fsanitize-memory-track-origins=2", "-fno-omit-frame-pointer"]


def _compile_plain(src: Path, out: Path, extra=(), cc: Optional[str] = None, env=None) -> str:
    cc = cc or _cc(src.suffix.lower() not in (".c",))
    if not cc:
        raise RuntimeError("no C/C++ compiler found (need gcc or clang)")
    e = {**os.environ, **env} if env else None
    r = subprocess.run([cc, *_PLAIN, *extra, "-o", str(out), str(src), "-lm"], capture_output=True,
                       text=True, timeout=300, check=False, env=e)
    if r.returncode != 0 or not out.exists():
        raise RuntimeError(f"plain build failed:\n{r.stderr[-3000:]}")
    return r.stderr


def _clang(cxx: bool) -> Optional[str]:
    return shutil.which("clang++") if cxx else shutil.which("clang")


def _afl_cc(cxx: bool) -> Optional[str]:
    """AFL++ instrumenting compiler for the fuzz fallback (Step 5, doc 52 §3c)."""
    names = (["afl-clang-fast++", "afl-c++", "afl-g++-fast"] if cxx
             else ["afl-clang-fast", "afl-cc", "afl-gcc-fast"])
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def prepare(path, *, argv: Optional[list] = None, mode: Optional[str] = None,
            build_timeout: int = 600) -> Prepared:
    p = Path(path).resolve()
    if p.is_file() and _is_elf(p):
        a, m = infer_invocation(p, argv, mode)
        meta = _elf_meta(p)
        return Prepared("binary", [Target(exe=p, argv=a, mode=m, arch=meta.get("arch"),
                                          endianness=meta.get("endianness"),
                                          bits=meta.get("bits"))])
    work = Path(tempfile.mkdtemp(prefix="lykos-hunt-build-"))
    if p.is_file() and p.suffix in _SRC:
        plain, san = work / p.stem, work / (p.stem + "_asan")
        log = _compile_plain(p, plain)
        try:
            log += _compile_plain(p, san, extra=_SAN)
        except RuntimeError as e:   # validation degrades to native crashes
            log += f"\nsanitizer build failed, validating by native crashes: {e}"
            san = None
        msan = work / (p.stem + "_msan")
        clang = _clang(p.suffix.lower() not in (".c",))
        if clang:
            try:
                log += _compile_plain(p, msan, extra=_MSAN, cc=clang)
            except RuntimeError as e:   # uninit validation simply unavailable for this target
                log += f"\nMSan build failed, uninit validation disabled: {e}"
                msan = None
        else:
            log += "\nclang not found: MSan (uninit) validation disabled"
            msan = None
        afl = work / (p.stem + "_afl")
        cmplog = work / (p.stem + "_cmplog")
        afl_cc = _afl_cc(p.suffix.lower() not in (".c",))
        if afl_cc:
            try:
                log += _compile_plain(p, afl, cc=afl_cc)
            except RuntimeError as e:        # the fuzz fallback simply has no instrumented build
                log += f"\nAFL build failed, fuzz fallback uses qemu-mode: {e}"
                afl = None
            try:                             # CmpLog build: lets AFL solve magic/keyword compares
                log += _compile_plain(p, cmplog, cc=afl_cc, env={"AFL_LLVM_CMPLOG": "1"})
            except RuntimeError as e:
                log += f"\nCmpLog build failed: {e}"
                cmplog = None
        else:
            afl = cmplog = None
        a, m = infer_invocation(plain, argv, mode)
        return Prepared("source-file", [Target(exe=plain, argv=a, mode=m, asan_exe=san,
                                               msan_exe=msan, afl_exe=afl, afl_cmplog=cmplog,
                                               source_root=p.parent)], log, work)
    if p.is_dir():
        from ..analyze.source_project import build_source_project, is_source_project
        if not is_source_project(p):
            raise RuntimeError(f"{p} is not a binary, a C/C++ file or a C/C++ source project")
        trees = {}
        logs = []
        for flavour in ("plain", "asan"):
            t = work / f"build-{flavour}"
            shutil.copytree(p, t, symlinks=True)
            res = build_source_project(t, timeout=build_timeout, sanitize=(flavour == "asan"),
                                       opt="-O0")
            logs.append(f"== {flavour} build ({res.get('system')}): "
                        f"{'ok' if res.get('ok') else 'FAILED'}\n{(res.get('log') or '')[-2000:]}")
            trees[flavour] = (t, res)
        plain_root, plain_res = trees["plain"]
        san_root, san_res = trees["asan"]
        if not plain_res.get("ok"):
            raise RuntimeError("the project did not build:\n" + "\n".join(logs))
        san_by_rel = {}
        for b in san_res.get("binaries") or []:
            try:
                san_by_rel[str(Path(b).relative_to(san_root))] = Path(b)
            except ValueError:
                pass
        targets = []
        for b in plain_res.get("binaries") or []:
            b = Path(b)
            try:
                rel = str(b.relative_to(plain_root))
            except ValueError:
                rel = b.name
            a, m = infer_invocation(b, argv, mode)
            targets.append(Target(exe=b, argv=a, mode=m, asan_exe=san_by_rel.get(rel),
                                  source_root=plain_root, display_root=p))
        return Prepared("source-project", targets, "\n".join(logs), work)
    raise RuntimeError(f"{p}: not a file or directory lykos can hunt")
