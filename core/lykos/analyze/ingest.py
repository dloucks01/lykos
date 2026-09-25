"""IT-01/03/05/18/19 + JE-26 — ingest helper and the `ingest_triage` stage.

`ingest()` stores a file content-addressed and creates/dedups its target row. The
`ingest_triage` stage reads that blob, builds the triage record, updates the target's
denormalized fields, and emits the triage JSON as an output artifact. `register()` wires
the stage into the job engine.
"""
from __future__ import annotations

import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from ..db.dao import TargetDAO
from ..hashing import canonical_json, hash_all_file
from ..jobs.registry import cached_output_json, register_stage
from .triage import TOOL, TOOL_VERSION, build_triage

INGEST_TRIAGE_STAGE = "ingest_triage"

# Source we can build and analyse directly. A source drop is compiled with AddressSanitizer +
# UndefinedBehaviorSanitizer and debug info, and the instrumented binary flows through the whole
# binary pipeline -- so fuzzing catches heap overflows, use-after-free and UB that a plain
# segfault-only search misses, and every crash carries a source file:line.
_C_EXT = {".c"}
_CXX_EXT = {".cc", ".cpp", ".cxx", ".c++"}
_SOURCE_EXT = _C_EXT | _CXX_EXT


def is_source(filename: str) -> bool:
    return Path(filename or "").suffix.lower() in _SOURCE_EXT


def compile_source(src: Path, filename: str, out: Path) -> dict:
    """Compile a single-file C/C++ source into an ASan+UBSan, debug, instrumented binary.

    Returns {"ok": True, "compiler": ..., "flags": ...} on success or raises NotAnalysable with
    the compiler's own diagnostics. Sanitizer runtimes are linked statically where the toolchain
    allows it, so the instrumented binary needs no sanitizer .so at run time on the air-gap host.
    """
    ext = Path(filename).suffix.lower()
    is_cxx = ext in _CXX_EXT
    cc = shutil.which("g++" if is_cxx else "gcc") or shutil.which("clang++" if is_cxx else "clang")
    if not cc:
        raise NotAnalysable("no C/C++ compiler found to build the source (need gcc/clang)")
    # The sandbox fuzzer detects crashes by SIGNAL, but AddressSanitizer/UBSan default to
    # exit(1) on Linux -- a clean exit the fuzzer would not count as a crash. This TU makes
    # them abort() (SIGABRT) on the first error, so every sanitizer catch IS a crash the
    # pipeline confirms, root-causes and turns into a PoC. Leak detection is off (noise + cost).
    opts_c = out.parent / "_lykos_san_opts.c"
    opts_c.write_text(
        'const char *__asan_default_options(void){'
        'return "abort_on_error=1:halt_on_error=1:detect_leaks=0";}\n'
        'const char *__ubsan_default_options(void){'
        'return "abort_on_error=1:halt_on_error=1:print_stacktrace=1";}\n')
    san = "address,undefined"
    # Permissive: we are building to ANALYSE, not to ship. Modern gcc makes implicit
    # declarations and implicit int hard errors; downgrade them so ordinary sloppy C still
    # builds, and silence warnings so the diagnostics we surface are real failures.
    base = [cc, "-g", "-O1", "-fno-omit-frame-pointer", f"-fsanitize={san}",
            "-fno-sanitize-recover=all", "-w",
            "-Wno-error=implicit-function-declaration", "-Wno-error=implicit-int",
            "-Wno-error=int-conversion", "-D_GNU_SOURCE",
            # Let AddressSanitizer report the overflow with a file:line, instead of glibc's
            # _FORTIFY_SOURCE aborting first with a terse "buffer overflow detected".
            "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0",
            str(src), str(opts_c), "-o", str(out)]
    # Prefer static sanitizer runtimes so the binary is self-contained on the air-gap host; fall
    # back to dynamic linking if the static runtime is not present in this toolchain.
    attempts = [base + ["-static-libasan", "-static-libubsan"], base]
    last = ""
    for argv in attempts:
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as e:
            last = str(e)
            continue
        if r.returncode == 0 and out.exists():
            return {"ok": True, "compiler": Path(cc).name, "sanitizers": san,
                    "static_runtime": "-static-libasan" in argv}
        last = (r.stderr or r.stdout or "").strip()
    raise NotAnalysable(f"could not compile {filename}:\n{last[:2000]}")


def compile_source_msan(src: Path, filename: str, out: Path):
    """Best-effort MemorySanitizer build, or None. MSan reports the ONE memory-safety class the
    ASan+UBSan build cannot -- a READ of never-initialized memory (CWE-457) -- so detonating the same
    inputs against this binary catches uninitialized-value bugs the primary build misses. MSan is
    clang-only and mutually exclusive with ASan, so this is a SEPARATE binary built only when clang is
    present; origin tracking is on so the report names where the value came from. Advisory: without an
    MSan-instrumented libc a value that flows through libc can read as uninitialized, so a hit is a
    lead the PoC ladder then confirms, not an assertion."""
    ext = Path(filename).suffix.lower()
    cc = shutil.which("clang++" if ext in _CXX_EXT else "clang")
    if not cc:
        return None
    opts_c = out.parent / "_lykos_msan_opts.c"
    opts_c.write_text('const char *__msan_default_options(void){'
                      'return "abort_on_error=1:halt_on_error=1";}\n')
    argv = [cc, "-g", "-O1", "-fno-omit-frame-pointer", "-fsanitize=memory",
            "-fsanitize-memory-track-origins=2", "-fno-sanitize-recover=all", "-w",
            "-Wno-error=implicit-function-declaration", "-Wno-error=implicit-int",
            "-Wno-error=int-conversion", "-D_GNU_SOURCE", str(src), str(opts_c), "-o", str(out)]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return out if (r.returncode == 0 and out.exists()) else None


def _apply_triage_denorm(targets: TargetDAO, target_id: str, rec: dict) -> None:
    targets.update_triage(
        target_id, file_type=rec["file_type"], arch=rec["arch"], bits=rec["bits"],
        endianness=rec["endianness"], linking=rec["linking"], stripped=rec["stripped"],
        mitigations=rec["mitigations"], entropy=rec["entropy"]["overall"])


def backfill_triage_denorm(store, target_id: str, run_id: str) -> bool:
    """Recover a target row's denormalized triage columns from a triage run's cached output.

    The triage stage denormalizes arch/bits/endianness/... onto the target row from inside its
    body. On a *cache hit* the job engine clones the prior run's output artifacts to the new run
    but never re-runs the body -- so a freshly uploaded copy of an already-analyzed binary (same
    bytes, new target row, e.g. a second case) would keep NULL arch, and arch-branching stages
    (the cross-arch monitor, disassembly routing) would misread it as native. This reads the
    linked triage-json artifact and writes the columns onto the new row. Returns True if it did.
    """
    if store.targets.get(target_id).arch is not None:
        return False
    rec = cached_output_json(store, run_id)
    if isinstance(rec, dict) and "arch" in rec and "entropy" in rec:
        _apply_triage_denorm(store.targets, target_id, rec)
        return True
    return False


class NotAnalysable(ValueError):
    """A file that cannot be a target, with a reason fit to show a user."""


_LIB_RE = re.compile(r"^(ld[-.]|ld-linux|ld\.so|libc[.-]|libc\.so|lib\w+\.so)", re.I)


def _elf_interp(path) -> tuple[bool, Optional[str]]:
    """(is_elf, PT_INTERP-string-or-None) for an ELF, pure stdlib. A RELATIVE interp (./ld-...)
    is the tell that a binary is part of a challenge bundle and cannot run standalone."""
    try:
        d = Path(path).read_bytes()
    except OSError:
        return False, None
    if d[:4] != b"\x7fELF" or len(d) < 64:
        return False, None
    is64 = d[4] == 2
    en = "<" if d[5] == 1 else ">"
    try:
        if is64:
            e_phoff = struct.unpack_from(en + "Q", d, 0x20)[0]
            e_phentsize, e_phnum = struct.unpack_from(en + "HH", d, 0x36)
        else:
            e_phoff = struct.unpack_from(en + "I", d, 0x1C)[0]
            e_phentsize, e_phnum = struct.unpack_from(en + "HH", d, 0x2A)
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if struct.unpack_from(en + "I", d, off)[0] != 3:      # PT_INTERP
                continue
            if is64:
                p_offset = struct.unpack_from(en + "Q", d, off + 8)[0]
                p_filesz = struct.unpack_from(en + "Q", d, off + 32)[0]
            else:
                p_offset = struct.unpack_from(en + "I", d, off + 4)[0]
                p_filesz = struct.unpack_from(en + "I", d, off + 16)[0]
            s = d[p_offset:p_offset + p_filesz].split(b"\x00", 1)[0]
            return True, s.decode("latin-1", "ignore")
    except Exception:                                             # noqa: BLE001 -- best-effort
        pass
    return True, None


def _looks_like_lib(name: str) -> bool:
    return bool(_LIB_RE.match(name))


def gather_bundle(dirpath) -> tuple[Optional[Path], dict[str, str]]:
    """A challenge DIRECTORY -> (main binary, {path-relative-to-dir: absolute path}) for its
    companion files. The main binary is the substantial ELF that is not itself a loader/library;
    the deps are everything else in the tree (a bundled loader named by a relative PT_INTERP, the
    challenge's libc, data files like flag.txt), so they can be staged beside it at run time."""
    dirpath = Path(dirpath)
    files = [p for p in dirpath.rglob("*") if p.is_file()]
    scanned = [(p, _elf_interp(p)) for p in files]
    mains = [p for (p, (is_elf, interp)) in scanned
             if is_elf and interp and not _looks_like_lib(p.name)]
    if not mains:                                        # a static exe has no interp
        mains = [p for (p, (is_elf, _)) in scanned if is_elf and not _looks_like_lib(p.name)]
    if not mains:
        return None, {}
    main = max(mains, key=lambda p: p.stat().st_size)
    deps: dict[str, str] = {}
    for p in files:
        if p == main or p.stat().st_size > 64 * 1024 * 1024:
            continue
        try:
            deps[p.relative_to(dirpath).as_posix()] = str(p)
        except ValueError:
            continue
    return main, deps


def _ingest_built_project(store, case_id, root, built, filename):
    """Ingest the binary produced by building a source PROJECT: store the primary instrumented
    executable as the target, keep the source TREE (tar.gz) keyed to its hash so the code view can
    show real source with the sanitizer's file:line attributions, and record the build provenance."""
    import io
    import tarfile

    root = Path(root)
    primary = Path(built["primary"])
    info = hash_all_file(primary)
    if not info["size"]:
        raise NotAnalysable(f"{filename}: project built an empty binary")
    # archive the source tree (skip build outputs and VCS/build dirs) for the code view + provenance
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            if any(seg in (".git", "_lykos_build", "node_modules") for seg in p.relative_to(root).parts):
                continue
            if p.suffix in {".o", ".a", ".so", ".lo", ".la"} or p == primary or p.stat().st_size > 8 << 20:
                continue
            try:
                tf.add(str(p), arcname=rel)
            except OSError:
                pass
    store.put_artifact(case_id, "source-project", data=buf.getvalue(),
                       meta={"binary_sha": info["sha256"], "filename": filename,
                             "build_system": built.get("system"), "compiler": built.get("compiler"),
                             "other_binaries": [b.name for b in built.get("binaries", [])[1:8]]})
    store.put_artifact(case_id, "target-blob", src=primary)
    return store.targets.upsert(case_id, filename, info["sha256"],
                                md5=info["md5"], sha1=info["sha1"], size=info["size"])


def ingest(store, case_id: str, path: str | Path, filename: Optional[str] = None,
           deps: Optional[dict[str, str]] = None):
    """IT-03/05: store the file (content-addressed) + create/dedup the target row.

    An empty file is refused here rather than downstream. Accepting one produced a target
    whose every triage field was null, a `detect_cwe` run that reported "done", and an advice
    panel recommending coverage-guided fuzzing -- a confident plan for nothing at all. There
    is no analysis anywhere in this platform that can say something true about zero bytes.
    """
    path = Path(path)
    if path.is_dir():
        # A SOURCE PROJECT (multiple files / Makefile / CMake / autotools) -> build it with
        # sanitizers and analyse the produced binary. Falls through to the prebuilt-binary bundle
        # path if the directory is not source, or the build produces nothing runnable.
        from . import source_project
        if source_project.is_source_project(path):
            built = source_project.build_source_project(path)
            if built["ok"] and built["primary"]:
                return _ingest_built_project(store, case_id, path, built,
                                             filename or path.name)
        # a challenge BUNDLE (prebuilt binary + loader/libc), or a source project that did not build
        main, dep_files = gather_bundle(path)
        if main is None:
            raise NotAnalysable(f"{path.name}: no analysable binary found in the bundle")
        return ingest(store, case_id, main, filename=filename or main.name, deps=dep_files)
    fname = filename or path.name
    if not path.stat().st_size:
        raise NotAnalysable(f"{fname} is empty (0 bytes) -- nothing to analyse")

    # Source drop: compile to an ASan+UBSan instrumented binary and analyse THAT. The source is
    # kept (keyed to the binary's hash) so the code view shows real source, and every crash the
    # sanitizers catch carries a file:line. Nothing else in the pipeline changes.
    if is_source(fname):
        with tempfile.TemporaryDirectory(prefix="lykos-cc-") as td:
            binout = Path(td) / ((Path(fname).stem or "a") + ".bin")
            meta = compile_source(path, fname, binout)
            info = hash_all_file(binout)
            if not info["size"]:
                raise NotAnalysable(f"{fname} compiled to an empty binary")
            # A SECOND, MemorySanitizer build (clang) alongside the ASan one: it catches the
            # uninitialized-read class (CWE-457) ASan cannot, and the fuzz stage detonates the corpus
            # against it. Best-effort -- keyed to the SAME binary sha so the fuzzer can find it.
            msanout = Path(td) / ((Path(fname).stem or "a") + ".msan")
            if compile_source_msan(path, fname, msanout) and msanout.exists():
                store.put_artifact(case_id, "msan-blob", src=msanout,
                                   meta={"binary_sha": info["sha256"], "filename": fname})
                meta["msan"] = True
            store.put_artifact(case_id, "source-code", data=path.read_bytes(),
                               meta={"binary_sha": info["sha256"], "filename": fname, **meta})
            store.put_artifact(case_id, "target-blob", src=binout)
            return store.targets.upsert(case_id, fname, info["sha256"],
                                        md5=info["md5"], sha1=info["sha1"], size=info["size"])

    info = hash_all_file(path)
    store.put_artifact(case_id, "target-blob", src=path)
    dep_map: Optional[dict[str, str]] = None
    if deps:
        dep_map = {}
        for rel, src in deps.items():
            try:
                sha, _, _ = store.content.put_file(src)
            except OSError:
                continue
            dep_map[rel] = sha
    return store.targets.upsert(case_id, fname, info["sha256"],
                                md5=info["md5"], sha1=info["sha1"], size=info["size"],
                                deps=dep_map or None)


def ingest_triage_stage(ctx) -> dict:
    """The registered stage. `ctx.target_id` must reference an already-ingested target."""
    targets = TargetDAO(ctx.conn)
    target = targets.get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("ingest_triage requires a target_id referencing an ingested blob")

    ctx.progress(msg="reading blob")
    blob_path = ctx.content.path(target.sha256)
    ctx.check_cancel()

    ctx.progress(msg="parsing + mitigations")
    rec = build_triage(blob_path,
                       {"sha256": target.sha256, "md5": target.md5, "sha1": target.sha1,
                        "size": target.size}, target.filename)
    ctx.check_cancel()

    # denormalize the triage subset onto the target row
    _apply_triage_denorm(targets, target.id, rec)

    sha = ctx.put_artifact("triage-json", data=canonical_json(rec))
    ctx.progress(pct=100, msg="triage complete")
    ctx.emit("triage.done", payload={"arch": rec["arch"], "file_type": rec["file_type"],
                                     "parse_errors": len(rec["parse_errors"])})
    return {"output_shas": [sha], "output_kind": "triage-json"}


def register() -> None:
    register_stage(INGEST_TRIAGE_STAGE, ingest_triage_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION,
                   on_cache_hit=backfill_triage_denorm)


def enqueue_triage(queue, target, *, force: bool = False):
    """Convenience: enqueue ingest_triage with cache-correct inputs/tool_version."""
    return queue.enqueue(target.case_id, INGEST_TRIAGE_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         force=force)
