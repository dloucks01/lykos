"""IT-01/03/05/18/19 + JE-26 — ingest helper and the `ingest_triage` stage.

`ingest()` stores a file content-addressed and creates/dedups its target row. The
`ingest_triage` stage reads that blob, builds the triage record, updates the target's
denormalized fields, and emits the triage JSON as an output artifact. `register()` wires
the stage into the job engine.
"""
from __future__ import annotations

import json
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
    the compiler's own diagnostics. The sanitizer runtimes are linked DYNAMICALLY (see the attempt
    list below): the binary is built and analysed on the same host, whose libasan.so the run
    sandbox already exposes, and a static link would bloat the image with the whole runtime for the
    RE backend to chew through. Static linking is kept only as a fallback.
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
    # `-x c`/`-x c++` fixes the INPUT LANGUAGE explicitly. The compiler otherwise infers it from
    # the file's on-disk extension, and the HTTP upload path hands us the body as `body.bin` (the
    # real name lives only in `filename`): gcc then treats `.bin` as a linker input -- "file format
    # not recognized; treating as linker script" -- and never compiles it. `-x none` after the
    # source restores extension-based detection for the sanitizer-options TU that follows.
    lang = "c++" if is_cxx else "c"
    base = [cc, "-g", "-O1", "-fno-omit-frame-pointer", f"-fsanitize={san}",
            "-fno-sanitize-recover=all", "-w",
            "-Wno-error=implicit-function-declaration", "-Wno-error=implicit-int",
            "-Wno-error=int-conversion", "-D_GNU_SOURCE",
            # Let AddressSanitizer report the overflow with a file:line, instead of glibc's
            # _FORTIFY_SOURCE aborting first with a terse "buffer overflow detected".
            "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0",
            "-x", lang, str(src), "-x", "none", str(opts_c), "-o", str(out)]
    # Prefer DYNAMIC sanitizer runtimes. Static linking pulls the ENTIRE libasan/libubsan
    # implementation into the image -- ~3,800 functions for a one-line program -- which the RE
    # backend then spends ~100s and hundreds of MB analysing (nothing needs it), and on a loaded
    # host that analysis is OOM-killed. The instrumented binary is BUILT and RUN on the same host
    # under a sandbox that `--ro-bind`s `/`, so libasan.so is always on hand; static
    # self-containment buys nothing here. Fall back to static only if dynamic linking fails.
    attempts = [base, base + ["-static-libasan", "-static-libubsan"]]
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


def compile_source_plain(src: Path, filename: str, out: Path):
    """Best-effort UNINSTRUMENTED build of the same source, or None.

    The one experiment a sanitizer build cannot run is the one that asks what the program ITSELF
    emits. For a source drop the ingested target IS the ASan+UBSan build (that is the whole point
    of compiling it), and on an out-of-bounds READ that build aborts inside the read -- so the
    bytes the read returned never reach stdout, and "does this disclosure defeat ASLR" is
    unanswerable on the only binary available. Measured: the disclosure verdict declined with
    "the ingested program is a sanitizer build" on every source target, which is exactly the path
    where out-of-bounds reads are detected at all.

    So build the program a second time with nothing added: same compiler, same permissive flags,
    no sanitizer, no abort-on-error TU. An out-of-bounds read then does what it does on an
    attacker's machine -- returns adjacent memory and keeps going -- and the bytes can be read.
    Kept as a `plain-blob` artifact keyed to the INSTRUMENTED binary's sha, the same way the MSan
    and TSan builds are, so any stage can ask for "the plain build of this target".

    No PIE/ASLR flags are forced either way: the point is to run what this program is, and a
    recovered load base is only meaningful against the layout the program actually gets.
    """
    ext = Path(filename).suffix.lower()
    is_cxx = ext in _CXX_EXT
    cc = shutil.which("gcc" if not is_cxx else "g++") or shutil.which(
        "clang" if not is_cxx else "clang++")
    if not cc:
        return None
    lang = "c++" if is_cxx else "c"
    argv = [cc, "-g", "-O1", "-fno-omit-frame-pointer", "-w",
            "-Wno-error=implicit-function-declaration", "-Wno-error=implicit-int",
            "-Wno-error=int-conversion", "-D_GNU_SOURCE",
            # Same _FORTIFY_SOURCE suppression as the instrumented build, for the opposite
            # reason: there glibc aborting first costs a file:line, here it costs the whole
            # experiment -- a fortified `read`/`memcpy` kills the process instead of returning
            # the adjacent bytes, and the disclosure that does exist reads as absent.
            "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0",
            "-x", lang, str(src), "-x", "none", "-o", str(out)]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return {"ok": True, "compiler": Path(cc).name} if (r.returncode == 0 and out.exists()) else None


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
    # `-x`: see compile_source -- the upload path hands us `body.bin`, so pin the input language
    # rather than let clang misread the extension.
    lang = "c++" if ext in _CXX_EXT else "c"
    # -O0, NOT -O1. Reading an uninitialized value is undefined behaviour, so at -O1 and above
    # clang is entitled to assume the read never happens: it folds the dependent branch (or the
    # whole path, as `unreachable`) away BEFORE the MSan pass instruments it, and the binary runs
    # clean. Measured on a canonical case -- branch on an uninitialized int -- MSan reports it at
    # -O0 and says nothing whatsoever at -O1/-O2, which left this entire build dead for the one
    # class it exists to catch. Optimisation buys nothing here; the binary is only detonated.
    argv = [cc, "-g", "-O0", "-fno-omit-frame-pointer", "-fsanitize=memory",
            "-fsanitize-memory-track-origins=2", "-fno-sanitize-recover=all", "-w",
            "-Wno-error=implicit-function-declaration", "-Wno-error=implicit-int",
            "-Wno-error=int-conversion", "-D_GNU_SOURCE",
            "-x", lang, str(src), "-x", "none", str(opts_c), "-o", str(out)]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return out if (r.returncode == 0 and out.exists()) else None


def compile_source_tsan(src: Path, filename: str, out: Path):
    """Best-effort ThreadSanitizer build, or None. TSan reports the one class no other sanitizer
    sees -- a DATA RACE (CWE-362), plus lock-order inversions and a few other concurrency bugs --
    so detonating a multithreaded target against this binary catches races the ASan/MSan builds
    cannot. TSan is mutually exclusive with ASan/MSan, so it is a SEPARATE binary built only when a
    compiler supports it. A race only surfaces when the input drives the threaded path, so, like
    MSan, it must be driven with the fuzz CORPUS; a hit is directly observed (not a lead)."""
    ext = Path(filename).suffix.lower()
    cc = shutil.which("clang++" if ext in _CXX_EXT else "clang") or \
        shutil.which("g++" if ext in _CXX_EXT else "gcc")
    if not cc:
        return None
    opts_c = out.parent / "_lykos_tsan_opts.c"
    opts_c.write_text('const char *__tsan_default_options(void){'
                      'return "abort_on_error=1:halt_on_error=1";}\n')
    lang = "c++" if ext in _CXX_EXT else "c"
    argv = [cc, "-g", "-O1", "-fno-omit-frame-pointer", "-fsanitize=thread",
            "-fno-sanitize-recover=all", "-w", "-Wno-error=implicit-function-declaration",
            "-Wno-error=implicit-int", "-Wno-error=int-conversion", "-D_GNU_SOURCE", "-pthread",
            "-x", lang, str(src), "-x", "none", str(opts_c), "-o", str(out)]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return out if (r.returncode == 0 and out.exists()) else None


def _apply_triage_denorm(targets: TargetDAO, target_id: str, rec: dict) -> None:
    targets.update_triage(
        target_id, file_type=rec["file_type"], arch=rec["arch"], bits=rec["bits"],
        endianness=rec["endianness"], linking=rec["linking"], stripped=rec["stripped"],
        mitigations=rec["mitigations"], entropy=rec["entropy"]["overall"],
        toolchain_hint=rec.get("toolchain_hint"))


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


def triage_record(conn, content, target) -> dict:
    """The parsed `ingest_triage` JSON for one target, or {}.

    Needed because a MANAGED target has no machine code: `disassemble` recovers no functions
    and writes no call edges, so everything that infers something from the names a program
    calls -- channel ranking above all -- had nothing to work with and fell back to a default.
    The names are not lost, though. Triage reads them straight out of the constant pool /
    metadata heaps / code object and records them here, where they name the APIs the program
    calls in the clear.

    `link.resolve` reads the same artifact for a whole case; this is the single-target query.
    """
    from ..db.dao import AnalysisRunDAO, ArtifactDAO, RunArtifactDAO
    runs = [r for r in AnalysisRunDAO(conn).list_by_case(target.case_id)
            if r.stage == INGEST_TRIAGE_STAGE and r.status == "done"
            and r.target_id == target.id]
    if not runs:
        return {}
    runs.sort(key=lambda r: (r.ended_at or 0), reverse=True)
    ra, art = RunArtifactDAO(conn), ArtifactDAO(conn)
    for link in ra.list_by_run(runs[0].id):
        a = art.get(link.artifact_sha256)
        if a and a.kind == "triage-json":
            try:
                rec = json.loads(content.get_bytes(a.sha256))
            except Exception:                            # noqa: BLE001 -- absent is the answer
                return {}
            return rec if isinstance(rec, dict) else {}
    return {}


def triage_symbols(conn, content, target) -> list:
    """Every symbol name triage recorded for a target: its IMPORTS and its EXPORTS.

    Reading only `imports.symbols` was right for the formats it was written against (a .NET
    assembly's memberrefs, a constant pool's method calls, a .pyc's names) and silently empty for
    the one where the inventory lives on the other side: a WebAssembly module's imports are its
    HOST CALL SURFACE, so a `--no-entry` reactor module has none at all -- measured 0 imports
    against 2 exports -- and the names a caller needs are in `exports.symbols`. A consumer asking
    "what does this target read?" could therefore never see a wasm module's names, whatever
    vocabulary it was given.

    Both halves answer that question, on either side of the boundary: a wasm module's imports name
    the WASI calls it makes (`fd_read`, `path_open`, `environ_get`) and its exports name its entry
    point (`_start`) and its functions. Imports first, de-duplicated, order preserved.
    """
    rec = triage_record(conn, content, target)
    out, seen = [], set()
    for half in ("imports", "exports"):
        for x in ((rec.get(half) or {}).get("symbols")) or []:
            s = str(x)
            if s and s not in seen:
                seen.add(s)
                out.append(s)
    return out


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


#: How many of a source project's executables one case will carry. Each is a full target with
#: its own budget, so this is a cost ceiling, not a judgement about which ones matter: the
#: builder returns them largest-first and the scorecard reports how many were left out.
MAX_ENTRY_POINTS = 6


def _source_tree_tgz(root, *, skip_binary=None) -> bytes:
    """A gzipped tar of a source tree -- the `source-project` artifact the source bug detectors read
    (they read the TEXT, not a built binary). Skips VCS/build dirs, object/library files, the built
    binary, and oversized files."""
    import io
    import tarfile

    root = Path(root)
    skip_binary = Path(skip_binary) if skip_binary is not None else None
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(root)
            if any(seg in (".git", "_lykos_build", "node_modules") for seg in rel.parts):
                continue
            if (p.suffix in {".o", ".a", ".so", ".lo", ".la"} or p == skip_binary
                    or p.stat().st_size > 8 << 20):
                continue
            try:
                tf.add(str(p), arcname=rel.as_posix())
            except OSError:
                pass
    return buf.getvalue()


def _ingest_built_project(store, case_id, root, built, filename):
    """Ingest the binary produced by building a source PROJECT: store the primary instrumented
    executable as the target, keep the source TREE (tar.gz) keyed to its hash so the code view can
    show real source with the sanitizer's file:line attributions, and record the build provenance."""
    root = Path(root)
    primary = Path(built["primary"])
    info = hash_all_file(primary)
    if not info["size"]:
        raise NotAnalysable(f"{filename}: project built an empty binary")
    # archive the source tree (skip build outputs and VCS/build dirs) for the code view + provenance
    buf_bytes = _source_tree_tgz(root, skip_binary=primary)
    store.put_artifact(case_id, "source-project", data=buf_bytes,
                       meta={"binary_sha": info["sha256"], "filename": filename,
                             "build_system": built.get("system"), "compiler": built.get("compiler"),
                             "other_binaries": [b.name for b in built.get("binaries", [])[1:8]]})
    store.put_artifact(case_id, "target-blob", src=primary)
    main = store.targets.upsert(case_id, filename, info["sha256"],
                                md5=info["md5"], sha1=info["sha1"], size=info["size"])
    # EVERY ENTRY POINT THE BUILD PRODUCED, not just the biggest one. A library project builds a
    # tool per operation -- libtiff builds ~20 -- and each is a different parser front end with a
    # different attack surface, while only `primary` (the largest executable) was ever registered.
    # The rest are registered as targets of the same case so the pass can reach them and the
    # report can say how many entry points exist; `MAX_ENTRY_POINTS` bounds how many a single
    # case will carry, because each one costs a full per-target budget.
    for extra in (built.get("binaries") or [])[1:MAX_ENTRY_POINTS]:
        try:
            ex = Path(extra)
            if ex == primary or not ex.is_file():
                continue
            xi = hash_all_file(ex)
            if not xi["size"]:
                continue
            store.put_artifact(case_id, "target-blob", src=ex)
            store.targets.upsert(case_id, ex.name, xi["sha256"],
                                 md5=xi["md5"], sha1=xi["sha1"], size=xi["size"])
            # Key the SAME source tree to THIS entry point too, not only the primary: a multi-binary
            # project (libtiff builds ~20 tools) otherwise had the tree bound to one sha, so every
            # other entry point's source detectors reported "no archived source tree". The content
            # store is content-addressed, so the identical tar.gz dedups to one blob -- only a cheap
            # per-sha artifact row is added. (source_lookup's case-level fallback also covers this,
            # but an exact key is better than a fallback that declines when the case holds several.)
            store.put_artifact(case_id, "source-project", data=buf_bytes,
                               meta={"binary_sha": xi["sha256"], "filename": ex.name,
                                     "build_system": built.get("system"),
                                     "compiler": built.get("compiler")})
        except OSError:
            continue
    return main


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
        build_log: Optional[str] = None
        if source_project.is_source_project(path):
            built = source_project.build_source_project(path)
            if built["ok"] and built["primary"]:
                return _ingest_built_project(store, case_id, path, built,
                                             filename or path.name)
            build_log = built.get("log")       # keep WHY the build failed for the error below
        # a challenge BUNDLE (prebuilt binary + loader/libc), or a source project that did not build
        main, dep_files = gather_bundle(path)
        if main is None:
            # When this WAS recognised as source, the build failure is the real reason -- surface it
            # (e.g. "cmake: No such file or directory" -> install the tool / run `make doctor`), not
            # the generic bundle message, which reads as "lykos could not understand the input".
            if build_log is not None:
                raise NotAnalysable(
                    f"{path.name}: source project did not build:\n{build_log.strip()[-600:]}")
            raise NotAnalysable(f"{path.name}: no analysable binary found in the bundle")
        tgt = ingest(store, case_id, main, filename=filename or main.name, deps=dep_files)
        if build_log is not None:
            # It WAS a source project but did not fully build (no/partial toolchain on the air-gapped
            # box -- missing cmake/autotools, a CMake min-version rejection, ...). The source bug
            # detectors read the source TEXT, not the built binary, so archive the tree ANYWAY --
            # keyed to the binary we did ingest -- and record that the build failed with its log.
            # Without this every source detector reported "no archived source tree" even though the
            # source is right here, and the operator never saw that the build was why.
            try:
                store.put_artifact(case_id, "source-project", data=_source_tree_tgz(path),
                                   meta={"binary_sha": tgt.sha256,
                                         "filename": filename or path.name, "build_failed": True,
                                         "build_log": (build_log or "").strip()[-2000:]})
            except Exception:                        # noqa: BLE001 -- best-effort source enrichment
                pass
        return tgt
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
            # An UNINSTRUMENTED build of the same source. Not for finding anything -- for the
            # one question the instrumented builds cannot answer, which is what the program
            # emits when the defect is NOT fatal. See compile_source_plain.
            plainout = Path(td) / ((Path(fname).stem or "a") + ".plain")
            if compile_source_plain(path, fname, plainout) and plainout.exists():
                store.put_artifact(case_id, "plain-blob", src=plainout,
                                   meta={"binary_sha": info["sha256"], "filename": fname})
                meta["plain"] = True
            # A THIRD, ThreadSanitizer build: catches the data-race class (CWE-362) no other
            # sanitizer sees; the fuzz stage detonates the corpus against it. Best-effort.
            tsanout = Path(td) / ((Path(fname).stem or "a") + ".tsan")
            if compile_source_tsan(path, fname, tsanout) and tsanout.exists():
                store.put_artifact(case_id, "tsan-blob", src=tsanout,
                                   meta={"binary_sha": info["sha256"], "filename": fname})
                meta["tsan"] = True
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
