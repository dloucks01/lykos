"""Coverage-guided in-process fuzzing of C/C++ SOURCE via libFuzzer.

The built-in engine is blind havoc with bolt-on breakpoint coverage; libFuzzer is a real
coverage-guided, in-process fuzzer that clang provides for free with `-fsanitize=fuzzer`. Real
source -- especially libraries with no `main` -- is the case it fits: build an
`LLVMFuzzerTestOneInput` harness (one the project already ships, as OSS-Fuzz projects do, or one
synthesized for a named entry function) with ASan+UBSan, let libFuzzer drive coverage, and harvest
each crash with its sanitizer report -- a confirmed finding with a source file:line and no oracle.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

_C_EXT = {".c"}
_CXX_EXT = {".cc", ".cpp", ".cxx", ".c++", ".C"}
_SRC_EXT = _C_EXT | _CXX_EXT
_HARNESS_SYM = "LLVMFuzzerTestOneInput"
_MAIN_RE = re.compile(r"\bint\s+main\s*\(", re.M)
_HARNESS_RE = re.compile(_HARNESS_SYM)
_SAN = ["-g", "-O1", "-fno-omit-frame-pointer", "-fsanitize=fuzzer,address,undefined",
        "-fno-sanitize-recover=all", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", "-w",
        "-Wno-error=implicit-function-declaration", "-Wno-error=implicit-int",
        "-Wno-error=int-conversion", "-D_GNU_SOURCE"]


def _clang(cxx: bool):
    return shutil.which("clang++" if cxx else "clang")


def find_harness(root) -> Path | None:
    """A source file defining LLVMFuzzerTestOneInput, if the project ships one."""
    for p in Path(root).rglob("*"):
        if p.is_file() and p.suffix in _SRC_EXT:
            try:
                if _HARNESS_RE.search(p.read_text(errors="ignore")):
                    return p
            except OSError:
                pass
    return None


_FN_DEF = re.compile(
    r"^[ \t]*(?!static\b)(?:[A-Za-z_][\w ]*?[ \t*]+)([A-Za-z_]\w*)[ \t]*\("
    r"[ \t]*(?:const[ \t]+)?(?:unsigned[ \t]+)?(?:char|void|uint8_t)[ \t]*\*[ \t]*\w*[ \t]*"
    r"(?:,[ \t]*(?:const[ \t]+)?(?:unsigned[ \t]+)?(?:size_t|int|long|unsigned)[ \t]*\w*[ \t]*)?\)",
    re.M)


def pick_harness_fn(root) -> str | None:
    """Auto-select an entry function to fuzz in a LIBRARY with no in-tree harness: a non-static,
    non-main function whose first parameter is a `char*`/`const char*`/`uint8_t*` (a string or
    buffer consumer -- the parsers where memory-safety bugs live). None if nothing suitable."""
    for p in sorted(Path(root).rglob("*")):
        if not (p.is_file() and p.suffix in _SRC_EXT):
            continue
        try:
            txt = p.read_text(errors="ignore")
        except OSError:
            continue
        for m in _FN_DEF.finditer(txt):
            name = m.group(1)
            if name not in ("main", "if", "for", "while", "switch", "return", "sizeof"):
                return name
    return None


def fn_first_arg_type(root, fn: str):
    """The spelling of `fn`'s FIRST parameter type in the source (e.g. "const char *", "char *"),
    or "" when it takes no args, or None if not found. Needed to forward-declare `fn` in the harness
    so C++ name mangling matches -- `extern void fn()` mangles differently than `fn(const char*)` and
    fails to link. C is lenient, but the exact declaration is correct for both."""
    pat = re.compile(r"\b" + re.escape(fn) + r"\s*\(([^)]*)\)\s*(?:const\s*)?\{", re.M)
    for p in sorted(Path(root).rglob("*")):
        if not (p.is_file() and p.suffix in _SRC_EXT):
            continue
        try:
            m = pat.search(p.read_text(errors="ignore"))
        except OSError:
            continue
        if not m:
            continue
        params = m.group(1).strip()
        if not params or params == "void":
            return ""
        first = params.split(",")[0].strip()
        first = re.sub(r"\b[A-Za-z_]\w*\s*$", "", first).strip() or first   # drop the param NAME
        return first
    return None


def fn_def_file(root, fn) -> Path | None:
    """The source file that DEFINES `fn` (for its language: .c -> a C symbol, .cc/.cpp -> a mangled
    C++ symbol -- which decides whether the harness declares it `extern "C"`)."""
    pat = re.compile(r"\b" + re.escape(fn) + r"\s*\([^)]*\)\s*(?:const\s*)?\{", re.M)
    for p in sorted(Path(root).rglob("*")):
        if p.is_file() and p.suffix in _SRC_EXT:
            try:
                if pat.search(p.read_text(errors="ignore")):
                    return p
            except OSError:
                pass
    return None


def synth_harness(fn: str, *, kind: str = "cstring", arg_type: str | None = None,
                  cxx: bool = False, c_linkage: bool = False) -> str:
    """A libFuzzer harness calling `fn` with the fuzz bytes. `cstring`: fn(char*) on a
    NUL-terminated copy; `buflen`: fn(const uint8_t*, size_t). `arg_type` is `fn`'s real first
    parameter spelling from the source so the forward declaration links (C++ mangles the signature).
    `cxx` emits a C++ harness (the fuzzer entry then needs `extern "C"`); `c_linkage` declares `fn`
    itself `extern "C"` when it is a C symbol reached from a C++ harness."""
    fuzz_qual = 'extern "C" ' if cxx else ""
    fn_qual = 'extern "C" ' if (cxx and c_linkage) else "extern "
    if kind == "buflen":
        decl = arg_type or "const unsigned char *, unsigned long"
        pre, call = "", f"    {fn}(data, size);\n"
    else:
        at = arg_type if arg_type not in (None, "") else "char *"
        decl = at
        pre = ("    char *s = (char*)malloc(size + 1);\n    if (!s) return 0;\n"
               "    memcpy(s, data, size); s[size] = 0;\n")
        call = f"    {fn}(({at})s);\n    free(s);\n"
    return ("#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>\n"
            f"{fn_qual}void {fn}({decl});\n"
            f"{fuzz_qual}int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n"
            f"{pre}{call}    return 0;\n}}\n")


def _sources(root: Path, exclude_main: bool):
    out = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix not in _SRC_EXT:
            continue
        if any(seg in (".git", "_lykos_build", "node_modules") for seg in p.relative_to(root).parts):
            continue
        try:
            txt = p.read_text(errors="ignore")
        except OSError:
            continue
        if exclude_main and _MAIN_RE.search(txt) and not _HARNESS_RE.search(txt):
            continue                                     # its own main clashes with libFuzzer's
        out.append(p)
    return out


def build_libfuzzer(root, out: Path, *, harness_fn: str | None = None,
                    harness_kind: str = "cstring", timeout: int = 300) -> dict:
    """Build a libFuzzer target from the project at `root`. Uses an in-tree LLVMFuzzerTestOneInput
    if present, else synthesizes one for `harness_fn`. Returns {ok, binary, harness, log}."""
    root = Path(root).resolve()
    existing = find_harness(root)
    if not existing and not harness_fn:
        harness_fn = pick_harness_fn(root)               # auto-harness a library's parser entry
    cxx = any(p.suffix in _CXX_EXT for p in _sources(root, exclude_main=False))
    cc = _clang(cxx)
    if not cc:
        return {"ok": False, "binary": None, "harness": None, "log": "clang not found (libFuzzer needs clang)"}
    tmp = Path(tempfile.mkdtemp(prefix="lykos-lf-"))
    srcs = _sources(root, exclude_main=True)
    harness_desc = None
    if existing:
        harness_desc = f"in-tree {existing.relative_to(root)}"
    elif harness_fn:
        h = tmp / ("harness.cc" if cxx else "harness.c")
        # match the target function's real signature and linkage so a C++ symbol (mangled) or a C
        # symbol reached from a C++ harness both resolve at link time.
        def_file = fn_def_file(root, harness_fn)
        c_linkage = bool(def_file and def_file.suffix in _C_EXT)
        h.write_text(synth_harness(harness_fn, kind=harness_kind,
                                   arg_type=fn_first_arg_type(root, harness_fn),
                                   cxx=cxx, c_linkage=c_linkage))
        srcs = srcs + [h]
        harness_desc = f"synthesized for {harness_fn}()"
    else:
        return {"ok": False, "binary": None, "harness": None,
                "log": "no LLVMFuzzerTestOneInput in the source and no harness_fn to synthesize one"}
    argv = [cc] + _SAN + [str(s) for s in srcs] + ["-I", str(root), "-o", str(out)]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        shutil.rmtree(tmp, ignore_errors=True)
        return {"ok": False, "binary": None, "harness": harness_desc, "log": str(e)}
    shutil.rmtree(tmp, ignore_errors=True)
    ok = r.returncode == 0 and out.exists()
    return {"ok": ok, "binary": out if ok else None, "harness": harness_desc,
            "log": ((r.stderr or "") + (r.stdout or ""))[-4000:]}


_ASAN_HDR = re.compile(r"(==\d+==ERROR: (?:AddressSanitizer|UndefinedBehaviorSanitizer).*)", re.S)


def run_libfuzzer(binary, workdir, *, seconds: int = 30, max_len: int = 4096,
                  corpus: list | None = None) -> dict:
    """Run the libFuzzer `binary` for `seconds`. Returns {crashes:[{input, report}], runs, log}.
    Each crash is the reproducing input (bytes) plus the sanitizer report libFuzzer printed."""
    workdir = Path(workdir)
    art = workdir / "lf-artifacts"
    art.mkdir(parents=True, exist_ok=True)
    corpus_dir = workdir / "lf-corpus"
    corpus_dir.mkdir(exist_ok=True)
    for i, seed in enumerate(corpus or []):
        try:
            (corpus_dir / f"seed{i}").write_bytes(seed if isinstance(seed, (bytes, bytearray)) else bytes(seed))
        except OSError:
            pass
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0:" + env.get("ASAN_OPTIONS", "")
    argv = [str(binary), str(corpus_dir), f"-max_total_time={seconds}", f"-max_len={max_len}",
            f"-artifact_prefix={art}/", "-print_final_stats=1", "-rss_limit_mb=2048"]
    crashes = []
    before = set(art.iterdir())
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=seconds + 30, env=env,
                           cwd=str(workdir))
        out = (r.stderr or "") + (r.stdout or "")
    except subprocess.TimeoutExpired as e:
        out = (e.stderr or b"").decode("latin-1", "ignore") if isinstance(e.stderr, bytes) else (e.stderr or "")
    m = _ASAN_HDR.search(out)
    report = m.group(1)[:4000] if m else None
    for f in sorted(set(art.iterdir()) - before):
        if f.name.startswith(("crash-", "oom-", "timeout-", "leak-")):
            try:
                crashes.append({"input": f.read_bytes(), "report": report})
            except OSError:
                pass
    return {"crashes": crashes, "log": out[-4000:]}
