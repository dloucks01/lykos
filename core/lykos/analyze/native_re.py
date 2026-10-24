"""Native (no-JVM) RE backend: rizin/radare2 for structure + decompilation, pypcode for the
Ghidra P-Code IR the detectors consume.

This is the Phase-1 (doc 24) alternative to the Ghidra-headless backend. It produces the SAME
analysis dict ``ghidra.parse_result`` returns -- ``{"program": {...}, "functions": [...],
"strings": [...], "imports": [...]}`` with per-function ``cfg`` (blocks -> instructions ->
``pcode``), ``frame``/``params``/``vars``, ``calls``, and ``decompiled`` -- so the disassemble
stage, the DB persistence, and every downstream detector (bounds/taint/int-overflow) run
unchanged.

Why this shape works with no Java:
  * The Ghidra *decompiler* and its SLEIGH lifter are C++, not Java. rizin+rz-ghidra (Kali
    package) or radare2+r2ghidra expose the decompiler; **pypcode** wraps the same SLEIGH
    engine to emit real Ghidra P-Code per instruction. So the P-Code the detectors parse is
    byte-for-byte the Ghidra IR -- just produced without the JVM.
  * What is genuinely weaker than full Ghidra is the *auto-analysis* (function boundaries,
    types, switch tables) feeding the decompiler -- see doc 24 for the honest delta.

The decompiled-C field uses the tool's Ghidra decompiler (``pdg`` from rz-ghidra/r2ghidra) when
present, else the built-in pseudo-decompiler (``pdc``) as a readable stand-in.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)

# Exhaustive by default: analyze EVERY function. A large kernel (the vxWorks 6.9 image is ~7200
# functions) previously had its function set silently TRUNCATED to the first 1200, so the CWE
# detectors -- which read the persisted function rows -- only ever saw ~17% of the program and the
# real defects in the rest were invisible. We now analyze all of them; the cost (minutes on a big
# binary) is paid by batching the per-function pass so it reports progress and survives a partial
# failure without losing the work already done. 0 = unlimited (the default); set LYKOS_MAX_FUNCS to
# a positive number only to deliberately cap a run.
_MAX_FUNCS = int(os.environ.get("LYKOS_MAX_FUNCS", "0") or "0")
# Hard ceiling for the SLEIGH (rizin-blind) recovery path specifically: unlike the rizin pass, it
# serialises every function's bytes to the worker, so a hostile symbol table declaring millions of
# functions would OOM. Independent of _MAX_FUNCS (which defaults to unlimited).
_SLEIGH_RECOVER_MAX = 100000
# How many times the isolated P-Code lifter is resumed after a native crash (pypcode aborts on some
# encodings) before the rest of the instructions are left un-lifted (and reported as such).
_LIFT_RESTARTS = int(os.environ.get("LYKOS_LIFT_RESTARTS", "8") or "8")
# The per-function structural pass is chunked into batches of this many functions. Each batch is a
# separate rizin invocation, so a batch that times out or errors costs only that batch -- the
# functions from prior batches are already on disk and get built and persisted. Smaller batches =
# finer progress + finer failure granularity; larger = less rizin-startup overhead.
_BATCH = max(1, int(os.environ.get("LYKOS_FUNC_BATCH", "500") or "500"))
# At or below this many functions the structural pass runs whole-program `aaa` (one pass): its
# emulation-based type propagation recovers array types, so buffers are detected precisely and the
# pass is still quick. Above it, `aaa` per batch would dominate the runtime, so we use the fast
# per-function path and recover buffers from stack geometry instead.
_AAA_MAX = int(os.environ.get("LYKOS_AAA_MAX", "2000") or "2000")
# Whole-program `aaa` (full autoanalysis: reference emulation, type propagation, autonaming) grows
# super-linearly with image size and TIMES OUT on a very large binary -- a 160MB .so never returns,
# so pass 1 fails and the target recovers NOTHING (no functions -> no detectors -> no escalation).
# Above this file size, pass 1 uses the lighter `aa` (analyze all: entry/symbol + call-graph function
# recovery), which completes and still yields the function list; buffers are then recovered from
# stack geometry, exactly the fallback the >_AAA_MAX function path already uses. The point is that a
# large binary comes back ANALYZED-but-lighter instead of not at all. Env-overridable.
_AAA_FULL_MAX_MB = float(os.environ.get("LYKOS_AAA_FULL_MAX_MB", "48") or "48")
# SIZE-TIERED recovery. Below this file size pass 1 is the original single whole-program `aaa` --
# a small binary gets exactly what it always got. At or above it, `aaa` (measured on r2 6.0.7:
# 110s / 2.3GB on a 36MB stripped C++ image, and on the field rizin it stopped finishing in the
# disassemble slice at ~24MB) is replaced by an ESCALATING ladder run in ONE process with a
# checkpoint after every rung:
#     aa  -> aflj checkpoint -> aac -> aflj checkpoint -> aar + string xrefs -> [aaa -> checkpoint]
# `aa` (symbols + entry) lands first so SOMETHING always comes back; `aac` (call-target function
# discovery) is what recovers a stripped binary's functions (gh, 36MB stripped Go: aa=65 functions,
# aa+aac=9,989 = the same as aaa, in 8s vs 25s); `aaa` is attempted last only below
# _AAA_FULL_MAX_MB, as a deepening the run keeps if it finishes. The deepest checkpoint that parses
# is used, so a per-pass timeout or an RLIMIT_AS kill mid-`aaa` keeps the `aa+aac` function list
# and call graph instead of collapsing to strings-only. Env-overridable.
_AAA_TIER_MB = float(os.environ.get("LYKOS_AAA_TIER_MB", "16") or "16")
# Share of the remaining stage time the tiered pass 1 may use (the per-function structural pass,
# the P-Code lift and the string table need the rest). When it runs out the deepest checkpoint is
# kept -- the cut is reported, never silent.
_P1_SHARE = float(os.environ.get("LYKOS_P1_SHARE", "0.6") or "0.6")
# Share of the (then) remaining time the optional `aaa` deepening may take, below _AAA_FULL_MAX_MB.
_P1_DEEPEN_SHARE = float(os.environ.get("LYKOS_P1_DEEPEN_SHARE", "0.25") or "0.25")
# Under a stage deadline, the batched structural pass stops while this share of the time it
# started with is still left, so the P-Code lift and the persist always run (see the batch loop).
_P2_RESERVE = float(os.environ.get("LYKOS_P2_RESERVE", "0.2") or "0.2")
_P2_POST_FACTOR = float(os.environ.get("LYKOS_P2_POST_FACTOR", "1.25") or "1.25")
# The (advisory, slowest) decompiled-C pass. Decompiling thousands of functions up front would take
# many minutes and risk losing everything on a timeout, and the detectors use the pypcode P-Code,
# not the C. So we decompile up to this many up front (small binaries come back fully decompiled),
# and EVERY OTHER function is decompiled lazily on demand when the analyst opens it (see the
# /functions/{id} endpoint). Nothing is permanently skipped. 0 disables the up-front pass entirely.
_MAX_DECOMPILE = int(os.environ.get("LYKOS_MAX_DECOMPILE", "400") or "400")
# Cap the per-string xref pass (axtj per string address) -- a big binary has tens of thousands of
# strings and computing an xref for each is another slow per-item loop. Strings are still all
# listed; only the xref sites beyond this cap are skipped.
_MAX_STRING_XREFS = int(os.environ.get("LYKOS_MAX_STRING_XREFS", "1500") or "1500")

# r2/rizin arch+bits+endian -> pypcode SLEIGH language id. Extend as architectures are added;
# an unmapped target still analyses (structure + decompile), only its P-Code is empty.
_SLEIGH = {
    ("x86", 64, "little"): "x86:LE:64:default",
    ("x86", 32, "little"): "x86:LE:32:default",
    ("arm", 32, "little"): "ARM:LE:32:v8",
    ("arm", 32, "big"): "ARM:BE:32:v8",
    ("arm", 64, "little"): "AARCH64:LE:64:v8A",
    ("aarch64", 64, "little"): "AARCH64:LE:64:v8A",
    ("ppc", 32, "big"): "PowerPC:BE:32:default",
    ("ppc", 64, "big"): "PowerPC:BE:64:default",
    ("mips", 32, "big"): "MIPS:BE:32:default",
    ("mips", 32, "little"): "MIPS:LE:32:default",
    # RISC-V: SLEIGH disassembles it even where the rizin build has no RISC-V plugin (Kali's does
    # not -- it silently decodes RISC-V bytes as x86). The pypcode recovery path below uses this.
    ("riscv", 64, "little"): "RISCV:LE:64:default",
    ("riscv", 32, "little"): "RISCV:LE:32:default",
}
# Arches the rizin/radare2 build here CANNOT disassemble (no asm plugin), so its structural pass
# decodes their bytes as the default (x86) and yields garbage bodies/edges. When SLEIGH can
# disassemble such a target, the pypcode recovery path owns the function bodies instead. rizin's
# bin loader still reads the correct arch name and the symbol-table function list, which we keep.
_RIZIN_BLIND = {"riscv"}

def locate_native(config: Optional[str] = None) -> Optional[Path]:
    """Path to the rizin or radare2 CLI, preferring rizin (the rz-ghidra host). Honours
    LYKOS_RIZIN / LYKOS_R2, then PATH."""
    for env in ("LYKOS_RIZIN", "LYKOS_R2"):
        v = os.environ.get(env)
        if v and Path(v).exists():
            return Path(v)
    if config and Path(config).exists():
        return Path(config)
    for name in ("rizin", "r2", "radare2"):
        w = shutil.which(name)
        if w:
            return Path(w)
    return None


#: What fraction of the host's CURRENTLY-AVAILABLE memory an analysis child may use. The cap is a
#: fraction, not a fixed number, precisely because another system has different memory than this
#: one: 60% leaves ~40% of whatever is free for the OS and other apps, on a 4GB laptop or a 256GB
#: server alike, computed fresh at the moment the child starts.
_MEM_CAP_FRACTION = 0.8
#: A floor so a normal binary's analysis is never starved on a modest host; and a lower bound below
#: which we do not bother capping (the host is already too small to protect this way).
_MEM_FLOOR_MB = 1024
#: An absolute ceiling: past this, rizin is not memory-starved, and a bigger cap just lets a
#: pathological binary map more before it is stopped. Keeps a 256GB server from handing one
#: analysis an absurd cap. Raised to 24GB so a large stripped binary gets room to analyse while
#: 80% of free RAM still leaves ~20% headroom for the host.
_MEM_CEILING_MB = 24576


def _mem_available_mb() -> Optional[int]:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    except Exception:
        # No readable /proc/meminfo (non-Linux, restricted container): return None so the caller
        # leaves the analysis child uncapped -- the prior behaviour -- rather than guessing a cap.
        return None
    return None


def _mem_cap_mb() -> Optional[int]:
    """How many MB of virtual address space an analysis child may use on THIS host, right now, or
    None to leave it uncapped. A fraction of currently-available memory (so it adapts to the
    machine the package runs on), floored so normal work is not starved and ceiled so a huge host
    does not hand one analysis an absurd cap."""
    avail = _mem_available_mb()
    if avail is None or avail < _MEM_FLOOR_MB:
        return None                                      # can't read it, or too small to help
    return int(max(_MEM_FLOOR_MB, min(avail * _MEM_CAP_FRACTION, _MEM_CEILING_MB)))


def _mem_cap_preexec():
    """A child preexec that caps VIRTUAL address space to leave the HOST headroom.

    rizin's whole-program analysis of a large binary grows without bound -- measured at ~3.5GB RSS
    and climbing on a 136MB Go binary -- and lykos ran it with NO memory limit, so on the laptop or
    server this is packaged onto it could exhaust RAM and take the whole MACHINE down, not just the
    analysis. Cap the child's RLIMIT_AS at a fraction of what is free RIGHT NOW (so the cap suits
    whatever host it runs on) and a huge-binary analysis fails GRACEFULLY -- rizin hits the cap and
    exits, disassemble recovers whatever was persisted and reports a truncation -- instead of
    OOMing the box. Measured: a 2GB cap held rizin's RSS to 1.8GB on the 136MB target that reached
    3.5GB uncapped. Only RLIMIT_AS is set, not RLIMIT_FSIZE, because rizin writes its analysis JSON
    to redirected files that legitimately exceed any small size cap. Returns None when memory
    cannot be read, leaving the child uncapped (the prior behaviour)."""
    cap_mb = _mem_cap_mb()
    if cap_mb is None:
        return None

    def _apply():
        try:
            import resource
            lim = cap_mb << 20
            resource.setrlimit(resource.RLIMIT_AS, (lim, lim))
        except Exception:
            # Runs post-fork, pre-exec in the child: no logging is possible here. If the limit
            # cannot be set (no resource module, hardened sandbox), proceed uncapped rather than
            # abort the analysis -- the cap is a safety margin, not a correctness requirement.
            pass
    return _apply


def _run(cli: Path, binary: Path, script: str, *, ctx=None, timeout: int,
         scratch: Optional[Path] = None) -> Optional[subprocess.CompletedProcess]:
    """Run a rizin/radare2 command script. Output is captured by the script itself via per-
    command file redirection (`cmd > file`), NOT by parsing stdout -- this is the only approach
    that is portable across rizin and radare2. rizin's `?e` markers do not print and abort the
    command chain, and rizin warns to stderr during `ij`, so we never rely on stdout ordering.

    Returns the CompletedProcess (returncode + captured stdout/stderr), so a caller that needs to
    tell a CLEAN empty result from a rizin that actually CRASHED can look at rc/stderr -- most
    callers ignore it (output comes from the redirected files). stderr is NOT a failure signal on
    its own: rizin writes analysis warnings there on a clean run.

    The script is delivered through a file with `-i`, never inline with `-c`: a statically linked
    sanitizer build carries thousands of functions, and the per-function structural/decompile
    pass then builds a multi-megabyte command string that overflows ARG_MAX -- the raw
    OSError(E2BIG, 'Argument list too long') that took `disassemble` (and thus the whole
    analysis) down on every ASan source target. A file has no such limit; rizin is run
    unsandboxed here, so it can read the script from the scratch dir alongside its output files.

    Two flags matter: not -2 (closing stderr makes rizin abort when it warns), and
    bin.relocs.apply for correct call targets."""
    import tempfile
    d = str(scratch) if scratch is not None else None
    fd, spath = tempfile.mkstemp(prefix="rzscript-", suffix=".rz", dir=d)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(script)
        cmd = [str(cli), "-q", "-e", "scr.color=0", "-e", "bin.relocs.apply=true",
               "-i", spath, str(binary)]
        # stdin MUST be /dev/null. rizin, seeing a non-TTY stdin (a worker's inherited pipe),
        # treats it as a COMMAND STREAM and blocks reading it -- so `disassemble` hangs forever
        # with no CPU whenever the server's stdin is not already /dev/null (e.g. ./RUN.sh launched
        # so the worker inherits an open pipe). Immediate EOF makes rizin quit after -i as intended.
        # Cap the child's memory to leave the host headroom: a large-binary analysis must never be
        # able to OOM the laptop it is packaged onto (see `_mem_cap_preexec`).
        _pre = _mem_cap_preexec()
        if ctx is not None:
            return ctx.run_subprocess(cmd, timeout=timeout, stdin=subprocess.DEVNULL,
                                      preexec_fn=_pre)
        return subprocess.run(cmd, capture_output=True, timeout=timeout,
                              stdin=subprocess.DEVNULL, preexec_fn=_pre)
    finally:
        try:
            os.unlink(spath)
        except OSError:
            pass


def _is_local_cut(e: BaseException, ctx) -> bool:
    """Is `e` a per-CALL cut (this one rizin call overran its own `timeout`) rather than the stage
    itself stopping? A local cut is recoverable -- keep the checkpoints already written; a user
    cancel / stage deadline (ctx.should_cancel()) or anything else must propagate."""
    if isinstance(e, subprocess.TimeoutExpired):
        return True
    if type(e).__name__ == "StageTimeout":
        try:
            return ctx is not None and not ctx.should_cancel()
        except Exception:                                   # noqa: BLE001
            return False
    return False


def _time_share(ctx, timeout: float, share: float, floor: int = 30) -> int:
    """A per-call timeout that is `share` of what the stage still has (its deadline when the ctx
    carries one, else `timeout`), floored so a pass is never handed a useless sliver."""
    import time as _t
    avail = float(timeout)
    dl = getattr(ctx, "deadline", None) if ctx is not None else None
    if isinstance(dl, (int, float)):
        avail = min(avail, max(0.0, dl - _t.time()))
    return int(max(floor, avail * max(0.05, min(1.0, share))))


# Read-only mmap view of a file for the byte-level ELF helpers (see elf.MappedFile).
from .elf import MappedFile as _Mapped  # noqa: E402


def _deadline_left(ctx):
    """Seconds until the stage deadline, or None when the ctx carries none."""
    dl = getattr(ctx, "deadline", None) if ctx is not None else None
    if not isinstance(dl, (int, float)):
        return None
    import time as _t
    return dl - _t.time()


def _prioritize(addrs: list, fn_by_addr: dict) -> list:
    """`addrs` with the functions that CALL a catalogued input source or dangerous sink first
    (stable otherwise). Uses pass-1 call refs (rizin embeds them in aflj); with none, unchanged."""
    try:
        from .detect.catalog import DANGEROUS, SOURCES, normalize
    except Exception:                                       # noqa: BLE001
        return addrs
    hot = set(DANGEROUS) | set(SOURCES)
    names = {a: _clean_name((f or {}).get("name")) for a, f in fn_by_addr.items()}

    def score(a):
        for c in (fn_by_addr.get(a) or {}).get("callrefs") or ():
            if isinstance(c, dict) and normalize(names.get(c.get("to")) or "") in hot:
                return 0
        return 1
    return sorted(addrs, key=score)                         # sorted() is stable


def _tiered_pass1(cli: Path, binary: Path, T: Path, main_seed: str, size_mb: float, string_addrs,
                  *, ctx, timeout: int) -> dict:
    """Pass 1 for a large binary (see _AAA_TIER_MB), in two rizin calls:

      1. ESSENTIAL, checkpointed: cheap facts -> `aa` -> aflj -> `aac` -> aflj -> `aar` + the string
         xrefs, within _P1_SHARE of the time left. Whatever rung it reaches is kept.
      2. DEEPEN (only below _AAA_FULL_MAX_MB, and only when call 1 finished): a fresh `aaa` -> aflj,
         attempted only if its estimated cost (~1.5x call 1, measured 1.4x on a 36MB C++ image) fits
         _P1_DEEPEN_SHARE of what is left; a cut or skipped deepening keeps the `aa+aac` list
         (measured: the same function count to within 0.1%) and is noted, never silent.

    Returns {"aflj", "tier", "planned", "proc", "cut", "budget", "xrefs_done", "notes"}."""
    import time as _t
    seed = main_seed.strip().rstrip(";")
    rungs = [("aa", "aa"), ("aa+aac", "aac")]
    planned = [r[0] for r in rungs] + (["aaa"] if size_mb < _AAA_FULL_MAX_MB else [])
    # Cheap facts first, so they land even if the analysis is killed (RLIMIT_AS on a huge image).
    parts = [_redir("ij", T / "ij"), _redir("izj", T / "strings"), _redir("iij", T / "imports")]
    for i, (_label, cmd) in enumerate(rungs):
        parts.append(cmd)
        if seed:
            parts.append(seed)
        parts.append(_redir("aflj", T / f"funcs.{i}"))
    # String xrefs ride on the analysis already loaded (a second whole-program pass just for them
    # would double the cost); `aar` is what records data references (+2s on a 43MB Go image), and
    # gives the same xrefs `aaa` does (measured on a 36MB C++ and a 36MB Go image).
    if string_addrs:
        parts.append("aar")
        for a in string_addrs:
            parts.append(f"s {a}")
            parts.append(_redir("axtj", T / f"x_{a}"))
        parts.append(_redir("ij", T / "xrefs.done"))           # marker: every xref was written
    budget = _time_share(ctx, timeout, _P1_SHARE)
    _emit(ctx, msg=(f"large binary ({size_mb:.0f}MB): tiered analysis "
                    f"{' -> '.join(planned)} (checkpointed; {budget}s share)"))
    proc, cut, notes = None, False, []
    t0 = _t.time()
    try:
        proc = _run(cli, binary, ";".join(parts), ctx=ctx, timeout=budget, scratch=T)
    except Exception as e:                                      # noqa: BLE001
        if not _is_local_cut(e, ctx):
            raise
        cut = True
    took = _t.time() - t0
    # The deepest checkpoint that parses (a rung killed mid-write leaves torn JSON -> skipped), but
    # never let an EMPTY deeper rung hide a non-empty shallower one.
    parsed = [(rungs[i][0], _readj(T / f"funcs.{i}", None)) for i in range(len(rungs))]
    parsed = [(t, g) for t, g in parsed if isinstance(g, list)]
    tier, aflj = ([p for p in parsed if p[1]] or parsed or [(None, [])])[-1]

    if "aaa" in planned and not cut and tier == "aa+aac" and aflj:
        est = took * 1.5
        d_budget = _time_share(ctx, timeout, _P1_DEEPEN_SHARE, floor=0)
        if est > d_budget:
            notes.append(f"`aaa` deepening skipped: estimated {est:.0f}s exceeds its "
                         f"{d_budget}s share of the time left; functions and call graph come "
                         f"from `aa+aac`")
        else:
            dparts = ["aaa"] + ([seed] if seed else []) + [_redir("aflj", T / "funcs.2")]
            try:
                _run(cli, binary, ";".join(dparts), ctx=ctx, timeout=d_budget, scratch=T)
            except Exception as e:                              # noqa: BLE001
                if not _is_local_cut(e, ctx):
                    raise
            deeper = _readj(T / "funcs.2", None)
            if isinstance(deeper, list) and deeper:
                tier, aflj = "aaa", deeper
            else:
                notes.append(f"`aaa` deepening did not finish in its {d_budget}s share; "
                             f"functions and call graph come from `aa+aac`")
    return {"aflj": aflj, "tier": tier, "planned": planned, "proc": proc, "cut": cut,
            "budget": budget, "xrefs_done": (T / "xrefs.done").exists(), "notes": notes}


def _emit(ctx, *, pct=None, msg=None):
    """Best-effort progress emit. Never raises: progress is a courtesy, not part of the result,
    and a ctx that lacks progress() (or one that fails) must not take the analysis down."""
    if ctx is None:
        return
    try:
        if pct is not None:
            ctx.progress(pct=pct, msg=msg)
        else:
            ctx.progress(msg=msg)
    except Exception:
        observe.absorbed(_log, "continuing")


def _readj(path: Path, default):
    """Read + JSON-parse a file a rizin command redirected into; default if missing/empty/bad."""
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return default
    try:
        return json.loads(text)
    except Exception:
        _log.debug("rizin JSON parse failed for %s", path, exc_info=True)
        return default


def _redir(cmd: str, path: Path) -> str:
    """A rizin command whose output is redirected to a file (`cmd > path`)."""
    return f"{cmd} > {path}"


def _tail_stderr(err, n: int = 400) -> str:
    """Short, printable tail of a child's captured stderr (bytes or str), for a diagnostic note /
    log line; "" when there is nothing."""
    if not err:
        return ""
    if isinstance(err, (bytes, bytearray)):
        return bytes(err[-n:]).decode("utf-8", "replace").strip()
    return str(err)[-n:].strip()


def _vn(ctx, v) -> str:
    """Format one P-Code varnode exactly as ExportAnalysis.java does: registers as
    'reg:NAME:size', constants as 'const:0xVAL:size', everything else 'space:0xOFF:size'."""
    sp = v.space.name
    if sp == "register":
        try:
            rn = ctx.getRegisterName(v.space, v.offset, v.size)
        except Exception:
            observe.absorbed(_log, "keeping the default")
            rn = None
        return f"reg:{rn}:{v.size}" if rn else f"register:{hex(v.offset)}:{v.size}"
    if sp == "const":
        return f"const:{hex(v.offset)}:{v.size}"
    return f"{sp}:{hex(v.offset)}:{v.size}"


def _have_pypcode() -> bool:
    try:
        import pypcode  # noqa: F401
        return True
    except Exception:                                        # noqa: BLE001
        return False


def _pcode_worker_path() -> Path:
    """Path to the standalone pcode_worker.py. Materialize it from the package when it is not a
    real file on disk (e.g. running from a zipapp), so it can be handed to a child interpreter."""
    here = Path(__file__).parent / "pcode_worker.py"
    if here.exists():
        return here
    import tempfile
    from importlib import resources
    data = (resources.files("lykos.analyze") / "pcode_worker.py").read_bytes()
    p = Path(tempfile.mkdtemp(prefix="lykos-pcodew-")) / "pcode_worker.py"
    p.write_bytes(data)
    return p


class _Lifter:
    """Ghidra P-Code via pypcode (SLEIGH, no JVM), lifted in a SEPARATE PROCESS.

    pypcode is a C extension that can crash the interpreter (a native double-free / SIGABRT on some
    instruction encodings -- seen on ppc64 big-endian). Lifting in-process would abort the whole
    server, so `lift_all` runs pcode_worker.py as a child: a crash there is contained, and the
    parent keeps every function's structure plus whatever P-Code was flushed. Falls back to empty
    P-Code when pypcode/the language is unavailable -- structure/decompile still work."""

    def __init__(self, langid: Optional[str]):
        self.langid = langid or None
        self.available = bool(langid) and _have_pypcode()
        # Honest bookkeeping for the last lift_all: instructions that crashed the lifter (skipped
        # after being pinpointed), and how many were left un-lifted (crash budget / timeout).
        self.crashed_at: list = []
        self.unlifted = 0
        self.lift_status = "ok"

    def lift_all(self, instrs: list, *, ctx=None, timeout: int = 600) -> dict:
        """Lift many instructions at once in a child process. `instrs` is [(addr_int, hexbytes)].
        Returns {addr_hex: [op_strings]}.

        A native crash on ONE encoding used to cost every instruction after the last flush --
        on a large binary, a crash early in 1.5M instructions silently left ~all of it without
        P-Code. The worker writes one row per instruction IN ORDER, so the parent knows exactly
        where it stopped: it RESUMES from there (the first resume flushes per-instruction so the
        offending encoding is pinpointed), SKIPS the crasher, and carries on -- bounded by
        _LIFT_RESTARTS and the overall timeout. What could not be lifted is counted on
        `self.unlifted` / `self.crashed_at` for the caller to report."""
        self.crashed_at, self.unlifted, self.lift_status = [], 0, "ok"
        if not self.available or not instrs:
            return {}
        import time as _t
        out: dict = {}
        remaining = list(instrs)
        pinpoint = False
        t_end = _t.time() + max(1, timeout)
        for _attempt in range(_LIFT_RESTARTS + 1):
            left = int(t_end - _t.time())
            if left < 1:
                self.lift_status = "timeout"
                break
            rows, status = self._invoke_status(
                {"langid": self.langid, "instrs": [[a, h] for a, h in remaining],
                 "flush_first": 256 if pinpoint else 0},
                ctx=ctx, timeout=left)
            done = 0
            for row in rows:
                if "a" in row:
                    out[row["a"]] = row.get("p") or []
                    done += 1
            if done >= len(remaining) or status != "crashed":
                if done < len(remaining):
                    self.lift_status = status
                remaining = remaining[done:]
                break
            if pinpoint and done < 256:
                self.crashed_at.append(remaining[done][0])      # this encoding kills the lifter
                remaining = remaining[done + 1:]
                pinpoint = False
            else:
                remaining = remaining[done:]
                pinpoint = True
            self.lift_status = "crashed"
        self.unlifted = max(0, len(instrs) - len(out) - len(self.crashed_at))
        return out

    def disasm_regions(self, regions: list, *, ctx=None, timeout: int = 600) -> dict:
        """Linearly disassemble whole function byte-ranges in the isolated worker -- for an arch the
        structural backend cannot disassemble, SLEIGH recovers the instruction boundaries itself.
        `regions` is [(addr_int, hexbytes)]; returns {region_addr_hex: [{a,len,text,p}, ...]}."""
        if not self.available or not regions:
            return {}
        rows = self._invoke({"langid": self.langid, "regions": [[a, h] for a, h in regions]},
                            ctx=ctx, timeout=timeout)
        return {row["region"]: (row.get("insns") or []) for row in rows if "region" in row}

    def _invoke(self, spec: dict, *, ctx=None, timeout: int = 600) -> list:
        """Run the isolated pcode worker with `spec` and return the parsed JSONL rows. A crash/timeout
        kills only the child; whatever it flushed is returned."""
        return self._invoke_status(spec, ctx=ctx, timeout=timeout)[0]

    def _invoke_status(self, spec: dict, *, ctx=None, timeout: int = 600) -> tuple:
        """`_invoke`, plus how the worker ended: "ok", "crashed" (non-zero exit / signal) or
        "timeout". A genuine stage cancel / deadline propagates (it used to be swallowed here)."""
        import tempfile
        d = Path(tempfile.mkdtemp(prefix="lykos-pcode-"))
        inp, outp = d / "in.json", d / "out.jsonl"
        try:
            inp.write_text(json.dumps(spec))
            cmd = [sys.executable, str(_pcode_worker_path()), str(inp), str(outp)]
            popen_env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
            status = "ok"
            try:
                if ctx is not None:
                    res = ctx.run_subprocess(cmd, timeout=timeout, env=popen_env)
                else:
                    res = subprocess.run(cmd, timeout=timeout, capture_output=True, check=False,
                                         stdin=subprocess.DEVNULL, env=popen_env)
                if getattr(res, "returncode", 0) not in (0, None):
                    status = "crashed"
                    _log.warning("pcode worker exited rc=%s; using its partial output",
                                 res.returncode)
            except Exception as e:                         # noqa: BLE001 -- crash/timeout: use partial
                if type(e).__name__ in ("StageCancelled", "StageTimeout") and (
                        ctx is not None and ctx.should_cancel()):
                    raise
                status = "timeout"
                _log.debug("pcode worker crashed or timed out; using partial output", exc_info=True)
            rows = []
            try:
                with open(outp, errors="replace") as fh:
                    for line in fh:                        # a torn final line from a hard crash
                        line = line.strip()
                        if line:
                            try:
                                rows.append(json.loads(line))
                            except ValueError:
                                continue
            except OSError:
                pass
            return rows, status
        finally:
            shutil.rmtree(d, ignore_errors=True)


def _clean_name(n: Optional[str]) -> Optional[str]:
    """Normalise a rizin/r2 symbol name to the plain form Ghidra emits, so the detectors (which
    match clean names like 'strcpy') fire unchanged. rizin decorates names: 'sym.imp.strcpy',
    'sym.strcpy', 'dbg.bug', 'reloc.puts', trailing '_NNN', a '@plt' suffix."""
    if not n:
        return n
    for pre in ("sym.imp.", "sym.func.", "sym.", "imp.", "dbg.", "reloc.", "loc.", "flirt."):
        if n.startswith(pre):
            n = n[len(pre):]
            break
    if n.endswith("@plt"):
        n = n[:-4]
    return n


def _is_import(rawname: Optional[str]) -> bool:
    """True when a rizin symbol denotes an imported / PLT-thunk function (Ghidra marks these
    'external')."""
    r = rawname or ""
    return r.startswith(("sym.imp.", "imp.", "reloc.")) or "@plt" in r or ".plt" in r


def _langid(prog: dict) -> Optional[str]:
    arch = (prog.get("arch") or "").lower()
    bits = int(prog.get("bits") or 0)
    endian = "big" if str(prog.get("endian") or "little").lower().startswith("b") else "little"
    return _SLEIGH.get((arch, bits, endian))


_BUFFER_SLOT_MIN = int(os.environ.get("LYKOS_BUFFER_SLOT_MIN", "16") or "16")


def _infer_buffers(vars_: list) -> list:
    """Size each stack local from the gap to the next-higher local, and mark the large ones as
    buffers even when the type was not recovered as an array.

    Without a decompiler that propagates array types (rz-ghidra `pdg`), rizin types a `char[64]`
    as a plain slot, so `is_buffer` ('[' in the type) is never set and the stack-smash detector
    stays silent on exactly the stripped/undecompiled binaries that need it most -- e.g. a whole
    VxWorks kernel where 6000+ functions had stack frames but ZERO recovered buffers. A local
    occupying >= 16 bytes is the classic smashable region; the detector still only fires when such
    a slot COINCIDES with an unbounded copy in the same function, so this widens recall without
    turning every large local into a finding on its own."""
    locs = [v for v in vars_ if isinstance(v.get("offset"), int) and v["offset"] < 0]
    locs.sort(key=lambda v: v["offset"])          # most negative (furthest from frame base) first
    for i, v in enumerate(locs):
        nxt = locs[i + 1]["offset"] if i + 1 < len(locs) else 0
        slot = nxt - v["offset"]
        if slot > 0 and not v.get("size"):
            v["size"] = slot
        if slot >= _BUFFER_SLOT_MIN and not v.get("is_buffer"):
            v["is_buffer"] = True
            v["buffer_inferred"] = True           # geometry, not a recovered array type
    return vars_


def _frame_and_vars(afvj: dict) -> tuple:
    """Turn rizin/r2 afvj (reg/bp/sp variable lists) into the schema's params + frame.vars +
    geometry. is_buffer = the recovered type is an array ('[' in the type) OR a large stack slot."""
    params, vars_, local_size = [], [], 0
    for p in (afvj.get("reg") or []):
        params.append({"name": p.get("name"), "type": p.get("type"), "reg": p.get("ref")})
    for v in (afvj.get("bp") or []) + (afvj.get("sp") or []):
        ref = v.get("ref") or {}
        off = ref.get("offset") if isinstance(ref, dict) else None
        typ = v.get("type") or ""
        vars_.append({"name": v.get("name"), "type": typ, "offset": off,
                      "is_buffer": "[" in typ})
        if isinstance(off, int) and off < 0:
            local_size = max(local_size, -off)
    frame = {"frame_size": local_size, "local_size": local_size,
             "param_size": 0, "ret_offset": 0, "vars": _infer_buffers(vars_)}
    return params, frame


def _frame_vars_rizin(meta: dict) -> tuple:
    """rizin embeds variables in aflj: `stackvars` [{name, arg, type, storage:{stack:off}}] and
    `regvars`. Locals (arg=false) become frame.vars (is_buffer = array type); args become
    params. This is what the bounds detector keys on (a fixed-size stack buffer + a sink)."""
    params, vars_, local_size = [], [], 0
    for v in (meta.get("stackvars") or []):
        st = v.get("storage") or {}
        off = st.get("stack") if isinstance(st, dict) else None
        typ = v.get("type") or ""
        if v.get("arg"):
            params.append({"name": v.get("name"), "type": typ})
        else:
            vars_.append({"name": v.get("name"), "type": typ, "offset": off,
                          "is_buffer": "[" in typ})
        if isinstance(off, int) and off < 0:
            local_size = max(local_size, -off)
    for r in (meta.get("regvars") or []):
        if r.get("arg"):
            params.append({"name": r.get("name"), "type": r.get("type")})
    frame = {"frame_size": local_size, "local_size": local_size,
             "param_size": 0, "ret_offset": 0, "vars": _infer_buffers(vars_)}
    return params, frame


def _faddr(f: dict):
    """Function start address: rizin uses `offset`, radare2 6.x uses `addr`."""
    a = f.get("offset")
    return a if a is not None else f.get("addr")


def quick_facts(binary: Path, *, ctx=None, timeout: int = 60) -> dict:
    """Strings + imports + program metadata with NO auto-analysis -- fast and size-independent.

    `analyze()` runs these behind the expensive `aaa` in one invocation, so on a large binary where
    `aaa` cannot finish within the budget the strings and imports are lost too and the target
    reports zero findings (a 24MB server timed out `aaa` -> 0 strings, 0 findings). This extracts
    just the cheap facts (`izj`/`iij`/`ij` -- none need `aaa`) so the disassemble stage can persist
    them FIRST; the detectors that key on strings and imports then still have input even when the
    full structural analysis is cut short. Returns {"program", "strings", "imports"}; best-effort
    (an empty result on any failure, never raising)."""
    try:
        from .. import vendorenv
        vendorenv.activate()
    except Exception:
        observe.absorbed(_log, "continuing")
    cli = locate_native()
    if cli is None:
        return {"program": {}, "strings": [], "imports": []}
    binary = Path(binary)
    import tempfile
    own = ctx is None
    scratch = ctx.scratch() if not own else Path(tempfile.mkdtemp(prefix="lykos-qf-"))
    T = Path(scratch) / "qf"
    T.mkdir(parents=True, exist_ok=True)
    try:
        try:
            _run(cli, binary, ";".join([
                _redir("ij", T / "ij"), _redir("izj", T / "strings"),
                _redir("iij", T / "imports")]),
                ctx=ctx, timeout=timeout, scratch=T)
        except Exception:
            observe.absorbed(_log, "quick_facts extraction cut short")
        ij = _readj(T / "ij", {})
        izj = _readj(T / "strings", [])
        iij = _readj(T / "imports", [])
    finally:
        if own:
            shutil.rmtree(scratch, ignore_errors=True)
    binf = ij.get("bin", {}) if isinstance(ij, dict) else {}
    core = ij.get("core", {}) if isinstance(ij, dict) else {}
    strings = [{"addr": hex(s["vaddr"]) if isinstance(s.get("vaddr"), int) else "",
                "value": s.get("string") or "", "xrefs": []}
               for s in (izj if isinstance(izj, list) else []) if isinstance(s, dict)]
    imports = [i.get("name") for i in (iij if isinstance(iij, list) else [])
               if isinstance(i, dict) and i.get("name")]
    prog = {"format": core.get("format") or binf.get("class") or "",
            "arch": binf.get("arch") or "", "bits": binf.get("bits") or 0}
    return {"program": prog, "strings": strings, "imports": imports}


def analyze(binary: Path, *, ctx=None, timeout: int = 900) -> dict:
    """Full native analysis producing the ghidra.parse_result schema, via file redirection
    (portable across rizin and radare2)."""
    # Ensure the vendored toolchain is on PATH (rizin) and pypcode is on sys.path, even when the
    # caller did not go through cli.main (tests, embeddings, a worker started directly).
    # Idempotent -- a second call is a no-op.
    try:
        from .. import vendorenv
        vendorenv.activate()
    except Exception:
        observe.absorbed(_log, "continuing")
    cli = locate_native()
    if cli is None:
        raise RuntimeError("no rizin/radare2 found for the native RE backend")
    binary = Path(binary)

    import tempfile
    # A ctx owns (and cleans) its scratch; a ctx-less caller (the CLI variant/patch-diff commands)
    # got a private temp dir that was never removed -- on a large binary that is hundreds of
    # thousands of per-function files left in /tmp per call. Remove it when we made it.
    own = ctx is None
    scratch = ctx.scratch() if not own else Path(tempfile.mkdtemp(prefix="lykos-nre-"))
    T = Path(scratch) / "nre"
    T.mkdir(parents=True, exist_ok=True)
    try:
        return _analyze_in(cli, binary, T, ctx=ctx, timeout=timeout)
    finally:
        if own:
            shutil.rmtree(scratch, ignore_errors=True)


def _analyze_in(cli: Path, binary: Path, T: Path, *, ctx, timeout: int) -> dict:
    """The body of `analyze`, writing its rizin output files under `T`."""
    # Recover `main` on an aarch64 binary where the disassembler would miss it: main is passed to
    # __libc_start_main only as a data pointer (never called), so a static/stripped aarch64 target
    # gets no function/name there. Decode _start (doc 04) and seed rizin with it so main is
    # analyzed + named for the function list, decompilation, xrefs and detectors alike.
    main_seed = ""
    try:
        from . import elf as _elf
        with _Mapped(binary) as _data:                    # mmap: never copy a 100MB image whole
            _mva = _elf.main_from_start(_data)
        if _mva is not None:
            main_seed = f"af @ {hex(_mva)}; afn main @ {hex(_mva)}; "
    except Exception:
        observe.absorbed(_log, "continuing")

    # Pass 1: program metadata + function list + strings + imports, each redirected to a file.
    # Keep the CompletedProcess: pass 1 is the run that discovers the function list, so its
    # rc/stderr is what tells a genuinely CLEAN "0 functions" apart from a rizin that crashed or
    # fell back to an old/incompatible build and recovered nothing (see the empty-recovery check
    # after the function list is parsed).
    #
    # SIZE-TIERED analysis depth (see _AAA_TIER_MB): whole-program `aaa` stops finishing in a normal
    # budget on a large image (and its RSS gets it killed by the RLIMIT_AS cap on a ~100MB one), and
    # a pass 1 that dies recovers NOTHING structural -- the run degraded to strings-only. A small
    # binary keeps the original single `aaa` pass byte-for-byte; a large one runs the checkpointed
    # aa -> aac -> [aaa] ladder and keeps the deepest rung that landed.
    try:
        _size_mb = binary.stat().st_size / (1024.0 * 1024.0)
    except OSError:
        _size_mb = 0.0
    tiered = _size_mb >= _AAA_TIER_MB
    degradations: list = []               # honest notes on every rung/pass that fell short
    tier = "aaa"
    p1_cut = False
    if not tiered:
        _p1 = _run(cli, binary, "aaa;" + main_seed + ";".join([
            _redir("ij", T / "ij"), _redir("aflj", T / "funcs"),
            _redir("izj", T / "strings"), _redir("iij", T / "imports")]),
            ctx=ctx, timeout=timeout, scratch=T)
        aflj = _readj(T / "funcs", [])
    else:
        # The string table first (no analysis, seconds) so pass 1 can compute the string xrefs on
        # the analysis it already holds.
        try:
            _run(cli, binary, _redir("izj", T / "strings"), ctx=ctx,
                 timeout=_time_share(ctx, min(timeout, 180), 1.0), scratch=T)
        except Exception as e:                            # noqa: BLE001
            if not _is_local_cut(e, ctx):
                raise
        _izj0 = _readj(T / "strings", [])
        xref_strings = [s.get("vaddr") for s in (_izj0 if isinstance(_izj0, list) else [])
                        if isinstance(s, dict)
                        and isinstance(s.get("vaddr"), int)][:_MAX_STRING_XREFS]
        _tp = _tiered_pass1(cli, binary, T, main_seed, _size_mb, xref_strings,
                            ctx=ctx, timeout=timeout)
        _p1, aflj, tier, p1_cut = _tp["proc"], _tp["aflj"], _tp["tier"], _tp["cut"]
        _how = (f"was cut at its {_tp['budget']}s share" if p1_cut else
                f"exited rc={getattr(_p1, 'returncode', None)}")
        if tier is None:
            degradations.append(f"tiered analysis ({' -> '.join(_tp['planned'])}) {_how} before "
                                f"even the `aa` rung landed: no function list was recovered")
        elif tier == "aa":
            degradations.append(f"tiered analysis {_how} after the `aa` rung (planned "
                                f"{' -> '.join(_tp['planned'])}): call-target discovery (aac) "
                                f"did not finish, so functions reached only by calls in a "
                                f"stripped binary are missing")
        degradations.extend(_tp["notes"])
        _emit(ctx, msg=(f"pass 1 recovered {len(aflj)} functions at the `{tier}` rung"
                        if tier else "pass 1 recovered no function list"))
    _p1_rc = getattr(_p1, "returncode", None)
    _p1_err = _tail_stderr(getattr(_p1, "stderr", None))
    # rizin warns to stderr by design, but a NON-ZERO exit is a real problem: surface its stderr
    # tail to the log so an old/absent/incompatible rizin is visible even when it still produced
    # some output. (The empty-recovery decision below additionally treats stderr-with-rc!=0 and
    # the 0-functions case as a failure.)
    if _p1_rc not in (0, None):
        _log.warning("rizin/r2 exited rc=%s during analysis pass 1%s", _p1_rc,
                     f"; stderr tail: {_p1_err}" if _p1_err else "")
    ij = _readj(T / "ij", {})
    binf = ij.get("bin", {}) if isinstance(ij, dict) else {}
    core = ij.get("core", {}) if isinstance(ij, dict) else {}
    prog = {
        "format": core.get("format") or binf.get("class") or "",
        "arch": binf.get("arch") or "", "bits": binf.get("bits") or 0,
        "endian": binf.get("endian") or "little",
        "compiler": binf.get("compiler") or "",
        "image_base": hex(binf.get("baddr") or 0),
    }
    prog["language"] = _langid(prog) or f'{prog["arch"]}:{prog["bits"]}'
    lifter = _Lifter(_langid(prog))

    izj = _readj(T / "strings", [])
    iij = _readj(T / "imports", [])
    fn_by_addr = {_faddr(f): f for f in aflj if isinstance(f, dict) and _faddr(f) is not None}
    # Skip the compiler/sanitizer/coverage runtime entirely (see _is_runtime_name). A static
    # ASan+UBSan build links in ~3,800 such functions for a one-line program, and analyzing them
    # (per-function structure + P-Code lift) is ~100s and hundreds of MB of pure waste: nothing
    # consumes their analysis -- the memory-safety detectors drop them by the same name test, and a
    # call into one keeps its name on the call EDGE regardless. Dropping them here keeps the static
    # binary self-contained for execution while making its analysis proportional to the user's code.
    runtime_n = sum(1 for f in fn_by_addr.values()
                    if _is_runtime_name(_clean_name(f.get("name"))))
    if runtime_n:
        fn_by_addr = {a: f for a, f in fn_by_addr.items()
                      if not _is_runtime_name(_clean_name(f.get("name")))}
        _emit(ctx, msg=f"skipping {runtime_n} sanitizer/compiler-runtime functions")
    # EXHAUSTIVE by default: every function is analyzed. A positive LYKOS_MAX_FUNCS caps it on
    # request; 0 (the default) means no cap. The old default silently kept only the first 1200,
    # which blinded the detectors to the rest of a large program.
    total_fns = len(fn_by_addr)
    if _MAX_FUNCS and total_fns > _MAX_FUNCS:
        fn_by_addr = dict(list(fn_by_addr.items())[:_MAX_FUNCS])
        _emit(ctx, msg=f"{total_fns} functions — capped to {_MAX_FUNCS} (LYKOS_MAX_FUNCS)")
    target_fns = len(fn_by_addr)

    # rizin embeds stack vars + call refs in aflj (per function); radare2 does not, and its
    # `afvj`/`afxj` commands do -- but on rizin `afvj` is unknown and ABORTS the -c chain. So we
    # take vars/calls from aflj on rizin, and only add afvj/afxj to the pass on radare2.
    #
    # Key this off the resolved BACKEND, not merely whether pass-1 happened to return stackvars:
    # a small/leaf/stripped rizin target can recover none, and keying on data presence then set
    # embedded=False, injected `afvj`, and ABORTED the whole per-function chain -- yielding a
    # near-empty structural pass reported as success. rizin is always `embedded`; the data check
    # remains as a secondary signal (e.g. a radare2 build that does embed skips the extra commands).
    is_rizin = Path(cli).name == "rizin"
    embedded = is_rizin or any(
        isinstance(f, dict) and ("stackvars" in f or "callrefs" in f) for f in aflj)

    # When the structural backend has no disassembler for this arch (e.g. Kali's rizin lacks the
    # RISC-V plugin and silently decodes it as x86), its per-function structure/CFG/edges are garbage.
    # If SLEIGH can disassemble it, recover the function bodies with pypcode instead -- skip rizin's
    # structural/decompile passes entirely and keep only its (correct) symbol-table function list.
    rizin_blind = (prog["arch"] or "").lower() in _RIZIN_BLIND and lifter.available
    if rizin_blind:
        _emit(ctx, msg=f"{prog['arch']}: structural backend cannot disassemble it; "
                       f"recovering function bodies via SLEIGH ({lifter.langid})")

    # Pass 2 (structure): CFG + disasm + stack vars per function, redirected to per-function files.
    #
    # Two strategies, chosen by size:
    #   * small binary (<= _AAA_MAX functions): ONE analysis pass that runs whole-program `aaa`
    #     first. `aaa` propagates types (emulation), so a `char[16]` comes back typed as an array
    #     and is_buffer is set from the type -- the precise signal the bounds detector wants. Cheap
    #     at this size, and one pass is fine because it finishes quickly.
    #   * large binary (> _AAA_MAX): BATCHED per-function `af @ addr` with NO whole-program `aaa`.
    #     Pass 1 already discovered every function, so `af` (analyze just this one) is ~60x cheaper
    #     than re-running `aaa` per batch -- 500 kernel functions in ~0.5s -- and batching means the
    #     run reports progress and never loses everything (a batch that times out is skipped, its
    #     predecessors already written). `aaa`-quality types are lost, so _infer_buffers recovers
    #     buffers from stack geometry instead.
    addrs = [] if rizin_blind else list(fn_by_addr)   # rizin-blind arch: SLEIGH recovery owns bodies
    done = 0
    failed_batches = 0
    stopped_at = None                                     # batch index a deadline stop cut at

    def _reraise_if_cancel(e):
        # A genuine stage cancel/deadline must PROPAGATE, not be swallowed as a "failed batch":
        # otherwise a user cancel keeps grinding through every remaining batch and the stage reports
        # a partial "done". Identified by class name to avoid importing the jobs layer here.
        #
        # BUT a per-BATCH subprocess that merely exceeded its own `timeout` ALSO surfaces as
        # StageTimeout (context.run_subprocess raises it for its local per-call cap, not only the
        # stage deadline). Propagating THAT killed the whole exhaustive pass and discarded every
        # batch already written -- the opposite of the batching design. So only propagate when the
        # STAGE is genuinely stopping (should_cancel() covers user-cancel and the stage deadline);
        # a bare per-batch timeout falls through and is counted as one failed batch.
        if type(e).__name__ == "KeyboardInterrupt":
            raise e
        if type(e).__name__ in ("StageCancelled", "StageTimeout"):
            if ctx is None or ctx.should_cancel():
                raise e

    def _fn_cmds(a):
        parts = [f"s {a}", _redir("afbj", T / f"{a}.b"), _redir("pdfj", T / f"{a}.o")]
        if not embedded:                                  # radare2: pull vars/calls via commands
            parts.append(_redir("afvj", T / f"{a}.v"))
            parts.append(_redir("afxj", T / f"{a}.x"))
        return parts

    if target_fns <= _AAA_MAX and not tiered:
        # (a large image always takes the batched path below: one whole-program pass that times
        # out would lose every function, and its `aaa` is exactly what tiering avoids)
        parts = ["aaa"]
        for a in addrs:
            parts += _fn_cmds(a)
        try:
            _run(cli, binary, ";".join(parts), ctx=ctx, timeout=timeout, scratch=T)
        except Exception as e:                            # noqa: BLE001
            _reraise_if_cancel(e)
            failed_batches += 1
            _emit(ctx, msg=f"structural pass did not finish ({type(e).__name__}); "
                           f"building the functions that were written")
        _emit(ctx, pct=75, msg=f"disassembled {target_fns} functions")
    else:
        # DEADLINE-AWARE batching. Running into the stage deadline mid-batch raised out of
        # analyze() and discarded EVERY batch already written (plus the whole function list), so a
        # large binary on a budget slice came back strings-only. When the stage has a deadline, the
        # loop instead stops while a reserve is still left for the P-Code lift + persist; the
        # functions it did not reach keep their pass-1 name and call edges (the call graph stays
        # whole) and the shortfall is reported. No deadline (CLI, tests) -> unchanged.
        # The reserve GROWS with the work done: building + lifting + persisting the functions
        # structured so far costs about as long as structuring them did (measured on a 36MB C++
        # image: 18,000 functions structured in ~100s, then ~40s just to build them and a 2.1M-
        # instruction lift), so the loop stops when the time left can no longer cover
        # _P2_POST_FACTOR x the structural time spent (+ the next batch), floored by _P2_RESERVE.
        import time as _t
        left0 = _deadline_left(ctx)
        reserve = None if left0 is None else max(30.0, _P2_RESERVE * left0)
        p2_t0, p2_batches = _t.time(), 0
        # With a deadline in play, take the functions that call a catalogued source/sink first,
        # so a cut keeps structure where the detectors look. Order is result-neutral otherwise.
        if reserve is not None:
            addrs = _prioritize(addrs, fn_by_addr)
        for i in range(0, len(addrs), _BATCH):
            if ctx is not None:
                ctx.check_cancel()                        # honor a cancel/timeout between batches
            left = _deadline_left(ctx)
            need = None
            if reserve is not None and left is not None:
                spent = _t.time() - p2_t0
                nxt = spent / p2_batches if p2_batches else 0.0
                need = max(reserve, (spent + nxt) * _P2_POST_FACTOR + 20.0)
                if left - nxt < need:
                    stopped_at = i
                    break
            p2_batches += 1
            chunk = addrs[i:i + _BATCH]
            parts = []
            for a in chunk:
                parts.append(f"af @ {a}")
                parts += _fn_cmds(a)
            btimeout = timeout if need is None else int(max(15, min(timeout, left - need)))
            try:
                _run(cli, binary, ";".join(parts), ctx=ctx, timeout=btimeout, scratch=T)
            except Exception as e:                        # noqa: BLE001 -- one batch, not the run
                _reraise_if_cancel(e)
                failed_batches += 1
                _emit(ctx, msg=f"disassembly batch {i // _BATCH + 1} did not finish "
                               f"({type(e).__name__}); keeping the {done} functions already done")
            done += len(chunk)
            pct = 5 + int(70 * done / max(1, target_fns))  # 5..75% is the structural pass
            _emit(ctx, pct=min(75, pct),
                  msg=f"disassembled {min(done, target_fns)}/{target_fns} functions")
        if stopped_at is not None:
            degradations.append(
                f"structural pass stopped ahead of the stage deadline: {done}/{len(addrs)} "
                f"functions got CFG/instructions/P-Code; the other {len(addrs) - done} keep "
                f"their name and call edges only (time reserved for the P-Code lift and persist)"
                " -- raise the budget for full depth")
            _emit(ctx, msg=degradations[-1])

    # Pass 3 (decompile): advisory C, the slowest step. We decompile only up to _MAX_DECOMPILE up
    # front (small binaries come back fully decompiled); every other function decompiles lazily on
    # demand when opened (see the /functions/{id} endpoint), so nothing is permanently skipped and a
    # big binary is not held up for minutes producing C that the detectors never read.
    if _MAX_DECOMPILE and target_fns <= _MAX_DECOMPILE and not rizin_blind:
        dec_cmd = "pdg" if _has_pdg(cli, binary, ctx, timeout) else "pdc"
        # A large (tiered) image defines just the functions it decompiles (`af @ a`) instead of
        # re-running the whole-program `aaa` that tiering exists to avoid.
        dparts = [] if tiered else ["aaa"]
        for a in addrs:
            if tiered:
                dparts.append(f"af @ {a}")
            dparts.append(f"s {a}")
            dparts.append(_redir(dec_cmd, T / f"{a}.d"))
        try:
            _run(cli, binary, ";".join(dparts), ctx=ctx, timeout=timeout, scratch=T)
        except Exception as e:                            # noqa: BLE001 -- advisory C only
            _reraise_if_cancel(e)          # a user cancel / stage deadline must still stop the run
            _log.debug("up-front decompile pass failed", exc_info=True)
    elif target_fns > _MAX_DECOMPILE:
        _emit(ctx, pct=78, msg=f"decompiled C is on-demand for {target_fns} functions "
                               f"(opens decompile the function you click; detectors use P-Code)")

    _emit(ctx, pct=80, msg=f"lifting P-Code for {target_fns} functions")
    # Bound the SLEIGH recovery by the stage deadline too (the rizin path bounds its lift inside
    # _build_functions): cut locally it keeps what it recovered; run INTO the deadline it raises.
    _left = _deadline_left(ctx)
    lift_timeout = timeout if _left is None else int(max(15, min(timeout, _left * 0.85)))
    functions = (_recover_via_pcode(binary, fn_by_addr, lifter, ctx=ctx, timeout=lift_timeout)
                 if rizin_blind
                 else _build_functions(T, fn_by_addr, lifter, embedded, ctx=ctx,
                                       timeout=timeout))
    if lifter.crashed_at or lifter.unlifted:
        # P-Code is what every data-flow detector reads: a lift that lost instructions is a
        # degradation of exactly those detectors, never a silent one.
        degradations.append(
            f"P-Code lift incomplete ({lifter.lift_status}): "
            f"{lifter.unlifted + len(lifter.crashed_at)} instruction(s) "
            f"left without P-Code" + (f"; {len(lifter.crashed_at)} encoding(s) crashed the "
                                      f"lifter and were skipped" if lifter.crashed_at else ""))
    strings, _xref_note = _build_strings(cli, binary, izj, T, ctx=ctx, timeout=timeout,
                                         precomputed=tiered)
    if _xref_note:
        degradations.append(_xref_note)
    imports = [i.get("name") for i in iij if isinstance(i, dict) and i.get("name")]

    # Empty recovery that is actually a FAILURE, not a clean "0 functions". When rizin crashed,
    # returned non-zero, or wrote to stderr while recovering ZERO functions (old bundled rizin, a
    # fallback to an old host r2, a missing arch plugin), the old result read as "ran clean, 0
    # functions" and every function-keyed detector silently starved. Flag it so the stage reports
    # recovery FAILED with the rc/stderr, rather than a silent clean small result.
    recovery_failed = (len(functions) == 0
                       and (_p1_rc not in (0, None) or bool(_p1_err) or p1_cut))
    recovery_error = ""
    if recovery_failed and p1_cut:
        recovery_error = (f"rizin/r2 recovered 0 functions: the tiered analysis of this "
                          f"{_size_mb:.0f} MB binary was cut before its first rung (`aa`) landed "
                          f"-- not a clean empty program; raise the budget to analyse it")
    elif recovery_failed:
        recovery_error = (f"rizin/r2 recovered 0 functions (rc={_p1_rc}"
                          + (f", stderr: {_p1_err}" if _p1_err else "")
                          + ") -- the disassembler produced no program (an old/incompatible "
                            "rizin/r2 or a missing arch plugin); every function-keyed detector "
                            "would see an empty program")

    return {"program": prog, "function_count": len(functions),
            "functions": functions, "strings": strings, "imports": imports,
            # honest bookkeeping: how complete this analysis is, surfaced by the stage.
            "total_functions": total_fns, "analyzed_functions": len(functions),
            "partial": bool(failed_batches or recovery_failed or stopped_at is not None
                            or (_MAX_FUNCS and total_fns > _MAX_FUNCS)
                            # tiered: stopped at `aa` -> call-discovered functions are missing
                            or (tiered and tier in (None, "aa"))),
            "failed_batches": failed_batches,
            # an empty recovery that was really a crash/incompatible-rizin, not a clean 0.
            "recovery_failed": recovery_failed, "recovery_error": recovery_error,
            # which pass-1 depth produced the function list ("aaa" for every small binary; the
            # deepest checkpointed rung for a tiered large one), and every pass that fell short.
            "analysis_tier": tier, "tiered": tiered, "degradations": degradations}


def decompile_one(binary: Path, addr, *, ctx=None, timeout: int = 120) -> str:
    """Decompile a SINGLE function on demand and return its C (or "" if unavailable).

    The disassemble stage decompiles only a bounded number of functions up front (decompiling
    thousands would take minutes and mostly go unread), so the /functions/{id} endpoint calls this
    to decompile the one function an analyst actually opened, then caches the result on the row.
    Uses `af @ addr` -- no whole-program analysis -- so it is fast even on a huge binary."""
    try:
        cli = locate_native()
    except Exception:
        observe.absorbed(_log, "keeping the default")
        cli = None
    if cli is None or addr is None:
        return ""
    try:
        a = int(addr, 16) if isinstance(addr, str) and addr.lower().startswith("0x") \
            else int(addr) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        return ""                      # a malformed address: no C, not an endpoint 500
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="lykos-dec1-"))
    try:
        dec_cmd = "pdg" if _has_pdg(cli, Path(binary), ctx, timeout) else "pdc"
        out = d / "d"
        script = f"af @ {a};s {a};" + _redir(dec_cmd, out)
        _run(cli, Path(binary), script, ctx=ctx, timeout=timeout, scratch=d)
        try:
            return _decompiled(out.read_text(errors="replace"))
        except OSError:
            return ""
    except Exception:
        _log.debug("on-demand decompile failed for %s", addr, exc_info=True)
        return ""
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _has_pdg(cli: Path, binary: Path, ctx, timeout: int) -> bool:
    """Is the Ghidra decompiler (rz-ghidra `pdg`) available? Probe by redirecting its help to a
    file: rz-ghidra prints usage; a rizin/r2 without it writes nothing (and, unlike a chained
    command, a lone unknown command is harmless)."""
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="lykos-pdg-"))
    try:
        _run(cli, binary, _redir("pdg?", d / "p"), ctx=None, timeout=min(timeout, 60))
        try:
            txt = (d / "p").read_text(errors="replace")
        except OSError:
            return False
        # A tool WITHOUT the decompiler answers `pdg?` with an install/error message, which is
        # non-empty -- so "any output" wrongly reported it present and the error text got stored
        # as the decompilation. Require real usage text and reject the known "install me" reply.
        if _is_missing_decompiler(txt):
            return False
        return "pdg" in txt.lower() or len(txt.strip()) > 8
    except Exception:
        observe.absorbed(_log, "answering no")
        return False
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _is_missing_decompiler(txt: str) -> bool:
    """The reply a tool gives for `pdg` when rz-ghidra / r2ghidra is not installed."""
    t = (txt or "").lower()
    return ("r2pm" in t or "rz-pm" in t or "install the plugin" in t
            or "you need to install" in t or "unknown command" in t or "cannot find" in t)


# Compiler/sanitizer/coverage runtime that an ASan+UBSan build statically links in. Its P-Code is
# never consumed (the memory-safety detectors drop these functions by the same name test), but on a
# sanitizer build it is the bulk of the functions -- ~3,800 for a one-line program -- and lifting
# all of it costs ~100s. Keep the functions (call graph, names) but skip the SLEIGH lift for them;
# any consumer that ever needs one re-decompiles it on demand.
_RUNTIME_PREFIXES = ("__asan", "__ubsan", "__lsan", "__tsan", "__msan", "__hwasan",
                     "__sanitizer", "__sancov", "asan.", "sancov.", "__sanitize")


def _is_runtime_name(name) -> bool:
    return bool(name) and str(name).startswith(_RUNTIME_PREFIXES)


_CALL_OP_TYPES = {"call", "ucall", "rcall", "ccall", "icall"}
_SYMTOK = re.compile(r"\b(?:sym|fcn|loc)\.(?:imp\.)?([A-Za-z_][\w.]*)")


def _calls_from_ops(ops: list, fn_by_addr: dict) -> list:
    """Call edges harvested from the per-instruction disassembly (rizin/r2 `ops`), for arches whose
    xref DB comes back empty. An op is a call when its `type` is a call variant; the target is the
    numeric `jump` when present, else the `sym.`/`fcn.` name the disassembler already resolved."""
    calls = []
    for o in ops:
        if (o.get("type") or "").lower() not in _CALL_OP_TYPES:
            continue
        frm = o.get("offset") if o.get("offset") is not None else o.get("addr")
        dst = o.get("jump")
        raw = (fn_by_addr.get(dst) or {}).get("name") if isinstance(dst, int) else None
        if not raw:                                          # fall back to the resolved name in text
            m = _SYMTOK.search(o.get("disasm") or o.get("opcode") or "")
            raw = m.group(0) if m else None
        calls.append({"site_addr": hex(frm) if isinstance(frm, int) else None,
                      "dst_addr": hex(dst) if isinstance(dst, int) else None,
                      "dst_name": _clean_name(raw), "external": _is_import(raw)})
    return calls


def _va_to_off(data: bytes, va: int):
    """File offset of a virtual address via the ELF program headers (ELF64/ELF32, either endian), or
    None. Used to feed a function's raw bytes to the SLEIGH recovery for a rizin-blind arch."""
    try:
        if data[:4] != b"\x7fELF":
            return None
        is64 = data[4] == 2
        en = "<" if data[5] == 1 else ">"
        if is64:
            e_phoff = struct.unpack_from(en + "Q", data, 32)[0]
            e_phentsize = struct.unpack_from(en + "H", data, 54)[0]
            e_phnum = struct.unpack_from(en + "H", data, 56)[0]
        else:
            e_phoff = struct.unpack_from(en + "I", data, 28)[0]
            e_phentsize = struct.unpack_from(en + "H", data, 42)[0]
            e_phnum = struct.unpack_from(en + "H", data, 44)[0]
        for i in range(e_phnum):
            b = e_phoff + i * e_phentsize
            if struct.unpack_from(en + "I", data, b)[0] != 1:        # PT_LOAD
                continue
            if is64:
                p_off, p_va, _p_pa, p_fsz = struct.unpack_from(en + "QQQQ", data, b + 8)[:4]
            else:
                p_off, p_va, _p_pa, p_fsz = struct.unpack_from(en + "IIII", data, b + 4)[:4]
            if p_va <= va < p_va + p_fsz:
                return p_off + (va - p_va)
    except (struct.error, IndexError):
        return None
    return None


def _recover_via_pcode(binary: Path, fn_by_addr: dict, lifter: "_Lifter", *,
                       ctx=None, timeout: int = 600) -> list:
    """Build the function list for an arch the structural backend cannot disassemble (rizin decodes
    its bytes as x86 garbage) by disassembling each symbol-table function's byte range with SLEIGH in
    the isolated worker. Recovers instructions (+ P-Code) and call edges (from P-Code CALL/CALLIND
    ops, whose direct targets SLEIGH resolves) -- the function LIST and names still come from rizin's
    (correct) symbol-table read; only the bodies are recovered here."""
    with _Mapped(binary) as data:          # mmap: only the function byte ranges are paged in
        return _recover_regions(data, fn_by_addr, lifter, ctx=ctx, timeout=timeout)


def _recover_regions(data, fn_by_addr: dict, lifter: "_Lifter", *, ctx=None,
                     timeout: int = 600) -> list:
    # The per-function SIZE in the structural backend's list was computed by its wrong (x86) decode,
    # so it cannot be trusted here. Bound each region by the NEXT function's start (the standard
    # linear-sweep bound), falling back to the symtab size then a cap -- decoding a little trailing
    # padding is harmless, decoding into the next function is not.
    sorted_addrs = sorted(fn_by_addr)
    next_addr = {a: sorted_addrs[i + 1] for i, a in enumerate(sorted_addrs[:-1])}
    # Bound the NUMBER of regions, not just each region's size: a hostile symbol table could declare
    # millions of functions, and serialising that many 64 KiB hex blobs to the worker is an OOM/hang.
    if len(sorted_addrs) > _SLEIGH_RECOVER_MAX:
        _emit(ctx, msg=f"SLEIGH recovery: {len(sorted_addrs)} functions — capping to "
                       f"{_SLEIGH_RECOVER_MAX}")
        sorted_addrs = sorted_addrs[:_SLEIGH_RECOVER_MAX]
    regions = []
    for faddr in sorted_addrs:
        meta = fn_by_addr[faddr]
        off = _va_to_off(data, faddr)
        if off is None:
            continue
        gap = next_addr.get(faddr, faddr + (meta.get("size") or 4096)) - faddr
        size = max(0, min(gap if gap > 0 else (meta.get("size") or 0), 1 << 16))
        if size <= 0:
            continue
        regions.append((faddr, data[off:off + size].hex()))
    _emit(ctx, msg=f"SLEIGH recovery: disassembling {len(regions)} functions (rizin-blind arch)")
    recovered = lifter.disasm_regions(regions, ctx=ctx, timeout=timeout)
    functions = []
    for faddr in sorted_addrs:                           # capped set only (don't materialise millions)
        meta = fn_by_addr[faddr]
        insns = recovered.get(hex(faddr)) or []
        instructions, calls = [], []
        for ins in insns:
            instructions.append({"addr": ins["a"], "text": ins.get("text") or "",
                                 "pcode": ins.get("p") or []})
            for op in (ins.get("p") or []):
                if op.startswith(("CALL ", "CALLIND ")):
                    # "CALL ram:0x16cca:8" -> resolve the ram target to a known function's name
                    dst = _ram_target(op)
                    raw = (fn_by_addr.get(dst) or {}).get("name") if dst is not None else None
                    calls.append({"site_addr": ins["a"],
                                  "dst_addr": hex(dst) if dst is not None else None,
                                  "dst_name": _clean_name(raw),
                                  "external": _is_import(raw)})
                    break
        block = {"addr": hex(faddr), "succ": [], "instructions": instructions}
        functions.append({
            "addr": hex(faddr), "name": _clean_name(meta.get("name")) or f"fcn.{faddr:x}",
            "size": meta.get("size") or 0, "signature": meta.get("signature") or "",
            "calling_convention": meta.get("cc") or meta.get("calltype") or "",
            "thunk": bool(meta.get("is-pure") or meta.get("is_pure")), "varargs": False,
            "decompiled": "", "blocks": 1 if instructions else 0, "edges": 0,
            "cfg": {"blocks": [block] if instructions else [], "edges": 0},
            "params": [], "frame": {"size": 0, "vars": []}, "calls": calls,
        })
    return functions


def _ram_target(op: str):
    """The ram address a 'CALL ram:0x..:sz' P-Code op points at, or None (indirect / non-ram)."""
    for tok in op.split()[1:]:
        if tok.startswith("ram:"):
            try:
                return int(tok.split(":")[1], 16)
            except (ValueError, IndexError):
                return None
    return None


def _build_functions(T: Path, fn_by_addr: dict, lifter: "_Lifter", embedded: bool,
                     ctx=None, timeout: int = 600) -> list:
    functions = []
    # P-Code is lifted OUT OF PROCESS (pypcode can crash on some encodings), so we first build every
    # function with empty pcode while collecting the instruction bytes, then lift them all in one
    # child and fill the results in. `pending` holds (addr, ins_dict) so the fill is a dict lookup.
    to_lift = {}                                             # addr_int -> hexbytes (deduped)
    pending = []                                             # (addr_int, ins_dict) to fill
    for faddr, meta in fn_by_addr.items():
        afbj = _readj(T / f"{faddr}.b", [])
        pdfj = _readj(T / f"{faddr}.o", {})
        afvj = _readj(T / f"{faddr}.v", {})
        afxj = _readj(T / f"{faddr}.x", [])
        try:
            decompiled = _decompiled((T / f"{faddr}.d").read_text(errors="replace"))
        except OSError:
            decompiled = ""

        ops = pdfj.get("ops", []) if isinstance(pdfj, dict) else \
            (pdfj if isinstance(pdfj, list) else [])
        ins_by_addr = {}
        for o in ops:
            a = o.get("offset") if o.get("offset") is not None else o.get("addr")  # rizin|r2
            if a is None or o.get("type") == "invalid":
                continue
            hexb = o.get("bytes", "") or ""
            ins = {"addr": hex(a), "text": o.get("disasm") or o.get("opcode") or "", "pcode": []}
            ins_by_addr[a] = ins
            if hexb:
                to_lift[a] = hexb
                pending.append((a, ins))

        blocks, edges = [], 0
        for b in (afbj if isinstance(afbj, list) else []):
            baddr = b.get("addr")
            bsize = b.get("size") or 0
            insns = [ins_by_addr[a] for a in sorted(ins_by_addr)
                     if baddr is not None and baddr <= a < baddr + bsize]
            succ = [hex(s) for s in (b.get("jump"), b.get("fail")) if isinstance(s, int)]
            edges += len(succ)
            blocks.append({"addr": hex(baddr) if isinstance(baddr, int) else str(baddr),
                           "succ": succ, "instructions": insns})

        # vars + calls: from aflj-embedded fields on rizin, from afvj/afxj files on radare2.
        if embedded:
            params, frame = _frame_vars_rizin(meta)
            callrefs = meta.get("callrefs") or []
        else:
            params, frame = _frame_and_vars(afvj)
            callrefs = afxj if isinstance(afxj, list) else []
        calls = []
        for c in callrefs:
            if (c.get("type") or "").upper() not in ("CALL", "CCALL", "UCALL"):
                continue
            dst = c.get("to")
            raw = (fn_by_addr.get(dst) or {}).get("name")
            frm = c.get("from")
            calls.append({
                "site_addr": hex(frm) if isinstance(frm, int) else None,
                          "dst_addr": hex(dst) if isinstance(dst, int) else None,
                          "dst_name": _clean_name(raw),
                          "external": _is_import(raw)})
        # Fallback: some arches (e.g. s390) disassemble correctly but leave callrefs/afxj EMPTY even
        # though the instruction stream clearly has calls -- rizin's xref DB just doesn't record them.
        # Harvest the call edges straight from the per-instruction ops (type == call, target from the
        # `jump` field or the `sym.`/`fcn.` token in the disasm), so the call graph is not lost.
        if not calls:
            calls = _calls_from_ops(ops, fn_by_addr)

        functions.append({
            "addr": hex(faddr), "name": _clean_name(meta.get("name")) or f"fcn.{faddr:x}",
            "size": meta.get("size") or 0, "signature": meta.get("signature") or "",
            "calling_convention": meta.get("cc") or meta.get("calltype") or "",
            "thunk": bool(meta.get("is-pure") or meta.get("is_pure")),
            "varargs": False, "decompiled": decompiled,
            "blocks": len(blocks), "edges": edges,
            "cfg": {"blocks": blocks, "edges": edges},
            "params": params, "frame": frame, "calls": calls,
        })

    # Lift every instruction's P-Code in ONE isolated child, then fill it into the built functions.
    if to_lift:
        # Deadline-aware: the lift gets what is left of the stage minus a persist reserve, measured
        # HERE (building the functions above takes real time on a large binary). A lift cut on its
        # own timeout keeps what it lifted and reports the rest; one that ran INTO the stage
        # deadline raised and lost the whole analysis.
        left = _deadline_left(ctx)
        lt = timeout if left is None else int(min(timeout, left * 0.8 - 5))
        if lt < 10:
            lifter.crashed_at, lifter.unlifted = [], len(to_lift)
            lifter.lift_status = "no time left before the stage deadline"
            _emit(ctx, msg=f"no time left to lift P-Code for {len(to_lift)} instructions")
            return functions
        _emit(ctx, msg=f"lifting P-Code for {len(to_lift)} instructions (isolated)")
        pcode_map = lifter.lift_all(sorted(to_lift.items()), ctx=ctx, timeout=lt)
        for a, ins in pending:
            ops = pcode_map.get(hex(a))
            if ops:
                ins["pcode"] = ops
    return functions


import re as _re

from .. import observe

_ANSI = _re.compile(r"\x1b\[[0-9;]*m")


def _decompiled(text: str) -> str:
    """pdg emits C directly; pdc emits pseudo-C. Return whichever, trimmed and with the terminal
    colour codes pdc leaves in stripped -- but never the tool's "install the decompiler" reply,
    which is not source and should read as 'none'."""
    t = _ANSI.sub("", text or "").strip()
    return "" if (not t or _is_missing_decompiler(t)) else t


def _build_strings(cli: Path, binary: Path, izj, T: Path, *, ctx, timeout,
                   precomputed: bool = False) -> tuple:
    """Strings + their xref sites (axtj per string address), each redirected to a file.

    Returns (strings, note). `precomputed` (a tiered large binary): pass 1 already wrote the
    `x_<addr>` files on the analysis it held, so only read them -- re-running a whole-program
    analysis here just for xrefs is the cost tiering avoids. `note` is "" when every capped string
    got its xref pass, else an honest one-line degradation (the strings themselves are always
    returned; only their xref sites are missing)."""
    strings = []
    addrs = [s.get("vaddr") for s in (izj if isinstance(izj, list) else [])
             if isinstance(s, dict) and isinstance(s.get("vaddr"), int)][:_MAX_STRING_XREFS]
    xrefs_by_addr = {}
    note = ""
    if addrs:
        if not precomputed:
            parts = ["aaa"]
            for a in addrs:
                parts.append(f"s {a}")
                parts.append(_redir("axtj", T / f"x_{a}"))
            try:
                _run(cli, binary, ";".join(parts), ctx=ctx, timeout=timeout, scratch=T)
            except Exception as e:                        # noqa: BLE001
                # A per-call timeout here used to propagate and discard the WHOLE analysis (every
                # function already built) over a best-effort xref pass. Keep the functions; a real
                # cancel / stage deadline still propagates.
                if not _is_local_cut(e, ctx):
                    raise
        done = 0
        for a in addrs:
            if (T / f"x_{a}").exists():
                done += 1
            xj = _readj(T / f"x_{a}", [])
            xrefs_by_addr[a] = [hex(x.get("from")) for x in (xj if isinstance(xj, list) else [])
                                if isinstance(x, dict) and isinstance(x.get("from"), int)]
        if done < len(addrs):
            note = (f"string xrefs were computed for {done}/{len(addrs)} strings (the xref pass "
                    f"did not finish); the remaining strings are listed without their "
                    f"referencing sites")
    for s in (izj if isinstance(izj, list) else []):
        va = s.get("vaddr")
        strings.append({"addr": hex(va) if isinstance(va, int) else "",
                        "value": s.get("string") or "",
                        "xrefs": xrefs_by_addr.get(va, [])})
    return strings, note
