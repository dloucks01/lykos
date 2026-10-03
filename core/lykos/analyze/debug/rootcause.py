"""Root-cause analysis of a confirmed crash (Phase 6).

Turns a fault capture (registers, fault address, faulting-instruction bytes, backtrace, memory
maps -- from the ptrace helper or GDB) into a structured explanation: what kind of memory-
safety failure occurred, where, and how attacker input reached it. The dynamic fault is then
*sliced* against the static call graph and taint results to name the path from an input source
to the crash site. objdump, when present, disassembles the faulting instruction (read vs write
vs return); everything else is pure stdlib.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from typing import Optional

from ..detect.catalog import SOURCES, normalize

_OBJDUMP_MACH = {"x86-64": "i386:x86-64", "x86": "i386", "aarch64": "aarch64", "arm": "arm"}


def _to_int(x):
    try:
        return int(x, 0) if isinstance(x, str) else int(x)
    except (ValueError, TypeError):
        return None


def disasm_one(pc_bytes: bytes, arch: str):
    """Disassemble the first instruction in `pc_bytes` via objdump; None if unavailable."""
    if not pc_bytes or not shutil.which("objdump"):
        return None
    mach = _OBJDUMP_MACH.get(arch, "i386:x86-64")
    fd, path = tempfile.mkstemp(suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(pc_bytes)
        r = subprocess.run(["objdump", "-D", "-b", "binary", "-m", mach, "-M", "intel", path],
                           capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    for line in r.stdout.splitlines():
        s = line.strip()
        parts = s.split("\t")
        if len(parts) >= 3 and parts[0].rstrip().endswith(":"):
            return parts[2].strip()
    return None


def mapping_for(maps, addr):
    if addr is None:
        return None
    for m in maps or []:
        if m["start"] <= addr < m["end"]:
            return m
    return None


def _fn_ranges(functions):
    out = []
    for f in functions:
        fa = _to_int(f.addr)
        if fa is None:
            continue
        size = f.size or 1
        out.append((fa, fa + size, f))
    out.sort()
    return out


def _fn_at(ranges, addr):
    for lo, hi, f in ranges:
        if lo <= addr < hi:
            return f
    return None


def module_base(maps, target_path):
    """Runtime load base of the target's OWN module."""
    if not maps or not target_path:
        return 0
    want = os.path.basename(target_path)
    starts = [m["start"] for m in maps
              if m.get("path") and os.path.basename(m["path"]) == want]
    return min(starts) if starts else 0


_ENTRY_NAMES = ("entry", "_start", "__start")


def _is_entry_name(name: str) -> bool:
    """True for the disassembler's name of the ELF entry point. Ghidra calls it `entry`/`_start`;
    rizin AND radare2 both call it `entry0` (and would use `entry1`... for extra entries) -- which
    the old `in ("entry","start")` check missed, so `image_base` returned None and PIE targets
    rebased NOTHING, silently killing crash attribution on every position-independent binary. The
    dotted decoys rizin also emits -- `entry.init0`, `entry.fini0` -- are the libc init/fini
    thunks, NOT the entry, so they are excluded (they contain a `.`)."""
    nm = (name or "").lstrip("_").lower()
    if "." in nm:
        return False
    return nm == "start" or nm == "entry" or (nm.startswith("entry") and nm[5:].isdigit())


def image_base(functions, elf_entry):
    """The address the DECOMPILER placed file offset 0 at, or None if it cannot be derived.

    Ghidra rebases a position-independent image -- 0x100000 for ET_DYN on this toolchain --
    so a runtime address minus its load base is a FILE OFFSET, not a decompiler address. That
    is derived here rather than assumed: the ELF header gives the entry point as a file vaddr
    and the function table gives the same function's decompiler address, and the difference
    between them is the base. Guessing it (rounding the lowest function down to a boundary)
    would resolve frames to the wrong functions whenever the guess was off.
    """
    if elf_entry is None:
        return None
    for f in functions:
        if _is_entry_name(f.name or ""):
            a = _to_int(f.addr)
            if a is not None and a >= elf_entry:
                return a - elf_entry
    return None


def rebase_delta(maps, target_path, functions, elf_entry):
    """How much to subtract from a runtime address to get a decompiler address.

    0 for a non-PIE image (the two coincide) and None when it cannot be established, in which
    case frames are matched absolutely and a PIE target simply resolves nothing -- which is
    what it did before, and is at least honest.
    """
    rb = module_base(maps, target_path)
    ib = image_base(functions, elf_entry)
    if not rb or ib is None:
        return None
    return rb - ib


def symbolize(addr, maps, ranges, target_path, delta=None):
    m = mapping_for(maps, addr)
    module = os.path.basename(m["path"]) if (m and m["path"]) else (
        "[anon]" if m else "??")
    entry = {"addr": addr, "module": module,
             "offset": (addr - m["start"]) if m else None, "symbol": None}
    f = _fn_at(ranges, addr)                      # absolute match (no-PIE)
    static = addr
    if f is None and delta and module == os.path.basename(target_path or ""):
        f = _fn_at(ranges, addr - delta)          # PIE: rebase into the decompiler's image
        if f is not None:
            static = addr - delta
    if f is not None:
        entry["symbol"] = f.name or f"sub_{f.addr}"
        entry["func_addr"] = f.addr
        entry["static_addr"] = static
    return entry


# Widest call encoding across the supported ISAs (m68k `jsr` reaches 6 bytes; SuperH's return
# address clears a delay slot), so a return address sits within this much of its call.
_CALL_WINDOW = 16
# Weakest to strongest. The distinction is the whole point: being in the same function as a
# crash is proximity, while faulting inside the call a finding names is a demonstration.
_TIERS = ("crash-function", "on-stack", "fault-site")


def attribute(frames, findings, sites_by_finding=None):
    """Which static findings does this crash actually demonstrate, and at which site?

    A verified PoC used to land as an orphan row keyed on the signal, next to an undifferen-
    tiated pile of static findings -- on jhead, one "out-of-bounds read" beside 38 unknown
    copy sites, several in the very function the fault was in, with nothing joining them.
    The backtrace already says which calls were executing; this reads it.

    Strength is graded and only the top tier is a proof:
      fault-site     the faulting PC is inside the call this site makes -- the sink itself
                     faulted, so the finding is demonstrated
      on-stack       that call was somewhere on the stack, so the site is on the crash path
      crash-function the site merely sits in a function the stack runs through

    Every tier NAMES THE SITE. Findings are deduped at defect grain -- one CWE-120 row covers
    twenty memcpy sites -- so "this defect occurs in a function on the stack" is close to
    vacuous on its own; which occurrence is the whole content of the claim.
    """
    by_finding = sites_by_finding or {}
    occ_of, sites = {}, []
    for f in findings:
        occ = [o for o in (by_finding.get(f.id) or []) if o.get("site_addr")]
        if not occ and f.site_addr:
            occ = [{"function_addr": f.function_addr, "site_addr": f.site_addr}]
        occ_of[f.id] = occ
        for o in occ:
            sa = _to_int(o.get("site_addr"))
            if sa is not None:
                sites.append((sa, f, o))
    fn_addrs = {_to_int(fr.get("func_addr")) for fr in frames}
    fn_addrs.discard(None)
    sym_of = {_to_int(fr.get("func_addr")): fr.get("symbol") for fr in frames
              if fr.get("func_addr")}
    best: dict = {}

    def where(o):
        fa, sa = _to_int(o.get("function_addr")), _to_int(o.get("site_addr"))
        name = sym_of.get(fa) or (f"0x{fa:x}" if fa is not None else "?")
        return f"0x{sa:x} in {name}" if sa is not None else name

    def offer(f, tier, detail, occ):
        cur = best.get(f.id)
        if cur is None or _TIERS.index(tier) > _TIERS.index(cur["tier"]):
            best[f.id] = {"finding": f, "tier": tier, "detail": detail,
                          "site": (occ or {}).get("site_addr"),
                          "function_addr": (occ or {}).get("function_addr")}

    for f in findings:
        for o in occ_of.get(f.id, ()):
            if _to_int(o.get("function_addr")) in fn_addrs:
                offer(f, "crash-function",
                      f"a site of this defect ({where(o)}) sits in a function on the crashing "
                      f"call stack -- proximity, not proof", o)
                break

    # The faulting instruction IS a recorded site. This is the only match available to a
    # finding that is not a call -- an out-of-bounds read is a `mov`, and matching return
    # addresses to call sites can never reach it. It is also the strongest match there is:
    # not "the call that faulted" but "the instruction that faulted".
    if frames and frames[0].get("fault_pc"):
        pc = frames[0].get("static_addr")
        if pc is not None:
            for sa, f, o in sites:
                if sa == pc:
                    offer(f, "fault-site",
                          f"the faulting instruction IS this site ({where(o)})",
                          o)

    # Frame 0 is the faulting instruction; every later frame is a RETURN address, which sits
    # just past the call it came from. That is what ties a frame to a recorded call site.
    returns = frames[1:] if (frames and frames[0].get("fault_pc")) else frames
    for depth, fr in enumerate(returns):
        ra = fr.get("static_addr")
        if ra is None:
            continue
        near = [t for t in sites if 0 < ra - t[0] <= _CALL_WINDOW]
        if not near:
            continue
        sa, f, o = max(near, key=lambda t: t[0])   # closest call before the return address
        if depth == 0:
            offer(f, "fault-site",
                  f"the fault occurred inside the call this finding names at {where(o)}",
                  o)
        else:
            offer(f, "on-stack",
                  f"the call at {where(o)} was on the stack when the fault occurred",
                  o)
    return sorted(best.values(), key=lambda a: -_TIERS.index(a["tier"]))


def _is_memory_write(disasm):
    """Intel-syntax: a store has the memory operand as the destination (before the comma)."""
    if not disasm:
        return False
    ops = disasm.split(None, 1)
    if len(ops) < 2:
        return False
    dest = ops[1].split(",")[0]
    return "[" in dest                            # destination dereferences memory -> a write


# AddressSanitizer/UBSan bug class -> (CWE, severity). The sanitizer names the exact defect a
# bare SIGABRT cannot; for the source-code path this is the difference between "aborted by a
# runtime check" and "heap-buffer-overflow at parser.c:88".
_ASAN_CWE = {
    "heap-buffer-overflow": ("CWE-122", "critical"),
    "stack-buffer-overflow": ("CWE-121", "critical"),
    "global-buffer-overflow": ("CWE-787", "high"),
    "dynamic-stack-buffer-overflow": ("CWE-121", "critical"),
    "heap-use-after-free": ("CWE-416", "critical"),
    "stack-use-after-return": ("CWE-562", "high"),
    "stack-use-after-scope": ("CWE-562", "high"),
    "use-after-poison": ("CWE-416", "high"),
    "double-free": ("CWE-415", "high"),
    "alloc-dealloc-mismatch": ("CWE-762", "medium"),
    "attempting-free-on-address": ("CWE-590", "high"),
    "negative-size-param": ("CWE-1284", "medium"),
    "SEGV": ("CWE-476", "high"),
}

# Tokens that can follow "AddressSanitizer:" in a non-defect line (setup/runtime failures, not
# bugs in the target). Belt-and-braces alongside the colon requirement in parse_asan_report.
_ASAN_NONBUG = frozenset({"failed", "out", "hard", "requested", "cannot", "unable", "shadow",
                          "nested", "ignoring", "while", "thread", "internal", "atos"})


def parse_asan_report(text: str) -> Optional[dict]:
    """Turn an AddressSanitizer / UBSan report into a classification, with the source location
    when the build was symbolized. Returns None when the text carries no sanitizer report."""
    import re
    t = text or ""
    # A real bug line is `ERROR: AddressSanitizer: <class>` or `SUMMARY: AddressSanitizer:
    # <class>` -- the colon after "AddressSanitizer" is what separates a defect report from a
    # runtime *setup failure* like "AddressSanitizer failed to allocate ..." (no colon), which a
    # too-small address-space limit produces and which is NOT a finding. Requiring the colon,
    # plus a denylist for the odd non-bug token, keeps those out of the classification.
    m = re.search(r"(?:ERROR|SUMMARY):\s*AddressSanitizer:\s*([a-z][a-z0-9-]+)", t)
    # MemorySanitizer reports the one class ASan/UBSan cannot: a READ of memory that was never
    # initialized (CWE-457). It needs its own -fsanitize=memory build (clang, mutually exclusive
    # with ASan), so this fires only when such a binary is detonated -- see compile_source_msan.
    msan = re.search(r"(?:ERROR|SUMMARY):\s*MemorySanitizer:\s*(use-of-uninitialized-value)", t)
    # ThreadSanitizer reports a data race (CWE-362) -- a concurrency class none of the other
    # sanitizers see; it needs its own -fsanitize=thread build (see compile_source_tsan).
    tsan = re.search(r"(?:WARNING|ERROR|SUMMARY):\s*ThreadSanitizer:\s*(data race|"
                     r"heap-use-after-free|thread leak|lock-order-inversion|"
                     r"destroy of a locked mutex|signal-unsafe call)", t)
    # LeakSanitizer (standalone, or inside an ASan build) reports a memory leak (CWE-401).
    lsan = re.search(r"(?:ERROR|SUMMARY):\s*LeakSanitizer:\s*detected memory leaks", t) or \
        re.search(r"(?:Direct|Indirect) leak of \d+ byte", t)
    ub = re.search(r"runtime error:\s*(.+)", t)
    if m and m.group(1) in _ASAN_NONBUG:
        m = None
    if not m and not msan and not tsan and not lsan and not ub:
        return None
    if msan:
        bug = "use-of-uninitialized-value"
        cwe, sev = ("CWE-457", "medium")
        detail = "MemorySanitizer: use of uninitialized value"
    elif tsan:
        bug = tsan.group(1).replace(" ", "-")
        cwe, sev = (("CWE-416", "high") if bug == "heap-use-after-free" else ("CWE-362", "high"))
        detail = f"ThreadSanitizer: {tsan.group(1)}"
    elif lsan:
        bug = "memory-leak"
        cwe, sev = ("CWE-401", "low")
        detail = "LeakSanitizer: detected memory leak"
    elif m:
        bug = m.group(1)
        cwe, sev = _ASAN_CWE.get(bug, ("CWE-119", "high"))
        detail = f"AddressSanitizer: {bug.replace('-', ' ')}"
    else:
        bug = "undefined-behavior"
        cwe, sev = ("CWE-758", "medium")
        detail = f"UndefinedBehaviorSanitizer: {ub.group(1).strip()[:120]}"
    # The first stack frame that names a real source file (skip the sanitizer interceptors).
    src = None
    for fm in re.finditer(r"#\d+ 0x[0-9a-f]+ in \S+ ([^\s:]+\.(?:c|cc|cpp|cxx|h|hpp)):(\d+)", t):
        src = f"{fm.group(1).split('/')[-1]}:{fm.group(2)}"
        break
    return {"class": bug, "cwe": cwe, "severity": sev,
            "detail": detail + (f" at {src}" if src else ""), "source": src}


def classify(cap, disasm):
    sig = cap.get("signal_name")
    pc = cap.get("pc")
    fault = cap.get("fault_addr")
    maps = cap.get("maps") or []
    pc_map = mapping_for(maps, pc)
    # only conclude "hijack" when we actually have maps and the PC is not in an exec region;
    # with no map info we cannot claim non-executability, so fall through to signal analysis.
    if maps and pc is not None and not (pc_map and "x" in pc_map.get("perms", "")):
        return {"class": "control-flow-hijack", "cwe": "CWE-787", "severity": "critical",
                "detail": f"program counter 0x{(pc or 0):x} is not in executable memory "
                          "(attacker-controlled execution transfer)"}
    if sig == "SIGABRT":
        return {"class": "detected-corruption-abort", "cwe": "CWE-787", "severity": "high",
                "detail": "process aborted by a runtime integrity check "
                          "(stack canary / _FORTIFY_SOURCE / heap consistency)"}
    if sig == "SIGFPE":
        return {"class": "arithmetic-exception", "cwe": "CWE-369", "severity": "high",
                "detail": "arithmetic fault (divide-by-zero or INT_MIN/-1)"}
    if sig == "SIGILL":
        return {"class": "illegal-instruction", "cwe": "CWE-119", "severity": "high",
                "detail": "illegal instruction (corrupted code or control flow)"}

    mnem = (disasm or "").split()[0] if disasm else ""
    if mnem in ("ret", "retq", "retn"):
        return {"class": "stack-return-overwrite", "cwe": "CWE-121", "severity": "critical",
                "detail": "fault at a function return: the saved return address was "
                          "overwritten (stack-based buffer overflow)"}
    is_write = _is_memory_write(disasm)
    rw = "write" if is_write else "read"
    if fault is not None and fault < 0x1000:
        return {"class": "null-pointer-dereference", "cwe": "CWE-476", "severity": "medium",
                "detail": f"{rw} through a NULL/near-NULL pointer (fault at 0x{fault:x})"}
    cwe = "CWE-787" if is_write else "CWE-125"
    return {"class": f"out-of-bounds-{rw}", "cwe": cwe, "severity": "high",
            "detail": f"invalid {rw} at 0x{(fault or 0):x}"
                      + (f" via `{disasm}`" if disasm else "")}


def _callgraph_path(call_edges, sources_callers, crash_fn_addr, maxdepth=8):
    """Shortest forward call path from any source-calling function to the crash function."""
    from collections import deque
    succ = {}
    for e in call_edges:
        sa, da = _to_int(e.src_addr), _to_int(e.dst_addr)
        if sa is not None and da is not None:
            succ.setdefault(sa, set()).add(da)
    target = _to_int(crash_fn_addr)
    seen = set()
    q = deque((s, [s]) for s in sources_callers)
    while q:
        node, path = q.popleft()
        if node == target:
            return path
        if node in seen or len(path) > maxdepth:
            continue
        seen.add(node)
        for nxt in succ.get(node, ()):
            q.append((nxt, path + [nxt]))
    return None


def attribution_upsert(f, a, signal_name):
    """The finding row an attribution produces. Pure -- the caller owns the DAO.

    Only `fault-site` promotes: the fault happened inside the call the finding names, so the
    crash IS that finding. The weaker tiers attach the evidence and leave the state alone,
    because being near a crash is not being the crash.
    """
    proven = a["tier"] == "fault-site"
    # Mark the SITE, not just the defect: a 99-site finding with one proven occurrence must
    # not render like one where all 99 are proven.
    # `attribute()` returns "site"; the slice serialises it as "site_addr". Accept both, or
    # the promotion lands on the finding and never reaches the occurrence it proved.
    sa = a.get("site") or a.get("site_addr")
    site = {"function_addr": a.get("function_addr"), "site_addr": sa,
            "site_verdict": "proven" if proven else a["tier"],
            "site_state": "poc-backed" if proven else None,
            "site_confidence": 0.97 if proven else None} if sa else {}
    return {
        **site,
        "dedup_key": f.dedup_key, "cwe": f.cwe, "severity": f.severity,
        # Its OWN channel: a promotion from a reproduced crash must not overwrite what the
        # static detector says, and must not be undone when that detector next re-runs.
        "channel": "crash-attribution",
        "detector": f.detector,          # upsert rewrites detector on merge; keep the original
        "state": "poc-backed" if proven else f.state,
        "confidence": 0.97 if proven else f.confidence,
        "evidence": [{"channel": "crash-attribution",
                      "detail": f"{a['detail']} -- reproduced {signal_name} crash"}]}


def build_slice(cap, functions, call_edges, findings, maps, target_path,
                sites_by_finding=None, elf_entry=None):
    ranges = _fn_ranges(functions)
    delta = rebase_delta(maps, target_path, functions, elf_entry)
    pc = cap.get("pc")
    chain = [pc] + list(cap.get("backtrace") or [])
    frames = [symbolize(a, maps, ranges, target_path, delta) for a in chain if a is not None]
    if pc is not None and frames:
        frames[0]["fault_pc"] = True              # the rest are return addresses
    crash_fn = next((fr for fr in frames if fr.get("func_addr")), None)

    sources_callers = {_to_int(e.src_addr) for e in call_edges
                       if normalize(e.dst_name) in SOURCES and _to_int(e.src_addr) is not None}
    path = None
    tainted = False
    if crash_fn:
        path = _callgraph_path(call_edges, sources_callers, crash_fn["func_addr"])
        for f in findings:
            if f.function_addr == crash_fn["func_addr"] and any(
                    (e.get("channel") if isinstance(e, dict) else "") .startswith("taint")
                    for e in (f.evidence or [])):
                tainted = True
    addr_to_name = {}
    for lo, _hi, fn in ranges:
        addr_to_name[lo] = fn.name or f"sub_{fn.addr}"
    named_path = [{"addr": hex(a), "symbol": addr_to_name.get(a)} for a in (path or [])]
    attributed = attribute(frames, findings, sites_by_finding)
    return {"backtrace": frames, "crash_function": crash_fn,
            "source_path": named_path, "input_tainted": tainted,
            "reachable_from_source": bool(path),
            "attributed": [{"finding_id": a["finding"].id, "tier": a["tier"],
                            "detail": a["detail"], "site_addr": a["site"],
                            "function_addr": a.get("function_addr"),
                            "title": a["finding"].title,
                            "cwe": a["finding"].cwe} for a in attributed]}


def analyze(cap, functions, call_edges, findings, target_path, arch,
            sites_by_finding=None, elf_entry=None):
    from . import exploitability
    disasm = disasm_one(bytes.fromhex(cap.get("pc_bytes", "")), arch)
    verdict = classify(cap, disasm)
    exploit = exploitability.rate(cap, verdict)
    sl = build_slice(cap, functions, call_edges, findings, cap.get("maps") or [], target_path,
                     sites_by_finding, elf_entry)
    summary = _summary(verdict, sl, cap, disasm)
    return {"signal": cap.get("signal_name"), "pc": cap.get("pc"),
            "fault_addr": cap.get("fault_addr"), "faulting_instruction": disasm,
            "classification": verdict, "exploitability": exploit, "slice": sl,
            "summary": summary}


def _summary(verdict, sl, cap, disasm):
    where = ""
    cf = sl.get("crash_function")
    if cf and cf.get("symbol"):
        where = f" in {cf['symbol']}"
    elif cf:
        where = f" in {cf['module']}+0x{cf['offset']:x}"
    reach = ""
    if sl.get("source_path"):
        names = [p["symbol"] or p["addr"] for p in sl["source_path"]]
        reach = " reached from untrusted input via " + " -> ".join(names)
    tail = f"; faulting instruction `{disasm}`" if disasm else ""
    return (f"{verdict['class']} ({verdict['cwe']}){where}: {verdict['detail']}{reach}{tail}")
