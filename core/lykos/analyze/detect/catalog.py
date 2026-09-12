"""CWE catalog subset + dangerous-API / input-source tables (deterministic, zero-AI)."""
from __future__ import annotations

# CWE id -> (name, default severity)
CWE = {
    "CWE-119": ("Improper Restriction of Operations within Memory Buffer Bounds", "high"),
    "CWE-120": ("Buffer Copy without Checking Size ('Classic Buffer Overflow')", "high"),
    "CWE-121": ("Stack-based Buffer Overflow", "high"),
    "CWE-122": ("Heap-based Buffer Overflow", "high"),
    "CWE-125": ("Out-of-bounds Read", "high"),
    "CWE-416": ("Use After Free", "high"),
    "CWE-476": ("NULL Pointer Dereference", "medium"),
    "CWE-787": ("Out-of-bounds Write", "high"),
    "CWE-134": ("Uncontrolled Format String", "high"),
    "CWE-242": ("Use of Inherently Dangerous Function", "high"),
    "CWE-676": ("Use of Potentially Dangerous Function", "medium"),
    "CWE-78":  ("OS Command Injection", "high"),
    "CWE-190": ("Integer Overflow or Wraparound", "medium"),
    "CWE-259": ("Use of Hard-coded Password", "high"),
    "CWE-321": ("Use of Hard-coded Cryptographic Key", "high"),
    "CWE-798": ("Use of Hard-coded Credentials", "high"),
    "CWE-327": ("Use of a Broken or Risky Cryptographic Algorithm", "medium"),
    "CWE-328": ("Use of Weak Hash", "medium"),
    "CWE-330": ("Use of Insufficiently Random Values", "medium"),
    "CWE-338": ("Use of Cryptographically Weak PRNG", "medium"),
    "CWE-377": ("Insecure Temporary File", "medium"),
    "CWE-693": ("Protection Mechanism Failure", "low"),
    "CWE-250": ("Execution with Unnecessary Privileges", "medium"),
}


def name(cwe):
    return CWE.get(cwe, (cwe, "info"))[0]


def default_severity(cwe):
    return CWE.get(cwe, (cwe, "info"))[1]


# dangerous function (normalized name) -> (cwe, severity, description)
DANGEROUS = {
    "gets":     ("CWE-242", "high",   "Use of gets() -- no bounds checking"),
    "strcpy":   ("CWE-120", "high",   "Unbounded strcpy into a buffer"),
    "strcat":   ("CWE-120", "high",   "Unbounded strcat into a buffer"),
    "sprintf":  ("CWE-120", "high",   "Unbounded sprintf into a buffer"),
    "vsprintf": ("CWE-120", "high",   "Unbounded vsprintf into a buffer"),
    "scanf":    ("CWE-120", "medium", "scanf with unbounded %s"),
    "sscanf":   ("CWE-120", "medium", "sscanf with unbounded %s"),
    "strncpy":  ("CWE-120", "low",    "strncpy (verify NUL-termination/bounds)"),
    "memcpy":   ("CWE-120", "low",    "memcpy (verify length is bounded)"),
    "memmove":  ("CWE-120", "low",    "memmove (verify length is bounded)"),
    "alloca":   ("CWE-676", "medium", "alloca with attacker-influenced size"),
    "system":   ("CWE-78",  "high",   "Command execution via system()"),
    "popen":    ("CWE-78",  "high",   "Command execution via popen()"),
    "execve":   ("CWE-78",  "medium", "Process execution via execve()"),
    "execl":    ("CWE-78",  "medium", "Process execution via execl()"),
    "execlp":   ("CWE-78",  "medium", "Process execution via execlp()"),
    "execvp":   ("CWE-78",  "medium", "Process execution via execvp()"),
    "printf":   ("CWE-134", "low",    "printf -- check the format string is not tainted"),
    "fprintf":  ("CWE-134", "low",    "fprintf -- check the format string is not tainted"),
    "snprintf": ("CWE-134", "low",    "snprintf -- check the format string is not tainted"),
    "syslog":   ("CWE-134", "low",    "syslog -- check the format string is not tainted"),
}

# APIs whose presence is worth REPORTING but is not by itself a defect claim. `memcpy` is a
# defect only if its length is attacker-controlled and `printf` only if its FORMAT is, and
# neither question is answered by "untrusted input reaches this function". Reachability
# corroborates an unbounded copy -- there the sink itself is the bug -- but promoting these
# on it made two thirds of jhead's report read "corroborated", which should mean a second
# channel agreed a defect exists. The channels that CAN answer them are bounds (a proven
# length) and taint (which argument the bytes reach).
ADVISORY = {"strncpy", "memcpy", "memmove", "printf", "fprintf", "snprintf", "syslog"}

# untrusted-input source functions (normalized) for reachability correlation
SOURCES = {
    "recv", "recvfrom", "recvmsg", "read", "fread", "fgets", "gets", "scanf",
    "fscanf", "sscanf", "getenv", "getchar", "fgetc", "getline", "readv",
}

# ------------------------------------------------------- which sink argument must be tainted
# A sink is only a data-flow finding if the attacker controls the argument that MAKES it a
# bug -- not merely some argument. `printf("%s", user)` is safe; `printf(user)` is CWE-134.
# Checking "any argument register is tainted" conflates the two and mislabels most printf
# calls in any program that touches input.
#
# Maps a normalized sink name -> the argument indices whose taint constitutes the finding.
# A sink ABSENT from this table falls back to "any argument", which is the conservative
# behaviour -- add an entry only where the position is unambiguous.
SINK_TAINT_ARGS = {
    # CWE-134 format strings: the FORMAT argument, and only it.
    "printf":   frozenset({0}),                   # printf(fmt, ...)
    "fprintf":  frozenset({1}),                   # fprintf(stream, fmt, ...)
    "snprintf": frozenset({2}),                   # snprintf(buf, size, fmt, ...)
    "syslog":   frozenset({1}),                   # syslog(priority, fmt, ...)
    # CWE-120 copies: the SOURCE and/or the LENGTH. A tainted DESTINATION pointer says
    # nothing about whether the copy overflows.
    "strcpy":   frozenset({1}),                   # strcpy(dst, src)
    "strcat":   frozenset({1}),
    "strncpy":  frozenset({1, 2}),                # strncpy(dst, src, n)
    "memcpy":   frozenset({1, 2}),                # memcpy(dst, src, n)
    "memmove":  frozenset({1, 2}),
    "sprintf":  frozenset({1, 2, 3, 4, 5}),       # sprintf(dst, fmt, ...) -- fmt and varargs
    "vsprintf": frozenset({1, 2}),
    "scanf":    frozenset({0}),                   # scanf(fmt, ...)
    "sscanf":   frozenset({0, 1}),                # sscanf(src, fmt, ...)
    "alloca":   frozenset({0}),                   # alloca(size)
    # CWE-78 execution: the COMMAND / program path.
    "system":   frozenset({0}),
    "popen":    frozenset({0}),                   # popen(cmd, mode)
    "execve":   frozenset({0, 1}),                # execve(path, argv, envp)
    "execl":    frozenset({0, 1}),
    "execlp":   frozenset({0, 1}),
    "execvp":   frozenset({0, 1}),
    # `gets` is intentionally absent: its only argument is the destination, so no argument
    # position makes it "more" of a bug -- it is unconditionally unsafe and the rule channel
    # already reports it.
}


# ---------------------------------------------------------------- entry-point taint sources
# SOURCES above covers input that arrives through a CALL. The other way untrusted input
# enters a program is as a PARAMETER of its entry point: argv/envp are handed to main by the
# loader, with no source function to observe. Without this a CLI binary -- the common case,
# and the one `strcpy(buf, argv[1])` lives in -- has no taint origin at all, so nothing can
# ever be corroborated (findings stay at `candidate` forever).
#
# Maps an entry-point name to the parameter indices that carry untrusted DATA.
#
# argc (index 0) is deliberately NOT seeded. It is attacker-influenced, but it is a count,
# not data: seeding it pushes taint through loop bounds and `if (argc > 1)` guards into
# values that carry no attacker bytes, which costs precision for very little detection. A
# size/bounds channel is the right home for argc, not the data-flow one.
ENTRY_PARAM_SOURCES = {
    "main":    {1, 2},        # main(argc, argv, envp)      -> argv, envp
    "wmain":   {1, 2},        # wide-char variant
    "tmain":   {1, 2},        # _tmain (normalize() strips the leading underscore)
    "winmain":  {2},          # WinMain(hInst, hPrev, lpCmdLine, nShow) -> lpCmdLine
    "wwinmain": {2},
}


def _declared_param_count(frame, signature):
    """How many parameters the decompiler says this function actually takes.

    Prefers the recovered parameter list; falls back to counting the signature's argument
    list (`int main(int argc, char **argv)` -> 2, `undefined8 main(void)` -> 0). Returns
    None when neither is available -- "unknown", which is not the same as zero.
    """
    if frame and isinstance(frame.get("params"), list):
        return len(frame["params"])
    if signature and "(" in signature and signature.rstrip().endswith(")"):
        args = signature[signature.index("(") + 1:signature.rstrip().rindex(")")].strip()
        if not args or args == "void":
            return 0
        depth, n = 0, 1
        for ch in args:                      # top-level commas only (skip nested templates)
            if ch in "(<":
                depth += 1
            elif ch in ")>":
                depth -= 1
            elif ch == "," and depth == 0:
                n += 1
        return n
    return None


def entry_seed_params(functions, frames=None):
    """Map entry-point function addr -> tainted parameter indices, for the taint seed.

    `functions` is any iterable of objects with `.name`/`.addr` (and optionally `.signature`);
    `frames` maps addr -> recovered stack frame, whose "params" list is the authoritative
    parameter count. Matching is on the normalized, lower-cased name, so `_main` and `main`
    both resolve.

    A parameter index is seeded ONLY if the entry point actually declares it. `main(void)`
    takes no argv, so seeding one would mark a callee-argument register tainted at entry and
    every downstream sink would inherit it -- turning a program that reads no input at all
    into a wall of corroborated findings. Where the parameter count is unknown (no decompiler
    output at all) nothing is seeded: no data, no claim.
    """
    seeds = {}
    for f in functions or ():
        idx = ENTRY_PARAM_SOURCES.get(normalize(getattr(f, "name", "") or "").lower())
        addr = getattr(f, "addr", None)
        if not idx or not addr:
            continue
        declared = _declared_param_count((frames or {}).get(addr),
                                         getattr(f, "signature", None))
        if declared is None:
            continue
        keep = {i for i in idx if i < declared}
        if keep:
            seeds[addr] = keep
    return seeds


def normalize(fname):
    """Normalize a callee name to a plain libc symbol (strip decorations).

    Two decorations here are not cosmetic -- without them whole architectures go dark:

    * A LEADING DOT is the PowerPC local-entry convention. Under ELFv2 (which is what every
      little-endian ppc64 system uses) a function has a global entry that sets up the TOC and
      a local entry 8 bytes later holding the actual body; Ghidra names the body `.main`.
      On a real ppc64le binary 845 of 1829 functions and 3659 of 4828 call targets carry the
      dot, so leaving it on meant `.strcpy` never matched a sink, `.main` never matched an
      entry point, and the architecture produced ZERO data-flow findings while big-endian
      ppc64 -- ELFv1, no dots -- produced 139 from the same source.
    * Ghidra names a PLT thunk `<hex>.plt_call.<symbol>` (e.g. `00000397.plt_call.strcat`),
      which matched nothing either. Seen on ppc64 big-endian, so this one was costing sinks
      on an architecture that otherwise looked healthy.
    """
    if not fname:
        return ""
    n = fname.strip()
    if ".plt_call." in n:                # Ghidra PLT thunk: 00000397.plt_call.strcat
        n = n.rsplit(".plt_call.", 1)[-1]
    for suffix in ("@plt", ".plt"):
        if n.endswith(suffix):
            n = n[:-len(suffix)]
    if "@@" in n or "@" in n:
        # Symbol VERSION suffix: `memcpy@@GLIBC_2.17`. Ghidra keeps it on the PLT thunks of
        # both ppc64 flavours, where it was hiding 9 of the 10 memcpy call sites -- the sink
        # matched only the one unversioned definition, so the ISA looked clean.
        n = n.split("@", 1)[0]
    n = n.lstrip(".")                    # PowerPC local entry point: .main -> main
    n = n.lstrip("_")
    if n.startswith("isoc99_"):          # __isoc99_scanf -> scanf
        n = n[len("isoc99_"):]
    if n.startswith("IO_"):              # glibc stdio alias: _IO_fgets -> fgets
        n = n[len("IO_"):]
    return n
