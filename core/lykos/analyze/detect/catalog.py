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
    "CWE-367": ("Time-of-check Time-of-use (TOCTOU) Race Condition", "medium"),
    "CWE-457": ("Use of Uninitialized Variable", "medium"),
}


def name(cwe):
    return CWE.get(cwe, (cwe, "info"))[0]


def default_severity(cwe):
    return CWE.get(cwe, (cwe, "info"))[1]


# One plain-language sentence per CWE -- what the weakness IS and why it matters -- for the UI to
# show on hover/click of a CWE badge, so an analyst does not have to leave the tool to look it up.
CWE_DESC = {
    "CWE-119": "Code reads or writes outside the intended bounds of a memory buffer, corrupting adjacent data or crashing.",
    "CWE-120": "Data is copied into a buffer without checking it fits, so a long input overruns the buffer (classic overflow).",
    "CWE-121": "A buffer on the call stack is overflowed, which can overwrite the saved return address and hijack control flow.",
    "CWE-122": "A heap-allocated buffer is overflowed, corrupting heap metadata or neighbouring allocations.",
    "CWE-125": "Code reads memory before the start or past the end of a buffer, leaking data or crashing.",
    "CWE-416": "Memory is used after it has been freed, letting an attacker control the freed contents.",
    "CWE-476": "A NULL pointer is dereferenced, typically crashing the program (denial of service).",
    "CWE-787": "Code writes past the bounds of a buffer, corrupting memory and often enabling code execution.",
    "CWE-134": "A format string is built from untrusted input, letting an attacker read or write memory via format specifiers.",
    "CWE-242": "A function that is unsafe by design (e.g. gets()) is used and cannot be made safe.",
    "CWE-676": "A function that is easy to misuse (e.g. strcpy, alloca) is used without the required safeguards.",
    "CWE-78":  "Untrusted input reaches a shell/command, letting an attacker run arbitrary OS commands.",
    "CWE-190": "An arithmetic operation wraps past the integer's range, producing a wrong (often tiny) size or index.",
    "CWE-259": "A password is hard-coded in the binary, so anyone who reads it gains access.",
    "CWE-321": "A cryptographic key is hard-coded in the binary, so the key is not secret.",
    "CWE-798": "Credentials are embedded in the code, usable by anyone who inspects the binary.",
    "CWE-327": "A broken or outdated cryptographic algorithm is used, so the protection it provides is weak.",
    "CWE-328": "A weak hash function is used, so hashes can be forged or reversed.",
    "CWE-330": "Values that must be unpredictable are generated with insufficient randomness.",
    "CWE-338": "A cryptographically weak PRNG is used where unpredictability is required.",
    "CWE-377": "A temporary file is created insecurely, allowing races or predictable-name attacks.",
    "CWE-693": "A protection mechanism is missing or bypassable, weakening the intended defense.",
    "CWE-250": "Code runs with more privilege than it needs, widening the impact of any other bug.",
    "CWE-367": "A path is checked (access/stat) then used (open/exec); an attacker can swap it in between (symlink race).",
    "CWE-457": "A variable is read before it is initialized, so its value is whatever was left in that memory.",
}


def describe(cwe):
    """A one-sentence plain-language description of the weakness, or None if unknown."""
    return CWE_DESC.get(cwe)


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

# ----------------------------------------------- which ARGUMENT a source fills, when it does
# Most of these do not RETURN the untrusted bytes -- they write them into a caller-supplied
# buffer and return a count or a pointer to that same buffer. Seeding taint on the return
# register alone therefore models `getchar()` correctly and `read(fd, buf, n)` not at all, and
# the difference is not academic: every file parser this platform targets reads its input with
# one of these.
#
# Measured on a fixture with two paths to the SAME sink carrying the SAME untrusted data --
# one via argv, one via fread into a buffer -- the argv path was corroborated and the fread
# path was not flagged at all. The taint channel silently under-reported every file-driven
# flow, and cross-component taint never fired on the commonest shape there is: a program that
# reads a file and hands the buffer to a library.
#
# name -> index of the argument that receives the data.
OUT_PARAM_SOURCES = {
    "read": 1, "readv": 1, "recv": 1, "recvfrom": 1, "recvmsg": 1,
    "fread": 0, "fgets": 0, "gets": 0, "getline": 0,
    # *scanf write through their variadic arguments; the first one after the format is the
    # earliest that can receive data, and taking just that is the conservative choice.
    "scanf": 1, "fscanf": 2, "sscanf": 2,
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
    # rizin renders the same version tag with a DOUBLE UNDERSCORE on ppc64 PLT thunks
    # (`strcpy__GLIBC_2.17`), which the `@`-split above misses -- so every libc sink on ppc64 was
    # invisible and the arch produced zero findings. Cut the known version tags off the end.
    for vtag in ("__GLIBC_", "__GLIBCXX_", "__CXXABI_", "__GCC_"):
        if vtag in n:
            n = n.split(vtag, 1)[0]
    n = n.lstrip(".")                    # PowerPC local entry point: .main -> main
    n = n.lstrip("_")
    if n.startswith("isoc"):             # __isoc99_scanf / __isoc23_sscanf -> scanf / sscanf
        # glibc routes the checked-input functions through an ISO-C-version alias; the number is
        # the C standard year (99, then 23, and whatever comes next), so match any digits. Without
        # this every scanf/sscanf sink is invisible on a modern glibc binary.
        rest = n[len("isoc"):]
        j = 0
        while j < len(rest) and rest[j].isdigit():
            j += 1
        if j > 0 and rest[j:j + 1] == "_":
            n = rest[j + 1:]
    if n.startswith("IO_"):              # glibc stdio alias: _IO_fgets -> fgets
        n = n[len("IO_"):]
    return n
