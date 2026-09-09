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

# untrusted-input source functions (normalized) for reachability correlation
SOURCES = {
    "recv", "recvfrom", "recvmsg", "read", "fread", "fgets", "gets", "scanf",
    "fscanf", "sscanf", "getenv", "getchar", "fgetc", "getline", "readv",
}


def normalize(fname):
    """Normalize a callee name to a plain libc symbol (strip decorations)."""
    if not fname:
        return ""
    n = fname.strip()
    for suffix in ("@plt", ".plt"):
        if n.endswith(suffix):
            n = n[:-len(suffix)]
    n = n.lstrip("_")
    if n.startswith("isoc99_"):          # __isoc99_scanf -> scanf
        n = n[len("isoc99_"):]
    return n
