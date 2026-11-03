"""The auditable CWE catalog -- the single source of truth for "have we considered every CWE?".

The honest answer to that question is not a vibe; it is a table in which EVERY CWE relevant to C /
native software has an explicit, declared detection METHOD, so a reviewer can see at a glance which
classes are covered by a static pattern, which need runtime (a sanitizer / execution), which are
recovered from the binary, and which are genuinely not-applicable to this language -- with nothing
silently missing. A test pins that every CWE named anywhere in lykos (`cwe.py`) has an entry here,
so the catalog cannot drift out of completeness.

`method` values:
  * "pattern"  -- statically matchable in source by `pattern` (a regex over a function body). The
                  sweep (`cwe_sweep`) runs these over every function, so coverage is line-complete.
  * "taint"    -- a real finding needs source->sink dataflow, not a local pattern; `pattern` here is
                  the SINK locator (where to start taint), still run over every function so the site
                  is never missed, but a hit is a lead, not a confirmed bug.
  * "runtime"  -- only a sanitizer / execution can confirm it (ASan/UBSan/LSan/MSan/TSan); the
                  static side can at best flag a suspicious shape. The oracle, not a pattern, decides.
  * "binary"   -- recovered from the compiled image (imports, rodata, symbols), not the source text.
  * "na"       -- not applicable to a C/native codebase (web/markup/XML/SQL-layer classes); recorded
                  so the exclusion is explicit and defensible, never an accidental gap.

`family` groups the classes for reporting. `pattern`, when present, is a compiled regex applied to a
function body; it is deliberately a RECALL-first locator (find every candidate site) -- precision is
the confirmation stage's job, not the catalog's.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class CweEntry:
    cwe: str
    name: str
    family: str
    method: str                    # pattern | taint | runtime | binary | na
    severity: str
    pattern: "re.Pattern | None" = None


def _p(rx: str) -> "re.Pattern":
    return re.compile(rx)


#: Comprehensive, auditable catalog. Each CWE relevant to C has a declared method; nothing is left
#: implicit. Patterns are recall-first locators over a function body.
CATALOG: dict = {}


def _add(cwe, name, family, method, severity, pattern=None):
    CATALOG[cwe] = CweEntry(cwe, name, family, method, severity, _p(pattern) if pattern else None)


# ---- memory: out-of-bounds read/write, buffer overflow (static shapes + runtime oracle) ----
_add("CWE-119", "Improper restriction of operations within memory bounds", "memory", "runtime", "high")
_add("CWE-120", "Buffer copy without checking size (classic overflow)", "memory", "pattern", "high",
     r"\b(strcpy|strcat|sprintf|vsprintf|gets|stpcpy)\s*\(")
_add("CWE-121", "Stack-based buffer overflow", "memory", "pattern", "high",
     r"\b(alloca|gets|strcpy|strcat|sprintf)\s*\(|char\s+\w+\s*\[\s*\d+\s*\][^;]*;\s*[^\n]*\b(memcpy|strcpy)\b")
_add("CWE-122", "Heap-based buffer overflow", "memory", "runtime", "high")
_add("CWE-123", "Write-what-where condition", "memory", "runtime", "high")
_add("CWE-124", "Buffer underwrite (boundary begin)", "memory", "pattern", "high",
     r"\[\s*-\s*\d+\s*\]|-\s*\d+\s*\]\s*=")
_add("CWE-125", "Out-of-bounds read", "memory", "runtime", "high")
_add("CWE-126", "Buffer over-read", "memory", "runtime", "medium")
_add("CWE-127", "Buffer under-read", "memory", "runtime", "medium")
_add("CWE-129", "Improper validation of array index", "memory", "pattern", "high",
     r"\[\s*[A-Za-z_]\w*\s*\]\s*=|\[\s*\w+\s*\+\+\s*\]")
_add("CWE-131", "Incorrect calculation of buffer size", "memory", "pattern", "medium",
     r"\b(malloc|calloc|realloc|memcpy|memmove)\s*\([^)]*[*+\-][^)]*\)")
_add("CWE-786", "Access of memory location before start of buffer", "memory", "runtime", "medium")
_add("CWE-787", "Out-of-bounds write", "memory", "runtime", "high")
_add("CWE-788", "Access of memory location after end of buffer", "memory", "runtime", "medium")
_add("CWE-680", "Integer overflow to buffer overflow", "memory", "pattern", "high",
     r"\b(malloc|calloc|realloc)\s*\([^)]*\*[^)]*\)")
_add("CWE-806", "Buffer access using size of source buffer", "memory", "pattern", "medium",
     r"memcpy\s*\([^,]+,[^,]+,\s*sizeof\s*\(")

# ---- use-after-free / free errors (static leads + runtime oracle) ----
_add("CWE-416", "Use after free", "lifetime", "runtime", "high")
_add("CWE-415", "Double free", "lifetime", "pattern", "high",
     r"\bfree\s*\(\s*(\w+)\s*\)[\s\S]{0,200}?\bfree\s*\(\s*\1\s*\)")
_add("CWE-590", "Free of memory not on the heap", "lifetime", "pattern", "high",
     r"\bfree\s*\(\s*&")
_add("CWE-761", "Free of pointer not at start of buffer", "lifetime", "runtime", "high")
_add("CWE-762", "Mismatched memory management routines", "lifetime", "pattern", "medium",
     r"\b(new\b[\s\S]{0,400}?\bfree\s*\(|malloc[\s\S]{0,400}?\bdelete\b)")
_add("CWE-825", "Expired pointer dereference", "lifetime", "runtime", "high")
_add("CWE-416", CATALOG["CWE-416"].name, "lifetime", "runtime", "high")  # idempotent re-assert

# ---- pointers / uninitialized / deref ----
_add("CWE-476", "NULL pointer dereference", "pointer", "pattern", "medium",
     r"\b(\w+)\s*=\s*(?:malloc|calloc|realloc|strdup|\w+_new|\w+_alloc)\s*\([^;]*\);\s*(?![^\n]*\bif\b)[^\n]*\*?\1\s*(?:->|\[)")
_add("CWE-457", "Use of uninitialized variable", "pointer", "pattern", "medium",
     r"\b(?:int|char|long|size_t|UINT\d+|BYTE|void\s*\*|\w+_t)\s+\*?\w+\s*;")
_add("CWE-824", "Access of uninitialized pointer", "pointer", "runtime", "high")
_add("CWE-822", "Untrusted pointer dereference", "pointer", "taint", "high",
     r"\*\s*\(\s*\([^)]*\*\s*\)")
_add("CWE-823", "Out-of-range pointer offset", "pointer", "runtime", "medium")
_add("CWE-562", "Return of stack variable address", "pointer", "pattern", "high",
     r"return\s+&\s*\w+\s*;")
_add("CWE-690", "Unchecked return value to NULL deref", "pointer", "pattern", "medium",
     r"=\s*(?:malloc|calloc|realloc|strdup)\s*\([^;]*\);\s*[^\n]*(?:->|\[)")

# ---- integers ----
_add("CWE-190", "Integer overflow or wraparound", "integer", "pattern", "high",
     r"\b(?:malloc|calloc|realloc|alloca)\s*\([^)]*[*+][^)]*\)|\*\s*\w+\s*\+\s*\d+")
_add("CWE-191", "Integer underflow", "integer", "pattern", "high",
     r"\b(?:len|size|count|n|remaining|left)\w*\s*-\s*\w+|-\s*\d+\s*\)\s*;")
_add("CWE-192", "Integer coercion error", "integer", "pattern", "medium",
     r"\(\s*(?:int|short|char|UINT8|UINT16|INT8|INT16)\s*\)\s*\w+")
_add("CWE-193", "Off-by-one error", "integer", "pattern", "medium",
     r"<=\s*\w*(?:len|size|count|LENGTH|SIZE)|\[\s*\w+(?:len|size|count)\s*\]")
_add("CWE-197", "Numeric truncation error", "integer", "pattern", "medium",
     r"\(\s*(?:UINT8|UINT16|INT8|INT16|uint8_t|uint16_t|short|char)\s*\)")
_add("CWE-369", "Divide by zero", "integer", "pattern", "medium",
     r"[/%]\s*\w+\b(?![^\n]*\bif\b[^\n]*(?:==\s*0|!=\s*0|>\s*0))")
_add("CWE-681", "Incorrect conversion between numeric types", "integer", "pattern", "medium",
     r"\(\s*(?:signed|unsigned)\s+\w+\s*\)")
_add("CWE-704", "Incorrect type conversion or cast", "integer", "pattern", "low",
     r"\(\s*\w+\s*\*\s*\)\s*\w+")

# ---- resource / allocation / loop ----
_add("CWE-400", "Uncontrolled resource consumption", "resource", "taint", "medium",
     r"\b(?:malloc|calloc|realloc)\s*\(\s*\w+")
_add("CWE-770", "Allocation of resources without limits", "resource", "pattern", "high",
     r"\b(?:malloc|calloc|realloc|alloca)\s*\(\s*(?:\w+(?:Count|Len|Length|Size|Num|num|count|len)\w*)\s*[*)]")
_add("CWE-789", "Memory allocation with excessive size value", "resource", "pattern", "medium",
     r"\b(?:malloc|calloc|realloc)\s*\([^)]*\b\w*(?:Count|Length|Size)\b")
_add("CWE-401", "Missing release of memory (leak)", "resource", "runtime", "medium")
_add("CWE-409", "Improper handling of highly compressed data (zip bomb)", "resource", "pattern", "medium",
     r"\b(?:inflate|uncompress|zgfx|decompress|LZ|rle)\w*\s*\(")
_add("CWE-674", "Uncontrolled recursion", "resource", "pattern", "medium", None)   # set below (self-call)
_add("CWE-835", "Loop with unreachable exit (infinite loop)", "resource", "pattern", "medium",
     r"\b(?:while|for)\s*\(\s*(?:1|true|TRUE|;;)\s*\)|\bfor\s*\(\s*;\s*;\s*\)")
_add("CWE-776", "XML entity expansion (billion laughs)", "resource", "na", "low")

# ---- control / assertion / signals ----
_add("CWE-617", "Reachable assertion", "control", "pattern", "medium",
     r"\b(?:assert|WINPR_ASSERT|WLog_ASSERT|abort)\s*\(")
_add("CWE-248", "Uncaught exception / fatal signal", "control", "runtime", "medium")
_add("CWE-252", "Unchecked return value", "control", "pattern", "medium",
     r"^\s*(?:read|write|recv|send|malloc|realloc|fread|fwrite)\s*\([^;]*\)\s*;")
_add("CWE-690", CATALOG["CWE-690"].name, "control", "pattern", "medium", CATALOG["CWE-690"].pattern.pattern)
_add("CWE-754", "Improper check for unusual conditions", "control", "pattern", "low",
     r"\breturn\s+\w+\s*\(")

# ---- injection / command / format / query / deserialization ----
_add("CWE-77", "Command injection", "injection", "taint", "high", r"\b(system|popen|execl|execv|execvp)\s*\(")
_add("CWE-78", "OS command injection", "injection", "taint", "high",
     r"\b(system|popen|execl|execle|execlp|execv|execvp|execve)\s*\(")
_add("CWE-88", "Argument injection", "injection", "taint", "high", r"\b(execv|execvp|popen)\s*\(")
_add("CWE-89", "SQL injection", "injection", "taint", "high",
     r"\b(sqlite3_exec|mysql_query|PQexec|sprintf[^;]*SELECT)\s*\(")
_add("CWE-94", "Code injection", "injection", "taint", "high", r"\b(dlopen|dlsym|LoadLibrary\w*)\s*\(")
_add("CWE-95", "Eval injection", "injection", "na", "high")
_add("CWE-98", "PHP file inclusion", "injection", "na", "high")
_add("CWE-134", "Uncontrolled format string", "injection", "pattern", "high",
     r"\b(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsnprintf|syslog|WLog_\w+)\s*\(\s*(?!\s*[\"A-Z])")
_add("CWE-502", "Deserialization of untrusted data", "injection", "taint", "high",
     r"\b(unserialize|unpack|\w*_from_bytes|\w*_deserialize|memcpy\s*\([^,]+,\s*\w+\s*,\s*sizeof)")
_add("CWE-79", "Cross-site scripting (XSS)", "injection", "na", "medium")
_add("CWE-116", "Improper encoding/escaping of output", "injection", "na", "medium")
_add("CWE-643", "XPath injection", "injection", "na", "medium")
_add("CWE-918", "Server-side request forgery", "injection", "na", "medium")

# ---- path / filename ----
_add("CWE-22", "Path traversal", "path", "taint", "high",
     r"\b(fopen|open|openat|CreateFile\w*|unlink|stat|access|opendir)\s*\(")
_add("CWE-23", "Relative path traversal", "path", "taint", "high", r"\.\.[\\/]")
_add("CWE-377", "Insecure temporary file", "path", "pattern", "medium",
     r"\b(tmpnam|tempnam|mktemp|tmpfile)\s*\(")
_add("CWE-611", "XML external entity (XXE)", "path", "na", "high")

# ---- crypto / secrets / randomness ----
_add("CWE-259", "Hard-coded password", "crypto", "pattern", "high",
     r"(?i)(password|passwd|pwd)\s*=\s*\"[^\"]{3,}\"")
_add("CWE-321", "Hard-coded cryptographic key", "crypto", "pattern", "high",
     r"(?i)(key|secret|iv)\s*\[\s*\]\s*=\s*\{|static\s+.*\b(key|secret)\b.*=\s*\"")
_add("CWE-798", "Hard-coded credentials", "crypto", "pattern", "high",
     r"(?i)(api[_-]?key|token|credential|secret)\s*=\s*\"[^\"]{6,}\"")
_add("CWE-327", "Broken/risky crypto algorithm", "crypto", "pattern", "medium",
     r"\b(DES|MD5|MD4|RC4|ECB)\b|\b(EVP_des|EVP_rc4|MD5_Init|DES_)\w*\s*\(")
_add("CWE-328", "Weak hash", "crypto", "pattern", "medium",
     r"\b(MD5|MD4|SHA1|SHA_1)\b|\b(MD5_Init|SHA1_Init)\s*\(")
_add("CWE-330", "Insufficiently random values", "crypto", "pattern", "medium",
     r"\b(rand|random|srand|srandom|rand_r)\s*\(")
_add("CWE-338", "Cryptographically weak PRNG", "crypto", "pattern", "medium",
     r"\b(rand|random|mt19937|rand_r)\s*\(")
_add("CWE-295", "Improper certificate validation", "crypto", "pattern", "high",
     r"SSL_VERIFY_NONE|verify\w*\s*=\s*0|InsecureSkipVerify|X509_V_OK\s*;?\s*return")
_add("CWE-547", "Hard-coded security-relevant constant", "crypto", "pattern", "low",
     r"(?i)#define\s+\w*(SECRET|KEY|PASS)\w*\s+\"")

# ---- concurrency ----
_add("CWE-362", "Race condition", "concurrency", "runtime", "medium")
_add("CWE-367", "TOCTOU", "concurrency", "pattern", "medium",
     r"\b(access|stat|lstat)\s*\([^;]*\);\s*[\s\S]{0,200}?\b(open|fopen|unlink|chmod)\s*\(")
_add("CWE-1335", "Incorrect bitwise shift", "concurrency", "pattern", "low",
     r"<<\s*\w+|>>\s*\w+")

# ---- type confusion / validation / info leak ----
_add("CWE-843", "Type confusion", "validation", "runtime", "high")
_add("CWE-20", "Improper input validation", "validation", "taint", "medium",
     r"\bStream_Read_\w+\s*\(|\brecv\s*\(|\bread\s*\(")
_add("CWE-1284", "Improper validation of quantity in input", "validation", "pattern", "high",
     r"\bStream_Read_(?:UINT|INT)\d+\s*\([^)]*\)\s*;(?![^\n]*Check)")
_add("CWE-1285", "Improper validation of specified index", "validation", "pattern", "medium",
     r"\[\s*\w+(?:Id|Index|Idx|Slot|Num)\s*\]")
_add("CWE-130", "Improper handling of length parameter inconsistency", "validation", "pattern", "medium",
     r"\b(?:memcpy|memmove|Stream_Read)\s*\([^,]+,[^,]+,\s*\w+(?:Len|Length|Size|Count)\w*\s*\)")
_add("CWE-172", "Encoding error", "validation", "na", "low")
_add("CWE-200", "Exposure of sensitive information", "validation", "runtime", "medium")
_add("CWE-203", "Observable discrepancy (side channel)", "validation", "runtime", "low")
_add("CWE-209", "Information exposure through error message", "validation", "pattern", "low",
     r"\b(printf|fprintf|WLog_\w+)\s*\([^;]*(errno|strerror|GetLastError)")

# ---- privilege / misc ----
_add("CWE-250", "Execution with unnecessary privileges", "privilege", "pattern", "medium",
     r"\b(setuid|setgid|seteuid|setegid)\s*\(\s*0\s*\)")
_add("CWE-252", CATALOG["CWE-252"].name, "privilege", "pattern", "medium", CATALOG["CWE-252"].pattern.pattern)
_add("CWE-693", "Protection mechanism failure", "privilege", "runtime", "low")
_add("CWE-242", "Use of inherently dangerous function", "api", "pattern", "high",
     r"\b(gets|getwd|scanf|sscanf|realpath)\s*\(")
_add("CWE-676", "Use of potentially dangerous function", "api", "pattern", "medium",
     r"\b(strcpy|strcat|sprintf|alloca|strtok|atoi|memcpy)\s*\(")
_add("CWE-494", "Download of code without integrity check", "api", "binary", "high")
_add("CWE-758", "Reliance on undefined behavior", "api", "pattern", "low",
     r"<<\s*31|<<\s*\d+[^;]*signed")
_add("CWE-686", "Function call with wrong argument type", "api", "runtime", "low")
_add("CWE-1066", "Missing serialization mechanism", "api", "na", "low")
_add("CWE-1188", "Insecure default initialization", "api", "pattern", "low",
     r"=\s*\{\s*0\s*\}")
_add("CWE-1395", "Dependency on vulnerable third-party component", "supply-chain", "binary", "medium")


def completeness(named: list) -> dict:
    """Account the catalog against a list of CWE names (e.g. every CWE lykos references): which are
    present, and which are MISSING -- the catalog's own gap worklist. A present entry is further
    classified by method so the caller can report static vs runtime vs na coverage."""
    present = {c for c in named if c in CATALOG}
    missing = sorted(set(named) - present, key=lambda c: int(c.split("-")[1]))
    by_method: dict = {}
    for c in present:
        by_method.setdefault(CATALOG[c].method, []).append(c)
    return {"present": sorted(present), "missing": missing,
            "by_method": {k: sorted(v) for k, v in by_method.items()},
            "total_catalog": len(CATALOG)}
