"""CWE id -> (name, plain-language description).

The workbench shows a CWE number on every finding; a bare number ("CWE-787") tells an analyst
nothing without a lookup. This maps the CWEs the platform actually emits to their MITRE name and a
one-sentence explanation, so the UI can explain a finding in place (the `cwe_name`/`cwe_desc`
fields the serializer attaches, rendered as the hover tooltip). Names track MITRE CWE; the
descriptions are deliberately short and plain, not the full MITRE text.

Keep this in sync with the CWEs detectors emit: `grep -rhoE 'CWE-[0-9]+' core/lykos` lists them.
An id that is not here degrades gracefully -- the UI falls back to showing just the number.
"""
from __future__ import annotations

from typing import Optional

#: id -> (name, one-line description)
CWE_NAMES: dict[str, tuple[str, str]] = {
    "CWE-20":  ("Improper Input Validation", "The program uses input without checking it is well-formed, letting malformed data reach sensitive operations."),
    "CWE-22":  ("Path Traversal", "A path built from input can escape its intended directory (e.g. '../'), reaching files it should not."),
    "CWE-77":  ("Command Injection", "Input flows into a command that an interpreter runs, so an attacker can inject extra commands."),
    "CWE-78":  ("OS Command Injection", "Input reaches a shell/OS command (system/exec), letting an attacker run arbitrary commands."),
    "CWE-79":  ("Cross-site Scripting (XSS)", "Untrusted input is emitted into a web page without escaping, running attacker script in the browser."),
    "CWE-88":  ("Argument Injection", "Input is concatenated into a command's arguments, letting an attacker inject extra flags/arguments."),
    "CWE-89":  ("SQL Injection", "Input is concatenated into an SQL query, letting an attacker alter the query's logic."),
    "CWE-94":  ("Code Injection", "Untrusted input is executed as code by the program."),
    "CWE-95":  ("Eval Injection", "Input reaches a dynamic-evaluation primitive (eval/exec), running attacker-controlled code."),
    "CWE-98":  ("PHP File Inclusion", "An include/require path is attacker-controlled, loading remote or unintended code."),
    "CWE-116": ("Improper Encoding/Escaping of Output", "Output is not encoded for its context, enabling injection downstream."),
    "CWE-119": ("Improper Restriction of Operations within Memory Bounds", "A read or write lands outside the bounds of an allocated buffer -- the classic memory-safety fault."),
    "CWE-120": ("Buffer Copy without Size Check (Classic Overflow)", "Data is copied into a buffer without checking it fits, overflowing it (e.g. strcpy/gets)."),
    "CWE-121": ("Stack-based Buffer Overflow", "An overflow of a stack buffer, which can overwrite the saved return address and hijack control flow."),
    "CWE-122": ("Heap-based Buffer Overflow", "An overflow of a heap allocation, corrupting adjacent heap data or allocator metadata."),
    "CWE-123": ("Write-what-where Condition", "An attacker can write a chosen value to a chosen address -- a powerful arbitrary-write primitive."),
    "CWE-124": ("Buffer Underwrite", "A write lands BEFORE the start of a buffer."),
    "CWE-125": ("Out-of-bounds Read", "A read lands outside the buffer's bounds, leaking adjacent memory or crashing."),
    "CWE-126": ("Buffer Over-read", "A read runs past the END of a buffer."),
    "CWE-127": ("Buffer Under-read", "A read lands BEFORE the start of a buffer."),
    "CWE-129": ("Improper Validation of Array Index", "An array is indexed with an unchecked value, reading or writing out of bounds."),
    "CWE-130": ("Improper Handling of Length Parameter Inconsistency", "A declared length and the real data length disagree, mis-sizing a buffer operation."),
    "CWE-131": ("Incorrect Calculation of Buffer Size", "A buffer is sized by a wrong calculation, so a later copy overflows it."),
    "CWE-134": ("Uncontrolled Format String", "Attacker-controlled data is used as a printf-style format string, enabling reads/writes of memory."),
    "CWE-172": ("Encoding Error", "Data is encoded/decoded incorrectly, changing its meaning in a security-relevant way."),
    "CWE-190": ("Integer Overflow or Wraparound", "Arithmetic wraps past the type's range, producing a tiny or negative value used for a size/bound."),
    "CWE-191": ("Integer Underflow", "Subtraction wraps below zero, producing a huge unsigned value used as a size/bound."),
    "CWE-192": ("Integer Coercion Error", "A value is converted between integer types incorrectly, changing its value or sign."),
    "CWE-193": ("Off-by-one Error", "A bound is off by one, reading/writing one element past the intended range."),
    "CWE-197": ("Numeric Truncation Error", "A value is truncated to a narrower type, discarding high bits that mattered."),
    "CWE-200": ("Exposure of Sensitive Information", "The program discloses data (memory contents, secrets) to an actor who should not see it."),
    "CWE-203": ("Observable Discrepancy", "Behaviour differs observably by input (timing, output), leaking information such as a secret."),
    "CWE-242": ("Use of Inherently Dangerous Function", "A function known to be unsafe (e.g. gets) is used."),
    "CWE-248": ("Uncaught Exception", "An exception propagates uncaught, crashing or leaving the program in a bad state."),
    "CWE-250": ("Execution with Unnecessary Privileges", "Code runs with more privilege than it needs, widening the impact of a flaw."),
    "CWE-252": ("Unchecked Return Value", "A function's error return is ignored, so a failure goes unhandled."),
    "CWE-259": ("Use of Hard-coded Password", "A password is embedded in the code/binary."),
    "CWE-295": ("Improper Certificate Validation", "A TLS/certificate check is missing or wrong, allowing interception."),
    "CWE-321": ("Use of Hard-coded Cryptographic Key", "A cryptographic key is embedded in the code/binary."),
    "CWE-327": ("Use of a Broken or Risky Cryptographic Algorithm", "A weak or outdated crypto algorithm is used."),
    "CWE-328": ("Use of Weak Hash", "A weak hash function (e.g. MD5/SHA-1) is used where collision/preimage resistance matters."),
    "CWE-330": ("Use of Insufficiently Random Values", "Predictable randomness is used where unpredictability is required."),
    "CWE-338": ("Use of Cryptographically Weak PRNG", "A non-cryptographic random generator is used for security-sensitive values."),
    "CWE-362": ("Race Condition", "Concurrent access to shared state is not synchronised, so interleaving can corrupt it."),
    "CWE-367": ("TOCTOU Race Condition", "A resource is checked and then used, but can change in between (time-of-check/time-of-use)."),
    "CWE-369": ("Divide By Zero", "A division uses a zero (or unchecked) divisor, faulting the program."),
    "CWE-377": ("Insecure Temporary File", "A temp file is created insecurely, allowing tampering or disclosure."),
    "CWE-400": ("Uncontrolled Resource Consumption", "Input can drive unbounded use of memory/CPU/handles -- a denial-of-service lever."),
    "CWE-401": ("Memory Leak", "Allocated memory is never freed, growing usage over time."),
    "CWE-409": ("Improper Handling of Highly Compressed Data (Zip Bomb)", "Decompression expands input enormously, exhausting resources."),
    "CWE-415": ("Double Free", "The same allocation is freed twice, corrupting allocator metadata -- often exploitable."),
    "CWE-416": ("Use After Free", "Memory is used after being freed; the freed chunk may be reallocated under attacker control."),
    "CWE-457": ("Use of Uninitialized Variable", "A variable is read before being set, using stale/garbage memory."),
    "CWE-476": ("NULL Pointer Dereference", "A null pointer is dereferenced, crashing the program (denial of service)."),
    "CWE-494": ("Download of Code Without Integrity Check", "Code/data is fetched and used without verifying it was not tampered with."),
    "CWE-502": ("Deserialization of Untrusted Data", "Untrusted serialized data is deserialized, which can instantiate attacker-chosen objects/code."),
    "CWE-547": ("Use of Hard-coded, Security-relevant Constants", "A security-relevant constant is hard-coded, making it brittle or exposed."),
    "CWE-562": ("Return of Stack Variable Address", "A pointer to a local (stack) variable is returned/kept, becoming dangling after the frame ends."),
    "CWE-590": ("Free of Memory Not on the Heap", "free() is called on a pointer that was not heap-allocated, corrupting state."),
    "CWE-611": ("XML External Entity (XXE)", "An XML parser resolves external entities, enabling file read or SSRF."),
    "CWE-617": ("Reachable Assertion", "An assertion can be triggered by input, aborting the program (denial of service)."),
    "CWE-643": ("XPath Injection", "Input is concatenated into an XPath query, letting an attacker alter it."),
    "CWE-674": ("Uncontrolled Recursion", "Input can drive unbounded recursion, exhausting the stack."),
    "CWE-676": ("Use of Potentially Dangerous Function", "A function with unsafe failure modes is used (e.g. unbounded string functions)."),
    "CWE-680": ("Integer Overflow to Buffer Overflow", "An integer overflow mis-sizes an allocation, which a later copy then overflows."),
    "CWE-681": ("Incorrect Conversion between Numeric Types", "A numeric conversion changes value/sign, breaking a size or bounds check."),
    "CWE-686": ("Function Call with Incorrect Argument Type", "An argument of the wrong type is passed, causing misinterpretation."),
    "CWE-693": ("Protection Mechanism Failure", "A security control is missing or ineffective for the threat."),
    "CWE-704": ("Incorrect Type Conversion or Cast", "A value is cast to an incompatible type and then misused."),
    "CWE-758": ("Reliance on Undefined Behavior", "The program relies on undefined/implementation-specific behaviour that may change."),
    "CWE-761": ("Free of Pointer not at Start of Buffer", "free() is called on a pointer into the middle of an allocation, corrupting the heap."),
    "CWE-762": ("Mismatched Memory Management Routines", "Allocation and deallocation use mismatched allocators (e.g. new/free)."),
    "CWE-770": ("Allocation Without Limits or Throttling", "A size/count from input drives allocation with no cap, exhausting memory."),
    "CWE-776": ("XML Entity Expansion (Billion Laughs)", "Nested XML entities expand explosively, exhausting resources."),
    "CWE-786": ("Access of Memory Location Before Start of Buffer", "A read/write lands before the beginning of a buffer."),
    "CWE-787": ("Out-of-bounds Write", "A write lands outside the buffer's bounds -- the most directly exploitable memory-corruption class."),
    "CWE-788": ("Access of Memory Location After End of Buffer", "A read/write lands past the end of a buffer."),
    "CWE-789": ("Memory Allocation with Excessive Size Value", "A size from input is used to allocate an excessively large (or wrapped) amount of memory."),
    "CWE-798": ("Use of Hard-coded Credentials", "Credentials (password/key/token) are embedded in the code/binary."),
    "CWE-822": ("Untrusted Pointer Dereference", "A pointer whose value came from input is dereferenced, reading/writing an attacker-chosen address."),
    "CWE-823": ("Out-of-range Pointer Offset", "A pointer is advanced by an out-of-range offset, then dereferenced out of bounds."),
    "CWE-824": ("Access of Uninitialized Pointer", "An uninitialized pointer is dereferenced, hitting garbage memory."),
    "CWE-825": ("Expired Pointer Dereference (Dangling)", "A pointer to freed/out-of-scope memory is dereferenced."),
    "CWE-835": ("Infinite Loop", "Input can drive a loop that never terminates (denial of service)."),
    "CWE-843": ("Type Confusion", "An object is accessed as the wrong type, misinterpreting its memory layout."),
    "CWE-918": ("Server-Side Request Forgery (SSRF)", "The server makes a request to a URL from input, reaching internal services."),
    "CWE-1066": ("Missing Serialization Control Element", "A serialization step omits a needed control element, corrupting the result."),
    "CWE-1188": ("Insecure Default Initialization of Resource", "A resource ships with an insecure default (e.g. a default password)."),
    "CWE-1284": ("Improper Validation of Specified Quantity in Input", "A quantity/length from input is not validated against expectations."),
    "CWE-1285": ("Improper Validation of Specified Index/Offset", "An index or offset from input is used without validating its range."),
    "CWE-1335": ("Incorrect Bitwise Shift", "A shift by an out-of-range or negative amount yields undefined/incorrect results."),
    "CWE-1395": ("Dependency on Vulnerable Third-Party Component", "The target depends on a component with a known vulnerability (CVE)."),
}


def cwe_info(cwe: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """(name, description) for a CWE id like 'CWE-787', or (None, None) if unknown.

    Tolerant of a bare number ('787'), extra whitespace, and lowercase.
    """
    if not cwe:
        return (None, None)
    key = str(cwe).strip().upper()
    if key.isdigit():
        key = "CWE-" + key
    hit = CWE_NAMES.get(key)
    return hit if hit else (None, None)
