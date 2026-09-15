"""JAR and .class parsing -- the third executable format, and the one that is not machine code.

A large share of real deployments are `java -jar app.jar -c app.conf`, and until now this
platform could not even name such a file: a jar is a zip, so triage classified it as "not a
binary", declined to analyse it, and every stage after that was unreachable. Nothing about the
platform's approach requires machine code, though. A .class file carries its whole string
constant pool and every method it calls, unobfuscated and in the clear -- which is strictly
MORE than a stripped ELF gives up -- and the JVM runs it under the same sandbox as anything
else.

What changes is the failure mode. A Java program does not segfault; it throws, and the
exception name and stack trace say more about the defect than a signal number and a fault
address ever do. So the crash oracle reads stderr rather than the wait status, and the
"faulting function" is the top stack frame.

What does NOT carry over is the top of the PoC ladder, and it is worth being blunt about why:
the JVM checks every array access and owns every pointer, so there is no instruction pointer
to take. L1 (a verified, reproducible fault) is reachable and is what this format supports.
L2 and L3 are not, and a badge claiming otherwise would be a lie about the runtime.
"""
from __future__ import annotations

import io
import re
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Optional

CLASS_MAGIC = b"\xca\xfe\xba\xbe"
JAR_MAGIC = b"PK\x03\x04"

# Constant-pool tags (JVMS 4.4). Long and Double take TWO slots, which is the classic way to
# mis-parse a constant pool: miss it and every index after the first `long` is off by one.
_UTF8, _INTEGER, _FLOAT, _LONG, _DOUBLE = 1, 3, 4, 5, 6
_CLASS, _STRING, _FIELDREF, _METHODREF, _IFACEREF = 7, 8, 9, 10, 11
_NAMEANDTYPE, _METHODHANDLE, _METHODTYPE, _DYNAMIC, _INVOKEDYNAMIC = 12, 15, 16, 17, 18
_MODULE, _PACKAGE = 19, 20
# tag -> fixed payload size for the ones we skip wholesale
_FIXED = {_INTEGER: 4, _FLOAT: 4, _LONG: 8, _DOUBLE: 8, _CLASS: 2, _STRING: 2,
          _FIELDREF: 4, _METHODREF: 4, _IFACEREF: 4, _NAMEANDTYPE: 4, _METHODHANDLE: 3,
          _METHODTYPE: 2, _DYNAMIC: 4, _INVOKEDYNAMIC: 4, _MODULE: 2, _PACKAGE: 2}

# Java SE class-file major versions: 45 is Java 1.0, 65 is Java 21. The range is the whole
# reason a class file can be told apart from a Mach-O universal binary, which shares the magic
# exactly -- see `is_class`.
_MIN_MAJOR, _MAX_MAJOR = 45, 90
_JAVA_RELEASE = {45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4", 49: "5", 50: "6", 51: "7",
                 52: "8", 53: "9", 54: "10", 55: "11", 56: "12", 57: "13", 58: "14",
                 59: "15", 60: "16", 61: "17", 62: "18", 63: "19", 64: "20", 65: "21",
                 66: "22", 67: "23", 68: "24", 69: "25"}


def is_class(data: bytes) -> bool:
    """A .class file, and specifically NOT a Mach-O universal binary.

    Both start with CAFEBABE -- Java chose the constant deliberately and Apple chose it
    independently -- so magic alone puts every fat Mach-O into the Java path and every class
    file into the Mach-O path, depending only on which check runs first. They are separable at
    the next four bytes: Java writes minor then MAJOR version (45 for Java 1.0 through 65 for
    Java 21), Mach-O writes a 32-bit architecture count, which is a handful. A file claiming
    45+ architectures is not a fat binary.
    """
    if len(data) < 10 or data[:4] != CLASS_MAGIC:
        return False
    major = struct.unpack_from(">H", data, 6)[0]
    return _MIN_MAJOR <= major <= _MAX_MAJOR


def is_jar(data: bytes) -> bool:
    """A zip that holds Java classes -- a jar, war, ear or Android-style bundle.

    Being a zip is not enough: a plain archive of source, a .docx and a firmware bundle are
    all zips, and calling one of those a Java program produces a target that cannot be run.
    """
    if data[:4] != JAR_MAGIC:
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
    except Exception:
        return False
    return any(n.endswith(".class") for n in names) or "META-INF/MANIFEST.MF" in names


@dataclass
class JvmInfo:
    kind: str = "jar"                       # "jar" or "class"
    main_class: Optional[str] = None
    class_path: list = field(default_factory=list)
    classes: list = field(default_factory=list)      # internal names, e.g. com/x/Svc
    strings: list = field(default_factory=list)      # constant-pool UTF-8, deduped
    calls: list = field(default_factory=list)        # "java/lang/Runtime.exec"
    by_class: dict = field(default_factory=dict)     # name -> {"calls": [...], "strings": n}
    java_version: Optional[str] = None
    major: Optional[int] = None
    manifest: dict = field(default_factory=dict)
    entries: int = 0
    signed: bool = False
    errors: list = field(default_factory=list)


# javac compiles `a + b` into an invokedynamic whose bootstrap argument is a RECIPE string:
# the literal text with \u0001 standing in for each argument. So a class that concatenates a
# constant carries that constant twice -- once as itself, once inside the recipe -- and a
# hard-coded credential was reported as two findings, one of them with a control character
# glued to the front. The recipe is real and correct (javap shows both); it is just not a
# second secret.
_CONCAT_MARKS = str.maketrans("", "", "\x01\x02")


def _norm_concat(s: str) -> str:
    return s.translate(_CONCAT_MARKS) if ("\x01" in s or "\x02" in s) else s


def _constant_pool(data: bytes, off: int, count: int):
    """(utf8 list, {index: utf8}, [(class_idx, nameandtype_idx)], end offset)."""
    utf8s: list = []
    by_index: dict = {}
    refs: list = []
    nameandtype: dict = {}
    classes: dict = {}
    i = 1
    while i < count:
        if off >= len(data):
            raise ValueError("constant pool runs past end of file")
        tag = data[off]
        off += 1
        if tag == _UTF8:
            (n,) = struct.unpack_from(">H", data, off)
            off += 2
            s = data[off:off + n].decode("utf-8", "replace")
            off += n
            by_index[i] = s
            utf8s.append(s)
        elif tag in _FIXED:
            if tag in (_METHODREF, _IFACEREF):
                refs.append(struct.unpack_from(">HH", data, off))
            elif tag == _NAMEANDTYPE:
                nameandtype[i] = struct.unpack_from(">HH", data, off)
            elif tag == _CLASS:
                classes[i] = struct.unpack_from(">H", data, off)[0]
            off += _FIXED[tag]
        else:
            raise ValueError(f"unknown constant pool tag {tag} at index {i}")
        # A long or a double occupies two entries and the second is unusable. Every index
        # after the first one shifts if this is missed, which turns a class's whole string
        # table into fragments of the wrong strings.
        i += 2 if tag in (_LONG, _DOUBLE) else 1
    return utf8s, by_index, refs, nameandtype, classes, off


def parse_class(data: bytes) -> JvmInfo:
    """One .class file: its strings, the methods it calls, and its own name."""
    info = JvmInfo(kind="class")
    try:
        minor, major, cp_count = struct.unpack_from(">HHH", data, 4)
        info.major = major
        info.java_version = _JAVA_RELEASE.get(major)
        utf8s, by_index, refs, nat, classes, off = _constant_pool(data, 10, cp_count)
        info.strings = utf8s
        _access, this_class = struct.unpack_from(">HH", data, off)
        name_idx = classes.get(this_class)
        if name_idx:
            info.classes = [by_index.get(name_idx, "")]
        for cls_idx, nat_idx in refs:
            owner = by_index.get(classes.get(cls_idx, 0), "?")
            pair = nat.get(nat_idx)
            meth = by_index.get(pair[0], "?") if pair else "?"
            info.calls.append(f"{owner}.{meth}")
    except Exception as e:
        info.errors.append(f"class: {e!r}")
    return info


_MANIFEST_KV = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$")


def parse_manifest(text: str) -> dict:
    """META-INF/MANIFEST.MF. Continuation lines start with a single space, and a Class-Path
    long enough to wrap is exactly where that matters."""
    out: dict = {}
    key = None
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if raw.startswith(" ") and key:
            out[key] += raw[1:]
            continue
        m = _MANIFEST_KV.match(raw)
        if m:
            key = m.group(1)
            out[key] = m.group(2)
        else:
            key = None
    return out


# A fat jar keeps the application's own classes under a prefix and its dependencies as nested
# jars. Treating the whole thing as one program means the report is 90% Spring, so the prefix
# is recorded and used to separate the two -- the same program-vs-library split `elf.py` does
# with STT_FILE symbols.
_APP_PREFIXES = ("BOOT-INF/classes/", "WEB-INF/classes/")


# A jar is untrusted: a member a few KB compressed can inflate to gigabytes (a "zip bomb").
# Cap every member read so one hostile entry cannot exhaust memory. 8 MB is far above any real
# class file (a single method's bytecode maxes at 64 KB) or manifest.
_MAX_ENTRY_BYTES = 8 * 1024 * 1024


def _safe_read(z: "zipfile.ZipFile", name: str) -> Optional[bytes]:
    """Read a zip member, refusing to inflate a decompression bomb. Returns None if the member
    is absent, unreadable, or larger than the per-entry cap. The read itself is bounded, so a
    member that LIES about its uncompressed size in the central directory is still contained."""
    try:
        if z.getinfo(name).file_size > _MAX_ENTRY_BYTES:
            return None
    except KeyError:
        return None
    try:
        with z.open(name) as fh:
            buf = fh.read(_MAX_ENTRY_BYTES + 1)
    except Exception:
        return None
    return None if len(buf) > _MAX_ENTRY_BYTES else buf


def parse(data: bytes, *, max_classes: int = 4000) -> JvmInfo:
    """A jar (or a bare .class) -- manifest, entry point, classes, strings and calls."""
    if is_class(data):
        return parse_class(data)
    info = JvmInfo(kind="jar")
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        info.errors.append(f"jar: {e!r}")
        return info
    with z:
        names = z.namelist()
        info.entries = len(names)
        info.signed = any(n.startswith("META-INF/") and n.endswith((".SF", ".RSA", ".DSA"))
                          for n in names)
        mf = _safe_read(z, "META-INF/MANIFEST.MF")
        if mf is not None:
            try:
                info.manifest = parse_manifest(mf.decode("utf-8", "replace"))
            except Exception:
                pass
        info.main_class = (info.manifest.get("Main-Class")
                           or info.manifest.get("Start-Class"))
        cp = info.manifest.get("Class-Path") or ""
        info.class_path = [x for x in cp.split() if x]

        app = [n for n in names if n.endswith(".class")]
        prefixed = [n for n in app if n.startswith(_APP_PREFIXES)]
        if prefixed:
            app = prefixed                   # a fat jar: analyse the application, not Spring
        strings: list = []
        seen: set = set()
        calls: set = set()
        for n in app[:max_classes]:
            raw = _safe_read(z, n)
            if raw is None:
                info.errors.append(f"{n}: skipped (entry too large or unreadable)")
                continue
            try:
                sub = parse_class(raw)
            except Exception as e:
                info.errors.append(f"{n}: {e!r}")
                continue
            info.classes.extend(sub.classes)
            # Per-class calls, so a finding can name WHERE it is rather than saying only that
            # the jar somewhere calls Runtime.exec. In a fat jar that difference is the whole
            # report: "this application shells out" against "one of its 900 dependencies does".
            if sub.classes:
                info.by_class[sub.classes[0]] = {
                    "calls": sub.calls,
                    "strings": list(dict.fromkeys(_norm_concat(x) for x in sub.strings))}
            if info.major is None:
                info.major, info.java_version = sub.major, sub.java_version
            for s in sub.strings:
                s = _norm_concat(s)
                if s and s not in seen:
                    seen.add(s)
                    strings.append(s)
            calls.update(sub.calls)
        info.strings = strings
        info.calls = sorted(calls)
        if len(app) > max_classes:
            info.errors.append(f"jar holds {len(app)} classes; parsed the first {max_classes}")
    return info


def strings_of(data: bytes) -> list:
    """The string constants in a jar or class.

    A jar is a zip, so scanning its bytes for printable runs -- which is what every other
    format here does -- reads DEFLATE output and finds nothing. Every consumer of a target's
    strings (the invocation discovery, the fuzzing dictionary, the format detector, the
    credential detector) therefore got an empty list and silently concluded there was nothing
    to find.
    """
    return parse(data).strings


def to_format_details(info: JvmInfo) -> dict:
    return {"jvm": {"kind": info.kind, "main_class": info.main_class,
                    "java_version": info.java_version, "class_file_major": info.major,
                    "classes": len(info.classes), "entries": info.entries,
                    "signed": info.signed, "class_path": info.class_path[:32],
                    "manifest": {k: v for k, v in list(info.manifest.items())[:24]}}}


# ---- what an uncaught exception actually means -------------------------------------------
#
# The native crash table falls through to CWE-119 (memory corruption) at "critical", which is
# the right default for a signal and a lie for a managed runtime: an
# ArrayIndexOutOfBoundsException is the JVM CATCHING the out-of-bounds access. The bug is
# real -- the index was attacker-controlled and unvalidated, and an uncaught one terminates
# the process, which for a service is denial of service -- but nothing was corrupted, and
# badging it "critical memory corruption" would misrepresent the runtime.
EXCEPTION_CWE = {
    # unvalidated index / size reaching an array
    "ArrayIndexOutOfBoundsException": ("CWE-129", "high"),
    "StringIndexOutOfBoundsException": ("CWE-129", "high"),
    "IndexOutOfBoundsException": ("CWE-129", "high"),
    "NegativeArraySizeException": ("CWE-129", "high"),
    # resource exhaustion the input controls
    "OutOfMemoryError": ("CWE-789", "high"),
    "StackOverflowError": ("CWE-674", "high"),
    # unvalidated input reaching a conversion or a cast
    "NumberFormatException": ("CWE-20", "medium"),
    "ClassCastException": ("CWE-704", "medium"),
    "ArrayStoreException": ("CWE-704", "medium"),
    "ArithmeticException": ("CWE-369", "medium"),
    "NullPointerException": ("CWE-476", "medium"),
    "BufferOverflowException": ("CWE-787", "high"),
    "BufferUnderflowException": ("CWE-125", "high"),
    # deserialization reaching code it should not
    "InvalidClassException": ("CWE-502", "high"),
    "StreamCorruptedException": ("CWE-502", "medium"),
    # A program that validates its input by throwing is doing the RIGHT thing. Uncaught in
    # main it still kills the process, so it is not nothing -- but it is a missing catch, not
    # a memory-safety defect, and ranking it with one would bury the findings that matter.
    "IllegalStateException": ("CWE-248", "low"),
    "IllegalArgumentException": ("CWE-248", "low"),
    "UnsupportedOperationException": ("CWE-248", "low"),
    "NoSuchElementException": ("CWE-248", "low"),
    "ConcurrentModificationException": ("CWE-248", "low"),
    "FileNotFoundException": ("CWE-248", "info"),
    "NoSuchFileException": ("CWE-248", "info"),
    "IOException": ("CWE-248", "low"),
    "SecurityException": ("CWE-248", "low"),
}
# The JVM itself dying is the one Java result that IS memory corruption.
_FATAL_PREFIX = "JVM-FATAL-"


def cwe_for_exception(name: str):
    """(cwe, severity) for an uncaught JVM fault, or None if this is not one."""
    if not name:
        return None
    if name.startswith(_FATAL_PREFIX):
        return ("CWE-119", "critical")
    hit = EXCEPTION_CWE.get(name)
    if hit:
        return hit
    if name.endswith(("Exception", "Error", "Throwable")):
        # Unknown, but unmistakably a JVM fault. CWE-248 with a middling severity is the
        # honest answer; inheriting the native default would call it critical memory
        # corruption on a runtime that has none.
        return ("CWE-248", "medium")
    return None
