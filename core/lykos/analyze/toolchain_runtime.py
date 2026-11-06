"""Is a symbol part of the TOOLCHAIN runtime linked into an instrumented build, not the program?

An ASan/UBSan/libFuzzer build links thousands of runtime functions and objects into the binary:
`__asan_*`, `__sanitizer::*` (mangled `_ZN11__sanitizer...`), libFuzzer's `fuzzer::*`
(`_ZN6fuzzer...`), the coverage callbacks. Stages that pick "the target's own" allocator or global
tables from the symbol table must skip them, or they analyse the sanitizer instead of the program:
on FreeRDP's libFuzzer harnesses heap_trace took `__asan_get_alloc_stack`/`__asan_get_free_stack`
for the target's allocator (~100 s per harness) and oob_index filed a CWE-129 on
`__sanitizer::internal_alloc_placeholder`.

Deliberately narrow: sanitizer, coverage and fuzzer-engine runtimes only. libc / libstdc++ are not
here -- callers that also exclude those keep their own lists.
"""
from __future__ import annotations

#: Plain (C-linkage or already-demangled) prefixes.
_PLAIN = ("__asan", "__ubsan", "__lsan", "__tsan", "__msan", "__hwasan", "__dfsan",
          "__sanitizer", "__sancov", "__interception", "__interceptor", "___interceptor",
          "__llvm_profile", "__llvm_gcov", "__cfi_", "__scudo", "asan.", "sancov.",
          "fuzzer::", "LLVMFuzzer", "__libfuzzer", "__lsan_", "__sanitize")

#: Itanium-mangled namespace heads (`_ZN` + length + name, `_ZL`/`_ZZN` for locals/statics).
_NS = ("__asan", "__ubsan", "__lsan", "__tsan", "__msan", "__hwasan", "__dfsan",
       "__sanitizer", "__interception", "__scudo", "__sancov", "fuzzer")
_MANGLED = tuple(f"{head}{len(ns)}{ns}" for ns in _NS for head in ("_ZN", "_ZNK", "_ZZN", "_ZL"))


def is_toolchain_runtime(name) -> bool:
    """True for a sanitizer / coverage / fuzzer-engine runtime symbol."""
    if not name:
        return False
    n = str(name).split("@", 1)[0].lstrip(".")
    if n.startswith(_PLAIN) or n.startswith(_MANGLED):
        return True
    # `_ZN11__sanitizerL26internal_alloc_placeholderE`: the namespace sits after the head even
    # for internal-linkage names, so the prefix test above already covers it; a nested name
    # (`_ZN4llvm...`) is the program's, not ours.
    return False


import re as _re

#: Object files of the sanitizer / libFuzzer runtimes as the static symbol table names them
#: (`asan_interceptors.cpp.o`, `ubsan_diag.cpp.o`, `FuzzerLoop.cpp.o`).
_RUNTIME_FILE = _re.compile(
    r"^(?:asan|lsan|ubsan|tsan|msan|hwasan|dfsan|sanitizer|interception|sancov|scudo|"
    r"memprof|nsan|rtsan|Fuzzer)[A-Za-z0-9_]*\.(?:c|cc|cpp|cxx|S|s|inc)(?:\.o)?$")


def runtime_symbols(blob: bytes) -> frozenset:
    """Every symbol the ELF symbol table attributes to a toolchain-runtime OBJECT FILE.

    A local (`static`) runtime object carries no namespace to recognise it by --
    `_ZL11ioctl_table` (asan_interceptors.cpp) and `_ZL17kSuppressionTypes` (ubsan_diag.cpp)
    read as ordinary file-static tables -- but `.symtab` lists each object file's locals right
    after an STT_FILE entry naming it. Empty for a stripped binary or a non-ELF input."""
    try:
        import io

        from elftools.elf.elffile import ELFFile
        st = ELFFile(io.BytesIO(blob)).get_section_by_name(".symtab")
    except Exception:                                    # noqa: BLE001 -- not an ELF we can read
        return frozenset()
    if st is None or not hasattr(st, "iter_symbols"):
        return frozenset()
    out, in_rt = set(), False
    for s in st.iter_symbols():
        if s["st_info"]["type"] == "STT_FILE":
            in_rt = bool(_RUNTIME_FILE.match(s.name or ""))
            continue
        if in_rt and s["st_info"]["bind"] == "STB_LOCAL" and s.name:
            out.add(s.name)
    return frozenset(out)
