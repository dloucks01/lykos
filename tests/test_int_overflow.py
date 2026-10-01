"""Integer-overflow-into-allocation detection (CWE-190), source-level.

The detector earns its keep by being guard-AWARE: unguarded size arithmetic feeding an allocator
is flagged, but the same arithmetic behind an overflow check (the fix) is not. The headline case
is FreeRTOS queue allocation -- vulnerable pre-10.4.3, guarded with SIZE_MAX afterwards.
"""
from __future__ import annotations

from pathlib import Path

from lykos.analyze.fingerprint import int_overflow as io


def _tree(tmp_path, files: dict) -> Path:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path


def _hits(root):
    return io.scan_source(root)


def test_direct_unguarded_multiply_into_malloc_is_flagged(tmp_path):
    root = _tree(tmp_path, {"v.c": "void *f(unsigned a, unsigned b){ return malloc(a * b); }\n"})
    assert len(_hits(root)) == 1
    assert _hits(root)[0]["cwe"] == "CWE-190"


def test_unguarded_multiply_via_a_size_variable_is_flagged(tmp_path):
    root = _tree(tmp_path, {"v.c":
                            "void *f(unsigned n, unsigned sz){\n"
                            "  unsigned total = n * sz;\n"
                            "  return malloc(total);\n}\n"})
    assert len(_hits(root)) == 1


def test_a_size_max_guard_suppresses_the_finding(tmp_path):
    """The FreeRTOS fix idiom: `SIZE_MAX / a >= b` before the multiply."""
    root = _tree(tmp_path, {"v.c":
                            "#include <stdint.h>\n"
                            "void *f(unsigned n, unsigned sz){\n"
                            "  if (n != 0 && (SIZE_MAX / n) < sz) return 0;\n"
                            "  return malloc(n * sz);\n}\n"})
    assert _hits(root) == []


def test_builtin_mul_overflow_guard_suppresses(tmp_path):
    root = _tree(tmp_path, {"v.c":
                            "void *f(unsigned n, unsigned sz){\n"
                            "  unsigned t;\n"
                            "  if (__builtin_mul_overflow(n, sz, &t)) return 0;\n"
                            "  return malloc(n * sz);\n}\n"})
    assert _hits(root) == []


def test_calloc_is_not_flagged(tmp_path):
    """calloc checks the product internally -- it is the FIX, not the bug."""
    root = _tree(tmp_path, {"v.c": "void *f(unsigned n){ return calloc(n, 16); }\n"})
    assert _hits(root) == []


def test_all_constant_size_is_not_flagged(tmp_path):
    root = _tree(tmp_path, {"v.c": "void *f(void){ return malloc(4 * 8); }\n"})
    assert _hits(root) == []


def test_a_comment_mentioning_overflow_does_not_count_as_a_guard(tmp_path):
    """Regression: a bare 'overflow' guard token matched the comment 'no overflow check' and
    suppressed the very bug it described."""
    root = _tree(tmp_path, {"v.c":
                            "void *f(unsigned a, unsigned b){\n"
                            "  /* no overflow check here */\n"
                            "  return malloc(a * b);\n}\n"})
    assert len(_hits(root)) == 1


def test_a_guarded_queue_alloc_like_freertos_11_is_not_flagged(tmp_path):
    """The real shape: the patched FreeRTOS xQueueGenericCreate must stay quiet."""
    root = _tree(tmp_path, {"queue.c":
                            "void *xQueueGenericCreate(unsigned uxQueueLength, unsigned uxItemSize){\n"
                            "  size_t xQueueSizeInBytes;\n"
                            "  if ((uxQueueLength > 0) && ((SIZE_MAX / uxQueueLength) >= uxItemSize)) {\n"
                            "    xQueueSizeInBytes = uxQueueLength * uxItemSize;\n"
                            "    return pvPortMalloc(sizeof(void*) + xQueueSizeInBytes);\n"
                            "  }\n  return 0;\n}\n"})
    assert _hits(root) == []


def test_vendored_and_test_dirs_are_skipped(tmp_path):
    root = _tree(tmp_path, {"third_party/x.c": "void *f(unsigned a,unsigned b){return malloc(a*b);}\n",
                            "tests/y.c": "void *g(unsigned a,unsigned b){return malloc(a*b);}\n"})
    assert _hits(root) == []
