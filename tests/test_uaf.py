"""Use-after-free / double-free detection (CWE-416 / CWE-415), source-level.

The static complement to the dynamic heap_trace: it flags a freed pointer that is used or freed
again with no reassignment in between, even on a path the fuzzer never drives. Its value is
precision -- a reassignment (including the safe `p = NULL;` idiom) must silence it, and a free in
one function must not implicate a same-named pointer in the next.
"""
from __future__ import annotations

from pathlib import Path

from lykos.analyze.fingerprint import uaf


def _tree(tmp_path, files: dict) -> Path:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path


def _hits(root):
    return uaf.scan_source(root)


def test_double_free_is_flagged(tmp_path):
    root = _tree(tmp_path, {"v.c": "void f(char*p){\n free(p);\n do_x();\n free(p);\n}\n"})
    h = _hits(root)
    assert len(h) == 1 and h[0]["cwe"] == "CWE-415"


def test_use_after_free_deref_is_flagged(tmp_path):
    root = _tree(tmp_path, {"v.c": "void f(obj*o){\n free(o);\n o->next = 0;\n}\n"})
    h = _hits(root)
    assert len(h) == 1 and h[0]["cwe"] == "CWE-416"


def test_use_after_free_as_call_argument_is_flagged(tmp_path):
    root = _tree(tmp_path, {"v.c": "void f(char*p){\n free(p);\n printf(\"%s\", p);\n}\n"})
    assert len(_hits(root)) == 1


def test_cpp_delete_then_use_is_flagged(tmp_path):
    root = _tree(tmp_path, {"v.cpp": "void f(){\n T*p = new T();\n delete p;\n p->go();\n}\n"})
    h = _hits(root)
    assert len(h) == 1 and h[0]["cwe"] == "CWE-416"


def test_reassign_to_null_suppresses(tmp_path):
    """The safe idiom `p = NULL;` after free clears the dangling pointer -> not flagged."""
    root = _tree(tmp_path, {"v.c": "void f(char*p){\n free(p);\n p = 0;\n if(p) use(p);\n}\n"})
    assert _hits(root) == []


def test_realloc_reuse_suppresses(tmp_path):
    """Freeing then reassigning (reallocating) the pointer is normal reuse, not a UAF."""
    root = _tree(tmp_path, {"v.c": "void f(char*p){\n free(p);\n p = malloc(32);\n p[0] = 1;\n}\n"})
    assert _hits(root) == []


def test_free_in_one_function_does_not_implicate_the_next(tmp_path):
    root = _tree(tmp_path, {"v.c": "void a(char*p){ free(p); }\nvoid b(char*p){ p[0] = 1; }\n"})
    assert _hits(root) == []


def test_address_of_a_freed_pointer_is_not_a_use(tmp_path):
    """`&p` stores the slot, not the freed object -- a common post-free bookkeeping pattern."""
    root = _tree(tmp_path, {"v.c": "void f(char*p){\n free(p);\n remember(&p);\n}\n"})
    assert _hits(root) == []


def test_use_before_free_is_not_flagged(tmp_path):
    root = _tree(tmp_path, {"v.c": "void f(char*p){\n p[0] = 1;\n free(p);\n}\n"})
    assert _hits(root) == []


def test_vendored_and_test_dirs_are_skipped(tmp_path):
    root = _tree(tmp_path, {"third_party/x.c": "void f(char*p){ free(p); free(p); }\n",
                            "tests/y.c": "void g(char*p){ free(p); p->n=1; }\n"})
    assert _hits(root) == []
