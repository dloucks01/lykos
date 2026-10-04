"""Tainted-argument sink detection (CWE-78 command injection, CWE-134 format string), source-level.

A dangerous sink called with a NON-LITERAL argument where a literal belongs: `system(cmd)` with a
variable command, `printf(fmt)` with a variable format. The detector's worth is precision -- a
string literal (even wrapped in an i18n macro, or held by a local assigned a literal) is the safe,
intentional case and must NOT be flagged.
"""
from __future__ import annotations

from pathlib import Path

from lykos.analyze.fingerprint import source_sinks as ss


def _tree(tmp_path, files: dict) -> Path:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path


def _cwes(root):
    return sorted(f["cwe"] for f in ss.scan_source(root))


def test_system_with_variable_is_command_injection(tmp_path):
    assert _cwes(_tree(tmp_path, {"a.c": "void f(char*u){ system(u); }"})) == ["CWE-78"]


def test_popen_with_built_command_is_command_injection(tmp_path):
    root = _tree(tmp_path, {"a.c": 'void f(char*u){ char b[99]; sprintf(b,"ping %s",u); popen(b,"r"); }'})
    assert _cwes(root) == ["CWE-78"]          # the sprintf format is a literal -> only the popen fires


def test_printf_with_variable_format_is_format_string(tmp_path):
    assert _cwes(_tree(tmp_path, {"a.c": "void f(char*u){ printf(u); }"})) == ["CWE-134"]


def test_fprintf_and_syslog_variable_format(tmp_path):
    root = _tree(tmp_path, {"a.c": "void f(char*u){ fprintf(stderr,u); }\n"
                                   "void g(char*u){ syslog(3,u); }\n"})
    assert _cwes(root) == ["CWE-134", "CWE-134"]


def test_sprintf_with_variable_format(tmp_path):
    assert _cwes(_tree(tmp_path, {"a.c": "void f(char*u,char*fm){ char b[9]; sprintf(b,fm,u); }"})) \
        == ["CWE-134"]


def test_literal_command_is_not_flagged(tmp_path):
    assert _cwes(_tree(tmp_path, {"a.c": 'void f(){ system("ls -la"); }'})) == []


def test_literal_format_is_not_flagged(tmp_path):
    assert _cwes(_tree(tmp_path, {"a.c": 'void f(char*s){ printf("%s", s); }'})) == []


def test_local_assigned_a_literal_format_is_safe(tmp_path):
    """`const char *fmt = "..."; printf(fmt)` is safe -- the detector tracks literal-assigned locals."""
    assert _cwes(_tree(tmp_path, {"a.c": 'void f(){ const char *fmt="hi %d"; printf(fmt,1); }'})) == []


def test_i18n_wrapped_literal_is_safe(tmp_path):
    assert _cwes(_tree(tmp_path, {"a.c": 'void f(char*n){ printf(_("hello %s"), n); }'})) == []


def test_snprintf_with_literal_format_is_safe(tmp_path):
    assert _cwes(_tree(tmp_path, {"a.c": 'void f(char*u){ char b[9]; snprintf(b,9,"%s",u); }'})) == []


def test_vendored_and_test_dirs_are_skipped(tmp_path):
    root = _tree(tmp_path, {"third_party/x.c": "void f(char*u){ system(u); }\n",
                            "tests/y.c": "void g(char*u){ printf(u); }\n"})
    assert _cwes(root) == []
