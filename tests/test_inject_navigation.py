"""Injection probing behind a menu / input gate.

A sink the entry channel cannot reach (a `printf(user)` under menu option 2) never saw a probe:
the first read consumed the payload as the menu choice, parsing failed and the program exited,
which the stage reported as "no injection confirmed on the entry channel". The prober now retries
with navigation preambles, so the program is AT the sink when the payload is read.
"""
from lykos.analyze.poc import inject_stage


class _Ctx:
    """Minimal stand-in: StringDAO(conn) fails, exercising the no-disassembler-strings fallback."""
    conn = object()


class _Target:
    id = "t1"


_MENU_BLOB = (b"\x7fELF" + b"\x00" * 60
              + b"1. Add note\n2. Show note\n3. Delete\nChoice: \x00" + b"A" * 200)


def test_menu_options_become_navigation_preambles():
    navs = inject_stage._nav_preambles(_Ctx(), _Target(), _MENU_BLOB)
    for opt in (b"1\n", b"2\n", b"3\n"):
        assert opt in navs


def test_menu_options_are_tried_before_over_broad_gates():
    # _gate_preambles is deliberately over-broad (it returns imported symbol names and the
    # interpreter path on a target with no real gate), so leading with it only buys sandbox runs.
    navs = inject_stage._nav_preambles(_Ctx(), _Target(), _MENU_BLOB)
    assert navs[:3] == [b"1\n", b"2\n", b"3\n"]


def test_every_preamble_is_newline_terminated_and_unique():
    # A preamble that does not end the line leaves the menu read waiting, and the payload is
    # appended to the choice instead of being read as the next field.
    navs = inject_stage._nav_preambles(_Ctx(), _Target(), _MENU_BLOB)
    assert navs, "a menu target must yield at least one preamble"
    assert all(p.endswith(b"\n") for p in navs)
    assert len(set(navs)) == len(navs)


def test_no_menu_yields_no_menu_preambles():
    navs = inject_stage._nav_preambles(_Ctx(), _Target(), b"\x7fELF" + b"\x00" * 64 + b"B" * 128)
    assert all(p not in (b"1\n", b"2\n", b"3\n") for p in navs)


def test_preamble_count_is_bounded():
    many = b"\x7fELF" + b"\x00" * 60 + b"".join(
        b"%d. option\n" % i for i in range(1, 30)) + b"Choice: \x00"
    assert len(inject_stage._nav_preambles(_Ctx(), _Target(), many)) <= 10


def test_stdin_delivery_prefixes_the_navigation():
    argv, stdin = inject_stage._deliver("stdin", b"%p%p", [], None, nav=b"2\n")
    assert stdin == b"2\n%p%p" and argv == []


def test_delivery_without_navigation_is_unchanged():
    argv, stdin = inject_stage._deliver("stdin", b"%p%p", ["--go"], None)
    assert stdin == b"%p%p" and argv == ["--go"]
