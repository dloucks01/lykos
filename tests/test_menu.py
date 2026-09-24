"""Menu-navigation seed synthesis for interactive/menu-driven targets."""
from lykos.analyze.fuzz import menu


def test_detects_numbered_menu_and_builds_navigation_seeds():
    strings = ["Welcome", "1 - Add Author", "2. Modify Author", "[3] Print Author",
               "4) Delete Author", "5: Exit", "Your choice: "]
    opts = menu.detect_menu(strings)
    assert opts == ["1", "2", "3", "4", "5"]
    seeds = menu.menu_seeds(strings)
    assert seeds, "expected navigation seeds"
    assert b"1\n" in seeds                                   # bare option
    assert any(s.startswith(b"1\n") and b"A" * 64 in s for s in seeds)   # option -> data
    assert any(b"64\n" in s for s in seeds)                 # option -> size -> data
    # a create-then-act multi-step sequence exists
    assert any(s.count(b"\n") >= 3 for s in seeds)


def test_no_menu_no_seeds():
    assert menu.detect_menu(["hello", "world", "just text"]) == []
    assert menu.menu_seeds(["nothing", "here"]) == []
    assert menu.detect_menu(["1 - only one option"]) == []   # need >= 2
