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


# --------------------------------------------------- menu-semantic sequence inference ----

def test_classify_prompt_index_number_string():
    assert menu.classify_prompt("Author ID: ") == "idx"
    assert menu.classify_prompt("Which slot?") == "idx"
    assert menu.classify_prompt("Note size: ") == "num"          # size wins over the "note" noun
    assert menu.classify_prompt("Age: ") == "num"
    assert menu.classify_prompt("Author Note size: ") == "num"   # object noun is not an index
    assert menu.classify_prompt("Name: ") == "str"
    assert menu.classify_prompt("Note: ") == "str"


def test_is_alloc_needs_size_then_string():
    # add flow: Name, Surname, Age, Note-size, Note -> allocates (num then a str after)
    assert menu._is_alloc(["str", "str", "num", "num", "str"])
    assert menu._is_alloc(["num", "str"])
    assert not menu._is_alloc(["idx"])                 # delete: index only
    assert not menu._is_alloc(["idx", "str"])          # modify by id: no size field
    assert not menu._is_alloc(["str", "str"])          # no size at all


def test_menu_op_sequences_from_model_types_fields_and_overflows():
    model = {"1": ["str", "str", "num", "num", "str"],   # add
             "2": ["idx", "str"],                         # modify
             "3": ["idx"]}                                # delete
    seqs = menu.menu_op_sequences(model, ["1", "2", "3"])
    assert seqs
    # the allocating option primes with typed values: Name/Surname strings, Age/size numbers, Note
    assert any(s.startswith(b"1\nAAAA\nAAAA\n16\n16\nAAAA\n") for s in seqs)
    # an over-long payload (overflow shape) reaches a non-alloc option
    assert any(b"B" * 200 in s for s in seqs)
    # delete driven twice on the same id (double-free shape)
    assert any(s.rstrip(b"\n").endswith(b"3\n1\n3\n1") or b"3\n1\n3\n1\n" in s for s in seqs)


def test_menu_op_sequences_empty_without_allocator():
    # only index/print options, nothing that allocates -> no sequences
    assert menu.menu_op_sequences({"1": ["idx"], "2": ["idx"]}, ["1", "2"]) == []


def test_crawl_menu_learns_field_templates(tmp_path):
    import subprocess, sys, textwrap
    prog = tmp_path / "fakemenu.py"
    prog.write_text(textwrap.dedent('''
        import sys
        def rd(): return sys.stdin.readline()
        while True:
            sys.stdout.write("1 - Add\\n2 - Modify\\n3 - Delete\\n4 - Exit\\nChoice: ")
            sys.stdout.flush()
            c = rd().strip()
            if c == "1":
                for p in ("Name: ", "Surname: ", "Age: ", "Note size: ", "Note: "):
                    sys.stdout.write(p); sys.stdout.flush(); rd()
                sys.stdout.write("added!\\n"); sys.stdout.flush()
            elif c == "2":
                sys.stdout.write("Author ID: "); sys.stdout.flush(); rd()
                sys.stdout.write("New name: "); sys.stdout.flush(); rd()
                sys.stdout.write("done\\n"); sys.stdout.flush()
            elif c == "3":
                sys.stdout.write("Author ID: "); sys.stdout.flush(); rd()
                sys.stdout.write("deleted\\n"); sys.stdout.flush()
            else:
                sys.stdout.write("bye\\n"); sys.stdout.flush(); break
    '''))

    def spawn():
        return subprocess.Popen([sys.executable, str(prog)], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # generous idle/budget so the prompt-stall detection stays reliable under heavy CI load
    model = menu.crawl_menu(spawn, ["1", "2", "3", "4"], idle=0.3, per_option=8.0)
    assert model.get("1") == ["str", "str", "num", "num", "str"]   # Name,Surname,Age,size,Note
    assert model.get("2") == ["idx", "str"]                        # id, new name
    assert model.get("3") == ["idx"]                               # id
    assert "4" not in model                                        # exit reads nothing
