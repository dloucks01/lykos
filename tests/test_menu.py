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
    assert menu._is_alloc(["num"])                     # size-only malloc(size) menu
    assert menu._is_alloc(["num", "num"])              # size-only (two numbers)


def test_menu_op_sequences_from_model_types_fields_and_overflows():
    model = {"1": ["str", "str", "num", "num", "str"],   # add
             "2": ["idx", "str"],                         # modify
             "3": ["idx"]}                                # delete
    seqs = menu.menu_op_sequences(model, ["1", "2", "3"])
    assert seqs
    # the allocating option primes with typed values: Name/Surname strings, Age/size numbers, and
    # the Note string sized to match the preceding size field (16 bytes, so a read(size) allocator
    # gets exactly what it asked for)
    assert any(s.startswith(b"1\nAAAA\nAAAA\n16\n16\n" + b"A" * 16 + b"\n") for s in seqs)
    # an over-long payload (overflow shape) reaches a non-alloc option
    assert any(b"B" * 200 in s for s in seqs)
    # delete driven twice on the same id (double-free shape)
    assert any(s.rstrip(b"\n").endswith(b"3\n1\n3\n1") or b"3\n1\n3\n1\n" in s for s in seqs)


def test_menu_op_sequences_empty_without_allocator():
    # only index/print options, nothing that allocates -> no sequences
    assert menu.menu_op_sequences({"1": ["idx"], "2": ["idx"]}, ["1", "2"]) == []


def test_crawl_menu_learns_field_templates(tmp_path):
    import subprocess
    import sys
    import textwrap
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


# --------------------------------------------------- fixed-width read(fd,buf,W) protocols ----

def test_fill_fixed_width_pads_scalars_and_raw_data():
    # line mode (default): newline-delimited
    assert menu._fill(["num", "str"], num=b"16", width=None) == b"16\n" + b"A" * 16 + b"\n"
    # fixed-width W=4: each scalar padded to 4 bytes, data sent raw (its read consumed exactly size)
    assert menu._fill(["num", "str"], num=b"16", width=4) == b"16  " + b"A" * 16
    assert menu._fill(["idx"], idx=b"0", width=4) == b"0   "


def test_menu_op_sequences_fixed_width_has_no_newlines():
    model = {"1": ["num", "str"], "2": ["idx"]}          # alloc, delete
    seqs = menu.menu_op_sequences(model, ["1", "2"], width=4)
    assert seqs and all(b"\n" not in s for s in seqs)     # fixed-width: newline-free
    # the allocating option: choice "1" padded, size "16" padded, then 16 data bytes
    assert any(s.startswith(b"1   16  " + b"A" * 16) for s in seqs)
    # delete driven twice on the same id (double-free shape), each field 4-wide
    assert any(b"2   0   2   0   " in s for s in seqs)


def test_crawl_menu_learns_fixed_width_protocol(tmp_path):
    import subprocess
    import sys
    import textwrap
    # a menu that reads every scalar as read(0, buf, 4) and data as read(0, buf, size)
    prog = tmp_path / "fw.py"
    prog.write_text(textwrap.dedent('''
        import os, sys
        def rd4():
            b = os.read(0, 4)
            if not b: sys.exit(0)
            return int(b.decode("latin1").strip() or "0")
        while True:
            sys.stdout.write("1) alloc\\n2) delete\\n> "); sys.stdout.flush()
            op = rd4()
            if op == 1:
                sys.stdout.write("size> "); sys.stdout.flush(); sz = rd4()
                sys.stdout.write("data> "); sys.stdout.flush(); os.read(0, sz if sz>0 else 8)
                sys.stdout.write("ok\\n"); sys.stdout.flush()
            elif op == 2:
                sys.stdout.write("idx> "); sys.stdout.flush(); rd4()
                sys.stdout.write("del\\n"); sys.stdout.flush()
            else:
                break
    '''))

    def spawn():
        return subprocess.Popen([sys.executable, str(prog)], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    model = menu.crawl_menu(spawn, ["1", "2"], idle=0.3, per_option=8.0, width=4)
    assert model.get("1") == ["num", "str"]              # size, data
    assert model.get("2") == ["idx"]                     # index
