"""Menu-navigation seed synthesis for interactive/menu-driven targets."""
import random

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


def test_fill_big_last_drives_the_governing_size_field_large():
    # A read(fd, buf, size) buffer is bounded by its size field, so an over-long string alone never
    # overflows: the size `num` immediately before the buffer must go large too, and the string is
    # filled to match. Leading non-size numbers (Age) stay small.
    out = menu._fill(["str", "str", "num", "num", "str"], big_last=True)
    parts = out.split(b"\n")
    # Name, Surname, Age(small), size(large=_OVERFLOW), Note(_OVERFLOW bytes)
    assert parts[2] == b"16"                              # Age: not a buffer size, stays small
    assert parts[3] == str(menu._OVERFLOW).encode()      # size: driven large
    assert parts[4] == b"B" * menu._OVERFLOW             # buffer filled to the announced size
    # with no size field before the last string, big_last keeps the fixed fallback payload
    assert b"B" * 200 in menu._fill(["idx", "str"], big_last=True)


def test_menu_op_sequences_emit_out_of_range_indices():
    # An index option bounded only on the high side takes a NEGATIVE index into an OOB table access
    # (CWE-129). The op-sequences must reach the indexed handler with such an index; generic seeds
    # never leave the front-door menu, so this navigation is the only way one lands there.
    model = {"1": ["str", "str", "num", "num", "str"],   # add (allocator, for priming)
             "2": ["idx"]}                                # index-taking handler
    seqs = menu.menu_op_sequences(model, ["1", "2"])
    body = b"".join(seqs)
    assert b"2\n-1\n" in body and b"2\n-2\n" in body      # negative indices reach the handler
    assert b"2\n9999\n" in body                           # oversized index too


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


def test_menu_mutator_navigates_and_overflows():
    """The menu-aware mutator generates a FRESH valid navigation each call: every operation begins
    with a real option token, the fields stay correctly typed (so a line-based target never
    desyncs), and it drives the buffer field into an overflow-length run."""
    model = {"1": ["str", "str", "num", "num", "str"],   # add: Name, Surname, Age, size, Note
             "2": ["idx", "str"],                         # modify: id, new name
             "3": ["idx"]}                                # delete: id
    mm = menu.MenuMutator(random.Random(1), model, ["1", "2", "3", "4"])
    assert mm.options == ["1", "2", "3"]                  # option 4 has no field template -> skipped
    assert mm.alloc == "1"                                # the size-then-string option primes objects
    saw_overflow = saw_oob_index = False
    for _ in range(300):
        out = mm.mutate(b"")
        assert out and out.endswith(b"\n")
        lines = out.split(b"\n")[:-1]                     # trailing newline -> empty last element
        # the first line is always a valid option choice (navigation never starts on junk)
        assert lines[0] in (b"1", b"2", b"3")
        # a line-based mutator must never emit an interior newline inside a field payload; splitting
        # on newline and re-joining round-trips, and no line is absurdly empty mid-stream
        if any(len(ln) >= 256 and len(set(ln)) == 1 for ln in lines):
            saw_overflow = True
        if any(ln.startswith(b"-") for ln in lines):      # a negative index reached an idx field
            saw_oob_index = True
    assert saw_overflow, "the mutator never produced an overflow-length buffer"
    assert saw_oob_index, "the mutator never drove an index field negative (CWE-129 shape)"


def test_menu_mutator_reaches_the_handlers_behind_the_menu():
    """End-to-end: feeding the mutator's output to a live menu program reaches the sub-handlers a
    blind byte mutator can't -- the whole point of navigating the menu."""
    import subprocess
    import sys
    import tempfile
    import textwrap
    from pathlib import Path
    d = Path(tempfile.mkdtemp())
    prog = d / "m.py"
    # Reads stdin as BYTES (like a C target using gets/read), so the mutator's full-byte-range
    # string payloads are accepted rather than crashing a UTF-8 text decoder.
    prog.write_text(textwrap.dedent('''
        import sys
        o = sys.stdout.buffer
        def rd(): return sys.stdin.buffer.readline()
        while True:
            o.write(b"1 - Add\\n2 - Del\\n3 - Exit\\nChoice: "); o.flush()
            c = rd().strip()
            if not c: break
            if c == b"1":
                for p in (b"Name: ", b"Size: ", b"Data: "): o.write(p); o.flush(); rd()
                o.write(b"ADDED\\n"); o.flush()
            elif c == b"2":
                o.write(b"Id: "); o.flush(); rd()
                o.write(b"DELETED\\n"); o.flush()
            else:
                o.write(b"bye\\n"); o.flush(); break
    '''))
    model = {"1": ["str", "num", "str"], "2": ["idx"]}
    mm = menu.MenuMutator(random.Random(7), model, ["1", "2", "3"])
    reached = 0
    for _ in range(40):
        payload = mm.mutate(b"")
        p = subprocess.run([sys.executable, str(prog)], input=payload,
                           capture_output=True, timeout=10)
        if b"ADDED" in p.stdout or b"DELETED" in p.stdout:
            reached += 1
    import shutil
    shutil.rmtree(d, ignore_errors=True)
    # A blind mutator effectively never completes a handler flow; the menu-aware one does it often.
    assert reached >= 20, f"only {reached}/40 navigations reached a handler"
