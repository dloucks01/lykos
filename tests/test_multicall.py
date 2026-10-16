"""A multi-call binary is many programs, and fuzzing the image fuzzes only the dispatcher.

`busybox` is one 1 MB static ELF holding 345 programs, selected by the first positional
argument. It is also the most common binary in the firmware this tool carves, and until these
tests existed the pipeline treated it as one target: `busybox` with no function prints its usage
and exits, so the campaign executed it thousands of times, entered no parser, and reported a
clean run. busybox 1.21.1 -- the build measured here -- has a published out-of-bounds read in
its unlzma decompressor (CVE-2021-42374, fixed in 1.34.0) and a use-after-free in awk
(CVE-2021-42378), and both live behind that dispatch.

`invocation.from_subcommands` could not see it, for reasons of SHAPE rather than of busybox: its
hint wants `usage: tool <command>` where busybox writes `Usage: busybox [function
[arguments]...]`, and its row parser wants one command per line with a description where a
multi-call binary prints a wrapped, comma-separated block of bare names.
"""
import re

from lykos.analyze import invocation as inv

# The real help text of busybox 1.21.1 (trimmed), as the stage's `_help_text` collects it.
_BB_HELP = """BusyBox v1.21.1 (2013-07-08 11:34:59 CDT) multi-call binary.
BusyBox is copyrighted by many authors between 1998-2012.

Usage: busybox [function [arguments]...]
   or: busybox --list[-full]
   or: busybox --install [-s] [DIR]
   or: function [arguments]...

Currently defined functions:
\t[, [[, acpid, addgroup, adduser, ar, arp, awk, base64, basename, bunzip2,
\tbzcat, bzip2, cat, cpio, dd, devmem, gunzip, gzip, hexdump, httpd, ifconfig,
\tmkfs.vfat, od, passwd, patch, reboot, rm, sed, tar, unlzma, unxz, unzip, wc
"""

_NOT_MULTICALL = """usage: tiffcp [options] input... output

  -c            compression scheme
  -r            rows per strip
"""


def test_the_programs_are_read_out_of_the_wrapped_block():
    names = inv.multicall_names(_BB_HELP)
    assert "unlzma" in names and "awk" in names and "tar" in names
    # `[` and `[[` are the test builtin and not names a campaign can invoke
    assert "[" not in names and "[[" not in names
    # the header block ends where it ends: nothing from the prose above it
    assert "busybox" not in names and "copyrighted" not in names


def test_a_tool_that_is_not_multi_call_yields_nothing():
    """The hint has to be specific or every program with a usage line becomes 'many programs'."""
    assert inv.multicall_names(_NOT_MULTICALL) == []
    assert inv.multicall_list_flag(_NOT_MULTICALL) is None


def test_the_listing_flag_is_taken_from_the_binary_not_invented():
    assert inv.multicall_list_flag(_BB_HELP) == "--list"
    # and the binary's own listing is used in preference to the wrapped block
    names = inv.multicall_names(_BB_HELP, list_output="unlzma\nunxz\ntar\nawk\n")
    assert names == ["unlzma", "unxz", "tar", "awk"]


def test_only_single_input_parsers_are_invoked():
    """An ALLOW-list, because a deny-list has to be complete to be safe.

    Among the 345 programs are `reboot`, `mkfs.vfat`, `devmem` (physical memory), `passwd`, `nc`
    and the whole of service supervision. The sandbox bounds memory, the filesystem view and the
    process tree; it does not change what those MEAN, and one name nobody thought of is a
    campaign firing `mkfs.vfat` with a mutated argv.
    """
    allowed = inv.rank_multicall(inv.multicall_names(_BB_HELP))
    for forbidden in ("reboot", "rm", "mkfs.vfat", "devmem", "passwd", "ifconfig", "httpd",
                      "dd", "adduser", "addgroup", "arp"):
        assert forbidden not in allowed, forbidden
    for parser in ("unlzma", "unxz", "bunzip2", "tar", "cpio", "awk", "sed", "od", "hexdump"):
        assert parser in allowed, parser


def test_the_deepest_parser_is_ranked_first():
    """A budget buys a handful of doors out of 345, so the ORDER decides what is searched."""
    allowed = inv.rank_multicall(inv.multicall_names(_BB_HELP))
    assert allowed[0] in ("bunzip2", "bzcat", "bzip2", "gunzip", "gzip", "unlzma", "unxz",
                          "unzip"), allowed[:4]
    # an archive reader outranks a text filter, which outranks a hash/dumper
    assert allowed.index("tar") < allowed.index("sed") < allowed.index("wc")


class _Fake:
    """A runner that accepts the shapes a real utility box accepts, and refuses the rest."""
    def __init__(self, accept):
        self.accept, self.calls = accept, []

    def __call__(self, argv, stdin):
        self.calls.append(list(argv))
        ok = tuple(argv) in self.accept
        out = b"" if ok else b"Usage: busybox tar -[cxtvO]\n"
        return type("R", (), {"stdout": out, "stderr": b""})()


def test_a_door_is_verified_by_running_it_not_proposed():
    """`tar` with the input on stdin prints its usage; `unlzma` reads it. Nothing in a name says
    which, so each candidate costs one execution against the target's own behaviour."""
    run = _Fake({("unlzma",), ("tar", "-t", inv.INPUT_PLACEHOLDER)})
    doors = inv.multicall_doors(run, ["unlzma", "tar", "awk"])
    assert doors == [("unlzma", ["unlzma"]),
                     ("tar", ["tar", "-t", inv.INPUT_PLACEHOLDER])]
    # awk refused every shape and is DROPPED rather than fuzzed through a door that never opened
    assert "awk" not in [n for n, _ in doors]


def test_a_compressor_is_driven_in_the_decompressing_direction():
    """Both directions accept the input and neither prints a usage line, so the probe cannot
    tell them apart -- and `gzip` compresses our mutated bytes (a writer) while `gzip -d` runs
    the parser that reads attacker-controlled structure."""
    run = _Fake({("gzip",), ("gzip", "-d")})
    doors = inv.multicall_doors(run, ["gzip"])
    assert doors == [("gzip", ["gzip", "-d"])]
    assert run.calls[0] == ["gzip", "-d"], "the -d shape is tried FIRST for a compressor"


def test_the_probe_is_bounded():
    """345 candidates x 6 shapes is not a budget anyone would spend on finding a door."""
    run = _Fake(set())
    inv.multicall_doors(run, [f"prog{i}" for i in range(50)], cap=3)
    assert len(run.calls) <= 50 * len(inv._MULTICALL_SHAPES)
    run2 = _Fake({(f"prog{i}",) for i in range(50)})
    doors = inv.multicall_doors(run2, [f"prog{i}" for i in range(50)], cap=3)
    assert len(doors) == 3


def test_an_archive_that_merely_fails_to_parse_is_still_an_open_door():
    """busybox exits 1 both for 'usage' and for 'that is not a valid archive'. The second is a
    parser that RAN, which is exactly what a door is -- so the refusal test reads the output."""
    assert inv._REFUSED.search("Usage: busybox tar -[cxtvO]")
    assert inv._REFUSED.search("tar: applet not found")
    assert not inv._REFUSED.search("tar: short read: Unexpected EOF")
    assert not inv._REFUSED.search("unlzma: corrupted data")
    assert not re.search(r"usage", "unlzma: corrupted data", re.I)


def test_the_target_makes_its_own_seed():
    """A decompressor rejects random bytes at its header, and the image holding `unlzma` also
    holds `lzma` -- so the valid archive this campaign needs is one execution away, and nothing
    here has to know the LZMA format."""
    assert inv.multicall_inverse("unlzma") == "lzma"
    assert inv.multicall_inverse("bzcat") == "bzip2"
    assert inv.multicall_inverse("awk") is None

    class _Z:
        def __call__(self, argv, stdin):
            out = b"\x5d\x00\x00\x80\x00" + stdin[::-1] if argv == ["lzma"] else b""
            return type("R", (), {"stdout": out, "stderr": b""})()

    seed = inv.multicall_seed(_Z(), "unlzma", text=b"abc")
    assert seed.startswith(b"\x5d\x00\x00\x80\x00")
    assert inv.multicall_seed(_Z(), "awk") == b""

    class _Echo:                                        # a program that hands the text back
        def __call__(self, argv, stdin):
            return type("R", (), {"stdout": stdin, "stderr": b""})()

    assert inv.multicall_seed(_Echo(), "unlzma", text=b"abc") == b"", \
        "output identical to the input is not a compressed seed"


def test_help_text_is_not_mistaken_for_a_seed():
    """A multi-call binary answers an unknown function with its own help, and `multicall_seed`
    asks for a function that may not exist (`lzma` beside `unlzma`). Help text makes a terrible
    seed: it passes no header check and it displaces the generic seeds it was ranked in front
    of."""
    class _Help:
        def __call__(self, argv, stdin):
            return type("R", (), {"stdout": b"Usage: fakebox [function [arguments]...]\n",
                                  "stderr": b""})()

    assert inv.multicall_seed(_Help(), "unlzma") == b""


def test_the_autopilot_takes_more_than_one_door():
    """busybox opens 14 doors and a campaign through one of them is a campaign through 1/14th of
    the target. The breadth pass is the `libfuzzer` second pass again, one substrate over -- and
    there is no build to repeat here, so it costs only fuzzing time.

    Asserted on the schedule rather than on a 900-second run: this is the kind of wiring that
    gets deleted by a refactor and noticed by nobody, which is exactly what
    `test_gates_are_wired` exists to say about lint.
    """
    import inspect

    from lykos.analyze import orchestrate
    src = inspect.getsource(orchestrate._run_autopilot_stages) \
        if hasattr(orchestrate, "_run_autopilot_stages") else inspect.getsource(orchestrate)
    assert "fuzz.multicall" in src and "multicall_door" in src, \
        "the autopilot no longer schedules the remaining doors of a multi-call binary"
    assert orchestrate._MORE_MULTICALL_DOORS >= 1


def test_the_door_reports_the_channel_it_was_verified_on(tmp_path):
    """A decompressor handed its input as an argv string sees a filename that does not exist, on
    every execution -- so the campaign delivers on the channel the door was SHOWN to read, not
    on the one ranked from the whole image's imports (345 programs' worth of imports)."""
    from lykos.analyze import invocation as invmod
    from lykos.analyze.fuzz import stage

    class _Ctx:
        params: dict = {}
        emitted: list = []

        def emit(self, kind, payload=None):
            self.emitted.append((kind, payload or {}))

    def probe(argv, stdin=b""):
        argv = [str(a) for a in argv]
        if argv == ["--list"]:
            return type("R", (), {"stdout": b"unlzma\nreboot\ntar\n", "stderr": b""})()
        if argv == ["unlzma"] or argv[:2] == ["tar", "-t"]:
            return type("R", (), {"stdout": b"", "stderr": b""})()
        return type("R", (), {"stdout": b"Usage: fakebox [function ...]\n", "stderr": b""})()

    help_text = ("FAKEBOX v1.0 multi-call binary.\n\nUsage: fakebox [function [arguments]...]\n"
                 "   or: fakebox --list\n")
    argv, note, door = stage._multicall_argv(_Ctx(), invmod, help_text, probe, tmp_path)
    assert argv == ["unlzma"] and door["door"] == "unlzma"
    assert door["verified_on"] == "stdin"
    assert "multi-call" in note

    # the same target, asked for the door the orchestrator's second pass wants
    class _Want(_Ctx):
        params = {"multicall_door": "tar"}

    argv2, _, door2 = stage._multicall_argv(_Want(), invmod, help_text, probe, tmp_path)
    assert argv2 == ["tar", "-t", invmod.INPUT_PLACEHOLDER]
    assert door2["verified_on"] == "file", "a door with @@ is delivered as a FILE"


def test_the_dispatcher_is_found_when_the_scored_help_text_is_empty(tmp_path):
    """The measured miss: busybox produced NO help text for the stage to read.

    `_help_text` tries [], --help, -h, help, --usage and keeps whichever output carries the most
    OPTION rows (`-x  description`) or command rows. busybox 1.21.1 has neither -- its flags are
    per-applet and its 345 programs print as a wrapped comma-separated block whose first entry
    is `[` -- so the scorer never beat its threshold and returned None. The multi-call path then
    had nothing to look at, and the first real run of this feature against the real binary found
    no doors at all. So the bare invocation's own banner is asked directly.
    """
    from lykos.analyze import invocation as invmod
    from lykos.analyze.fuzz import stage

    class _Ctx:
        params: dict = {}

        def emit(self, kind, payload=None):
            pass

    banner = (b"BusyBox v1.21.1 (2013-07-08 11:34:59 CDT) multi-call binary.\n\n"
              b"Usage: busybox [function [arguments]...]\n   or: busybox --list\n")

    calls = []

    def probe(argv, stdin=b""):
        argv = [str(a) for a in argv]
        calls.append(argv)
        if argv == []:
            return type("R", (), {"stdout": banner, "stderr": b""})()
        if argv == ["--list"]:
            return type("R", (), {"stdout": b"unlzma\ntar\n", "stderr": b""})()
        if argv == ["unlzma"]:
            return type("R", (), {"stdout": b"", "stderr": b""})()
        return type("R", (), {"stdout": b"Usage: busybox [function ...]\n", "stderr": b""})()

    argv, note, door = stage._multicall_argv(_Ctx(), invmod, None, probe, tmp_path)
    assert argv == ["unlzma"], f"the dispatcher was missed; probes were {calls[:3]}"
    assert door["door"] == "unlzma"
    assert calls[0] == [], "the bare invocation is what a multi-call binary answers"

    # A program that is NOT one costs exactly one probe and then gets out of the way.
    calls.clear()

    def plain(argv, stdin=b""):
        calls.append([str(a) for a in argv])
        return type("R", (), {"stdout": b"usage: tiffcp [options] input... output\n",
                              "stderr": b""})()

    assert stage._multicall_argv(_Ctx(), invmod, None, plain, tmp_path) == (None, None, {})
    assert len(calls) == 1


def test_doors_into_the_same_decoder_count_once():
    """`bunzip2`, `bzcat` and `bzip2 -d` are one decoder reached three ways.

    Measured on busybox 1.21.1: the eight verified doors were bunzip2, bzcat, bzip2, gunzip,
    gzip, lzcat, lzma, lzop -- so the first five the autopilot takes covered TWO decoders, and
    `unlzma`, the one busybox's own CVE list names, was never reached. Deduplicating by family
    makes the same five cover bzip2, gzip, lzma, lzop and xz.
    """
    names = ["bunzip2", "bzcat", "bzip2", "gunzip", "gzip", "zcat", "lzcat", "unlzma", "lzma",
             "unxz", "xzcat", "tar", "cpio"]
    run = _Fake({(n,) for n in names} | {("bzip2", "-d"), ("gzip", "-d"), ("lzma", "-d"),
                                         ("tar", "-t", inv.INPUT_PLACEHOLDER)})
    doors = [n for n, _ in inv.multicall_doors(run, names, cap=6)]
    assert len(set(inv.codec_family(n) for n in doors)) == len(doors), doors
    assert inv.codec_family("bzcat") == inv.codec_family("bunzip2") == "bzip2"
    assert "lzma" in {inv.codec_family(n) for n in doors}, doors
    # and a program with no family twin is its own family
    assert inv.codec_family("awk") == "awk"
