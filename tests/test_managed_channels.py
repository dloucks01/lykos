"""Which stream does a MANAGED target read? Ranked from its metadata, not from call edges.

`modes_for` ranks the input channels from the functions a binary imports, which is the right
question -- "default to stdin" is a coin flip that loses on most real targets. But it asks that
question of the CALL EDGES, and a managed target owns no machine code: `disassemble` recovers
no functions and writes no edges for a jar, a .pyc or a .NET assembly. So the name sets matched
nothing and `arg` came first for every one of them.

That is not a wrong answer -- the autopilot retries the other channels and does find the bug --
it is a WASTED one. A .NET assembly runs at 8 exec/s, so the campaign spent ~364 executions,
about 45 seconds of its budget, fuzzing a channel the program never reads before trying the one
it does.

The names were never missing: triage reads them out of the metadata heaps, the constant pool or
the code object and records them. They are not libc symbols, so they need their own vocabulary
-- and the vocabulary has to be careful, which is most of what this file pins down. `ReadLine`
is `Console.ReadLine` on stdin and `StreamReader.ReadLine` on a file, so a read method on its
own must decide nothing.
"""
import pytest
from lykos.analyze.poc.capture import _managed_channels, modes_for

# Real symbol lists, as triage recorded them from assemblies built for this.
_DOTNET_CONSOLE = ["Int32", "<Module>", "System.IO", "System.Private.CoreLib", "System.Console",
                   "ReadLine", "WriteLine", "String", "get_Length", "Program", "System",
                   "get_In", "Main", "TextReader", ".ctor", "Object"]
_DOTNET_STDIN_STREAM = ["System.Console", "OpenStandardInput", "MemoryStream", "CopyTo",
                        "WriteLine", "Main", "ToArray", "Program"]
_PYC_STDIN = ["sys", "stdin", "readline", "s", "t", "print", "len"]


def test_a_dotnet_console_reader_ranks_stdin_first():
    assert modes_for([], symbols=_DOTNET_CONSOLE)[0] == "stdin"


def test_a_dotnet_assembly_reading_the_standard_input_stream_ranks_stdin_first():
    assert modes_for([], symbols=_DOTNET_STDIN_STREAM)[0] == "stdin"


def test_a_dotnet_file_reader_ranks_file_first():
    """`File`/`ReadAllBytes` is unambiguous: those exist to touch the filesystem."""
    syms = ["System.IO", "File", "ReadAllBytes", "System.Console", "WriteLine", "Main"]
    assert modes_for([], symbols=syms)[0] == "file"


def test_a_dotnet_assembly_that_only_WRITES_to_the_console_claims_no_input_channel():
    """`System.Console` + `WriteLine` is output. Treating the Console type alone as a stdin
    signal would rank stdin first for every console app that prints and reads nothing."""
    has_stdin, has_file, _ = _managed_channels(["System.Console", "WriteLine", "Main"])
    assert not has_stdin and not has_file


def test_the_namespace_alone_is_not_a_file_signal():
    """`System.IO` appears in an assembly that only ever touches `Console.In` -- TextReader
    lives there. So does MemoryStream. Neither means the program opens a file."""
    has_stdin, has_file, _ = _managed_channels(["System.IO", "TextReader", "MemoryStream",
                                                "System.Console", "ReadLine"])
    assert has_stdin and not has_file


def test_a_read_method_without_its_type_decides_nothing():
    """The ambiguity this vocabulary exists to respect: bare `ReadLine` could be either."""
    has_stdin, has_file, _ = _managed_channels(["ReadLine", "ReadToEnd", "Main"])
    assert not has_stdin and not has_file


def test_cpython_bytecode_naming_stdin_ranks_stdin_first():
    assert modes_for([], symbols=_PYC_STDIN)[0] == "stdin"


@pytest.mark.parametrize("syms,first", [
    (["input", "print"], "stdin"),                      # Python input() reads a line
    (["Scanner", "nextLine", "println"], "stdin"),      # Java Scanner over a stream
    (["System.in", "read"], "stdin"),                   # Java System.in field ref
    (["open", "read", "close"], "file"),                # Python open()
    (["FileInputStream", "read"], "file"),              # Java file stream
])
def test_the_unambiguous_markers_across_runtimes(syms, first):
    assert modes_for([], symbols=syms)[0] == first


def test_every_channel_is_still_attempted_whatever_the_ranking():
    """The contract the autopilot relies on: ranking reorders, it never drops a channel, so a
    wrong guess costs time and never costs the finding."""
    for syms in ([], _DOTNET_CONSOLE, _PYC_STDIN, ["File", "ReadAllText"]):
        assert sorted(modes_for([], symbols=syms)) == ["arg", "file", "stdin"]


def test_a_native_target_is_completely_unaffected():
    """The managed signals are unioned in, never substituted: passing no symbols must give
    exactly the previous answer, and a native target passes none."""
    class E:
        def __init__(s, n):
            s.dst_name = n
    assert modes_for([E("fgets"), E("printf")])[0] == "stdin"
    assert modes_for([E("fopen"), E("fread")])[0] == "file"
    assert modes_for([E("scanf"), E("fopen")])[0] == "stdin"      # interactive breaks the tie
    assert modes_for([E("printf")])[0] == "arg"
    # and the same calls plus a managed inventory still lead with the native verdict
    assert modes_for([E("fopen"), E("fread")], symbols=["File", "ReadAllBytes"])[0] == "file"


def test_an_explicit_mode_still_overrides_everything():
    assert modes_for([], given="file", symbols=_DOTNET_CONSOLE) == ["file"]


def test_a_native_targets_import_table_ranks_its_channels_without_disassembly():
    """Reading only call edges made the ranking depend on `disassemble` having produced them.

    Measured on the HTB target quack_quack, whose `disassemble` returned in 0.6 s under the
    per-target budget: the edge set was empty, so no channel had any evidence, the no-evidence
    fallback (`arg`) was taken -- correct for a binary that genuinely reads nothing, wrong here
    -- and the concolic stage solved against argv for a program whose input is `read(0, ...)`.
    90,872 executions and a 300 s solver slice could not reach a defect that is one stdin write
    away. Triage parsed that import table at ingest, long before any disassembly.
    """
    assert modes_for([], symbols=["read", "printf", "alarm"], file_type="elf")[0] == "stdin"
    assert modes_for([], symbols=["fopen", "fread", "malloc"], file_type="elf")[0] == "file"
    # a binary that imports no input function at all still falls through to argv
    assert modes_for([], symbols=["printf", "malloc"], file_type="elf")[0] == "arg"


def test_a_managed_inventory_is_not_read_with_the_C_vocabulary():
    """The same spellings mean different things on a runtime: Python's `open`/`read` are a file
    object's methods, not `open(2)` and `read(2)` on fd 0. Unioning them into the native
    vocabulary turned a Python file reader into an interactive stdin target."""
    assert modes_for([], symbols=["open", "read", "close"])[0] == "file"
    assert modes_for([], symbols=["FileInputStream", "read"])[0] == "file"
