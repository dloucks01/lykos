"""Running a .NET assembly: the exception is the fault, and a NON-RUN must never read as clean.

A .NET assembly is a PE, so for as long as the dispatch asked only "is it a PE" it went to
WINE -- which cannot execute managed code without Wine Mono. Nothing ran, and the result came
back `crashed=False` with no note at all: a clean verdict on a target that was never executed,
on a host with a full .NET SDK installed. Most of this file pins down the three ways that
failure could come back, because each one was found by reproducing it:

  * the wrong substrate (wine instead of the CLR),
  * the `dotnet` muxer refusing a file whose name does not end in `.dll`,
  * a HOST failure, which prints a managed stack trace with no "Unhandled exception." header
    and so parsed as "no fault" -- i.e. as a clean run.
"""
import json
import os
import pathlib
import shutil
import subprocess

import pytest
from lykos.analyze import dotnet
from lykos.analyze.dynamic import sandbox
from lykos.analyze.runtime_fault import managed_fault

# An index taken straight from the input with no bounds check of its own. The CLR checks it, so
# the defect arrives as IndexOutOfRangeException rather than a signal.
_PROGRAM = """using System;
using System.IO;
public static class Program {
    static readonly int[] Table = new int[8];
    static int Lookup(byte[] input) { return Table[input.Length >= 1 ? input[0] : 0]; }
    public static int Main(string[] args) {
        byte[] data;
        using (var si = Console.OpenStandardInput())
        using (var ms = new MemoryStream()) { si.CopyTo(ms); data = ms.ToArray(); }
        Console.WriteLine("read {0}", data.Length);
        Console.WriteLine("value {0}", Lookup(data));
        return 0;
    }
}
"""

# Compiled with the SDK's Roslyn directly rather than `dotnet build`. MSBuild drags in a NuGet
# restore and spawns node processes: it took five seconds idle and timed out after TEN MINUTES
# when the rest of the suite was loading the machine. csc alone takes under a second, needs no
# network, and produces the same assembly -- and the missing runtimeconfig.json is precisely
# what the sandbox synthesizes, so the leaner artifact exercises more of the path, not less.
_REFS = ("System.Runtime", "System.Console", "System.Private.CoreLib", "System.Runtime.Extensions")


def _compile_cs(src_dir, source, out_name):
    """Build `out_name` from C# source with the SDK's csc. Returns the path, or None."""
    exe = shutil.which("dotnet")
    if not exe:
        return None
    root = pathlib.Path(os.path.realpath(exe)).parent
    csc = sorted(root.glob("sdk/*/Roslyn/bincore/csc.dll"))
    fw = sorted(root.glob("shared/Microsoft.NETCore.App/*"))
    if not csc or not fw:
        return None
    src = src_dir / "Program.cs"
    src.write_text(source)
    out = src_dir / out_name
    cmd = [exe, str(csc[-1]), "-nologo", "-nostdlib", "-target:exe", f"-out:{out}"]
    cmd += [f"-r:{fw[-1] / (r + '.dll')}" for r in _REFS]
    cmd.append(str(src))
    try:
        done = subprocess.run(cmd, capture_output=True, timeout=240)
    except subprocess.TimeoutExpired:
        return None
    return out if done.returncode == 0 and out.exists() else None


@pytest.fixture(scope="module")
def assembly(tmp_path_factory):
    """A real .NET assembly, or a skip. Nothing here is worth asserting against a mock."""
    if not shutil.which("dotnet"):
        pytest.skip("no dotnet SDK")
    built = _compile_cs(tmp_path_factory.mktemp("netoob"), _PROGRAM, "oob.dll")
    if built is None:
        pytest.skip("the .NET SDK here could not compile a test assembly")
    return built


# ---- the exception taxonomy ---------------------------------------------------------------

def test_the_managed_index_fault_is_an_index_cwe_not_generic_memory_corruption():
    assert dotnet.cwe_for_exception("System.IndexOutOfRangeException") == ("CWE-129", "high")
    assert dotnet.cwe_for_exception("IndexOutOfRangeException") == ("CWE-129", "high")


def test_a_fully_qualified_name_resolves_the_same_as_a_bare_one():
    """The CLR prints `System.X`; a finding may carry either form."""
    for bare in ("NullReferenceException", "DivideByZeroException", "OverflowException"):
        assert dotnet.cwe_for_exception(bare) == dotnet.cwe_for_exception("System." + bare)


def test_an_unsafe_block_escaping_the_clr_is_real_memory_corruption():
    """The CLR bounds-checks what it owns. An `unsafe`/P-Invoke fault is handed to it, not
    prevented by it, so it is the one managed result that IS memory corruption."""
    for name in ("AccessViolationException", "SEHException"):
        cwe, sev = dotnet.cwe_for_exception(name)
        assert cwe == "CWE-119" and sev == "critical", name


def test_validating_input_by_throwing_is_not_ranked_as_memory_corruption():
    """A program that rejects bad input by throwing is doing the right thing. Uncaught it still
    kills the process, so it is not nothing -- but ranking it with a buffer overflow would bury
    the findings that matter."""
    for name in ("ArgumentException", "InvalidOperationException", "NotSupportedException"):
        cwe, sev = dotnet.cwe_for_exception(name)
        assert cwe == "CWE-248" and sev in ("low", "info"), name


def test_a_cancellation_is_not_a_defect():
    for name in ("OperationCanceledException", "TaskCanceledException"):
        assert dotnet.cwe_for_exception(name) is None, name


def test_an_unknown_exception_is_honest_rather_than_critical():
    cwe, sev = dotnet.cwe_for_exception("Acme.Widget.FrobFailedException")
    assert cwe == "CWE-248" and sev == "medium"


def test_the_runtime_aborting_outright_is_memory_corruption():
    assert dotnet.cwe_for_exception("CLR-FATAL-INTERNAL-CLR-ERROR") == ("CWE-119", "critical")


# ---- parsing the CLR's output -------------------------------------------------------------

_TRACE = (b"read 1\n"
          b"Unhandled exception. System.IndexOutOfRangeException: Index was outside the "
          b"bounds of the array.\n"
          b"   at Program.Lookup(Byte[] input) in /src/Program.cs:line 10\n"
          b"   at Program.Main(String[] args) in /src/Program.cs:line 22\n")


def test_an_unhandled_exception_is_read_as_a_crash():
    kind, detail, frames = sandbox.dotnet_exception(_TRACE, 134)
    assert kind == "IndexOutOfRangeException"
    assert "Index was outside" in detail
    assert ("Program.Lookup(Byte[] input)", "/src/Program.cs", 10) in frames


def test_a_formatted_exception_printed_by_a_program_that_exits_zero_is_not_a_crash():
    """`Console.Error.Write(ex)` is byte-identical to the real thing, so a target that echoes
    its input, or one that handles errors correctly and reports them, would otherwise crash on
    any mutation containing the words. The exit code is the only discriminator."""
    assert sandbox.dotnet_exception(_TRACE, 0)[0] is None


def test_the_deepest_application_frame_is_blamed_not_the_framework():
    """`Table[i]` throws inside the framework; blaming the top frame blames the runtime and
    merges every index bug in the assembly into one finding."""
    frames = [("System.ThrowHelper.ThrowIndexOutOfRangeException()", "", 0),
              ("Program.Lookup(Byte[] input)", "/src/Program.cs", 10)]
    assert sandbox.app_frame_clr(frames)[0] == "Program.Lookup(Byte[] input)"


def test_two_different_sites_in_one_assembly_get_different_ids():
    a = sandbox.clr_site([("Program.A()", "/src/P.cs", 10)])
    b = sandbox.clr_site([("Program.B()", "/src/P.cs", 44)])
    assert a and b and a != b


def test_a_site_without_a_pdb_still_gets_an_id_from_the_method():
    assert sandbox.clr_site([("Program.Lookup(Byte[] input)", "", 0)]) is not None


@pytest.mark.parametrize("err", [
    b"You must install or update .NET to run this application.\n",
    b"Failed to run as a self-contained app.\n  - The application was run as ...\n",
    b"A fatal error was encountered. The library 'libhostpolicy.so' was not found.\n",
    b"Could not execute because the specified command or file was not found.\n",
])
def test_a_host_that_cannot_start_the_assembly_reports_a_gap_not_a_crash(err):
    """A falsy kind WITH a reason: not a crash, and emphatically not a clean run."""
    kind, detail, _ = sandbox.dotnet_exception(err, 1)
    assert kind == "" and detail


def test_a_host_failure_with_no_unhandled_header_is_still_a_non_run():
    """This is the one that got through. The `dotnet` CLI failing prints a managed trace with
    NO "Unhandled exception." header, so keying only on that header returned "no fault" and
    the run was reported clean. Found by pointing HOME at a read-only directory."""
    err = (b"System.IO.IOException: Read-only file system : '/staged/.dotnet'\n"
           b"   at System.IO.FileSystem.CreateDirectory(String fullPath)\n"
           b"   at Microsoft.DotNet.Configurer.FirstTimeUseNoticeSentinel.Exists()\n")
    kind, detail, _ = sandbox.dotnet_exception(err, 1)
    assert kind == "", "a host failure must not read as a clean run"
    assert "before the program's entry point" in detail


def test_a_blown_stack_is_recursion_not_generic_corruption():
    """The CLR cannot THROW for a blown stack -- it aborts. Reporting it as the fatal-abort
    CWE-119 would overstate a recursion bug as memory corruption."""
    kind, _d, _f = sandbox.dotnet_exception(b"Stack overflow.\n   at Program.Recurse()\n", 134)
    assert kind == "StackOverflowException"
    assert managed_fault(kind, "dotnet")[0] == "CWE-674"


def test_clean_output_is_clean():
    assert sandbox.dotnet_exception(b"read 1\nvalue 0\n", 0)[0] is None
    assert sandbox.dotnet_exception(b"", 0)[0] is None


# ---- end to end, against the real runtime -------------------------------------------------

def test_a_dotnet_assembly_is_recognised_as_managed_before_it_is_recognised_as_a_pe(assembly):
    assert sandbox._is_dotnet(assembly)
    assert sandbox._is_pe(assembly), "it really is a PE -- which is why order matters"


def test_the_managed_fault_is_reproduced_through_the_sandbox(assembly):
    clean = sandbox.run(assembly, stdin=b"\x03", timeout=60.0)
    assert clean.isolation.endswith("clr") and not clean.crashed

    crash = sandbox.run(assembly, stdin=b"\xff", timeout=60.0)
    assert crash.crashed
    assert crash.signal_name == "IndexOutOfRangeException"
    assert crash.fault_pc is not None
    assert managed_fault(crash.signal_name, "dotnet") == ("CWE-129", "high", "the CLR")


def test_an_ingested_assembly_under_a_generated_name_still_runs(assembly, tmp_path):
    """The autopilot stages a target as `target.bin`. The `dotnet` muxer dispatches on the
    `.dll` EXTENSION and otherwise looks for a global tool called `dotnet-target.bin`, so
    without staging a .dll name EVERY execution was a non-run -- on a case that works.
    """
    staged = tmp_path / "target.bin"
    staged.write_bytes(assembly.read_bytes())
    r = sandbox.run(staged, stdin=b"\xff", timeout=60.0)
    assert r.crashed and r.signal_name == "IndexOutOfRangeException"


def test_a_single_file_assembly_gets_the_runtimeconfig_it_needs(assembly, tmp_path):
    """An ingested assembly never travels with its build output. Without a sibling
    runtimeconfig.json the host refuses to start it at all."""
    staged = tmp_path / "solo.dll"
    staged.write_bytes(assembly.read_bytes())
    assert not (tmp_path / "solo.runtimeconfig.json").exists()
    r = sandbox.run(staged, stdin=b"\xff", timeout=60.0)
    cfg = tmp_path / "solo.runtimeconfig.json"
    assert cfg.exists(), "the runtimeconfig the host asked for was not synthesized"
    assert json.loads(cfg.read_text())["runtimeOptions"]["framework"]["name"] \
        == "Microsoft.NETCore.App"
    assert r.crashed and r.signal_name == "IndexOutOfRangeException"


def test_the_batch_runner_refuses_a_managed_assembly(assembly):
    """The batch runner execs the target and traces it with ptrace. A managed assembly is not
    executable and the CLR is not the target."""
    assert sandbox.run_batch(assembly, [b"\xff"], host=sandbox.host_arch()) is None
