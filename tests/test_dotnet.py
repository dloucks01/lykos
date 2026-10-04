""".NET managed-PE front-end: a PE that is CIL bytecode, not native machine code.

A .NET assembly shares the PE container, so magic detection calls it `pe` and the native path would
disassemble its CIL as x86 (garbage). The front-end must recognise the managed truth via the CLI
header + BSJB metadata root, inventory the names/strings the format gives in the clear, and route
triage to the managed branch -- stopping the PoC ladder honestly at the CLR boundary.
"""
import glob
import os
import shutil
import subprocess

import pytest
from lykos.analyze import dotnet, filetype, triage

_PROGRAM = (
    "using System;\n"
    "class HelloLykos {\n"
    "  static int Secret(string token) { return token.Length * 7; }\n"
    "  static void Main(string[] args) {\n"
    '    Console.WriteLine("lykos-dotnet-marker");\n'
    "    Console.WriteLine(Secret(\"abc\"));\n"
    "  }\n"
    "}\n")


def _csc_and_refs():
    """(csc.dll, [ref assemblies]) from an installed .NET SDK, or (None, []) -- lets the test build a
    managed assembly with no NuGet/network (direct Roslyn against the shipped reference assemblies)."""
    cscs = glob.glob("/usr/share/dotnet/sdk/*/Roslyn/bincore/csc.dll") + \
        glob.glob("/usr/lib/dotnet/sdk/*/Roslyn/bincore/csc.dll")
    refdirs = glob.glob("/usr/share/dotnet/packs/Microsoft.NETCore.App.Ref/*/ref/net*/") + \
        glob.glob("/usr/lib/dotnet/packs/Microsoft.NETCore.App.Ref/*/ref/net*/")
    if not cscs or not refdirs:
        return None, []
    refdir = sorted(refdirs)[-1]
    want = ["System.Runtime.dll", "System.Console.dll", "System.Private.CoreLib.dll"]
    refs = [os.path.join(refdir, w) for w in want if os.path.exists(os.path.join(refdir, w))]
    return sorted(cscs)[-1], refs


_SECRET_PROGRAM = (
    "using System;\n"
    "class Svc {\n"
    '  const string ApiPassword = "password=SuperSecretP@ss123";\n'
    '  const string AwsKey = "AKIAIOSFODNN7EXAMPLE";\n'
    "  static void Main() { Console.WriteLine(ApiPassword.Length + AwsKey.Length); }\n"
    "}\n")


def _compile(tmp_path_factory, name, source, outname):
    dotnet_bin = shutil.which("dotnet")
    csc, refs = _csc_and_refs()
    if not (dotnet_bin and csc and refs):
        pytest.skip("no .NET SDK (csc + reference assemblies) to build a managed assembly")
    d = tmp_path_factory.mktemp(name)
    (d / "src.cs").write_text(source)
    out = d / outname
    cmd = [dotnet_bin, csc, "-nologo", "-target:library", f"-out:{out}"]
    cmd += [f"-reference:{r}" for r in refs] + [str(d / "src.cs")]
    if subprocess.run(cmd, capture_output=True).returncode or not out.exists():
        pytest.skip("could not compile the managed assembly with Roslyn")
    return out


@pytest.fixture(scope="module")
def dotnet_dll(tmp_path_factory):
    return _compile(tmp_path_factory, "dotnet", _PROGRAM, "hello.dll")


@pytest.fixture(scope="module")
def dotnet_secret_dll(tmp_path_factory):
    return _compile(tmp_path_factory, "dotnet_secret", _SECRET_PROGRAM, "svc.dll")


def test_is_dotnet_detects_managed_and_rejects_native(dotnet_dll):
    assert dotnet.is_dotnet(dotnet_dll.read_bytes()) is True
    assert dotnet.is_dotnet(b"\x7fELF" + b"\0" * 200) is False      # native ELF
    with open("/bin/ls", "rb") as fh:
        assert dotnet.is_dotnet(fh.read()) is False                 # real native ELF
    assert dotnet.is_dotnet(b"MZ" + b"\0" * 8) is False             # truncated PE, no CLI dir


def test_parse_extracts_names_strings_and_counts(dotnet_dll):
    info = dotnet.parse(dotnet_dll.read_bytes())
    assert info.is_dotnet and not info.errors
    assert info.clr_version and info.clr_version.startswith("v")
    assert bool(info.runtime_flags & 0x1)                           # IL-only
    assert info.type_count >= 1 and info.method_count >= 2
    assert {"#~", "#Strings", "#US"} <= set(info.streams)
    # names and literals are in the clear, like a JVM constant pool
    assert {"HelloLykos", "Secret", "Main"} <= set(info.names)
    assert "lykos-dotnet-marker" in info.user_strings


def test_triage_routes_managed_pe_to_dotnet_not_native(dotnet_dll):
    rec = triage.build_triage(str(dotnet_dll), {"sha256": "x"}, "hello.dll")
    assert rec["file_type"] == filetype.DOTNET, "managed PE was not routed to the .NET branch"
    assert rec["arch"] == "cil", "a .NET assembly must not be analysed as native x86"
    assert rec["analyzable"] is True
    assert triage.validate(rec) == [], "triage record failed schema validation"
    assert rec["format_details"]["format"] == "dotnet"
    assert "HelloLykos" in rec["exports"]["symbols"]
    # the advisory must state the honest ladder stop (no native IP to hijack under the CLR)
    assert "CLR" in (rec["advisory"] or "") and "L2/L3" in (rec["advisory"] or "")


def test_metadata_strings_feed_the_string_detectors(dotnet_secret_dll):
    """The advisory claims the string-based detectors work on a .NET target -- prove it: a hardcoded
    password and an AWS key in the #US heap must both be found (CWE-798), so the claim is true, not
    aspirational. This is the same substrate-independent detector set the JVM path reuses."""
    from lykos.analyze import dotnet as dotnetmod
    from lykos.analyze import invocation as inv
    from lykos.analyze.detect import detectors as D
    from lykos.analyze.detect.stage import DetectContext
    info = dotnetmod.parse(dotnet_secret_dll.read_bytes())
    rows = (inv.string_rows(info.user_strings, where="#US")
            + inv.string_rows(info.names, where="#Strings"))
    dctx = DetectContext(target_id="t", case_id="c", call_edges=[], strings=rows,
                         functions=[], mitigations={}, frames={})
    cwes = set()
    for det in D.DETECTORS:
        if getattr(det, "jvm_safe", False):
            for c in det(dctx):
                cwes.add(c.get("cwe"))
    assert "CWE-798" in cwes, f"hardcoded-credential detector did not fire on .NET metadata: {cwes}"
