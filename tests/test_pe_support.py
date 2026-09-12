"""Windows PE support: what the platform can say and do about a Windows binary.

Found by walking the GUI with a real PE -- jhead built with mingw, the same program and the
same CWE-125 as the ELF target, through an entirely different substrate. Every stage reported
"done" and most had done nothing, which is the failure mode this suite exists to pin down.
"""
import shutil
import subprocess

import pytest
from lykos.analyze import pe
from lykos.analyze.dynamic import sandbox


def _build_pe(tmp_path):
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if not cc:
        pytest.skip("no mingw cross compiler")
    src = tmp_path / "t.c"
    src.write_text('#include <stdio.h>\n#include <string.h>\n'
                   'int main(int c,char**v){char b[32];FILE*f=fopen(v[1],"rb");'
                   'if(f){fread(b,1,8,f);fclose(f);}strcpy(b,v[1]);return (int)strlen(b);}\n')
    out = tmp_path / "t.exe"
    if subprocess.run([cc, "-O0", "-w", str(src), "-o", str(out)],
                      capture_output=True, timeout=180).returncode != 0:
        pytest.skip("mingw cannot link here")
    return out


def test_a_wine_page_fault_is_a_crash():
    """Wine has two formats for reporting a guest crash and we matched only one. The commonest
    crash there is -- an access violation -- uses the other, so EVERY PE crash read as a clean
    exit: no crash row, no root cause, no PoC. The whole ladder was unreachable on Windows.

    This is the exact line wine emitted for the committed jhead crasher."""
    real = (b"wine: Unhandled page fault on read access to 00007FFFFF8A0C77 at address "
            b"000000014000547D (thread 0024), starting debugger...")
    code, name, detail = sandbox.wine_exception(real)
    assert code == "c0000005" and name == "EXCEPTION_ACCESS_VIOLATION"
    assert "read access" in detail and "0x000000014000547D" in detail
    # the other format still works
    code, name, _ = sandbox.wine_exception(b"err:seh: Unhandled exception code c00000fd")
    assert (code, name) == ("c00000fd", "EXCEPTION_STACK_OVERFLOW")
    # and a clean run is still clean
    assert sandbox.wine_exception(b"fixme:dbghelp:elf_search_auxv") == (None, None, None)
    assert sandbox.wine_exception(b"") == (None, None, None)


def test_pe_headers_are_parsed(tmp_path):
    """Triage recorded `file_type: pe` and then null for arch, bits, linking, stripped and
    mitigations -- the panel that shows them was blank on every Windows binary."""
    exe = _build_pe(tmp_path)
    i = pe.parse(exe.read_bytes())
    assert i.ok and i.arch == "x86-64" and i.bits == 64
    assert i.entry and i.image_base and i.subsystem == "windows-cui"
    assert i.linking == "dynamic", "a PE with an import table is dynamically linked"
    assert "msvcrt.dll" in [x.lower() for x in i.imports["libraries"]] or \
           any("ucrt" in x.lower() for x in i.imports["libraries"])
    assert i.imports["symbols"], "the import directory is entry [1], not [0]"
    # the Windows mitigations, which is the part an analyst actually wants
    assert set(i.mitigations) >= {"aslr", "dep", "cfg", "seh", "pe_format"}
    assert i.mitigations["pe_format"] == "PE32+"


def test_a_non_pe_is_refused_without_raising():
    for junk in (b"", b"MZ", b"\x7fELF" + b"\x00" * 64, b"MZ" + b"\x00" * 128):
        info = pe.parse(junk)
        assert info.ok is False and info.errors


def test_a_pe_is_described_as_a_pe(tmp_path):
    """`_describe` hardcoded "ELF", so the moment PE triage started filling these fields in it
    described a Windows binary as an ELF."""
    from lykos.analyze.triage import build_triage
    exe = _build_pe(tmp_path)
    rec = build_triage(exe, {"sha256": "x" * 64, "md5": "m", "sha1": "s", "size": 1}, "t.exe")
    assert rec["detected"].startswith("PE,")
    assert rec["analyzable"] is True, "disassembly, detection and Wine execution all work"
    assert "not yet available for this format" not in (rec["advisory"] or "")


def test_advice_does_not_recommend_afl_for_a_pe():
    """AFL++ instruments ELF and cannot drive a PE, and the Wine path runs at about one
    execution a second -- so recommending coverage_fuzz was a confident plan that cannot work."""
    from lykos.analyze.advise import advise
    pe_advice = advise(imports=["fopen"], functions=200, findings=3, seeds=0, has_format=False,
                       afl_usable=True, executable=True, file_format="pe")
    assert pe_advice["backend"] == "synthesize_poc"
    assert "one execution per second" in pe_advice["backend_why"]
    elf_advice = advise(imports=["fopen"], functions=200, findings=3, seeds=0, has_format=False,
                        afl_usable=True, executable=True, file_format="elf")
    assert elf_advice["backend"] == "coverage_fuzz"


def test_the_crt_is_watched_as_behaviour():
    """A mingw binary does its I/O through the C runtime; the Win32 call underneath happens
    inside msvcrt, which is not the target's image and is correctly not attributed to it.
    Watching only the Win32 names meant a file parser reported "calls: 0" out of 368
    attributed calls -- an inventory saying it touches no files."""
    from lykos.analyze.debug import winapi
    for fn in ("fopen", "fread", "fwrite", "fputc", "_popen", "remove"):
        assert fn in winapi._DANGER, fn
    assert "_popen" in winapi._EXEC, "a CRT popen is still an exec"
    # the Win32 set is untouched
    for fn in ("CreateFileW", "WinExec", "RegSetValueExW", "connect"):
        assert fn in winapi._DANGER, fn


def test_the_relay_trace_is_bounded():
    """+relay logs every Win32 call -- 24 MB for one second of jhead on a warm prefix, and far
    more while Wine boots a cold one. capture_output held it in memory as bytes and then again
    as a str."""
    import inspect

    from lykos.analyze.debug import winapi
    src = inspect.getsource(winapi._relay)
    assert "_RELAY_CAP" in src and "TemporaryFile" in src
    assert "capture_output" not in src, "that is what held it twice in memory"
    # the child writes to the fd, so the parent's own position never moves: tell() is always 0
    assert "fstat" in src and "errf.tell()" not in src
    assert winapi._RELAY_CAP >= (8 << 20)
