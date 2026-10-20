"""FLIRT library-ID names libc sinks in a STRIPPED STATIC binary so detection is not blind.

A statically-linked, stripped ELF has no symbols, so recovery leaves every libc call as `fcn.XXXX`
and the call-graph detectors (dangerous_api) see nothing -- the measured air-gap gap was 625
functions recovered, 0 named, 0 findings on a static strcpy/system target. `flirt` matches the
target's code against signatures built from the host libc.a (whose .o members carry the exact
bodies the static link pulls in, plus the relocation mask over the variant bytes) and names the
security-relevant functions, propagating the names onto the call edges.
"""
import shutil
import subprocess

import pytest
from lykos.analyze import flirt
from lykos.analyze.dynamic import sandbox


@pytest.fixture
def ref_archive():
    path = flirt.reference_archive()
    if not path:
        pytest.skip("no reference libc.a on this host")
    return path


@pytest.fixture
def x86_64_only():
    if sandbox.host_arch() != "x86-64":
        pytest.skip("FLIRT signatures here are x86-64")


@pytest.fixture
def static_bin(tmp_path, x86_64_only):
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no gcc")
    c = tmp_path / "v.c"
    c.write_text(
        "#include <string.h>\n#include <stdlib.h>\n#include <unistd.h>\n"
        "void proc(char*in){char b[64]; strcpy(b,in);}\n"
        "int main(void){char l[256]; int n=read(0,l,255); l[n>0?n:0]=0; proc(l);"
        " system(\"true\"); return 0;}\n")
    out = tmp_path / "statvuln"
    r = subprocess.run([gcc, "-static", "-no-pie", "-fno-stack-protector", "-w",
                        str(c), "-o", str(out)], capture_output=True)
    if r.returncode != 0 or not out.exists():
        pytest.skip("cannot build a static binary here (libc.a/-static unavailable)")
    subprocess.run(["strip", "--strip-all", str(out)], capture_output=True)
    return out


def test_signatures_cover_the_sinks(ref_archive):
    sigs = flirt.build_signatures(open(ref_archive, "rb").read())
    # The shell/exec sinks must be present -- they are the RCE-relevant names and are not IFUNCs.
    for name in ("system", "execve", "popen"):
        assert name in sigs, f"no signature built for {name}"
        assert all(len(s) and len(m) == len(s) for s, m in sigs[name])


def test_identify_names_system_in_stripped_static(ref_archive, static_bin):
    sigs = flirt.build_signatures(open(ref_archive, "rb").read())
    tgt = static_bin.read_bytes()
    named = flirt.identify(tgt, None, sigs)              # {hex_va: name}
    assert "system" in named.values(), "FLIRT did not name system() in the stripped static binary"


def test_relabel_propagates_names_onto_call_edges(ref_archive, static_bin):
    sigs = flirt.build_signatures(open(ref_archive, "rb").read())
    tgt = static_bin.read_bytes()
    named = flirt.identify(tgt, None, sigs)
    sys_va = next(a for a, n in named.items() if n == "system")
    # A recovered-function set as the disassembler hands it over: a caller whose edge to system is
    # unnamed, mirroring the stripped-static case. relabel must name the edge.
    funcs = [{"addr": "0x401000", "name": "fcn.00401000",
              "calls": [{"site_addr": "0x401010", "dst_addr": sys_va,
                         "dst_name": "fcn." + sys_va[2:], "external": False}]}]
    n = flirt.relabel(tgt, funcs)
    assert n >= 1
    assert funcs[0]["calls"][0]["dst_name"] == "system", "the call edge was not renamed to system"


def test_relabel_is_a_noop_on_a_non_elf_or_named_target(ref_archive):
    # No ELF64 bytes -> nothing to do, and a real name is never clobbered.
    assert flirt.relabel(b"not an elf", []) == 0
    funcs = [{"addr": "0x1000", "name": "my_real_func", "calls": []}]
    flirt.relabel(b"\x7fELF\x02" + b"\x00" * 60, funcs)
    assert funcs[0]["name"] == "my_real_func"


def test_ifunc_stub_resolves_an_ifunc_sink(ref_archive, static_bin):
    """strcpy/str*/mem* are IFUNCs: the body is identified but the CALL lands on a resolver thunk
    (jmp *[rip+GOT]), not the body. ifunc_stub_names must chain GOT -> IRELATIVE resolver -> the
    named variant the resolver lea's, so the thunk/GOT -- and the call edge to it -- gets the name."""
    sigs = flirt.build_signatures(open(ref_archive, "rb").read())
    tgt = static_bin.read_bytes()
    named = flirt.identify(tgt, None, sigs)
    stubs = flirt.ifunc_stub_names(tgt, named)
    assert "strcpy" in stubs.values(), "IFUNC thunk/GOT for strcpy was not resolved to a name"


@pytest.fixture
def aarch64_static_bin(tmp_path):
    gcc = shutil.which("aarch64-linux-gnu-gcc")
    if not gcc or not flirt.reference_archive(flirt._EM_AARCH64):
        pytest.skip("no aarch64 cross toolchain / aarch64 libc.a")
    c = tmp_path / "v.c"
    c.write_text(
        "#include <string.h>\n#include <stdlib.h>\n#include <unistd.h>\n"
        "void proc(char*in){char b[64]; strcpy(b,in);}\n"
        "int main(void){char l[256]; int n=read(0,l,255); l[n>0?n:0]=0; proc(l);"
        " system(\"true\"); return 0;}\n")
    out = tmp_path / "a64stat"
    r = subprocess.run([gcc, "-static", "-no-pie", "-fno-stack-protector", "-w",
                        str(c), "-o", str(out)], capture_output=True)
    if r.returncode != 0 or not out.exists():
        pytest.skip("cannot build a static aarch64 binary")
    strip = shutil.which("aarch64-linux-gnu-strip") or shutil.which("strip")
    subprocess.run([strip, "--strip-all", str(out)], capture_output=True)
    return out


def test_flirt_names_sinks_in_a_stripped_static_aarch64_binary(aarch64_static_bin):
    """FLIRT is arch-aware: the signature bodies + relocation masks come from the aarch64 libc.a,
    so a stripped static ARM64 binary (a common firmware shape) gets its libc sinks named too."""
    tgt = aarch64_static_bin.read_bytes()
    assert flirt._target_machine(tgt) == flirt._EM_AARCH64
    sigs = flirt.build_signatures(open(flirt.reference_archive(flirt._EM_AARCH64), "rb").read())
    named = flirt.identify(tgt, None, sigs)
    assert "system" in named.values(), "FLIRT did not name system() in the aarch64 static binary"
    # relabel must also apply (arch gate accepts aarch64), naming a synthetic edge to system.
    sys_va = next(a for a, n in named.items() if n == "system")
    funcs = [{"addr": "0x400000", "name": "fcn.00400000",
              "calls": [{"site_addr": "0x400004", "dst_addr": sys_va,
                         "dst_name": "fcn." + sys_va[2:], "external": False}]}]
    assert flirt.relabel(tgt, funcs) >= 1
    assert funcs[0]["calls"][0]["dst_name"] == "system"
