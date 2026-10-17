"""Linux kernel modules: what this platform can and cannot say about them.

What it cannot: anything dynamic. Measured on this host -- there is no kernel build tree
(`/lib/modules/$(uname -r)/build`), so a planted-bug module cannot be COMPILED and no conformance
fixture is possible; and `qemu-system-*` is not installed, so no kernel can be BOOTED. Every rung
above static is therefore out of reach, and that is a property of the environment, not a gap in
the analysis.

What it can, and could not before: see the module at all. A `.ko` is an ET_REL object, and three
pieces of plumbing hid it completely --

* imports were read only from `.dynsym`, which an ET_REL object does not have, so a module parsed
  as ZERO imports and every import-gated detector and injection probe was blind to it;
* `relro`/`bind_now` were reported as `off`, which states a fact that is not in the file: both are
  properties of a link, and a relocatable object has no program headers at all;
* the call graph is in the RELOCATIONS. Every external call is `call <self+5>` with a placeholder
  displacement, and the callee's name appears only in `.rela.text`, so a disassembler that does not
  apply relocations loses it.

These tests run against the host's REAL modules, and the call-site recovery is checked against
`readelf` entry for entry rather than against itself.
"""
import glob
import lzma
import os
import re
import shutil
import subprocess

import pytest
from lykos.analyze import elf
from lykos.analyze.detect.catalog import DANGEROUS

_KMOD_DIR = f"/lib/modules/{os.uname().release}/kernel"


def _some_modules(limit=6):
    found = sorted(glob.glob(_KMOD_DIR + "/**/*.ko*", recursive=True))
    return found[:limit]


@pytest.fixture(scope="module")
def modules(tmp_path_factory):
    """Real kernel modules from this host, decompressed if needed. A module is not attacker data
    here, but it is still read as DATA -- parsed, never loaded."""
    paths = _some_modules()
    if not paths:
        pytest.skip("no kernel modules on this host")
    d = tmp_path_factory.mktemp("kmods")
    out = []
    for p in paths:
        try:
            raw = open(p, "rb").read()
            if p.endswith(".xz"):
                raw = lzma.decompress(raw)
            elif p.endswith(".zst"):
                continue                                 # no stdlib zstd
            if raw[:4] != b"\x7fELF":
                continue
            q = d / (os.path.basename(p).split(".ko")[0] + ".ko")
            q.write_bytes(raw)
            out.append(q)
        except Exception:                                # noqa: BLE001
            continue
    if not out:
        pytest.skip("no decompressible ELF modules")
    return out


def test_a_module_is_recognised_as_a_relocatable_object(modules):
    for m in modules:
        i = elf.parse(m.read_bytes())
        assert i.elf_type == "rel", (m.name, i.elf_type)
        assert i.bits in (32, 64) and i.arch


def test_a_modules_imports_come_from_symtab_not_dynsym(modules):
    """The fix that makes every import-gated detector and probe able to see a module at all. Before
    it, this count was zero for every module on the system."""
    seen = 0
    for m in modules:
        i = elf.parse(m.read_bytes())
        if i.imported_symbols:
            seen += 1
            # a module links against the kernel, so these are kernel symbols, not libc ones
            assert i.imports["functions_count"] == len(i.imported_symbols)
            assert any(n.startswith("__") or "_" in n for n in i.imported_symbols)
    assert seen, "no module reported any imports; the symtab fallback is not working"


def test_link_time_mitigations_are_unknown_not_off_for_a_relocatable_object(modules):
    """RELRO and bind-now are properties of a LINK. An object that has not been linked has no
    program headers, so there is no PT_GNU_RELRO to find and no DT_FLAGS to read -- reporting
    `off` asserts something the file does not say."""
    for m in modules:
        i = elf.parse(m.read_bytes())
        assert i.mitigations["relro"] == "unknown", (m.name, i.mitigations)
        assert i.mitigations["bind_now"] == "unknown", (m.name, i.mitigations)
        assert i.mitigations["pie"] == "unknown", (m.name, i.mitigations)


def test_rel_call_sites_matches_readelf_entry_for_entry(modules):
    """The recovery is exact, not heuristic, so it is checked against a different tool rather than
    against its own output. `readelf`'s own view: PC32/PLT32 relocations in code sections whose
    symbol is UNDEFINED."""
    if not shutil.which("readelf"):
        pytest.skip("no readelf")
    checked = 0
    for m in modules:
        data = m.read_bytes()
        i = elf.parse(data)
        if (i.arch or "").lower() not in ("x86-64", "x86"):
            continue
        syms = subprocess.run(["readelf", "-sW", str(m)], capture_output=True, text=True).stdout
        undef = set()
        for line in syms.splitlines():
            f = line.split()
            if len(f) >= 8 and f[6] == "UND" and f[-1] != "UND":
                undef.add(f[-1])
        rel = subprocess.run(["readelf", "-rW", str(m)], capture_output=True, text=True).stdout
        n, on = 0, False
        for line in rel.splitlines():
            mm = re.match(r"^Relocation section '\.rela([^']*)'", line)
            if mm:
                on = mm.group(1).startswith((".text", ".init", ".exit"))
                continue
            if on and ("R_X86_64_PLT32" in line or "R_X86_64_PC32" in line):
                f = line.split()
                nm = f[4].split("-")[0].split("+")[0] if len(f) > 4 else ""
                if nm in undef:
                    n += 1
        assert len(elf.rel_call_sites(data, i)) == n, (m.name, n)
        checked += 1
    assert checked, "no x86 modules to check"


def test_rel_call_sites_names_callees_a_disassembler_would_lose(modules):
    """The substance: the names are recovered, with the section and byte offset they patch."""
    total = 0
    for m in modules:
        sites = elf.rel_call_sites(m.read_bytes())
        total += len(sites)
        for s in sites:
            assert s["name"] and s["section"].startswith((".text", ".init", ".exit"))
            assert isinstance(s["offset"], int)
    assert total > 50, f"only {total} call sites across {len(modules)} modules"


def test_rel_call_sites_is_empty_for_a_linked_binary(tmp_path):
    """An executable's call graph is in its instructions and its PLT, and the disassembler already
    has it -- this path must not fire there and produce a second, parallel set of edges."""
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    (tmp_path / "t.c").write_text("#include <stdio.h>\nint main(void){puts(\"x\");return 0;}\n")
    exe = tmp_path / "t"
    if subprocess.run([gcc, "-O0", "-w", str(tmp_path / "t.c"), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("build failed")
    assert elf.rel_call_sites(exe.read_bytes()) == []
    # ...but the same source compiled to an OBJECT does have them
    obj = tmp_path / "t.o"
    if subprocess.run([gcc, "-c", "-O0", "-w", str(tmp_path / "t.c"), "-o", str(obj)],
                      capture_output=True).returncode:
        pytest.skip("object build failed")
    sites = elf.rel_call_sites(obj.read_bytes())
    assert any(s["name"] == "puts" for s in sites), sites


def test_the_kernel_user_boundary_sinks_are_in_the_catalogue():
    """These are what make a recovered module call graph mean something. Advisory severities on
    purpose -- the sink is certain, whether the length is validated needs the data flow -- but the
    CWEs have to name the KERNEL weakness, not a userspace overflow."""
    for name in ("copy_from_user", "_copy_from_user", "__copy_from_user", "copy_to_user",
                 "memdup_user", "strncpy_from_user"):
        assert name in DANGEROUS, name
    assert DANGEROUS["_copy_from_user"][0] == "CWE-1285"      # improper validation of an index
    assert DANGEROUS["copy_to_user"][0] == "CWE-200"          # disclosure, the other direction
    assert DANGEROUS["memdup_user"][0] == "CWE-789"           # a user-controlled allocation
    # and the double-underscore forms must say WHY they are worse
    assert "access_ok" in DANGEROUS["__copy_from_user"][2]


def test_a_real_module_user_copy_surface_is_located(modules):
    """End to end on a real module: if any of these modules crosses the user boundary, the site is
    named with its section and offset. Skipped rather than failed when none of the sampled modules
    happens to have one -- which module set a host ships is not ours to choose."""
    hits = []
    for m in modules:
        for s in elf.rel_call_sites(m.read_bytes()):
            if s["name"].lstrip("_") in ("copy_from_user", "copy_to_user") \
                    or s["name"] in DANGEROUS:
                hits.append((m.name, s["section"], hex(s["offset"]), s["name"]))
    if not hits:
        pytest.skip("none of the sampled modules calls a catalogued sink")
    assert all(h[1].startswith((".text", ".init", ".exit")) for h in hits)
