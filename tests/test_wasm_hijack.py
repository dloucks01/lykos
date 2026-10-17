"""WASM function-pointer hijack: an overflow in linear memory -> an attacker-chosen indirect call.

The engine's own substrate guard says the right thing about WebAssembly -- the engine owns the
instruction pointer and no linear-memory corruption gives it up, so control-flow hijack in the
native sense is not a claim this runtime supports. This is a different claim, and it had no route:
a C function pointer on wasm32 is a 4-byte INDEX into `__indirect_function_table` held in linear
memory, so an overflow changes which function the module's own `call_indirect` dispatches to.
"""
import struct
import subprocess

import pytest
from lykos.analyze import wasm
from lykos.analyze.poc import wasm_hijack as wh

_SRC = '''typedef void (*cb_t)(void);
static void plain(void) { }
static void win(void)   { __builtin_trap(); }
__attribute__((used)) static cb_t handlers[2] = { plain, win };
struct obj { char buf[32]; cb_t cb; };
static struct obj o = { .cb = plain };
__attribute__((export_name("take"))) void take(char *p, int n) {
  for (int i = 0; i < n; i++) o.buf[i] = p[i];
  o.cb(); }
'''


def _build(tmp_path):
    import shutil
    clang = shutil.which("clang")
    if not clang:
        pytest.skip("no clang")
    c = tmp_path / "m.c"; c.write_text(_SRC)
    out = tmp_path / "m.wasm"
    r = subprocess.run([clang, "--target=wasm32", "-O1", "-nostdlib", "-Wl,--no-entry",
                        "-Wl,--export-all", "-o", str(out), str(c)], capture_output=True)
    if r.returncode or not out.exists():
        pytest.skip("clang cannot target wasm32 here")
    return out.read_bytes()


def test_the_parser_reads_the_indirect_call_table(tmp_path):
    """The sweep needs the table's size, and the module states it. Without this the search would
    have to guess how many slots exist -- and the whole technique is a sweep over them."""
    info = wasm.parse(_build(tmp_path))
    assert info.table_size and info.table_size >= 2
    assert info.table_funcs, "the element section says which slots hold functions"


def test_a_failed_hijack_is_never_an_effect():
    """An index that names no function, or one whose type does not match the call site, traps with
    the engine's own message. That is a FAILED hijack and the one thing a sweep over a table is
    guaranteed to produce a lot of -- filing it as an effect would make every sweep "succeed"."""
    assert wh._is_mismatch("null function or function signature mismatch")
    assert wh._is_mismatch("indirect call type mismatch")
    assert not wh._is_mismatch("unreachable")
    assert not wh._is_mismatch("memory access out of bounds")


def test_the_search_confirms_against_two_controls(tmp_path):
    """A hijack is confirmed when the verdict differs from the module's behaviour on a payload
    that never reaches the pointer AND a benign slot at the SAME offset does not produce it.
    Driven here against a simulated engine so the logic is tested without node."""
    mod = _build(tmp_path)

    def run(payload):
        if len(payload) <= 8:
            return "clean"                               # never reaches the pointer
        if len(payload) < 36:
            return "clean"
        idx = struct.unpack_from("<i", payload, 32)[0]
        if idx == 2:
            return "unreachable"                         # win() ran
        if idx == 0:
            return "null function or function signature mismatch"
        return "clean"                                   # plain(), or any benign slot

    hit = wh.find_hijack(mod, run)
    assert hit and hit["offset"] == 32 and hit["index"] == 2
    assert hit["verdict"] == "unreachable" and hit["baseline"] == "clean"
    assert hit["control_verdict"] != hit["verdict"], "the control must not produce the effect"


def test_the_control_is_chosen_at_the_same_offset():
    """Picking the benign slot from a different offset would compare two different writes and call
    the difference a hijack."""
    import inspect
    src = inspect.getsource(wh.find_hijack)
    i = src.index("for offset in range")
    assert "benign = None" in src[i:src.index("for index in slots", i)], \
        "the control index must be reset per offset"


def test_the_arm_runs_before_the_ip_control_guard():
    """`supports_ip_control("wasm")` is False and correct -- so the arm has to come first, or the
    stage declines with a reason that is true of everything except this technique."""
    import inspect

    from lykos.analyze import substrate
    from lykos.analyze.poc import exploit_stage
    assert substrate.supports_ip_control("wasm") is False
    src = inspect.getsource(exploit_stage.build_exploit_stage)
    assert src.index('== "wasm"') < src.index("supports_ip_control")
