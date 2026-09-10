"""argv/envp as a taint origin, and the frame-slot tracking that makes it usable.

Before this, taint originated only at calls to catalog.SOURCES (read/fgets/getenv/...), so a
program whose input arrives as a command-line argument had no taint origin at all and nothing
could ever be corroborated. Two things were needed:

  1. seeding the entry point's own parameters (argv/envp arrive from the loader, with no call
     site to observe), and
  2. tracking constant-offset frame slots -- at -O0 the prologue spills every parameter to
     the stack, so register-only taint dies at the first spill and the seed never reaches a
     sink inside main itself.

The IR below mirrors the p-code Ghidra actually emits for that spill/reload pair.
"""
from types import SimpleNamespace

from lykos.analyze.detect import taint
from lykos.analyze.detect.catalog import entry_seed_params

_MAIN = "0x1000"


def _i(addr, pcode):
    return {"addr": addr, "text": "", "pcode": pcode}


def _edge(site, name, dst="0x9000"):
    return SimpleNamespace(src_addr=_MAIN, site_addr=site, dst_addr=dst,
                           dst_name=name, external=True)


# `main` spills argv (RSI) to [RBP-0x10], reloads it, and passes it to a sink -- the exact
# shape gcc -O0 produces and the one register-only taint used to lose.
_SPILL = [
    "INT_ADD reg:RBP:8 const:0xfffffffffffffff0:8 -> unique:0x8f00:8",
    "COPY reg:RSI:8 -> unique:0xd500:8",
    "STORE const:0x1b1:4 unique:0x8f00:8 unique:0xd500:8",
]
_RELOAD = [
    "INT_ADD reg:RBP:8 const:0xfffffffffffffff0:8 -> unique:0x8f00:8",
    "LOAD const:0x1b1:4 unique:0x8f00:8 -> unique:0x23e00:8",
    "COPY unique:0x23e00:8 -> reg:RAX:8",
]


def _spill_reload_ir(sink_site="0x100c"):
    return {"blocks": [{"addr": _MAIN, "succ": [], "instructions": [
        _i("0x1000", _SPILL),
        _i("0x1004", _RELOAD),
        _i("0x1008", ["COPY reg:RAX:8 -> reg:RDI:8"]),      # reloaded argv -> arg0
        _i(sink_site, ["CALL ram:0x9000:8"]),
    ]}]}


def _run(ir, edges, seeds):
    return taint.analyze_program({_MAIN: ir}, edges, "x86-64", entry_seeds=seeds)


# ------------------------------------------------------------------ entry-point seeding
def _fn(name, addr, signature=None):
    return SimpleNamespace(name=name, addr=addr, signature=signature)


def test_entry_seed_params_respects_declared_arity():
    """main(void) takes no argv -- seeding one would taint a callee-argument register at
    entry and every downstream sink would inherit it."""
    assert entry_seed_params([_fn("main", "0x1", "undefined8 main(void)")]) == {}
    assert entry_seed_params([_fn("main", "0x1", "int main(int c, char **v)")]) == {"0x1": {1}}
    assert entry_seed_params(
        [_fn("main", "0x1", "int main(int c, char **v, char **e)")]) == {"0x1": {1, 2}}
    # the recovered frame is authoritative over the signature string
    assert entry_seed_params([_fn("main", "0x1", "int main(int c, char **v)")],
                             {"0x1": {"params": []}}) == {}
    # no prototype information at all -> no claim
    assert entry_seed_params([_fn("main", "0x1")]) == {}
    # only real entry points, not functions that merely start with "main"
    assert entry_seed_params([_fn("mainloop", "0x1", "void mainloop(int a, char **b)")]) == {}


# ------------------------------------------------- argv reaches a sink through the spill
def test_argv_seed_reaches_sink_through_frame_spill():
    edges = [_edge("0x100c", "system")]
    ir = _spill_reload_ir()
    assert _run(ir, edges, {_MAIN: {1}}) == {"0x100c"}, "argv must reach system() through the spill"


def test_without_the_entry_seed_nothing_is_tainted():
    """The regression this whole change exists to prevent: with no entry seed an argv-driven
    program has no taint origin, so the sink is never flagged."""
    assert _run(_spill_reload_ir(), [_edge("0x100c", "system")], None) == set()


def test_frame_slot_is_killed_when_overwritten():
    """Spilling an untainted value over a tainted slot clears it -- otherwise the slot would
    stay tainted for the rest of the function."""
    ir = {"blocks": [{"addr": _MAIN, "succ": [], "instructions": [
        _i("0x1000", _SPILL),                               # argv -> [RBP-0x10]  (tainted)
        _i("0x1002", [                                      # 0 -> [RBP-0x10]     (clean)
            "INT_ADD reg:RBP:8 const:0xfffffffffffffff0:8 -> unique:0x8f00:8",
            "COPY const:0x0:8 -> unique:0xd600:8",
            "STORE const:0x1b1:4 unique:0x8f00:8 unique:0xd600:8",
        ]),
        _i("0x1004", _RELOAD),
        _i("0x1008", ["COPY reg:RAX:8 -> reg:RDI:8"]),
        _i("0x100c", ["CALL ram:0x9000:8"]),
    ]}]}
    assert _run(ir, [_edge("0x100c", "system")], {_MAIN: {1}}) == set()


def test_distinct_frame_slots_do_not_alias():
    """A reload from a DIFFERENT offset must not pick up the tainted slot's taint."""
    ir = {"blocks": [{"addr": _MAIN, "succ": [], "instructions": [
        _i("0x1000", _SPILL),                               # taint lands in [RBP-0x10]
        _i("0x1004", [                                      # read [RBP-0x08] instead
            "INT_ADD reg:RBP:8 const:0xfffffffffffffff8:8 -> unique:0x8f00:8",
            "LOAD const:0x1b1:4 unique:0x8f00:8 -> unique:0x23e00:8",
            "COPY unique:0x23e00:8 -> reg:RAX:8",
        ]),
        _i("0x1008", ["COPY reg:RAX:8 -> reg:RDI:8"]),
        _i("0x100c", ["CALL ram:0x9000:8"]),
    ]}]}
    assert _run(ir, [_edge("0x100c", "system")], {_MAIN: {1}}) == set()


# --------------------------------------------- the sink argument that constitutes the bug
def test_format_string_sink_needs_the_format_argument_tainted():
    """printf(user) is CWE-134; printf("%s", user) is not. Checking "any argument register"
    conflates them and mislabels most printf calls in any program that touches input."""
    tainted_format = _spill_reload_ir()                     # argv -> RDI (printf arg0)
    assert _run(tainted_format, [_edge("0x100c", "printf")], {_MAIN: {1}}) == {"0x100c"}

    # argv stays in RSI (printf's first vararg); the format in RDI is a constant
    only_vararg = {"blocks": [{"addr": _MAIN, "succ": [], "instructions": [
        _i("0x1000", ["COPY const:0x402010:8 -> reg:RDI:8"]),   # literal format
        _i("0x100c", ["CALL ram:0x9000:8"]),
    ]}]}
    assert _run(only_vararg, [_edge("0x100c", "printf")], {_MAIN: {1}}) == set()


def test_copy_sink_ignores_a_tainted_destination():
    """strcpy(tainted_dst, literal) does not overflow because of the destination pointer;
    the source is what carries attacker bytes."""
    dst_only = {"blocks": [{"addr": _MAIN, "succ": [], "instructions": [
        _i("0x1000", ["COPY reg:RSI:8 -> reg:RDI:8"]),      # argv -> strcpy dst (arg0)
        _i("0x1002", ["COPY const:0x402010:8 -> reg:RSI:8"]),  # literal source
        _i("0x100c", ["CALL ram:0x9000:8"]),
    ]}]}
    assert _run(dst_only, [_edge("0x100c", "strcpy")], {_MAIN: {1}}) == set()


def test_unlisted_sink_falls_back_to_any_argument():
    """A sink with no declared argument position keeps the old conservative behaviour."""
    ir = {"blocks": [{"addr": _MAIN, "succ": [], "instructions": [
        _i("0x100c", ["CALL ram:0x9000:8"]),                # RSI (arg1) tainted by the seed
    ]}]}
    assert _run(ir, [_edge("0x100c", "gets")], {_MAIN: {1}}) == {"0x100c"}
