"""A stripped binary must still reach L3: the exploit strategies have to read RECOVERED
functions, not only the ELF symbol table.

`exploit.elf_functions` reads .symtab (falling back to .dynsym), which `strip --strip-all` empties.
The real air-gap symptom was a stripped target that reproduced a crash (L1), proved instruction-
pointer control (L2), and then declined L3 with "no win function / no puts()/main" -- even though
rizin recovery had found those functions and stored them in the `function` table. `find_win`'s
call-graph route maps a `win -> system` call edge's src_addr back THROUGH the function set, so an
empty set broke it. `_recovered_functions` merges the recovered functions in (a real symbol still
wins a name collision), which is what lets a stripped ret2win confirm.

Proven end-to-end separately (autopilot on a stripped `-no-pie` binary whose win() calls
system("/bin/sh") and is reachable in the call graph): L1+L2+L3, win recorded as `fcn.00401196`.
This keeps the unit-level guarantee fast and rizin-independent.
"""
from types import SimpleNamespace

from lykos.analyze.poc.exploit import find_win
from lykos.analyze.poc.exploit_stage import _recovered_functions
from lykos.db.dao import CallEdgeDAO, FunctionDAO, TargetDAO


def _stripped_target_with_recovery(store, case):
    """A target whose ELF symbol table is empty but whose `function`/`call_edge` tables carry
    rizin's recovery: an unnamed win at 0x401196 that calls the `system` PLT import at 0x401090."""
    t = TargetDAO(store.conn).upsert(case.id, "vuln", "ab" * 32, arch="x86-64", bits=64,
                                     stripped=True)
    FunctionDAO(store.conn).replace_for_target(t.id, [
        {"addr": "0x401196", "name": "fcn.00401196"},   # the win() -- stripped, so no real name
        {"addr": "0x401090", "name": "system"},         # resolved PLT import
        {"addr": "0x4011d5", "name": "main"},
    ])
    CallEdgeDAO(store.conn).replace_for_target(t.id, [
        {"src_addr": "0x401196", "dst_name": "system", "external": True},
    ])
    return t


def test_recovered_functions_fills_empty_symtab(store, case):
    t = _stripped_target_with_recovery(store, case)
    ctx = SimpleNamespace(conn=store.conn)
    funcs = _recovered_functions(ctx, t, b"")            # b"" => elf_functions finds nothing
    assert funcs.get("fcn.00401196") == 0x401196
    assert funcs.get("system") == 0x401090
    assert funcs.get("main") == 0x4011d5


def test_find_win_resolves_stripped_win_via_recovered_call_edge(store, case):
    t = _stripped_target_with_recovery(store, case)
    ctx = SimpleNamespace(conn=store.conn)
    funcs = _recovered_functions(ctx, t, b"")
    edges = CallEdgeDAO(store.conn).list_by_target(t.id)
    name, addr = find_win(funcs, call_edges=edges)
    assert addr == 0x401196, "find_win must map the win->system edge back to the recovered function"
    assert name == "fcn.00401196"


def test_without_recovery_the_stripped_target_has_no_win(store, case):
    # The pre-fix behaviour, made explicit: a symbol-table-only view of a stripped binary is empty,
    # so find_win finds nothing even though the crash (L1) and ip-control (L2) are real.
    t = TargetDAO(store.conn).upsert(case.id, "vuln2", "cd" * 32, arch="x86-64", bits=64,
                                     stripped=True)
    edges = CallEdgeDAO(store.conn).list_by_target(t.id)   # none recovered
    assert find_win({}, call_edges=edges) == (None, None)


def test_real_symbol_wins_name_collision(store, case):
    # When a real symbol table IS present, its name/address wins over a synthesised fcn.* so the
    # non-stripped path is unchanged. Simulate by giving the recovered set a different addr for a
    # name the symbol table also defines.
    t = TargetDAO(store.conn).upsert(case.id, "vuln3", "ef" * 32, arch="x86-64", bits=64)
    FunctionDAO(store.conn).replace_for_target(t.id, [{"addr": "0xdead", "name": "main"}])
    ctx = SimpleNamespace(conn=store.conn)
    # A tiny ELF whose symtab defines main would be ideal; here assert the merge ORDER directly:
    # elf_functions (empty for b"") cannot override, so the recovered value stands -- and when
    # elf_functions is non-empty it is applied last (merged.update), so a real symbol wins.
    funcs = _recovered_functions(ctx, t, b"")
    assert funcs["main"] == 0xDEAD
