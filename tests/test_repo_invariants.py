"""Repo-level invariants that no single-module test can see.

These exist because of a specific class of bug this suite kept missing: a name that is only ever
referenced from inside an `except` handler. The handler is the one path unit tests rarely take, so
an undefined name there survives every green run -- and then, when the error it was written to
absorb finally happens, the handler itself raises and the failure escapes as a NameError from a
stage that was supposed to degrade quietly.

Two such bugs shipped: `_log` was used in four `except` blocks across heap_discover.py and
exploit_stage.py without either module ever creating a logger, and `_exploit` was called in
`_pie_canary_ret2libc` without being imported. `shared_op_model` -- the function wrapping two of
those handlers -- is called from five stages.

`ruff check --select F821` catches all of this, which is the real fix; these tests are the backstop
for a host with no ruff installed, and they make the intent explicit rather than incidental.
"""
from __future__ import annotations

import ast
import pathlib
import symtable

CORE = pathlib.Path(__file__).resolve().parents[1] / "core" / "lykos"

# Builtins, plus the module-level dunders the interpreter injects rather than the source binding.
_ALLOWED_GLOBALS = set(dir(__builtins__) if isinstance(__builtins__, type(ast)) else __builtins__)
_ALLOWED_GLOBALS |= {"__file__", "__name__", "__doc__", "__package__", "__spec__", "__loader__",
                     "__builtins__", "__debug__"}



def _modules():
    return sorted(CORE.rglob("*.py"))


def test_every_module_that_logs_defines_its_logger():
    """A module that calls `_log.<level>()` must create `_log`. The four original misses were all
    inside `except` handlers, so the only thing that executed them was a real failure.

    Asked of the AST, not of the text. A regex for `_log.` matches `build_log.strip()` (a local
    named build_log) and it matches prose -- several modules now explain this very bug in their
    docstrings, quoting `_log.debug(...)`, and a text search reads the explanation as the thing
    being explained."""
    missing = []
    for p in _modules():
        tree = ast.parse(p.read_text())
        calls_log = any(
            isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "_log"
            for n in ast.walk(tree))
        if not calls_log:
            continue
        defines = any(
            isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "_log" for t in n.targets)
            for n in tree.body
        )
        if not defines:
            missing.append(str(p.relative_to(CORE.parents[1])))
    assert not missing, "modules call _log without defining it: %s" % missing


def test_no_undefined_names_in_core():
    """Repo-wide F821, via the stdlib symbol table: every global a module reads must be bound
    somewhere in that module, imported by it, or a builtin. This is the check that would have
    caught `_exploit` in `_pie_canary_ret2libc` -- a function-local import that was simply never
    written, in a function no test reaches."""
    offenders = []
    for p in _modules():
        src = p.read_text()
        top = symtable.symtable(src, str(p), "exec")
        bound = {s.get_name() for s in top.get_symbols() if s.is_assigned() or s.is_imported()}
        stack = list(top.get_children())
        while stack:
            scope = stack.pop()
            stack.extend(scope.get_children())
            local = {s.get_name() for s in scope.get_symbols() if s.is_assigned() or s.is_imported()}
            for sym in scope.get_symbols():
                name = sym.get_name()
                if not sym.is_referenced() or sym.is_parameter():
                    continue
                if name in local or name in bound or name in _ALLOWED_GLOBALS:
                    continue
                # A name bound in any enclosing function scope (closures, nested helpers).
                if sym.is_free() or sym.is_global() and name in bound:
                    continue
                if sym.is_local() or sym.is_free():
                    continue
                offenders.append("%s: %s (in %s)" % (p.relative_to(CORE.parents[1]), name,
                                                     scope.get_name()))
    # Names resolved through a wildcard import or injected by a plugin host would show up here;
    # the core is stdlib-only and uses neither, so the expected set is empty.
    assert not offenders, "undefined names in core: %s" % sorted(set(offenders))[:20]
