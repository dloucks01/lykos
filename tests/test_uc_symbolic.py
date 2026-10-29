"""Under-constrained symbolic execution of a single function (discovery for undriven code).

The sound, low-false-positive signal is a DATA-dependent unconstrained instruction pointer: symbolic
data the function READ reaches control flow. A PC controlled only by an argument register (a passed
callback) must NOT be flagged -- that is a benign indirect call, not a bug. These pin that gate:
  * a function that calls through its argument (callback) -> NOT hijackable (reg-only PC)
  * a function that reads memory and calls through it -> hijackable (mem-derived PC)
  * a function that does nothing with control flow -> no unconstrained state
UC runs angr in a subprocess, so the test is gated on angr + a C compiler.
"""
import shutil
import subprocess

import pytest

_SRC = (
    "#include <stdint.h>\n"
    "typedef void (*fp)(void);\n"
    "void call_arg(fp f){ f(); }                      /* PC from an ARG register -> benign callback */\n"
    "void call_mem(char *p){ fp *t=(fp*)p; (*t)(); }  /* PC from MEMORY the fn read -> data->PC */\n"
    "void safe_fn(int a){ (void)a; }                  /* nothing reaches PC */\n"
)


def _angr():
    import sys
    sys.path.insert(0, "core") if "core" not in sys.path else None
    from lykos.analyze.symbolic import concolic as C
    return C.locate_angr_python()


@pytest.mark.skipif(not (shutil.which("gcc") or shutil.which("cc")), reason="needs a C compiler")
def test_uc_flags_data_to_pc_not_callback_args(tmp_path):
    if _angr() is None:
        pytest.skip("angr not available")
    from lykos.analyze.symbolic.uc_symbolic import uc_scan_function
    cc = shutil.which("gcc") or shutil.which("cc")
    src = tmp_path / "uc.c"
    src.write_text(_SRC)
    so = tmp_path / "uc.so"
    assert subprocess.run([cc, "-O0", "-g", "-shared", str(src), "-o", str(so)],
                          capture_output=True).returncode == 0

    cb = uc_scan_function(so, "call_arg", timeout=40)
    assert cb.get("reached") and cb.get("hijackable") is False, cb   # callback arg is NOT flagged

    mem = uc_scan_function(so, "call_mem", timeout=40)
    assert mem.get("reached") and mem.get("hijackable") is True, mem  # data->PC IS flagged
    assert mem.get("data_to_pc", 0) >= 1

    safe = uc_scan_function(so, "safe_fn", timeout=40)
    assert safe.get("reached") and not safe.get("hijackable"), safe


def test_uc_missing_symbol_is_handled(tmp_path):
    if _angr() is None:
        pytest.skip("angr not available")
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        pytest.skip("needs a C compiler")
    from lykos.analyze.symbolic.uc_symbolic import uc_scan_function
    src = tmp_path / "u.c"
    src.write_text("int real(int a){ return a; }\n")
    so = tmp_path / "u.so"
    subprocess.run([cc, "-O0", "-g", "-shared", str(src), "-o", str(so)], capture_output=True)
    r = uc_scan_function(so, "no_such_symbol", timeout=20)
    assert r.get("reached") is False and "not found" in (r.get("note") or "")
