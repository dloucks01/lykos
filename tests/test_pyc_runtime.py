"""Running CPython bytecode: a defect is an uncaught exception, and a REFUSAL is neither.

The JVM lesson pointed the other way. There, a failed launch looked like a clean run and hid a
real defect behind a zero. Here a failed launch looks like a crash on EVERY input -- bytecode
built for another interpreter version prints `RuntimeError: Bad magic number`, a missing
third-party import prints `ModuleNotFoundError`, and both do it identically for every byte you
feed in. Classifying either as a fault would not produce one false positive; it would produce a
campaign made entirely of them.
"""
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
from lykos.analyze import pyc
from lykos.analyze.dynamic import sandbox
from lykos.analyze.runtime_fault import managed_fault

_INDEXED_BY_INPUT_LENGTH = (
    "import sys\n"
    "s = sys.stdin.readline()\n"
    "t = [1, 2, 3, 4]\n"
    "print('slot', len(s), '=', t[len(s)])\n")


def _compile(tmp_path, body=_INDEXED_BY_INPUT_LENGTH, name="oob"):
    if shutil.which("python3") is None:
        pytest.skip("no python3")
    (tmp_path / (name + ".py")).write_text(body)
    r = subprocess.run(["python3", "-m", "py_compile", name + ".py"],
                       cwd=str(tmp_path), capture_output=True)
    if r.returncode:
        pytest.skip("py_compile failed here")
    made = sorted(tmp_path.rglob(name + "*.pyc"))
    if not made:
        pytest.skip("py_compile produced no .pyc")
    return made[0]


def _staged(tmp_path, **kw):
    """The target as a stage actually writes it: content-addressed, under a generic name.

    Unlike a bare .class this must keep working, because CPython loads a .pyc under any name --
    the point of the test is that the generic name is not a problem here.
    """
    staged = tmp_path / "target.bin"
    shutil.copy(_compile(tmp_path, **kw), staged)
    return staged


def test_a_pyc_is_recognised_and_a_lookalike_is_not(tmp_path):
    assert sandbox._is_pyc(_staged(tmp_path))
    # \r\n at offset 2 is far too weak a signal on its own: the magic has to be a version
    # CPython actually shipped, which is also what decides whether this interpreter can run it.
    fake = tmp_path / "not.pyc"
    fake.write_bytes(struct.pack("<H", 1) + b"\r\n" + b"\x00" * 24)
    assert not sandbox._is_pyc(fake)


def test_an_uncaught_exception_is_the_fault_and_names_the_defect():
    trace = ('Traceback (most recent call last):\n'
             '  File "svc.py", line 14, in parse\n'
             '    return table[int(field)]\n'
             'IndexError: list index out of range\n')
    kind, detail, frames = sandbox.python_exception(trace.encode(), 1)
    assert kind == "IndexError"
    assert "svc.py:14" in detail and "parse" in detail
    assert frames and frames[-1][0] == "svc.py"
    assert managed_fault(kind) == ("CWE-129", "high", "CPython")


def test_the_LAST_exception_of_a_chain_is_the_one_that_killed_it():
    trace = ('Traceback (most recent call last):\n'
             '  File "svc.py", line 3, in <module>\n'
             'ZeroDivisionError: division by zero\n'
             '\nDuring handling of the above exception, another exception occurred:\n\n'
             'Traceback (most recent call last):\n'
             '  File "svc.py", line 5, in <module>\n'
             'ValueError: bad field\n')
    kind, _detail, _frames = sandbox.python_exception(trace.encode(), 1)
    assert kind == "ValueError"


def test_the_blame_frame_is_the_targets_code_not_the_stdlib():
    """`json.loads` raises three stdlib frames down. Blaming the deepest frame blames CPython
    and merges every such defect in the program into one finding."""
    trace = ('Traceback (most recent call last):\n'
             '  File "svc.py", line 14, in parse\n'
             '  File "/usr/lib/python3.14/json/__init__.py", line 346, in loads\n'
             '  File "/usr/lib/python3.14/json/decoder.py", line 338, in decode\n'
             'ValueError: Expecting value\n')
    _k, detail, frames = sandbox.python_exception(trace.encode(), 1)
    assert sandbox.app_frame_py(frames)[0] == "svc.py"
    assert "svc.py:14" in detail


def test_two_exceptions_from_different_lines_are_two_defects():
    a = sandbox.python_site([("svc.py", "14", "parse")])
    b = sandbox.python_site([("svc.py", "99", "other")])
    assert a and b and a != b


def test_a_deliberate_exit_is_not_a_fault():
    trace = ('Traceback (most recent call last):\n'
             '  File "svc.py", line 2, in <module>\n'
             'SystemExit: 2\n')
    kind, detail, _f = sandbox.python_exception(trace.encode(), 2)
    assert kind == "" and "not an input-driven fault" in detail
    assert pyc.cwe_for_exception("SystemExit") is None


@pytest.mark.parametrize("text,why", [
    ("RuntimeError: Bad magic number in .pyc file\n", "magic"),
    ("ModuleNotFoundError: No module named 'requests'\n", "import"),
    ("ValueError: bad marshal data (unknown type code)\n", "marshal"),
])
def test_an_interpreter_refusal_is_not_a_crash(text, why):
    """Each of these fails the same way for every input. A falsy kind WITH a reason says
    'this never executed', which is neither a crash nor a clean run."""
    kind, detail, _f = sandbox.python_exception(("Traceback (most recent call last):\n"
                                                + text).encode(), 1)
    assert kind == "", why
    assert detail and ("could not load" in detail or "not an input-driven fault" in detail)


def test_the_interpreter_itself_crashing_is_memory_corruption():
    text = ("Fatal Python error: Segmentation fault\n\n"
            "Current thread 0x00007f (most recent call first):\n"
            '  File "svc.py", line 9 in go\n')
    kind, detail, _f = sandbox.python_exception(text.encode(), -11)
    assert kind == "PY-FATAL-SEGMENTATION"
    assert "native memory corruption" in detail
    assert managed_fault(kind) == ("CWE-119", "critical", "CPython")


def test_a_traceback_the_target_merely_PRINTED_is_not_a_crash():
    """A program that catches its own exception and calls traceback.print_exc() writes a
    byte-identical block to stderr and then carries on. Unlike the JVM -- where an uncaught
    exception is prefixed "Exception in thread" and printStackTrace is not -- CPython gives the
    two no textual difference at all, so the exit code is the only thing that separates them.
    Reporting the handled one as a crash would turn correct error handling into a finding."""
    text = ('Traceback (most recent call last):\n'
            '  File "svc.py", line 4, in <module>\n'
            'IndexError: list index out of range\n')
    assert sandbox.python_exception(text.encode(), 0) == (None, None, [])
    assert sandbox.python_exception(text.encode(), 1)[0] == "IndexError"


def test_the_staged_target_actually_runs_and_faults(tmp_path):
    """End to end: the defect is only observable if the program ran at all."""
    staged = _staged(tmp_path)
    clean = sandbox.run(staged, stdin=b"ab\n", timeout=30)
    assert clean.crashed is False and clean.exit_code == 0, (
        "a short input must run cleanly: if the interpreter never ran the program, every "
        "result looks the same and the campaign is meaningless")
    boom = sandbox.run(staged, stdin=b"AAAAAAAA\n", timeout=30)
    assert boom.crashed and boom.signal_name == "IndexError"
    assert boom.fault_pc, "a managed fault still needs a site, or two defects dedup into one"


def test_bytecode_for_another_interpreter_reports_a_gap_not_a_crash(tmp_path):
    """The whole reason _PY_NOT_RUNNABLE exists, end to end."""
    staged = _staged(tmp_path)
    data = bytearray(Path(staged).read_bytes())
    data[0:2] = struct.pack("<H", 3495)                 # claim Python 3.10 bytecode
    other = tmp_path / "other.pyc"
    other.write_bytes(bytes(data))
    if (data[0] | (data[1] << 8)) not in pyc._MAGIC_VERSION:
        pytest.skip("3.10's magic is not in the table")
    r = sandbox.run(other, stdin=b"AAAAAAAA\n", timeout=30)
    assert r.crashed is False
    assert "not-runnable" in r.isolation and "could not load" in (r.note or "")


def test_batching_is_refused_for_bytecode(tmp_path):
    """run_batch execs the target directly and traces it with ptrace. A .pyc is not
    executable and the interpreter is not the target, so batching it would run the wrong
    program under breakpoints meant for another."""
    assert sandbox.run_batch(_staged(tmp_path), [b"a", b"b"]) is None
