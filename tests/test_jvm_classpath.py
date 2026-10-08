"""Running a bare .class: the class name comes from the BYTECODE, not the file name.

Every stage stages the target under a generic name (`target.bin`). The launcher derived the class
name from the file stem, so the JVM answered `Could not find or load main class target` and the
program never ran -- on every execution, while the campaign recorded each as a non-crash and
reported a clean zero. A measured fuzz campaign did 274 executions and found 0 crashes against a
target that faults on almost any input, entirely because of this.
"""
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from lykos.analyze.dynamic import sandbox

_INDEXED_BY_INPUT_LENGTH = (
    "public class Idx{public static void main(String[] a)throws Exception{"
    "java.io.BufferedReader r=new java.io.BufferedReader("
    "new java.io.InputStreamReader(System.in));String s=r.readLine();"
    "if(s==null)s=\"\";int[] t=new int[4];int i=s.length();"
    "System.out.println(\"slot \"+i+\" = \"+t[i]);}}\n")


def _compile(tmp_path, body=_INDEXED_BY_INPUT_LENGTH):
    if shutil.which("javac") is None:
        pytest.skip("javac not installed")
    src = tmp_path / "Idx.java"
    src.write_text(body)
    if subprocess.run(["javac", src.name], cwd=str(tmp_path),
                      capture_output=True).returncode != 0:
        pytest.skip("javac could not compile here")
    return tmp_path / "Idx.class"


def _staged(tmp_path):
    """The target as a stage actually writes it: content-addressed under a generic name."""
    cls = _compile(tmp_path)
    staged = tmp_path / "target.bin"
    shutil.copy(cls, staged)
    return staged


def test_class_name_is_read_from_the_bytecode_not_the_filename(tmp_path):
    cpdir, name = sandbox._jvm_class_entry(_staged(tmp_path), None)
    assert name == "Idx", "the class name must come from this_class, not the file stem"
    # and the file has to be laid out where the JVM will actually look for it
    assert (Path(cpdir) / "Idx.class").exists()


def test_a_correctly_named_class_is_left_where_it_sits(tmp_path):
    cls = _compile(tmp_path)
    cpdir, name = sandbox._jvm_class_entry(cls, None)
    assert name == "Idx" and cpdir == str(tmp_path)


def test_an_explicit_main_class_wins(tmp_path):
    _cp, name = sandbox._jvm_class_entry(_staged(tmp_path), "Idx")
    assert name == "Idx"


def test_unparseable_bytecode_falls_back_to_the_stem(tmp_path):
    # Must degrade, never raise: this is on the hot path of every JVM execution.
    junk = tmp_path / "Whatever.class"
    junk.write_bytes(struct.pack(">I", 0xCAFEBABE) + b"\x00" * 8)
    cpdir, name = sandbox._jvm_class_entry(junk, None)
    assert name == "Whatever" and cpdir == str(tmp_path)


def test_the_staged_target_actually_runs_and_faults(tmp_path):
    """End to end: the defect is only observable if the program ran at all."""
    if shutil.which("java") is None:
        pytest.skip("no JVM installed")
    staged = _staged(tmp_path)
    clean = sandbox.run(staged, stdin=b"ab\n", timeout=40)
    assert clean.crashed is False and clean.exit_code == 0, (
        "a short input must run cleanly -- a launch failure also looks like 'no crash', which is "
        "the whole bug this guards")
    boom = sandbox.run(staged, stdin=b"AAAAAAAA\n", timeout=40)
    assert boom.crashed and boom.signal_name == "ArrayIndexOutOfBoundsException"
