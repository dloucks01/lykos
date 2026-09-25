"""Language / toolchain fingerprinting: identify Go / Rust / C++ / C binaries and PERSIST it on the
target (it was computed in triage but dropped, so it never reached the UI, report, or analysis). A
real deployment runs on many languages; the label decides what analysis applies (memory-safety
detectors mean little on a bounds-checked Go/Rust binary)."""
from __future__ import annotations

import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.elf import parse
from lykos.analyze.ingest import ingest, enqueue_triage
from lykos.db.dao import TargetDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


@pytest.fixture
def x86_64_only():
    if sandbox.host_arch() != "x86-64":
        pytest.skip("native x86-64 only")


def _build(tool, src_name, src, out, tmp, *args):
    if not shutil.which(tool):
        pytest.skip(f"no {tool}")
    (tmp / src_name).write_text(src)
    exe = tmp / out
    if subprocess.run([tool, *args, str(tmp / src_name), "-o", str(exe)],
                      capture_output=True, cwd=str(tmp)).returncode != 0:
        pytest.skip(f"{tool} build failed")
    return exe


def test_detect_c_and_cpp(tmp_path, x86_64_only):
    cc = _build("gcc", "c.c", "int main(){return 0;}\n", "cbin", tmp_path)
    assert parse(cc.read_bytes()).toolchain_hint in ("gcc", "clang")
    cxx = _build("g++", "c.cpp", "#include <string>\n#include <iostream>\n"
                 "int main(){ std::string s=\"x\"; std::cout<<s; return 0; }\n", "cppbin", tmp_path)
    assert parse(cxx.read_bytes()).toolchain_hint == "c++"


def test_detect_go(tmp_path, x86_64_only):
    go = _build("go", "m.go", "package main\nimport \"fmt\"\nfunc main(){ fmt.Println(\"x\") }\n",
                "gobin", tmp_path, "build")
    assert parse(go.read_bytes()).toolchain_hint == "go"


def test_detect_rust(tmp_path, x86_64_only):
    rs = _build("rustc", "m.rs", "fn main(){ println!(\"{}\", std::env::args().count()); }\n",
                "rustbin", tmp_path)
    assert parse(rs.read_bytes()).toolchain_hint == "rust"


def test_toolchain_hint_persisted(store, case, tmp_path, x86_64_only):
    register()
    cxx = _build("g++", "c.cpp", "#include <string>\nint main(){ std::string s=\"x\"; return s.size(); }\n",
                 "cppbin", tmp_path)
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, case.id, cxx, filename="cppbin")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True); assert pool.wait_idle(40)
        assert TargetDAO(store.conn).get(t.id).toolchain_hint == "c++"   # survives the DB round-trip
    finally:
        pool.stop(grace=3.0)
