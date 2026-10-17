"""Phase 6 — PoC bundle build + self-verification + poc-backed promotion."""
import io
import subprocess
import tarfile

import pytest
from lykos.analyze import register
from lykos.analyze.ingest import ingest
from lykos.analyze.poc import bundle
from lykos.analyze.poc.stage import enqueue_build_poc
from lykos.db.dao import FindingDAO, PocDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_CRASH_ON_A = ("#include <unistd.h>\nint main(){char b[64];int n=read(0,b,63);"
               "for(int i=0;i<n;i++) if(b[i]=='A'){volatile int*p=0;*p=1;}return 0;}\n")
_OK = "#include <unistd.h>\nint main(){char b[64];read(0,b,63);return 0;}\n"


@pytest.fixture(scope="module")
def bins(gcc, tmp_path_factory):
    d = tmp_path_factory.mktemp("pocbins")
    out = {}
    for name, src in (("crash", _CRASH_ON_A), ("ok", _OK)):
        c = d / (name + ".c"); c.write_text(src)
        b = d / name
        if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True).returncode == 0:
            out[name] = b
    return out


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=30, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_bundle_contents():
    data = bundle.build(b"\x7fELFbinary", b"AAAA", {"target_sha256": "abc", "arch": "x86-64"},
                        b"stack smashing detected", "stdin", [], "SIGSEGV")
    names = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        names = set(t.getnames())
        runner = t.extractfile("poc/runner.sh").read()
        inp = t.extractfile("poc/input.bin").read()
    assert {"poc/target.bin", "poc/input.bin", "poc/runner.sh", "poc/meta.json",
            "poc/README.txt"}.issubset(names)
    assert inp == b"AAAA" and b"input.bin" in runner


def test_bundle_readme_is_actionable():
    data = bundle.build(b"\x7fELFbin", b"AAAA", {"target_sha256": "abc", "arch": "x86-64",
                        "level": "L2"}, b"", "stdin", [], "SIGSEGV")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        readme = t.extractfile("poc/README.txt").read().decode()
    for section in ("WHAT THIS IS", "HOW TO RUN", "WHAT TO DO WITH IT", "FILES"):
        assert section in readme
    assert "sandbox" in readme.lower() and "sh ./runner.sh" in readme
    assert "PRIMITIVE" in readme      # L2 -> mentions the primitive


def test_script_bundle_ships_exploit_py_and_runs_it():
    """A leak-based (PIE) bundle carries a live exploit.py reproducer, and the runner runs it
    (a static payload can't re-hijack under fresh ASLR)."""
    script = b"#!/usr/bin/env python3\nprint('demo')\n"
    data = bundle.build(b"\x7fELFbin", b"payload", {"target_sha256": "abc", "arch": "x86-64",
                        "level": "L3"}, b"", "stdin", [], "SIGSEGV",
                        extra_files={"exploit.py": script},
                        run_cmd="python3 ./exploit.py ./target.bin")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        assert "poc/exploit.py" in t.getnames()
        runner = t.extractfile("poc/runner.sh").read().decode()
        readme = t.extractfile("poc/README.txt").read().decode()
    assert "python3 ./exploit.py" in runner
    assert "exploit.py" in readme and "ASLR" in readme


def test_build_poc_verifies_and_promotes(store, case, pool, bins):
    if "crash" not in bins:
        pytest.skip("build failed")
    target = ingest(store, case.id, bins["crash"])
    input_sha = store.put_artifact(case.id, "fuzz-crash-input", data=b"AAAA").sha256

    q = JobQueue(store.conn)
    run = enqueue_build_poc(q, target, params={"input_sha": input_sha, "input_mode": "stdin"})
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"

    pocs = PocDAO(store.conn).list_by_target(target.id)
    assert pocs and pocs[0].verified and pocs[0].level == "L1"
    assert pocs[0].bundle_sha
    # the bundle is a real, retrievable archive
    data = store.content.get_bytes(pocs[0].bundle_sha)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        assert "poc/target.bin" in t.getnames()

    pb = [f for f in FindingDAO(store.conn).list_by_target(target.id) if f.state == "poc-backed"]
    assert pb and any(e["channel"] == "poc" for e in pb[0].evidence)
    # the PoC row is linked to its finding so the report can attach the bundle (Phase 7)
    assert pocs[0].finding_id == pb[0].id


def test_build_poc_unverified_when_no_crash(store, case, pool, bins):
    if "ok" not in bins:
        pytest.skip("build failed")
    target = ingest(store, case.id, bins["ok"])
    input_sha = store.put_artifact(case.id, "fuzz-crash-input", data=b"AAAA").sha256
    q = JobQueue(store.conn)
    run = enqueue_build_poc(q, target, params={"input_sha": input_sha, "input_mode": "stdin"})
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"
    pocs = PocDAO(store.conn).list_by_target(target.id)
    assert pocs and not pocs[0].verified and pocs[0].level == "L0"
    assert not [f for f in FindingDAO(store.conn).list_by_target(target.id)
                if f.state == "poc-backed"]


def test_build_poc_forwards_endianness_and_bits(store, case, pool, monkeypatch, bins):
    """_qemu_for routes ppc64->ppc64le, mips->mipsel and riscv->riscv32/64 on endianness and
    bits. build_poc omitted both, so a little-endian ppc64 target was handed the BIG-endian
    emulator, could not run, produced no crash, and was filed as an unverified L0 instead of
    a verified L1 -- silently, since "did not reproduce" is a legitimate outcome.
    """
    if "crash" not in bins:
        pytest.skip("no C compiler")
    from lykos.analyze.poc import stage as poc_stage

    seen = {}
    real = poc_stage.sandbox.run

    def spy(exe, **kw):
        seen.update(kw)
        return real(exe, **kw)

    monkeypatch.setattr(poc_stage.sandbox, "run", spy)

    t = ingest(store, case.id, bins["crash"], filename="crash")
    store.targets.update_triage(t.id, arch="ppc64", endianness="little", bits=64)
    sha = store.put_artifact(case.id, "seed", data=b"A" * 64).sha256
    q = JobQueue(store.conn)
    enqueue_build_poc(q, t, params={"input_sha": sha, "input_mode": "stdin"})
    assert pool.wait_idle(60)

    assert seen.get("endianness") == "little", "build_poc dropped endianness"
    assert seen.get("bits") == 64, "build_poc dropped bits"


def _member(data: bytes, name: str) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return tar.extractfile(name).read()


def test_a_guard_page_bundle_carries_the_preload_and_says_why():
    """A crash found under the guard-page allocator is SILENT without one.

    The project's rule is that a verified PoC reproduces, so the preload has to travel with the
    crash. The library belongs to AFL++ and is not ours to redistribute, so the runner looks for
    it and -- this is the part that matters -- says plainly that the defect does not fault on its
    own when it is missing, instead of exiting 0 and reading as a broken reproducer.
    """
    data = bundle.build(b"\x7fELFbin", b"AAAA", {"target_sha256": "abc", "arch": "x86-64"},
                        b"", "stdin", [], "SIGSEGV",
                        guard_page="/usr/lib/afl/libdislocator.so")
    sh = _member(data, "poc/runner.sh").decode()
    assert "libdislocator.so" in sh and "LD_PRELOAD" in sh
    assert "LYKOS_GUARD_PAGE" in sh, "the operator can point it at their own copy"
    assert "does NOT fault on its own" in sh
    # and a bundle for an ordinary crash says nothing about any of it
    plain = bundle.build(b"\x7fELFbin", b"AAAA", {"target_sha256": "abc", "arch": "x86-64"},
                         b"", "stdin", [], "SIGSEGV")
    assert "LD_PRELOAD" not in _member(plain, "poc/runner.sh").decode()


# ------------------------------------------------- a managed PoC is a deliverable or it is nothing
def _unpack(data):
    import io
    import pathlib
    import tarfile
    import tempfile
    out = pathlib.Path(tempfile.mkdtemp())
    tarfile.open(fileobj=io.BytesIO(data)).extractall(out, filter="data")
    return next(d for d in out.iterdir() if (d / "runner.sh").exists())


def test_every_runtime_gets_a_runner_it_can_actually_execute():
    """`poc/stage` mapped two runtimes -- jar and class -- so a .pyc, a .NET assembly and a WASM
    module fell through to "native" and the reproducer said `./target.bin < ./input.bin`: a file
    the shell cannot execute. The fault was reproduced and the DELIVERABLE was broken, which is
    most of why those substrates read as identification-only in the coverage matrix."""
    from lykos.analyze.poc import bundle
    want = {"pyc": "python3", "dotnet": "dotnet ./app.dll", "wasm": "wasm_driver.js",
            "class": "java -cp", "native": "./target.bin"}
    for runtime, needle in want.items():
        root = _unpack(bundle.build(b"\x00", b"A", {"level": "L1"}, b"", "stdin", [], "SIGSEGV",
                                    runtime=runtime, main_class="Idx"))
        runner = (root / "runner.sh").read_text()
        assert needle in runner, f"{runtime}: {needle!r} missing from runner.sh"
    # the WASM host travels with the bundle: a module is not a process
    root = _unpack(bundle.build(b"\x00", b"A", {"level": "L1"}, b"", "stdin", [], "trap",
                                runtime="wasm"))
    assert (root / "wasm_driver.js").exists()


def test_the_bundle_says_how_to_judge_its_own_result():
    """A reproducer's exit status means different things per runtime -- 128+signum for a native
    crash, 1 for an uncaught JVM or CPython exception, 134 for a .NET abort, and 0 for a WASM
    module that trapped (node exits cleanly; the verdict is in report.json). Anything checking a
    bundle mechanically has to be told which, and the one consumer that does -- the conformance
    gate -- required >=128 and would have called a good managed reproducer broken."""
    import json

    from lykos.analyze.poc import bundle
    for runtime, exit_kind in (("native", "signal"), ("class", "nonzero"), ("pyc", "nonzero"),
                               ("dotnet", "nonzero"), ("wasm", "any")):
        root = _unpack(bundle.build(b"\x00", b"A", {"level": "L1"}, b"", "stdin", [], "SIGSEGV",
                                    runtime=runtime, main_class="Idx"))
        m = json.loads((root / "meta.json").read_text())
        assert m["runtime"] == runtime
        assert m["verdict"]["exit"] == exit_kind, (runtime, m["verdict"])
    # ...and the gate reads that instead of assuming a signal
    import inspect
    import pathlib
    import sys
    tools = pathlib.Path(__file__).resolve().parents[1] / "tools"
    if str(tools) not in sys.path:
        sys.path.insert(0, str(tools))
    import pipeline_conformance as pc
    src = inspect.getsource(pc._bundle_reproduces)
    assert 'want_exit == "nonzero"' in src and 'want_exit == "any"' in src
    assert 'verdict.get("exit")' in src


def test_a_pyc_poc_bundle_reproduces_for_real(tmp_path):
    """End to end on a real .pyc: build the bundle, unpack it into a fresh directory, run its own
    runner.sh, and require the runtime's own criterion -- a non-zero exit with a traceback."""
    import json
    import py_compile
    import subprocess

    from lykos.analyze.poc import bundle
    src = tmp_path / "idx.py"
    src.write_text("import sys\ns = sys.stdin.readline().rstrip('\\n')\nt = [0,1,2,3]\n"
                   "print('slot', len(s), '=', t[len(s)])\n")
    pyc = py_compile.compile(str(src), cfile=str(tmp_path / "idx.pyc"), doraise=True)
    root = _unpack(bundle.build(open(pyc, "rb").read(), b"AAAAAAAA\n",
                                {"level": "L1"}, b"", "stdin", [], "IndexError", runtime="pyc"))
    r = subprocess.run(["sh", "./runner.sh"], cwd=str(root), capture_output=True, timeout=60)
    m = json.loads((root / "meta.json").read_text())
    txt = (r.stdout + r.stderr).decode("utf-8", "replace")
    assert r.returncode != 0 and m["verdict"]["stderr"] in txt, txt[-300:]
