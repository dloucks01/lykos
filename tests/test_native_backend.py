"""Phase-1 (doc 24) native RE backend: rizin/radare2 + pypcode instead of Ghidra+JVM.

Proves the swap preserves the pipeline: the native backend must produce the same analysis
schema Ghidra does -- functions with real Ghidra **P-Code** per instruction and recovered
stack frames -- so the existing detectors run unchanged and still flag the bug. Skips cleanly
where the native tools are absent, exactly like the Ghidra path skips without Ghidra.
"""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze import native_re, register
from lykos.analyze.detect.stage import enqueue_detect
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import FindingDAO, FunctionDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_HAVE_NATIVE = native_re.locate_native() is not None
try:
    import pypcode  # noqa: F401
    _HAVE_PYPCODE = True
except Exception:
    _HAVE_PYPCODE = False

pytestmark = pytest.mark.skipif(
    not (_HAVE_NATIVE and _HAVE_PYPCODE),
    reason="native RE backend needs rizin/radare2 + pypcode")

_VULN = (
    "#include <string.h>\n#include <stdio.h>\n"
    "void bug(char *in){ char buf[16]; strcpy(buf, in); puts(buf); }\n"
    "int main(int c, char **v){ if (c > 1) bug(v[1]); return 0; }\n"
)


@pytest.fixture
def vuln_bin(gcc, tmp_path):
    src = tmp_path / "v.c"
    src.write_text(_VULN)
    out = tmp_path / "vuln"
    subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-g", str(src),
                    "-o", str(out)], check=True, capture_output=True)
    return out


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=1, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_native_backend_produces_ghidra_pcode(vuln_bin):
    """Unit-level: the backend emits real Ghidra P-Code in the detector's string format, plus
    a recovered char[] buffer -- the two things bounds/taint/int-overflow actually consume."""
    res = native_re.analyze(vuln_bin, timeout=180)
    assert res["function_count"] >= 3
    bug = next((f for f in res["functions"] if "bug" in (f["name"] or "")), None)
    assert bug, "bug() not recovered"

    # a char[16] stack buffer, flagged is_buffer -- what the bounds detector keys on
    assert any(v["is_buffer"] and "[" in (v["type"] or "") for v in bug["frame"]["vars"])

    pcode = [pc for b in bug["cfg"]["blocks"] for i in b["instructions"] for pc in i["pcode"]]
    assert pcode, "no P-Code emitted"
    # real Ghidra ops in the exact format the detectors parse (MNEMONIC ... -> out)
    assert any(pc.startswith(("INT_", "COPY", "LOAD", "STORE")) for pc in pcode)
    assert any(pc.startswith("CALL") for pc in pcode)
    # register/const varnode encoding the detectors depend on
    assert any("reg:" in pc for pc in pcode) and any("const:" in pc for pc in pcode)


def test_infer_buffers_from_stack_geometry():
    """A large stack local with no recovered array type is still marked a buffer, sized from the
    gap to the next-higher local. This is what lets the stack-smash detector fire on a stripped or
    undecompiled binary (a whole VxWorks kernel had 6000+ frames and ZERO typed buffers)."""
    # offsets are negative bp-relative; -0x40 slot spans to -0x10 (48 bytes) -> buffer, -0x10 to
    # -0x8 (8 bytes) -> not a buffer, -0x8 to 0 (8 bytes) -> not.
    vars_ = [{"name": "big", "type": "int32_t", "offset": -0x40, "is_buffer": False},
             {"name": "p1", "type": "void*", "offset": -0x10, "is_buffer": False},
             {"name": "p2", "type": "int32_t", "offset": -0x8, "is_buffer": False}]
    out = native_re._infer_buffers(vars_)
    big = next(v for v in out if v["name"] == "big")
    assert big["is_buffer"] and big.get("buffer_inferred") and big["size"] == 0x30
    assert not any(v["is_buffer"] for v in out if v["name"] in ("p1", "p2"))
    # an already-typed array is left as a (non-inferred) buffer
    typed = native_re._infer_buffers([{"name": "b", "type": "char [64]", "offset": -0x50,
                                       "is_buffer": True}])
    assert typed[0]["is_buffer"] and not typed[0].get("buffer_inferred")


def test_analyze_is_exhaustive_and_reports_completeness(vuln_bin):
    """analyze() carries honest completeness bookkeeping and, by default, caps nothing."""
    res = native_re.analyze(vuln_bin, timeout=180)
    assert res["partial"] in (False, 0) and res["failed_batches"] == 0
    assert res["analyzed_functions"] == res["function_count"] == res["total_functions"]


def test_native_disassemble_then_detect_finds_the_overflow(store, case, pool, vuln_bin,
                                                            monkeypatch):
    """End-to-end through the real pipeline with the native backend selected: ingest ->
    disassemble (rizin/r2 + pypcode, no JVM) -> detect_cwe must persist P-Code-bearing
    functions and land a memory-safety finding on the strcpy sink."""
    monkeypatch.setenv("LYKOS_DECOMPILER", "native")

    target = ingest(store, case.id, vuln_bin, filename="vuln")
    q = JobQueue(store.conn)
    enqueue_triage(q, target, force=True)
    assert pool.wait_idle(30)
    enqueue_disassemble(q, target, force=True)
    assert pool.wait_idle(60)

    funcs = FunctionDAO(store.conn).list_by_target(target.id)
    assert len(funcs) >= 3, "native disassemble recovered no functions"
    # at least one function carries real P-Code in the DB (what detect reads back)
    dao = FunctionDAO(store.conn)
    pcoded = 0
    for f in funcs:
        full = dao.get(f.id)
        for b in ((full.ir or {}).get("blocks") or []):
            for i in b.get("instructions", []):
                if i.get("pcode"):
                    pcoded += 1
    assert pcoded, "no P-Code persisted from the native backend"

    enqueue_detect(q, target, force=True)
    assert pool.wait_idle(60)

    findings = FindingDAO(store.conn).list_by_target(target.id)
    assert findings, "detect produced no findings on a strcpy overflow"
    mem_cwes = {"CWE-120", "CWE-121", "CWE-119", "CWE-787", "CWE-125", "CWE-134"}
    assert any((f.cwe in mem_cwes) or (f.detector in ("dangerous_api", "bounds"))
               for f in findings), \
        "no memory-safety finding: %s" % [(f.cwe, f.detector) for f in findings]


def test_run_delivers_script_via_file_not_argv(monkeypatch):
    """Regression: a statically linked sanitizer build carries thousands of functions, so the
    per-function disassemble script grows past ARG_MAX and an inline `-c <script>` argv raised
    OSError(E2BIG, 'Argument list too long'), taking `disassemble` -- and the whole analysis --
    down on every ASan source target. The script must be delivered through a file (`-i`), whose
    contents are the script and which is itself not a command-line argument."""
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = list(cmd)
        i = cmd.index("-i")
        captured["script"] = open(cmd[i + 1]).read()   # must exist AT CALL TIME
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(native_re.subprocess, "run", fake_run)
    big = ";".join("s 0x%x" % a for a in range(200000))   # multi-MB: would overflow an inline argv
    native_re._run(native_re.Path("/bin/true"), native_re.Path("/bin/true"), big, timeout=5)
    cmd = captured["cmd"]
    assert "-i" in cmd and "-c" not in cmd
    assert big not in cmd                                  # the script is NOT passed as an argv
    assert captured["script"] == big
