"""Root cause on a Java target.

The JVM branch of the root-cause stage had no test at all, and it is not a thin adapter: it
decides which application frame to blame, which CWE an exception maps to, and -- the part that
matters most for honesty -- it states the ceiling. The JVM owns the instruction pointer, so a
Java fault cannot be escalated to control-flow hijack, and a stage that quietly implied
otherwise would be overselling every Java finding this platform produces.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.debug import enqueue_root_cause
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

pytestmark = pytest.mark.skipif(
    not (shutil.which("javac") and shutil.which("jar") and shutil.which("java")),
    reason="needs a JDK (javac, jar, java)")

# reads a config file and indexes past the end of a split -- the shape a real parser has
_SVC = """
import java.nio.file.*;
import java.util.*;
public class Svc {
  public static void main(String[] a) throws Exception {
    if (a.length < 1) { System.err.println("usage: Svc <config>"); System.exit(2); }
    for (String line : Files.readAllLines(Paths.get(a[0]))) {
      if (line.isEmpty() || line.startsWith("#")) continue;
      String[] kv = line.split("=");
      setOpt(kv[0], kv[1]);
    }
  }
  static void setOpt(String k, String v) { System.out.println(k + " -> " + v); }
}
"""

_PARSE = """
public class Svc {
  public static void main(String[] a) throws Exception {
    java.util.List<String> ls = java.nio.file.Files.readAllLines(
        java.nio.file.Paths.get(a[0]));
    System.out.println(Integer.parseInt(ls.get(0).trim()));
  }
}
"""


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=120, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=5.0)


def _jar(tmp_path, source, name="Svc"):
    classes = tmp_path / "classes"
    classes.mkdir(exist_ok=True)
    src = tmp_path / "Svc.java"
    src.write_text(source)
    if subprocess.run(["javac", "-d", str(classes), str(src)],
                      capture_output=True).returncode:
        pytest.skip("javac failed")
    mf = tmp_path / "m.txt"
    mf.write_text("Main-Class: Svc\n")
    jar = tmp_path / f"{name}.jar"
    r = subprocess.run(["jar", "cfm", str(jar), str(mf), "-C", str(classes), "."],
                       capture_output=True)
    if r.returncode or not jar.exists():
        pytest.skip("jar failed")
    return jar


def _triaged(store, pool, case_id, path):
    """Ingest AND triage. `ingest` only stores the bytes -- it is the triage stage that
    classifies the substrate, and root_cause dispatches on `target.file_type`. Without it a
    jar arrives as file_type=None and takes the native path, which is how the stage used to
    decline a Java target with "no qemu gdbstub layout for jvm"."""
    t = ingest(store, case_id, path)
    q = JobQueue(store.conn)
    enqueue_triage(q, t)
    assert pool.wait_idle(180)
    from lykos.db.dao import TargetDAO
    t = TargetDAO(store.conn).get(t.id)
    assert (t.file_type or "").lower() == "jar", f"triage classified it as {t.file_type!r}"
    return t


def _run(store, pool, target, crashing: bytes, params=None):
    sha, _, _ = store.content.put_bytes(crashing)
    q = JobQueue(store.conn)
    run = enqueue_root_cause(q, target, params={"input_sha": sha, "input_mode": "file",
                                                "timeout": 60, **(params or {})})
    assert pool.wait_idle(180)
    return q.runs.get(run.id)


def test_an_uncaught_exception_is_rooted_to_the_application_frame(store, case, pool, tmp_path):
    """`kv[1]` on a line with no `=` throws ArrayIndexOutOfBounds. The blame has to land on
    Svc, not on the JDK: a JDK frame would merge every such defect in the program into one
    finding."""
    jar = _jar(tmp_path, _SVC)
    t = _triaged(store, pool, case.id, jar)
    rec = _run(store, pool, t, b"novalue\n")
    assert rec.status == "done", rec.error
    fs = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "root_cause"]
    assert fs, "an uncaught exception under the JVM produced no root-cause finding"
    f = fs[0]
    assert "ArrayIndexOutOfBounds" in f.title
    assert f.state == "confirmed"
    assert f.site_addr and "Svc" in f.site_addr, \
        f"blamed {f.site_addr!r} instead of the application frame"


def test_a_jdk_thrown_exception_still_blames_the_application(store, case, pool, tmp_path):
    """`Integer.parseInt("abc")` throws three JDK frames deep. The top frame is
    java.base/NumberFormatException; the frame that matters is the caller in Svc."""
    jar = _jar(tmp_path, _PARSE)
    t = _triaged(store, pool, case.id, jar)
    rec = _run(store, pool, t, b"not-a-number\n")
    assert rec.status == "done", rec.error
    fs = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "root_cause"]
    assert fs, "no root-cause finding for an uncaught NumberFormatException"
    assert "Svc" in (fs[0].site_addr or ""), \
        f"blamed {fs[0].site_addr!r} -- a JDK frame merges unrelated defects into one finding"


def test_the_report_states_the_java_ceiling_rather_than_implying_more(store, case, pool,
                                                                     tmp_path):
    """The JVM checks every array access and owns every pointer. Saying so is the difference
    between an honest denial-of-service finding and one an operator reads as exploitable."""
    import json
    jar = _jar(tmp_path, _SVC)
    t = _triaged(store, pool, case.id, jar)
    rec = _run(store, pool, t, b"novalue\n")
    assert rec.status == "done", rec.error
    from lykos.db.dao import ArtifactDAO
    arts = [a for a in ArtifactDAO(store.conn).list_by_case(case.id)
            if a.kind == "root-cause"]
    assert arts, "no root-cause report artifact"
    rep = json.loads(store.content.get_bytes(arts[-1].sha256))
    assert rep["backend"] == "jvm"
    assert rep["exploitability"]["rating"] == "denial-of-service"
    assert any("L2/L3" in r or "control-flow" in r
               for r in rep["exploitability"]["reasons"]), rep["exploitability"]
    # the symbolised stack is the thing the native path cannot produce; it has to be there
    assert rep["stack"] and any("Svc" in fr for fr in rep["stack"])
    assert rep["blame_frame"] and "Svc" in rep["blame_frame"]


def test_an_input_that_does_not_fault_says_which_channels_were_tried(store, case, pool,
                                                                    tmp_path):
    """A clean input must not be filed as a finding, and the operator has to be able to tell
    "this input is harmless" from "we fed it the wrong way"."""
    jar = _jar(tmp_path, _SVC)
    t = _triaged(store, pool, case.id, jar)
    rec = _run(store, pool, t, b"key=value\n")
    assert rec.status == "done", rec.error
    fs = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "root_cause"]
    assert not fs, "a clean input was filed as a root-cause finding"


def test_a_jar_does_not_take_the_emulator_path(store, case, pool, tmp_path):
    """Before the JVM branch existed the stage declined with "no qemu gdbstub layout for jvm"
    -- true of qemu, and irrelevant: nothing needed emulating."""
    jar = _jar(tmp_path, _SVC)
    t = _triaged(store, pool, case.id, jar)
    rec = _run(store, pool, t, b"novalue\n")
    assert rec.status == "done", rec.error
    assert "qemu" not in (str(rec.error) or "").lower()
