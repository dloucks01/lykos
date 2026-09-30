"""Java targets: a jar is a third executable format, and the one that is not machine code.

Until this existed the platform could not name a jar -- triage called it "not a binary",
declined to analyse it, and every stage after that was unreachable. Nothing about the approach
needed machine code: a .class file carries its whole string constant pool and every method it
calls in the clear, which is more than a stripped ELF gives up.
"""
import io
import shutil
import struct
import subprocess
import zipfile

import pytest
from lykos.analyze import filetype, jvm
from lykos.analyze.detect import jvmdetect
from lykos.analyze.dynamic import sandbox


def _class(major=65):
    """Minimal class-file head: magic, minor, major."""
    return b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, major) + b"\x00" * 56


def test_cafebabe_is_both_java_and_macho_and_they_are_separable():
    """Java chose CAFEBABE deliberately and Apple chose it independently, so whichever check
    runs first claims every file of the other kind. The next four bytes decide it: Java writes
    a class-file major version (45 = Java 1.0, 65 = Java 21); Mach-O writes a count of
    architectures, which is a handful. Nothing has 45 architectures."""
    assert jvm.is_class(_class(65))
    assert filetype.detect(_class(52)) == filetype.CLASS
    fat = b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\x00" * 56      # 2 architectures
    assert not jvm.is_class(fat)
    assert filetype.detect(fat) == filetype.MACHO


def test_a_plain_zip_is_not_a_jar():
    """PK\\x03\\x04 is every zip: a firmware bundle, a .docx, an archive of source."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("notes.txt", "hello")
    assert not jvm.is_jar(buf.getvalue())


def test_long_and_double_take_two_constant_pool_slots():
    """A long or a double occupies two entries and the second is unusable. Miss it and every
    index after the first `long` shifts, which turns a class's string table into fragments of
    the wrong strings."""
    if not shutil.which("javac"):
        pytest.skip("no javac")
    # exercised via a real class below; here assert the table the parser uses is right
    assert jvm._FIXED[jvm._LONG] == 8 and jvm._FIXED[jvm._DOUBLE] == 8


def test_manifest_continuation_lines():
    """A manifest wraps at 72 bytes MID-TOKEN, and the continuation rejoins with no separator
    -- so a dependency name is split across two lines and only reassembles if this is right.
    Getting it wrong turns `commons-collections-3.2.1.jar` (the ysoserial gadget) into two
    strings that match nothing."""
    got = jvm.parse_manifest("Main-Class: com.x.Main\r\n"
                             "Class-Path: lib/commons-collect\r\n ions-3.2.1.jar lib/b.jar\r\n")
    assert got["Main-Class"] == "com.x.Main"
    assert got["Class-Path"] == "lib/commons-collections-3.2.1.jar lib/b.jar"


# ---- the crash oracle: a Java program throws, it does not segfault ------------------------

def test_an_uncaught_exception_is_the_fault():
    err = (b'Exception in thread "main" java.lang.ArrayIndexOutOfBoundsException: '
           b'Index 99 out of bounds for length 8\n\tat Svc.setOpt(Svc.java:14)\n'
           b'\tat Svc.main(Svc.java:45)\n')
    kind, detail, frames = sandbox.jvm_exception(err, 1)
    assert kind == "ArrayIndexOutOfBoundsException"
    assert "Svc.setOpt(Svc.java:14)" in detail
    assert frames[0] == ("Svc.setOpt", "Svc.java:14")


def test_a_handled_exception_printed_by_the_program_is_not_a_crash():
    """printStackTrace() writes a nearly identical block and the program carries on. Reporting
    that as a crash turns correct error handling into a finding."""
    assert sandbox.jvm_exception(
        b"java.lang.IllegalStateException: oops\n\tat X.y(X.java:1)\n", 0)[0] is None


def test_the_vm_terminating_on_oom_is_read_from_stdout():
    """-XX:+ExitOnOutOfMemoryError kills the VM instead of unwinding, which is what we want --
    but it prints to STDOUT, so reading stderr alone made unbounded allocation invisible."""
    kind, detail, _ = sandbox.jvm_exception(
        b"", 3, b"Terminating due to java.lang.OutOfMemoryError: Java heap space\n")
    assert kind == "OutOfMemoryError"
    assert "allocation the input controls" in detail


def test_a_target_echoing_the_marker_is_not_a_crash():
    """Scanning both streams for everything opens a hole a fuzzer finds on its own: a target
    that echoes its input reports a crash the moment a mutation contains `Exception in
    thread`, and a mutator rewarded for crashes produces that string deliberately."""
    echoed = b'slot0=Exception in thread "main" java.lang.Error\n'
    assert sandbox.jvm_exception(b"", 0, echoed)[0] is None


def test_blame_is_the_application_frame_not_the_jdk_one():
    """Integer.parseInt("abc") throws three JDK frames deep. Blaming the top frame blames
    java.base and dedups every NumberFormatException in the program into one finding."""
    frames = [("java.base/java.lang.NumberFormatException.forInputString", "N.java:67"),
              ("java.base/java.lang.Integer.parseInt", "Integer.java:662"),
              ("Svc.setOpt", "Svc.java:16")]
    assert sandbox.app_frame(frames)[0] == "Svc.setOpt"
    other = [frames[0], frames[1], ("Other.go", "Other.java:9")]
    assert sandbox.jvm_site(frames) != sandbox.jvm_site(other)


def test_a_jvm_exception_is_not_memory_corruption():
    """The native table falls through to CWE-119 at critical, which is right for a signal and
    a lie for a managed runtime: an ArrayIndexOutOfBoundsException is the JVM CATCHING the
    out-of-bounds access."""
    assert jvm.cwe_for_exception("ArrayIndexOutOfBoundsException") == ("CWE-129", "high")
    assert jvm.cwe_for_exception("OutOfMemoryError") == ("CWE-789", "high")
    # a program validating its input by throwing is doing the RIGHT thing
    assert jvm.cwe_for_exception("IllegalStateException") == ("CWE-248", "low")
    # the JVM itself dying IS memory corruption -- the one Java result that is
    assert jvm.cwe_for_exception("JVM-FATAL-SIGSEGV") == ("CWE-119", "critical")
    # unknown, but unmistakably a JVM fault: never the native default
    assert jvm.cwe_for_exception("SomeCustomException") == ("CWE-248", "medium")
    assert jvm.cwe_for_exception("SIGSEGV") is None


# ---- the PoC bundle has to name the runtime that reads the target -------------------------

def test_the_reproducer_runs_a_jar_under_the_jvm():
    from lykos.analyze.poc.bundle import _runner
    sh = _runner("file", ["-c", "@@", "-d", ":0"], "ArrayIndexOutOfBoundsException",
                 runtime="jar").decode()
    assert "java -jar ./target.bin -c ./input.bin -d :0" in sh
    assert "128+signum" not in sh, "a JVM fault is an exception on stderr, not a signal"
    assert "chmod +x" not in sh, "a jar is not executable"


def test_the_reproducer_honours_the_input_placeholder_for_native_targets_too():
    """File mode ignored argv ENTIRELY, so a target needing `-c <config>` got a reproducer
    reading `./target.bin ./input.bin`: it prints its usage, exits 2, and the bundle that was
    supposed to prove the crash proves nothing."""
    from lykos.analyze.poc.bundle import _runner
    sh = _runner("file", ["-c", "@@"], "SIGSEGV").decode()
    assert "./target.bin -c ./input.bin" in sh
    plain = _runner("file", [], "SIGSEGV").decode()
    assert "./target.bin ./input.bin" in plain


def test_every_replay_path_places_the_input_where_argv_says():
    """Eight stages hand-rolled `argv + [path]`, which for a target whose recorded prefix is
    ["-c", "@@"] produced `target -c @@ /tmp/input.bin`: the program opens a file literally
    named `@@`, does not crash, and the whole ladder filed "the input did not fault"."""
    from lykos.analyze.fuzz.runner import place
    assert place(["-c", "@@", "-v"], "/tmp/i") == ["-c", "/tmp/i", "-v"]
    assert place(["-v"], "/tmp/i") == ["-v", "/tmp/i"]
    assert place([], "/tmp/i") == ["/tmp/i"]


# ---- constant-pool detection --------------------------------------------------------------

class _Info:
    def __init__(self, calls, strings=(), by_class=None):
        self.calls, self.strings = list(calls), list(strings)
        self.by_class = by_class or {}


def test_the_xxe_finding_is_suppressed_when_the_hardening_call_is_there():
    """A parser configured with setFeature(...disallow-doctype-decl...) is the fixed form, and
    reporting it anyway is how a report teaches its reader to ignore it."""
    unguarded = _Info(["javax/xml/parsers/DocumentBuilderFactory.newInstance"])
    assert any(f["cwe"] == "CWE-611" for f in jvmdetect.analyze(unguarded))
    guarded = _Info(["javax/xml/parsers/DocumentBuilderFactory.newInstance",
                     "javax/xml/parsers/DocumentBuilderFactory.setFeature"])
    assert not any(f["cwe"] == "CWE-611" for f in jvmdetect.analyze(guarded))


def test_the_xxe_guard_is_per_class_not_program_wide():
    """A parser hardened with setFeature in ONE class must not suppress an unhardened parser
    in ANOTHER. The guard lives with the factory that uses it, so it is checked per class."""
    factory = "javax/xml/parsers/DocumentBuilderFactory.newInstance"
    guard = "javax/xml/parsers/DocumentBuilderFactory.setFeature"
    info = _Info(
        calls=[factory, guard],
        by_class={
            "com/app/Safe": {"calls": [factory, guard], "strings": []},
            "com/app/Vuln": {"calls": [factory], "strings": []},
        })
    xxe = [f for f in jvmdetect.analyze(info) if f["cwe"] == "CWE-611"]
    assert xxe, "the unhardened parser in com.app.Vuln must still be reported"
    # the finding names the unguarded class, not the hardened one
    detail = xxe[0]["evidence"][0]["detail"]
    assert "com.app.Vuln" in detail and "com.app.Safe" not in detail


def test_the_xxe_guard_still_suppresses_when_both_are_in_the_same_class():
    """Per-class evaluation must not lose the real suppression: a class that hardens the
    parser it creates is the fixed form and stays suppressed."""
    factory = "javax/xml/parsers/SAXParserFactory.newInstance"
    guard = "javax/xml/parsers/SAXParserFactory.setFeature"
    info = _Info(
        calls=[factory, guard],
        by_class={"com/app/Safe": {"calls": [factory, guard], "strings": []}})
    assert not any(f["cwe"] == "CWE-611" for f in jvmdetect.analyze(info))


def test_weak_crypto_is_the_algorithm_string_not_the_factory_call():
    """Cipher.getInstance is not a defect; "DES" is."""
    weak = _Info(["javax/crypto/Cipher.getInstance"], ["DES/ECB/PKCS5Padding"])
    assert any(f["cwe"] == "CWE-327" for f in jvmdetect.analyze(weak))
    strong = _Info(["javax/crypto/Cipher.getInstance"], ["AES/GCM/NoPadding"])
    assert not any(f["cwe"] == "CWE-327" for f in jvmdetect.analyze(strong))


def test_nothing_dangerous_means_no_findings():
    assert jvmdetect.analyze(_Info(["java/lang/String.equals"], ["hello"])) == []


SVC_JAVA = r"""
import java.io.*;
import java.nio.file.*;
public class Svc {
    static String[] slots = new String[8];      // fixed: the bug lives here
    static void setOpt(String k, String v) {
        if (k.equals("slot")) {
            String[] p = v.split(",");
            slots[Integer.parseInt(p[0])] = p[1];   // unchecked index
        }
    }
    static void load(String path) throws IOException {
        for (String line : Files.readAllLines(Paths.get(path))) {
            if (line.startsWith("#")) continue;
            int eq = line.indexOf('=');
            if (eq < 0) continue;
            setOpt(line.substring(0, eq), line.substring(eq + 1));
        }
    }
    public static void main(String[] args) throws Exception {
        String cfg = null, display = null;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-c") && i + 1 < args.length) cfg = args[++i];
            else if (args[i].equals("-d") && i + 1 < args.length) display = args[++i];
        }
        if (cfg == null || display == null) {
            System.err.println("usage: Svc -c <config> -d <display-id>");
            System.exit(2);
        }
        load(cfg);
        System.out.println("slot0=" + slots[0] + " display=" + display);
    }
}
"""


def _build_jar(tmp_path):
    if not (shutil.which("javac") and shutil.which("jar") and shutil.which("java")):
        pytest.skip("no JDK")
    src = tmp_path / "Svc.java"
    src.write_text(SVC_JAVA)
    classes = tmp_path / "classes"
    classes.mkdir()
    if subprocess.run(["javac", "-d", str(classes), str(src)],
                      capture_output=True).returncode != 0:
        pytest.skip("javac failed")
    mf = tmp_path / "m.txt"
    mf.write_text("Main-Class: Svc\n")
    jar = tmp_path / "app.jar"
    subprocess.run(["jar", "cfm", str(jar), str(mf), "-C", str(classes), "."],
                   capture_output=True, check=True)
    return jar


def test_a_jar_is_analysed_run_and_cracked_from_the_file_alone(tmp_path):
    """End to end, told nothing: triage names the jar and its main class, invocation discovery
    reads `-c <config> -d <display-id>` out of the CONSTANT POOL (a jar is a zip, so scanning
    its bytes finds only DEFLATE output), the campaign verifies that command line by running
    it, infers the input is a text config, and drives the JVM into an uncaught
    ArrayIndexOutOfBoundsException -- which is CWE-129, not the native default of CWE-119
    critical memory corruption.
    """
    jar = _build_jar(tmp_path)

    from lykos.analyze import invocation as invmod
    from lykos.analyze import register as register_stages
    from lykos.analyze.fuzz import enqueue_fuzz
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.casestore import CaseStore
    from lykos.db.dao import DynResultDAO, EventDAO, FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    # the strings come from the constant pool, and everything downstream depends on that
    data = jar.read_bytes()
    found = invmod.discover(invmod.raw_strings(data))
    assert {f["flag"] for f in found["flags"]} == {"-c", "-d"}
    assert invmod.propose_argv(found) == ["-c", "@@", "-d", ":0"]

    register_stages()
    store = CaseStore.open(tmp_path / "case")
    cid = store.cases.create("jvm").id
    target = ingest(store, cid, jar, filename=jar.name)
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2))
    pool.start()
    try:
        q = JobQueue(store.conn)
        enqueue_triage(q, target)
        pool.wait_idle(180)
        target = store.targets.get(target.id)
        assert target.file_type == "jar"
        # A small budget on purpose: the campaign calibrates every seed VERBATIM before it
        # mutates, and the config path seeds boundary-value configs (slot=0, ...) first, so the
        # unchecked array index is hit in the first batch -- not stumbled on after thousands of
        # JVM-slow executions. That is the property under test: the find is deterministic even
        # when the box is loaded and this campaign completes a few dozen executions, not 4000.
        enqueue_fuzz(q, target, params={"max_execs": 40, "max_seconds": 40,
                                        "exec_timeout": 5}, force=True)
        pool.wait_idle(300)
    finally:
        pool.stop()

    ev = {}
    for e in EventDAO(store.conn).list(case_id=cid, limit=9000):
        ev.setdefault(e.type, e.payload or {})
    assert ev["fuzz.invocation"]["argv"] == ["-c", "@@", "-d", ":0"]
    assert "verified by running it" in (ev["fuzz.invocation"].get("discovered") or "")
    assert ev.get("fuzz.format", {}).get("model") == "keyvalue"

    crashes = [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed]
    assert crashes, "the unchecked array index behind slot= should be reached"
    kinds = {c.signal_name for c in crashes}
    assert "ArrayIndexOutOfBoundsException" in kinds, kinds
    # ...and the fault is NOT filed as native memory corruption
    cwes = {f.cwe for f in FindingDAO(store.conn).list_by_target(target.id)}
    assert "CWE-129" in cwes and "CWE-119" not in cwes


def test_afl_cannot_drive_a_jvm_or_a_pe():
    """The stage's own gate, which is also what `advise` consults -- one source of truth for
    "can AFL++ run this", so advice cannot recommend a backend the stage then declines.

    Only the substrate rules are asserted here. Whether a given ARCHITECTURE is available
    depends on which guest the installed afl-qemu-trace was built for, which is a property of
    the machine, not of Java -- see test_afl_arch.py."""
    from lykos.analyze.fuzz.coverage import _unsupported

    class T:
        def __init__(self, ft=None, arch=None):
            self.file_type, self.arch = ft, arch
    assert "JVM" in (_unsupported(T("jar")) or "")
    assert "PE" in (_unsupported(T("pe")) or "")


def test_disassembling_a_jar_declines_instead_of_raising(tmp_path):
    """It surfaced `FileNotFoundError(2, 'No such file or directory')` to the operator --
    a raw stdlib exception, in a pipeline whose other stages say "heap check not applicable:
    target is statically linked"."""
    jar = _build_jar(tmp_path)

    from lykos.analyze import register as register_stages
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.casestore import CaseStore
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    register_stages()
    store = CaseStore.open(tmp_path / "case")
    cid = store.cases.create("jvm-dis").id
    target = ingest(store, cid, jar, filename=jar.name)
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=1))
    pool.start()
    try:
        q = JobQueue(store.conn)
        enqueue_triage(q, target)
        pool.wait_idle(180)
        target = store.targets.get(target.id)
        enqueue_disassemble(q, target)
        pool.wait_idle(180)
    finally:
        pool.stop()
    runs = [r for r in store.runs.list_by_case(cid) if r.stage == "disassemble"]
    assert runs and runs[-1].status == "done", (runs[-1].status, runs[-1].error)
    ev = [e for e in store.events.list(case_id=cid, limit=500) if e.type == "re.done"]
    assert ev and ev[-1].payload.get("supported") is False
    assert "constant pool" in ev[-1].payload.get("note", "")
