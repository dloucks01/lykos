"""Release gate: the WHOLE chain, on a program that behaves like real software.

The other gates each cover a slice and between them leave the join uncovered:

  * `test` is 491 unit tests over synthetic P-Code and pure functions. Nothing runs a program.
  * `eval-gate` scores detection precision/recall on inline micro-cases. It stops at detect.
  * `arch-gate` drives triage -> build_poc -> primitive -> exploit across 13 ISAs, which is
    genuinely end to end -- but it never runs `detect` or `root_cause`, it hands every stage
    an explicit `input_mode="stdin"`, and its fixture reads stdin. So the analysis half has no
    end-to-end cover at all, argv and file delivery are never exercised, and nothing ever runs
    a PoC bundle.

Six defects shipped through that gap in one session, every one of them a confident wrong
answer rather than a crash: three stages defaulting `input_mode` to stdin (a crashing input
fed the wrong way reads exactly like an input that does not crash), argv payloads corrupted
because `os.execv` re-encodes latin-1 text as UTF-8, `argv_arg` refusing a payload the kernel
would have delivered intact, a bundle whose reproducer ran `./target.bin ''`, gdb's frame #1
dropped by a bad slice, and PIE frames never symbolising. Unit tests cannot see any of them.

So this gate asserts the things those bugs broke:
  * NO stage is told how to feed the target -- `input_sha` and nothing else, which is exactly
    what the API sends. Each case is reachable through exactly ONE delivery channel, so the
    mode sweep has to find it.
  * the fixtures are PIE, so symbolisation has to rebase.
  * the produced bundle is extracted and RUN, because the bundle is the deliverable.
  * detect, root_cause and the PoC ladder run together, because crash attribution is the join
    between them and no other gate runs either half.

The fixtures are built here rather than downloaded: this is an air-gapped platform, and a
release gate that needs the network is not one. They are small but not toy -- several
functions, a real call graph, argv and file input paths -- and they reproduce the shapes that
were validated by hand against ncompress 4.2.4 (CVE-2001-1413) and jhead 3.04.
"""
from __future__ import annotations

import io
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# no-canary so the saved return address is reachable, PIE so symbolisation has to rebase.
_CFLAGS = ["-O0", "-fno-stack-protector", "-w"]

# Reached only through argv: stdin is ignored and a file path is far too short to overflow.
# Mirrors ncompress's comprexx() -- an unchecked strcpy of a command-line name into a
# fixed stack buffer (CVE-2001-1413).
_SRC_ARGV = r"""
#include <stdio.h>
#include <string.h>
static void report(const char *what, int n){ fprintf(stderr, "%s: %d\n", what, n); }
static void handle(const char *arg){
    char path[1024];
    strcpy(path, arg);            /* unchecked: the bug */
    report("len", (int)strlen(path));
}
int main(int argc, char **argv){
    if (argc < 2){ report("usage", 0); return 1; }
    handle(argv[1]);
    return 0;
}
"""

# Reached only through a file: argv is a path that will not open, stdin is ignored. The
# offset is read from the file and never checked, so memcpy faults on the SOURCE read --
# which leaves the stack intact, so the backtrace still names the call that faulted. That is
# the shape that makes fault-site attribution provable (jhead's ProcessGpsInfo, by hand).
_SRC_FILE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void parse(const char *src, unsigned long n){
    char buf[64];
    memcpy(buf, src, n);          /* src is attacker-positioned: the bug */
    fprintf(stderr, "parsed %lu\n", n);
    if (buf[0]) fputs("x", stderr);
}
int main(int argc, char **argv){
    if (argc < 2) return 1;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    char *data = malloc(1 << 16);
    size_t got = fread(data, 1, 1 << 16, f);
    fclose(f);
    if (got < 8) return 1;
    unsigned long off;
    memcpy(&off, data, 8);
    parse(data + off, 64);
    return 0;
}
"""


# A Java service in the shape most real ones have: a MANDATORY `-c <config>` behind a flag, a
# key=value parser, and an unchecked index in it. Reachable through exactly one channel like
# every other case here -- stdin is never read and argv holds a path, not the payload.
#
# This is the only case whose substrate is not machine code, and that is the point: the JVM
# path has its own triage, its own executor, its own crash oracle (an uncaught exception, not
# a signal), its own CWE mapping and its own bundle runner, and none of it was covered by a
# gate. Its unit tests pass; so did the unit tests for every defect listed at the top of this
# file.
_SRC_JAVA = r"""
import java.io.*;
import java.nio.file.*;
public class Svc {
    static String[] slots = new String[8];          // fixed: the bug lives here
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

_JDK = ("javac", "jar", "java")

# The shape most of this platform's real targets have, on the architecture most of them use:
# a mandatory `-c <config>` behind a flag, a key=value parser, an unchecked copy in it. Built
# STATIC because the ARM dynamic loader is not installed on an x86-64 host, and the PoC bundle
# has to run `./target.bin` directly -- binfmt_misc routes it to qemu-arm, but only a static
# image needs no /lib/ld-linux-armhf.so.3.
_SRC_CONFIG = r"""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
struct cfg { char name[64]; char listen[32]; int workers; };
static void set_opt(struct cfg *c, const char *k, const char *v) {
    if (!strcmp(k, "name"))         strcpy(c->name, v);      /* unchecked: the bug */
    else if (!strcmp(k, "listen"))  strncpy(c->listen, v, sizeof c->listen - 1);
    else if (!strcmp(k, "workers")) c->workers = atoi(v);
}
int main(int argc, char **argv) {
    struct cfg c; const char *path = NULL; char line[512]; FILE *f;
    memset(&c, 0, sizeof c);
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "-c") && i + 1 < argc) path = argv[++i];
    if (!path) { fprintf(stderr, "usage: %s -c <config>\n", argv[0]); return 2; }
    if (!(f = fopen(path, "r"))) { fprintf(stderr, "cannot open config\n"); return 1; }
    while (fgets(line, sizeof line, f)) {
        char *eq, *nl;
        if (line[0] == '#') continue;
        if ((nl = strchr(line, '\n'))) *nl = 0;
        if (!(eq = strchr(line, '='))) continue;
        *eq = 0; set_opt(&c, line, eq + 1);
    }
    fclose(f);
    printf("name=%s listen=%s workers=%d\n", c.name, c.listen, c.workers);
    return 0;
}
"""


@dataclass
class RealCase:
    label: str
    source: str
    payload: bytes
    channel: str                  # the ONE delivery channel that reaches the bug
    expect: dict                  # assertion name -> required value
    note: str = ""
    flags: list = field(default_factory=list)
    prebuilt: str = ""            # repo-relative binary to use INSTEAD of compiling `source`
    fuzz: bool = False            # find the crashing input rather than being handed one
    lang: str = "c"               # "c" -> gcc; "java" -> javac + jar
    cc: str = ""                  # a cross-compiler for this case, instead of the host cc

    @property
    def optional(self) -> bool:
        """A prebuilt fixture is not committed (large, reproducible), so its absence skips.
        A case that fails to COMPILE still fails the gate -- that is an opt-out, not a
        missing download.

        A Java case skips only when there is no JDK at all, on the same rule the arch gate
        uses for an absent cross-compiler: a toolchain this machine does not have is not a
        regression. If javac IS present and the build fails, that is a hard failure.
        """
        if self.lang == "java":
            return not all(shutil.which(t) for t in _JDK)
        if self.cc:
            # a cross toolchain this machine does not have is not a regression -- the same
            # rule arch-gate uses
            return shutil.which(self.cc) is None
        return bool(self.prebuilt)


_REPO = Path(__file__).resolve().parents[3]
# A real parser with no known bug should produce a report an analyst can read. unzip's
# fifteen findings were two thirds false; this is the ceiling that would have caught it.
_REPORT_CEILING = 12
# A `no_crash` negative only means something if the fuzzer ACTUALLY RAN. An empty crash set
# from a campaign that never executed (mis-config, sandbox down) is indistinguishable from a
# genuinely quiet target -- the "absence of evidence" trap. Require this many real executions
# before crediting a clean result; matches the stage's own "starved" floor.
_MIN_FUZZ_EXECS = 200


MATRIX = [
    RealCase(
        "argv_ip_control", _SRC_ARGV, b"A" * 1400, "arg",
        {"cwe121": True, "L1": True, "L2": True, "bundle_reproduces": True},
        note="unchecked strcpy of a command-line name (ncompress CVE-2001-1413 shape)"),
    RealCase(
        "file_attribution", _SRC_FILE,
        (1 << 40).to_bytes(8, "little") + b"payload" * 8, "file",
        {"cwe120": True, "L1": True, "attributed": True, "poc_backed": True},
        note="file-positioned memcpy source; fault inside the call names the finding"),
    # The synthetic cases above are shapes VALIDATED against real software. This one is the
    # real software: third-party C, its own CVE-class bug, and nothing supplied but the
    # binary. It is the only case that exercises format detection, seed generation and
    # structure-aware mutation, which is the difference between "the chain works when handed a
    # crashing input" and "the platform finds the bug".
    RealCase(
        "real_jhead", "", b"", "file",
        {"cwe125": True, "found_by_fuzzing": True, "L1": True,
         "attributed": True, "poc_backed": True},
        prebuilt="examples/vuln-targets/bin/jhead_x86-64", fuzz=True,
        note="jhead 3.04 CWE-125 in ProcessGpsInfo, found from the binary alone "
             "(run examples/vuln-targets/fetch_build.sh to enable)"),
    # The ladder above L1 on REAL code. jhead's bug is an out-of-bounds read, so it cannot
    # reach L2 at all; this is the shape that gives instruction-pointer control, and until now
    # the only evidence for L2 outside a synthetic fixture was a hand-run measurement.
    RealCase(
        "real_ncompress", "", b"A" * 1400, "arg",
        {"cwe121": True, "L1": True, "L2": True, "bundle_reproduces": True},
        prebuilt="examples/vuln-targets/bin/ncompress_x86-64_cve",
        note="ncompress CVE-2001-1413: unchecked strcpy of an argv pathname, to L2"),
    # The architecture this platform is most often pointed at, and the one where the most
    # changed: coverage-guided fuzzing went from refused outright to ~1,965 exec/s, on the
    # strength of a per-guest emulator lookup that nothing else here covers. Every other real
    # case is x86-64, so the quality bar was measuring a corpus that is not the one in use.
    #
    # This one case exercises, together: invocation discovery reading `-c <config>` off the
    # binary and verifying it by running the target, the text-config mutation model, the
    # cross-architecture sandbox, and a PoC bundle that has to replay an ARM binary.
    RealCase(
        "real_arm_config", _SRC_CONFIG, b"", "file",
        {"found_by_fuzzing": True, "cwe120": True, "L1": True, "bundle_reproduces": True},
        cc="arm-linux-gnueabihf-gcc", flags=["-static"], fuzz=True,
        note="a config-driven ARM service: found from the binary alone, argv discovered from "
             "its own usage line, and the bundle replays under binfmt/qemu"),
    # CWE-120 rather than CWE-121 here, and the difference is the FIXTURE, not the
    # architecture. `stack_buffer_overflow` needs a function that owns a local buffer; this
    # service keeps its state in a `struct cfg` that main owns and passes by pointer, so the
    # function doing the strcpy has no local array and the specific stack-overflow
    # classification does not apply. Verified by building the same source for x86-64, which
    # also yields no CWE-121 -- checked because "ARM detects less" would have been an easy and
    # wrong conclusion to draw from one failing assertion.
    # The only case whose substrate is not machine code. Java has its own triage, executor,
    # crash oracle, CWE mapping and bundle runner, and every one of them was uncovered by a
    # gate -- including a bundle that ran `./target.bin` on a zip file and a reproducer that
    # appended the input instead of putting it behind `-c`.
    RealCase(
        "real_jvm_config", _SRC_JAVA, b"", "file",
        {"found_by_fuzzing": True, "cwe129": True, "not_memory_corruption": True,
         "L1": True, "bundle_reproduces": True,
         "fault": "ArrayIndexOutOfBoundsException"},
        lang="java", fuzz=True,
        note="a Java service behind a mandatory -c <config>: found from the jar alone, and "
             "the bundle replays as `java -jar ./target.bin -c ./input.bin -d :0`"),
    # The NEGATIVE case, and the only measurement of precision on real code anywhere in the
    # gates: giflib 5.1.4 already carries the check CVE-2016-3977 defeated. Every precision
    # number quoted for a real binary so far came from reading output by hand -- including the
    # ten false credentials in unzip, which shipped.
    RealCase(
        "real_gif2rgb_clean", "", b"", "file",
        {"no_crash": True, "no_credentials": True, "bounded_report": True},
        prebuilt="examples/vuln-targets/bin/gif2rgb_x86-64", fuzz=True,
        note="giflib 5.1.4 gif2rgb: a real parser with no known bug -- it must stay quiet"),
]


def _build_jar(case: RealCase, outdir: Path):
    """javac + jar. The target this platform analyses is the JAR, not a class directory:
    that is what an operator has, and `java -jar` is how it runs."""
    d = outdir / case.label
    classes = d / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    src = d / "Svc.java"
    src.write_text(case.source)
    if subprocess.run(["javac", "-d", str(classes), str(src)],
                      capture_output=True).returncode != 0:
        return None
    mf = d / "manifest.txt"
    mf.write_text("Main-Class: Svc\n")
    jar = d / f"{case.label}.jar"
    r = subprocess.run(["jar", "cfm", str(jar), str(mf), "-C", str(classes), "."],
                       capture_output=True)
    return jar if r.returncode == 0 and jar.exists() else None


def compile_case(case: RealCase, outdir: Path, cc: str = "gcc"):
    if case.lang == "java":
        return _build_jar(case, outdir) if not case.optional else None
    if case.prebuilt:
        exe = _REPO / case.prebuilt
        return exe if exe.exists() else None
    src = outdir / f"{case.label}.c"
    src.write_text(case.source)
    out = outdir / case.label
    r = subprocess.run([case.cc or cc, *_CFLAGS, *case.flags, str(src), "-o", str(out)],
                       capture_output=True)
    return out if r.returncode == 0 and out.exists() else None


def _bundle_reproduces(store, bundle_sha, *, runtime: str = "native",
                       expect: str = "") -> bool:
    """Extract the PoC bundle and RUN it. The bundle is the deliverable; one that does not
    reproduce is worse than none, and for argv targets it silently was not.

    What counts as "reproduced" depends on the runtime, and conflating them would make this
    check vacuous for Java: a JVM fault is an uncaught exception on stderr with an exit code
    of 1 (or 3 on OutOfMemoryError), never 128+signum. A check that only knows about signals
    would fail every correct Java bundle -- or, worse, if it were loosened to "non-zero exit",
    would pass a bundle whose target merely printed its usage and exited 2, which is exactly
    the failure this gate exists to catch.
    """
    d = Path(tempfile.mkdtemp(prefix="lykos-realgate-bundle-"))
    try:
        data = store.content.get_bytes(bundle_sha)
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            tf.extractall(d, filter="data")
        runner = next((p for p in d.rglob("runner.sh")), None)
        if runner is None:
            return False
        for p in (runner, *runner.parent.glob("target.bin")):
            p.chmod(0o755)
        r = subprocess.run(["sh", str(runner)], capture_output=True, timeout=120,
                           cwd=str(runner.parent))
        out = (r.stdout or b"").decode("latin-1", "ignore")
        err = (r.stderr or b"").decode("latin-1", "ignore")
        if runtime in ("jar", "class"):
            # the exception itself, from the JVM's own handler -- not merely a non-zero exit,
            # which a usage message also produces
            if "Exception in thread" not in err and "Terminating due to" not in out:
                return False
            return (not expect) or expect in err or expect in out
        # runner.sh reports the child's status; a crash shows as 128+signum
        return any(f"exit status: {128 + s}" in out for s in (4, 6, 7, 8, 11))
    except Exception:
        return False
    finally:
        shutil.rmtree(d, ignore_errors=True)


def run_case(case: RealCase, exe: Path, *, timeout: float = 30.0) -> dict:
    """Drive one case through the real stages, telling no stage how to feed the target."""
    from ..analyze import register as register_stages
    from ..analyze.debug.stage import enqueue_root_cause
    from ..analyze.detect.stage import enqueue_detect
    from ..analyze.disassemble import enqueue_disassemble
    from ..analyze.ingest import enqueue_triage, ingest
    from ..analyze.poc.primitive_stage import enqueue_primitive
    from ..analyze.poc.stage import enqueue_build_poc
    from ..casestore import CaseStore
    from ..db.dao import FindingDAO, PocDAO
    from ..jobs import JobConfig, JobQueue, WorkerPool

    register_stages()
    got: dict = {k: False for k in case.expect}
    res: dict = {"label": case.label, "note": case.note, "got": got, "detail": {}}
    d = Path(tempfile.mkdtemp(prefix=f"lykos-realgate-{case.label}-"))
    store = CaseStore.open(d / "case")
    try:
        cid = store.cases.create(case.label).id
        target = ingest(store, cid, exe, filename=exe.name)
        sha = store.put_artifact(cid, "realgate-seed", data=case.payload).sha256
        pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2))
        pool.start()
        try:
            q = JobQueue(store.conn)
            enqueue_triage(q, target)
            pool.wait_idle(timeout * 4)
            target = store.targets.get(target.id)
            res["detail"]["pie"] = (target.mitigations or {}).get("pie")
            runtime = {"jar": "jar", "class": "class"}.get(
                (target.file_type or "").lower(), "native")
            if runtime == "native":
                enqueue_disassemble(q, target)
                pool.wait_idle(timeout * 120)
            else:
                # There is no machine code to decompile. Running Ghidra over a zip would burn
                # the gate's whole time budget to produce nothing, and `detect` reads the
                # constant pool directly.
                res["detail"]["substrate"] = runtime
            enqueue_detect(q, target)
            pool.wait_idle(timeout * 40)

            fd = FindingDAO(store.conn)
            cwes = {f.cwe for f in fd.list_by_target(target.id)}
            got["cwe121"] = "CWE-121" in cwes
            got["cwe120"] = "CWE-120" in cwes
            got["cwe125"] = "CWE-125" in cwes

            if "no_credentials" in case.expect:
                # Precision on real code: a clean binary must not accumulate findings it
                # cannot support. Counted at CANDIDATE, because that is where noise lands.
                findings = fd.list_by_target(target.id)
                got["no_credentials"] = not any(f.cwe == "CWE-798" for f in findings)
                got["bounded_report"] = len(findings) <= _REPORT_CEILING
                res["detail"]["findings"] = len(findings)

            if case.fuzz:
                # Nothing supplied but the binary: the campaign has to work out the format
                # from the target's own strings, generate a seed its parser accepts, and
                # mutate it into a crash. Then the ladder continues from what it found.
                from ..analyze.fuzz import enqueue_fuzz
                from ..db.dao import DynResultDAO
                enqueue_fuzz(q, target, params={"input_mode": case.channel,
                                                "max_execs": 20000, "max_seconds": timeout * 4,
                                                "exec_timeout": 2}, force=True)
                pool.wait_idle(timeout * 40)
                crashes = [d for d in DynResultDAO(store.conn).list_by_target(target.id)
                           if d.crashed]
                got["found_by_fuzzing"] = bool(crashes)
                res["detail"]["model"] = _done_field(store, cid, "fuzz", "fuzz.format", "model")
                res["detail"]["crashes"] = len(crashes)
                # The campaign's total executions come from its TERMINAL summary event, which
                # sits past _done_field's small window (fuzz emits a progress event every 250
                # execs), so scan to the end for it.
                fuzz_execs = _last_done_field(store, cid, "fuzz", "fuzz.channels", "execs")
                res["detail"]["execs"] = fuzz_execs
                ran = isinstance(fuzz_execs, int) and fuzz_execs >= _MIN_FUZZ_EXECS
                # A clean result is only credited when the fuzzer both ran and found nothing.
                # A campaign that did not run FAILS the negative case rather than passing it.
                got["no_crash"] = (not crashes) and ran
                if "no_crash" in case.expect:
                    if not ran:
                        res["detail"]["why_no_crash"] = (
                            f"fuzz campaign did not run (execs={fuzz_execs}); a clean verdict "
                            "cannot be credited")
                    res["ok"] = all(got.get(k) == v for k, v in _asserts(case).items())
                    res["missing"] = [k for k, v in _asserts(case).items()
                                      if got.get(k) != v]
                    return res
                if not crashes:
                    res["ok"] = False
                    res["missing"] = [k for k, v in _asserts(case).items()
                                      if got.get(k) != v]
                    return res
                # When the case asserts a SPECIFIC fault, prove the bundle for THAT crash, not
                # for whatever landed last. A target can throw several distinct faults -- the JVM
                # config parser reaches an ArrayIndexOutOfBoundsException (CWE-129) on slot=0 AND a
                # NumberFormatException on an out-of-int-range boundary value -- and the crash list
                # is ordered most-recent-first, so "the first crash" is not a stable choice. The
                # real autopilot proves EVERY distinct crash for this reason; the gate drives one,
                # so it picks the one it makes an assertion about. Falls back to the first crash
                # when the case names no fault.
                want_fault = case.expect.get("fault")
                picked = next((c for c in crashes if want_fault and c.signal_name == want_fault),
                              crashes[0])
                sha = picked.input_sha
                if "cwe129" in case.expect or "not_memory_corruption" in case.expect:
                    # Recomputed AFTER the crash: the fault's CWE comes from the exception,
                    # and the native table falls through to CWE-119 "critical" for anything it
                    # does not recognise. An ArrayIndexOutOfBoundsException is the JVM CATCHING
                    # the out-of-bounds access, so filing it as memory corruption would be a
                    # lie about the runtime -- and a plausible one to reintroduce.
                    after = {f.cwe for f in fd.list_by_target(target.id)}
                    got["cwe129"] = "CWE-129" in after
                    got["not_memory_corruption"] = "CWE-119" not in after
                    res["detail"]["fault"] = picked.signal_name

            # NOTE: input_sha and nothing else. The stage must work out the channel itself --
            # every case here is reachable through exactly one, so the sweep is load-bearing.
            enqueue_build_poc(q, target, params={"input_sha": sha, "timeout": timeout},
                              force=True)
            pool.wait_idle(timeout * 20)
            pocs = PocDAO(store.conn).list_by_target(target.id)
            got["L1"] = any(p.verified and p.level == "L1" for p in pocs)
            res["detail"]["mode"] = _done_field(store, cid, "build_poc", "poc.done",
                                                "input_mode")
            if not got["L1"]:
                # a gate that only says "L1 missing" sends you back to reproduce it by hand
                res["detail"]["tried"] = _done_field(store, cid, "build_poc", "poc.done",
                                                     "input_modes_tried")
                res["detail"]["why"] = _done_field(store, cid, "build_poc", "poc.done",
                                                   "input_mode_why")
                res["detail"]["crash_input"] = sha[:12]

            if "bundle_reproduces" in case.expect and "L2" not in case.expect:
                # The L1 bundle IS the deliverable when the ladder stops there, which for a
                # managed runtime it always does. For a jar this is the assertion that matters
                # most: it proves the reproducer names the runtime (`java -jar ./target.bin`,
                # not `./target.bin`) and places the input where argv says (`-c ./input.bin`,
                # not appended), both of which were wrong.
                l1 = [x for x in pocs if x.verified and x.level == "L1" and x.bundle_sha]
                if l1:
                    got["bundle_reproduces"] = _bundle_reproduces(
                        store, l1[-1].bundle_sha, runtime=runtime,
                        expect=case.expect.get("fault") or "")

            if "L2" in case.expect:
                enqueue_primitive(q, target, params={"input_sha": sha, "timeout": timeout},
                                  force=True)
                pool.wait_idle(timeout * 60)
                pocs = PocDAO(store.conn).list_by_target(target.id)
                l2 = [p for p in pocs if p.verified and p.level == "L2"]
                got["L2"] = bool(l2)
                res["detail"]["offset"] = _done_field(store, cid, "poc_primitive",
                                                      "primitive.done", "offset")
                if "bundle_reproduces" in case.expect and l2:
                    got["bundle_reproduces"] = _bundle_reproduces(store, l2[-1].bundle_sha)

            if "attributed" in case.expect:
                enqueue_root_cause(q, target, params={"input_sha": sha, "timeout": timeout},
                                   force=True)
                pool.wait_idle(timeout * 20)
                n_attr = _done_field(store, cid, "root_cause", "rootcause.done", "attributed")
                n_poc = _done_field(store, cid, "root_cause", "rootcause.done", "poc_backed")
                got["attributed"] = bool(n_attr)
                got["poc_backed"] = bool(n_poc)
                res["detail"]["attributed"] = n_attr
                res["detail"]["promoted"] = n_poc
        finally:
            pool.stop()
    finally:
        store.close()
        shutil.rmtree(d, ignore_errors=True)
    res["ok"] = all(got.get(k) == v for k, v in _asserts(case).items())
    res["missing"] = [k for k, v in _asserts(case).items() if got.get(k) != v]
    return res


def _asserts(case: RealCase) -> dict:
    """The boolean assertions. `fault` carries the exception the bundle must show, which is a
    parameter to the check rather than something `got` reports."""
    return {k: v for k, v in case.expect.items() if k != "fault"}


def _done_field(store, cid, stage, event_type, field_name):
    """Read one field out of a stage's completion event."""
    runs = [r for r in store.runs.list_by_case(cid) if r.stage == stage]
    for r in reversed(runs):
        for e in store.events.list(run_id=r.id, limit=60):
            if e.type == event_type and isinstance(e.payload, dict):
                return e.payload.get(field_name)
    return None


def _last_done_field(store, cid, stage, event_type, field_name):
    """Like `_done_field`, but scans ALL of a run's events to the end and returns the LAST
    match. Needed for a TERMINAL event of a high-volume stage: fuzz emits a progress event
    every 250 execs, so its final `fuzz.channels` summary sits far past a small page window."""
    runs = [r for r in store.runs.list_by_case(cid) if r.stage == stage]
    for r in reversed(runs):
        found = None
        after = 0
        while True:
            batch = store.events.list(run_id=r.id, after_id=after, limit=500)
            if not batch:
                break
            for e in batch:
                if e.type == event_type and isinstance(e.payload, dict):
                    found = e.payload.get(field_name)
            after = batch[-1].id
            if len(batch) < 500:
                break
        if found is not None:
            return found
    return None


def run(cases=None, *, timeout: float = 30.0, cc: str = "gcc", progress=None) -> dict:
    cases = list(cases if cases is not None else MATRIX)
    out, skipped = [], []
    workdir = Path(tempfile.mkdtemp(prefix="lykos-realgate-"))
    try:
        for i, case in enumerate(cases, 1):
            if progress:
                progress(f"[{i}/{len(cases)}] {case.label}")
            exe = compile_case(case, workdir, cc)
            if exe is None:
                skipped.append({"label": case.label, "optional": case.optional,
                                "why": ("fixture not built -- run "
                                        "examples/vuln-targets/fetch_build.sh"
                                        if case.optional else "did not compile")})
                continue
            out.append(run_case(case, exe, timeout=timeout))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return {"results": out, "skipped": skipped}


def gate(report: dict) -> tuple:
    """(passed, verdict, reason) -- the shape the archgate command already expects.

    A case that did not build FAILS rather than skipping: this gate exists to be run, and a
    silent opt-out is the same failure mode it was written to catch.
    """
    hard = [s for s in report["skipped"] if not s.get("optional")]
    if hard:
        return False, "FAIL", "did not build: " + ", ".join(
            f"{s['label']} ({s['why']})" for s in hard)
    bad = [r for r in report["results"] if not r["ok"]]
    if bad:
        return False, "FAIL", "; ".join(
            f"{r['label']} missing {r['missing']}" for r in bad)
    absent = [s["label"] for s in report["skipped"]]
    note = f" ({len(absent)} fixture(s) absent: {', '.join(absent)})" if absent else ""
    return True, "PASS", f"{len(report['results'])} real-chain cases passed" + note


def table(report: dict) -> str:
    rows = ["case                 result  detail",
            "-------------------- ------- ------------------------------------------"]
    for r in report["results"]:
        det = ", ".join(f"{k}={v}" for k, v in r["detail"].items() if v is not None)
        rows.append(f"{r['label']:<20} {'PASS' if r['ok'] else 'FAIL':<7} {det}")
        if not r["ok"]:
            rows.append(f"{'':<20} {'':<7} missing: {r['missing']}")
    for s in report["skipped"]:
        rows.append(f"{s['label']:<20} {'SKIP':<7} {s['why']}")
    return "\n".join(rows)
