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


@dataclass
class RealCase:
    label: str
    source: str
    payload: bytes
    channel: str                  # the ONE delivery channel that reaches the bug
    expect: dict                  # assertion name -> required value
    note: str = ""
    flags: list = field(default_factory=list)


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
]


def compile_case(case: RealCase, outdir: Path, cc: str = "gcc"):
    src = outdir / f"{case.label}.c"
    src.write_text(case.source)
    out = outdir / case.label
    r = subprocess.run([cc, *_CFLAGS, *case.flags, str(src), "-o", str(out)],
                       capture_output=True)
    return out if r.returncode == 0 and out.exists() else None


def _bundle_reproduces(store, bundle_sha) -> bool:
    """Extract the PoC bundle and RUN it. The bundle is the deliverable; one that does not
    reproduce is worse than none, and for argv targets it silently was not."""
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
            enqueue_disassemble(q, target)
            pool.wait_idle(timeout * 120)
            enqueue_detect(q, target)
            pool.wait_idle(timeout * 40)

            fd = FindingDAO(store.conn)
            cwes = {f.cwe for f in fd.list_by_target(target.id)}
            got["cwe121"] = "CWE-121" in cwes
            got["cwe120"] = "CWE-120" in cwes

            # NOTE: input_sha and nothing else. The stage must work out the channel itself --
            # every case here is reachable through exactly one, so the sweep is load-bearing.
            enqueue_build_poc(q, target, params={"input_sha": sha, "timeout": timeout},
                              force=True)
            pool.wait_idle(timeout * 20)
            pocs = PocDAO(store.conn).list_by_target(target.id)
            got["L1"] = any(p.verified and p.level == "L1" for p in pocs)
            res["detail"]["mode"] = _done_field(store, cid, "build_poc", "poc.done",
                                                "input_mode")

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
    res["ok"] = all(got.get(k) == v for k, v in case.expect.items())
    res["missing"] = [k for k, v in case.expect.items() if got.get(k) != v]
    return res


def _done_field(store, cid, stage, event_type, field_name):
    """Read one field out of a stage's completion event."""
    runs = [r for r in store.runs.list_by_case(cid) if r.stage == stage]
    for r in reversed(runs):
        for e in store.events.list(run_id=r.id, limit=60):
            if e.type == event_type and isinstance(e.payload, dict):
                return e.payload.get(field_name)
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
                skipped.append({"label": case.label, "why": "did not compile"})
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
    if report["skipped"]:
        return False, "FAIL", "did not build: " + ", ".join(
            f"{s['label']} ({s['why']})" for s in report["skipped"])
    bad = [r for r in report["results"] if not r["ok"]]
    if bad:
        return False, "FAIL", "; ".join(
            f"{r['label']} missing {r['missing']}" for r in bad)
    return True, "PASS", f"{len(report['results'])} real-chain cases passed"


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
