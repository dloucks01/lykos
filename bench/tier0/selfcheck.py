#!/usr/bin/env python3
"""Tier-0 corpus self-check (python3 stdlib only).

Builds every case into a temp dir with build.sh, then proves the ground truth:
  * every bug's ref_poc fires its oracle AT THE DECLARED file:line (and function,
    and asan_kind when given) on prog_asan;
  * seed.bin (when present) runs clean: expected exit code, no sanitizer report,
    no signal, no unintended exec;
  * negatives (bugs == []) stay clean on the seed and on every hostile_*.bin.

usage: selfcheck.py [--keep DIR] [case-id ...]
Prints one PASS/FAIL line per bug / seed / negative input; exits 1 on any FAIL.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TIMEOUT = 20
SHELLS = {"sh", "bash", "dash"}

ENV = dict(os.environ)
ENV["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0:symbolize=1:allocator_may_return_null=1"
ENV["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"
ENV["LC_ALL"] = "C"
MSAN_ENV = {"MSAN_OPTIONS": "halt_on_error=1:abort_on_error=0:print_stats=0:exitcode=99"}

ASAN_ERR = re.compile(r"ERROR: AddressSanitizer: (.+?)(?: on (?:unknown )?address| on 0x|:? \(|$)", re.M)
UBSAN_ERR = re.compile(r"(\S*prog\.c):(\d+):\d+: runtime error: (.*)$", re.M)
FRAME = re.compile(r"^\s*#\d+ 0x[0-9a-f]+ in (\S+) (\S*prog\.c):(\d+)", re.M)
EXECVE = re.compile(r'execve\("([^"]*)",.*\)\s*=\s*(-?\d+)')
OPENPATH = re.compile(r'\bopen(?:at|64|at64)?\([^"]*"((?:[^"\\]|\\.)*)"')
TRAVERSAL_TAIL = "etc/passwd"
MSAN_ERR = re.compile(r"MemorySanitizer: use-of-uninitialized-value", re.M)
MSAN_FRAME = re.compile(r"^\s*#\d+ 0x[0-9a-f]+ in (\S+) (\S*prog\.c):(\d+)", re.M)
LSAN_ERR = re.compile(r"LeakSanitizer: detected memory leaks", re.M)
LEAK_BLOCK = re.compile(r"(?:Direct|Indirect) leak of .*? allocated from:\n((?:\s*#\d+ .*\n)+)", re.S)
LSAN_ENV = {"ASAN_OPTIONS": "detect_leaks=1:abort_on_error=0:symbolize=1:allocator_may_return_null=1"}


def parse_msan(stderr):
    """(function, line) of the first in-program frame of an MSan report, or None."""
    m = MSAN_ERR.search(stderr)
    if not m:
        return None
    fr = MSAN_FRAME.search(stderr, m.end())
    return (fr.group(1), int(fr.group(3))) if fr else None


def parse_lsan(stderr):
    """[(function, line)] for each leaked allocation's first in-program (prog.c) frame."""
    if not LSAN_ERR.search(stderr):
        return []
    out = []
    for m in LEAK_BLOCK.finditer(stderr):
        fr = MSAN_FRAME.search(m.group(1))
        if fr:
            out.append((fr.group(1), int(fr.group(3))))
    return out


def ubsan_kind(msg):
    if "out of bounds for type" in msg:
        return "ubsan:index-out-of-bounds"
    if "signed integer overflow" in msg:
        return "ubsan:signed-integer-overflow"
    if "shift" in msg:
        return "ubsan:shift"
    if "null pointer" in msg:
        return "ubsan:null"
    return "ubsan:" + msg.split(" ")[0]


def parse_report(stderr):
    """Return (kind, function, line) of the first sanitizer report, or None.
    function/line come from the first in-program (prog.c) frame."""
    a = ASAN_ERR.search(stderr)
    u = UBSAN_ERR.search(stderr)
    if u and (not a or u.start() < a.start()):
        fr = FRAME.search(stderr, u.end())
        func = fr.group(1) if fr else None
        return ubsan_kind(u.group(3)), func, int(u.group(2))
    if a:
        kind = a.group(1).strip()
        fr = FRAME.search(stderr, a.end())
        if not fr:
            return kind, None, None
        return kind, fr.group(1), int(fr.group(3))
    if "Sanitizer" in stderr and "SUMMARY" in stderr:
        return "unknown-sanitizer", None, None
    return None


def run(binary, case, data, workdir, strace=False, extra_env=None):
    inv = case["invocation"]
    mode = inv["input_mode"]
    argv = [binary]
    stdin_path = None
    inp = os.path.join(workdir, "input.bin")
    with open(inp, "wb") as fh:
        fh.write(data)
    for a in inv["argv"]:
        if a == "@@":
            if mode == "file":
                argv.append(inp)
            elif mode == "arg":
                if b"\x00" in data:
                    raise ValueError("arg-mode input contains NUL")
                argv.append(data)
            else:
                raise ValueError("@@ in stdin mode")
        else:
            argv.append(a)
    if mode == "stdin":
        stdin_path = inp
    trace = os.path.join(workdir, "strace.out")
    if strace:
        if os.path.exists(trace):
            os.remove(trace)
        argv = ["strace", "-f", "-qq", "-e", "trace=execve,open,openat,creat", "-o", trace] + argv
    stdin = open(stdin_path, "rb") if stdin_path else subprocess.DEVNULL
    env = ENV if not extra_env else {**ENV, **extra_env}
    try:
        p = subprocess.run(argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           cwd=workdir, env=env, timeout=TIMEOUT)
    finally:
        if stdin_path:
            stdin.close()
    execs, opens = [], []
    if strace and os.path.exists(trace):
        with open(trace, errors="replace") as fh:
            for ln in fh:
                m = EXECVE.search(ln)
                if m and m.group(2) == "0":
                    execs.append(m.group(1))
                o = OPENPATH.search(ln)
                if o:
                    opens.append(o.group(1))
    return p.returncode, p.stderr.decode("utf-8", "replace"), execs, opens


def run_timed(binary, case, data, workdir, timeout):
    """True if `binary` does NOT exit within `timeout` seconds on this input (a hang)."""
    import signal as _sig
    inv = case["invocation"]
    mode = inv["input_mode"]
    inp = os.path.join(workdir, "rinput.bin")
    with open(inp, "wb") as fh:
        fh.write(data)
    argv = [binary]
    for a in inv["argv"]:
        argv.append((inp if mode == "file" else data) if a == "@@" else a)
    stdin = open(inp, "rb") if mode == "stdin" else subprocess.DEVNULL
    try:
        p = subprocess.Popen(argv, stdin=stdin, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, cwd=workdir, env=ENV, start_new_session=True)
        try:
            p.wait(timeout=timeout)
            return False
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(p.pid), _sig.SIGKILL)
            p.wait()
            return True
    finally:
        if hasattr(stdin, "close"):
            stdin.close()


def unintended(execs, case, binary):
    allowed = SHELLS | set(case.get("intended_exec", [])) | {os.path.basename(binary)}
    return [e for e in execs if os.path.basename(e) not in allowed]


def traversed(opens):
    """Open paths that escaped a base directory: a `../` sequence AND the sentinel tail."""
    return [p for p in opens if "../" in p and TRAVERSAL_TAIL in p]


def check_clean(label, binary, case, data, workdir, expect_rc=None):
    rc, err, execs, opens = run(binary, case, data, workdir, strace=True)
    rep = parse_report(err)
    bad = unintended(execs, case, binary)
    problems = []
    if rep:
        problems.append("sanitizer report %r at %s:%s" % rep)
    if rc < 0:
        problems.append("killed by signal %d" % -rc)
    if expect_rc is not None and rc != expect_rc:
        problems.append("exit %d != %d" % (rc, expect_rc))
    if bad:
        problems.append("unintended exec %s" % bad)
    if case.get("class") == "path-traversal" and traversed(opens):
        problems.append("escaped base via %s" % traversed(opens)[0])
    if case.get("class") == "uninit":
        mbin = binary.replace("prog_asan", "prog_msan")
        if os.path.exists(mbin):
            _, merr, _, _ = run(mbin, case, data, workdir, extra_env=MSAN_ENV)
            mr = parse_msan(merr)
            if mr:
                problems.append("MSan use-of-uninitialized at prog.c:%d" % mr[1])
    if case.get("class") == "memleak":
        _, lerr, _, _ = run(binary, case, data, workdir, extra_env=LSAN_ENV)
        lk = parse_lsan(lerr)
        if lk:
            problems.append("LSan leak at prog.c:%d" % lk[0][1])
    if case.get("class") == "resource":
        if run_timed(binary.replace("prog_asan", "prog"), case, data, workdir, 4):
            problems.append("did not terminate within 4s")
    return label, (not problems), "; ".join(problems) or "clean (rc=%d)" % rc


def check_bug(binary, case, bug, data, workdir):
    if bug["oracle"] == "timeout":
        pbin = binary.replace("prog_asan", "prog")
        if run_timed(pbin, case, data, workdir, 6):
            return True, "did not terminate within 6s"
        return False, "terminated within 6s"
    if bug["oracle"] == "lsan":
        _, lerr, _, _ = run(binary, case, data, workdir, extra_env=LSAN_ENV)
        lines = [ln for _f, ln in parse_lsan(lerr)]
        if not lines:
            return False, "no leak reported"
        if bug["line"] not in lines:
            return False, "leak at line(s) %s != declared %d" % (sorted(set(lines)), bug["line"])
        return True, "leaked allocation at prog.c:%d" % bug["line"]
    if bug["oracle"] == "msan":
        mbin = binary.replace("prog_asan", "prog_msan")
        if not os.path.exists(mbin):
            return False, "no prog_msan build (clang required)"
        _, merr, _, _ = run(mbin, case, data, workdir, extra_env=MSAN_ENV)
        mr = parse_msan(merr)
        if not mr:
            return False, "no MSan report"
        func, line = mr
        problems = []
        if line != bug["line"]:
            problems.append("line %s != declared %d" % (line, bug["line"]))
        if func != bug["function"]:
            problems.append("function %s != declared %s" % (func, bug["function"]))
        if problems:
            return False, "; ".join(problems)
        return True, "use-of-uninitialized-value at prog.c:%d in %s" % (line, func)
    if bug["oracle"] == "exec":
        rc, err, execs, opens = run(binary, case, data, workdir, strace=True)
        bad = unintended(execs, case, binary)
        if bad:
            return True, "injected exec %s" % [os.path.basename(b) for b in bad]
        return False, "no unintended execve (saw %s)" % [os.path.basename(e) for e in execs]
    if bug["oracle"] == "openat":
        rc, err, execs, opens = run(binary, case, data, workdir, strace=True)
        hit = traversed(opens)
        if hit:
            return True, "opened out-of-base path %s" % hit[0]
        return False, "no out-of-base open (saw %s)" % opens[:3]
    rc, err, _, _ = run(binary, case, data, workdir)
    rep = parse_report(err)
    if not rep:
        return False, "no sanitizer report (rc=%d)" % rc
    kind, func, line = rep
    problems = []
    if line != bug["line"]:
        problems.append("line %s != declared %d" % (line, bug["line"]))
    if func is not None and func != bug["function"]:
        problems.append("function %s != declared %s" % (func, bug["function"]))
    if bug.get("asan_kind") and kind != bug["asan_kind"]:
        problems.append("kind %r != declared %r" % (kind, bug["asan_kind"]))
    if problems:
        return False, "; ".join(problems)
    return True, "%s at prog.c:%d in %s" % (kind, line, func)


def main():
    args = sys.argv[1:]
    keep = None
    if args[:1] == ["--keep"]:
        keep, args = args[1], args[2:]
    ids = args or sorted(d for d in os.listdir(HERE)
                         if os.path.isfile(os.path.join(HERE, d, "case.json")))
    tmp = tempfile.mkdtemp(prefix="tier0-")
    bindir = keep or os.path.join(tmp, "bin")
    try:
        b = subprocess.run([os.path.join(HERE, "build.sh"), bindir] + ids,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if b.returncode != 0:
            sys.stdout.write(b.stdout.decode("utf-8", "replace"))
            print("FAIL build")
            return 1
        failures = total = 0

        def report(ok, what, detail):
            nonlocal failures, total
            total += 1
            failures += 0 if ok else 1
            print("%s %-28s %-14s %s" % ("PASS" if ok else "FAIL", cid, what, detail))

        for cid in ids:
            cdir = os.path.join(HERE, cid)
            with open(os.path.join(cdir, "case.json")) as fh:
                case = json.load(fh)
            binary = os.path.join(bindir, cid, "prog_asan")
            work = os.path.join(tmp, "run", cid)
            os.makedirs(work, exist_ok=True)
            bugs = case["bugs"]
            for bug in bugs:
                name = "ref_poc.bin" if len(bugs) == 1 else "ref_poc_%s.bin" % bug["id"]
                path = os.path.join(cdir, name)
                if not os.path.exists(path):
                    report(False, bug["id"], "missing " + name)
                    continue
                with open(path, "rb") as fh:
                    ok, detail = check_bug(binary, case, bug, fh.read(), work)
                report(ok, bug["id"] + "/" + bug["oracle"], detail)
            seed = os.path.join(cdir, "seed.bin")
            if os.path.exists(seed):
                with open(seed, "rb") as fh:
                    _, ok, detail = check_clean("seed", binary, case, fh.read(), work,
                                                expect_rc=case.get("seed_exit", 0))
                report(ok, "seed", detail)
            elif not bugs:
                report(False, "seed", "negative case without seed.bin")
            if not bugs:
                hostiles = sorted(f for f in os.listdir(cdir) if f.startswith("hostile_"))
                if not hostiles:
                    report(False, "hostile", "negative case without hostile_*.bin")
                for h in hostiles:
                    with open(os.path.join(cdir, h), "rb") as fh:
                        _, ok, detail = check_clean(h, binary, case, fh.read(), work)
                    report(ok, h.replace(".bin", ""), detail)
        print("%d/%d checks passed" % (total - failures, total))
        return 1 if failures else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
