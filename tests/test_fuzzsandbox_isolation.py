"""Fuzzer containment + silent-negative regressions (audit doc 48, "Sandbox safety" / "Silent 0
crashes").

* net_fuzz / env_fuzz / AFL coverage_fuzz used to run the untrusted target with rlimits only -- no
  read-only root, no secret mask; each now runs under bubblewrap and REPORTS its tier.
* run_batch never asked whether an execution actually started, so a dynamic ELF missing a `.so`
  was "fuzzed" thousands of times and read clean.
* netfuzz piped the server's stderr and never read it, so a logging server wedged.
* afl-fuzz was handed AFL_BENCH_JUST_ONE=0, which AFL++ treats as SET: every campaign stopped
  after its first queue entry, about a second in.
* differential `file` mode staged its input under /tmp, which the sandbox masks.
* the prompted runner and the menu drain could block forever past their deadline.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
import types
from pathlib import Path

import pytest
from lykos.analyze.dynamic import sandbox
from lykos.analyze.fuzz import aflpp, differential, envfuzz, menu, netfuzz

_CC = shutil.which("gcc") or shutil.which("cc")
_BWRAP = sandbox._bwrap_usable()
needs_cc = pytest.mark.skipif(not _CC, reason="no C compiler")
needs_bwrap = pytest.mark.skipif(not _BWRAP, reason="bubblewrap unusable on this host")


def _build(tmp_path, name, src, *flags):
    c = tmp_path / f"{name}.c"
    c.write_text(src)
    exe = tmp_path / name
    r = subprocess.run([_CC, "-O0", "-fno-stack-protector", str(c), "-o", str(exe), *flags],
                       capture_output=True)
    if r.returncode != 0:
        pytest.skip("build failed: " + r.stderr.decode()[:200])
    return exe


# ---------------------------------------------------------------- run_batch: did it even start?
@pytest.fixture
def missing_so_exe(tmp_path):
    if not _CC:
        pytest.skip("no C compiler")
    lib = tmp_path / "lib"
    lib.mkdir()
    (tmp_path / "g.c").write_text("int lykos_gone(void){return 1;}\n")
    r = subprocess.run([_CC, "-shared", "-fPIC", str(tmp_path / "g.c"), "-o",
                        str(lib / "liblykosgone2.so")], capture_output=True)
    if r.returncode != 0:
        pytest.skip("cannot build a shared object")
    (tmp_path / "m.c").write_text("int lykos_gone(void);\nint main(void){return lykos_gone()-1;}\n")
    exe = tmp_path / "uses_gone"
    r = subprocess.run([_CC, str(tmp_path / "m.c"), f"-L{lib}", "-llykosgone2", "-o", str(exe)],
                       capture_output=True)
    if r.returncode != 0:
        pytest.skip("cannot link against the shared object")
    (lib / "liblykosgone2.so").unlink()                       # now the loader cannot find it
    return exe


@needs_bwrap
@pytest.mark.parametrize("blocks", [(), (0x1000,)], ids=["untraced", "traced"])
def test_run_batch_reports_a_missing_library_as_not_run(missing_so_exe, blocks):
    rs = sandbox.run_batch(str(missing_so_exe), [b"a", b"b", b"c"], blocks=blocks)
    if rs is None:
        pytest.skip("batch path unavailable here")
    assert len(rs) == 3
    for r in rs:
        assert sandbox.did_not_run(r.isolation), r
        assert not r.crashed
        assert "liblykosgone2.so" in (r.note or ""), r.note   # the loader's own words, quoted


@needs_bwrap
@pytest.mark.parametrize("blocks", [(), (0x1000,)], ids=["untraced", "traced"])
def test_run_batch_reports_an_exec_failure_as_not_run(tmp_path, blocks):
    """An ELF whose interpreter does not exist: execv fails in the runner. The traced path used to
    read the reaped child as rc=0 -- a CLEAN run of a program that never started."""
    if not _CC:
        pytest.skip("no C compiler")
    exe = _build(tmp_path, "ok", "int main(void){return 0;}\n")
    b = bytearray(exe.read_bytes())
    i = b.find(b"/lib64/ld-linux-x86-64.so.2")
    if i < 0:
        pytest.skip("not an x86-64 glibc interpreter path")
    b[i:i + 27] = b"/lib64/ld-nope-x86-64.so.99"
    exe.write_bytes(bytes(b))
    rs = sandbox.run_batch(str(exe), [b"x", b"y"], blocks=blocks)
    if rs is None:
        pytest.skip("batch path unavailable here")
    assert all(sandbox.did_not_run(r.isolation) and r.exit_code != 0 for r in rs), rs


@needs_bwrap
def test_run_batch_still_runs_a_healthy_target(tmp_path):
    exe = _build(tmp_path, "ok2", "#include <unistd.h>\nint main(void){char b[8];"
                                  "return read(0,b,8)>0 ? 3 : 0;}\n")
    rs = sandbox.run_batch(str(exe), [b"a", b""])
    if rs is None:
        pytest.skip("batch path unavailable here")
    assert [r.exit_code for r in rs] == [3, 0]
    assert not any(sandbox.did_not_run(r.isolation) for r in rs)


# --------------------------------------------------------------------------------- net_fuzz
_LOGGY_VULN = r"""
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
static char junk[4096];
static void handle(int c){ char buf[32]; int n=read(c,buf,4096); if(n>0) write(c,"ok\n",3); }
int main(void){
    memset(junk,'L',sizeof junk);
    int s=socket(AF_INET,SOCK_STREAM,0); int one=1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(0);
    a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(s,(void*)&a,sizeof a); listen(s,4);
    for(;;){ int c=accept(s,0,0); if(c<0) continue;
             for(int i=0;i<40;i++) write(2,junk,sizeof junk);   /* 160 KiB of log per request */
             handle(c); close(c); }
}
"""


@needs_cc
def test_netfuzz_drains_a_logging_servers_stderr(tmp_path):
    """160 KiB of stderr per request fills an undrained pipe on the first connection; the server
    then blocks in write() and every later payload reads as 'survived'."""
    exe = _build(tmp_path, "loggy", _LOGGY_VULN)
    res = netfuzz.fuzz_server(str(exe), "tcp", max_execs=60, listen_timeout=5)
    assert res.crashed, f"logging server wedged instead of crashing (note={res.note})"
    assert res.signal_name == "SIGSEGV" and res.signal == 11


_ONE_SHOT = r"""
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
int main(void){
    int s=socket(AF_INET,SOCK_STREAM,0); int one=1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(0);
    a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(s,(void*)&a,sizeof a); listen(s,1);
    int c=accept(s,0,0); char buf[32]; int n=read(c,buf,4096); if(n>0) write(c,"ok\n",3);
    close(c); return 0;                                        /* one connection, then exit */
}
"""


@needs_cc
def test_netfuzz_respawns_a_one_shot_server_instead_of_stopping(tmp_path):
    """A server that handles ONE connection and exits ended the whole campaign after the first
    (benign) payload with 'exit0'. It is respawned now, so the overflowing seed reaches it."""
    exe = _build(tmp_path, "oneshot", _ONE_SHOT)
    res = netfuzz.fuzz_server(str(exe), "tcp", max_execs=40, listen_timeout=5)
    assert res.crashed, f"one-shot server never got past payload #1 (note={res.note}, " \
                        f"execs={res.execs})"
    assert res.execs > 1


_ESCAPE_SERVER = r"""
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
int main(int argc, char **argv){
    FILE *f = fopen(argv[1], "w"); if (f) { fputs("escaped", f); fclose(f); }
    int s=socket(AF_INET,SOCK_STREAM,0); int one=1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(0);
    a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(s,(void*)&a,sizeof a); listen(s,4);
    for(;;){ int c=accept(s,0,0); if(c<0) continue; char b[64]; read(c,b,64); close(c); }
}
"""


@needs_cc
@needs_bwrap
def test_netfuzz_server_is_contained_but_reachable(tmp_path):
    """Under the sandbox the server cannot write the host filesystem, yet we still find its port
    (it is a GRANDCHILD of the bwrap pid now) and reach it over loopback."""
    exe = _build(tmp_path, "escape", _ESCAPE_SERVER)
    outside = tmp_path / "host-write"
    res = netfuzz.fuzz_server(str(exe), "tcp", argv=[str(outside)], max_execs=20,
                              listen_timeout=5)
    assert res.isolation == "bwrap+loopback"
    assert res.port and res.execs >= 20, res.note           # found the port, delivered payloads
    assert not outside.exists(), "the server wrote to the host filesystem"


@needs_cc
def test_netfuzz_quotes_why_a_server_never_listened(tmp_path):
    exe = _build(tmp_path, "nolisten", '#include <stdio.h>\nint main(void){'
                                       'fputs("fatal: cannot read /etc/lykosd.conf\\n", stderr);'
                                       'return 2;}\n')
    notes = []
    res = netfuzz.fuzz_server(str(exe), "tcp", max_execs=5, listen_timeout=2,
                              on_attempt=lambda d, det, ph: notes.append(det.get("note")))
    assert not res.crashed and res.note == "no-listen"
    assert any("lykosd.conf" in (n or "") for n in notes), notes


@needs_cc
def test_netfuzz_honours_should_stop(tmp_path):
    exe = _build(tmp_path, "echo", _ESCAPE_SERVER)
    calls = {"n": 0}

    def stop():
        calls["n"] += 1
        return calls["n"] > 3
    res = netfuzz.fuzz_server(str(exe), "tcp", argv=[str(tmp_path / "x")], max_execs=10_000,
                              listen_timeout=5, should_stop=stop)
    assert not res.crashed and res.execs == 3 and "stopped" in (res.note or "")


# --------------------------------------------------------------------------------- env_fuzz
_ENV_VULN = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv){
    FILE *f = fopen(argv[1], "w"); if (f) { fputs("escaped", f); fclose(f); }
    const char *v = getenv("LYKOS_CFG"); char buf[16];
    if (v) strcpy(buf, v);
    return buf[0] == 'Z';
}
"""


@needs_cc
def test_envfuzz_crash_is_found_and_classified_under_the_sandbox(tmp_path):
    exe = _build(tmp_path, "envvuln", _ENV_VULN)
    outside = tmp_path / "host-write"
    res = envfuzz.fuzz_env(str(exe), ["LYKOS_CFG"], argv=[str(outside)], max_execs=60,
                           timeout=3)
    assert res.crashed and res.var == "LYKOS_CFG", res.note
    assert res.signal_name in ("SIGSEGV", "SIGBUS", "SIGABRT")
    if _BWRAP:
        assert res.isolation == "bwrap+netns"
        assert not outside.exists(), "the target wrote to the host filesystem"
        # a crash under bwrap (exit 128+N) is still handed back as the native negative rc
        d = envfuzz._run_with_env_detail(str(exe), [str(outside)], {"LYKOS_CFG": "A" * 400})
        assert d["rc"] is not None and d["rc"] < 0, d
    else:
        assert res.isolation == "rlimits-only"


@needs_cc
def test_envfuzz_target_sees_exactly_the_fuzzed_environment(tmp_path):
    """The variables reach the TARGET (via `env -i` inside the namespace), not just bwrap."""
    exe = _build(tmp_path, "envecho", '#include <stdlib.h>\n#include <string.h>\n'
                                      'int main(void){const char*v=getenv("LYKOS_X");'
                                      'if(!v) return 10; if(getenv("LYKOS_NOT_PASSED")) return 11;'
                                      'return strcmp(v,"hello")==0 ? 0 : 12;}\n')
    os.environ["LYKOS_NOT_PASSED"] = "1"
    try:
        d = envfuzz._run_with_env_detail(str(exe), [], {"LYKOS_X": "hello"}, timeout=5)
    finally:
        os.environ.pop("LYKOS_NOT_PASSED", None)
    assert d["rc"] == 0, d


def test_envfuzz_timeout_kills_the_whole_group(tmp_path, monkeypatch):
    """The unwrapped tier (no bubblewrap) is the one where a bare proc.kill() let a forked child
    live on; under bwrap the namespace dies with its monitor anyway."""
    monkeypatch.setattr(sandbox, "_bwrap_usable", lambda: False)
    sh = shutil.which("sh")
    if not sh:
        pytest.skip("no sh")
    marker = tmp_path / "still-alive"
    s = tmp_path / "forker.sh"
    # the forked child would touch the marker 2 s later if it survived the timeout kill
    s.write_text(f"#!/bin/sh\n(sleep 2; : > {marker}) &\nsleep 30\n")
    s.chmod(0o755)
    t0 = time.time()
    d = envfuzz._run_with_env_detail(str(s), [], {}, timeout=0.5)
    assert d["timed_out"] and time.time() - t0 < 5
    time.sleep(2.5)
    assert not marker.exists(), "a child of the timed-out target survived the kill"


# ------------------------------------------------------------------------------------- AFL++
def test_afl_bench_just_one_is_never_set(monkeypatch, tmp_path):
    """AFL++ tests AFL_BENCH_JUST_ONE for PRESENCE: "0" turned it on and every campaign stopped
    after its first queue entry."""
    seen = {}

    class _P:
        returncode, pid = 0, 1

        def wait(self, timeout=None):
            return 0

    def fake_popen(cmd, env=None, **kw):
        seen["env"] = env or {}
        return _P()
    monkeypatch.setenv("AFL_BENCH_JUST_ONE", "1")             # even an inherited one goes
    monkeypatch.setattr(aflpp, "contain", lambda cmd, **k: (cmd, "rlimits-only", "test"))
    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    sd = tmp_path / "in"
    sd.mkdir()
    exe = tmp_path / "t"
    exe.write_bytes(b"\x7fELF")
    aflpp.run_campaign(Path("/usr/bin/afl-fuzz"), exe, sd, tmp_path / "out", seconds=1)
    assert "AFL_BENCH_JUST_ONE" not in seen["env"]


def test_afl_contain_degrades_loudly_without_bwrap(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox, "_bwrap_usable", lambda: False)
    cmd = ["/usr/bin/afl-fuzz", "-i", "in", "-o", "out", "--", "t"]
    out, iso, note = aflpp.contain(cmd, afl="/usr/bin/afl-fuzz", exe=tmp_path / "t",
                                   seeds_dir=tmp_path, out_dir=tmp_path / "out", env={})
    assert out == cmd and iso == "rlimits-only" and "WITHOUT the sandbox" in note


@needs_bwrap
def test_afl_contain_wraps_and_binds_the_campaign_dirs(tmp_path):
    afl = shutil.which("afl-fuzz")
    if not afl:
        pytest.skip("afl-fuzz not installed")
    sd, od = tmp_path / "in", tmp_path / "out"
    sd.mkdir()
    exe = tmp_path / "target.bin"
    exe.write_bytes(b"\x7fELF")
    cmd = [afl, "-i", str(sd), "-o", str(od), "--", str(exe)]
    out, iso, note = aflpp.contain(cmd, afl=afl, exe=exe, seeds_dir=sd, out_dir=od,
                                   env=dict(os.environ))
    assert iso == "bwrap+netns" and not note
    assert out[0] == "bwrap" and out[-len(cmd):] == cmd
    i = [j for j, a in enumerate(out) if a == "--bind" and out[j + 1] == str(tmp_path.resolve())]
    assert i, "the campaign's work dir must be bound WRITABLE (afl writes its queue there)"
    assert "--unshare-net" in out


_A64 = shutil.which("aarch64-linux-gnu-gcc")


@needs_bwrap
@pytest.mark.skipif(not (_A64 and shutil.which("afl-fuzz")), reason="needs afl-fuzz + aarch64 cc")
def test_real_afl_campaign_runs_its_budget_inside_the_sandbox(tmp_path):
    """End to end: a -Q campaign under bubblewrap runs for its whole -V budget and finds the
    crash. Before the AFL_BENCH_JUST_ONE fix it stopped ~1 s in, sandbox or not."""
    afl = aflpp.locate_afl(None)
    trace = aflpp.locate_qemu_trace_for(afl, "aarch64") if afl else None
    if trace is None:
        pytest.skip("no aarch64 afl-qemu-trace")
    (tmp_path / "t.c").write_text(
        "#include <unistd.h>\nint main(void){char b[64];int n=read(0,b,64);"
        "if(n>3&&b[0]=='C'&&b[1]=='R'&&b[2]=='A'){char*p=0;*p=1;}return 0;}\n")
    exe = tmp_path / "target.bin"
    r = subprocess.run([_A64, "-static", "-O0", str(tmp_path / "t.c"), "-o", str(exe)],
                       capture_output=True)
    if r.returncode != 0:
        pytest.skip("aarch64 build failed")
    sd = tmp_path / "in"
    sd.mkdir()
    (sd / "s0").write_bytes(b"AAAA")
    ap = aflpp.stage_qemu_trace(trace, tmp_path)
    t0 = time.time()
    cp = aflpp.run_campaign(afl, exe, sd, tmp_path / "out", seconds=8, mode="stdin",
                            qemu=True, afl_path=ap)
    assert aflpp.campaign_failed(cp) is None, cp.stderr[-400:]
    assert cp.isolation == "bwrap+netns", cp.isolation_note
    assert time.time() - t0 >= 6, "afl-fuzz quit early (bench-just-one?)"
    st = aflpp.campaign_stats(tmp_path / "out")
    assert int(st.get("run_time", "0")) >= 5, st


# ------------------------------------------------------------------------------- differential
def test_differential_ignores_a_program_that_never_ran():
    ran = types.SimpleNamespace(isolation="bwrap+netns", crashed=False, timed_out=False,
                                exit_code=0, stdout=b"")
    norun = types.SimpleNamespace(isolation="bwrap+netns/not-runnable", crashed=False,
                                  timed_out=False, exit_code=127, stdout=b"")
    hung = types.SimpleNamespace(isolation="bwrap+netns", crashed=False, timed_out=True,
                                 exit_code=None, stdout=b"")
    oc = {"a": differential.outcome(ran), "b": differential.outcome(norun),
          "c": differential.outcome(hung)}
    assert oc == {"a": "accept", "b": differential.NORUN, "c": differential.TIMEOUT}
    assert differential.discrepancy(oc)["disagree"] is False   # no fabricated accept-reject


def test_differential_file_mode_input_reaches_the_sandboxed_target(tmp_path):
    sh = shutil.which("sh")
    if not sh:
        pytest.skip("no sh")
    a = tmp_path / "strict.sh"
    a.write_text('#!/bin/sh\ngrep -q x "$1"\n')               # accepts only inputs holding 'x'
    b = tmp_path / "lax.sh"
    b.write_text('#!/bin/sh\ntest -r "$1"\n')                 # accepts any readable input
    for p in (a, b):
        p.chmod(0o755)
    progs = [differential.Program("strict", str(a), mode="file"),
             differential.Program("lax", str(b), mode="file")]
    oc = differential.outcomes_for(progs, b"abc")
    assert oc == {"strict": "reject", "lax": "accept"}, \
        "the input file was invisible inside the sandbox (both rejected)"
    assert differential.outcomes_for(progs, b"xyz") == {"strict": "accept", "lax": "accept"}


# ----------------------------------------------------------------------- prompted / menu drain
def test_prompted_runner_enforces_its_timeout(tmp_path):
    from lykos.analyze.fuzz.runner import run_input_prompted
    sh = shutil.which("sh")
    if not sh:
        pytest.skip("no sh")
    s = tmp_path / "prompt.sh"
    s.write_text("#!/bin/sh\necho 'name:'\nread x\nwhile :; do sleep 1; done\n")
    s.chmod(0o755)
    t0 = time.time()
    _argv, res = run_input_prompted(str(s), b"bob\n", timeout=1.0)
    assert time.time() - t0 < 10, "a still-running target blocked the stdout read"
    assert res.timed_out and "prompted" in res.isolation
    assert not sandbox.did_not_run(res.isolation)


def test_prompted_runner_reports_a_loader_failure_as_not_run(missing_so_exe):
    from lykos.analyze.fuzz.runner import run_input_prompted
    _argv, res = run_input_prompted(str(missing_so_exe), b"x\n", timeout=3.0)
    assert sandbox.did_not_run(res.isolation), res


def test_menu_drain_does_not_block_on_a_lingering_grandchild():
    import selectors
    p = subprocess.Popen(["sh", "-c", "echo hi; (sleep 20 &); exit 0"], stdout=subprocess.PIPE,
                         stdin=subprocess.PIPE, start_new_session=True)
    try:
        sel = selectors.DefaultSelector()
        sel.register(p.stdout, selectors.EVENT_READ)
        p.wait(timeout=5)
        t0 = time.monotonic()
        out, alive = menu._drain(p, sel, idle=0.1, deadline=time.monotonic() + 3)
        assert time.monotonic() - t0 < 5 and not alive and "hi" in out
    finally:
        try:
            os.killpg(p.pid, 9)
        except OSError:
            pass
        menu._kill(p)
