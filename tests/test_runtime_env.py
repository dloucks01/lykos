"""Runtime-environment discovery (doc 47 R2.d / P5): a target that needs a config WITH content at
a fixed path, a data dir, or an env var gets them -- staged inside the sandbox, confirmed by
running it, minimised to what it actually needed -- and a target that needs nothing is untouched.
"""
import os
import shutil
import subprocess

import pytest
from lykos.analyze import runtime_env as R
from lykos.analyze.dynamic import sandbox
from lykos.analyze.fuzz import textconf

# Unique names so no host path can satisfy a gate by accident (the tests assert they don't exist).
GATE_ALL = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
int main(void){
  FILE *f = fopen("/etc/lykosrt_t1/app.conf", "r");
  if(!f){ fprintf(stderr, "cannot open config /etc/lykosrt_t1/app.conf\n"); return 2; }
  char line[256]; int kv = 0;
  while(fgets(line, sizeof line, f)) if(line[0] != '#' && strchr(line, '=')) kv++;
  if(!kv){ fprintf(stderr, "empty config\n"); return 3; }
  if(!getenv("LYKOSRT_HOME")){ fprintf(stderr, "LYKOSRT_HOME not set\n"); return 4; }
  DIR *d = opendir("/var/lib/lykosrt_t1");
  if(!d){ fprintf(stderr, "no data dir\n"); return 5; }
  puts("REACHED"); return 0; }
'''

REL_CONF = r'''
#include <stdio.h>
#include <string.h>
static const char *keys[] = {"listen", "workers", "logdir", 0};
int main(void){
  FILE *f = fopen("conf/lykosrt_rel.conf", "r");
  if(!f){ fprintf(stderr, "cannot open conf/lykosrt_rel.conf\n"); return 2; }
  char line[256]; int n = 0;
  while(fgets(line, sizeof line, f))
    for(int i = 0; keys[i]; i++) if(!strncmp(line, keys[i], strlen(keys[i]))) n++;
  if(!n){ fprintf(stderr, "no known key in config\n"); return 3; }
  puts("REACHED"); return 0; }
'''

ENV_ONLY = r'''
#include <stdio.h>
#include <stdlib.h>
int main(void){
  const char *t = getenv("LYKOSRT_TOKEN");
  if(!t || !*t){ fprintf(stderr, "LYKOSRT_TOKEN must be set\n"); return 7; }
  puts("REACHED"); return 0; }
'''

DAEMON = r'''
#include <stdio.h>
#include <unistd.h>
int main(void){
  FILE *f = fopen("/etc/lykosrt_daemon.conf", "r");
  if(!f){ fprintf(stderr, "cannot open /etc/lykosrt_daemon.conf\n"); return 1; }
  for(;;) pause();                    /* configured: the daemon stays up */
}
'''

# The data dir's path is BUILT at run time, so no call site names it: only the trace -- and only
# AFTER the config is supplied -- reveals it.
CHAIN = r'''
#include <stdio.h>
#include <dirent.h>
static const char *base = "/srv/lykosrt_chain";
int main(void){
  FILE *f = fopen("/etc/lykosrt_chain.conf", "r");
  if(!f){ fprintf(stderr, "cannot open /etc/lykosrt_chain.conf\n"); return 1; }
  char p[128]; snprintf(p, sizeof p, "%s/%s", base, "spool");
  DIR *d = opendir(p);
  if(!d){ fprintf(stderr, "cannot open spool\n"); return 2; }
  puts("REACHED"); return 0; }
'''

PLAIN = r'''
#include <stdio.h>
int main(void){ puts("hello"); return 0; }
'''

# Reads an OPTIONAL config and falls back to defaults: it already runs, so nothing may change.
OPTIONAL = r'''
#include <stdio.h>
#include <stdlib.h>
int main(void){
  FILE *f = fopen("/etc/lykosrt_optional.conf", "r");
  const char *v = getenv("LYKOSRT_OPTIONAL_LEVEL");
  printf("defaults %d %d\n", f != 0, v != 0); return 0; }
'''


def _build(gcc, tmp_path, name, src):
    d = tmp_path / name
    d.mkdir()
    (d / "t.c").write_text(src)
    exe = d / "target.bin"
    subprocess.run([gcc, "-O2", str(d / "t.c"), "-o", str(exe)], check=True, capture_output=True)
    return exe


def _contained(renv, exe):
    """Run `exe` contained with `renv` the way the sandbox hook will: bwrap args + env."""
    return R._run_probe(str(exe), [], renv, timeout=5.0, trace=False)


need_bwrap = pytest.mark.skipif(not sandbox._bwrap_usable(), reason="bubblewrap unusable here")
need_overlay = pytest.mark.skipif(not R.overlay_usable(), reason="bwrap cannot tmp-overlay here")
need_strace = pytest.mark.skipif(not shutil.which("strace"), reason="no strace")


@pytest.fixture(autouse=True)
def _host_paths_absent():
    for p in ("/etc/lykosrt_t1", "/var/lib/lykosrt_t1", "/etc/lykosrt_daemon.conf",
              "/srv/lykosrt_chain", "/etc/lykosrt_chain.conf", "/etc/lykosrt_optional.conf"):
        assert not os.path.lexists(p), f"host already has {p}; fixture would not be gated"


# --- static discovery -------------------------------------------------------------------------------

def test_callsite_recovery_names_env_file_and_dir(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "g", GATE_ALL)
    sites = {(c["func"], c["value"]) for c in R.callsite_args(exe.read_bytes())}
    assert ("fopen", "/etc/lykosrt_t1/app.conf") in sites
    assert ("getenv", "LYKOSRT_HOME") in sites
    assert ("opendir", "/var/lib/lykosrt_t1") in sites
    needs = R.discover(exe.read_bytes())
    assert [e["name"] for e in needs["env"]] == ["LYKOSRT_HOME"]
    kinds = {p["path"]: p["kind"] for p in needs["paths"]}
    assert kinds == {"/etc/lykosrt_t1/app.conf": "file", "/var/lib/lykosrt_t1": "dir"}
    # symbol names are not config keys
    assert not {"getenv", "opendir", "puts"} & set(needs["config"]["keys"])


def test_callsite_recovery_at_O0(gcc, tmp_path):
    d = tmp_path / "o0"
    d.mkdir()
    (d / "t.c").write_text(GATE_ALL)
    exe = d / "t0"
    subprocess.run([gcc, "-O0", str(d / "t.c"), "-o", str(exe)], check=True, capture_output=True)
    sites = {(c["func"], c["value"]) for c in R.callsite_args(exe.read_bytes())}
    assert {("fopen", "/etc/lykosrt_t1/app.conf"), ("getenv", "LYKOSRT_HOME"),
            ("opendir", "/var/lib/lykosrt_t1")} <= sites


def test_parse_trace_strace_and_qemu_formats():
    text = ('4 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3\n'
            '4 openat(AT_FDCWD, "/etc/app/app.conf", O_RDONLY) = -1 ENOENT (No such file)\n'
            '77 openat(AT_FDCWD,"/var/lib/app",O_RDONLY|O_DIRECTORY) = -1 errno=2 (No such file '
            'or directory)\n'
            '4 chdir("/srv/x") = -1 ENOENT (No such file or directory)\n')
    t = R.parse_trace(text)
    assert [p for _s, p, _f in t["enoent"]] == ["/etc/app/app.conf", "/var/lib/app", "/srv/x"]
    assert t["calls"] == 4


def test_plausible_config_has_content_in_the_named_format():
    strs = ["[server]", "listen", "port", "workers", "datadir", "%s = %s"]
    body = textconf.plausible_config("/etc/app/app.ini", strs).decode()
    assert "[server]" in body and "port = 8080" in body and "datadir = /tmp" in body
    js = textconf.plausible_config("/etc/app/app.json", strs, keys=["port"]).decode()
    assert '"port": "8080"' in js
    # never empty, even with nothing to go on
    assert b"=" in textconf.plausible_config("/etc/x.conf", [])


# --- confirmed supply -------------------------------------------------------------------------------

@need_bwrap
@need_overlay
@need_strace
def test_gate_all_gets_config_env_and_datadir(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "g", GATE_ALL)
    assert _contained(None, exe).rc == 2                       # gated without help
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0)
    s = renv.summary()
    assert renv.applied, s["note"]
    assert s["baseline"]["rc"] == 2 and s["result"]["rc"] == 0
    assert s["result"]["says"] == "REACHED"
    got = {(r["kind"], r.get("path") or r.get("name")) for r in s["supplied"]}
    assert got == {("file", "/etc/lykosrt_t1/app.conf"), ("dir", "/var/lib/lykosrt_t1"),
                   ("env", "LYKOSRT_HOME")}
    conf = next(r for r in s["supplied"] if r["kind"] == "file")
    assert "=" in conf["content"]                              # a config WITH content
    assert all(r["confirmed"] == "removing it reverts the run" for r in s["supplied"])
    # the host was never touched
    assert not os.path.exists("/etc/lykosrt_t1") and not os.path.exists("/var/lib/lykosrt_t1")
    # the staged environment, applied the way the sandbox hook applies it, reaches the code
    r = _contained(renv, exe)
    assert r.rc == 0 and "REACHED" in r.out


@need_bwrap
@need_overlay
def test_gate_all_without_a_tracer_static_plus_differential(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "g", GATE_ALL)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0, trace=False)
    assert renv.applied, renv.note
    assert not renv.traced
    assert renv.result["says"] == "REACHED"
    assert {r.get("source") for r in renv.supplied} == {"call-site"}


@need_bwrap
def test_relative_config_with_keys_lands_in_cwd(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "rel", REL_CONF)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0)
    assert renv.applied, renv.note
    (rec,) = renv.supplied
    assert rec["path"] == "conf/lykosrt_rel.conf" and rec["at"] == "<cwd>/conf/lykosrt_rel.conf"
    assert any(k in rec["content"] for k in ("listen", "workers", "logdir"))
    assert _contained(renv, exe).rc == 0


@need_bwrap
def test_env_only_gate(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "env", ENV_ONLY)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0)
    assert renv.applied, renv.note
    assert list(renv.env) == ["LYKOSRT_TOKEN"] and renv.env["LYKOSRT_TOKEN"]
    assert renv.files == [] and renv.overlays == []


@need_bwrap
@need_overlay
def test_daemon_that_stays_up_once_configured(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "d", DAEMON)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=1.5)
    assert renv.applied, renv.note
    assert renv.result["timed_out"] and "stays up" in renv.note


@need_bwrap
@need_overlay
@need_strace
def test_trace_chases_what_the_first_supply_unlocked(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "c", CHAIN)
    # nothing static names the spool dir: it is assembled at run time
    assert "/srv/lykosrt_chain/spool" not in {p["path"] for p in
                                             R.discover(exe.read_bytes())["paths"]}
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0)
    assert renv.applied, renv.note
    paths = {r["path"]: r for r in renv.supplied}
    assert paths["/srv/lykosrt_chain/spool"]["source"] == "trace"
    assert "/etc/lykosrt_chain.conf" in paths
    assert renv.result["says"] == "REACHED"


def test_no_bwrap_absolute_path_is_degraded_not_written(gcc, tmp_path, monkeypatch):
    exe = _build(gcc, tmp_path, "g", GATE_ALL)
    monkeypatch.setattr(sandbox, "_bwrap_usable", lambda: False)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0, trace=False)
    # it cannot get past the first gate without writing /etc -- so nothing is applied, and the
    # absolute paths are reported as not suppliable rather than silently skipped
    assert not renv.applied
    assert {d["path"] for d in renv.degraded} >= {"/etc/lykosrt_t1/app.conf"}
    assert not os.path.exists("/etc/lykosrt_t1")


def test_no_bwrap_relative_config_still_supplied_via_cwd(gcc, tmp_path, monkeypatch):
    exe = _build(gcc, tmp_path, "rel", REL_CONF)
    monkeypatch.setattr(sandbox, "_bwrap_usable", lambda: False)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0, trace=False)
    assert renv.applied, renv.note
    d = tmp_path / "cwd"
    d.mkdir()
    renv.populate_cwd(d)
    assert b"=" in (d / "conf" / "lykosrt_rel.conf").read_bytes()


# --- negative controls: never degrade --------------------------------------------------------------

def test_plain_target_is_untouched(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "p", PLAIN)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0)
    assert not renv.applied and renv.bwrap_args() == [] and renv.env == {}
    assert "nothing supplied" in renv.note
    assert renv.runs == 1                                    # one baseline, no probing


def test_target_with_optional_config_is_untouched(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "o", OPTIONAL)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0)
    assert not renv.applied, renv.summary()
    R.register(renv, exe)
    assert R.for_exe(exe) is None                            # a no-op env is never registered


@need_bwrap
def test_registry_keys_on_the_staged_dir(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "env", ENV_ONLY)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0)
    assert renv.applied
    R.register(renv, exe)
    try:
        assert R.for_exe(exe) is renv and R.for_exe(exe.parent) is renv
        assert R.for_exe(tmp_path) is None
    finally:
        R.unregister(exe)
    assert R.for_exe(exe) is None


# --- invocation: a config value slot gets content (opt-in) ---------------------------------------------

def test_materialize_config_slot_gets_content_only_when_asked(tmp_path):
    from lykos.analyze import invocation as inv
    found = {"flags": [{"flag": "-C", "takes_value": True, "kind": "config",
                        "placeholder": "<config>"},
                       {"flag": "-c", "takes_value": True, "kind": "config",
                        "placeholder": "<config>"}], "usage": "", "sources": []}
    argv = inv.materialize(found, tmp_path / "a")
    assert "@@" in argv
    conf = tmp_path / "a" / "lykos.conf"
    assert conf.read_bytes() == b"# lykos\n"                  # unchanged default
    inv.materialize(found, tmp_path / "b", strings=["listen", "workers", "[main]", "getenv"])
    body = (tmp_path / "b" / "lykos.conf").read_text()
    assert "[main]" in body and "listen=127.0.0.1" in body and "workers=1" in body


# --- an asterisk-shaped daemon: config with a section + keys, a runtime dir to create in /var/run,
# a pid file in it, a data dir -- and then it stays up --------------------------------------------

DAEMONISH = r'''
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
static const char *keys[] = {"astrundir", "astdatadir", "astlogdir", 0};
int main(int argc, char **argv){
  const char *conf = "/etc/lykosrt_ast/lykosrt_ast.conf";
  for(int i = 1; i < argc - 1; i++) if(!strcmp(argv[i], "-C")) conf = argv[++i];
  FILE *f = fopen(conf, "r");
  if(!f){ fprintf(stderr, "Unable to open specified master config file '%s'\n", conf); return 1; }
  char line[256]; int sec = 0, k = 0;
  while(fgets(line, sizeof line, f)){
    if(!strncmp(line, "[directories]", 13)) sec = 1;
    for(int i = 0; keys[i]; i++) if(sec && !strncmp(line, keys[i], strlen(keys[i]))) k++;
  }
  if(!k){ fprintf(stderr, "no [directories] configured\n"); return 1; }
  if(mkdir("/var/run/lykosrt_ast", 0755) && errno != EEXIST){
    fprintf(stderr, "Unable to create rundir /var/run/lykosrt_ast: %s\n", strerror(errno)); return 1; }
  int fd = open("/var/run/lykosrt_ast/lykosrt_ast.pid", O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if(fd < 0){ fprintf(stderr, "Unable to open pid file: %s\n", strerror(errno)); return 1; }
  if(!opendir("/var/lib/lykosrt_ast")){ fprintf(stderr, "Unable to open data dir\n"); return 1; }
  puts("Asterisk Ready."); fflush(stdout);
  for(;;) pause();
}
'''


@need_bwrap
@need_overlay
@need_strace
def test_daemonish_config_rundir_pidfile_datadir(gcc, tmp_path):
    assert not os.path.lexists("/run/lykosrt_ast") and not os.path.lexists("/etc/lykosrt_ast")
    exe = _build(gcc, tmp_path, "ast", DAEMONISH)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=1.5)
    s = renv.summary()
    assert renv.applied, s
    assert s["result"]["timed_out"] and "stays up" in renv.note
    sup = {r["path"]: r for r in s["supplied"]}
    conf = sup["/etc/lykosrt_ast/lykosrt_ast.conf"]
    assert "[directories]" in conf["content"] and "astrundir" in conf["content"]
    assert "/var/lib/lykosrt_ast" in sup
    # the runtime dir is created in a writable /run (overlay or a fresh tmpfs), never on the host
    assert any(r["kind"] in ("dir", "writable-dir") and "lykosrt_ast" in r["path"]
               and r["path"].startswith(("/run", "/var/run")) or r["kind"] == "writable-dir"
               for r in s["supplied"])
    assert not os.path.lexists("/run/lykosrt_ast") and not os.path.lexists("/etc/lykosrt_ast")
    assert all(r["confirmed"] == "removing it reverts the run" for r in s["supplied"])


# --- cross-arch: qemu -strace is the tracer, strings the static source ---------------------------------

@need_bwrap
@need_overlay
@pytest.mark.skipif(not (shutil.which("aarch64-linux-gnu-gcc") and sandbox._qemu_for("aarch64")),
                    reason="no aarch64 cross compiler / qemu-aarch64")
def test_cross_arch_aarch64_gate(tmp_path):
    d = tmp_path / "a64"
    d.mkdir()
    (d / "t.c").write_text(GATE_ALL)
    exe = d / "target.bin"
    subprocess.run(["aarch64-linux-gnu-gcc", "-O2", str(d / "t.c"), "-o", str(exe)], check=True,
                   capture_output=True)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=8.0, arch="aarch64",
                     endianness="little", bits=64)
    assert renv.applied, renv.summary()
    assert renv.traced and renv.result["says"] == "REACHED"
    assert {r.get("path") or r.get("name") for r in renv.supplied} == {
        "/etc/lykosrt_t1/app.conf", "/var/lib/lykosrt_t1", "LYKOSRT_HOME"}


# --- gating precision: help text is not a complaint; a flood of env knobs is not a gate -----------------

def test_help_table_is_not_a_missing_resource_complaint():
    p = R._Probe(rc=1, out="usage: git [-v | --version]\n\n   backfill   Download missing objects\n")
    assert not R._gated(p)
    q = R._Probe(rc=1, out="fatal: cannot open config /etc/x.conf\n")
    assert R._gated(q)
    # a clean exit / a run that stays up is never gated, whatever it printed
    assert not R._gated(R._Probe(rc=0, out="warning: no such file, using defaults\n"))
    assert not R._gated(R._Probe(timed_out=True, out="cannot open x\n"))


def test_stage_hook_reports_and_registers(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "env", ENV_ONLY)
    events = []

    class Ctx:
        def scratch(self):
            return tmp_path / "scratch"

        def emit(self, kind, payload=None):
            events.append((kind, payload))

    (tmp_path / "scratch").mkdir()

    class T:
        arch = sandbox.host_arch()
        endianness = "little"
        bits = 64

    renv = R.stage_hook(Ctx(), T(), exe, exec_timeout=1.0)
    try:
        assert events and events[0][0] == "runtime_env"
        if sandbox._bwrap_usable():
            assert renv.applied and events[0][1]["supplied"][0]["name"] == "LYKOSRT_TOKEN"
            assert R.for_exe(exe) is renv and R.for_exe(tmp_path / "scratch") is renv
            assert R.bwrap_args_for(exe) == renv.bwrap_args()
    finally:
        R.release(Ctx(), exe)
    assert R.for_exe(exe) is None and R.bwrap_args_for(exe) == []
