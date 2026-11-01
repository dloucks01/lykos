"""Concolic reach past a VALUE GUARD to a command-injection sink (doc 58, reaching bridge).

Enumeration (menu sequences) cannot pass a sink guarded by a magic number / byte compare. The angr
hypo driver symbolically solves a stdin that REACHES the sink through the guard; _concolic_consume
then substitutes our own forgery-proof payload into the solved sink-argument slot (keeping the
guard-passing prefix) and confirms by effect -- the injected command RUNS, not echoes.
"""
import shutil
import subprocess

import pytest

from lykos.analyze.poc import inject_stage, injection

_HAVE_ANGR = None


def _have_angr():
    global _HAVE_ANGR
    if _HAVE_ANGR is None:
        try:
            from lykos.hypo import engine
            _HAVE_ANGR = engine.angr_python() is not None and engine._scope_usable()
        except Exception:
            _HAVE_ANGR = False
    return _HAVE_ANGR


# A cmdi sink behind a 4-byte MAGIC guard read via read() (no menu option opens it -- only a solver
# finds the magic bytes). Then it reads a line and system()s it.
_FIXTURE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
int main(void){
    unsigned char magic[4]; char buf[128];
    if (read(0, magic, 4) != 4) return 0;
    if (magic[0]==0xde && magic[1]==0xad && magic[2]==0xbe && magic[3]==0xef) {
        int n = read(0, buf, sizeof buf - 1); if (n <= 0) return 0; buf[n] = 0;
        buf[strcspn(buf, "\n")] = 0;
        system(buf);                                 /* cmdi behind the value guard */
    }
    return 0;
}
"""


class _Ctx:
    params = {"concolic_budget": 60, "timeout": 8}

    def should_cancel(self):
        return False

    def progress(self, **kw):
        pass


class _Target:
    # Match the host's canonical arch string so sandbox.run stays native (not qemu).
    from lykos.analyze.dynamic import sandbox as _sb
    arch = _sb.host_arch()
    endianness = "little"
    bits = 64
    mitigations = {}


def _build(tmp_path):
    src = tmp_path / "vg.c"
    src.write_text(_FIXTURE)
    exe = tmp_path / "vg"
    r = subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-O0", "-w", "-o", str(exe),
                        str(src)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"fixture build failed: {r.stderr[:200]}")
    exe.chmod(0o755)
    return exe


# A cmdi sink behind a NUMERIC guard read via scanf("%u") -- the common menu pattern. angr's own
# scanf crashes on a symbolic stream position; the driver's PreciseScanf must solve the guard. The
# stdin is unbuffered (setvbuf _IONBF) -- the standard CTF pattern that lets scanf and a later raw
# read() mix (with a buffered FILE, scanf slurps the whole pipe and read(0) gets nothing, so the
# sink would be unreachable at runtime for ANY input regardless of the solver).
_FIXTURE_SCANF = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
int main(void){
    unsigned key; char buf[128];
    setvbuf(stdin, NULL, _IONBF, 0);
    if (scanf("%u", &key) != 1) return 0;
    if (key == 31337) {
        int n = read(0, buf, sizeof buf - 1); if (n <= 0) return 0; buf[n] = 0;
        buf[strcspn(buf, "\n")] = 0;
        system(buf);
    }
    return 0;
}
"""


def _build_src(tmp_path, src_text, name):
    src = tmp_path / (name + ".c")
    src.write_text(src_text)
    exe = tmp_path / name
    r = subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-O0", "-w", "-o", str(exe),
                        str(src)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"build failed: {r.stderr[:200]}")
    exe.chmod(0o755)
    return exe


@pytest.mark.skipif(not shutil.which("gcc"), reason="needs gcc")
def test_preprocess_scanf_numeric_guard_is_reached(tmp_path):
    # PreciseScanf fixes angr's scanf CRASH (a symbolic stream position used to raise in
    # format_parser), so a cmdi sink behind a scanf("%u") numeric guard is REACHED and solved
    # symbolically -- angr finds input making the scanned key == 31337.
    if not _have_angr():
        pytest.skip("needs the vendored angr venv + a usable systemd --user scope")
    exe = _build_src(tmp_path, _FIXTURE_SCANF, "vscanf")
    ctx, target = _Ctx(), _Target()
    out = inject_stage._run_concolic(ctx, target, exe.read_bytes(), exe)
    assert out, "angr driver returned nothing (scanf path would have crashed before the fix)"
    cmdi = [h for h in out.get("hypotheses", []) if h.get("cwe") == "CWE-78"]
    assert cmdi, "no command-injection hypothesis proposed"
    assert any(h.get("reached") for h in cmdi), \
        "the scanf('%u') value guard was not passed (PreciseScanf did not model the numeric read)"


@pytest.mark.skipif(not shutil.which("gcc"), reason="needs gcc")
def test_scanf_numeric_guard_run_reproduces(tmp_path):
    # The consumed-length FORKING model (fork_scanf) forks the scanf read on each feasible concrete
    # consumed-length, so the stream position stays CONCRETE and the sink's later read lands at a
    # fixed offset. The digits scanf ate ("31337") become a fixed-length prefix of the solved stdin
    # and our payload lands in the next read verbatim -- so the solution RUN-reproduces end-to-end
    # (the injected `echo` RUNS, proven by the forgery-proof marker), not just reaches. This is what
    # the earlier honest-limit note scoped as future work; the stream-position fix (SimFileStream
    # advances its OWN pos, not the duplex mirror) is what makes the rewind actually take effect.
    if not _have_angr():
        pytest.skip("needs the vendored angr venv + a usable systemd --user scope")
    exe = _build_src(tmp_path, _FIXTURE_SCANF, "vscanf")
    ctx, target = _Ctx(), _Target()
    out = inject_stage._run_concolic(ctx, target, exe.read_bytes(), exe)
    assert out and out.get("hypotheses"), "angr driver returned no hypotheses"

    spec = injection.PROBES["command-injection"]
    marker = "MKsc"
    payloads = spec["payloads"](marker)
    hit = inject_stage._concolic_consume(out, spec, payloads, marker, exe, target, timeout=8)
    assert hit is not None, "the scanf-guarded injection did not RUN-reproduce (forking model)"
    # The scanned number is the fixed-length guard prefix; the payload follows it immediately.
    assert hit["nav"] == b"31337", f"guard prefix was not the scanned number: {hit['nav']!r}"
    assert hit["stdin"].startswith(b"31337"), f"solved stdin missing the guard digits: {hit['stdin'][:8]!r}"
    assert spec["confirm"](hit["out"], hit["payload"], marker)


@pytest.mark.skipif(not shutil.which("gcc"), reason="needs gcc")
def test_concolic_solves_value_guarded_cmdi(tmp_path):
    if not _have_angr():
        pytest.skip("needs the vendored angr venv + a usable systemd --user scope")
    exe = _build(tmp_path)
    tb = exe.read_bytes()
    ctx, target = _Ctx(), _Target()

    out = inject_stage._run_concolic(ctx, target, tb, exe)
    assert out and out.get("hypotheses"), "angr driver returned no hypotheses"

    spec = injection.PROBES["command-injection"]
    marker = "MKvg"
    payloads = spec["payloads"](marker)
    hit = inject_stage._concolic_consume(out, spec, payloads, marker, exe, target, timeout=8)
    assert hit is not None, "concolic reach did not confirm a value-guarded injection"
    # The confirming stdin carries the solved magic-byte guard prefix, then our payload.
    assert hit["stdin"].startswith(b"\xde\xad\xbe\xef"), f"guard prefix missing: {hit['stdin'][:8]!r}"
    assert hit["nav"] == b"\xde\xad\xbe\xef"                 # the value-guard-passing prefix
    assert spec["confirm"](hit["out"], hit["payload"], marker)


# A cmdi sink behind a NON-MENU multi-step STATE gate: an earlier line sets the "mode", and the sink
# is reachable only when that line == "admin". Menu enumeration tries option tokens (1/2/3), never
# an arbitrary string like "admin", so only a solver passes this. The line models (line_fgets +
# precise_strcspn) make the earlier fg()-read line both solvable and run-reproducible.
_FIXTURE_STATE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){
    char mode[64], buf[128];
    if (!fgets(mode, sizeof mode, stdin)) return 0;
    mode[strcspn(mode, "\n")] = 0;
    if (strcmp(mode, "admin") == 0) {                /* non-menu state gate set by an earlier line */
        if (!fgets(buf, sizeof buf, stdin)) return 0;
        buf[strcspn(buf, "\n")] = 0;
        system(buf);                                 /* cmdi behind the state gate */
    }
    return 0;
}
"""


@pytest.mark.skipif(not shutil.which("gcc"), reason="needs gcc")
def test_concolic_solves_nonmenu_line_state_gate(tmp_path):
    # The concolic fallback enables the driver's line models (line_fgets KLEE-forks fgets per
    # concrete line length; precise_strcspn keeps `s[strcspn(s,"\n")]=0` from pinning the line at
    # its max length), so a sink gated by an EARLIER line's value is solved AND run-reproduces --
    # the gate enumeration (menu tokens) cannot pass. End-to-end: the injected command RUNS.
    if not _have_angr():
        pytest.skip("needs the vendored angr venv + a usable systemd --user scope")
    exe = _build_src(tmp_path, _FIXTURE_STATE, "vstate")
    ctx, target = _Ctx(), _Target()
    out = inject_stage._run_concolic(ctx, target, exe.read_bytes(), exe)
    assert out and out.get("hypotheses"), "angr driver returned no hypotheses"

    spec = injection.PROBES["command-injection"]
    marker = "MKst"
    hit = inject_stage._concolic_consume(out, spec, spec["payloads"](marker), marker, exe, target,
                                         timeout=8)
    assert hit is not None, "the non-menu line state gate was not solved + run-reproduced"
    # The guard-passing prefix is the earlier line that sets the mode; the payload follows on its
    # own line (the second fgets).
    assert hit["nav"] == b"admin\n", f"state-gate prefix was not the mode line: {hit['nav']!r}"
    assert hit["stdin"].startswith(b"admin\n"), f"solved stdin missing the mode line: {hit['stdin'][:8]!r}"
    assert spec["confirm"](hit["out"], hit["payload"], marker)
