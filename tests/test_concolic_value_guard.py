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
# scanf crashes on a symbolic stream position; the driver's PreciseScanf must solve the guard.
_FIXTURE_SCANF = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
int main(void){
    unsigned key; char buf[128];
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
    # format_parser), so a cmdi sink behind a scanf("%u") numeric guard is now REACHED and solved
    # symbolically -- angr finds input making the scanned key == 31337. (Run-reproducing the solved
    # input for a scanf target needs a consumed-length forking model; until then the inject_stage
    # concolic fallback's run-confirm gate rejects the imprecise solution -- no false PoC.)
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
