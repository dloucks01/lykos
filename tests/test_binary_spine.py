"""The binary-only spine: on a stripped/binary-only target, reachability must start where attacker
bytes enter PROGRAM code (main, input readers), an undecided verdict must never be filed as
off-surface, and stripped auto-named functions must resolve for the symbolic driver.

Regressions for the 2026-11-04 binary audit: before these fixes every binary-only finding came out
of grounding as undecided (reach seeded only from the read import, which has no callees), triage then
filed undecided as off-surface, and the UC stage resolved 0 functions on stripped code."""
from __future__ import annotations

import shutil
import subprocess

import pytest
from lykos.analyze import elf
from lykos.analyze import taint_reach as TR
from lykos.analyze.triage_stage import _stored_grounding
from lykos.db.dao import CallEdgeDAO, FunctionDAO, TargetDAO

_SRC = "int helper(int x){return x*3;}\nint main(int c,char**v){return helper(c);}\n"


def _nm_main(path) -> int:
    out = subprocess.run(["nm", str(path)], capture_output=True, text=True).stdout
    return int(next(ln for ln in out.splitlines() if ln.endswith(" main")).split()[0], 16)


@pytest.mark.parametrize("flags", [["-no-pie"], ["-pie", "-fPIE"], ["-static"]],
                         ids=["nopie", "pie", "static"])
def test_main_recovered_from_start_on_stripped_x86_64(flags, tmp_path, gcc):
    if not shutil.which("strip") or not shutil.which("nm"):
        pytest.skip("needs binutils")
    c = tmp_path / "m.c"; c.write_text(_SRC)
    exe = tmp_path / "m"
    if subprocess.run([gcc, "-O1", *flags, str(c), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build fixture")
    real = _nm_main(exe)
    subprocess.run(["strip", str(exe)], check=True)
    assert elf.main_from_start(exe.read_bytes()) == real


def test_binary_reach_seeds_from_main_and_input_readers(store, case):
    """A binary's call graph: main -> parse_file -> {read_hdr (calls fread) -> decode_chunk}, plus a
    reader island fcn.4000 -> fcn.4100 that main never calls but which itself reads input, and a
    dead helper. Everything main reaches, and everything an input reader hands its bytes to, is on
    the surface; the dead helper is not."""
    conn = store.conn
    t = TargetDAO(conn).upsert(case.id, "prog", "c" * 64, arch="x86-64", bits=64)
    FunctionDAO(conn).replace_for_target(t.id, [
        {"addr": "0x1000", "name": "main"}, {"addr": "0x1100", "name": "parse_file"},
        {"addr": "0x1200", "name": "read_hdr"}, {"addr": "0x1300", "name": "decode_chunk"},
        {"addr": "0x4000", "name": "fcn.00004000"}, {"addr": "0x4100", "name": "fcn.00004100"},
        {"addr": "0x9000", "name": "dead_helper"}])
    CallEdgeDAO(conn).replace_for_target(t.id, [
        {"src_addr": "0x1000", "dst_addr": "0x1100"},
        {"src_addr": "0x1100", "dst_addr": "0x1200"},
        {"src_addr": "0x1200", "dst_name": "sym.imp.fread", "external": 1},
        {"src_addr": "0x1200", "dst_addr": "0x1300"},
        {"src_addr": "0x4000", "dst_name": "recv", "external": 1},
        {"src_addr": "0x4000", "dst_addr": "0x4100"}])
    reach = TR.attacker_reachable_names(conn, case.id)
    assert {"main", "parse_file", "read_hdr", "decode_chunk"} <= reach
    assert {"fcn.00004000", "fcn.00004100"} <= reach        # an input reader + what it feeds
    assert "dead_helper" not in reach
    # the harness-only view keeps its old meaning (no program-entry seeding)
    assert "decode_chunk" not in TR.harness_reachable_names(conn, case.id)
    fd = {"function_addr": "0x1300", "target_id": t.id, "evidence": []}
    assert TR.ground_reach(fd, reach, conn=conn)["reachable"] is True


def test_undecided_reachability_is_not_filed_off_surface():
    import json

    def gm(reachable):
        return {"evidence": [{"channel": "grounding-map", "detail": json.dumps(
            {"grounded": True, "reachable": reachable, "verdict": "x"})}]}
    assert _stored_grounding(gm(True)) == (True, "exploitable-candidate")
    assert _stored_grounding(gm(False)) == (True, "off-surface-candidate")
    assert _stored_grounding(gm(None)) == (True, "undecided")


def test_angr_driver_resolves_stripped_autonames(tmp_path, gcc):
    """rizin names a stripped function `fcn.<linkaddr>`; on a PIE angr maps the image at 0x400000,
    so the driver must parse the auto-name AND rebase it onto angr's load."""
    angr = pytest.importorskip("angr")
    from lykos.analyze.symbolic import angr_driver
    c = tmp_path / "m.c"; c.write_text(_SRC)
    exe = tmp_path / "m"
    if subprocess.run([gcc, "-O1", "-pie", "-fPIE", str(c), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("cannot build fixture")
    link_main = _nm_main(exe)
    proj = angr.Project(str(exe), auto_load_libs=False)
    want = proj.loader.find_symbol("main").rebased_addr
    for name in (f"fcn.{link_main:08x}", f"FUN_{link_main:08x}", f"sub_{link_main:x}",
                 hex(link_main), "main"):
        assert angr_driver._fn_addr(proj, name) == want, name
    assert angr_driver._fn_addr(proj, "no_such_function") is None


def test_taint_fixpoint_honours_a_stop_request():
    """A cancelled detect stage kept its worker ~2 min (jhead-3.04). analyze_program polls the
    stage's cancel check and returns its partial result, marked cut short."""
    from lykos.analyze.detect import taint
    calls = []
    rk: dict = {}
    out = taint.analyze_program({0x1000: object()}, [], "x86-64", ranked_out=rk,
                                should_stop=lambda: calls.append(1) or True)
    assert out == set() and calls and rk.get("cut_short") is True
