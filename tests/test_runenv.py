"""Per-run target libraries / deep-seed: never shared between two cases' runs.

They were written into os.environ for an autopilot run, and the server runs every case's stages
in one process: two cases running at once got the last writer's QEMU_LD_PREFIX."""
import threading

from lykos.jobs import runenv


def test_two_cases_bound_in_two_workers_never_see_each_other(monkeypatch):
    monkeypatch.delenv(runenv.SYSROOT, raising=False)
    runenv.set_case("A", {runenv.SYSROOT: "/a"})
    runenv.set_case("B", {runenv.SYSROOT: "/b"})
    seen = {}

    def job(cid):
        tok = runenv.bind(runenv.for_case(cid))
        try:
            seen[cid] = runenv.get(runenv.SYSROOT)
        finally:
            runenv.unbind(tok)

    ts = [threading.Thread(target=job, args=(c,)) for c in ("A", "B")]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert seen == {"A": "/a", "B": "/b"}
    # an unbound thread with two cases registered cannot tell them apart: no guess
    assert runenv.get(runenv.SYSROOT) is None
    runenv.clear_case("A")
    runenv.clear_case("B")


def test_fallbacks(monkeypatch):
    monkeypatch.setenv(runenv.SYSROOT, "/operator")
    assert runenv.get(runenv.SYSROOT) == "/operator"            # nothing registered: the env
    runenv.set_case("C", {runenv.SYSROOT: "/c"})
    try:
        assert runenv.get(runenv.SYSROOT) == "/c"               # one case: a spawned thread too
        tok = runenv.bind({runenv.BUFFER_SEED: "1"})
        assert runenv.get(runenv.SYSROOT) == "/operator"        # bound, but not for this key
        assert runenv.get(runenv.BUFFER_SEED) == "1"
        runenv.unbind(tok)
    finally:
        runenv.clear_case("C")


def test_the_autopilot_registers_per_case_and_never_touches_os_environ():
    import inspect

    from lykos.analyze import orchestrate
    src = inspect.getsource(orchestrate.run_case_autopilot)
    assert "_runenv.set_case(case_id, _renv)" in src and "_runenv.clear_case(case_id)" in src
    assert 'os.environ["LYKOS_QEMU_SYSROOT"]' not in src and "_env_set(" not in src
