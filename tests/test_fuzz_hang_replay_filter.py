"""Hang inputs must not poison the stages that replay recorded inputs.

concolic's `_gather_seeds` and mem_oracle's `_probe_inputs` replay every recorded input of a
target; an input recorded as a timeout/hang costs each of them a full timeout per replay (and a
memcheck run 10-30x that), and traces a path that never ends. Hangs are recorded three ways: a
dyn_result row with `timed_out`, libFuzzer's `timeout` artifact row (signal_name "timeout"), and
the input of a re-verified CWE-835 hang finding, which deliberately has NO dyn_result row."""
from lykos.analyze.dynamic import uninit_stage
from lykos.analyze.fuzz.stage import hang_input_shas, replayable_input_shas
from lykos.analyze.ingest import ingest
from lykos.analyze.symbolic import stage as sym
from lykos.db.dao import DynResultDAO, FindingDAO

OK1, OK2 = "a" * 64, "b" * 64
HUNG_ROW, LF_TIMEOUT, HUNG_FINDING = "c" * 64, "d" * 64, "e" * 64


def _seed(store, case, sample_elf):
    t = ingest(store, case.id, sample_elf)
    dd = DynResultDAO(store.conn)
    dd.insert(t.id, case.id, input_sha=OK1, input_mode="stdin", crashed=False)
    dd.insert(t.id, case.id, input_sha=HUNG_ROW, input_mode="stdin", crashed=False, timed_out=True)
    # a libFuzzer `timeout-` artifact recorded before timed_out was set on those rows
    dd.insert(t.id, case.id, input_sha=LF_TIMEOUT, input_mode="file", crashed=False,
              signal_name="timeout", isolation="libfuzzer")
    dd.insert(t.id, case.id, input_sha=HUNG_FINDING, input_mode="stdin", crashed=False)
    dd.insert(t.id, case.id, input_sha=OK2, input_mode="stdin", crashed=True, signal_name="SIGSEGV")
    FindingDAO(store.conn).upsert(t.id, case.id, {
        "cwe": "CWE-835", "title": "Input that does not terminate (denial of service)",
        "severity": "medium", "detector": "fuzz", "state": "corroborated", "confidence": 0.75,
        "dedup_key": "CWE-835:hang:stdin", "function_addr": None, "site_addr": None,
        "evidence": [{"channel": "dynamic", "detail": "hang", "input_sha": HUNG_FINDING}]})
    return t


def test_hang_inputs_are_identified_every_way_they_are_recorded(store, case, sample_elf):
    t = _seed(store, case, sample_elf)
    assert hang_input_shas(store.conn, t.id) == {HUNG_ROW, LF_TIMEOUT, HUNG_FINDING}


def test_replayable_inputs_skip_hangs_and_count_them(store, case, sample_elf):
    t = _seed(store, case, sample_elf)
    shas, skipped = replayable_input_shas(store.conn, t.id, 16)
    assert set(shas) == {OK1, OK2} and skipped == 3
    # the limit counts REPLAYABLE inputs, so hangs do not crowd the good ones out
    assert len(replayable_input_shas(store.conn, t.id, 2)[0]) == 2


class _Ctx:
    def __init__(self):
        self.events = []

    def emit(self, typ, payload=None, **_k):
        self.events.append((typ, payload))


def test_concolic_seeds_skip_hangs_visibly(store, case, sample_elf):
    t = _seed(store, case, sample_elf)
    ctx = _Ctx()
    seeds = sym._gather_seeds(store.conn, t.id, ctx=ctx)
    assert set(seeds) == {OK1, OK2}
    ev = [p for typ, p in ctx.events if typ == "concolic.seeds"]
    assert ev and ev[0]["skipped_hangs"] == 3


def test_mem_oracle_never_probes_a_hang_input(store, case, sample_elf):
    t = _seed(store, case, sample_elf)
    probes = uninit_stage._probe_inputs(store.conn, t)
    assert probes and not set(probes) & {HUNG_ROW, LF_TIMEOUT, HUNG_FINDING}


def test_hang_finding_carries_the_benign_control_input(store, case, sample_elf):
    """poc/dos.hang_poc re-verifies a hang against the SAME control the campaign used."""
    from lykos.analyze.dynamic.sandbox import RunResult
    from lykos.analyze.fuzz import stage as S
    t = ingest(store, case.id, sample_elf)

    class Ctx:
        run_id = None
        conn = store.conn

        def put_artifact(self, kind, data):
            return store.put_artifact(case.id, kind, data=data).sha256

        def emit(self, typ, payload=None):
            pass

    sha = S._file_hang(Ctx(), t, FindingDAO(store.conn), mode="stdin", data=b"\xff" * 8,
                       prefix=[], hang=RunResult(isolation="bwrap", timed_out=True,
                                                 duration_ms=4000),
                       control=RunResult(isolation="bwrap", duration_ms=2), exec_timeout=2.0,
                       detector="fuzz", event_prefix="fuzz", control_data=b"benign\n")
    ev = [f for f in FindingDAO(store.conn).list_by_target(t.id)
          if f.cwe == "CWE-835"][0].evidence[0]
    assert ev["input_sha"] == sha
    assert store.content.get_bytes(ev["control_sha"]) == b"benign\n"
    # and the hang input is then never replayed as a seed, the control is not a hang
    assert sha in hang_input_shas(store.conn, t.id)
    assert ev["control_sha"] not in hang_input_shas(store.conn, t.id)
