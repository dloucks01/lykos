"""Routes the GUI reads that had no test: strings (paged), functions, callgraph,
dynresults, pocs, and run cancellation.

These are the endpoints the operator's screens are built on, and an endpoint that answers
wrongly is indistinguishable in the UI from a stage that found nothing -- which is the
failure mode this codebase keeps rediscovering. Driven over the real unix socket, like the UI.
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import time

import pytest
from lykos.api.server import serve, shutdown


@pytest.fixture
def api(tmp_path):
    sock = str(tmp_path / "s.sock")
    servers, pool = serve(tmp_path / "cs", sock, workers=2, block=False)
    for _ in range(200):
        if os.path.exists(sock):
            break
        time.sleep(0.02)
    try:
        yield sock
    finally:
        shutdown(servers, pool)


class _UDS(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost")
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._path)


def _req(sock_path, method, url, body=None, headers=None):
    c = _UDS(sock_path)
    try:
        c.request(method, url, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def _json(sock_path, method, url, obj=None):
    body = json.dumps(obj).encode() if obj is not None else None
    st, data = _req(sock_path, method, url, body,
                    {"Content-Type": "application/json"} if obj is not None else {})
    return st, (json.loads(data) if data else None)


def _upload(sock_path, cid, filename, filedata):
    boundary = "----lykostest"
    pre = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
           f"filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
    body = pre + filedata + f"\r\n--{boundary}--\r\n".encode()
    st, data = _req(sock_path, "POST", f"/cases/{cid}/targets", body,
                    {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    return st, json.loads(data)


def _wait_run(sock_path, run_id, timeout=30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st, run = _json(sock_path, "GET", f"/runs/{run_id}")
        if st == 200 and run["status"] in ("done", "error", "cancelled"):
            return run
        time.sleep(0.05)
    raise TimeoutError("run did not finish")


@pytest.fixture
def triaged(api, sample_elf, tmp_path):
    """A case with one real, triaged ELF, and a known string table.

    The strings come from the DISASSEMBLE stage, which needs Ghidra -- so a triage-only
    target has none, and every paging assertion below would skip on a host without it. The
    endpoint's paging is what is under test here, not string extraction, so the rows are
    seeded directly and the test says what it means on any host.
    """
    from lykos.casestore import CaseStore
    from lykos.db.dao import StringDAO
    _st, case = _json(api, "POST", "/cases", {"name": "routes"})
    cid = case["id"]
    _st, tgt = _upload(api, cid, "sample", sample_elf.read_bytes())
    tid = tgt["target"]["id"] if "target" in tgt else tgt["id"]
    if tgt.get("run_id"):
        _wait_run(api, tgt["run_id"])
    st = CaseStore.open(tmp_path / "cs")
    try:
        StringDAO(st.conn).replace_for_target(
            tid, [{"addr": f"0x{0x400000 + i * 16:x}", "value": f"string-{i:03d}"}
                  for i in range(SEEDED_STRINGS)])
    finally:
        st.close()
    return api, cid, tid


SEEDED_STRINGS = 25


# ---- strings, which is the one with real logic in it -------------------------------------

def test_strings_are_paged_and_say_how_many_there_are(triaged):
    sock, _cid, tid = triaged
    st, body = _json(sock, "GET", f"/targets/{tid}/strings")
    assert st == 200
    assert {"total", "offset", "limit", "truncated", "items"} <= set(body)
    assert isinstance(body["items"], list)
    assert body["total"] >= len(body["items"])
    assert body["offset"] == 0


def test_a_limit_is_honoured_and_truncation_is_declared(triaged):
    """The regression: the response stopped at the cap with nothing saying so, and was
    indistinguishable from "that is all of them"."""
    sock, _cid, tid = triaged
    st, body = _json(sock, "GET", f"/targets/{tid}/strings?limit=1")
    assert st == 200
    assert len(body["items"]) == 1
    assert body["limit"] == 1
    assert body["total"] == SEEDED_STRINGS
    assert body["truncated"] is True
    # and asking for all of them says it is NOT truncated -- the two have to differ, or the
    # flag carries no information
    _st, whole = _json(sock, "GET", f"/targets/{tid}/strings?limit=5000")
    assert len(whole["items"]) == SEEDED_STRINGS
    assert whole["truncated"] is False


def test_an_offset_walks_the_list_without_repeating(triaged):
    sock, _cid, tid = triaged
    seen, offset = [], 0
    while True:
        _st, page = _json(sock, "GET", f"/targets/{tid}/strings?limit=7&offset={offset}")
        if not page["items"]:
            break
        seen += [x["value"] for x in page["items"]]
        offset += 7
    # every string exactly once: a paged reader that repeats or drops rows is worse than one
    # that truncates, because nothing in the response says it happened
    assert len(seen) == SEEDED_STRINGS
    assert len(set(seen)) == SEEDED_STRINGS


def test_a_nonsense_limit_is_clamped_rather_than_crashing(triaged):
    sock, _cid, tid = triaged
    for q in ("limit=0", "limit=999999", "offset=-5", "limit=abc"):
        st, body = _json(sock, "GET", f"/targets/{tid}/strings?{q}")
        # "abc" is not a number: the endpoint may reject it, but it must not 500
        assert st in (200, 400), f"{q} -> {st}"
        if st == 200:
            assert body["limit"] >= 1 and body["offset"] >= 0


def test_an_offset_past_the_end_is_an_empty_page_not_an_error(triaged):
    sock, _cid, tid = triaged
    st, body = _json(sock, "GET", f"/targets/{tid}/strings?offset=100000")
    assert st == 200
    assert body["items"] == [] and body["truncated"] is False


# ---- the plain readers -------------------------------------------------------------------

@pytest.mark.parametrize("route", ["functions", "callgraph", "dynresults", "pocs",
                                   "findings", "strings"])
def test_every_target_reader_answers_for_a_real_target(triaged, route):
    sock, _cid, tid = triaged
    st, body = _json(sock, "GET", f"/targets/{tid}/{route}")
    assert st == 200, f"{route} -> {st}"
    assert isinstance(body, (list, dict))


@pytest.mark.parametrize("route", ["functions", "callgraph", "dynresults", "pocs",
                                   "findings", "strings", "advice", "capabilities", "source",
                                   "invocation"])
def test_every_target_reader_survives_an_unknown_target(api, route):
    """The UI builds these URLs from whatever is selected; a stale id must not 500."""
    st, _body = _json(api, "GET", f"/targets/deadbeef-not-a-target/{route}")
    assert st in (200, 404), f"{route} -> {st}"


def test_a_function_that_does_not_exist_is_a_404(api):
    st, body = _json(api, "GET", "/functions/nope")
    assert st == 404
    assert body.get("error")


def test_a_finding_that_does_not_exist_is_a_404(api):
    st, body = _json(api, "GET", "/findings/nope")
    assert st == 404
    assert body.get("error")


def test_background_autopilot_status_is_none_before_any_run(triaged):
    """The server-side background Autopilot: status for a case with no run reads 'none', and
    cancelling a non-existent run is a 404 -- neither is a 500."""
    sock, cid, _tid = triaged
    st, body = _json(sock, "GET", f"/cases/{cid}/autopilot")
    assert st == 200 and body.get("state") == "none"
    st, _b = _req(sock, "POST", f"/cases/{cid}/autopilot/cancel")
    assert st == 404


def test_background_autopilot_needs_targets(api):
    """Starting on a case with no targets is a clean 400, not a spawned thread doing nothing."""
    st, c = _json(api, "POST", "/cases", {"name": "empty"})
    st, body = _json(api, "POST", f"/cases/{c['id']}/autopilot", {})
    assert st == 400 and body.get("error")


def test_source_endpoint_reports_no_source_for_a_binary_target(triaged):
    """A plain binary target has no source; the endpoint answers {source: null}, not an error."""
    sock, _cid, tid = triaged
    st, body = _json(sock, "GET", f"/targets/{tid}/source")
    assert st == 200
    assert body.get("source") is None


def test_replay_requires_an_input_and_survives_a_bogus_one(triaged):
    """The false-positive review replays a crashing input; a missing input is a 400, an unknown
    input a 404, and neither is a 500."""
    sock, _cid, tid = triaged
    st, _b = _json(sock, "POST", f"/targets/{tid}/replay", {})
    assert st == 400
    st, _b = _json(sock, "POST", f"/targets/{tid}/replay", {"input_sha": "deadbeef", "times": 2})
    assert st == 404


def test_verifications_endpoint_shape_and_unknown_case(triaged):
    """A reopened case restores its VerifyBadges from GET /cases/{cid}/verifications. With no
    review run yet it is an empty object (never an error), and an unknown case is a 404 -- so the
    reopen fetch degrades cleanly instead of blanking the results."""
    sock, cid, _tid = triaged
    st, body = _json(sock, "GET", f"/cases/{cid}/verifications")
    assert st == 200 and isinstance(body, dict) and body == {}
    st, _b = _json(sock, "GET", "/cases/not-a-case/verifications")
    assert st == 404


# ---- cancellation ------------------------------------------------------------------------

def test_cancelling_an_unknown_run_is_a_404_not_a_500(api):
    st, _body = _req(api, "POST", "/runs/not-a-run/cancel")
    assert st in (404, 400)


def test_a_finished_run_cannot_be_cancelled_into_a_lie(triaged):
    """Cancelling a run that already finished must not rewrite it as cancelled -- the run
    list is evidence about what actually happened."""
    sock, cid, _tid = triaged
    _st, runs = _json(sock, "GET", f"/cases/{cid}/runs")
    done = [r for r in runs if r["status"] == "done"]
    if not done:
        pytest.skip("no finished run to try this on")
    rid = done[0]["id"]
    _st, _b = _req(sock, "POST", f"/runs/{rid}/cancel")
    _st, run = _json(sock, "GET", f"/runs/{rid}")
    assert run["status"] == "done", "a finished run was relabelled by a cancel"


def test_run_output_returns_the_stage_result(triaged):
    """The workbench log shows WHAT each stage found, read from GET /runs/<id>/output. The
    triage run always produces an output artifact, so its output is a dict here."""
    sock, cid, _tid = triaged
    _st, runs = _json(sock, "GET", f"/cases/{cid}/runs")
    done = [r for r in runs if r["status"] == "done"]
    if not done:
        pytest.skip("no finished run")
    rid = done[0]["id"]
    st, body = _json(sock, "GET", f"/runs/{rid}/output")
    assert st == 200
    assert body["run_id"] == rid and body["stage"] == done[0]["stage"]
    assert "output" in body  # present (dict for triage/disassemble; may be None for row-only stages)


def test_run_output_for_an_unknown_run_is_a_404(api):
    st, body = _json(api, "GET", "/runs/not-a-run/output")
    assert st == 404 and body.get("error")


def test_a_malformed_query_parameter_is_never_a_server_fault(triaged):
    """`?limit=abc` reached int() inside the handler and came back 500. The UI builds these
    from its own controls, but the URL gets typed by hand too, and a 500 in the network tab
    reads as "the server is broken" rather than "that is not a number"."""
    sock, cid, tid = triaged
    for url in (f"/targets/{tid}/strings?limit=abc",
                f"/targets/{tid}/strings?offset=abc",
                f"/targets/{tid}/strings?limit=&offset=",
                f"/cases/{cid}/events?after=abc"):
        st, _body = _json(sock, "GET", url)
        assert st != 500, f"{url} -> 500"


def test_orchestrate_prove_stages_receive_params():
    """Regression: the background (server-side) Autopilot listed root_cause/build_poc/
    poc_primitive as no-param stages, so _run_target_stage dropped the crashing input the prove
    loop threads in -- every one then failed with 'requires params.input_sha'. Those stages must
    NOT be in _NO_PARAMS; only the genuinely param-less recover stages are."""
    from lykos.analyze import orchestrate
    for stage in ("root_cause", "build_poc", "poc_primitive"):
        assert stage not in orchestrate._NO_PARAMS, \
            f"{stage} needs params.input_sha but is marked no-param"
    assert orchestrate._NO_PARAMS == {"disassemble", "detect_cwe", "heap_trace", "oob_index",
                                      "chain_primitive", "synthesize_poc", "firmware_carve",
                                      "source_cve_scan", "embedded_audit",
                                      "int_overflow_scan", "net_fuzz", "cve_corroborate"}
