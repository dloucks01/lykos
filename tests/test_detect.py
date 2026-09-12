"""Phase 3 — CWE detection engine: finding lifecycle, detectors, reachability, stage."""
import pytest
from factories import make_target
from lykos.analyze import ingest, register  # noqa: F401
from lykos.analyze.detect.detectors import (
    DetectContext,
    correlate,
    dangerous_api,
    hardcoded_secrets,
)
from lykos.analyze.detect.stage import enqueue_detect
from lykos.db.dao import CallEdgeDAO, FindingDAO, FunctionDAO, StringDAO
from lykos.db.models import CallEdge, StringRef
from lykos.jobs import JobConfig, JobQueue, WorkerPool


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=8, poll_interval=0.02,
                             heartbeat_interval=2.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _edge(src, site, dst, name, ext):
    return CallEdge(id="x", target_id="t", created_at=0, src_addr=src, site_addr=site,
                    dst_addr=dst, dst_name=name, external=ext)


def test_finding_dao_upsert_merges_and_promotes(store, case):
    t = make_target(store, case.id)
    fd = FindingDAO(store.conn)
    base = dict(cwe="CWE-120", title="strcpy", severity="high", function_addr="0x2000",
                site_addr="0x2004", detector="dangerous_api", dedup_key="k1")
    fd.upsert(t.id, case.id, {**base, "state": "candidate", "confidence": 0.4,
                              "evidence": [{"channel": "pattern", "detail": "a"}]})
    fd.upsert(t.id, case.id, {**base, "state": "corroborated", "confidence": 0.65,
                              "evidence": [{"channel": "taint-reachability", "detail": "b"}]})
    fs = fd.list_by_target(t.id)
    assert len(fs) == 1                                  # merged, not duplicated
    f = fs[0]
    assert f.state == "corroborated" and f.confidence == 0.65
    assert len(f.evidence) == 2                          # evidence unioned


def test_dangerous_api_detector():
    ctx = DetectContext("t", "c", call_edges=[
        _edge("0x2000", "0x2004", "0x9100", "strcpy", True),
        _edge("0x2000", "0x2008", "0x9200", "__isoc99_scanf", True),
        _edge("0x2000", "0x200c", "0x3000", "my_helper", False),   # not dangerous
    ], strings=[])
    cands = dangerous_api(ctx)
    cwes = {c["cwe"] for c in cands}
    assert "CWE-120" in cwes                              # strcpy + scanf
    assert len(cands) == 2 and all(c["detector"] == "dangerous_api" for c in cands)


def test_hardcoded_secrets_detector():
    ctx = DetectContext("t", "c", call_edges=[], strings=[
        StringRef(id="1", target_id="t", addr="0x3000", created_at=0,
                  value="password=admin123", xrefs=["0x1200"]),
        StringRef(id="2", target_id="t", addr="0x3010", created_at=0,
                  value="just a normal string", xrefs=[]),
        StringRef(id="3", target_id="t", addr="0x3020", created_at=0,
                  value="-----BEGIN RSA PRIVATE KEY-----", xrefs=[]),
    ])
    cands = hardcoded_secrets(ctx)
    cwes = {c["cwe"] for c in cands}
    assert "CWE-798" in cwes and "CWE-321" in cwes
    assert len(cands) == 2                                # the benign string is ignored


def test_correlate_promotes_reachable_sink():
    # main(0x1000) reads input (recv) and calls parse(0x2000); parse calls strcpy (sink)
    edges = [
        _edge("0x1000", "0x1004", "0x9000", "recv", True),      # source in main
        _edge("0x1000", "0x1008", "0x2000", "parse", False),    # main -> parse
        _edge("0x2000", "0x2004", "0x9100", "strcpy", True),    # sink in parse
    ]
    ctx = DetectContext("t", "c", call_edges=edges, strings=[])
    cands = correlate(dangerous_api(ctx), ctx)
    sink = next(c for c in cands if c["function_addr"] == "0x2000")
    assert sink["state"] == "corroborated"               # reachable from recv via main->parse
    assert any(e["channel"] == "taint-reachability" for e in sink["evidence"])


def test_detect_stage_end_to_end(store, case, pool):
    t = make_target(store, case.id)
    FunctionDAO(store.conn).replace_for_target(t.id, [
        {"addr": "0x1000", "name": "main"}, {"addr": "0x2000", "name": "parse"}])
    CallEdgeDAO(store.conn).replace_for_target(t.id, [
        {"src_addr": "0x1000", "site_addr": "0x1004", "dst_addr": "0x9000",
         "dst_name": "recv", "external": True},
        {"src_addr": "0x1000", "site_addr": "0x1008", "dst_addr": "0x2000",
         "dst_name": "parse", "external": False},
        {"src_addr": "0x2000", "site_addr": "0x2004", "dst_addr": "0x9100",
         "dst_name": "strcpy", "external": True},
    ])
    StringDAO(store.conn).replace_for_target(t.id, [
        {"addr": "0x3000", "value": "api_key=deadbeefcafebabe", "xrefs": ["0x1200"]}])

    q = JobQueue(store.conn)
    run = enqueue_detect(q, t)
    assert pool.wait_idle(10)
    assert q.runs.get(run.id).status == "done"

    fd = FindingDAO(store.conn)
    findings = fd.list_by_target(t.id)
    cwes = {f.cwe for f in findings}
    assert "CWE-120" in cwes and "CWE-798" in cwes
    strcpy = next(f for f in findings if f.cwe == "CWE-120")
    assert strcpy.state == "corroborated"                # reachability promoted it

    # re-run is idempotent (dedup/merge, not duplicate)
    before = fd.count_by_target(t.id)
    run2 = enqueue_detect(q, t)
    assert pool.wait_idle(10) and q.runs.get(run2.id).status == "done"
    assert fd.count_by_target(t.id) == before


def test_weak_crypto_detector():
    from lykos.analyze.detect.detectors import weak_crypto
    ctx = DetectContext("t", "c", call_edges=[
        _edge("0x1", "0x1", "0x9", "MD5_Init", True),
        _edge("0x1", "0x2", "0x9", "DES_set_key", True),
        _edge("0x1", "0x3", "0x9", "destroy_object", False),   # must NOT match 'des'
        _edge("0x1", "0x4", "0x9", "arc4random", True),        # must NOT match 'rc4'
    ], strings=[])
    cands = weak_crypto(ctx)
    assert {c["cwe"] for c in cands} == {"CWE-328", "CWE-327"}   # MD5 + DES only
    assert len(cands) == 2


def test_weak_random_detector():
    from lykos.analyze.detect.detectors import weak_random
    ctx = DetectContext("t", "c", strings=[], call_edges=[
        _edge("0x1", "0x1", "0x9", "rand", True),
        _edge("0x1", "0x2", "0x9", "arc4random", True)])       # not in the weak set
    cands = weak_random(ctx)
    assert len(cands) == 1 and cands[0]["cwe"] == "CWE-330"


def test_insecure_tmp_detector():
    from lykos.analyze.detect.detectors import insecure_tmp
    ctx = DetectContext("t", "c", strings=[], call_edges=[
        _edge("0x1", "0x1", "0x9", "mktemp", True),
        _edge("0x1", "0x2", "0x9", "mkstemp", True)])          # mkstemp is safe
    cands = insecure_tmp(ctx)
    assert len(cands) == 1 and cands[0]["cwe"] == "CWE-377"


def test_hardening_detector():
    from lykos.analyze.detect.detectors import hardening
    ctx = DetectContext("t", "c", call_edges=[], strings=[],
                        mitigations={"nx": "off", "canary": "off", "pie": "on",
                                     "relro": "partial"})
    cands = hardening(ctx)
    assert {c["cwe"] for c in cands} == {"CWE-693"}
    assert len(cands) == 3           # nx off + canary off + relro partial (pie on -> none)
    assert cands[0]["detector"] == "hardening"


def test_stack_buffer_overflow_detector_uses_recovered_frame():
    """A function that owns a fixed stack buffer AND calls an unbounded copy is flagged
    CWE-121, citing the recovered buffer size and offset-to-return."""
    from lykos.analyze.detect.detectors import stack_buffer_overflow
    ctx = DetectContext(
        target_id="t", case_id="c",
        call_edges=[_edge("0x1000", "0x1010", None, "strcpy", 1)],
        strings=[],
        frames={"0x1000": {"frame_size": 88, "vars": [
            {"name": "msg", "offset": -72, "size": 64, "type": "char[64]", "is_buffer": True},
            {"name": "i", "offset": -8, "size": 4, "type": "int", "is_buffer": False}]}})
    out = stack_buffer_overflow(ctx)
    assert len(out) == 1
    f = out[0]
    assert f["cwe"] == "CWE-121" and f["function_addr"] == "0x1000"
    # The recovered size and the offset-to-return describe THIS occurrence, so they belong to
    # the site. The title names the defect, which is what the dedup key groups on.
    assert "64-byte" not in f["title"], "the title is the defect, not one buffer"
    assert "64 B" in f["site_detail"] and "return address" in f["site_detail"]
    # a function with the sink but NO stack buffer is not flagged
    novar = {"name": "x", "offset": -8, "size": 4, "type": "int", "is_buffer": False}
    ctx2 = DetectContext(target_id="t", case_id="c",
                         call_edges=[_edge("0x2000", "0x2010", None, "strcpy", 1)],
                         strings=[], frames={"0x2000": {"vars": [novar]}})
    assert stack_buffer_overflow(ctx2) == []


def test_stack_buffer_overflow_reports_at_defect_grain():
    """Keying on the FUNCTION made every call site its own high-severity finding: seven
    near-identical rows on jhead, most of its HIGH count, reading as seven separate bugs.
    Every other sink detector groups by defect and records each place as a site."""
    from lykos.analyze.detect.detectors import stack_buffer_overflow
    buf = {"name": "msg", "offset": -72, "size": 64, "type": "char[64]", "is_buffer": True}
    ctx = DetectContext(
        target_id="t", case_id="c", strings=[],
        call_edges=[_edge("0x1000", "0x1010", None, "strcpy", 1),
                    _edge("0x2000", "0x2010", None, "strcpy", 1),
                    _edge("0x3000", "0x3010", None, "sprintf", 1)],
        frames={a: {"frame_size": 88, "vars": [buf]} for a in ("0x1000", "0x2000", "0x3000")})
    out = stack_buffer_overflow(ctx)
    assert len(out) == 3, "one candidate per occurrence"
    keys = {c["dedup_key"] for c in out}
    assert len(keys) == 2, "strcpy and sprintf are two defects, not three findings"
    assert all("0x1000" not in k and "0x2000" not in k for k in keys), \
        "the key must not carry the function address"
    assert len({c["site_addr"] for c in out}) == 3


def test_function_dao_roundtrips_signature_and_frame(store, case):
    t = make_target(store, case.id)
    fd = FunctionDAO(store.conn)
    fd.replace_for_target(t.id, [{
        "addr": "0x1000", "name": "greet", "size": 40, "blocks": 3, "edges": 2,
        "signature": "void greet(char * who)",
        "params": [{"name": "who", "type": "char *", "size": 8}],
        "calling_convention": "__stdcall", "thunk": False, "varargs": False,
        "frame": {"frame_size": 88, "ret_offset": 8, "vars": [
            {"name": "msg", "offset": -72, "size": 64, "type": "char[64]", "is_buffer": True}]},
        "cfg": {"blocks": []}}])
    light = fd.list_by_target(t.id)[0]
    assert light.signature == "void greet(char * who)"   # signature is in the light list view
    full = fd.get(light.id)
    assert full.frame["vars"][0]["is_buffer"] is True and full.frame["vars"][0]["size"] == 64
    assert full.frame["params"][0]["name"] == "who"
    assert full.frame["calling_convention"] == "__stdcall"


def test_normalize_strips_powerpc_and_plt_decorations():
    """Callee-name decorations that silently cost whole architectures.

    A LEADING DOT is the PowerPC local-entry convention: under ELFv2 (every little-endian
    ppc64 system) a function has a global entry that sets up the TOC and a local entry 8 bytes
    later holding the body, which Ghidra names `.main`. On a real ppc64le binary 845/1829
    functions and 3659/4828 call targets carry it, so leaving it on meant `.strcpy` matched no
    sink and `.main` matched no entry point: the architecture produced ZERO data-flow findings
    while big-endian ppc64 produced 139 from identical source.

    Ghidra's PLT thunks (`00000397.plt_call.strcat`) matched nothing either, costing sinks
    even on architectures that looked healthy.
    """
    from lykos.analyze.detect.catalog import DANGEROUS, SOURCES, normalize
    assert normalize(".main") == "main"                       # ppc64le ELFv2 local entry
    assert normalize(".strcpy") in DANGEROUS
    assert normalize("00000397.plt_call.strcat") in DANGEROUS  # Ghidra PLT thunk
    assert normalize("._IO_fgets") in SOURCES                  # dot + glibc stdio alias
    assert normalize("_IO_fgets") in SOURCES
    # existing behaviour must be untouched
    assert normalize("strcpy@plt") in DANGEROUS
    assert normalize("__isoc99_scanf") in DANGEROUS
    assert normalize("main") == "main"
    assert normalize("") == "" and normalize(None) == ""


def test_entry_seeding_finds_the_powerpc_local_entry():
    """`.main` must be recognised as an entry point, or argv is seeded onto the 8-byte
    global-entry TOC stub (which uses no parameters) and reaches nothing."""
    from types import SimpleNamespace

    from lykos.analyze.detect.catalog import entry_seed_params
    fns = [SimpleNamespace(name=".main", addr="0x10000b68",
                           signature="undefined8 main(int param_1, long param_2)")]
    assert entry_seed_params(fns) == {"0x10000b68": {1}}


def test_reachability_uses_shortest_distance_not_first_path_found():
    """`reaches_within` answers "is a source within N call levels", which must mean the
    SHORTEST distance.

    The previous implementation was a depth-limited DFS sharing one `seen` set across the
    whole search: a node first reached with the budget nearly spent was marked visited and
    never re-explored along a shorter path that still had budget. Whether that lost a real
    source depended on the order a Python set happened to iterate, so it never reproduced
    reliably -- and a missed source is invisible, it just looks like a finding that stayed
    `candidate`. These assertions hold for every exploration order.
    """
    from lykos.analyze.detect.detectors import reaches_within

    # sink <- A <- {B, X}; B <- X; X <- src.  src sits at distance 3 by the short route
    # (sink->A->X->src) and 4 by the long one (sink->A->B->X->src).
    callers = {"sink": {"A"}, "A": {"B", "X"}, "B": {"X"}, "X": {"src"}}
    assert reaches_within("sink", {"src"}, callers, depth=3) is True
    assert reaches_within("sink", {"src"}, callers, depth=2) is False   # genuinely too far

    # a long dead-end branch must never mask a short live one
    callers2 = {"sink": {"L1", "S1"}, "L1": {"L2"}, "L2": {"L3"}, "L3": {"L4"},
                "S1": {"src"}}
    assert reaches_within("sink", {"src"}, callers2, depth=2) is True

    # boundary + degenerate cases
    assert reaches_within("src", {"src"}, {}, depth=0) is True          # start IS a source
    assert reaches_within("sink", {"src"}, {}, depth=4) is False        # no edges at all
    assert reaches_within("a", {"src"}, {"a": {"b"}, "b": {"a"}}, depth=9) is False  # cycle


def test_a_finding_is_a_defect_and_call_sites_are_its_evidence(store, case):
    """One dangerous call site used to be one finding, so the finding COUNT tracked compiler
    inlining rather than risk: jhead 3.06 built with distro flags produced 27 findings and the
    same program at -O0 produced 230, because -O0 does not inline memcpy. The findings board
    showed 12 identical `strncpy` rows with no location, while the workbench showed one row
    saying "x12 sites" -- two views of one API disagreeing about what a finding is.
    """
    from lykos.analyze.detect.detectors import DetectContext, dangerous_api
    from lykos.db.dao import FindingDAO
    from lykos.db.models import CallEdge

    t = make_target(store, case.id, content=b"\x7fELFgrain1")
    edges = [CallEdge(id=f"e{i}", target_id=t.id, src_addr=f"0x1{i:03x}",
                      site_addr=f"0x2{i:03x}", dst_addr=None, dst_name="strcpy",
                      external=True, created_at=0) for i in range(7)]
    ctx = DetectContext(target_id=t.id, case_id=case.id, call_edges=edges, strings=[])
    fd = FindingDAO(store.conn)
    for c in dangerous_api(ctx):
        fd.upsert(t.id, case.id, c)

    fs = fd.list_by_target(t.id)
    assert len(fs) == 1, f"7 call sites of one sink must be ONE defect, got {len(fs)}"
    sites = fd.sites(fs[0].id)
    assert len(sites) == 7, "every call site is kept as evidence"
    assert fd.site_counts(t.id)[fs[0].id] == 7
    # the finding still carries a representative location for existing consumers
    assert fs[0].function_addr and fs[0].site_addr
    # and each site is individually addressable, which the board needs for its Where column
    assert {s["site_addr"] for s in sites} == {f"0x2{i:03x}" for i in range(7)}


def test_distinct_sinks_stay_distinct_findings(store, case):
    """Grouping must not over-merge: strcpy and system are different defects."""
    from lykos.analyze.detect.detectors import DetectContext, dangerous_api
    from lykos.db.dao import FindingDAO
    from lykos.db.models import CallEdge

    t = make_target(store, case.id, content=b"\x7fELFgrain2")
    edges = [CallEdge(id="a", target_id=t.id, src_addr="0x100", site_addr="0x200",
                      dst_addr=None, dst_name="strcpy", external=True, created_at=0),
             CallEdge(id="b", target_id=t.id, src_addr="0x100", site_addr="0x204",
                      dst_addr=None, dst_name="system", external=True, created_at=0)]
    ctx = DetectContext(target_id=t.id, case_id=case.id, call_edges=edges, strings=[])
    fd = FindingDAO(store.conn)
    for c in dangerous_api(ctx):
        fd.upsert(t.id, case.id, c)
    fs = fd.list_by_target(t.id)
    assert len(fs) == 2, "different sinks are different defects"
    assert {f.cwe for f in fs} == {"CWE-120", "CWE-78"}


def test_a_message_about_a_password_is_not_a_hard_coded_password():
    """Matching the keyword alone flagged ten strings in unzip -- "Enter password: ",
    "incorrect password", "-P p Use password p to decrypt files" -- every one of them a message
    ABOUT passwords and none of them a secret. That was two thirds of every finding reported
    for that binary, which is how a real report becomes unreadable."""
    from lykos.analyze.detect.detectors import _secret
    for prose in ("error:  must give decryption password with -P option",
                  "  -P p Use password p to decrypt files.  THIS IS INSECURE!  ",
                  "  funzip [-password] [input[.zip|.gz]]",
                  "%lu file%s skipped because of incorrect password.",
                  "   skipping: %-22s  incorrect password",
                  "password incorrect--reenter: ",
                  "Enter password: ",
                  "[%s] %s password: "):
        assert _secret(prose) is None, f"still fires on {prose!r}"


def test_a_credential_bound_to_a_value_is_still_found():
    """The point is precision, not silence: a keyword bound to a secret-shaped value is the
    thing worth reporting."""
    from lykos.analyze.detect.detectors import _secret
    for real in ("db_password=S3cr3t!", "api_key: AKIAIOSFODNN7EXAMPLE",
                 '"password": "hunter2A"', "SECRET_TOKEN=abc123XYZ", "ftp_pass=Tr0ub4dor",
                 # a hex or base64 token has no mixed case and no punctuation: it is still
                 # the commonest credential shape there is
                 "api_key=deadbeefcafebabe", "token=aGVsbG93b3JsZGhlbGxv"):
        hit = _secret(real)
        assert hit and hit[0] == "CWE-798", f"missed {real!r}"
    assert _secret("AKIAIOSFODNN7EXAMPLE")[0] == "CWE-798"
    assert _secret("-----BEGIN RSA PRIVATE KEY-----")[0] == "CWE-321"


def test_a_placeholder_is_not_a_credential():
    """`password=password` in a sample config is documentation, not a leak."""
    from lykos.analyze.detect.detectors import _secret
    assert _secret("password=password") is None
    assert _secret("secret = changeme") is None
    assert _secret("api_key=-v") is None, "a command-line option is not a value"
