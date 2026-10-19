"""Phase 5 — black-box fuzzing: mutator + a campaign that finds a crash and confirms it."""
import random
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.fuzz.mutator import Mutator
from lykos.analyze.fuzz.stage import enqueue_fuzz
from lykos.analyze.ingest import ingest
from lykos.db.dao import DynResultDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# crashes if any 'A' appears in the input -> a seed of "AAAA" hits almost immediately
_CRASH_ON_A = ("#include <unistd.h>\nint main(){char b[64];int n=read(0,b,63);"
               "for(int i=0;i<n;i++) if(b[i]=='A'){volatile int*p=0;*p=1;}return 0;}\n")
_OK = "#include <unistd.h>\nint main(){char b[64];read(0,b,63);return 0;}\n"


@pytest.fixture(scope="module")
def bins(gcc, tmp_path_factory):
    d = tmp_path_factory.mktemp("fuzzbins")
    out = {}
    for name, src in (("crash", _CRASH_ON_A), ("ok", _OK)):
        c = d / (name + ".c"); c.write_text(src)
        b = d / name
        if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True).returncode == 0:
            out[name] = b
    return out


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=60, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_mutator_deterministic_and_bounded():
    m1 = Mutator(random.Random(42), [b"admin", b"%n"])
    m2 = Mutator(random.Random(42), [b"admin", b"%n"])
    corpus = [b"seed", b"AAAA"]
    outs1 = [m1.mutate(b"AAAA", corpus) for _ in range(50)]
    outs2 = [m2.mutate(b"AAAA", corpus) for _ in range(50)]
    assert outs1 == outs2                       # same seed -> same sequence
    assert all(isinstance(o, bytes) and len(o) <= 8192 for o in outs1)


def test_fuzz_finds_crash_and_confirms(store, case, pool, bins):
    if "crash" not in bins:
        pytest.skip("build failed")
    import base64
    target = ingest(store, case.id, bins["crash"])
    q = JobQueue(store.conn)
    run = enqueue_fuzz(q, target, params={
        "input_mode": "stdin", "max_execs": 400, "max_seconds": 20, "exec_timeout": 1,
        "seeds": [base64.b64encode(b"AAAA").decode()]})
    assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"

    crashes = [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed]
    assert crashes and crashes[0].signal_name == "SIGSEGV"
    # at least one crash was minimized to a tiny reproducer (the one that became a finding)
    inputs = [store.content.get_bytes(d.input_sha) for d in crashes]
    assert any(b"A" in ci and len(ci) <= 4 for ci in inputs)
    assert any(d.note and "minimized" in d.note for d in crashes)

    confirmed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
                 if f.state == "confirmed"]
    assert confirmed and confirmed[0].detector == "fuzz"


def test_fuzz_clean_binary_no_crash(store, case, pool, bins):
    if "ok" not in bins:
        pytest.skip("build failed")
    target = ingest(store, case.id, bins["ok"])
    q = JobQueue(store.conn)
    run = enqueue_fuzz(q, target, params={
        "input_mode": "stdin", "max_execs": 150, "max_seconds": 15, "exec_timeout": 1})
    assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"
    assert not [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed]
    assert not [f for f in FindingDAO(store.conn).list_by_target(target.id)
                if f.state == "confirmed"]


# ---------------------------------------------------- structure-aware (format) mutation
def test_struct_mutator_roundtrip_and_coordinates_length_with_blob():
    import struct as _s

    from lykos.analyze.fuzz import structure
    spec = [{"type": "magic", "value": "IMG\x00"},
            {"type": "u32", "endian": "little", "name": "len", "length_of": "data"},
            {"type": "blob", "name": "data"}]
    model = structure.FormatModel(spec)
    seed = b"IMG\x00" + _s.pack("<I", 8) + b"A" * 8
    assert model.serialize(model.parse(seed)) == seed        # parse/serialize roundtrip
    mut = structure.StructMutator(random.Random(1337), model)
    kept, overflow_shaped = 0, 0
    for _ in range(300):
        out = mut.mutate(seed)
        if out[:4] == b"IMG\x00":
            kept += 1
        if len(out) >= 8:
            length = _s.unpack("<I", out[4:8])[0]
            if length > 64 and len(out) - 8 >= 65:            # length AND data both large
                overflow_shaped += 1
    assert kept > 250            # magic preserved (format gate passes) most of the time
    assert overflow_shaped > 20  # coordinates length>buf with matching data -> the overflow


_FILE_PARSER = (
    "#include <stdio.h>\n#include <string.h>\n"
    "int main(int c,char**v){ if(c<2) return 1; FILE*f=fopen(v[1],\"rb\"); if(!f) return 1;\n"
    "  char m[4]; if(fread(m,1,4,f)!=4){fclose(f);return 0;}\n"
    "  if(memcmp(m,\"IMG\",3)!=0){fclose(f);return 0;}\n"
    "  unsigned len=0; fread(&len,4,1,f); char buf[64];\n"
    "  fread(buf,1,len,f); fclose(f); return 0; }\n")


def test_structure_aware_fuzz_finds_format_overflow(store, case, pool, gcc, tmp_path):
    """Structure-aware mutation finds a length-driven overflow in a file parser that byte-level
    havoc misses -- it coordinates the length field with the data size."""
    import base64
    import struct as _s
    src = tmp_path / "fp.c"; src.write_text(_FILE_PARSER)
    exe = tmp_path / "fp"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w", str(src),
                       "-o", str(exe)], capture_output=True).returncode != 0:
        pytest.skip("build failed")
    target = ingest(store, case.id, exe, filename="fp")
    q = JobQueue(store.conn)
    seed = base64.b64encode(b"IMG\x00" + _s.pack("<I", 8) + b"A" * 8).decode()
    spec = [{"type": "magic", "value": "IMG\x00"},
            {"type": "u32", "endian": "little", "name": "len", "length_of": "data"},
            {"type": "blob", "name": "data"}]
    run = enqueue_fuzz(q, target, params={
        "input_mode": "file", "max_execs": 400, "max_seconds": 40, "exec_timeout": 1,
        "seeds": [seed], "format": spec})
    assert pool.wait_idle(60) and q.runs.get(run.id).status == "done"
    crashes = [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed]
    assert crashes and crashes[0].signal_name == "SIGSEGV"    # the overflow was found


def test_suggest_spec_autofinds_length_field():
    """The builder derives a magic + length + blob spec from a real sample, locating the
    length field by matching an integer to the trailing byte count."""
    import struct as _s

    from lykos.analyze.fuzz import structure
    sample = b"%PDF" + _s.pack("<I", 16) + b"A" * 16
    sug = structure.suggest_spec(sample)
    spec = sug["spec"]
    assert spec[0]["type"] == "magic" and spec[0]["value"] == "%PDF"
    assert spec[1]["type"] == "u32" and spec[1]["endian"] == "little"
    assert spec[1]["length_of"] == "data" and spec[-1]["type"] == "blob"


def test_describe_reports_field_carving_and_length_match():
    """describe() carves a sample with the real parser and flags whether each length field
    matches the actual blob size (the truthful preview the GUI shows)."""
    import struct as _s

    from lykos.analyze.fuzz import structure
    spec = [{"type": "magic", "value": "%PDF"},
            {"type": "u32", "endian": "little", "name": "len", "length_of": "data"},
            {"type": "blob", "name": "data"}]
    d = structure.describe(spec, b"%PDF" + _s.pack("<I", 16) + b"A" * 16)
    assert d["ok"] and d["roundtrip"] and d["consumed"] == d["sample_size"]
    intf = [f for f in d["fields"] if f["type"] == "u32"][0]
    assert intf["int"] == 16 and intf["length_match"] is True
    # a mismatched length is reported, not hidden
    d2 = structure.describe(spec, b"%PDF" + _s.pack("<I", 999) + b"A" * 4)
    assert [f for f in d2["fields"] if f["type"] == "u32"][0]["length_match"] is False


def test_detect_magic_known_signatures():
    from lykos.analyze.fuzz import structure
    assert structure.detect_magic(b"\x89PNG\r\n\x1a\nrest")[0] == "PNG"
    assert structure.detect_magic(b"%PDF-1.7 ...")[0] == "PDF"
    assert structure.detect_magic(b"nope")[0] is None


def test_b64_magic_roundtrips_through_from_spec():
    """Non-printable magic travels as {"b64": ...}; from_spec/describe must decode it."""
    import base64

    from lykos.analyze.fuzz import structure
    magic = b"\x00\x01\x02\xff"
    spec = [{"type": "magic", "value": {"b64": base64.b64encode(magic).decode()}},
            {"type": "blob", "name": "data"}]
    d = structure.describe(spec, magic + b"payload")
    assert d["ok"] and d["fields"][0]["match"] is True
    model = structure.from_spec(spec)
    assert model.serialize(model.parse(magic + b"payload")) == magic + b"payload"


def test_load_external_seeds_from_files_and_dir(tmp_path):
    """External seeding: real example input/config files reach the corpus via `seed_files` and
    `seed_dir` (not only base64 inline). This is what lets a config/parameter-driven parser be
    fuzzed from the files you already have -- jhead's EXIF OOB read was unreproduced until the
    crashing sample could be seeded this way. base64 `seeds` still works; bad/oversized entries
    are skipped, never fatal."""
    import base64

    from lykos.analyze.fuzz.stage import _MAX_SEED_BYTES, _load_external_seeds

    f1 = tmp_path / "a.conf"; f1.write_bytes(b"key=value\n")
    sd = tmp_path / "corpus"; sd.mkdir()
    (sd / "s1.bin").write_bytes(b"\xff\xd8sample")
    (sd / "s2.bin").write_bytes(b"other")
    big = tmp_path / "big.bin"; big.write_bytes(b"A" * (_MAX_SEED_BYTES + 1))

    out = _load_external_seeds({
        "seeds": [base64.b64encode(b"inline").decode()],
        "seed_files": [str(f1), str(tmp_path / "missing.bin"), str(big)],
        "seed_dir": str(sd),
    })
    assert b"inline" in out                      # base64 inline still honoured
    assert b"key=value\n" in out                 # explicit file loaded
    assert b"\xff\xd8sample" in out and b"other" in out   # whole directory loaded
    assert not any(len(s) > _MAX_SEED_BYTES for s in out)  # oversized skipped
    assert all(isinstance(s, bytes) for s in out)          # missing path skipped, no crash


def test_load_external_seeds_empty_is_empty():
    from lykos.analyze.fuzz.stage import _load_external_seeds
    assert _load_external_seeds({}) == []        # lets the caller fall back to _DEFAULT_SEEDS


# A parameter-driven service: it REQUIRES three well-formed flags before it runs -- a number
# (-t), a strict-shape session id (-s NNN-NNN-NNN-NNN), and a config file (-c). Fuzzed bare it
# just prints usage; the harness must DISCOVER the flags and SYNTHESIZE a valid value for each
# (especially the structured -s) to reach the strcpy overflow behind the config parser.
_PARAM_SVC = (
    "#include <ctype.h>\n#include <stdio.h>\n#include <string.h>\n#include <unistd.h>\n"
    "static void usage(const char*p){fprintf(stderr,"
    "\"usage: %s -t <seconds> -s <NNN-NNN-NNN-NNN> -c <config>\\n\",p);}\n"
    "static int valid_sid(const char*s){ if(!s||strlen(s)!=15) return 0;\n"
    "  for(int i=0;i<15;i++){ if((i+1)%4==0){ if(s[i]!='-') return 0; }\n"
    "    else if(!isdigit((unsigned char)s[i])) return 0; } return 1; }\n"
    "static void set_name(const char*v){ char name[64]; strcpy(name,v); printf(\"name=%s\\n\",name); }\n"
    "int main(int c,char**v){ const char*sid=0,*cfg=0; int ht=0,o;\n"
    "  while((o=getopt(c,v,\"t:s:c:\"))!=-1){ if(o=='t')ht=1; else if(o=='s')sid=optarg;\n"
    "    else if(o=='c')cfg=optarg; else {usage(v[0]);return 2;} }\n"
    "  if(!ht||!sid||!cfg){usage(v[0]);return 2;}\n"
    "  if(!valid_sid(sid)){fprintf(stderr,\"bad session id\\n\");return 3;}\n"
    "  FILE*f=fopen(cfg,\"r\"); if(!f) return 1; char line[512];\n"
    "  while(fgets(line,sizeof line,f)){ size_t n=strlen(line);\n"
    "    if(n&&line[n-1]=='\\n')line[n-1]=0; if(!strncmp(line,\"name=\",5)) set_name(line+5); }\n"
    "  fclose(f); return 0; }\n")


def test_parameter_driven_target_is_discovered_and_crashed(store, case, pool, gcc, tmp_path):
    """The parameter-driven case: a service gated behind required flags, one of them a strict-shape
    id (-s NNN-NNN-NNN-NNN). The campaign must discover `-c @@ -s <valid-shape> -t <n>` -- synthesize
    a value the validator accepts -- deliver the fuzzed config at @@, and reach the overflow. Locks
    structured required-value synthesis + file-arg delivery together."""
    import re
    src = tmp_path / "svc.c"; src.write_text(_PARAM_SVC)
    exe = tmp_path / "svc"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w", str(src),
                       "-o", str(exe)], capture_output=True).returncode != 0:
        pytest.skip("build failed")
    seed = tmp_path / "seed.conf"; seed.write_bytes(b"name=hello\nhost=127.0.0.1\n")
    target = ingest(store, case.id, exe, filename="svc")
    q = JobQueue(store.conn)
    # do NOT pin input_mode: the stage must discover the argv and force file delivery via @@
    run = enqueue_fuzz(q, target, params={"max_execs": 800, "max_seconds": 45, "exec_timeout": 1,
                                          "seed_files": [str(seed)]})
    assert pool.wait_idle(90) and q.runs.get(run.id).status == "done"
    crashes = [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed]
    assert crashes, "no crash: the parameter-driven target was never driven past its arg gate"
    # ANY recorded crash whose invocation carries a shape-synthesized id, not `crashes[0]`.
    # The campaign also fuzzes OPTION PREFIXES, so a crash can be recorded under
    # `-s -t -c @@ -s 111-111-111-111 -t 0` -- a prefix the flag fuzzer prepended in front of
    # the discovered invocation (getopt takes the last value, so it still reproduces). Reading
    # the FIRST `-s` of the FIRST crash then found the fuzzed flag rather than the discovered
    # one, which made this test depend on which campaign happened to crash first: it passed
    # until dispatch-prefix seeding made an earlier batch crash, and the capability it is about
    # -- synthesizing a value the validator accepts -- was unchanged either way.
    def _sid(argv):
        for i, a in enumerate(argv or []):
            if str(a) == "-s" and i + 1 < len(argv):
                if re.fullmatch(r"\d{3}-\d{3}-\d{3}-\d{3}", str(argv[i + 1])):
                    return str(argv[i + 1])
        return None
    hits = [(c, _sid(c.argv)) for c in crashes if _sid(c.argv)]
    assert hits, ("no crashing invocation carried a shape-synthesized -s value: "
                  + "; ".join(str(c.argv) for c in crashes[:3]))
    argv = hits[0][0].argv or []
    joined = " ".join(str(a) for a in argv)
    assert "@@" in joined or any("conf" in str(a) or "/" in str(a) for a in argv)  # config delivered


def test_parameter_driven_structured_crash_weaponizes_to_l2(store, case, pool, gcc, tmp_path):
    """The whole parameter-driven weaponization: a service gated behind `-t/-s/-c` (one a shaped
    id) whose config overflow is structured (`name=<...>`). The discovered invocation delivers the
    crashing config, and the L2 primitive -- preserving the `name=` structure around the overflow --
    confirms instruction-pointer control. Locks discovery + structured-input L2 together."""
    from lykos.analyze import invocation
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.ingest import enqueue_triage
    from lykos.analyze.poc.primitive_stage import enqueue_primitive
    from lykos.analyze.poc.stage import enqueue_build_poc
    from lykos.db.dao import DynResultDAO, PocDAO
    src = tmp_path / "svc.c"; src.write_text(_PARAM_SVC)
    exe = tmp_path / "svc"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w", str(src),
                       "-o", str(exe)], capture_output=True).returncode != 0:
        pytest.skip("build failed")
    target = ingest(store, case.id, exe, filename="svc")
    q = JobQueue(store.conn)
    for fn in (enqueue_triage, enqueue_disassemble):
        fn(q, target, force=True); assert pool.wait_idle(300)
    # discovery synthesizes the required params (incl. the shaped -s) that let the app run at all
    found = invocation.discover(["usage: %s -t <seconds> -s <NNN-NNN-NNN-NNN> -c <config>"])
    argv = invocation.propose_argv(found)
    assert "-s" in argv and "@@" in argv
    crash = b"name=" + b"A" * 300 + b"\n"                 # the structured, minimized crash shape
    sha = store.content.put_bytes(crash)[0]
    run = store.runs.create(case.id, "fuzz", status="done")
    DynResultDAO(store.conn).insert(target.id, case.id, run_id=run.id, input_sha=sha,
                                    input_mode="file", argv=argv, signal_name="SIGSEGV", crashed=True)
    p = {"input_sha": sha, "input_mode": "file", "argv": argv}
    enqueue_build_poc(q, target, params=dict(p), force=True); assert pool.wait_idle(300)
    enqueue_primitive(q, target, params=dict(p), force=True); assert pool.wait_idle(300)
    levels = {pc.level for pc in PocDAO(store.conn).list_by_target(target.id) if pc.verified}
    assert "L2" in levels, f"structured parameter-driven crash did not weaponize to L2: {levels}"


# svc + a win() reachable only via the overflow return: the whole parameter-driven -> L3 path.
_PARAM_SVC_WIN = _PARAM_SVC.replace(
    "#include <ctype.h>", "#include <ctype.h>\n#include <stdlib.h>").replace(
    "static void set_name",
    'static void win(void){ system("/bin/sh"); }\nstatic void set_name')


def test_parameter_driven_structured_crash_weaponizes_to_l3(store, case, pool, gcc, tmp_path):
    """The full parameter-driven -> L3 path: a service gated behind `-t/-s/-c` (one a shaped id),
    a config overflow (`name=<...>`), and a win(). Discovery synthesizes the required params, the
    crash is delivered through the structured config, and the exploit stage -- preserving the
    `name=` structure -- reaches L3: control flow is hijacked to win(), confirmed under the debugger
    with a negative control. Locks structured-input exploitation (not just the L2 primitive)."""
    from lykos.analyze import invocation
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.ingest import enqueue_triage
    from lykos.analyze.poc.exploit_stage import enqueue_exploit
    from lykos.analyze.poc.primitive_stage import enqueue_primitive
    from lykos.analyze.poc.stage import enqueue_build_poc
    from lykos.db.dao import DynResultDAO, PocDAO
    src = tmp_path / "svcw.c"; src.write_text(_PARAM_SVC_WIN)
    exe = tmp_path / "svcw"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w", str(src),
                       "-o", str(exe)], capture_output=True).returncode != 0:
        pytest.skip("build failed")
    target = ingest(store, case.id, exe, filename="svcw")
    q = JobQueue(store.conn)
    for fn in (enqueue_triage, enqueue_disassemble):
        fn(q, target, force=True); assert pool.wait_idle(300)
    found = invocation.discover(["usage: %s -t <seconds> -s <NNN-NNN-NNN-NNN> -c <config>"])
    argv = invocation.propose_argv(found)                 # -c @@ -s 111-111-111-111 -t 0
    crash = b"name=" + b"A" * 300 + b"\n"
    sha = store.content.put_bytes(crash)[0]
    run = store.runs.create(case.id, "fuzz", status="done")
    DynResultDAO(store.conn).insert(target.id, case.id, run_id=run.id, input_sha=sha,
                                    input_mode="file", argv=argv, signal_name="SIGSEGV", crashed=True)
    p = {"input_sha": sha, "input_mode": "file", "argv": argv}
    for fn in (enqueue_build_poc, enqueue_primitive):
        fn(q, target, params=dict(p), force=True); assert pool.wait_idle(300)
    enqueue_exploit(q, target, params={**p, "strategy": "auto", "timeout": 25}, force=True)
    assert pool.wait_idle(400)
    levels = {pc.level for pc in PocDAO(store.conn).list_by_target(target.id) if pc.verified}
    assert "L3" in levels, f"structured parameter-driven crash did not reach L3: {levels}"


# A parameter-driven service whose config overflow is BINARY-SAFE (fread + memcpy, not strcpy), so a
# full ROP chain -- whose x86-64 addresses contain NULs -- can be delivered through the structured
# `name=` config. No win(); ret2system is reached via a provided `pop rdi;ret` gadget + system@plt +
# "/bin/sh". The whole parameter-driven -> spawned-shell path.
_PARAM_SVC_SHELL = (
    "#include <ctype.h>\n#include <stdlib.h>\n#include <stdio.h>\n#include <string.h>\n"
    "#include <unistd.h>\n"
    '__asm__(".text\\n.global g_pop\\n g_pop: pop %rdi\\n ret\\n");\n'
    'volatile char *g_sh = "/bin/sh";\n'
    'static void usage(const char*p){fprintf(stderr,'
    '"usage: %s -t <seconds> -s <NNN-NNN-NNN-NNN> -c <config>\\n",p);}\n'
    "static int valid_sid(const char*s){ if(!s||strlen(s)!=15) return 0;\n"
    "  for(int i=0;i<15;i++){ if((i+1)%4==0){ if(s[i]!='-') return 0; }\n"
    "    else if(!isdigit((unsigned char)s[i])) return 0; } return 1; }\n"
    "static void set_name(const char*v,size_t n){ char name[64]; memcpy(name,v,n);"
    ' printf("ok %zu\\n",n); }\n'
    "int main(int c,char**v){ const char*sid=0,*cfg=0; int ht=0,o;\n"
    "  if(c>9999) system((char*)g_sh);\n"
    "  while((o=getopt(c,v,\"t:s:c:\"))!=-1){ if(o=='t')ht=1; else if(o=='s')sid=optarg;\n"
    "    else if(o=='c')cfg=optarg; else {usage(v[0]);return 2;} }\n"
    "  if(!ht||!sid||!cfg){usage(v[0]);return 2;}\n"
    "  if(!valid_sid(sid)){fprintf(stderr,\"bad session id\\n\");return 3;}\n"
    "  FILE*f=fopen(cfg,\"r\"); if(!f) return 1; char buf[4096];\n"
    "  size_t n=fread(buf,1,sizeof buf,f); fclose(f);\n"
    '  if(n>=5 && !memcmp(buf,"name=",5)) set_name(buf+5,n-5); return 0; }\n')


def test_parameter_driven_structured_crash_spawns_a_shell(store, case, pool, gcc, tmp_path):
    """The demonstrated EFFECT through structured params: a binary that needs `-t/-s/-c` (one a
    shaped id) and overflows a binary-safe `memcpy` of a `name=` config value is driven to a
    SPAWNED SHELL -- ret2system via a pop-rdi gadget, the chain delivered inside the structured
    config, confirmed by a real /bin/sh evaluating a forgery-proof marker."""
    from lykos.analyze import invocation
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.ingest import enqueue_triage
    from lykos.analyze.poc.exploit_stage import enqueue_exploit
    from lykos.analyze.poc.primitive_stage import enqueue_primitive
    from lykos.analyze.poc.stage import enqueue_build_poc
    from lykos.db.dao import DynResultDAO, FindingDAO, PocDAO
    src = tmp_path / "svcx.c"; src.write_text(_PARAM_SVC_SHELL)
    exe = tmp_path / "svcx"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w", str(src),
                       "-o", str(exe)], capture_output=True).returncode != 0:
        pytest.skip("build failed")
    target = ingest(store, case.id, exe, filename="svcx")
    q = JobQueue(store.conn)
    for fn in (enqueue_triage, enqueue_disassemble):
        fn(q, target, force=True); assert pool.wait_idle(300)
    argv = invocation.propose_argv(invocation.discover(
        ["usage: %s -t <seconds> -s <NNN-NNN-NNN-NNN> -c <config>"]))
    crash = b"name=" + b"A" * 300            # binary-safe; whole file is read
    sha = store.content.put_bytes(crash)[0]
    run = store.runs.create(case.id, "fuzz", status="done")
    DynResultDAO(store.conn).insert(target.id, case.id, run_id=run.id, input_sha=sha,
                                    input_mode="file", argv=argv, signal_name="SIGSEGV", crashed=True)
    p = {"input_sha": sha, "input_mode": "file", "argv": argv}
    for fn in (enqueue_build_poc, enqueue_primitive):
        fn(q, target, params=dict(p), force=True); assert pool.wait_idle(300)
    enqueue_exploit(q, target, params={**p, "strategy": "auto", "timeout": 25}, force=True)
    assert pool.wait_idle(400)
    levels = {pc.level for pc in PocDAO(store.conn).list_by_target(target.id) if pc.verified}
    assert "L3" in levels, f"did not reach L3: {levels}"
    titles = [f.title or "" for f in FindingDAO(store.conn).list_by_target(target.id)]
    assert any("spawned shell" in t for t in titles), f"no spawned-shell effect: {titles}"


# A converter: `conv [options] input output`. argc<3 -> usage; otherwise it reads the INPUT file
# (binary-safe fread) into a 64-byte buffer (overflow) and writes the OUTPUT. The harness must
# discover the two-positional shape and supply a writable scratch OUTPUT, or it never runs.
_CONV = (
    "#include <stdio.h>\n#include <string.h>\n"
    "static void usage(const char*p){ fprintf(stderr,\"usage: %s [options] input output\\n\",p); }\n"
    "int main(int c,char**v){ if(c<3){ usage(v[0]); return 2; }\n"
    "  FILE*f=fopen(v[1],\"rb\"); if(!f){ perror(\"open\"); return 1; }\n"
    "  char buf[64]; size_t n=fread(buf,1,4096,f); fclose(f);\n"
    "  FILE*o=fopen(v[2],\"wb\"); if(o){ fwrite(buf,1,n>64?64:n,o); fclose(o); } return 0; }\n")


def test_multipositional_converter_is_driven_to_a_crash(store, case, pool, gcc, tmp_path):
    """A `tool [opts] INPUT OUTPUT` converter: lykos must discover the two-positional shape, supply
    a writable scratch output, drive the input through the parser, and find the overflow -- not sit
    at the usage gate. Asserts a crash is found AND the invocation carried the output positional."""
    from lykos.analyze.ingest import enqueue_triage
    src = tmp_path / "conv.c"; src.write_text(_CONV)
    exe = tmp_path / "conv"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w", str(src),
                       "-o", str(exe)], capture_output=True).returncode != 0:
        pytest.skip("build failed")
    seed = tmp_path / "seed.bin"; seed.write_bytes(b"A" * 300)       # overflows buf[64]
    target = ingest(store, case.id, exe, filename="conv")
    q = JobQueue(store.conn)
    enqueue_triage(q, target, force=True); assert pool.wait_idle(120)
    run = enqueue_fuzz(q, target, params={"timeout": 60, "seed_files": [str(seed)]})
    assert pool.wait_idle(120) and q.runs.get(run.id).status == "done"
    crashes = [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed]
    assert crashes, "converter not driven to a crash (stuck at the usage gate?)"
    argv = crashes[0].argv or []
    assert any("lykos.out" in str(a) for a in argv), f"output positional not supplied: {argv}"


# A getenv-driven target: reads APP_CONFIG into a 64-byte buffer (strcpy overflow) and separately
# reads a benign APP_MODE. The env channel must mine the env-var NAMES from the binary, set a
# payload into them, crash the target, and ATTRIBUTE the crash to APP_CONFIG (not APP_MODE).
_ENV_VULN = (
    "#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n"
    "int main(void){ char buf[64];\n"
    "  char*m=getenv(\"APP_MODE\"); if(m) printf(\"mode=%s\\n\",m);\n"
    "  char*v=getenv(\"APP_CONFIG\"); if(v){ strcpy(buf,v); printf(\"cfg=%s\\n\",buf); }\n"
    "  return 0; }\n")


def test_env_var_channel_finds_and_attributes_crash(store, case, pool, gcc, tmp_path):
    """The environment-variable input channel: a program whose bug is reached only by SETTING an env
    var (not stdin/argv/file). The stage must detect the getenv import, mine the env NAMES from the
    binary's strings, fuzz a value in, crash it, and record a DynResult(input_mode='env') attributed
    to the vulnerable variable -- so the rest of the PoC ladder picks it up like any other crash."""
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.fuzz.env_stage import enqueue_env_fuzz
    from lykos.analyze.ingest import enqueue_triage
    src = tmp_path / "envvuln.c"; src.write_text(_ENV_VULN)
    exe = tmp_path / "envvuln"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w", str(src),
                       "-o", str(exe)], capture_output=True).returncode != 0:
        pytest.skip("build failed")
    target = ingest(store, case.id, exe, filename="envvuln")
    q = JobQueue(store.conn)
    for fn in (enqueue_triage, enqueue_disassemble):
        fn(q, target, force=True); assert pool.wait_idle(300)
    run = enqueue_env_fuzz(q, target, params={"max_execs": 400}, force=True)
    assert pool.wait_idle(300) and q.runs.get(run.id).status == "done"
    crashes = [d for d in DynResultDAO(store.conn).list_by_target(target.id)
               if d.crashed and d.input_mode == "env"]
    assert crashes, "env-var channel did not record a crash via the environment"
    argv0 = " ".join(str(a) for a in (crashes[0].argv or []))
    assert "APP_CONFIG=" in argv0, f"crash not attributed to the vulnerable env var: {argv0}"
    assert "APP_MODE=" not in argv0, f"benign env var misattributed as the cause: {argv0}"


def test_env_channel_self_gates_on_no_getenv(store, case, pool, gcc, tmp_path):
    """A target that reads no environment variable must leave the env channel inapplicable -- no
    getenv import means nothing to fuzz, and the stage records no env crash (negative control)."""
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.fuzz.env_stage import enqueue_env_fuzz
    from lykos.analyze.ingest import enqueue_triage
    src = tmp_path / "noenv.c"; src.write_text(_OK)
    exe = tmp_path / "noenv"
    if subprocess.run([gcc, "-O0", "-w", str(src), "-o", str(exe)],
                      capture_output=True).returncode != 0:
        pytest.skip("build failed")
    target = ingest(store, case.id, exe, filename="noenv")
    q = JobQueue(store.conn)
    for fn in (enqueue_triage, enqueue_disassemble):
        fn(q, target, force=True); assert pool.wait_idle(300)
    run = enqueue_env_fuzz(q, target, params={"max_execs": 100}, force=True)
    assert pool.wait_idle(300) and q.runs.get(run.id).status == "done"
    env_crashes = [d for d in DynResultDAO(store.conn).list_by_target(target.id)
                   if d.crashed and d.input_mode == "env"]
    assert not env_crashes, "env channel fired on a target that reads no environment variable"


# ------------------------------------------------- distillation is an optimiser, not a campaign
def test_distillation_stops_when_its_time_is_up():
    """Measured on zlib's ASan `example` binary: a 169-input corpus with 12,584 blocks armed took
    150 seconds to trace -- five to twelve times the whole campaign slice the caller had
    (34.2s/12.0s/12.0s) -- and the campaign that distillation exists to SPEED UP then executed
    the target zero times and reported `starved: True`.

    `cap` could not prevent it: a count bound is not a time bound when one item costs a second.
    This is the same lesson as the leak sweep, in a new place."""
    import time

    from lykos.analyze.fuzz import distill as D

    traced = []

    class _FakeRes:
        def __init__(self, blocks):
            self.blocks_hit, self.crashed = blocks, False

    import lykos.analyze.dynamic.sandbox as SB
    real = SB.run_batch
    try:
        def fake_run_batch(exe, datas, **kw):
            traced.append(datas[0])
            time.sleep(0.02)                             # each trace costs real time
            return [_FakeRes([0x1000 + len(traced)])]
        SB.run_batch = fake_run_batch
        inputs = [bytes([i]) * 4 for i in range(100)]
        out = D.block_coverage("x", inputs, blocks=(0x1000,), deadline=time.time() + 0.2)
    finally:
        SB.run_batch = real
    assert len(out) == len(inputs), "the result must stay aligned with the corpus"
    assert 0 < len(traced) < len(inputs), f"traced {len(traced)} of {len(inputs)}"
    # everything past the deadline comes back UNMEASURED, and distill keeps an unmeasured input
    assert out[-1] == set()
    kept = D.distill(inputs, out)["kept"]
    assert len(kept) >= len(inputs) - len(traced), "an unmeasured input was dropped as redundant"


def test_distillation_stops_asking_a_tracer_that_reports_nothing():
    """`directed.coverage_unavailable`: "blocks were recovered and armed but the runner reported
    no coverage for any input (ptrace may be unavailable in this sandbox)". The stage discovered
    that AFTER tracing all 169 seeds. Eight probes are enough to know."""
    from lykos.analyze.fuzz import distill as D

    traced = []

    class _Empty:
        blocks_hit, crashed = (), False

    import lykos.analyze.dynamic.sandbox as SB
    real = SB.run_batch
    try:
        def fake_run_batch(exe, datas, **kw):
            traced.append(datas[0])
            return [_Empty()]
        SB.run_batch = fake_run_batch
        inputs = [bytes([i]) * 4 for i in range(80)]
        out = D.block_coverage("x", inputs, blocks=(0x1000,))
    finally:
        SB.run_batch = real
    assert len(traced) <= D._SILENT_TRACER_PROBES, \
        f"asked a silent tracer {len(traced)} times"
    assert all(c == set() for c in out)
    # and nothing is dropped on that evidence
    assert len(D.distill(inputs, out)["kept"]) == len(inputs)


def test_a_working_tracer_is_not_cut_short():
    """The bail must not fire on a target where tracing works -- that would silently stop
    minsetting everywhere."""
    from lykos.analyze.fuzz import distill as D

    class _Res:
        def __init__(self, b):
            self.blocks_hit, self.crashed = b, False

    import lykos.analyze.dynamic.sandbox as SB
    real = SB.run_batch
    n = []
    try:
        def fake_run_batch(exe, datas, **kw):
            n.append(1)
            return [_Res([0x1000 + len(n)])]
        SB.run_batch = fake_run_batch
        inputs = [bytes([i]) * 4 for i in range(40)]
        out = D.block_coverage("x", inputs, blocks=(0x1000,))
    finally:
        SB.run_batch = real
    assert len(n) == len(inputs), "a working tracer was cut short"
    assert all(c for c in out)


def test_a_dispatch_token_is_seeded_where_the_program_tests_for_it():
    """`strncmp(line, "dump=", 5)` matches at OFFSET 0, so a token inserted mid-line reaches that
    branch by luck only -- and once a campaign has found one bug its corpus fills with inputs
    carrying the other prefix and keeps it through mutation.

    Measured on a fixture with two dispatch branches and a defect behind each: 21 of 21 crashes
    were the first branch's overflow, the campaign's own inputs show the second token being
    inserted mid-line (`name=\\x00dump=\\x00name=...`), and the defect behind it was never
    reached -- so the chain stopped one rung short for want of what that branch discloses.
    """
    from lykos.analyze.fuzz.stage import _dispatch_prefix_seeds
    seeds = _dispatch_prefix_seeds([b"name=", b"dump=", b"show:", b"AAAA", b"/bin/sh", b"%s"])
    assert b"dump=0" in seeds and b"name=0" in seeds and b"show:0" in seeds
    assert any(s.startswith(b"dump=") and len(s) > 50 for s in seeds), "a filler body too"
    assert any(s == b"dump=99999999" for s in seeds), "and an out-of-range number"
    # NOT every string in the image: that floods the corpus with noise
    assert not any(s.startswith(b"AAAA") or s.startswith(b"/bin/sh") for s in seeds)
    # bounded
    assert len(_dispatch_prefix_seeds([b"k%d=" % i for i in range(100)])) <= 40


# ---------------------------------------------------- a library is not a program
_LIB_SRC = ("#include <string.h>\n"
            "int parse(const char *s){ char b[8]; strcpy(b, s); return b[0]; }\n")


def test_fuzz_refuses_a_shared_object_instead_of_fabricating_a_crash(store, case, pool, gcc,
                                                                     tmp_path):
    """A shared object has no entry point, so executing it faults in the loader before any user
    code runs. That loader fault was being promoted to a 'confirmed critical CWE-787 RCE' -- a
    fabricated exploit on an image that never ran as a program.

    Measured on libfreerdp3.so at --budget 600: the baseline correctly reported DID NOT RUN, yet
    the directed campaign spun 30,248 no-op 'executions' and one of them surfaced a loader fault
    (pc outside any executable mapping) that `root_cause` filed as a confirmed critical
    control-flow hijack -- non-reproducible ('the reproducer did not re-crash'), once in ~30k. The
    run()/run_batch guards stop the COMMON path, but the campaign must refuse the image up front
    so no execution of it can surface at all -- a library is fuzzed through a harness (the
    libFuzzer path), never by running it."""
    so = tmp_path / "libvuln.so"
    c = tmp_path / "vuln.c"
    c.write_text(_LIB_SRC)
    if subprocess.run([gcc, "-shared", "-fPIC", "-O0", str(c), "-o", str(so)],
                      capture_output=True).returncode != 0:
        pytest.skip("build failed")
    from lykos.analyze.dynamic import sandbox
    assert sandbox._is_elf_shared_object(so), "fixture must be a no-entry-point shared object"

    target = ingest(store, case.id, so)
    q = JobQueue(store.conn)
    run = enqueue_fuzz(q, target, params={
        "input_mode": "stdin", "max_execs": 4000, "max_seconds": 25, "exec_timeout": 1})
    assert pool.wait_idle(60) and q.runs.get(run.id).status == "done"

    assert not [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed], \
        "a shared object produced a crash -- it must not be executed as a program"
    assert not [f for f in FindingDAO(store.conn).list_by_target(target.id)
                if f.state == "confirmed"], \
        "no confirmed finding may come from executing a library"


def test_the_campaign_short_circuits_a_shared_object_before_the_loop():
    """Source guard: the behavioural test above needs a C compiler, so this ensures the gate
    itself is not silently dropped. `fuzz_campaign` must refuse an ELF shared object up front
    (before spending the budget on no-op executions), not rely only on run()/run_batch returning
    not-runnable for each of thousands of iterations."""
    import inspect

    from lykos.analyze.fuzz import stage
    src = inspect.getsource(stage.fuzz_campaign)
    assert "_is_elf_shared_object" in src, "the campaign must check for a shared object"
    head = src[:src.index("_is_elf_shared_object")]
    assert "while execs <" not in head, "the shared-object guard must come BEFORE the exec loop"


# ------------------------------------------------- env channel refuses a shared object
_ENV_VULN_LIB = (
    "#include <string.h>\n#include <stdlib.h>\n"
    "int configure(void){ char buf[64];\n"
    "  char*v=getenv(\"APP_CONFIG\"); if(v){ strcpy(buf,v); return buf[0]; } return 0; }\n")


def test_env_channel_refuses_a_shared_object(store, case, pool, gcc, tmp_path):
    """The env channel's native runner is a bare subprocess (not sandbox.run), so it had no
    shared-object guard: it executed libfreerdp3.so, the loader faulted before any getenv, and
    that fault was filed as a crash and promoted to a fabricated confirmed critical CWE-787. The
    library here calls getenv (so the applicability gate passes on its import) but has no entry
    point, and the stage must refuse to run it -- no env crash, no finding."""
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.fuzz.env_stage import enqueue_env_fuzz
    from lykos.analyze.ingest import enqueue_triage
    src = tmp_path / "envlib.c"; src.write_text(_ENV_VULN_LIB)
    so = tmp_path / "libenvvuln.so"
    if subprocess.run([gcc, "-shared", "-fPIC", "-O0", "-w", str(src), "-o", str(so)],
                      capture_output=True).returncode != 0:
        pytest.skip("build failed")
    from lykos.analyze.dynamic import sandbox
    assert sandbox._is_elf_shared_object(so), "fixture must be a no-entry-point shared object"

    target = ingest(store, case.id, so, filename="libenvvuln.so")
    q = JobQueue(store.conn)
    for fn in (enqueue_triage, enqueue_disassemble):
        fn(q, target, force=True); assert pool.wait_idle(300)
    run = enqueue_env_fuzz(q, target, params={"max_execs": 400}, force=True)
    assert pool.wait_idle(300) and q.runs.get(run.id).status == "done"
    assert not [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed], \
        "the env channel executed a shared object and recorded a loader fault as a crash"
    assert not [f for f in FindingDAO(store.conn).list_by_target(target.id)
                if f.state == "confirmed"], "no confirmed finding may come from running a library"


def test_the_bare_env_runner_backstops_a_shared_object():
    """Source guard for the backstop inside the runner itself: `_run_with_env` is the single
    native exec door for the env channel and must refuse a shared object even if a future caller
    forgets the stage-level gate."""
    import inspect

    from lykos.analyze.fuzz import envfuzz
    src = inspect.getsource(envfuzz._run_with_env)
    assert "_is_elf_shared_object" in src
    head = src[:src.index("_is_elf_shared_object")]
    assert "Popen" not in head, "the guard must come before the subprocess is spawned"


def test_a_shared_object_with_a_nonzero_entry_point_is_still_refused(gcc, tmp_path):
    """The REGRESSION that shipped: the guard keyed on `entry == 0`, but Debian (and others) link
    a shared library with a NONZERO entry stub -- e.g. libz.so.1 at 0x3310. Such a library slipped
    past the guard, was executed as a PIE, faulted in the loader, and was filed as a confirmed
    critical CWE on a stock system library. The discriminator is ET_DYN + no PT_INTERP (a PIE has
    an interpreter; a static-PIE carries DF_1_PIE); the entry point is irrelevant."""
    from lykos.analyze.dynamic import sandbox
    so = tmp_path / "libentry.so"
    c = tmp_path / "e.c"; c.write_text("int f(int x){ return x + 1; }\n")
    if subprocess.run([gcc, "-shared", "-fPIC", "-O0", str(c), "-o", str(so)],
                      capture_output=True).returncode != 0:
        pytest.skip("build failed")
    # Force a nonzero e_entry, exactly as a Debian-style .so carries, without depending on the
    # toolchain default: patch the ELF header's entry field in place.
    data = bytearray(so.read_bytes())
    is64 = data[4] == 2
    en = "little" if data[5] == 1 else "big"
    off, size = (24, 8) if is64 else (24, 4)
    data[off:off + size] = (0x3310).to_bytes(size, en)      # a nonzero entry, like libz.so.1
    so.write_bytes(bytes(data))
    assert not sandbox._interp_of(so), "a shared object has no PT_INTERP"
    assert sandbox._is_elf_shared_object(so), \
        "a shared object with a nonzero entry stub must still be refused (the libz regression)"


def test_a_static_pie_executable_is_not_mistaken_for_a_library(gcc, tmp_path):
    """The one runnable ET_DYN-without-PT_INTERP: a static-PIE executable, marked DF_1_PIE. The
    guard must NOT refuse it, or we would decline to fuzz a legitimate program. file(1) reads the
    same bit to tell a 'pie executable' from a 'shared object'."""
    from lykos.analyze.dynamic import sandbox
    exe = tmp_path / "sp"
    c = tmp_path / "m.c"; c.write_text("int main(void){ return 0; }\n")
    if subprocess.run([gcc, "-static-pie", "-fPIE", str(c), "-o", str(exe)],
                      capture_output=True).returncode != 0:
        pytest.skip("static-pie unsupported by this toolchain")
    assert not sandbox._interp_of(exe), "a static-PIE has no PT_INTERP"
    assert sandbox._has_df_1_pie(exe), "a static-PIE must carry DF_1_PIE"
    assert not sandbox._is_elf_shared_object(exe), \
        "a static-PIE executable must be runnable, not refused as a library"
