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
    from lykos.analyze.fuzz.stage import _load_external_seeds, _MAX_SEED_BYTES

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
    argv = crashes[0].argv or []
    joined = " ".join(str(a) for a in argv)
    assert "-s" in argv, f"the required -s flag was not in the crashing invocation: {argv}"
    sid = argv[argv.index("-s") + 1]
    assert re.fullmatch(r"\d{3}-\d{3}-\d{3}-\d{3}", sid), f"-s value not shape-synthesized: {sid!r}"
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
