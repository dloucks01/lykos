"""Phase 6 — injection PoC synthesis: command injection / format string / path traversal
confirmed by effect, without fuzzing."""
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.analyze.poc import enqueue_inject, injection
from lykos.db.dao import CallEdgeDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_CMDI = ('#include <stdio.h>\n#include <stdlib.h>\n'
         'int main(int c,char**v){if(c<2)return 1;char cmd[256];'
         'snprintf(cmd,sizeof cmd,"echo got: %s",v[1]);return system(cmd);}\n')
_FMT = ('#include <stdio.h>\n'
        'int main(int c,char**v){if(c<2)return 1;printf(v[1]);printf("\\n");return 0;}\n')
_TRAV = ('#include <stdio.h>\nint main(int c,char**v){if(c<2)return 1;FILE*f=fopen(v[1],"r");'
         'if(!f)return 1;char b[512];size_t n=fread(b,1,sizeof b,f);fwrite(b,1,n,stdout);'
         'fclose(f);return 0;}\n')
# CWE-89: stdin concatenated into a sqlite3 query; the matching rows are printed (a UNION-injected
# marker column surfaces). The sqlite3 API is forward-declared so no dev header is needed.
_SQLI = ('#include <stdio.h>\n#include <string.h>\n#include <unistd.h>\n'
         'typedef struct sqlite3 sqlite3; typedef int(*cb)(void*,int,char**,char**);\n'
         'extern int sqlite3_open(const char*,sqlite3**);\n'
         'extern int sqlite3_exec(sqlite3*,const char*,cb,void*,char**);\n'
         'extern int sqlite3_close(sqlite3*);\n'
         'static int row(void*u,int a,char**v,char**c){printf("found: %s\\n",(a>0&&v[0])?v[0]:"");'
         'return 0;}\n'
         'int main(void){sqlite3*db;sqlite3_open(":memory:",&db);'
         'sqlite3_exec(db,"CREATE TABLE users(name TEXT);",0,0,0);'
         'sqlite3_exec(db,"INSERT INTO users VALUES(\'admin\'),(\'bob\');",0,0,0);'
         'char u[128],q[512];int n=read(0,u,sizeof u-1);if(n<=0)return 0;'
         'if(u[n-1]==\'\\n\')n--;u[n]=0;'
         'snprintf(q,sizeof q,"SELECT name FROM users WHERE name=\'%s\'",u);'
         'sqlite3_exec(db,q,row,0,0);sqlite3_close(db);return 0;}\n')


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=60, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _edges(sinks):
    return [{"src_addr": "0x1149", "site_addr": "0x1160", "dst_addr": None,
             "dst_name": s, "external": 1} for s in sinks]


def _run(store, pool, gcc, tmp_path, src, name, sinks, cwe):
    c = tmp_path / f"{name}.c"; c.write_text(src)
    b = tmp_path / name
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    case = store.cases.create(name)
    target = ingest(store, case.id, b)
    CallEdgeDAO(store.conn).replace_for_target(target.id, _edges(sinks))
    q = JobQueue(store.conn)
    run = enqueue_inject(q, target, params={"input_mode": "arg", "timeout": 8})
    assert pool.wait_idle(60)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("sandbox unavailable: " + str(rec.error))
    cwes = {f.cwe for f in FindingDAO(store.conn).list_by_target(target.id)
            if f.detector == "inject_synth"}
    return cwe in cwes


def test_fmt_and_traversal_payloads_and_confirm():
    # unit: confirmation logic
    assert injection.cmdi_confirm(b"got: \nMARK123\n", "; echo MARK123", "MARK123")
    assert not injection.cmdi_confirm(b"got: ; echo MARK123\n", "x", "MARK123")
    assert injection.fmt_confirm(b"AAA.0x7ffe.0x40.0x0", b"AAA...", "AAA")
    assert not injection.fmt_confirm(b"AAA.%p.%p", b"AAA...", "AAA")
    assert injection.traversal_confirm(b"root:x:0:0:root:/root", b"", "")


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native x86-64")
def test_command_injection_confirmed(store, pool, gcc, tmp_path):
    assert _run(store, pool, gcc, tmp_path, _CMDI, "ci", ["system"], "CWE-78")


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native x86-64")
def test_format_string_confirmed(store, pool, gcc, tmp_path):
    assert _run(store, pool, gcc, tmp_path, _FMT, "fs", ["printf"], "CWE-134")


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native x86-64")
def test_path_traversal_confirmed(store, pool, gcc, tmp_path):
    assert _run(store, pool, gcc, tmp_path, _TRAV, "tv", ["fopen"], "CWE-22")


_XXE = ('#include <stdio.h>\n#include <unistd.h>\n'
        '#include <libxml/parser.h>\n#include <libxml/tree.h>\n'
        'int main(void){char b[8192];int n=read(0,b,sizeof b-1);if(n<=0)return 0;b[n]=0;'
        'xmlDocPtr d=xmlReadMemory(b,n,"in.xml",0,XML_PARSE_NOENT|XML_PARSE_DTDLOAD);'
        'if(!d){printf("parse error\\n");return 1;}xmlNodePtr r=xmlDocGetRootElement(d);'
        'xmlChar*t=r?xmlNodeGetContent(r):0;if(t){printf("parsed: %s\\n",(char*)t);xmlFree(t);}'
        'xmlFreeDoc(d);return 0;}\n')


_SSRF = ('#include <stdio.h>\n#include <string.h>\n#include <unistd.h>\n'
         'typedef void CURL; extern CURL*curl_easy_init(void);\n'
         'extern int curl_easy_setopt(CURL*,int,...); extern int curl_easy_perform(CURL*);\n'
         'extern void curl_easy_cleanup(CURL*);\n'
         'int main(void){char u[512];int n=read(0,u,sizeof u-1);if(n<=0)return 0;'
         'if(u[n-1]==\'\\n\')n--;u[n]=0;CURL*c=curl_easy_init();if(!c)return 1;'
         'curl_easy_setopt(c,10002,u);curl_easy_setopt(c,10001,stdout);'
         'curl_easy_perform(c);curl_easy_cleanup(c);return 0;}\n')


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native x86-64")
def test_ssrf_confirmed(store, pool, gcc, tmp_path):
    """A C program fetching a user-controlled URL via libcurl is driven to a confirmed CWE-918 PoC:
    a file: URL makes the server return a local file (the offline-observable SSRF facet)."""
    import glob
    if not (glob.glob("/usr/lib/x86_64-linux-gnu/libcurl.so*") or glob.glob("/usr/lib/libcurl.so*")
            or glob.glob("/lib/x86_64-linux-gnu/libcurl.so*")):
        pytest.skip("no libcurl runtime")
    c = tmp_path / "ssrf.c"; c.write_text(_SSRF); b = tmp_path / "ssrf"
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(b), "-l:libcurl.so.4"],
                      capture_output=True, check=False).returncode:
        pytest.skip("cannot build libcurl fixture")
    case = store.cases.create("ssrf"); target = ingest(store, case.id, b)
    CallEdgeDAO(store.conn).replace_for_target(target.id,
                                               _edges(["curl_easy_setopt", "curl_easy_perform"]))
    run = enqueue_inject(JobQueue(store.conn), target, params={"input_mode": "stdin", "timeout": 8})
    assert pool.wait_idle(60)
    if JobQueue(store.conn).runs.get(run.id).status != "done":
        pytest.skip("sandbox unavailable")
    f = next((f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.detector == "inject_synth" and f.cwe == "CWE-918"), None)
    assert f is not None and "ssrf" in f.title.lower()


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native x86-64")
def test_xxe_confirmed(store, pool, gcc, tmp_path):
    """A C program parsing stdin XML with entity substitution enabled (XML_PARSE_NOENT) is driven to
    a confirmed CWE-611 PoC: an external SYSTEM entity resolves /etc/passwd and its content returns."""
    import glob
    if not glob.glob("/usr/include/libxml2/libxml/parser.h"):
        pytest.skip("no libxml2 dev headers")
    c = tmp_path / "xxe.c"; c.write_text(_XXE); b = tmp_path / "xxe"
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(b), "-I/usr/include/libxml2", "-lxml2"],
                      capture_output=True, check=False).returncode:
        pytest.skip("cannot build libxml2 fixture")
    case = store.cases.create("xxe"); target = ingest(store, case.id, b)
    CallEdgeDAO(store.conn).replace_for_target(target.id, _edges(["xmlReadMemory"]))
    run = enqueue_inject(JobQueue(store.conn), target, params={"input_mode": "stdin", "timeout": 8})
    assert pool.wait_idle(60)
    if JobQueue(store.conn).runs.get(run.id).status != "done":
        pytest.skip("sandbox unavailable")
    f = next((f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.detector == "inject_synth" and f.cwe == "CWE-611"), None)
    assert f is not None and ("xxe" in f.title.lower() or "external entity" in f.title.lower())


_SQLI_ERR = ('#include <stdio.h>\n#include <string.h>\n#include <unistd.h>\n'
             'typedef struct sqlite3 sqlite3; typedef int(*cb)(void*,int,char**,char**);\n'
             'extern int sqlite3_open(const char*,sqlite3**);\n'
             'extern int sqlite3_exec(sqlite3*,const char*,cb,void*,char**);\n'
             'extern int sqlite3_close(sqlite3*);\n'
             'int main(void){sqlite3*db;sqlite3_open(":memory:",&db);'
             'sqlite3_exec(db,"CREATE TABLE u(name TEXT);",0,0,0);'
             'char u[128],q[512],*e=0;int n=read(0,u,sizeof u-1);if(n<=0)return 0;'
             'if(u[n-1]==\'\\n\')n--;u[n]=0;'
             'snprintf(q,sizeof q,"SELECT COUNT(*) FROM u WHERE name=\'%s\'",u);'  # VULNERABLE
             'int rc=sqlite3_exec(db,q,0,0,&e);'
             'if(rc!=0&&e)printf("DB error: %s\\n",e);else printf("query ok\\n");'  # surfaces error
             'sqlite3_close(db);return 0;}\n')


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native x86-64")
def test_sql_injection_error_based_confirmed(store, pool, gcc, tmp_path):
    """An auth/count-style SQLi target that never displays rows but SURFACES the DB error is still
    driven to a confirmed CWE-89 PoC via the error-based path (a parse error names our token)."""
    import glob
    if not (glob.glob("/usr/lib/x86_64-linux-gnu/libsqlite3.so*") or glob.glob("/usr/lib/libsqlite3.so*")
            or glob.glob("/lib/x86_64-linux-gnu/libsqlite3.so*")):
        pytest.skip("no libsqlite3 runtime")
    c = tmp_path / "sqlie.c"; c.write_text(_SQLI_ERR); b = tmp_path / "sqlie"
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(b), "-l:libsqlite3.so.0"],
                      capture_output=True, check=False).returncode:
        pytest.skip("cannot build sqlite3 fixture")
    case = store.cases.create("sqlie"); target = ingest(store, case.id, b)
    CallEdgeDAO(store.conn).replace_for_target(target.id, _edges(["sqlite3_exec", "sqlite3_open"]))
    run = enqueue_inject(JobQueue(store.conn), target, params={"input_mode": "stdin", "timeout": 8})
    assert pool.wait_idle(60)
    if JobQueue(store.conn).runs.get(run.id).status != "done":
        pytest.skip("sandbox unavailable")
    f = next((f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.detector == "inject_synth" and f.cwe == "CWE-89"), None)
    assert f is not None and "sql injection" in f.title.lower()


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native x86-64")
def test_sql_injection_confirmed(store, pool, gcc, tmp_path):
    """A C program that concatenates stdin into a sqlite3 query is driven to a confirmed CWE-89 PoC:
    a UNION-injected marker column comes back from the DB (forgery-proof, no analyst input)."""
    import glob
    if not (glob.glob("/usr/lib/x86_64-linux-gnu/libsqlite3.so*") or glob.glob("/usr/lib/libsqlite3.so*")
            or glob.glob("/lib/x86_64-linux-gnu/libsqlite3.so*")):
        pytest.skip("no libsqlite3 runtime")
    c = tmp_path / "sqli.c"; c.write_text(_SQLI)
    b = tmp_path / "sqli"
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(b), "-l:libsqlite3.so.0"],
                      capture_output=True, check=False).returncode:
        pytest.skip("cannot build sqlite3 fixture (no libsqlite3)")
    case = store.cases.create("sqli")
    target = ingest(store, case.id, b)
    CallEdgeDAO(store.conn).replace_for_target(target.id, _edges(["sqlite3_exec", "sqlite3_open"]))
    run = enqueue_inject(JobQueue(store.conn), target, params={"input_mode": "stdin", "timeout": 8})
    assert pool.wait_idle(60)
    if JobQueue(store.conn).runs.get(run.id).status != "done":
        pytest.skip("sandbox unavailable")
    f = next((f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.detector == "inject_synth" and f.cwe == "CWE-89"), None)
    assert f is not None and "sql injection" in f.title.lower() and "demonstrated" in f.title.lower()


def test_leaked_words_extracts_and_decodes_secret_bytes():
    """The format-string leak proof: hex words after the marker are the disclosed memory, and the
    printable ones decode to the leaked stack strings/secrets (this is how a leaked canary shows)."""
    from lykos.analyze.poc.inject_stage import _leaked_words
    # 0x435f543352433353 = 'S3CR3T_C' little-endian; a non-printable pointer is not an ascii hit
    out = b"MARK.0x7ffe12340000.0x435f543352433353.(nil)"
    words, ascii_hits = _leaked_words(out, "MARK")
    assert "0x7ffe12340000" in words and "(nil)" in words
    assert any("S3CR3T" in a for a in ascii_hits)         # the secret was recovered from the leak


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native x86-64")
def test_format_string_demonstrates_disclosure_with_proof(store, pool, gcc, tmp_path):
    """A confirmed format string must not just be labelled -- it DEMONSTRATES information
    disclosure, headlines the finding as such, and attaches the captured leaked memory as a proof
    artifact (with %n write-what-where flagged as the potential next effect)."""
    import json
    from lykos.analyze.poc import enqueue_inject
    from lykos.db.dao import CallEdgeDAO, FindingDAO
    from lykos.analyze.ingest import ingest
    from lykos.jobs import JobQueue
    b = tmp_path / "fs2"
    (tmp_path / "fs2.c").write_text(_FMT)
    if subprocess.run([gcc, "-O0", "-w", str(tmp_path / "fs2.c"), "-o", str(b)],
                      capture_output=True).returncode:
        pytest.skip("build failed")
    case = store.cases.create("fs2")
    target = ingest(store, case.id, b)
    CallEdgeDAO(store.conn).replace_for_target(target.id, _edges(["printf"]))
    run = enqueue_inject(JobQueue(store.conn), target, params={"input_mode": "arg", "timeout": 8})
    assert pool.wait_idle(60)
    if JobQueue(store.conn).runs.get(run.id).status != "done":
        pytest.skip("sandbox unavailable")
    f = next((f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.detector == "inject_synth" and f.cwe == "CWE-134"), None)
    assert f is not None and "disclosure" in f.title.lower() and "demonstrated" in f.title.lower()
    effs = json.loads(next(e["detail"] for e in f.evidence if e["channel"] == "effects"))
    leak = next(e for e in effs if e["kind"] == "info-disclosure")
    assert leak["status"] == "demonstrated" and leak["proof"]["sha"]        # captured evidence
    assert store.content.get_bytes(leak["proof"]["sha"])                    # proof is fetchable
    assert any(e["kind"] == "memory-corruption" for e in effs)              # %n -> write, potential
