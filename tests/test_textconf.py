"""Config-driven targets: discover the invocation, infer the input is text, mine the keys.

This is the shape most real services have -- a mandatory `-c <config>` and a `fgets` loop with
a `strcpy` behind it -- and it was the shape the platform was worst at. Argv was ignored, so
the target printed its usage and exited on every execution; and once argv was fixed, no format
model described `key=value` text, so 2,000 executions produced 826 distinct behaviours and no
crashes against a 64-byte buffer.
"""
import random

from lykos.analyze import invocation
from lykos.analyze.fuzz import textconf


def test_keys_come_from_the_binarys_own_key_equals_literals():
    """`name=%s listen=%s workers=%d` is a printf format, and it names every config key. It is
    also the ONLY place some of them appear: .rodata packs `name` against its neighbour, so
    the standalone string is "@@name" and mining bare words misses the one key that reaches
    the bug."""
    keys = textconf.keys_from(["@@name", "name=%s listen=%s workers=%d", "cannot open config"])
    assert keys[:3] == ["name", "listen", "workers"]


def test_disassembled_code_bytes_are_not_config_keys():
    """Scanning a binary's raw bytes yields `ATSH` and `AVAUA` (x86 register-save sequences),
    `Genu`/`ntel` (the CPUID vendor string split across registers) and `uHdH`. They match a
    letters-and-digits shape perfectly and filled the first sixteen key slots of a program
    whose keys are name, listen and workers. Most fall to a shape rule -- an identifier's case
    is consistent and a name does not contain `MMMM` -- but the CPUID fragments are lowercase
    four-letter words and simply have to be named."""
    junk = ["ATSH", "AVAUA", "AWAVAUATSH", "Genu", "ntel", "uHdH", "u6H=x", "yKAF=1",
            "IMMMMEMMMMMAMMMMM=2"]
    assert textconf.keys_from(junk) == []


def test_the_mutator_writes_lines_that_the_parser_will_actually_parse():
    """A key the program does not accept is a line it skips, which is an execution that does
    nothing. Every generated line has to carry a real key and a separator."""
    m = textconf.KeyValueMutator(random.Random(7), ["name", "listen"])
    data = textconf.seed_for(["name", "listen"])
    hits = 0
    for _ in range(200):
        out = m.mutate(data)
        assert isinstance(out, bytes)
        hits += any(k in out and (b"=" in out or b":" in out) for k in (b"name", b"listen"))
    assert hits > 190


def test_the_mutator_produces_values_past_the_usual_buffer_sizes():
    """A 64-byte destination is not overflowed by a value that is merely "long"."""
    m = textconf.KeyValueMutator(random.Random(3), ["name"])
    longest = 0
    for _ in range(400):
        for line in m.mutate(b"name=ok\n").split(b"\n"):
            if line.startswith(b"name="):
                longest = max(longest, len(line) - 5)
    assert longest > 256


def test_binary_input_falls_back_to_byte_havoc():
    """A campaign that picked this model wrongly must degrade to the old behaviour rather than
    spin on input it cannot parse."""
    m = textconf.KeyValueMutator(random.Random(1), ["name"])
    png = b"\x89PNG\r\n\x1a\n" + bytes(64)
    out = m.mutate(png)
    assert isinstance(out, bytes) and out != b""


def test_a_seed_the_parser_accepts():
    seed = textconf.seed_for(["name", "listen", "workers"])
    assert b"name=" in seed and seed.endswith(b"\n")
    assert all(b"=" in line for line in seed.split(b"\n") if line and not line.startswith(b"#"))


def test_the_config_flag_is_what_says_the_input_is_text():
    """The model is chosen on evidence, not on a hunch: the binary documents a REQUIRED config
    path, so its input is a config file, so it is line-oriented text. An optional flag is not
    that evidence -- unzip documents `[-d exdir]` and takes a zip."""
    found = invocation.discover(["usage: svc -c <config>", "c:v"])
    assert any(f["kind"] == "config" and not f["optional"] for f in found["flags"])
    unz = invocation.discover(["Usage: unzip [-opts] file[.zip] [-d exdir]"])
    assert all(f["optional"] for f in unz["flags"])
    assert invocation.propose_argv(unz) == []


CONFIG_DAEMON = r"""
/* The shape of a real service: mandatory -c <config>, key=value parser, bug in the parser. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
struct cfg { char name[64]; char listen[32]; int workers; };
static void set_opt(struct cfg *c, const char *k, const char *v) {
    if (!strcmp(k, "name"))         strcpy(c->name, v);      /* unchecked: the bug */
    else if (!strcmp(k, "listen"))  strncpy(c->listen, v, sizeof c->listen - 1);
    else if (!strcmp(k, "workers")) c->workers = atoi(v);
}
int main(int argc, char **argv) {
    struct cfg c; const char *path = NULL; char line[512]; FILE *f;
    memset(&c, 0, sizeof c);
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "-c") && i + 1 < argc) path = argv[++i];
    if (!path) { fprintf(stderr, "usage: %s -c <config>\n", argv[0]); return 2; }
    if (!(f = fopen(path, "r"))) { fprintf(stderr, "cannot open config\n"); return 1; }
    while (fgets(line, sizeof line, f)) {
        char *eq, *nl;
        if (line[0] == '#') continue;
        if ((nl = strchr(line, '\n'))) *nl = 0;
        if (!(eq = strchr(line, '='))) continue;
        *eq = 0; set_opt(&c, line, eq + 1);
    }
    fclose(f);
    printf("name=%s listen=%s workers=%d\n", c.name, c.listen, c.workers);
    return 0;
}
"""


def test_a_config_daemon_is_cracked_from_the_binary_alone(tmp_path):
    """End to end, told nothing: the campaign reads `-c <config>` off the binary's own usage
    line, RUNS the target to check the proposal, infers from that flag that the input is text,
    mines `name`/`listen`/`workers` out of the printf format, and overflows the 64-byte buffer.

    Every one of those steps was missing. Without the argv the daemon printed its usage and
    exited on all 8,000 executions; with the argv but no text model, 2,000 executions produced
    826 distinct behaviours and no crash.
    """
    import shutil
    import subprocess

    import pytest
    if not shutil.which("cc"):
        pytest.skip("no C compiler")
    src = tmp_path / "daemon.c"
    src.write_text(CONFIG_DAEMON)
    exe = tmp_path / "daemon"
    if subprocess.run(["cc", "-w", "-fno-stack-protector", "-o", str(exe), str(src)],
                      capture_output=True).returncode != 0:
        pytest.skip("compile failed")

    from lykos.analyze import register as register_stages
    from lykos.analyze.fuzz import enqueue_fuzz
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.casestore import CaseStore
    from lykos.db.dao import DynResultDAO, EventDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    register_stages()
    store = CaseStore.open(tmp_path / "case")
    cid = store.cases.create("cfgdaemon").id
    target = ingest(store, cid, exe, filename=exe.name)
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2))
    pool.start()
    try:
        q = JobQueue(store.conn)
        enqueue_triage(q, target)
        pool.wait_idle(120)
        target = store.targets.get(target.id)
        # nothing supplied: no argv, no seed, no format, no prior disassembly
        enqueue_fuzz(q, target, params={"max_execs": 9000, "max_seconds": 90,
                                        "exec_timeout": 2}, force=True)
        pool.wait_idle(400)
    finally:
        pool.stop()

    events = {}
    for e in EventDAO(store.conn).list(case_id=cid, limit=5000):
        events.setdefault(e.type, e.payload or {})
    assert events.get("fuzz.invocation", {}).get("argv") == ["-c", "@@"], \
        "the usage line says -c <config> and the target accepts it"
    assert "verified by running it" in (events["fuzz.invocation"].get("discovered") or "")
    assert events.get("fuzz.format", {}).get("model") == "keyvalue"

    crashes = [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed]
    assert crashes, "the 64-byte strcpy behind name= should be reached"
