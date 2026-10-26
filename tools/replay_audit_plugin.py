"""Bundle-replay audit: does every verified L3 PoC's shipped runner.sh actually reproduce?

A verified L3 is confirmed live by the exploit stage; the bundle handed to the operator is a
separate artifact, and nothing ran it. This pytest plugin does: after every test that used the
`store` fixture, it unpacks each verified L3 bundle that test filed, runs its runner.sh, and
appends one JSON line per bundle to $LYKOS_REPLAY_REPORT (default /tmp/replay_audit.jsonl).

    LYKOS_REPLAY_REPORT=/tmp/r.jsonl PYTHONPATH=tools python -m pytest -p replay_audit_plugin \
        tests/test_exploit.py tests/test_ret2libc.py ...
    python tools/replay_audit_plugin.py /tmp/r.jsonl          # one line per bundle

Reading the result: a shell-proved bundle (replay_shell.py / replay_leak.py) exits 0 and prints
[+]; a redirect-only ret2win "succeeds" by printing the win's own output (it may then crash);
cross-arch register-proof L3s have no observable effect to replay. Doc 51 item 2 has the
2026-10-26 matrix."""
import io
import json
import os
import subprocess
import tarfile
import tempfile

import pytest

REPORT = os.environ.get("LYKOS_REPLAY_REPORT", "/tmp/replay_audit.jsonl")


@pytest.fixture(autouse=True)
def _replay_l3_bundles(request):
    # Requested BEFORE the test, so this fixture tears down before `store` does.
    store = request.getfixturevalue("store") if "store" in request.fixturenames else None
    yield
    if store is None:
        return
    try:
        rows = store.conn.execute(
            "SELECT id, bundle_sha, target_id FROM poc WHERE level='L3' AND verified=1").fetchall()
    except Exception as e:                                   # noqa: BLE001
        rows = []
        _log({"test": request.node.nodeid, "error": repr(e)})
    for pid, bsha, tid in rows:
        rec = {"test": request.node.nodeid, "poc": pid}
        try:
            data = store.content.get_bytes(bsha)
            with tempfile.TemporaryDirectory() as d:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
                    tf.extractall(d, filter="data")
                    names = tf.getnames()
                runner = next((os.path.join(d, n) for n in names if n.endswith("runner.sh")), None)
                meta = next((n for n in names if n.endswith("meta.json")), None)
                if meta:
                    with open(os.path.join(d, meta)) as fh:
                        m = json.load(fh)
                    rec["exploit"] = m.get("exploit")
                    rec["verdict"] = m.get("verdict")
                rec["files"] = sorted(os.path.basename(n) for n in names)
                if runner:
                    r = subprocess.run(["sh", "./runner.sh"], cwd=os.path.dirname(runner),
                                       capture_output=True, timeout=90)
                    rec["rc"] = r.returncode
                    rec["out"] = r.stdout[-300:].decode("latin-1")
                    rec["err"] = r.stderr[-200:].decode("latin-1")
                    rec["input_len"] = os.path.getsize(os.path.join(os.path.dirname(runner),
                                                                    "input.bin")) \
                        if os.path.exists(os.path.join(os.path.dirname(runner), "input.bin")) else None
        except Exception as e:                               # noqa: BLE001
            rec["error"] = repr(e)
        _log(rec)


def _log(rec):
    with open(REPORT, "a") as f:
        f.write(json.dumps(rec) + "\n")


if __name__ == "__main__":                                    # summarise a report
    import sys
    with open(sys.argv[1] if len(sys.argv) > 1 else REPORT) as fh:
        lines = fh.readlines()
    for line in lines:
        r = json.loads(line)
        if "poc" not in r:
            print("ERR ", r.get("test"), str(r.get("error"))[:100])
            continue
        ok = r.get("rc") == 0 and "[+]" in (r.get("out") or "")
        print("OK  " if ok else "????", r.get("rc"), r.get("exploit"),
              r["test"].split("::")[-1][:60], "|",
              (r.get("out") or r.get("error") or "")[-90:].replace("\n", " "))
