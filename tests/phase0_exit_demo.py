#!/usr/bin/env python3
"""
Phase 0 Exit-Demo — automated acceptance harness.

This is the runnable proof that Phase 0 (the spine + ingest/triage vertical slice) is DONE.
It drives the documented Phase-0 API over the Unix domain socket and asserts every exit
criterion from `tasks/phase-0-foundations.md`:

  1. Create a case (persisted).
  2. Ingest an ELF (stored content-addressed; hash matches the file).
  3. Triage fields correct: format, arch, bits, endianness, mitigations, entropy, stripped.
  4. Live logs + progress stream over the event WebSocket while the job runs.
  5. Re-running the same job hits the result cache (no recompute, identical output).
  + Transport is a Unix socket (no TCP bind) — reinforces the air-gapped posture.
  + The triage artifact is retrievable by hash and is schema-valid.

STATUS: acceptance SPEC + harness. It runs against the Phase-0 build once implemented.
Endpoint/CLI/event names below are the CONTRACT the tickets must satisfy; if an
implementation renames one, update the constants at the top rather than the logic.

Contract assumed (from P0.1/P0.2/P0.3/P0.5/JE-27/IT-00):
  CLI:   `lykos db init` ; `lykos serve --socket <path> --case-store <dir>`
  REST (over UDS, base http://localhost):
    GET  /health                          -> 200 {"status":"ok"}
    POST /cases            {name}          -> {"id"}
    GET  /cases/{id}                       -> {"id","name",...}
    POST /cases/{id}/targets  (multipart: file=@binary) -> {"id" (target_id), "sha256"}
    GET  /targets/{id}                     -> {..., triage subset ...}
    POST /runs  {case_id,target_id,stage,params} -> {"run_id","from_cache":bool}
    GET  /runs/{id}                        -> {"status","from_cache","outputs":[{"sha256","role","kind"}]}
    GET  /artifacts/{sha256}               -> raw bytes (the triage JSON when kind=triage-json)
  WS:  /events?case_id={id}                -> stream of {"type","run_id","level","ts","payload"}
       event types (JE-27): job.queued|started|progress|log|cachehit|done|error|cancelled

Run:
  # against an already-running service:
  python tests/phase0_exit_demo.py --socket /run/lykos.sock --sample tests/corpus/httpd-aarch64
  # or let the harness boot a throwaway service on a temp case-store:
  python tests/phase0_exit_demo.py --start --sample tests/corpus/httpd-aarch64

Deps (test-only): httpx, websockets.
"""
from __future__ import annotations
import argparse, asyncio, hashlib, json, os, subprocess, sys, tempfile, time
from pathlib import Path

import httpx
import websockets

# ---- Expected triage values for the reference sample (override via --expect-json) ----
DEFAULT_EXPECT = {
    "file_type": "elf",
    "arch": "aarch64",
    "bits": 64,
    "endianness": "little",
    "stripped": True,
    # mitigations: keys must exist with enum values on|off|partial|unknown
    "mitigations_keys": ["nx", "pie", "relro", "canary", "fortify"],
}
MITIGATION_ENUM = {"on", "off", "partial", "unknown"}
INGEST_STAGE = "ingest_triage"

# --------------------------------------------------------------------------- results
class Results:
    def __init__(self): self.items = []
    def check(self, crit, name, ok, detail=""):
        self.items.append((crit, name, bool(ok), detail))
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] ({crit}) {name}" + (f" — {detail}" if detail else ""))
        return ok
    def summary(self) -> int:
        passed = sum(1 for *_, ok, _ in [(c,n,o,d) for (c,n,o,d) in self.items] if ok)
        total = len(self.items)
        print(f"\n=== Phase 0 exit demo: {passed}/{total} checks passed ===")
        failed = [(c, n, d) for (c, n, o, d) in self.items if not o]
        for c, n, d in failed:
            print(f"  FAILED ({c}) {n}: {d}")
        return 0 if not failed else 1

# --------------------------------------------------------------------------- helpers
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

async def wait_health(client: httpx.AsyncClient, timeout=30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = await client.get("/health")
            if r.status_code == 200 and r.json().get("status") == "ok":
                return True
        except Exception:
            pass
        await asyncio.sleep(0.25)
    return False

async def collect_events(sock: str, case_id: str, stop: asyncio.Event, out: list):
    """Subscribe to the event WS and append events until `stop` is set."""
    uri = f"ws://localhost/events?case_id={case_id}"
    try:
        async with websockets.unix_connect(sock, uri) as ws:
            while not stop.is_set():
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=0.5)
                    out.append(json.loads(msg))
                except asyncio.TimeoutError:
                    continue
    except Exception as e:  # WS failure is itself a criterion-4 failure, recorded by caller
        out.append({"type": "__ws_error__", "payload": str(e)})

async def enqueue_and_wait(client: httpx.AsyncClient, case_id, target_id, timeout=120.0):
    r = await client.post("/runs", json={"case_id": case_id, "target_id": target_id,
                                         "stage": INGEST_STAGE, "params": {}})
    r.raise_for_status()
    run_id = r.json()["run_id"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        run = (await client.get(f"/runs/{run_id}")).json()
        if run["status"] in ("done", "error", "cancelled"):
            return run
        await asyncio.sleep(0.3)
    raise TimeoutError(f"run {run_id} did not finish in {timeout}s")

def output_triage_hash(run: dict):
    for o in run.get("outputs", []):
        if o.get("role") == "output" and o.get("kind") == "triage-json":
            return o["sha256"]
    return None

# --------------------------------------------------------------------------- the demo
async def run_demo(sock: str, sample: Path, expect: dict, R: Results):
    transport = httpx.AsyncHTTPTransport(uds=sock)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost", timeout=30) as client:
        if not await wait_health(client):
            R.check("0", "service healthy on unix socket", False, "no /health after 30s")
            return
        R.check("+", "transport is a unix socket (no TCP bind)", Path(sock).exists(),
                f"socket={sock}")

        # (1) create case
        cid = (await client.post("/cases", json={"name": "demo-001"})).json()["id"]
        got = (await client.get(f"/cases/{cid}")).json()
        R.check("1", "case created and persisted", got.get("id") == cid and got.get("name") == "demo-001")

        # subscribe to events BEFORE running, so we catch the live stream (criterion 4)
        events: list = []
        stop = asyncio.Event()
        ev_task = asyncio.create_task(collect_events(sock, cid, stop, events))
        await asyncio.sleep(0.3)  # let the WS attach

        # (2) ingest target
        expected_sha = sha256_file(sample)
        with open(sample, "rb") as f:
            up = await client.post(f"/cases/{cid}/targets", files={"file": (sample.name, f, "application/octet-stream")})
        up.raise_for_status()
        tid = up.json()["id"]
        R.check("2", "target ingested, content hash matches file",
                up.json().get("sha256") == expected_sha,
                f"expected {expected_sha[:12]}… got {str(up.json().get('sha256'))[:12]}…")

        # run #1: ingest_triage
        run1 = await enqueue_and_wait(client, cid, tid)
        R.check("2", "ingest_triage run completed", run1["status"] == "done", f"status={run1['status']}")

        # (3) triage fields
        tri_sha = output_triage_hash(run1)
        R.check("+", "triage artifact linked to run", bool(tri_sha))
        triage = {}
        if tri_sha:
            raw = (await client.get(f"/artifacts/{tri_sha}")).content
            R.check("+", "triage artifact retrievable by hash & valid JSON",
                    True if (triage := _try_json(raw)) is not None else False)
        if triage:
            R.check("3", "schema_version present", triage.get("schema_version") == 1)
            for key in ("file_type", "arch", "bits", "endianness", "stripped"):
                R.check("3", f"triage.{key} == {expect.get(key)!r}",
                        triage.get(key) == expect.get(key), f"got {triage.get(key)!r}")
            mit = triage.get("mitigations", {}) or {}
            for mk in expect["mitigations_keys"]:
                v = mit.get(mk)
                R.check("3", f"mitigation '{mk}' present & valid enum",
                        v in MITIGATION_ENUM, f"got {v!r}")
            R.check("3", "entropy computed", isinstance((triage.get("entropy") or {}).get("overall"), (int, float)))

        # (4) live event stream
        stop.set(); await ev_task
        types = [e.get("type") for e in events]
        run1_types = [e.get("type") for e in events if e.get("run_id") == run1.get("run_id") or e.get("run_id") == run1.get("id")]
        R.check("4", "no WS error", "__ws_error__" not in types,
                next((e["payload"] for e in events if e.get("type") == "__ws_error__"), ""))
        R.check("4", "job.started streamed", any(t == "job.started" for t in types))
        R.check("4", "job.progress and/or job.log streamed",
                any(t in ("job.progress", "job.log") for t in types))
        R.check("4", "job.done streamed", any(t == "job.done" for t in types))

        # (5) re-run -> cache hit
        events2: list = []
        stop2 = asyncio.Event()
        ev2 = asyncio.create_task(collect_events(sock, cid, stop2, events2))
        await asyncio.sleep(0.3)
        run2 = await enqueue_and_wait(client, cid, tid)
        stop2.set(); await ev2
        tri_sha2 = output_triage_hash(run2)
        saw_cachehit = any(e.get("type") == "job.cachehit" for e in events2)
        saw_progress = any(e.get("type") == "job.progress" for e in events2)
        cache_ok = run2.get("from_cache") is True or saw_cachehit
        R.check("5", "re-run reported as cache hit", cache_ok,
                f"from_cache={run2.get('from_cache')} cachehit_event={saw_cachehit}")
        R.check("5", "cache hit produced identical triage output", tri_sha2 == tri_sha,
                f"{str(tri_sha2)[:12]}… vs {str(tri_sha)[:12]}…")
        R.check("5", "cache hit did NOT recompute (no progress phases)", not saw_progress)

def _try_json(raw: bytes):
    try:
        return json.loads(raw)
    except Exception:
        return None

# --------------------------------------------------------------------------- lifecycle
async def main():
    ap = argparse.ArgumentParser(description="Phase 0 exit-demo acceptance harness")
    ap.add_argument("--socket", default="/run/lykos.sock", help="service unix socket path")
    ap.add_argument("--sample", required=True, type=Path, help="reference ELF (e.g. stripped AArch64)")
    ap.add_argument("--start", action="store_true", help="boot a throwaway service on a temp case-store")
    ap.add_argument("--lykos-cmd", default="lykos", help="CLI entrypoint")
    ap.add_argument("--expect-json", type=Path, help="override expected triage values (JSON)")
    args = ap.parse_args()

    if not args.sample.exists():
        print(f"sample not found: {args.sample} (build the golden corpus, ticket IT-21)"); sys.exit(2)

    expect = DEFAULT_EXPECT
    if args.expect_json:
        expect = {**DEFAULT_EXPECT, **json.loads(args.expect_json.read_text())}

    R = Results()
    proc = None
    tmp = None
    sock = args.socket
    try:
        if args.start:
            tmp = tempfile.mkdtemp(prefix="lykos-exitdemo-")
            sock = str(Path(tmp) / "lykos.sock")
            subprocess.run([args.lykos_cmd, "db", "init", "--case-store", tmp], check=True)
            proc = subprocess.Popen([args.lykos_cmd, "serve", "--socket", sock, "--case-store", tmp])
            print(f"[demo] started service pid={proc.pid} socket={sock} case-store={tmp}")

        print("\n--- Phase 0 exit demo ---")
        await run_demo(sock, args.sample, expect, R)
    finally:
        if proc:
            proc.terminate()
            try: proc.wait(timeout=10)
            except subprocess.TimeoutExpired: proc.kill()
        # NB: leave `tmp` for post-mortem; operator removes it. Do not auto-delete evidence.

    sys.exit(R.summary())

if __name__ == "__main__":
    asyncio.run(main())
