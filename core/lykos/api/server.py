"""P0.2 / P0.6 — local HTTP API + event WebSocket over a Unix domain socket.

Threaded server; each request opens its OWN sqlite connection (sqlite conns are not shared
across threads). The event WebSocket tails the persisted `event` table by cursor.
"""
from __future__ import annotations

import base64
import json
import os
import re
import select
import signal
import socket
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from ..casestore import CaseStore
from ..db.connection import connect
from ..db.dao import CallEdgeDAO, DynResultDAO, EventDAO, FindingDAO, FunctionDAO, PocDAO, StringDAO
from ..jobs import JobConfig, JobQueue, WorkerPool
from . import ws
from .multipart import extract_file

_INGEST = "ingest_triage"


# --------------------------------------------------------------------------- server
class UnixHTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_UNIX
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, socket_path: str, handler, *, case_dir: Path):
        self.case_dir = Path(case_dir)
        self.content = CaseStore.open(case_dir).content  # ensures schema + content dir
        self._socket_path = socket_path
        if os.path.exists(socket_path):
            os.unlink(socket_path)
        super().__init__(socket_path, handler)

    def server_bind(self):  # AF_UNIX: skip the INET hostname logic in HTTPServer
        socket.socket.bind(self.socket, self.server_address)
        self.server_name = "localhost"
        self.server_port = 0

    def server_close(self):
        super().server_close()
        try:
            os.unlink(self._socket_path)
        except OSError:
            pass


class TcpHTTPServer(ThreadingHTTPServer):
    """Loopback TCP bind for the browser UI (loopback is not egress)."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, *, case_dir: Path):
        self.case_dir = Path(case_dir)
        self.content = CaseStore.open(case_dir).content
        super().__init__(address, handler)


# --------------------------------------------------------------------------- handler
_RUN_ID = re.compile(r"^/runs/([^/]+)$")
_CASE_ID = re.compile(r"^/cases/([^/]+)$")
_TARGET_ID = re.compile(r"^/targets/([^/]+)$")
_ARTIFACT = re.compile(r"^/artifacts/([0-9a-fA-F]+)$")
_CASE_EVENTS = re.compile(r"^/cases/([^/]+)/events$")
_CASE_TARGETS = re.compile(r"^/cases/([^/]+)/targets$")
_CASE_RUNS = re.compile(r"^/cases/([^/]+)/runs$")
_TARGET_FUNCS = re.compile(r"^/targets/([^/]+)/functions$")
_FUNC_ID = re.compile(r"^/functions/([^/]+)$")
_TARGET_CG = re.compile(r"^/targets/([^/]+)/callgraph$")
_TARGET_STR = re.compile(r"^/targets/([^/]+)/strings$")
_TARGET_FIND = re.compile(r"^/targets/([^/]+)/findings$")
_CASE_FIND = re.compile(r"^/cases/([^/]+)/findings$")
_FIND_ID = re.compile(r"^/findings/([^/]+)$")
_TARGET_DYN = re.compile(r"^/targets/([^/]+)/dynresults$")
_TARGET_POC = re.compile(r"^/targets/([^/]+)/pocs$")
_TARGET_ADVICE = re.compile(r"^/targets/([^/]+)/advice$")
_CASE_REPORT = re.compile(r"^/cases/([^/]+)/report$")
_CASE_EXPORT = re.compile(r"^/cases/([^/]+)/export$")
_CASE_SYSMAP = re.compile(r"^/cases/([^/]+)/systemmap$")


def _read_ui() -> bytes:
    """Load the UI page — works from a filesystem checkout AND from a zipapp (.pyz)."""
    try:
        from importlib import resources
        return (resources.files("lykos.api") / "static" / "index.html").read_bytes()
    except Exception:
        return (Path(__file__).parent / "static" / "index.html").read_bytes()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # silence + AF_UNIX-safe logging
    def log_message(self, *a):  # noqa: D401
        pass

    def address_string(self):
        return "unix"

    @property
    def db_path(self) -> Path:
        return self.server.case_dir / "case.db"

    # ---- helpers ----
    def _json(self, obj: Any, status: int = 200) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _bytes(self, data: bytes, content_type: str, *, status: int = 200,
               filename: Optional[str] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n) if n else b""

    def _store(self) -> CaseStore:
        return CaseStore(self.server.case_dir)

    def _static(self) -> None:
        try:
            body = _read_ui()
        except Exception:
            return self._json({"error": "ui not found"}, 404)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---- GET ----
    def do_GET(self):
        parsed = urlparse(self.path)
        path, qs = parsed.path, parse_qs(parsed.query)
        # WebSocket upgrade for /events
        if path == "/events" and "websocket" in self.headers.get("Upgrade", "").lower():
            return self._ws_events(qs.get("case_id", [None])[0])
        # WebSocket upgrade for the interactive detonation console
        if path == "/console" and "websocket" in self.headers.get("Upgrade", "").lower():
            return self._ws_console(qs)
        try:
            if path in ("/", "/index.html"):
                return self._static()
            if path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return
            if path == "/health":
                return self._json({"status": "ok"})
            if path == "/cases":
                s = self._store()
                try:
                    return self._json([_case(c) for c in s.cases.list()])
                finally:
                    s.close()
            m = _CASE_TARGETS.match(path)
            if m:
                s = self._store()
                try:
                    return self._json([_target(t) for t in s.targets.list_by_case(m.group(1))])
                finally:
                    s.close()
            m = _CASE_RUNS.match(path)
            if m:
                s = self._store()
                try:
                    return self._json([_run(r) for r in s.runs.list_by_case(m.group(1))])
                finally:
                    s.close()
            m = _TARGET_FUNCS.match(path)
            if m:
                s = self._store()
                try:
                    fns = FunctionDAO(s.conn).list_by_target(m.group(1))
                    return self._json([_function(f) for f in fns])
                finally:
                    s.close()
            m = _TARGET_CG.match(path)
            if m:
                s = self._store()
                try:
                    edges = CallEdgeDAO(s.conn).list_by_target(m.group(1))
                    return self._json([_call_edge(e) for e in edges])
                finally:
                    s.close()
            m = _TARGET_STR.match(path)
            if m:
                s = self._store()
                try:
                    strs = StringDAO(s.conn).list_by_target(m.group(1))
                    return self._json([_stringref(x) for x in strs])
                finally:
                    s.close()
            m = _TARGET_FIND.match(path)
            if m:
                s = self._store()
                try:
                    fd = FindingDAO(s.conn)
                    fs = fd.list_by_target(m.group(1))
                    counts = fd.site_counts(m.group(1))
                    return self._json([_finding(x, site_count=counts.get(x.id, 0))
                                       for x in fs])
                finally:
                    s.close()
            m = _CASE_FIND.match(path)
            if m:
                return self._get_case_findings(m.group(1))
            m = _CASE_REPORT.match(path)
            if m:
                return self._get_report(m.group(1), qs)
            m = _CASE_EXPORT.match(path)
            if m:
                return self._get_case_export(m.group(1))
            m = _CASE_SYSMAP.match(path)
            if m:
                return self._get_systemmap(m.group(1))
            m = _FIND_ID.match(path)
            if m:
                s = self._store()
                try:
                    fd = FindingDAO(s.conn)
                    f = fd.get(m.group(1))
                    if not f:
                        return self._json({"error": "no finding"}, 404)
                    return self._json(_finding(f, sites=fd.sites(f.id)))
                finally:
                    s.close()
            m = _TARGET_DYN.match(path)
            if m:
                s = self._store()
                try:
                    return self._json([_dynresult(x)
                                       for x in DynResultDAO(s.conn).list_by_target(m.group(1))])
                finally:
                    s.close()
            m = _TARGET_ADVICE.match(path)
            if m:
                return self._get_advice(m.group(1))
            m = _TARGET_POC.match(path)
            if m:
                s = self._store()
                try:
                    return self._json([_poc(x) for x in PocDAO(s.conn).list_by_target(m.group(1))])
                finally:
                    s.close()
            m = _FUNC_ID.match(path)
            if m:
                s = self._store()
                try:
                    fn = FunctionDAO(s.conn).get(m.group(1))
                    if not fn:
                        return self._json({"error": "no function"}, 404)
                    d = _function(fn, code=True)
                    ce = CallEdgeDAO(s.conn)
                    d["callees"] = [_call_edge(e) for e in ce.callees_of(fn.target_id, fn.addr)]
                    d["callers"] = [_call_edge(e) for e in ce.callers_of(fn.target_id, fn.addr)]
                    return self._json(d)
                finally:
                    s.close()
            m = _CASE_ID.match(path)
            if m:
                return self._get_case(m.group(1))
            m = _TARGET_ID.match(path)
            if m:
                return self._get_target(m.group(1))
            m = _RUN_ID.match(path)
            if m:
                return self._get_run(m.group(1))
            m = _ARTIFACT.match(path)
            if m:
                return self._get_artifact(m.group(1))
            m = _CASE_EVENTS.match(path)
            if m:
                after = int(qs.get("after", ["0"])[0])
                return self._get_events(m.group(1), after)
            self._json({"error": "not found"}, 404)
        except Exception as e:  # never crash the server thread
            self._json({"error": repr(e)}, 500)

    # ---- POST ----
    def do_POST(self):
        path = urlparse(self.path).path
        try:
            if path == "/cases":
                return self._create_case()
            m = _CASE_TARGETS.match(path)
            if m:
                return self._upload_target(m.group(1))
            if path == "/runs":
                return self._create_run()
            if path == "/format/analyze":
                return self._format_analyze()
            if path == "/import":
                return self._import_case()
            self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"error": repr(e)}, 500)

    # ---- DELETE ----
    def do_DELETE(self):
        path = urlparse(self.path).path
        try:
            m = _TARGET_ID.match(path)
            if m:
                return self._delete_target(m.group(1))
            self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"error": repr(e)}, 500)

    def _delete_target(self, tid):
        """Remove a target and everything derived from it (rows cascade; component edges
        touching it are removed too, so the System Map stays consistent)."""
        s = self._store()
        try:
            t = s.targets.get(tid)
            if not t:
                return self._json({"error": "no target"}, 404)
            case_id, name = t.case_id, t.filename
            ok = s.targets.delete(tid)
            s.events.append("target.removed", case_id=case_id,
                            payload={"target_id": tid, "filename": name})
            return self._json({"deleted": ok, "id": tid})
        finally:
            s.close()

    # ---- route impls ----
    def _get_advice(self, tid):
        """What to do next with this target, and why.

        This lived in the GUI, so anything driving the API had to guess -- and guessing wrong
        is expensive: a scripted run picked black-box fuzzing and burned 98,500 executions on
        a parser for nothing while the GUI was recommending a seed and a structure model.
        """
        from ..analyze import advise as advise_mod
        s = self._store()
        try:
            t = s.targets.get(tid)
            if not t:
                return self._json({"error": "no target"}, 404)
            fd = FindingDAO(s.conn)
            findings = fd.list_by_target(tid)
            imports = []
            run = next((r for r in s.runs.list_by_case(t.case_id)
                        if r.target_id == tid and r.stage == _INGEST
                        and r.status == "done"), None)
            if run:
                from ..jobs.registry import cached_output_json
                rec = cached_output_json(s, run.id) or {}
                # triage stores imports as {"libraries": [...], "symbols": [...]}
                imp = rec.get("imports") or {}
                imports = list(imp.get("symbols") or []) if isinstance(imp, dict) else list(imp)
            crashes = sum(1 for d in DynResultDAO(s.conn).list_by_target(tid) if d.crashed)
            pocs = [p for p in PocDAO(s.conn).list_by_target(tid) if p.verified]
            out = advise_mod.advise(
                imports=[str(x) for x in imports],
                functions=len(FunctionDAO(s.conn).list_by_target(tid)),
                findings=len(findings),
                seeds=sum(1 for a in s.artifacts.list_by_case(t.case_id)
                          if a.kind in ("seed", "console-seed", "afl-crash")),
                has_format=False,
                afl_usable=advise_mod.afl_usable(),
                crashes=crashes, pocs=len(pocs))
            return self._json(out)
        finally:
            s.close()

    def _get_case_findings(self, cid):
        """All findings in a case, enriched with target filename/arch and the target's best
        PoC level -- the data the case findings board aggregates."""
        s = self._store()
        try:
            tmap = {t.id: t for t in s.targets.list_by_case(cid)}
            best_poc = {}
            for t in tmap.values():
                lvls = [p.level for p in PocDAO(s.conn).list_by_target(t.id)
                        if p.verified and p.level]
                if lvls:
                    best_poc[t.id] = max(lvls)          # "L2" > "L1" lexicographically
            out = []
            fd = FindingDAO(s.conn)
            counts = {}
            for tid in tmap:
                counts.update(fd.site_counts(tid))
            for f in fd.list_by_case(cid):
                d = _finding(f, site_count=counts.get(f.id, 0))
                t = tmap.get(f.target_id)
                d["target_name"] = t.filename if t else None
                d["target_arch"] = t.arch if t else None
                d["poc_level"] = best_poc.get(f.target_id)
                out.append(d)
            return self._json(out)
        finally:
            s.close()

    def _get_report(self, cid, qs):
        """Generate a report for a case in the requested format (html|pdf|sarif|json).

        Query params: format, min_severity, min_state, states=csv, finding_ids=csv,
        embed=0|1 (embed PoC bundles into html/json; default on).
        """
        from ..report import (
            DEFAULT_MIN_STATE,
            build_report,
            to_html,
            to_pdf,
            to_sarif,
        )
        from ..report.casejson import to_case_json_bytes
        fmt = qs.get("format", ["html"])[0]
        embed = qs.get("embed", ["1"])[0] != "0" and fmt in ("html", "json")
        states = _csv(qs.get("states"))
        finding_ids = _csv(qs.get("finding_ids"))
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            report = build_report(
                s, cid,
                min_severity=qs.get("min_severity", [None])[0],
                min_state=qs.get("min_state", [DEFAULT_MIN_STATE])[0],
                states=states, finding_ids=finding_ids, embed_pocs=embed,
            )
        finally:
            s.close()
        name = (report["case"].get("name") or "case").replace(" ", "_")[:40]
        if fmt == "pdf":
            return self._bytes(to_pdf(report), "application/pdf",
                               filename=f"{name}.pdf")
        if fmt == "sarif":
            body = json.dumps(to_sarif(report), indent=2).encode("utf-8")
            return self._bytes(body, "application/json", filename=f"{name}.sarif")
        if fmt == "json":
            return self._bytes(to_case_json_bytes(report), "application/json",
                               filename=f"{name}.json")
        return self._bytes(to_html(report).encode("utf-8"), "text/html; charset=utf-8")

    def _get_case_export(self, cid):
        """Stream a portable single-case archive (rows + artifact blobs) as .tar.gz."""
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            name = (s.cases.get(cid).name or "case").replace(" ", "_")[:40]
            with tempfile.TemporaryDirectory(prefix="lykos-export-") as td:
                tmp = Path(td) / f"{name}.tar.gz"
                s.export_case(cid, tmp)
                data = tmp.read_bytes()
        finally:
            s.close()
        return self._bytes(data, "application/gzip", filename=f"{name}.tar.gz")

    def _get_systemmap(self, cid):
        """The component graph (doc 17.1): nodes are targets, edges are resolved
        cross-binary relationships. `?resolve=1` recomputes links before returning."""
        from ..analyze.link.resolve import edge_symbols, resolve_case
        from ..db.dao import ComponentEdgeDAO, FindingDAO
        parsed = urlparse(self.path)
        do_resolve = parse_qs(parsed.query).get("resolve", ["0"])[0] == "1"
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            if do_resolve:
                resolve_case(s.conn, s.content, cid, persist=True)
            fdao = FindingDAO(s.conn)
            nodes = []
            for t in s.targets.list_by_case(cid):
                nodes.append({**_target(t),
                              "findings": fdao.count_by_target(t.id)})
            edges = []
            for e in ComponentEdgeDAO(s.conn).list_by_case(cid):
                edges.append({"src": e.src_target, "dst": e.dst_target, "kind": e.kind,
                              "symbol": e.symbol or None,
                              "detail": e.detail if e.kind in ("ipc", "taint") else None,
                              "symbols": edge_symbols(e.detail)})
            return self._json({"nodes": nodes, "edges": edges})
        finally:
            s.close()

    def _import_case(self):
        """Merge an uploaded case archive (per-case or whole-store .tar.gz) into the store."""
        ctype = self.headers.get("Content-Type", "")
        body = self._read_body()
        _, data = extract_file(ctype, body)
        if data is None:
            data = body
        with tempfile.TemporaryDirectory(prefix="lykos-import-") as td:
            tmp = Path(td) / "import.tar.gz"
            tmp.write_bytes(data)
            s = self._store()
            try:
                ids = s.import_archive(tmp)
                return self._json({"cases": ids}, 201)
            finally:
                s.close()

    def _get_case(self, cid):
        s = self._store()
        try:
            c = s.cases.get(cid)
            return self._json(_case(c)) if c else self._json({"error": "no case"}, 404)
        finally:
            s.close()

    def _get_target(self, tid):
        s = self._store()
        try:
            t = s.targets.get(tid)
            return self._json(_target(t)) if t else self._json({"error": "no target"}, 404)
        finally:
            s.close()

    def _get_run(self, rid):
        s = self._store()
        try:
            r = s.runs.get(rid)
            if not r:
                return self._json({"error": "no run"}, 404)
            outputs = []
            for link in s.run_artifacts.list_by_run(rid):
                art = s.artifacts.get(link.artifact_sha256)
                outputs.append({"sha256": link.artifact_sha256, "role": link.role,
                                "kind": art.kind if art else None})
            cachehit = any(e.type == "job.cachehit"
                           for e in s.events.list(run_id=rid, limit=1000))
            return self._json({**_run(r), "outputs": outputs, "from_cache": cachehit})
        finally:
            s.close()

    def _get_artifact(self, sha):
        try:
            data = self.server.content.get_bytes(sha)
        except Exception:
            return self._json({"error": "no artifact"}, 404)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _get_events(self, cid, after):
        s = self._store()
        try:
            evs = s.events.list(case_id=cid, after_id=after, limit=500)
            return self._json([_event(e) for e in evs])
        finally:
            s.close()

    def _create_case(self):
        body = json.loads(self._read_body() or b"{}")
        s = self._store()
        try:
            c = s.cases.create(body.get("name", "case"), notes=body.get("notes"),
                               engagement_ref=body.get("engagement_ref"))
            return self._json(_case(c), 201)
        finally:
            s.close()

    def _upload_target(self, cid):
        from ..analyze import ingest
        from ..analyze.ingest import enqueue_triage
        from ..jobs.registry import reproject_cache_hit
        ctype = self.headers.get("Content-Type", "")
        body = self._read_body()
        filename, data = extract_file(ctype, body)
        if data is None:  # allow raw octet-stream fallback
            filename = self.headers.get("X-Filename", "upload.bin")
            data = body
        s = self._store()
        try:
            # TemporaryDirectory, not mkdtemp: the old code unlinked the FILE and left the
            # directory behind, leaking one empty directory per upload for the life of the
            # process. It is also removed on the error paths, which an explicit unlink was not.
            with tempfile.TemporaryDirectory(prefix="lykos-upload-") as td:
                tmp = Path(td) / (filename or "upload.bin")
                tmp.write_bytes(data)
                target = ingest(s, cid, tmp, filename=filename)
            run = enqueue_triage(JobQueue(s.conn), target)
            if run.status == "done":   # cache hit: body skipped, re-project its per-target rows
                reproject_cache_hit(s, run.stage, target.id, run.id)
            return self._json({"id": target.id, "sha256": target.sha256,
                               "run_id": run.id}, 201)
        finally:
            s.close()

    def _format_analyze(self):
        """Custom-format builder support: with just a sample, suggest a starting spec
        (detect magic, auto-find the length field); with a spec, show how it carves the
        sample using the real fuzzer parser. No case/target needed."""
        from ..analyze.fuzz import structure
        body = json.loads(self._read_body() or b"{}")
        sample = base64.b64decode(body["sample_b64"]) if body.get("sample_b64") else b""
        sample = sample[:65536]                          # cap: previews stay fast
        spec = body.get("spec")
        if spec is not None:
            return self._json({"preview": structure.describe(spec, sample)})
        return self._json({"suggestion": structure.suggest_spec(sample)})

    # Stage dispatch. Each entry is (module, enqueue-function name). The bodies were a
    # ~90-line elif chain over 25 names, which had to be edited in two places to add a stage
    # and silently accepted any unknown name through its final else. Imports stay lazy (they
    # pull in heavy optional backends), so the value is the module path, not the function.
    _CASE_STAGES = {
        "link_case": ("..analyze.link", "enqueue_link"),
        "ipc_model": ("..analyze.link", "enqueue_ipc"),
        "whole_system": ("..analyze.link", "enqueue_whole_system"),
        "cross_taint": ("..analyze.link", "enqueue_cross_taint"),
    }
    _TARGET_STAGES = {
        _INGEST: ("..analyze.ingest", "enqueue_triage"),
        "disassemble": ("..analyze.disassemble", "enqueue_disassemble"),
        "detect_cwe": ("..analyze.detect", "enqueue_detect"),
        "dynamic_run": ("..analyze.dynamic", "enqueue_dynamic"),
        "fuzz": ("..analyze.fuzz", "enqueue_fuzz"),
        "coverage_fuzz": ("..analyze.fuzz", "enqueue_coverage_fuzz"),
        "directed_fuzz": ("..analyze.fuzz", "enqueue_directed_fuzz"),
        "concolic": ("..analyze.symbolic", "enqueue_concolic"),
        "build_poc": ("..analyze.poc", "enqueue_build_poc"),
        "poc_primitive": ("..analyze.poc", "enqueue_primitive"),
        "build_exploit": ("..analyze.poc", "enqueue_exploit"),
        "synthesize_poc": ("..analyze.poc", "enqueue_synthesize"),
        "synthesize_injection": ("..analyze.poc", "enqueue_inject"),
        "synthesize_secret": ("..analyze.poc", "enqueue_secret"),
        "boundary_fuzz": ("..analyze.link", "enqueue_boundary"),
        "heap_check": ("..analyze.dynamic", "enqueue_heap_check"),
        "root_cause": ("..analyze.debug", "enqueue_root_cause"),
        "multi_debug": ("..analyze.debug", "enqueue_multi_debug"),
        "debug_monitor": ("..analyze.debug", "enqueue_monitor"),
        "extract_secrets": ("..analyze.debug", "enqueue_extract"),
        "behavior_trace": ("..analyze.debug", "enqueue_behavior_trace"),
        "dynamic_taint": ("..analyze.debug", "enqueue_taint"),
        "cve_scan": ("..analyze.fingerprint", "enqueue_cve_scan"),
        "firmware_carve": ("..analyze.firmware", "enqueue_firmware"),
        "firmware_rehost": ("..analyze.firmware", "enqueue_rehost"),
    }

    @staticmethod
    def _enqueue_fn(entry):
        from importlib import import_module
        mod, fn = entry
        return getattr(import_module(mod, __package__), fn)

    def _create_run(self):
        from ..jobs.registry import reproject_cache_hit
        body = json.loads(self._read_body() or b"{}")
        s = self._store()
        try:
            q = JobQueue(s.conn)
            stage = body.get("stage", _INGEST)
            target_id = body.get("target_id")
            params = body.get("params")

            if stage in self._CASE_STAGES:            # case-scoped: no target needed
                cid = body.get("case_id") or (
                    s.targets.get(target_id).case_id if target_id else None)
                fn = self._enqueue_fn(self._CASE_STAGES[stage])
                run = fn(q, cid) if stage in ("link_case", "ipc_model", "cross_taint") \
                    else fn(q, cid, params=params)
                return self._json({"run_id": run.id, "from_cache": run.status == "done"}, 201)

            if stage in self._TARGET_STAGES and target_id:
                target = s.targets.get(target_id)
                if not target:
                    return self._json({"error": "no target"}, 404)
                fn = self._enqueue_fn(self._TARGET_STAGES[stage])
                run = fn(q, target) if stage in (_INGEST, "disassemble", "detect_cwe") \
                    else fn(q, target, params=params)
            elif stage in self._TARGET_STAGES:
                return self._json({"error": f"stage {stage!r} requires a target_id"}, 400)
            else:
                # An unregistered name used to fall through to a bare enqueue, creating a run
                # no worker can ever execute; it now fails at the edge with the valid names.
                known = sorted(set(self._CASE_STAGES) | set(self._TARGET_STAGES))
                return self._json({"error": f"unknown stage {stage!r}", "stages": known}, 400)

            if run.status == "done" and target_id:   # cache hit: re-project its per-target rows
                reproject_cache_hit(s, stage, target_id, run.id)
            return self._json({"run_id": run.id, "from_cache": run.status == "done"}, 201)
        finally:
            s.close()

    # ---- WebSocket event stream ----
    def _ws_console(self, qs):
        """Interactive detonation console: spawn the target under a PTY in the sandbox and proxy
        it live over the WebSocket (send/receive), with a save-as-seed hook."""
        import shutil
        import tempfile

        from . import console
        key = self.headers.get("Sec-WebSocket-Key")
        target_id = qs.get("target_id", [None])[0]
        if not key or not target_id:
            return self._json({"error": "console needs target_id + WebSocket"}, 400)
        s = self._store()
        try:
            target = s.targets.get(target_id)
            if not target:
                return self._json({"error": "no target"}, 404)
            case_id = target.case_id
            blob = s.content.path(target.sha256).read_bytes()
            arch, endianness, bits = target.arch, target.endianness, target.bits
        finally:
            s.close()

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", ws.accept_key(key))
        self.end_headers()

        workdir = Path(tempfile.mkdtemp(prefix="lykos-console-"))
        exe = workdir / "target.bin"
        exe.write_bytes(blob)
        os.chmod(exe, 0o755)
        argv = _csv(qs.get("argv")) or []

        def put_seed(data: bytes) -> str:
            st = CaseStore(self.server.case_dir)
            try:
                return st.put_artifact(case_id, "console-seed", data=data).sha256
            finally:
                st.close()

        try:
            console.serve(self.connection, exe, argv=argv, arch=arch, endianness=endianness,
                          bits=bits, cwd=str(workdir), put_seed=put_seed)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def _ws_events(self, case_id: Optional[str]):
        key = self.headers.get("Sec-WebSocket-Key")
        if not key:
            return self._json({"error": "missing Sec-WebSocket-Key"}, 400)
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", ws.accept_key(key))
        self.end_headers()

        conn = connect(self.db_path)
        ed = EventDAO(conn)
        sock = self.connection
        # start after the current tail so the client sees live events
        row = conn.execute(
            "SELECT MAX(id) AS m FROM event WHERE case_id IS ? OR ? IS NULL",
            (case_id, case_id)).fetchone()
        cursor = int(row["m"]) if row and row["m"] is not None else 0
        stop: threading.Event = self.server.stop_event
        try:
            while not stop.is_set():
                evs = ed.list(case_id=case_id, after_id=cursor, limit=200) if case_id \
                    else ed.list(after_id=cursor, limit=200)
                for e in evs:
                    sock.sendall(ws.text_frame(json.dumps(_event(e))))
                    cursor = e.id
                # client-close detection
                r, _, _ = select.select([sock], [], [], 0.15)
                if r and not sock.recv(4096):
                    break
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            try:
                sock.sendall(ws.close_frame())
            except OSError:
                pass
            conn.close()


# --------------------------------------------------------------------------- serializers
def _csv(vals):
    """Parse a repeated/CSV query param into a list, or None if absent."""
    if not vals:
        return None
    out = []
    for v in vals:
        out += [x for x in v.split(",") if x]
    return out or None


def _case(c):
    return {"id": c.id, "name": c.name, "notes": c.notes,
            "engagement_ref": c.engagement_ref, "created_at": c.created_at}


def _target(t):
    return {"id": t.id, "case_id": t.case_id, "filename": t.filename, "sha256": t.sha256,
            "md5": t.md5, "sha1": t.sha1, "size": t.size, "file_type": t.file_type,
            "arch": t.arch, "bits": t.bits, "endianness": t.endianness,
            "linking": t.linking, "stripped": t.stripped, "mitigations": t.mitigations,
            "entropy": t.entropy}


def _poc(x):
    return {"id": x.id, "level": x.level, "verified": x.verified, "signal": x.signal_name,
            "input_sha": x.input_sha, "bundle_sha": x.bundle_sha, "created_at": x.created_at}


def _dynresult(d):
    return {"id": d.id, "crashed": d.crashed, "timed_out": d.timed_out,
            "signal": d.signal_name, "exit_code": d.exit_code, "isolation": d.isolation,
            "input_mode": d.input_mode, "input_sha": d.input_sha,
            "duration_ms": d.duration_ms, "note": d.note, "created_at": d.created_at}


def _finding(f, sites=None, site_count=None):
    """Serialize a finding. `sites` is the list of places the defect occurs; `site_count` is
    the cheap aggregate for list views. A finding is a DEFECT -- the sites are evidence."""
    d = {"id": f.id, "target_id": f.target_id, "case_id": f.case_id, "cwe": f.cwe,
         "title": f.title, "severity": f.severity, "state": f.state,
         "confidence": f.confidence, "function_addr": f.function_addr,
         "site_addr": f.site_addr, "detector": f.detector, "evidence": f.evidence}
    if sites is not None:
        d["sites"] = sites
    d["site_count"] = len(sites) if sites is not None else (site_count or 0)
    return d


def _call_edge(e):
    return {"src_addr": e.src_addr, "site_addr": e.site_addr, "dst_addr": e.dst_addr,
            "dst_name": e.dst_name, "external": e.external}


def _stringref(x):
    return {"addr": x.addr, "value": x.value, "xrefs": x.xrefs}


def _function(f, code=False):
    d = {"id": f.id, "target_id": f.target_id, "addr": f.addr, "name": f.name,
         "size": f.size, "blocks": f.blocks, "edges": f.edges,
         "signature": getattr(f, "signature", None)}
    if code:
        d["decompiled"] = f.decompiled
        d["frame"] = getattr(f, "frame", None)   # params + stack-var layout (offsets/sizes/buffers)
        d["ir"] = f.ir          # {blocks:[{addr,instructions:[{addr,text,pcode:[...]}],succ}]}
    return d


def _run(r):
    return {"id": r.id, "case_id": r.case_id, "target_id": r.target_id, "stage": r.stage,
            "status": r.status, "error": r.error, "attempts": r.attempts,
            "cache_key": r.cache_key, "created_at": r.created_at,
            "started_at": r.started_at, "ended_at": r.ended_at}


def _event(e):
    return {"id": e.id, "type": e.type, "level": e.level, "case_id": e.case_id,
            "run_id": e.run_id, "ts": e.ts, "payload": e.payload}


# --------------------------------------------------------------------------- serve()
def serve(case_dir: str | Path, socket_path: Optional[str] = None, *,
          http: Optional[tuple[str, int]] = None, workers: Optional[int] = None,
          block: bool = True):
    """Start the worker pool + HTTP server(s).

    Bind a unix socket (`socket_path`), a loopback TCP address (`http=(host,port)`), or both.
    Returns (servers, pool) when block=False.
    """
    import lykos.analyze  # noqa: F401  registers the ingest_triage stage

    if not socket_path and not http:
        raise ValueError("serve() needs socket_path and/or http")
    store = CaseStore.open(case_dir)
    cfg = JobConfig() if workers is None else JobConfig(workers=workers)
    pool = WorkerPool(store.db_path, store.content, cfg)
    pool.start()

    stop = threading.Event()
    servers: list = []
    if socket_path:
        u = UnixHTTPServer(str(socket_path), Handler, case_dir=store.dir)
        u.stop_event = stop
        servers.append(u)
    if http:
        t = TcpHTTPServer(http, Handler, case_dir=store.dir)
        t.stop_event = stop
        servers.append(t)
    for s in servers:
        threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.2},
                         daemon=True).start()

    if not block:
        return servers, pool

    def _sig(*_a):
        stop.set()

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)
    where = ", ".join([str(socket_path)] if socket_path else []
                      + ([f"http://{http[0]}:{http[1]}"] if http else []))
    print(f"lykos serving on {where} (case-store {store.dir}); Ctrl-C to stop")
    try:
        while not stop.wait(0.5):
            pass
    finally:
        shutdown(servers, pool)


def shutdown(servers, pool):
    servers = servers if isinstance(servers, list) else [servers]
    for s in servers:
        try:
            s.stop_event.set()
        except Exception:
            pass
        s.shutdown()
        s.server_close()
    pool.stop()
