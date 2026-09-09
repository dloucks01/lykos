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
                    fs = FindingDAO(s.conn).list_by_target(m.group(1))
                    return self._json([_finding(x) for x in fs])
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
                    f = FindingDAO(s.conn).get(m.group(1))
                    if not f:
                        return self._json({"error": "no finding"}, 404)
                    return self._json(_finding(f))
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
            for f in FindingDAO(s.conn).list_by_case(cid):
                d = _finding(f)
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
            tmp = Path(tempfile.mkdtemp()) / f"{name}.tar.gz"
            s.export_case(cid, tmp)
            data = tmp.read_bytes()
        finally:
            s.close()
        try:
            os.unlink(tmp)
        except OSError:
            pass
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
        tmp = Path(tempfile.mkdtemp()) / "import.tar.gz"
        tmp.write_bytes(data)
        s = self._store()
        try:
            ids = s.import_archive(tmp)
            return self._json({"cases": ids}, 201)
        finally:
            s.close()
            try:
                os.unlink(tmp)
            except OSError:
                pass

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
        ctype = self.headers.get("Content-Type", "")
        body = self._read_body()
        filename, data = extract_file(ctype, body)
        if data is None:  # allow raw octet-stream fallback
            filename = self.headers.get("X-Filename", "upload.bin")
            data = body
        s = self._store()
        try:
            tmp = Path(tempfile.mkdtemp()) / (filename or "upload.bin")
            tmp.write_bytes(data)
            target = ingest(s, cid, tmp, filename=filename)
            run = enqueue_triage(JobQueue(s.conn), target)
            os.unlink(tmp)
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

    def _create_run(self):
        from ..analyze.detect import enqueue_detect
        from ..analyze.disassemble import enqueue_disassemble
        from ..analyze.ingest import enqueue_triage
        body = json.loads(self._read_body() or b"{}")
        s = self._store()
        try:
            q = JobQueue(s.conn)
            stage = body.get("stage", _INGEST)
            target_id = body.get("target_id")
            if stage in ("link_case", "cross_taint", "ipc_model", "whole_system"):
                cid = body.get("case_id") or (
                    s.targets.get(target_id).case_id if target_id else None)
                if stage == "link_case":
                    from ..analyze.link import enqueue_link
                    run = enqueue_link(q, cid)
                elif stage == "ipc_model":
                    from ..analyze.link import enqueue_ipc
                    run = enqueue_ipc(q, cid)
                elif stage == "whole_system":
                    from ..analyze.link import enqueue_whole_system
                    run = enqueue_whole_system(q, cid, params=body.get("params"))
                else:
                    from ..analyze.link import enqueue_cross_taint
                    run = enqueue_cross_taint(q, cid)
                return self._json({"run_id": run.id, "from_cache": run.status == "done"}, 201)
            if stage in (_INGEST, "disassemble", "detect_cwe", "dynamic_run", "fuzz",
                         "coverage_fuzz", "directed_fuzz", "concolic",
                         "build_poc", "poc_primitive", "build_exploit", "boundary_fuzz",
                         "synthesize_poc", "root_cause", "multi_debug", "debug_monitor",
                         "firmware_carve",
                         "firmware_rehost") and target_id:
                target = s.targets.get(target_id)
                if not target:
                    return self._json({"error": "no target"}, 404)
                if stage == _INGEST:
                    run = enqueue_triage(q, target)
                elif stage == "disassemble":
                    run = enqueue_disassemble(q, target)
                elif stage == "detect_cwe":
                    run = enqueue_detect(q, target)
                elif stage == "dynamic_run":
                    from ..analyze.dynamic import enqueue_dynamic
                    run = enqueue_dynamic(q, target, params=body.get("params"))
                elif stage == "fuzz":
                    from ..analyze.fuzz import enqueue_fuzz
                    run = enqueue_fuzz(q, target, params=body.get("params"))
                elif stage == "coverage_fuzz":
                    from ..analyze.fuzz import enqueue_coverage_fuzz
                    run = enqueue_coverage_fuzz(q, target, params=body.get("params"))
                elif stage == "directed_fuzz":
                    from ..analyze.fuzz import enqueue_directed_fuzz
                    run = enqueue_directed_fuzz(q, target, params=body.get("params"))
                elif stage == "concolic":
                    from ..analyze.symbolic import enqueue_concolic
                    run = enqueue_concolic(q, target, params=body.get("params"))
                elif stage == "poc_primitive":
                    from ..analyze.poc import enqueue_primitive
                    run = enqueue_primitive(q, target, params=body.get("params"))
                elif stage == "build_exploit":
                    from ..analyze.poc import enqueue_exploit
                    run = enqueue_exploit(q, target, params=body.get("params"))
                elif stage == "root_cause":
                    from ..analyze.debug import enqueue_root_cause
                    run = enqueue_root_cause(q, target, params=body.get("params"))
                elif stage == "multi_debug":
                    from ..analyze.debug import enqueue_multi_debug
                    run = enqueue_multi_debug(q, target, params=body.get("params"))
                elif stage == "debug_monitor":
                    from ..analyze.debug import enqueue_monitor
                    run = enqueue_monitor(q, target, params=body.get("params"))
                elif stage == "firmware_carve":
                    from ..analyze.firmware import enqueue_firmware
                    run = enqueue_firmware(q, target, params=body.get("params"))
                elif stage == "firmware_rehost":
                    from ..analyze.firmware import enqueue_rehost
                    run = enqueue_rehost(q, target, params=body.get("params"))
                elif stage == "boundary_fuzz":
                    from ..analyze.link import enqueue_boundary
                    run = enqueue_boundary(q, target, params=body.get("params"))
                elif stage == "synthesize_poc":
                    from ..analyze.poc import enqueue_synthesize
                    run = enqueue_synthesize(q, target, params=body.get("params"))
                else:
                    from ..analyze.poc import enqueue_build_poc
                    run = enqueue_build_poc(q, target, params=body.get("params"))
            else:
                run = q.enqueue(body["case_id"], stage, target_id=target_id,
                                params=body.get("params"))
            return self._json({"run_id": run.id, "from_cache": run.status == "done"}, 201)
        finally:
            s.close()

    # ---- WebSocket event stream ----
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


def _finding(f):
    return {"id": f.id, "target_id": f.target_id, "case_id": f.case_id, "cwe": f.cwe,
            "title": f.title, "severity": f.severity, "state": f.state,
            "confidence": f.confidence, "function_addr": f.function_addr,
            "site_addr": f.site_addr, "detector": f.detector, "evidence": f.evidence}


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
