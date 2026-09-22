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
import shutil
import signal
import socket
import tarfile
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
# What `_get_report` can actually produce. Anything else used to fall through to
# HTML, so `?format=md` returned 200 and a web page rather than saying it is not a
# format this build makes.
_REPORT_FORMATS = {"html", "pdf", "sarif", "json"}


# --------------------------------------------------------------------------- server

def _int_param(q, name, default: int) -> int:
    """A query parameter as an int, falling back to the default when it is not one.

    The UI builds these from its own controls, but the URL is typed by hand as often as not --
    and `?limit=abc` reaching int() raised straight out of the handler and returned a 500.
    A malformed parameter is a bad request at worst, never a server fault.
    """
    try:
        return int((q.get(name) or [str(default)])[0])
    except (TypeError, ValueError):
        return default


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
# Loopback hosts the browser UI legitimately reaches us on. A request whose Host or Origin is
# anything else is a cross-site or DNS-rebinding attempt against 127.0.0.1:8787.
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
# Ceiling on a single request body (uploads, case-archive imports). Bounds memory; firmware
# images fit comfortably under this.
_MAX_BODY = 1 * 1024 * 1024 * 1024  # 1 GiB
# Chunk size for streaming request bodies and file responses.
_CHUNK = 1 << 20  # 1 MiB


class _TruncatedBody(Exception):
    """Client declared a Content-Length but delivered fewer bytes: the body is incomplete and
    must never be treated as if it were the whole request (a truncated upload would otherwise
    be ingested as a real -- but different -- target)."""


def _hostname_only(value: str) -> str:
    """Host header -> bare hostname (strip port, unwrap [::1])."""
    v = value.strip()
    if v.startswith("["):
        end = v.find("]")
        return v[1:end] if end != -1 else v[1:]
    return v.rsplit(":", 1)[0] if ":" in v else v


_RUN_ID = re.compile(r"^/runs/([^/]+)$")
_RUN_CANCEL = re.compile(r"^/runs/([^/]+)/cancel$")
_RUN_OUTPUT = re.compile(r"^/runs/([^/]+)/output$")
_TARGET_INVOKE = re.compile(r"^/targets/([^/]+)/invocation$")
_TARGET_REPLAY = re.compile(r"^/targets/([^/]+)/replay$")
_TARGET_CAPS = re.compile(r"^/targets/([^/]+)/capabilities$")
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
_TARGET_SOURCE = re.compile(r"^/targets/([^/]+)/source$")
_CASE_REPORT = re.compile(r"^/cases/([^/]+)/report$")
_CASE_EXPORT = re.compile(r"^/cases/([^/]+)/export$")
_CASE_SYSMAP = re.compile(r"^/cases/([^/]+)/systemmap$")
_CASE_VERIFS = re.compile(r"^/cases/([^/]+)/verifications$")
_CASE_AUTOPILOT = re.compile(r"^/cases/([^/]+)/autopilot$")
_CASE_AUTOPILOT_CANCEL = re.compile(r"^/cases/([^/]+)/autopilot/cancel$")


def _read_ui() -> bytes:
    """Load the UI page — works from a filesystem checkout AND from a zipapp (.pyz)."""
    return _read_static("index.html")


# Assets the SPA loads after index.html: the vendored ESM runtime and the app modules.
# Only these subtrees are served, and only plain web asset types -- nothing else under the
# package is reachable, and a name with `..` or a leading slash never resolves.
_STATIC_ASSET = re.compile(
    r"^/((?:app|vendor)/(?!\.\.?(?:/|$))[A-Za-z0-9._-]+(?:/(?!\.\.?(?:/|$))[A-Za-z0-9._-]+)*)$")
_ASSET_TYPES = {
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}


def _read_static(relpath: str) -> bytes:
    """Read one file under lykos/api/static — from a checkout AND from a zipapp (.pyz).

    `relpath` is already validated by the route regex: no `..`, no leading slash, no
    backslash. It is joined component-by-component so a traversal can never form even if the
    regex is later loosened.
    """
    parts = [p for p in relpath.split("/") if p and p != "."]
    if any(p == ".." for p in parts):
        raise FileNotFoundError(relpath)
    try:
        from importlib import resources
        node = resources.files("lykos.api") / "static"
        for p in parts:
            node = node / p
        return node.read_bytes()
    except FileNotFoundError:
        raise
    except Exception:
        base = (Path(__file__).parent / "static").resolve()
        target = base.joinpath(*parts).resolve()
        if base != target and base not in target.parents:
            raise FileNotFoundError(relpath)
        return target.read_bytes()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # Server-side Autopilot runs, keyed by case. Each is {thread, status, stop}. In-memory (one
    # server process): a run survives the client tab closing, its results persist in the case DB,
    # and a reopened case shows them. Class-level so it is shared across request threads.
    _AUTOPILOTS: dict = {}
    _AUTOPILOTS_LOCK = threading.Lock()

    # silence + AF_UNIX-safe logging
    def log_message(self, *a):  # noqa: D401
        pass

    def address_string(self):
        return "unix"

    @property
    def db_path(self) -> Path:
        return self.server.case_dir / "case.db"

    # ---- helpers ----
    def _json(self, obj: Any, status: int = 200, *, close: bool = False) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if close:
            # Early-return error paths often have an unread request body still in the socket.
            # On an HTTP/1.1 keep-alive connection that leftover would be parsed as the next
            # request line and desync the stream, so tear the connection down instead.
            self.close_connection = True
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _bytes(self, data: bytes, content_type: str, *, status: int = 200,
               filename: Optional[str] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if filename:
            # The filename is derived from a user-controlled case name; CR/LF/quote in a header
            # value would split the response (header injection). Strip them.
            safe = filename.replace("\r", "").replace("\n", "").replace('"', "")
            self.send_header("Content-Disposition", f'attachment; filename="{safe}"')
        self.end_headers()
        self.wfile.write(data)

    def _stream_file(self, path: Path, content_type: str, *,
                     filename: Optional[str] = None) -> None:
        """Send a file straight from disk in fixed-size chunks with a known Content-Length.
        Artifacts (and case exports) can approach the 1 GiB body ceiling; reading the whole
        blob into memory per request would multiply resident memory by the thread count."""
        size = path.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        if filename:
            safe = filename.replace("\r", "").replace("\n", "").replace('"', "")
            self.send_header("Content-Disposition", f'attachment; filename="{safe}"')
        self.end_headers()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(_CHUNK)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def _guard_local(self) -> bool:
        """Refuse cross-site browser requests (CSRF) and DNS-rebinding for state-changing calls.
        A same-origin UI request carries a loopback Origin; a non-browser client (curl) sends no
        Origin and is allowed. A request whose Host or Origin is not loopback is refused, which
        also defeats a rebinding page that points a hostname at 127.0.0.1. Returns True if the
        request may proceed; otherwise it has already sent a 403."""
        host = _hostname_only(self.headers.get("Host", ""))
        if host and host not in _LOCAL_HOSTS:
            self._json({"error": "host not allowed"}, 403, close=True)
            return False
        origin = self.headers.get("Origin")
        if origin:
            o = urlparse(origin)
            if (o.hostname or "") not in _LOCAL_HOSTS:
                self._json({"error": "cross-origin request refused"}, 403, close=True)
                return False
        return True

    def _read_body(self, max_bytes: int = _MAX_BODY) -> Optional[bytes]:
        """Read the request body, bounded. Returns None (caller sends 413) when Content-Length is
        malformed or exceeds the ceiling; reads in chunks so a lying huge length cannot
        pre-allocate. Prevents an unbounded body from exhausting memory.

        Raises _TruncatedBody when the client sent FEWER bytes than it declared: a partial read
        must surface as an error, never as a shorter-but-plausible body (invariant 4)."""
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return None
        if n < 0 or n > max_bytes:
            return None
        buf = bytearray()
        remaining = n
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, _CHUNK))
            if not chunk:
                # short read: the declared body never fully arrived
                raise _TruncatedBody(f"expected {n} bytes, got {len(buf)}")
            buf += chunk
            remaining -= len(chunk)
        return bytes(buf)

    def _json_body(self) -> Optional[dict]:
        """Parse a JSON request body, or send the right error and return None. An over-limit or
        malformed-length body is a 413 (not silently coerced to {}); invalid JSON is a 400."""
        raw = self._read_body()
        if raw is None:
            self._json({"error": "request body too large or malformed"}, 413, close=True)
            return None
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            self._json({"error": "invalid JSON body"}, 400)
            return None

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

    def _static_asset(self, relpath: str) -> None:
        """Serve one vendored/app asset with the right media type."""
        try:
            body = _read_static(relpath)
        except Exception:
            return self._json({"error": "not found"}, 404)
        ext = os.path.splitext(relpath)[1].lower()
        self.send_response(200)
        self.send_header("Content-Type", _ASSET_TYPES.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        # These are content-hashed by name in practice and change only on redeploy; a short
        # cache keeps a reload from re-fetching the whole runtime while never going stale
        # across a version bump the operator would notice.
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    # ---- GET ----
    def do_GET(self):
        # Reads leak case data too: findings, artifact blobs, the whole-case export. A
        # DNS-rebinding page (Host set to an attacker name that resolves to 127.0.0.1) is
        # same-origin with itself and could otherwise exfiltrate all of it, so the read side
        # gets the same Host/Origin guard the WS upgrades and the write side already have.
        if not self._guard_local():
            return
        parsed = urlparse(self.path)
        path, qs = parsed.path, parse_qs(parsed.query)
        # WebSocket upgrade for /events. Guard first: a WS handshake is not subject to the
        # same-origin policy, so without this any page the analyst visits could open the stream
        # (or, on /console, drive a target) against 127.0.0.1:8787.
        if path == "/events" and "websocket" in self.headers.get("Upgrade", "").lower():
            if not self._guard_local():
                return
            return self._ws_events(qs.get("case_id", [None])[0])
        # WebSocket upgrade for the interactive detonation console
        if path == "/console" and "websocket" in self.headers.get("Upgrade", "").lower():
            if not self._guard_local():
                return
            return self._ws_console(qs)
        try:
            if path in ("/", "/index.html"):
                return self._static()
            if path == "/classic.html":       # the preserved single-file UI, linked from the app
                return self._static_asset("classic.html")
            m = _STATIC_ASSET.match(path)
            if m:
                return self._static_asset(m.group(1))
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
                    # A case that does not exist is not a case with no targets. Returning []
                    # with 200 makes a typo'd or deleted id indistinguishable from an empty
                    # case, and a caller polling for its targets waits forever on nothing.
                    if not s.cases.get(m.group(1)):
                        return self._json({"error": "no case"}, 404)
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
                    # A binary can hold far more strings than the cap returns, and the old
                    # response was indistinguishable from "that is all of them" -- it stopped
                    # at exactly 2000 with nothing saying so.
                    q = parse_qs(urlparse(self.path).query)
                    limit = max(1, min(_int_param(q, "limit", 2000), 5000))
                    offset = max(0, _int_param(q, "offset", 0))
                    sd = StringDAO(s.conn)
                    strs = sd.list_by_target(m.group(1), limit=limit, offset=offset)
                    total = sd.count_by_target(m.group(1))
                    return self._json({"total": total, "offset": offset, "limit": limit,
                                       "truncated": offset + len(strs) < total,
                                       "items": [_stringref(x) for x in strs]})
                finally:
                    s.close()
            m = _TARGET_FIND.match(path)
            if m:
                s = self._store()
                try:
                    fd = FindingDAO(s.conn)
                    fs = fd.list_by_target(m.group(1))
                    counts = fd.site_counts(m.group(1))
                    prov = fd.proven_sites(m.group(1))
                    return self._json([_finding(x, site_count=counts.get(x.id, 0),
                                                proven=prov.get(x.id, 0))
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
            m = _CASE_VERIFS.match(path)
            if m:
                return self._get_verifications(m.group(1))
            m = _CASE_AUTOPILOT.match(path)
            if m:
                return self._get_autopilot(m.group(1))
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
            m = _TARGET_SOURCE.match(path)
            if m:
                return self._get_target_source(m.group(1))
            m = _TARGET_CAPS.match(path)
            if m:
                return self._get_capabilities(m.group(1))
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
            m = _RUN_OUTPUT.match(path)
            if m:
                return self._get_run_output(m.group(1))
            m = _RUN_ID.match(path)
            if m:
                return self._get_run(m.group(1))
            m = _ARTIFACT.match(path)
            if m:
                return self._get_artifact(m.group(1))
            m = _CASE_EVENTS.match(path)
            if m:
                after = _int_param(qs, "after", 0)
                return self._get_events(m.group(1), after)
            self._json({"error": "not found"}, 404)
        except _TruncatedBody as e:
            self._json({"error": f"request body truncated: {e}"}, 400, close=True)
        except Exception as e:  # never crash the server thread
            self._json({"error": repr(e)}, 500)

    # ---- POST ----
    def do_POST(self):
        if not self._guard_local():
            return
        path = urlparse(self.path).path
        try:
            if path == "/cases":
                return self._create_case()
            m = _CASE_TARGETS.match(path)
            if m:
                return self._upload_target(m.group(1))
            if path == "/runs":
                return self._create_run()
            m = _RUN_CANCEL.match(path)
            if m:
                return self._cancel_run(m.group(1))
            m = _TARGET_INVOKE.match(path)
            if m:
                return self._check_invocation(m.group(1))
            m = _TARGET_REPLAY.match(path)
            if m:
                return self._replay_input(m.group(1))
            if path == "/format/analyze":
                return self._format_analyze()
            if path == "/import":
                return self._import_case()
            m = _CASE_AUTOPILOT_CANCEL.match(path)
            if m:
                return self._cancel_autopilot(m.group(1))
            m = _CASE_AUTOPILOT.match(path)
            if m:
                return self._start_autopilot(m.group(1))
            self._json({"error": "not found"}, 404, close=True)
        except _TruncatedBody as e:
            self._json({"error": f"request body truncated: {e}"}, 400, close=True)
        except Exception as e:
            self._json({"error": repr(e)}, 500, close=True)

    def _get_capabilities(self, tid):
        """What this target can and cannot have done to it, and why not.

        Separate from /advice on purpose: advice says what to do NEXT, this says what is
        POSSIBLE at all. The workbench needs both -- it highlights the recommendation and
        disables the impossible with its reason, instead of rendering the same twenty-two
        controls for an ELF, a PE, a jar and a firmware image.
        """
        from ..analyze import capabilities as capmod
        s = self._store()
        try:
            t = s.targets.get(tid)
            if not t:
                return self._json({"error": "no target"}, 404)
            plan = []
            try:
                plan = (self._advice_for(s, t) or {}).get("plan") or []
            except Exception:
                pass
            done = {r.stage for r in s.runs.list_by_case(t.case_id)
                    if r.target_id == tid and r.status == "done"}
            return self._json({
                "target": tid, "file_type": t.file_type, "arch": t.arch,
                "groups": [{"key": k, "label": lab, "why": why}
                           for k, lab, why in capmod.GROUPS],
                "stages": capmod.for_target(t, plan=plan, done=done),
                "unavailable": capmod.unavailable_summary(t),
            })
        finally:
            s.close()

    def _coverage_blocked(self, t):
        try:
            from ..analyze.fuzz.coverage import _unsupported
            return _unsupported(t)
        except Exception:
            return None

    def _target_strings(self, s, tid):
        """The target's strings -- from the DB if `disassemble` has run, else scanned from the
        bytes. Requiring Ghidra first would put the answer to "how do I run this" behind the
        analysis it is needed to set up."""
        from ..analyze import invocation as invmod
        rows = [x.value for x in StringDAO(s.conn).list_by_target(tid) if x.value]
        if rows:
            return rows
        t = s.targets.get(tid)
        return invmod.raw_strings(s.content.path(t.sha256).read_bytes()) if t else []

    def _check_invocation(self, tid):
        """Propose a command line for this target -- and RUN it to see if the target accepts.

        A proposal read off the strings is a hypothesis. Applying one unchecked produces the
        exact failure it exists to fix: unzip needs no flags, and `-d <dir> -x x` is a worse
        command line than none at all. The target's own refusal is quoted back.
        """
        from ..analyze import invocation as invmod
        from ..analyze.dynamic import sandbox
        body = self._json_body()
        if body is None:
            return
        s = self._store()
        try:
            t = s.targets.get(tid)
            if not t:
                return self._json({"error": "no target"}, 404)
            found = invmod.discover(self._target_strings(s, tid),
                                    usage_hint=body.get("usage_hint"))
            d = Path(tempfile.mkdtemp(prefix="lykos-invocation-"))
            try:
                # Into the EXE's directory: the sandbox masks /tmp and binds back only that
                # one, so a jar or config written elsewhere does not exist for the target.
                argv = body.get("argv") or invmod.materialize(found, d)
                found["proposed_argv"] = argv
                if not body.get("verify", True) or not argv:
                    return self._json(found)
                exe = d / "target.bin"
                exe.write_bytes(s.content.path(t.sha256).read_bytes())
                os.chmod(exe, 0o755)
                sample = d / "sample.bin"
                sample.write_bytes(base64.b64decode(body["sample_b64"])
                                   if body.get("sample_b64") else b"name=lykos\n")

                def _run(a):
                    return sandbox.run(exe, argv=a, stdin=b"", timeout=float(body.get(
                        "timeout", 15)), arch=t.arch, endianness=t.endianness, bits=t.bits)
                found["verified"] = invmod.verify(_run, exe, argv, str(sample))
            finally:
                shutil.rmtree(d, ignore_errors=True)
            return self._json(found)
        finally:
            s.close()

    def _replay_input(self, tid):
        """Re-run a crashing input several times to confirm it is a TRUE, deterministic crash.

        A demonstrated finding is only trustworthy if its own reproducer fires every time; a
        crash that appears once in five runs is flaky evidence, not a proof. This is the
        false-positive review: it replays the recorded crashing input in the sandbox N times
        and reports how many crashed and with which signal, so the workbench can badge a finding
        verified or flag it flaky. Bounded (<=10 runs, short timeout) so it is cheap and safe.
        """
        from ..analyze.review import replay_verdict
        body = self._json_body()
        if body is None:
            return
        input_sha = (body or {}).get("input_sha")
        times = max(1, min(int((body or {}).get("times", 5)), 10))
        timeout = float((body or {}).get("timeout", 8))
        s = self._store()
        try:
            t = s.targets.get(tid)
            if not t:
                return self._json({"error": "no target"}, 404)
            if not input_sha:
                return self._json({"error": "input_sha required"}, 400)
            # The replay + verdict persistence is shared with the server-side Autopilot's review
            # pass; run_input() there handles delivery mode, argv placement and NUL-safe argv.
            verdict = replay_verdict(s, t, input_sha, times=times, timeout=timeout)
            if verdict is None:
                return self._json({"error": "unknown input"}, 404)
            return self._json(verdict)
        finally:
            s.close()

    def _start_autopilot(self, cid):
        """Start (or restart) a server-side Autopilot for a case: a daemon thread that drives the
        pipeline to a PoC and keeps running after the client disconnects."""
        from ..analyze import orchestrate
        body = self._json_body() or {}
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            target_ids = body.get("target_ids") or [t.id for t in s.targets.list_by_case(cid)]
        finally:
            s.close()
        if not target_ids:
            return self._json({"error": "no targets to analyse"}, 400)
        with Handler._AUTOPILOTS_LOCK:
            cur = Handler._AUTOPILOTS.get(cid)
            if cur and cur["thread"].is_alive():
                return self._json({"error": "already running", "status": cur["status"]}, 409)
            status = {"state": "starting", "stage": None, "target": 0, "targets": len(target_ids)}
            stop = threading.Event()
            th = threading.Thread(
                target=orchestrate.run_case_autopilot,
                args=(self.server.case_dir, cid, target_ids, status, stop),
                name=f"autopilot-{cid[:8]}", daemon=True)
            Handler._AUTOPILOTS[cid] = {"thread": th, "status": status, "stop": stop}
            th.start()
        return self._json({"started": True, "targets": len(target_ids)}, 202)

    def _get_autopilot(self, cid):
        """The status of a case's server-side Autopilot, for polling from the UI."""
        with Handler._AUTOPILOTS_LOCK:
            rec = Handler._AUTOPILOTS.get(cid)
            if not rec:
                return self._json({"state": "none"})
            st = dict(rec["status"])
            st["running"] = rec["thread"].is_alive()
        return self._json(st)

    def _cancel_autopilot(self, cid):
        with Handler._AUTOPILOTS_LOCK:
            rec = Handler._AUTOPILOTS.get(cid)
            if not rec:
                return self._json({"error": "no run"}, 404)
            rec["stop"].set()
        return self._json({"cancelling": True})

    def _cancel_run(self, run_id):
        """Stop a running stage.

        The job engine has had `JobQueue.cancel` and `ctx.should_cancel()` all along and
        nothing exposed them, so a campaign started from the UI could not be stopped -- a
        ten-minute fuzz had to be waited out or the server killed.
        """
        s = self._store()
        try:
            run = s.runs.get(run_id)
            if not run:
                return self._json({"error": "no run"}, 404)
            if run.status in ("done", "error", "cancelled"):
                # not an error: the user clicked as it finished
                return self._json({"cancelled": False, "status": run.status,
                                   "note": f"run already {run.status}"})
            ok = JobQueue(s.conn).cancel(run_id)
            after = s.runs.get(run_id)
            return self._json({"cancelled": bool(ok), "status": after.status if after else None})
        finally:
            s.close()

    # ---- DELETE ----
    def do_DELETE(self):
        if not self._guard_local():
            return
        path = urlparse(self.path).path
        try:
            m = _TARGET_ID.match(path)
            if m:
                return self._delete_target(m.group(1))
            self._json({"error": "not found"}, 404, close=True)
        except _TruncatedBody as e:
            self._json({"error": f"request body truncated: {e}"}, 400, close=True)
        except Exception as e:
            self._json({"error": repr(e)}, 500, close=True)

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
        s = self._store()
        try:
            t = s.targets.get(tid)
            if not t:
                return self._json({"error": "no target"}, 404)
            return self._json(self._advice_for(s, t))
        finally:
            s.close()

    def _advice_for(self, s, t) -> dict:
        """The advice DICT, so /capabilities can reuse it. It needs the plan to know which
        stage is recommended, and computing it twice would be two answers to one question."""
        from ..analyze import advise as advise_mod
        tid = t.id
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
        if not imports:
            # A statically linked binary has no import table, but its symbol table still
            # names fopen/fgets/read -- the same evidence, in the other place. Without
            # this a config-driven daemon was reported as "argv/none".
            try:
                from ..analyze.poc.exploit import elf_functions
                blob = s.content.path(t.sha256).read_bytes()
                imports = list(elf_functions(blob))
            except Exception:
                imports = []
        # How to invoke it, read off the binary's own usage line and option string. Static
        # only here: advice must stay fast, and running the target to CHECK the proposal
        # is what POST /targets/<id>/invocation is for.
        try:
            from ..analyze import invocation as invmod
            found = invmod.discover(self._target_strings(s, tid))
            found["proposed_argv"] = invmod.propose_argv(found)
        except Exception:
            found = None
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
            # triage could not name a format, so there is nothing here to run
            executable=bool(t.file_type and t.file_type not in ("raw", "other")),
            file_format=t.file_type,
            crashes=crashes, pocs=len(pocs), invocation=found,
            # One source of truth for "can AFL++ run THIS target": the stage's own gate.
            # Advice that says coverage_fuzz while the stage declines it is a plan that
            # dead-ends one click later.
            coverage_blocked=self._coverage_blocked(t))
        if found and found.get("flags"):
            out["invocation"] = found
        return out

    def _get_case_findings(self, cid):
        """All findings in a case, enriched with target filename/arch and the target's best
        PoC level -- the data the case findings board aggregates."""
        s = self._store()
        try:
            # A mistyped or deleted case returned `200 []`, so the board rendered "no
            # findings" for a case that does not exist -- indistinguishable from a real case
            # that has none.
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            tmap = {t.id: t for t in s.targets.list_by_case(cid)}
            best_poc = {}
            for t in tmap.values():
                lvls = [p.level for p in PocDAO(s.conn).list_by_target(t.id)
                        if p.verified and p.level]
                if lvls:
                    best_poc[t.id] = max(lvls)          # "L2" > "L1" lexicographically
            out = []
            fd = FindingDAO(s.conn)
            counts, proven = {}, {}
            for tid in tmap:
                counts.update(fd.site_counts(tid))
                proven.update(fd.proven_sites(tid))
            for f in fd.list_by_case(cid):
                d = _finding(f, site_count=counts.get(f.id, 0),
                             proven=proven.get(f.id, 0))
                t = tmap.get(f.target_id)
                d["target_name"] = t.filename if t else None
                d["target_arch"] = t.arch if t else None
                # Only on a finding that IS PoC-backed. This was the TARGET's best level
                # pinned to every finding of that target, so all 24 of jhead's rows wore an
                # "L1" badge and the one finding actually backed by a PoC looked no different
                # from the 23 that were not.
                if f.state == "poc-backed":
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
        # An unknown format fell through to HTML. `?format=csv` then returned 200 and a web
        # page, so a caller that asked for something this build does not produce got a
        # plausible-looking answer in the wrong format and no indication of the typo.
        if fmt not in _REPORT_FORMATS:
            return self._json({"error": f"unknown report format {fmt!r}",
                               "formats": sorted(_REPORT_FORMATS)}, 400)
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
                # Stream from the temp file (inside the with-block, before cleanup) rather than
                # slurping the whole archive into memory.
                self._stream_file(tmp, "application/gzip", filename=f"{name}.tar.gz")
        finally:
            s.close()

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

    def _get_verifications(self, cid):
        """The false-positive review verdicts for a case, `{input_sha: verdict}` (the latest for
        each input). Persisted as `replay-verdict` artifacts by the replay endpoint; without a way
        to read them back, a REOPENED case lost every VerifyBadge (the live run gets them from the
        event stream, a reopen has no stream). Mirrors the report model's verdict aggregation."""
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            verdicts: dict = {}
            for a in s.artifacts.list_by_case(cid):
                if a.kind != "replay-verdict":
                    continue
                m = a.meta or {}
                ish = m.get("input_sha")
                if not ish:
                    continue
                at = a.created_at or 0
                if ish not in verdicts or at > verdicts[ish].get("_at", 0):
                    verdicts[ish] = {"runs": m.get("runs"), "crashed": m.get("crashed"),
                                     "signal": m.get("signal"),
                                     "deterministic": m.get("deterministic"), "_at": at}
            for v in verdicts.values():
                v.pop("_at", None)
            return self._json(verdicts)
        finally:
            s.close()

    def _import_case(self):
        """Merge an uploaded case archive (per-case or whole-store .tar.gz) into the store."""
        ctype = self.headers.get("Content-Type", "")
        body = self._read_body()
        if body is None:
            return self._json({"error": "request body too large or malformed"}, 413, close=True)
        _, data = extract_file(ctype, body)
        if data is None:
            data = body
        with tempfile.TemporaryDirectory(prefix="lykos-import-") as td:
            tmp = Path(td) / "import.tar.gz"
            tmp.write_bytes(data)
            s = self._store()
            try:
                try:
                    ids = s.import_archive(tmp)
                except tarfile.ReadError:
                    # this endpoint takes a case ARCHIVE, and the name invites people to try a
                    # binary here; `ReadError('not a gzip file')` is a Python repr, not an
                    # answer. Binaries go to POST /cases/<id>/targets.
                    return self._json({"error": (
                        "this is not a lykos case archive (expected a .tar.gz produced by "
                        "export). To add a binary to a case, upload it to "
                        "/cases/<case-id>/targets instead.")}, 400)
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

    def _get_target_source(self, tid):
        """The source a target was compiled from, when it came from a source drop.

        A source upload is compiled to an instrumented binary at ingest and analysed as that
        binary; the original source is kept as an artifact keyed to the binary's hash, so the
        code view can show real source instead of disassembly. Returns {source: null} for an
        ordinary binary target.
        """
        s = self._store()
        try:
            t = s.targets.get(tid)
            if not t:
                return self._json({"error": "no target"}, 404)
            for a in s.artifacts.list_by_case(t.case_id):
                if a.kind == "source-code" and (a.meta or {}).get("binary_sha") == t.sha256:
                    try:
                        text = s.content.get_bytes(a.sha256).decode("utf-8", "replace")
                    except Exception:
                        text = None
                    m = a.meta or {}
                    return self._json({"source": text, "filename": m.get("filename"),
                                       "compiler": m.get("compiler"), "sanitizers": m.get("sanitizers")})
            return self._json({"source": None})
        finally:
            s.close()

    def _get_run_output(self, rid):
        """The parsed JSON a stage produced -- what actually happened, for the run log.

        The run row carries status and error but not the stage's own result (how many execs
        the fuzzer ran, how many functions were recovered, what the crash signal was). That
        lives in the run's 'output' artifact; this surfaces it so the UI can say what a stage
        found instead of only that it finished.
        """
        from ..jobs.registry import cached_output_json
        s = self._store()
        try:
            r = s.runs.get(rid)
            if not r:
                return self._json({"error": "no run"}, 404)
            try:
                out = cached_output_json(s, rid)
            except Exception:
                out = None
            return self._json({"run_id": rid, "stage": r.stage, "status": r.status,
                               "error": r.error, "output": out})
        finally:
            s.close()

    def _get_artifact(self, sha):
        path = self.server.content.path(sha)
        if not path.exists():
            return self._json({"error": "no artifact"}, 404)
        # Stream from disk in chunks -- an artifact may be a firmware image near the 1 GiB
        # ceiling, and get_bytes() would load the whole blob into memory per concurrent request.
        return self._stream_file(path, "application/octet-stream")

    def _get_events(self, cid, after):
        s = self._store()
        try:
            evs = s.events.list(case_id=cid, after_id=after, limit=500)
            return self._json([_event(e) for e in evs])
        finally:
            s.close()

    def _create_case(self):
        body = self._json_body()
        if body is None:
            return
        s = self._store()
        try:
            c = s.cases.create(body.get("name", "case"), notes=body.get("notes"),
                               engagement_ref=body.get("engagement_ref"))
            return self._json(_case(c), 201)
        finally:
            s.close()

    def _upload_target(self, cid):
        # `..analyze` re-exports `ingest` as a FUNCTION, so importing the module under an
        # alias binds the function and the exception lookup fails at runtime
        from ..analyze.ingest import NotAnalysable, enqueue_triage, ingest
        from ..jobs.registry import reproject_cache_hit
        ctype = self.headers.get("Content-Type", "")
        body = self._read_body()
        if body is None:
            return self._json({"error": "request body too large or malformed"}, 413, close=True)
        filename, data = extract_file(ctype, body)
        if data is None:  # allow raw octet-stream fallback
            filename = self.headers.get("X-Filename", "upload.bin")
            data = body
        # The client-supplied filename must never influence where we write: an absolute path or
        # `../` would escape the temp dir (arbitrary file write). Reduce it to a bare basename.
        safe_name = Path(filename or "upload.bin").name or "upload.bin"
        s = self._store()
        try:
            # TemporaryDirectory, not mkdtemp: the old code unlinked the FILE and left the
            # directory behind, leaking one empty directory per upload for the life of the
            # process. It is also removed on the error paths, which an explicit unlink was not.
            with tempfile.TemporaryDirectory(prefix="lykos-upload-") as td:
                tmp = Path(td) / safe_name
                tmp.write_bytes(data)
                try:
                    target = ingest(s, cid, tmp, filename=safe_name)
                except NotAnalysable as e:
                    # 400, not 500: the upload was understood and refused, and the reason is
                    # for the person who picked the file
                    return self._json({"error": str(e)}, 400)
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
        body = self._json_body()
        if body is None:
            return
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
        body = self._json_body()
        if body is None:
            return
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

        sock = self.connection
        # A server started outside serve() may not have set stop_event; default to a
        # never-set Event rather than an AttributeError after the 101 is already on the wire.
        stop: threading.Event = getattr(self.server, "stop_event", None) or threading.Event()
        # Open the connection INSIDE the try so a failure in the initial cursor query can't
        # leak it (the SELECT ran before the finally that closes it).
        conn = connect(self.db_path)
        try:
            ed = EventDAO(conn)
            # start after the current tail so the client sees live events
            row = conn.execute(
                "SELECT MAX(id) AS m FROM event WHERE case_id IS ? OR ? IS NULL",
                (case_id, case_id)).fetchone()
            cursor = int(row["m"]) if row and row["m"] is not None else 0
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
    # finding_id links the PoC to the defect it proves. Without it the workbench cannot tell
    # which finding a bundle belongs to and would offer the same download on every card.
    return {"id": x.id, "finding_id": x.finding_id, "level": x.level, "verified": x.verified,
            "signal": x.signal_name, "input_sha": x.input_sha, "bundle_sha": x.bundle_sha,
            "created_at": x.created_at}


def _dynresult(d):
    # argv and fault_pc are recorded and were not projected. Both matter to a reader looking
    # at a crash row: argv is HOW the input was delivered -- now that a target may need
    # `-c @@` to run at all, "which invocation produced this" is not a detail -- and fault_pc
    # is WHERE it faulted, which is what the dedup key is built from, so two rows that look
    # identical are distinguishable only by a field the API did not return.
    return {"id": d.id, "crashed": d.crashed, "timed_out": d.timed_out,
            "signal": d.signal_name, "exit_code": d.exit_code, "isolation": d.isolation,
            "input_mode": d.input_mode, "input_sha": d.input_sha,
            "argv": list(getattr(d, "argv", None) or []),
            "fault_pc": (hex(d.fault_pc) if getattr(d, "fault_pc", None) else None),
            "duration_ms": d.duration_ms, "note": d.note, "created_at": d.created_at}


def _finding(f, sites=None, site_count=None, proven=0):
    """Serialize a finding. `sites` is the list of places the defect occurs; `site_count` is
    the cheap aggregate for list views. A finding is a DEFECT -- the sites are evidence."""
    d = {"id": f.id, "target_id": f.target_id, "case_id": f.case_id, "cwe": f.cwe,
         "title": f.title, "severity": f.severity, "state": f.state,
         "confidence": f.confidence, "function_addr": f.function_addr,
         "site_addr": f.site_addr, "detector": f.detector, "evidence": f.evidence,
         # the dedup key lets the UI fold an unlocated crash into its located, analysed twin
         "dedup_key": f.dedup_key}
    if sites is not None:
        d["sites"] = sites
    d["site_count"] = len(sites) if sites is not None else (site_count or 0)
    # How many of those places are individually PROVEN. A poc-backed finding with 99 sites and
    # one proven occurrence must not read like one where all 99 are.
    d["proven_sites"] = len([s for s in sites if s.get("state") == "poc-backed"]) \
        if sites is not None else (proven or 0)
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
