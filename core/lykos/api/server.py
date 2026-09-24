"""P0.2 / P0.6 — local HTTP API + event WebSocket over a Unix domain socket.

Threaded server; each request opens its OWN sqlite connection (sqlite conns are not shared
across threads). The event WebSocket tails the persisted `event` table by cursor.
"""
from __future__ import annotations

import json
import os
import select
import shutil
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
from ..jobs import JobConfig, WorkerPool
from . import ws
from .autopilot import AutopilotMixin
from .endpoints import EndpointsMixin
from .serializers import (_INGEST, _call_edge, _case, _csv, _dynresult, _event, _finding,
                          _function, _poc, _run, _stringref, _target)

# What `_get_report` can actually produce. Anything else used to fall through to
# HTML, so `?format=md` returned 200 and a web page rather than saying it is not a
# format this build makes.


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


from .routes import (  # route table + traversal-safe static reader (extracted from this module)
    _ARTIFACT, _ASSET_TYPES, _CASE_AUTOPILOT, _CASE_AUTOPILOT_CANCEL, _CASE_EVENTS, _CASE_EXPORT,
    _CASE_FIND, _CASE_ID, _CASE_REPORT, _CASE_RUNS, _CASE_SYSMAP, _CASE_TARGETS, _CASE_VERIFS,
    _FIND_ID, _FUNC_ID, _RUN_CANCEL, _RUN_ID, _RUN_OUTPUT, _STATIC_ASSET, _TARGET_ADVICE,
    _TARGET_CAPS, _TARGET_CG, _TARGET_DYN, _TARGET_FIND, _TARGET_FUNCS, _TARGET_ID, _TARGET_INVOKE,
    _TARGET_POC, _TARGET_REPLAY, _TARGET_SOURCE, _TARGET_STR, _read_static, _read_ui)


class Handler(EndpointsMixin, AutopilotMixin, BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # Socket timeout: a client that opens a connection and then dribbles (or never sends) its
    # request holds a worker thread indefinitely otherwise (slowloris). Bounds the per-request
    # read; large legitimate uploads still progress because each recv resets the timer.
    timeout = 60

    # The server-side Autopilot registry + its /autopilot endpoints live in AutopilotMixin.

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

    def _read_body_to_file(self, dest: Path, max_bytes: int = _MAX_BODY) -> bool:
        """Stream the request body to `dest` in chunks -- for large uploads (target binaries, case
        archives), so the whole body never sits in memory at once (the concurrent-upload OOM the
        1 GiB in-memory `_read_body` risked). Returns False (caller sends 413) on a malformed or
        over-ceiling Content-Length; raises _TruncatedBody on a short read, like `_read_body`."""
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return False
        if n < 0 or n > max_bytes:
            return False
        remaining = n
        with open(dest, "wb") as out:
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, _CHUNK))
                if not chunk:
                    raise _TruncatedBody(f"expected {n} bytes, got {n - remaining}")
                out.write(chunk)
                remaining -= len(chunk)
        return True

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
                    fdao = FunctionDAO(s.conn)
                    fn = fdao.get(m.group(1))
                    if not fn:
                        return self._json({"error": "no function"}, 404)
                    # On-demand decompilation: the disassemble stage does not decompile every
                    # function up front (a big binary has thousands), so if this one has no cached C
                    # yet, decompile just this function now and store it for next time. Best-effort:
                    # a decompiler that is absent or fails leaves the disassembly view to fall back.
                    if not fn.decompiled:
                        try:
                            from ..analyze import native_re
                            t = s.targets.get(fn.target_id)
                            if t is not None:
                                code = native_re.decompile_one(s.content.path(t.sha256), fn.addr)
                                if code:
                                    fdao.set_decompiled(fn.id, code)
                                    fn.decompiled = code
                        except Exception:
                            pass
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


    # ---- route impls ----


















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
        "heap_trace": ("..analyze.dynamic", "enqueue_heap_trace"),
        "oob_index": ("..analyze.dynamic", "enqueue_oob_index"),
        "chain_primitive": ("..analyze.poc", "enqueue_chain"),
        "poc_diff": ("..analyze.poc", "enqueue_poc_diff"),
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



    # ---- WebSocket event stream ----
    def _ws_console(self, qs):
        """Interactive detonation console: spawn the target under a PTY in the sandbox and proxy
        it live over the WebSocket (send/receive), with a save-as-seed hook."""

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
