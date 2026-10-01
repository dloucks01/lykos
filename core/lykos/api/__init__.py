"""Local HTTP API + event WebSocket (P0.2 / P0.6), stdlib-based, Unix-socket bound.

No FastAPI/uvicorn dependency: a ThreadingHTTPServer over AF_UNIX with a hand-rolled
RFC-6455 WebSocket for /events. The event stream tails the persisted `event` table
(the job engine already writes there), which is the P0.6 bus for Phase 0.
"""
from .server import serve  # noqa: F401
