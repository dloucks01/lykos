"""DM-03 — Connection factory + pragmas.

SQLite tuning + single-writer discipline. Every process (each worker) opens its own
connection via `connect()`; connections are NOT shared across threads/processes.
"""
from __future__ import annotations

import itertools
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

# Pragmas applied to every connection. WAL + synchronous are persistent-ish / per-conn;
# foreign_keys and busy_timeout MUST be set per connection (they do not persist).
_BUSY_TIMEOUT_MS = 5000

# A top-level BEGIN that still sees 'database is locked' after its full busy_timeout wait is
# retried this many times with brief backoff before the error surfaces. The queue's hot writers
# have their own retry (queue._begin_immediate); this gives the SAME resilience to every cold
# writer that goes through transaction() -- the user-facing endpoints (create case, upload) among
# them. Without it a case-create under heavy concurrent write load (several pipelines at once)
# returned a bare HTTP 500 'database is locked' instead of waiting the storm out.
_BEGIN_RETRIES = 5

_SAVEPOINT_SEQ = itertools.count()


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a tuned connection. Creates the file if missing."""
    conn = sqlite3.connect(str(db_path), isolation_level=None)  # autocommit; we manage txns
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA temp_store=MEMORY")
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection, *, immediate: bool = False
                ) -> Iterator[sqlite3.Connection]:
    """Explicit transaction. Commits on success, rolls back on exception.

    Used with the autocommit connection above so writes are grouped and atomic.
    Keep write transactions short (single-writer discipline; the queue is the hot writer).

    Nest-safe: called while a transaction is already open (e.g. a DAO bulk write invoked inside
    a larger `transaction()`), it opens a SAVEPOINT and participates in the outer transaction
    instead of raising "cannot start a transaction within a transaction". The inner block then
    rolls back to its savepoint on error and re-raises, leaving the outer transaction to decide
    the final commit/rollback. `immediate=True` takes the write lock up front (BEGIN IMMEDIATE)
    at the top level; nested, the outer transaction already holds it.
    """
    if conn.in_transaction:
        name = f"lykos_sp_{next(_SAVEPOINT_SEQ)}"
        conn.execute(f"SAVEPOINT {name}")
        try:
            yield conn
        except Exception:
            conn.execute(f"ROLLBACK TO {name}")
            conn.execute(f"RELEASE {name}")
            raise
        else:
            conn.execute(f"RELEASE {name}")
    else:
        _begin_resilient(conn, "BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield conn
        except Exception:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")


def _begin_resilient(conn: sqlite3.Connection, stmt: str) -> None:
    """Open a transaction, retrying a transient lock a few times past the busy_timeout wait.

    Each attempt already blocks up to busy_timeout (5s) when another connection holds the write
    lock; this rides out a longer storm instead of letting the OperationalError become a 500. A
    non-lock OperationalError re-raises at once, and the final attempt lets the error surface."""
    for i in range(max(1, _BEGIN_RETRIES)):
        try:
            conn.execute(stmt)
            return
        except sqlite3.OperationalError as e:
            msg = str(e).lower()
            if "lock" not in msg and "busy" not in msg:
                raise
            if i == _BEGIN_RETRIES - 1:
                raise
            time.sleep(0.05 * (i + 1))
