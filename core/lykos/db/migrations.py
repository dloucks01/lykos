"""DM-02 — Migration runner.

Forward-only, numbered migrations. Each migration applies in its own transaction and is
recorded in `schema_version`. Applying is idempotent: only migrations newer than the
current version run. `init_db` connects and brings a DB fully up to date.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from .connection import connect, transaction


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    # Either raw SQL (executescript) or a callable(conn) for programmatic migrations.
    sql: str | None = None
    fn: Callable[[sqlite3.Connection], None] | None = None

    def apply(self, conn: sqlite3.Connection) -> None:
        if self.sql is not None:
            for stmt in _split_sql(self.sql):
                conn.execute(stmt)  # executed inside the caller's transaction (txn-safe DDL)
        if self.fn is not None:
            self.fn(conn)


def _split_sql(sql: str) -> list[str]:
    """Split a controlled DDL script into individual statements.

    Strips `--` line comments and splits on `;`, but is STRING-LITERAL AWARE: a `;` or `--`
    inside a `'...'` SQL string literal (doubled `''` is an escaped quote) does not split or
    truncate. This keeps a future migration that embeds `;`/`--` in a literal from being
    silently mis-split. (Trigger BEGIN/END bodies are still unsupported.) We do NOT use
    sqlite3.executescript(), which implicitly commits and would break the transaction wrapping
    apply_migrations().
    """
    stmts: list[str] = []
    buf: list[str] = []
    i, n, in_str = 0, len(sql), False
    while i < n:
        c = sql[i]
        if in_str:
            buf.append(c)
            if c == "'":
                if i + 1 < n and sql[i + 1] == "'":   # doubled '' -> escaped quote, stay in
                    buf.append("'"); i += 2; continue
                in_str = False
            i += 1
        elif c == "'":
            in_str = True; buf.append(c); i += 1
        elif c == "-" and i + 1 < n and sql[i + 1] == "-":   # line comment -> skip to newline
            j = sql.find("\n", i)
            if j < 0:
                break
            i = j
        elif c == ";":
            s = "".join(buf).strip()
            if s:
                stmts.append(s)
            buf = []; i += 1
        else:
            buf.append(c); i += 1
    s = "".join(buf).strip()
    if s:
        stmts.append(s)
    return stmts


def _ensure_version_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version("
        "version INTEGER NOT NULL UNIQUE, name TEXT NOT NULL, applied_at INTEGER NOT NULL)"
    )


def current_version(conn: sqlite3.Connection) -> int:
    _ensure_version_table(conn)
    row = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
    return int(row["v"]) if row and row["v"] is not None else 0


def apply_migrations(conn: sqlite3.Connection, migrations: Sequence[Migration]) -> int:
    """Apply all migrations with version > current, in order. Returns new version.

    Concurrency-safe: every worker that opens a case DB migrates it (CaseStore.open ->
    init_db), so two workers opening a fresh/just-created DB could both read have=0 and both
    run migration 1 -> `table "case" already exists` (or duplicate schema_version rows). The
    whole run is therefore serialized behind the write lock (BEGIN IMMEDIATE) and the version is
    RE-READ inside it; the loser then sees head and does nothing. A quick unlocked pre-check
    keeps the common already-at-head open lock-free.
    """
    _ensure_version_table(conn)
    pending = sorted(migrations, key=lambda x: x.version)
    head = pending[-1].version if pending else 0
    if current_version(conn) >= head:
        return current_version(conn)
    with transaction(conn, immediate=True):
        have = current_version(conn)          # re-read under the write lock
        for m in pending:
            if m.version <= have:
                continue
            m.apply(conn)
            conn.execute(
                "INSERT INTO schema_version(version, name, applied_at) VALUES (?,?,?)",
                (m.version, m.name, int(time.time())),
            )
    return current_version(conn)


def init_db(db_path: str | Path,
            migrations: Sequence[Migration] | None = None) -> sqlite3.Connection:
    """Connect and migrate to head. Returns the open connection."""
    from .schema import MIGRATIONS  # local import to avoid cycle

    conn = connect(db_path)
    apply_migrations(conn, migrations if migrations is not None else MIGRATIONS)
    return conn
