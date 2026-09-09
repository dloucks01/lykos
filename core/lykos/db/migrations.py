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

    Strips `--` line comments and splits on `;`. Adequate for our own migration DDL
    (no `;` inside string literals, no trigger BEGIN/END bodies). We do NOT use
    sqlite3.executescript() because it implicitly commits, which conflicts with the
    explicit per-migration transaction in apply_migrations().
    """
    buf = []
    for line in sql.splitlines():
        idx = line.find("--")
        if idx >= 0:
            line = line[:idx]
        buf.append(line)
    joined = "\n".join(buf)
    return [s.strip() for s in joined.split(";") if s.strip()]


def _ensure_version_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version("
        "version INTEGER NOT NULL, name TEXT NOT NULL, applied_at INTEGER NOT NULL)"
    )


def current_version(conn: sqlite3.Connection) -> int:
    _ensure_version_table(conn)
    row = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
    return int(row["v"]) if row and row["v"] is not None else 0


def apply_migrations(conn: sqlite3.Connection, migrations: Sequence[Migration]) -> int:
    """Apply all migrations with version > current, in order. Returns new version."""
    _ensure_version_table(conn)
    have = current_version(conn)
    for m in sorted(migrations, key=lambda x: x.version):
        if m.version <= have:
            continue
        with transaction(conn):
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
