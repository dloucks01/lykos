"""DM-19 — migration runner + schema + pragmas."""
import sqlite3

import pytest
from lykos.db import connection
from lykos.db.connection import connect, transaction
from lykos.db.migrations import apply_migrations, current_version, init_db
from lykos.db.schema import MIGRATIONS

TABLES = {"case", "target", "artifact", "analysis_run", "run_artifact", "event",
          "schema_version"}


def _table_names(conn):
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r["name"] for r in rows}


HEAD = max(m.version for m in MIGRATIONS)


def test_fresh_init_creates_all_tables(tmp_path):
    conn = init_db(tmp_path / "x.db")
    assert current_version(conn) == HEAD
    assert TABLES.issubset(_table_names(conn))


def test_migrations_are_idempotent(tmp_path):
    conn = init_db(tmp_path / "x.db")
    v1 = current_version(conn)
    # applying again must be a no-op, not an error
    v2 = apply_migrations(conn, MIGRATIONS)
    assert v1 == v2 == HEAD
    # one applied row per migration
    n = conn.execute("SELECT COUNT(*) AS c FROM schema_version").fetchone()["c"]
    assert n == len(MIGRATIONS)


def test_queue_columns_present(tmp_path):
    conn = init_db(tmp_path / "x.db")
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(analysis_run)").fetchall()}
    assert {"claimed_by", "lease_expires_at", "attempts", "max_attempts",
            "priority", "resource_class", "cancel_requested"}.issubset(cols)


def test_pragmas_set(tmp_path):
    conn = connect(tmp_path / "x.db")
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_indexes_present(tmp_path):
    conn = init_db(tmp_path / "x.db")
    idx = {r["name"] for r in
           conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
    assert {"ix_run_case", "ix_run_cache", "ix_event_case", "ix_event_run",
            "ix_target_case"}.issubset(idx)


class _FlakyConn:
    """A connection whose BEGIN raises 'database is locked' a fixed number of times, then works.
    Everything else delegates to a real connection so COMMIT/ROLLBACK behave."""
    def __init__(self, real, fail_times):
        self._real, self._fail = real, fail_times
        self.begins = 0
        self.in_transaction = False

    def execute(self, sql, *a):
        if sql.startswith("BEGIN"):
            self.begins += 1
            if self._fail > 0:
                self._fail -= 1
                raise sqlite3.OperationalError("database is locked")
        return self._real.execute(sql, *a)


def test_transaction_rides_out_transient_lock(tmp_path):
    # A cold writer (an endpoint, say) must not 500 because the write lock was briefly held: the
    # top-level BEGIN retries past the busy_timeout wait. Three transient locks, then success.
    real = connect(tmp_path / "x.db")
    flaky = _FlakyConn(real, fail_times=3)
    with transaction(flaky):
        pass
    assert flaky.begins == 4                        # 3 locked retries + 1 that stuck


def test_transaction_gives_up_after_retries(tmp_path, monkeypatch):
    monkeypatch.setattr(connection, "_BEGIN_RETRIES", 2)
    flaky = _FlakyConn(connect(tmp_path / "x.db"), fail_times=99)
    with pytest.raises(sqlite3.OperationalError):
        with transaction(flaky):
            pass
    assert flaky.begins == 2                         # bounded: it does not spin forever


def test_transaction_reraises_non_lock_error_at_once(tmp_path):
    class _Boom:
        in_transaction = False
        def execute(self, sql, *a):
            raise sqlite3.OperationalError("no such table: nope")
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        with transaction(_Boom()):
            pass
