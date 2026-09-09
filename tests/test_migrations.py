"""DM-19 — migration runner + schema + pragmas."""
from lykos.db.connection import connect
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
