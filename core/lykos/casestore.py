"""DM-18 — Case directory, content-addressed store, and portable export/import.

A case is a self-contained directory:
    <case_dir>/case.db                 SQLite (WAL)
    <case_dir>/artifacts/<aa>/<bb>/<sha256>   content-addressed blobs

Export/import archive the whole directory so a case moves intact between air-gapped hosts
(doc 12). This ships a MINIMAL content store; the artifact-store epic (P0.4) formalizes it.
"""
from __future__ import annotations

import shutil
import sqlite3
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Optional, Tuple

# (table, WHERE clause, bound params) -- one copy step of a per-case export.
_CasePlan = tuple[str, str, tuple[Any, ...]]

from .db.dao import AnalysisRunDAO, ArtifactDAO, CaseDAO, EventDAO, RunArtifactDAO, TargetDAO
from .db.migrations import init_db
from .db.models import Artifact
from .hashing import hash_all_file, hash_bytes

_ARTIFACTS = "artifacts"


class ContentStore:
    """Content-addressed blob store under <case_dir>/artifacts."""

    def __init__(self, root: Path) -> None:
        self.root = root
        (self.root / _ARTIFACTS).mkdir(parents=True, exist_ok=True)

    def _rel(self, sha256: str) -> str:
        return f"{_ARTIFACTS}/{sha256[:2]}/{sha256[2:4]}/{sha256}"

    def path(self, sha256: str) -> Path:
        return self.root / self._rel(sha256)

    def exists(self, sha256: str) -> bool:
        return self.path(sha256).exists()

    def put_bytes(self, data: bytes) -> Tuple[str, str, int]:
        sha = hash_bytes(data)
        return self._place(sha, data=data), self._rel(sha), len(data)

    def put_file(self, src: str | Path) -> Tuple[str, str, int]:
        info = hash_all_file(src)
        sha = info["sha256"]
        dst = self.path(sha)
        if not dst.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
        return sha, self._rel(sha), info["size"]

    def _place(self, sha256: str, data: bytes) -> str:
        dst = self.path(sha256)
        if not dst.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
        return sha256

    def get_bytes(self, sha256: str) -> bytes:
        data = self.path(sha256).read_bytes()
        if hash_bytes(data) != sha256:  # integrity check on read
            raise IOError(f"artifact {sha256} failed integrity check")
        return data


class CaseStore:
    """Open/create a case directory and expose its DAOs + content store."""

    def __init__(self, case_dir: str | Path) -> None:
        self.dir = Path(case_dir)
        self.db_path = self.dir / "case.db"
        self.content = ContentStore(self.dir)
        self.conn = init_db(self.db_path)
        self.cases = CaseDAO(self.conn)
        self.targets = TargetDAO(self.conn)
        self.artifacts = ArtifactDAO(self.conn)
        self.run_artifacts = RunArtifactDAO(self.conn)
        self.runs = AnalysisRunDAO(self.conn)
        self.events = EventDAO(self.conn)

    @classmethod
    def open(cls, case_dir: str | Path) -> "CaseStore":
        Path(case_dir).mkdir(parents=True, exist_ok=True)
        return cls(case_dir)

    # -- high-level: store a blob AND register its artifact row in one call --
    def put_artifact(self, case_id: str, kind: str, *, data: Optional[bytes] = None,
                     src: Optional[str | Path] = None,
                     meta: Optional[dict] = None) -> Artifact:
        if (data is None) == (src is None):
            raise ValueError("provide exactly one of data= or src=")
        if data is not None:
            sha, rel, size = self.content.put_bytes(data)
        else:
            sha, rel, size = self.content.put_file(src)  # type: ignore[arg-type]
        return self.artifacts.register(sha, case_id, kind, rel, size=size, meta=meta)

    def checkpoint(self) -> None:
        """Fold the WAL into the main DB file (call before export)."""
        self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------- export / import
    def export(self, archive_path: str | Path) -> Path:
        """Archive the whole case directory (rows + artifacts) to a .tar.gz."""
        self.checkpoint()
        archive_path = Path(archive_path)
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(self.dir, arcname=self.dir.name)
        return archive_path

    def export_case(self, case_id: str, archive_path: str | Path) -> Path:
        """Archive a SINGLE logical case (rows + its artifact blobs) as a portable,
        self-contained .tar.gz that `import_archive` can merge into any store."""
        if not self.cases.get(case_id):
            raise KeyError(f"no case {case_id!r}")
        archive_path = Path(archive_path)
        tmp = Path(tempfile.mkdtemp()) / "case-export"
        dst = CaseStore.open(tmp)
        try:
            copy_case(self, dst, case_id)
            dst.checkpoint()
        finally:
            dst.close()
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(tmp, arcname="case-export")
        shutil.rmtree(tmp.parent, ignore_errors=True)
        return archive_path

    def import_archive(self, archive_path: str | Path) -> list[str]:
        """Merge every logical case from an exported archive (per-case OR whole-store)
        into THIS store. Returns the imported case ids. Idempotent (INSERT OR IGNORE)."""
        tmpdir = Path(tempfile.mkdtemp())
        try:
            with tarfile.open(archive_path, "r:gz") as tar:
                members = tar.getmembers()
                top = members[0].name.split("/")[0] if members else None
                _safe_extract(tar, tmpdir)
            if not top:
                raise IOError("empty archive")
            src = CaseStore.open(tmpdir / top)
            try:
                ids = [r["id"] for r in src.conn.execute('SELECT id FROM "case"')]
                for cid in ids:
                    copy_case(src, self, cid)
            finally:
                src.close()
            return ids
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @staticmethod
    def import_(archive_path: str | Path, dest_parent: str | Path) -> "CaseStore":
        """Extract an exported case under dest_parent and open it."""
        dest_parent = Path(dest_parent)
        dest_parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getmembers()
            top = members[0].name.split("/")[0] if members else None
            _safe_extract(tar, dest_parent)
        if not top:
            raise IOError("empty archive")
        return CaseStore.open(dest_parent / top)


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Guard against path traversal in archives (defensive; we control creation)."""
    dest = dest.resolve()
    for m in tar.getmembers():
        target = (dest / m.name).resolve()
        if not str(target).startswith(str(dest)):
            raise IOError(f"unsafe path in archive: {m.name}")
    tar.extractall(dest)


# --------------------------------------------------------------- per-case portability
# A store holds many logical cases in one DB + one content dir. These move a SINGLE case
# (its rows + referenced artifact blobs) between stores so one engagement is portable and
# self-contained (doc 12), independent of the whole-store archive above.

# Tables to copy for a case, with the WHERE that selects its rows. Order respects FKs.
def _case_tables(conn: sqlite3.Connection, case_id: str) -> list[_CasePlan]:
    tids = [r["id"] for r in
            conn.execute("SELECT id FROM target WHERE case_id=?", (case_id,))]
    rids = [r["id"] for r in
            conn.execute("SELECT id FROM analysis_run WHERE case_id=?", (case_id,))]
    plan = [('"case"', "id=?", (case_id,)),
            ("target", "case_id=?", (case_id,)),
            ("artifact", "case_id=?", (case_id,)),
            ("analysis_run", "case_id=?", (case_id,))]
    for tid in tids:
        plan += [("function", "target_id=?", (tid,)),
                 ("call_edge", "target_id=?", (tid,)),
                 ("string_ref", "target_id=?", (tid,))]
    for rid in rids:
        plan.append(("run_artifact", "run_id=?", (rid,)))
    plan += [("finding", "case_id=?", (case_id,)),
             ("dyn_result", "case_id=?", (case_id,)),
             ("poc", "case_id=?", (case_id,)),
             ("component_edge", "case_id=?", (case_id,)),
             ("event", "case_id=?", (case_id,))]
    return plan


def _copy_rows(sc: sqlite3.Connection, dc: sqlite3.Connection, table: str, where: str,
               params: tuple[Any, ...], *, drop_cols: tuple[str, ...] = ()) -> None:
    rows = sc.execute(f"SELECT * FROM {table} WHERE {where}", params).fetchall()
    if not rows:
        return
    cols = [c for c in rows[0].keys() if c not in drop_cols]
    collist = ",".join(f'"{c}"' for c in cols)
    ph = ",".join("?" * len(cols))
    dc.executemany(f'INSERT OR IGNORE INTO {table}({collist}) VALUES({ph})',
                   [tuple(r[c] for c in cols) for r in rows])


def copy_case(src: "CaseStore", dst: "CaseStore", case_id: str) -> None:
    """Copy one logical case (rows + artifact blobs) from src into dst (idempotent)."""
    for table, where, params in _case_tables(src.conn, case_id):
        # event.id is per-store autoincrement -> drop it so dst assigns fresh ids
        drop = ("id",) if table == "event" else ()
        _copy_rows(src.conn, dst.conn, table, where, params, drop_cols=drop)
    dst.conn.commit()
    for r in dst.conn.execute("SELECT DISTINCT sha256 FROM artifact WHERE case_id=?",
                              (case_id,)):
        sha = r["sha256"]
        if src.content.exists(sha) and not dst.content.exists(sha):
            dst.content.put_bytes(src.content.get_bytes(sha))
