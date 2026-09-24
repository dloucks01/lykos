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
import subprocess
import tarfile
import tempfile
import warnings
from pathlib import Path
from typing import Any, Optional, Tuple

# (table, WHERE clause, bound params) -- one copy step of a per-case export.
_CasePlan = tuple[str, str, tuple[Any, ...]]

from .db.connection import transaction
from .db.dao import AnalysisRunDAO, ArtifactDAO, CaseDAO, EventDAO, RunArtifactDAO, TargetDAO
from .db.migrations import init_db
from .db.models import Artifact
from .hashing import hash_all_file, hash_bytes

_ARTIFACTS = "artifacts"


def _make_runnable(exe: Path, workdir: Path) -> None:
    """Make a staged bundled binary run from ANY cwd: repoint a RELATIVE ELF interpreter (a
    challenge's ./ld-2.31.so) at the staged loader by absolute path, and add the staged dir to the
    rpath so the bundled libc is found. Best-effort via patchelf; if patchelf is absent the binary
    is left as-is and still runs when the caller's cwd is the staged dir. Never fatal."""
    pe = shutil.which("patchelf")
    if not pe:
        return
    try:
        interp = subprocess.run([pe, "--print-interpreter", str(exe)], capture_output=True,
                                text=True, timeout=20).stdout.strip()
    except Exception:                                    # noqa: BLE001 -- static exe / no interp
        interp = ""
    args = [pe]
    if interp and not interp.startswith("/"):            # a relative, bundled loader
        loader = workdir / Path(interp).name
        if not loader.exists():
            cand = workdir / interp.lstrip("./")         # e.g. ./glibc/ld-linux-x86-64.so.2
            if cand.exists():
                loader = cand
        if loader.exists():
            args += ["--set-interpreter", str(loader)]
    args += ["--set-rpath", str(workdir), str(exe)]      # bundled libc found regardless of cwd
    try:
        subprocess.run(args, capture_output=True, timeout=30)
    except Exception:                                    # noqa: BLE001 -- best-effort
        pass


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

    def stage_target(self, target, workdir, name: str = "target.bin", *,
                     mode: int = 0o755) -> Path:
        """Materialise a target for RUNNING: write its binary to <workdir>/<name> and every
        companion dep (a bundled loader / libc / data file) to its path RELATIVE to the workdir,
        so the binary's relative ELF interpreter (e.g. ./ld-2.31.so) resolves when it runs with
        cwd=workdir. Returns the staged binary Path. A target with no deps just writes the binary,
        so callers can use this unconditionally in place of a bare content read + write.
        """
        workdir = Path(workdir)
        exe = workdir / name
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.write_bytes(self.path(target.sha256).read_bytes())
        try:
            exe.chmod(mode)
        except OSError:
            pass
        deps = getattr(target, "deps", None) or {}
        for rel, sha in deps.items():
            rp = Path(rel)
            if rp.is_absolute() or ".." in rp.parts:     # never let a dep escape the workdir
                continue
            dst = workdir / rp
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(self.path(sha).read_bytes())
                dst.chmod(0o755)
            except OSError:
                pass
        if deps:
            _make_runnable(exe, workdir)                  # cwd-independent interp/libc resolution
        return exe


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
                    conflicts = copy_case(src, self, cid)
                    if conflicts:
                        # Import is add-only: these rows changed in the source but the
                        # destination already had a differing copy, which was kept. Surface it
                        # rather than let a stale finding/target/run pass unnoticed.
                        warnings.warn(
                            f"import kept {len(conflicts)} stale row(s) for case {cid!r} "
                            f"(add-only import does not overwrite): "
                            + ", ".join(f"{c['table']}{tuple(c['pk'].values())}"
                                        for c in conflicts[:8])
                            + (" ..." if len(conflicts) > 8 else ""),
                            stacklevel=2)
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
        # Reject link/device members outright: a symlink or hardlink member can point outside
        # the case dir so a following member writes THROUGH it (the name-path check below only
        # covers where the entry itself lands, not where a link redirects a later write). We
        # only ever emit plain files and dirs, so anything else is hostile.
        if m.issym() or m.islnk() or m.isdev():
            raise IOError(f"unsafe member in archive: {m.name}")
        target = (dest / m.name).resolve()
        # Containment by path components, not string prefix: a startswith check lets a member
        # resolving to a SIBLING (dest="/tmp/abc", target="/tmp/abc-evil/x") pass.
        if target != dest and dest not in target.parents:
            raise IOError(f"unsafe path in archive: {m.name}")
    # `filter="data"` (Python 3.12+) is the hardened extractor realgate.py already uses; fall
    # back on older Pythons that lack the kwarg. The explicit link/dev rejection above keeps the
    # protection on every version regardless of whether the filter is available.
    try:
        tar.extractall(dest, filter="data")
    except TypeError:
        tar.extractall(dest)


# --------------------------------------------------------------- per-case portability
# A store holds many logical cases in one DB + one content dir. These move a SINGLE case
# (its rows + referenced artifact blobs) between stores so one engagement is portable and
# self-contained (doc 12), independent of the whole-store archive above.

# Tables to copy for a case, with the WHERE that selects its rows. Order respects FKs.
def _case_artifact_shas(conn: sqlite3.Connection, case_id: str) -> list[str]:
    """Every artifact blob the case needs to be self-contained: the ones it OWNS
    (artifact.case_id) plus the ones its runs merely REFERENCE through run_artifact. A cache
    hit (queue._materialize_cache_hit) links a blob first registered under another case, so
    selecting artifacts by case_id alone leaves run_artifact rows pointing at blobs the export
    omitted -- a foreign-key failure on import, or a case that is missing its own outputs."""
    shas = {r["sha256"] for r in
            conn.execute("SELECT sha256 FROM artifact WHERE case_id=?", (case_id,))}
    shas |= {r["artifact_sha256"] for r in conn.execute(
        "SELECT ra.artifact_sha256 FROM run_artifact ra "
        "JOIN analysis_run r ON r.id=ra.run_id WHERE r.case_id=?", (case_id,))}
    return sorted(shas)


def _case_tables(conn: sqlite3.Connection, case_id: str) -> list[_CasePlan]:
    tids = [r["id"] for r in
            conn.execute("SELECT id FROM target WHERE case_id=?", (case_id,))]
    rids = [r["id"] for r in
            conn.execute("SELECT id FROM analysis_run WHERE case_id=?", (case_id,))]
    # finding_site / finding_verdict carry no case_id -- they hang off finding(id). Select
    # them by the case's finding ids, or export/import silently drops which sites are proven
    # and every channel's standing verdict (the exact loss migration 12's seed guards against).
    fids = [r["id"] for r in
            conn.execute("SELECT id FROM finding WHERE case_id=?", (case_id,))]
    shas = _case_artifact_shas(conn, case_id)
    art_where = f"sha256 IN ({','.join('?' * len(shas))})" if shas else "0=1"
    plan = [('"case"', "id=?", (case_id,)),
            ("target", "case_id=?", (case_id,)),
            ("artifact", art_where, tuple(shas)),
            ("analysis_run", "case_id=?", (case_id,))]
    for tid in tids:
        plan += [("function", "target_id=?", (tid,)),
                 ("call_edge", "target_id=?", (tid,)),
                 ("string_ref", "target_id=?", (tid,))]
    for rid in rids:
        plan.append(("run_artifact", "run_id=?", (rid,)))
    plan.append(("finding", "case_id=?", (case_id,)))
    # Must follow `finding` (FK finding_id -> finding.id, foreign_keys=ON on import).
    fid_where = f"finding_id IN ({','.join('?' * len(fids))})" if fids else "0=1"
    plan += [("finding_site", fid_where, tuple(fids)),
             ("finding_verdict", fid_where, tuple(fids))]
    plan += [("dyn_result", "case_id=?", (case_id,)),
             ("poc", "case_id=?", (case_id,)),
             ("component_edge", "case_id=?", (case_id,)),
             ("event", "case_id=?", (case_id,))]
    return plan


# Mutable tables whose rows can legitimately CHANGE in the source between exports (a finding
# gets promoted, triage fields are refined, a run finishes). Import is add-only (INSERT OR
# IGNORE), so a changed row is silently skipped and the destination keeps the stale copy. For
# these we detect that case by primary key and surface it as a conflict rather than swallowing
# it. Content-addressed / append-only tables are not listed: artifact is deliberately re-homed
# on conflict, and event ids are reassigned so every row is genuinely new.
_MUTABLE_PK: dict[str, tuple[str, ...]] = {
    "finding": ("id",),
    "target": ("id",),
    "analysis_run": ("id",),
}

# analysis_run rows in a NON-terminal status carry live queue state (a claim, a lease, a
# heartbeat) that means nothing in the destination store -- importing them verbatim leaves the
# destination pool with phantom `running`/`queued` jobs it would claim and re-execute. On copy
# we neutralize that state: strip the claim/lease/heartbeat and settle a non-terminal status to
# `error` so the imported run is an inert record of what happened, not a job to run.
_TERMINAL_RUN_STATUSES = frozenset({"done", "error", "cancelled"})


def _copy_rows(sc: sqlite3.Connection, dc: sqlite3.Connection, table: str, where: str,
               params: tuple[Any, ...], *, drop_cols: tuple[str, ...] = (),
               override: Optional[dict[str, Any]] = None,
               conflicts: Optional[list[dict[str, Any]]] = None) -> None:
    rows = sc.execute(f"SELECT * FROM {table} WHERE {where}", params).fetchall()
    if not rows:
        return
    cols = [c for c in rows[0].keys() if c not in drop_cols]
    collist = ",".join(f'"{c}"' for c in cols)
    ph = ",".join("?" * len(cols))
    ov = override or {}
    # An override value may be a callable, computed per source row (used to settle a run's
    # non-terminal status against the row's own current status); a plain value applies as-is.
    def _val(c: str, r: sqlite3.Row) -> Any:
        if c not in ov:
            return r[c]
        return ov[c](r) if callable(ov[c]) else ov[c]
    vals = [tuple(_val(c, r) for c in cols) for r in rows]

    pk = _MUTABLE_PK.get(table)
    if pk and conflicts is not None:
        # Add-only import: report any row whose PK already exists in dst with DIFFERING content,
        # so a stale skip is visible instead of silent. (Detection only -- the INSERT OR IGNORE
        # below still keeps the destination row; import does not overwrite.)
        idx = {c: i for i, c in enumerate(cols)}
        for v in vals:
            pkwhere = " AND ".join(f'"{c}"=?' for c in pk)
            pkvals = tuple(v[idx[c]] for c in pk)
            existing = dc.execute(
                f'SELECT {collist} FROM {table} WHERE {pkwhere}', pkvals).fetchone()
            if existing is not None and tuple(existing) != v:
                conflicts.append({"table": table,
                                  "pk": {c: v[idx[c]] for c in pk}})

    dc.executemany(f'INSERT OR IGNORE INTO {table}({collist}) VALUES({ph})', vals)


def copy_case(src: "CaseStore", dst: "CaseStore", case_id: str) -> list[dict[str, Any]]:
    """Copy one logical case (rows + artifact blobs) from src into dst (idempotent).

    Import is ADD-ONLY: rows are inserted with INSERT OR IGNORE, so a row already present in
    dst is kept as-is and never overwritten. When the source has a CHANGED version of a mutable
    row (a promoted finding, refined triage, a finished run), that change is skipped -- this
    returns the list of such conflicts so the caller can surface them instead of losing them
    silently. Returns [] on a clean copy.

    The row copy is one transaction: a mid-copy failure (e.g. a foreign-key violation) must
    leave dst untouched rather than a half-imported case. Blobs are content-addressed and
    copied after commit -- putting an already-present blob is a no-op."""
    shas = _case_artifact_shas(src.conn, case_id)
    conflicts: list[dict[str, Any]] = []
    with transaction(dst.conn):
        for table, where, params in _case_tables(src.conn, case_id):
            # event.id is per-store autoincrement -> drop it so dst assigns fresh ids
            drop = ("id",) if table == "event" else ()
            # An artifact may be owned by another case (a cache hit shares one content-addressed
            # blob); re-home it to THIS case so the export is self-contained and artifact.case_id
            # still references a case that travels with it. ON CONFLICT keeps an existing owner.
            override: Optional[dict[str, Any]] = None
            if table == "artifact":
                override = {"case_id": case_id}
            elif table == "analysis_run":
                # Neutralize live queue state so an imported run is inert (see _TERMINAL_RUN_STATUSES).
                override = {
                    "status": lambda r: (r["status"] if r["status"] in _TERMINAL_RUN_STATUSES
                                         else "error"),
                    "claimed_by": None,
                    "lease_expires_at": None,
                    "heartbeat_at": None,
                }
            _copy_rows(src.conn, dst.conn, table, where, params,
                       drop_cols=drop, override=override, conflicts=conflicts)
    for sha in shas:
        if src.content.exists(sha) and not dst.content.exists(sha):
            dst.content.put_bytes(src.content.get_bytes(sha))
    return conflicts
