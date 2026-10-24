"""Operator-facing endpoints added for CLI parity and run honesty, as a Handler mixin.

  GET    /cases/<id>/run-signals        the run's honesty signals (api/runsignals.py)
  GET    /targets/<id>/crash-triage     crashes grouped by root cause, ranked (api/triage.py)
  GET    /cases/<id>/seeds              operator seed files stored in the case
  POST   /cases/<id>/seeds              upload one seed (raw body + X-Filename, or multipart)
  DELETE /cases/<id>/seeds/<sha>        drop a seed from the case's seed set
  GET    /doctor                        engine readiness on this host (`lykos doctor`)
  GET    /version                       which build is serving (api/buildinfo.py)

Seeds are the GUI's answer to the CLI's `--seed FILE`: the CLI hands the autopilot server PATHS,
which a browser cannot (and must not be able to) name. The browser uploads the bytes instead;
they are stored content-addressed in the case store, recorded in the case's event log
(`operator.seed`), and resolved back to their store paths only when the autopilot is started
with `overrides.seed_shas` -- so a request can reference a seed of THIS case and nothing else on
the server's filesystem.
"""
from __future__ import annotations

import logging
import tempfile
import threading
import time
from pathlib import Path

from .. import observe

_log = logging.getLogger(__name__)

#: Largest seed accepted. Mirrors the fuzz stage's `_MAX_SEED_BYTES`: a bigger file would be
#: stored and then silently skipped by the loader, which is worse than refusing it here.
MAX_SEED_BYTES = 1 << 20
#: Seeds per case (the campaign corpus is bounded too; past this they add nothing).
MAX_CASE_SEEDS = 64
#: Multipart framing allowance on top of the seed itself.
_SEED_BODY_SLACK = 64 << 10
SEED_EVENT = "operator.seed"

#: Doctor results are cached: a full survey spawns many subprocess probes (several seconds).
_DOCTOR_TTL = 600.0
_DOCTOR = {"state": "idle", "at": 0.0, "result": None, "error": None, "thread": None}
_DOCTOR_LOCK = threading.Lock()


def case_seeds(conn, case_id: str) -> list[dict]:
    """The case's current seed set, folded from its `operator.seed` add/remove events."""
    from ..db.dao import EventDAO
    seeds: dict = {}
    for p in EventDAO(conn).payloads_of_type(SEED_EVENT, case_id=case_id):
        sha = p.get("sha256")
        if not isinstance(sha, str):
            continue
        if p.get("action") == "remove":
            seeds.pop(sha, None)
        else:
            seeds[sha] = {"sha256": sha, "name": p.get("name"), "size": p.get("size")}
    return list(seeds.values())


def _run_survey():
    from .. import toolchain, vendorenv
    try:
        rows = toolchain.survey()
        tools = [{"key": t.key, "title": t.title, "tier": t.tier, "found": got,
                  "present": bool(got), "unlocks": t.unlocks, "without": t.without,
                  "install": t.install} for t, got in rows]
        try:
            line = vendorenv.status_line()
        except Exception:                                # noqa: BLE001
            line = None
        missing_req = [t["title"] for t in tools if t["tier"] == "required" and not t["present"]]
        res = {"tools": tools, "toolchain": line, "present": sum(t["present"] for t in tools),
               "total": len(tools), "required_missing": missing_req}
        with _DOCTOR_LOCK:
            _DOCTOR.update(state="done", at=time.time(), result=res, error=None)
    except Exception as e:                               # noqa: BLE001 -- reported, not raised
        observe.absorbed(_log, "doctor survey failed")
        with _DOCTOR_LOCK:
            _DOCTOR.update(state="error", at=time.time(), error=repr(e)[:300])


class OpsMixin:
    # ---- run honesty signals -------------------------------------------------------------
    def _get_run_signals(self, cid):
        from . import runsignals
        from .autopilot import AutopilotMixin
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            names = {t.id: t.filename for t in s.targets.list_by_case(cid)}
            rows = runsignals.signal_rows(s.conn, str(self.server.case_dir), cid)
        finally:
            s.close()
        with AutopilotMixin._AUTOPILOTS_LOCK:
            rec = AutopilotMixin._AUTOPILOTS.get(cid)
            running = bool(rec and rec["thread"].is_alive())
        return self._json(runsignals.summarize(rows, running=running, filenames=names))

    # ---- crash triage --------------------------------------------------------------------
    def _get_crash_triage(self, tid):
        from ..db.dao import DynResultDAO, FindingDAO, PocDAO
        from . import triage
        from .serializers import _dynresult, _finding, _poc
        try:
            from ..analyze.orchestrate import _MAX_DISTINCT_CRASHES as cap
        except Exception:                                # noqa: BLE001 -- the cap is advisory
            cap = None
        s = self._store()
        try:
            if not s.targets.get(tid):
                return self._json({"error": "no target"}, 404)
            dyns = []
            for d in DynResultDAO(s.conn).list_by_target(tid):
                if d.crashed:
                    row = _dynresult(d)
                    row["defect_key"] = getattr(d, "defect_key", None)
                    dyns.append(row)
            fs = [_finding(f) for f in FindingDAO(s.conn).list_by_target(tid)]
            ps = [_poc(p) for p in PocDAO(s.conn).list_by_target(tid)]
        finally:
            s.close()
        return self._json(triage.crash_groups(dyns, fs, ps, prove_cap=cap))

    # ---- operator seeds ------------------------------------------------------------------
    def _get_seeds(self, cid):
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            return self._json({"seeds": case_seeds(s.conn, cid), "max_bytes": MAX_SEED_BYTES,
                               "max_seeds": MAX_CASE_SEEDS})
        finally:
            s.close()

    def _upload_seed(self, cid):
        from .endpoints import _extract_upload
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404, close=True)
            current = case_seeds(s.conn, cid)
            if len(current) >= MAX_CASE_SEEDS:
                return self._json({"error": f"a case holds at most {MAX_CASE_SEEDS} seeds; "
                                            "remove one first"}, 400, close=True)
            with tempfile.TemporaryDirectory(prefix="lykos-seed-") as td:
                tdp = Path(td)
                raw = tdp / "body.bin"
                if not self._read_body_to_file(raw, MAX_SEED_BYTES + _SEED_BODY_SLACK):
                    return self._json({"error": f"seed too large (max {MAX_SEED_BYTES} bytes) "
                                                "or malformed body"}, 413, close=True)
                try:
                    filename, path = _extract_upload(self.headers.get("Content-Type", ""), raw,
                                                     tdp, self.headers.get("X-Filename"))
                except ValueError as e:
                    return self._json({"error": str(e)}, 400, close=True)
                size = path.stat().st_size
                if size > MAX_SEED_BYTES:
                    return self._json({"error": f"seed too large (max {MAX_SEED_BYTES} bytes)"},
                                      413)
                if size == 0:
                    return self._json({"error": "empty seed"}, 400)
                data = path.read_bytes()
            # The name is display-only (never a path on this side): basename, printable, bounded.
            name = Path(filename or "seed.bin").name or "seed.bin"
            name = "".join(ch for ch in name if ch.isprintable())[:120] or "seed.bin"
            art = s.put_artifact(cid, "operator-seed", data=data, meta={"name": name})
            sha = art.sha256
            if not any(x["sha256"] == sha for x in current):
                s.events.append(SEED_EVENT, case_id=cid,
                                payload={"action": "add", "sha256": sha, "name": name,
                                         "size": size})
            return self._json({"sha256": sha, "name": name, "size": size}, 201)
        finally:
            s.close()

    def _delete_seed(self, cid, sha):
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            if not any(x["sha256"] == sha for x in case_seeds(s.conn, cid)):
                return self._json({"error": "no such seed in this case"}, 404)
            s.events.append(SEED_EVENT, case_id=cid, payload={"action": "remove", "sha256": sha})
            return self._json({"removed": sha})
        finally:
            s.close()

    def _resolve_seed_shas(self, cid, shas):
        """seed_shas from an autopilot request -> ([store paths], None) or (None, error)."""
        if not (isinstance(shas, list) and all(isinstance(x, str) for x in shas)):
            return None, "overrides.seed_shas must be a list of seed hashes"
        s = self._store()
        try:
            have = {x["sha256"] for x in case_seeds(s.conn, cid)}
        finally:
            s.close()
        unknown = [x for x in shas if x not in have]
        if unknown:
            return None, f"seed(s) not in this case: {', '.join(u[:12] for u in unknown[:5])}"
        paths = []
        for sha in dict.fromkeys(shas):
            p = self.server.content.path(sha)
            if not p.is_file():
                return None, f"seed {sha[:12]} is missing from the case store"
            paths.append(str(p))
        return paths, None

    # ---- engine readiness (doctor) -------------------------------------------------------
    def _get_doctor(self, qs):
        refresh = (qs.get("refresh") or ["0"])[0] in ("1", "true", "yes")
        with _DOCTOR_LOCK:
            stale = _DOCTOR["result"] is None or time.time() - _DOCTOR["at"] > _DOCTOR_TTL
            busy = _DOCTOR["thread"] is not None and _DOCTOR["thread"].is_alive()
            if (refresh or stale or _DOCTOR["state"] == "error") and not busy:
                th = threading.Thread(target=_run_survey, name="lykos-doctor", daemon=True)
                _DOCTOR.update(state="probing", thread=th)
                th.start()
                busy = True
            out = {"state": "probing" if busy else _DOCTOR["state"],
                   "checked_at": _DOCTOR["at"] or None, "error": _DOCTOR["error"]}
            if _DOCTOR["result"] is not None:
                out.update(_DOCTOR["result"])
        return self._json(out)

    # ---- build / version -----------------------------------------------------------------
    def _get_version(self):
        from .buildinfo import build_info
        try:
            return self._json(build_info())
        except Exception as e:                           # noqa: BLE001 -- never 500 a footer
            observe.absorbed(_log, "build info unavailable")
            return self._json({"version": None, "display": "lykos (build unknown)",
                               "error": repr(e)[:200]})
