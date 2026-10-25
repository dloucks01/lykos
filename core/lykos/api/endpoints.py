"""The analyst API endpoint handlers, split out of `server.py` as a mixin.

`server.Handler` mixes this in, so every handler keeps full access to the request/response
helpers (`self._json`, `self._store`, `self._read_body`, `self.server`) and the routing dicts
(`self._CASE_STAGES`, `self._TARGET_STAGES`) via the MRO. Behaviour is unchanged; this only moves
the ~900 lines of endpoint bodies out of the 1600-line server module.
"""
from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import observe
from ..casestore import CaseStore  # noqa: F401  (some handlers construct it directly)
from ..db.dao import DynResultDAO, FindingDAO, FunctionDAO, PocDAO, StringDAO
from ..jobs import JobQueue
from .multipart import extract_file, extract_file_to, parse_boundary
from .serializers import (
    _INGEST,
    _REPORT_FORMATS,
    _case,
    _csv,
    _event,
    _finding,
    _function,  # noqa: F401
    _run,
    _target,
)

_log = logging.getLogger(__name__)

# Bodies at or below this size are extracted in memory (the proven, simple path); larger uploads
# have their file part streamed to disk so a big binary/firmware never sits fully in RAM.
_INMEM_LIMIT = 16 << 20


# Archive formats that ARE themselves an analysable target, not a bundle to unpack: a .jar/.war/
# .ear/.aar is JVM bytecode and a .apk is an Android package -- all zips, but ingest() analyses
# them whole. Unpacking one yields only .class/resource files and no native binary, so a valid
# upload was refused with "no analysable binary found in the bundle". Match on the name, since the
# magic is just "a zip".
_SELF_CONTAINED_ARCHIVES = (".jar", ".war", ".ear", ".aar", ".apk")


#: Ceilings on what an uploaded BUNDLE may expand to. The upload itself is capped at the 1 GiB
#: request ceiling, but a zip/tar can declare far more than it carries (a zip bomb: a few MB that
#: inflates to many GB, or millions of empty members), and extraction ran with no bound at all --
#: filling the server's temp disk or pinning a request thread. Twice the request ceiling covers a
#: real firmware/challenge bundle with room to spare; 20,000 members covers a large rootfs.
_MAX_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_BUNDLE_MEMBERS = 20_000


#: Stage params that name a server-side path or tool binary: CLI-only (see `_create_run`).
_CLI_ONLY_PARAMS = frozenset({"seed_files", "seed_dir", "afl_path", "gdb_path", "symqemu_path",
                              "angr_python", "unicorn_python"})
#: Stages that take operator seeds (`seed_shas` from the browser, resolved to `seed_files`).
_SEEDED_STAGES = frozenset({"fuzz", "coverage_fuzz", "directed_fuzz", "diff_test"})


class BundleRejected(Exception):
    """An archive upload that would exceed the expansion ceilings. Carries the HTTP status."""

    def __init__(self, msg: str, status: int = 413):
        super().__init__(msg)
        self.status = status


def _check_bundle_budget(sizes, what: str) -> None:
    """Refuse an archive whose declared members exceed the ceilings, BEFORE writing anything.

    The declared sizes are binding: zipfile stops a member at its declared `file_size` (and fails
    its CRC when the data disagrees) and tarfile copies exactly the header's size, so their sum is
    what extraction can write."""
    n = total = 0
    for sz in sizes:
        n += 1
        total += max(0, int(sz or 0))
        if n > _MAX_BUNDLE_MEMBERS:
            raise BundleRejected(f"{what} has more than {_MAX_BUNDLE_MEMBERS} members; refusing "
                                 "to extract it (upload the binary and its libraries directly, "
                                 "or a smaller archive)", 400)
        if total > _MAX_BUNDLE_BYTES:
            raise BundleRejected(f"{what} expands to more than {_MAX_BUNDLE_BYTES >> 30} GiB; "
                                 "refusing to extract it", 413)


def _maybe_extract_bundle(upload: Path, td: Path, filename: str = ""):
    """If `upload` is a zip/tar archive (a zipped challenge bundle), extract it SAFELY to a temp
    directory and return that dir for ingest() to treat as a bundle; otherwise return None. Path
    traversal / absolute members are dropped so an archive can never write outside the temp dir.
    A self-contained JVM/Android archive (.jar/.apk/...) is left alone -- it IS the target. The
    real name comes in via `filename`, since `upload` is a streamed temp path (part.bin)."""
    upload = Path(upload)
    if Path(filename or upload.name).suffix.lower() in _SELF_CONTAINED_ARCHIVES:
        return None
    dest = td / "bundle"
    try:
        if zipfile.is_zipfile(upload):
            with zipfile.ZipFile(upload) as z:
                infos = z.infolist()
                _check_bundle_budget((i.file_size for i in infos), "the zip archive")
                for info in infos:
                    m = info.filename
                    mp = Path(m)
                    if m.endswith("/") or mp.is_absolute() or ".." in mp.parts:
                        continue
                    z.extract(info, dest)
            return dest if any(dest.rglob("*")) else None
        if tarfile.is_tarfile(upload):
            with tarfile.open(upload) as tf:
                # getmembers() reads headers only (a compressed tar is streamed through, never
                # written), so the budget is checked before a byte lands on disk.
                members = tf.getmembers()
                _check_bundle_budget((m.size if m.isfile() else 0 for m in members),
                                     "the tar archive")
                tf.extractall(dest, filter="data")   # 'data' filter blocks traversal/special files
            return dest if any(dest.rglob("*")) else None
    except BundleRejected:
        raise                                        # an over-ceiling archive is refused, not
                                                     # silently ingested as one opaque file
    except Exception:                                # noqa: BLE001 -- a bad archive falls back to
        pass                                         # ingesting the upload as a single file
    return None


def _extract_upload(ctype: str, raw: Path, td: Path, x_filename):
    """(filename, path) of the file to ingest from a body already streamed to `raw`.

    A NON-multipart body is a raw octet-stream upload (the body file itself). A MULTIPART body is
    parsed: small ones in memory, large ones streamed to disk. When the streamed extractor cannot
    cheaply locate the file part in a large multipart body, we fall back to the correct in-memory
    parse -- and if even that fails, raise -- rather than ingesting the FRAMED body (boundaries +
    part headers) as if it were the binary, which silently feeds the analysis the wrong bytes.
    """
    if parse_boundary(ctype) is None:           # not multipart -> raw octet-stream upload
        return (x_filename or "upload.bin"), raw

    def _inmem():
        filename, data = extract_file(ctype, raw.read_bytes())
        if data is None:
            raise ValueError("multipart body: could not locate the uploaded file part")
        part = td / "part.bin"
        part.write_bytes(data)
        return filename, part

    if raw.stat().st_size <= _INMEM_LIMIT:
        return _inmem()
    fn = extract_file_to(ctype, raw, td / "part.bin")
    if fn is not None:
        return fn, (td / "part.bin")
    return _inmem()                             # streamed locate failed: parse correctly, don't ingest raw


def _hexdump(data: bytes, limit: int = 1024) -> str:
    """A classic `offset  hex bytes  |ascii|` hexdump of up to `limit` bytes -- for showing an
    exploit payload inline in the inspector rather than only offering it as a download."""
    data = data[:limit]
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        hexpart = f"{hexpart[:23]:<23} {hexpart[24:]:<23}" if len(chunk) > 8 else f"{hexpart:<23}"
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart}  |{ascii_}|")
    return "\n".join(lines)


class EndpointsMixin:
    # ---- operator curation (doc 47 P3) -- see api/curation.py for the event-sourced model ----
    @staticmethod
    def _curation_map(s, case_id) -> dict:
        """{finding_id: curation} for a case. Best-effort: a curation read that fails must never
        take the findings list down with it, so it degrades to "nothing curated" and is logged."""
        from . import curation
        try:
            return curation.current_for_case(s.conn, case_id) if case_id else {}
        except Exception:
            observe.absorbed(_log, "serving findings without curation")
            return {}

    @staticmethod
    def _with_curation(d: dict, cur: dict) -> dict:
        """Attach the operator's verdict BESIDE the tool's own fields (never over `state`)."""
        c = cur.get(d.get("id"))
        d["curation"] = ({"status": c["status"], "note": c["note"],
                          "updated_at": c["updated_at"]} if c else None)
        return d

    def _get_case_curation(self, cid):
        from . import curation
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            return self._json({"curation": curation.current_for_case(s.conn, cid),
                               "statuses": list(curation.STATUSES),
                               "labels": curation.STATUS_LABEL})
        finally:
            s.close()

    def _get_finding_curation(self, fid):
        from . import curation
        s = self._store()
        try:
            f = FindingDAO(s.conn).get(fid)
            if not f:
                return self._json({"error": "no finding"}, 404)
            cur = curation.current_for_case(s.conn, f.case_id).get(fid)
            return self._json({"finding_id": fid, "current": cur,
                               "history": curation.history_for_finding(s.conn, f.case_id, fid)})
        finally:
            s.close()

    def _set_finding_curation(self, fid):
        """POST {status: false_positive|true_positive|needs_review|null, note: str}. Records the
        operator's verdict as an append-only case event; the finding row itself is untouched."""
        from . import curation
        body = self._json_body()
        if body is None:
            return
        try:
            status, note = curation.validate(body)
        except curation.CurationError as e:
            return self._json({"error": str(e), "statuses": list(curation.STATUSES)}, 400)
        s = self._store()
        try:
            f = FindingDAO(s.conn).get(fid)
            if not f:
                return self._json({"error": "no finding"}, 404)
            return self._json(curation.record(s, f, status, note))
        finally:
            s.close()

    def _get_capabilities(self, tid):
        """What this target can and cannot have done to it, and why not.

        Separate from /advice on purpose: advice says what to do NEXT, this says what is
        POSSIBLE at all. The workbench needs both -- it highlights the recommendation and
        disables the impossible with its reason, instead of rendering the same twenty-two
        controls for an ELF, a PE, a jar and a firmware image.
        """
        from ..analyze import capabilities as capmod
        s = self._store()
        try:
            t = s.targets.get(tid)
            if not t:
                return self._json({"error": "no target"}, 404)
            plan = []
            try:
                plan = (self._advice_for(s, t) or {}).get("plan") or []
            except Exception:
                observe.absorbed(_log, "continuing")
            done = {r.stage for r in s.runs.list_by_case(t.case_id)
                    if r.target_id == tid and r.status == "done"}
            return self._json({
                "target": tid, "file_type": t.file_type, "arch": t.arch,
                "groups": [{"key": k, "label": lab, "why": why}
                           for k, lab, why in capmod.GROUPS],
                "stages": capmod.for_target(t, plan=plan, done=done),
                "unavailable": capmod.unavailable_summary(t),
            })
        finally:
            s.close()

    def _coverage_blocked(self, t):
        try:
            from ..analyze.fuzz.coverage import _unsupported
            return _unsupported(t)
        except Exception:
            observe.absorbed(_log, "answering None")
            return None

    def _target_strings(self, s, tid):
        """The target's strings -- from the DB if `disassemble` has run, else scanned from the
        bytes. Requiring Ghidra first would put the answer to "how do I run this" behind the
        analysis it is needed to set up."""
        from ..analyze import invocation as invmod
        rows = [x.value for x in StringDAO(s.conn).list_by_target(tid) if x.value]
        if rows:
            return rows
        t = s.targets.get(tid)
        return invmod.raw_strings(s.content.path(t.sha256).read_bytes()) if t else []

    def _check_invocation(self, tid):
        """Propose a command line for this target -- and RUN it to see if the target accepts.

        A proposal read off the strings is a hypothesis. Applying one unchecked produces the
        exact failure it exists to fix: unzip needs no flags, and `-d <dir> -x x` is a worse
        command line than none at all. The target's own refusal is quoted back.
        """
        from ..analyze import invocation as invmod
        from ..analyze.dynamic import sandbox
        body = self._json_body()
        if body is None:
            return
        _argv = body.get("argv")
        if _argv is not None and not (isinstance(_argv, list)
                                      and all(isinstance(a, str) for a in _argv)):
            # a STRING argv was iterated character by character into the sandbox command line
            return self._json({"error": "argv must be a list of strings"}, 400)
        try:                                             # a bad value is a 400, not a 500
            _tmo = float(body.get("timeout", 15))
            _sample = (base64.b64decode(body["sample_b64"])
                       if body.get("sample_b64") else b"name=lykos\n")
        except (ValueError, TypeError, binascii.Error):
            return self._json({"error": "invalid timeout or sample_b64"}, 400)
        s = self._store()
        try:
            t = s.targets.get(tid)
            if not t:
                return self._json({"error": "no target"}, 404)
            found = invmod.discover(self._target_strings(s, tid),
                                    usage_hint=body.get("usage_hint"),
                                    prog=getattr(t, "filename", None))
            d = Path(tempfile.mkdtemp(prefix="lykos-invocation-"))
            try:
                # Into the EXE's directory: the sandbox masks /tmp and binds back only that
                # one, so a jar or config written elsewhere does not exist for the target.
                argv = body.get("argv") or invmod.materialize(found, d)
                found["proposed_argv"] = argv
                if not body.get("verify", True) or not argv:
                    return self._json(found)
                exe = d / "target.bin"
                exe.write_bytes(s.content.path(t.sha256).read_bytes())
                os.chmod(exe, 0o755)
                sample = d / "sample.bin"
                sample.write_bytes(_sample)

                def _run(a):
                    return sandbox.run(exe, argv=a, stdin=b"", timeout=_tmo,
                                       arch=t.arch, endianness=t.endianness, bits=t.bits)
                found["verified"] = invmod.verify(_run, exe, argv, str(sample))
            finally:
                shutil.rmtree(d, ignore_errors=True)
            return self._json(found)
        finally:
            s.close()

    def _replay_input(self, tid):
        """Re-run a crashing input several times to confirm it is a TRUE, deterministic crash.

        A demonstrated finding is only trustworthy if its own reproducer fires every time; a
        crash that appears once in five runs is flaky evidence, not a proof. This is the
        false-positive review: it replays the recorded crashing input in the sandbox N times
        and reports how many crashed and with which signal, so the workbench can badge a finding
        verified or flag it flaky. Bounded (<=10 runs, short timeout) so it is cheap and safe.
        """
        from ..analyze.review import replay_verdict
        body = self._json_body()
        if body is None:
            return
        input_sha = (body or {}).get("input_sha")
        try:
            times = max(1, min(int((body or {}).get("times", 5)), 10))
            timeout = float((body or {}).get("timeout", 8))
        except (ValueError, TypeError):
            return self._json({"error": "invalid times or timeout"}, 400)
        s = self._store()
        try:
            t = s.targets.get(tid)
            if not t:
                return self._json({"error": "no target"}, 404)
            if not input_sha:
                return self._json({"error": "input_sha required"}, 400)
            # The replay + verdict persistence is shared with the server-side Autopilot's review
            # pass; run_input() there handles delivery mode, argv placement and NUL-safe argv.
            verdict = replay_verdict(s, t, input_sha, times=times, timeout=timeout)
            if verdict is None:
                return self._json({"error": "unknown input"}, 404)
            return self._json(verdict)
        finally:
            s.close()

    def _cancel_run(self, run_id):
        """Stop a running stage.

        The job engine has had `JobQueue.cancel` and `ctx.should_cancel()` all along and
        nothing exposed them, so a campaign started from the UI could not be stopped -- a
        ten-minute fuzz had to be waited out or the server killed.
        """
        s = self._store()
        try:
            run = s.runs.get(run_id)
            if not run:
                return self._json({"error": "no run"}, 404)
            if run.status in ("done", "error", "cancelled"):
                # not an error: the user clicked as it finished
                return self._json({"cancelled": False, "status": run.status,
                                   "note": f"run already {run.status}"})
            ok = JobQueue(s.conn).cancel(run_id)
            after = s.runs.get(run_id)
            return self._json({"cancelled": bool(ok), "status": after.status if after else None})
        finally:
            s.close()

    def _delete_target(self, tid):
        """Remove a target and everything derived from it (rows cascade; component edges
        touching it are removed too, so the System Map stays consistent)."""
        s = self._store()
        try:
            t = s.targets.get(tid)
            if not t:
                return self._json({"error": "no target"}, 404)
            case_id, name = t.case_id, t.filename
            ok = s.targets.delete(tid)
            s.events.append("target.removed", case_id=case_id,
                            payload={"target_id": tid, "filename": name})
            return self._json({"deleted": ok, "id": tid})
        finally:
            s.close()

    def _get_advice(self, tid):
        """What to do next with this target, and why.

        This lived in the GUI, so anything driving the API had to guess -- and guessing wrong
        is expensive: a scripted run picked black-box fuzzing and burned 98,500 executions on
        a parser for nothing while the GUI was recommending a seed and a structure model.
        """
        s = self._store()
        try:
            t = s.targets.get(tid)
            if not t:
                return self._json({"error": "no target"}, 404)
            return self._json(self._advice_for(s, t))
        finally:
            s.close()

    def _advice_for(self, s, t) -> dict:
        """The advice DICT, so /capabilities can reuse it. It needs the plan to know which
        stage is recommended, and computing it twice would be two answers to one question."""
        from ..analyze import advise as advise_mod
        tid = t.id
        fd = FindingDAO(s.conn)
        findings = fd.list_by_target(tid)
        imports = []
        run = next((r for r in s.runs.list_by_case(t.case_id)
                    if r.target_id == tid and r.stage == _INGEST
                    and r.status == "done"), None)
        if run:
            from ..jobs.registry import cached_output_json
            rec = cached_output_json(s, run.id) or {}
            # triage stores imports as {"libraries": [...], "symbols": [...]}
            imp = rec.get("imports") or {}
            imports = list(imp.get("symbols") or []) if isinstance(imp, dict) else list(imp)
        if not imports:
            # A statically linked binary has no import table, but its symbol table still
            # names fopen/fgets/read -- the same evidence, in the other place. Without
            # this a config-driven daemon was reported as "argv/none".
            try:
                from ..analyze.poc.exploit import elf_functions
                blob = s.content.path(t.sha256).read_bytes()
                imports = list(elf_functions(blob))
            except Exception:
                observe.absorbed(_log, "keeping the default")
                imports = []
        # How to invoke it, read off the binary's own usage line and option string. Static
        # only here: advice must stay fast, and running the target to CHECK the proposal
        # is what POST /targets/<id>/invocation is for.
        try:
            from ..analyze import invocation as invmod
            found = invmod.discover(self._target_strings(s, tid),
                                    prog=getattr(t, "filename", None))
            found["proposed_argv"] = invmod.propose_argv(found)
        except Exception:
            observe.absorbed(_log, "keeping the default")
            found = None
        crashes = sum(1 for d in DynResultDAO(s.conn).list_by_target(tid) if d.crashed)
        pocs = [p for p in PocDAO(s.conn).list_by_target(tid) if p.verified]
        out = advise_mod.advise(
            imports=[str(x) for x in imports],
            functions=len(FunctionDAO(s.conn).list_by_target(tid)),
            findings=len(findings),
            seeds=sum(1 for a in s.artifacts.list_by_case(t.case_id)
                      if a.kind in ("seed", "console-seed", "afl-crash")),
            has_format=False,
            afl_usable=advise_mod.afl_usable(),
            # triage could not name a format, so there is nothing here to run
            executable=bool(t.file_type and t.file_type not in ("raw", "other")),
            file_format=t.file_type,
            crashes=crashes, pocs=len(pocs), invocation=found,
            # One source of truth for "can AFL++ run THIS target": the stage's own gate.
            # Advice that says coverage_fuzz while the stage declines it is a plan that
            # dead-ends one click later.
            coverage_blocked=self._coverage_blocked(t))
        if found and found.get("flags"):
            out["invocation"] = found
        return out

    def _get_case_findings(self, cid):
        """All findings in a case, enriched with target filename/arch and the target's best
        PoC level -- the data the case findings board aggregates."""
        s = self._store()
        try:
            # A mistyped or deleted case returned `200 []`, so the board rendered "no
            # findings" for a case that does not exist -- indistinguishable from a real case
            # that has none.
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            tmap = {t.id: t for t in s.targets.list_by_case(cid)}
            best_poc = {}
            for t in tmap.values():
                lvls = [p.level for p in PocDAO(s.conn).list_by_target(t.id)
                        if p.verified and p.level]
                if lvls:
                    best_poc[t.id] = max(lvls)          # "L2" > "L1" lexicographically
            out = []
            fd = FindingDAO(s.conn)
            counts, proven = {}, {}
            for tid in tmap:
                counts.update(fd.site_counts(tid))
                proven.update(fd.proven_sites(tid))
            cur = self._curation_map(s, cid)
            for f in fd.list_by_case(cid):
                d = self._with_curation(_finding(f, site_count=counts.get(f.id, 0),
                                                 proven=proven.get(f.id, 0)), cur)
                t = tmap.get(f.target_id)
                d["target_name"] = t.filename if t else None
                d["target_arch"] = t.arch if t else None
                # Only on a finding that IS PoC-backed. This was the TARGET's best level
                # pinned to every finding of that target, so all 24 of jhead's rows wore an
                # "L1" badge and the one finding actually backed by a PoC looked no different
                # from the 23 that were not.
                if f.state == "poc-backed":
                    d["poc_level"] = best_poc.get(f.target_id)
                out.append(d)
            return self._json(out)
        finally:
            s.close()

    def _get_report(self, cid, qs):
        """Generate a report for a case in the requested format (html|pdf|sarif|json).

        Query params: format, min_severity, min_state, states=csv, finding_ids=csv,
        embed=0|1 (embed PoC bundles into html/json; default on).
        """
        from ..report import (
            DEFAULT_MIN_STATE,
            build_report,
            to_html,
            to_pdf,
            to_sarif,
        )
        from ..report.casejson import to_case_json_bytes
        fmt = qs.get("format", ["html"])[0]
        # An unknown format fell through to HTML. `?format=csv` then returned 200 and a web
        # page, so a caller that asked for something this build does not produce got a
        # plausible-looking answer in the wrong format and no indication of the typo.
        if fmt not in _REPORT_FORMATS:
            return self._json({"error": f"unknown report format {fmt!r}",
                               "formats": sorted(_REPORT_FORMATS)}, 400)
        embed = qs.get("embed", ["1"])[0] != "0" and fmt in ("html", "json")
        states = _csv(qs.get("states"))
        finding_ids = _csv(qs.get("finding_ids"))
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            try:
                report = build_report(
                    s, cid,
                    min_severity=qs.get("min_severity", [None])[0],
                    min_state=qs.get("min_state", [DEFAULT_MIN_STATE])[0],
                    states=states, finding_ids=finding_ids, embed_pocs=embed,
                )
            except ValueError as e:
                # An unknown min_state / min_severity / state is the caller's typo; refusing it
                # beats the old behaviour (ranked 0 -> silently widened to every candidate).
                return self._json({"error": str(e)}, 400)
        finally:
            s.close()
        name = (report["case"].get("name") or "case").replace(" ", "_")[:40]
        if fmt == "pdf":
            return self._bytes(to_pdf(report), "application/pdf",
                               filename=f"{name}.pdf")
        if fmt == "sarif":
            body = json.dumps(to_sarif(report), indent=2).encode("utf-8")
            return self._bytes(body, "application/json", filename=f"{name}.sarif")
        if fmt == "json":
            return self._bytes(to_case_json_bytes(report), "application/json",
                               filename=f"{name}.json")
        return self._bytes(to_html(report).encode("utf-8"), "text/html; charset=utf-8")

    def _get_case_export(self, cid):
        """Stream a portable single-case archive (rows + artifact blobs) as .tar.gz."""
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            name = (s.cases.get(cid).name or "case").replace(" ", "_")[:40]
            with tempfile.TemporaryDirectory(prefix="lykos-export-") as td:
                tmp = Path(td) / f"{name}.tar.gz"
                s.export_case(cid, tmp)
                # Stream from the temp file (inside the with-block, before cleanup) rather than
                # slurping the whole archive into memory.
                self._stream_file(tmp, "application/gzip", filename=f"{name}.tar.gz")
        finally:
            s.close()

    def _get_systemmap(self, cid):
        """The component graph (doc 17.1): nodes are targets, edges are resolved
        cross-binary relationships. `?resolve=1` recomputes links before returning."""
        from ..analyze.link.resolve import edge_symbols, resolve_case
        from ..db.dao import ComponentEdgeDAO, FindingDAO
        parsed = urlparse(self.path)
        do_resolve = parse_qs(parsed.query).get("resolve", ["0"])[0] == "1"
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            if do_resolve:
                resolve_case(s.conn, s.content, cid, persist=True)
            fdao = FindingDAO(s.conn)
            nodes = []
            for t in s.targets.list_by_case(cid):
                nodes.append({**_target(t),
                              "findings": fdao.count_by_target(t.id)})
            edges = []
            for e in ComponentEdgeDAO(s.conn).list_by_case(cid):
                edges.append({"src": e.src_target, "dst": e.dst_target, "kind": e.kind,
                              "symbol": e.symbol or None,
                              "detail": e.detail if e.kind in ("ipc", "taint") else None,
                              "symbols": edge_symbols(e.detail)})
            return self._json({"nodes": nodes, "edges": edges})
        finally:
            s.close()

    def _get_scorecard(self, cid):
        """WHAT THIS RUN DID, per target: executions, which stages worked, which declined and
        why, which were never scheduled, and what the run absorbed.

        The web UI could not show any of this. The CLI prints it and the HTML report renders it,
        but there was no endpoint, so the primary interface -- the one `./start` opens -- showed
        findings with no account of the work behind them. A null result is only worth something
        next to that account: of two targets with zero crashes, one executed 2,756 times and the
        other executed zero because a stage upstream ate the budget, and nothing in the UI told
        them apart.

        Read from the EVENT LOG rather than from the live autopilot record, so it survives a
        server restart, a reopened case, and a case produced by `lykos analyze` on the CLI --
        none of which have an in-memory record. `payloads_of_type` takes no limit: the scorecard
        is the last event a target emits, which is the first thing a windowed read drops.
        """
        from ..db.dao import EventDAO
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            from ..analyze.orchestrate import SCORECARD_EVENT
            cards = EventDAO(s.conn).payloads_of_type(SCORECARD_EVENT, case_id=cid)
            # One per target, latest wins: the autopilot re-emits if a target is re-run.
            by_target: dict = {}
            for card in cards:
                tid = card.get("target_id")
                if tid:
                    by_target[tid] = card
            return self._json({"cards": list(by_target.values())})
        finally:
            s.close()

    def _get_verifications(self, cid):
        """The false-positive review verdicts for a case, `{input_sha: verdict}` (the latest for
        each input). Persisted as `replay-verdict` artifacts by the replay endpoint; without a way
        to read them back, a REOPENED case lost every VerifyBadge (the live run gets them from the
        event stream, a reopen has no stream). Mirrors the report model's verdict aggregation."""
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            verdicts: dict = {}
            for a in s.artifacts.list_by_case(cid):
                if a.kind != "replay-verdict":
                    continue
                m = a.meta or {}
                ish = m.get("input_sha")
                if not ish:
                    continue
                at = a.created_at or 0
                if ish not in verdicts or at > verdicts[ish].get("_at", 0):
                    verdicts[ish] = {"runs": m.get("runs"), "crashed": m.get("crashed"),
                                     "signal": m.get("signal"),
                                     "deterministic": m.get("deterministic"), "_at": at}
            for v in verdicts.values():
                v.pop("_at", None)
            return self._json(verdicts)
        finally:
            s.close()

    def _import_case(self):
        """Merge an uploaded case archive (per-case or whole-store .tar.gz) into the store."""
        ctype = self.headers.get("Content-Type", "")
        with tempfile.TemporaryDirectory(prefix="lykos-import-") as td:
            tdp = Path(td)
            raw = tdp / "body.bin"
            if not self._read_body_to_file(raw):   # streamed to disk, never held in memory
                return self._json({"error": "request body too large or malformed"},
                                  413, close=True)
            _, tmp = _extract_upload(ctype, raw, tdp, None)   # the uploaded .tar.gz on disk
            s = self._store()
            try:
                try:
                    ids = s.import_archive(tmp)
                except tarfile.ReadError:
                    # this endpoint takes a case ARCHIVE, and the name invites people to try a
                    # binary here; `ReadError('not a gzip file')` is a Python repr, not an
                    # answer. Binaries go to POST /cases/<id>/targets.
                    return self._json({"error": (
                        "this is not a lykos case archive (expected a .tar.gz produced by "
                        "export). To add a binary to a case, upload it to "
                        "/cases/<case-id>/targets instead.")}, 400)
                return self._json({"cases": ids}, 201)
            finally:
                s.close()

    def _get_case(self, cid):
        s = self._store()
        try:
            c = s.cases.get(cid)
            return self._json(_case(c)) if c else self._json({"error": "no case"}, 404)
        finally:
            s.close()

    def _get_target(self, tid):
        s = self._store()
        try:
            t = s.targets.get(tid)
            return self._json(_target(t)) if t else self._json({"error": "no target"}, 404)
        finally:
            s.close()

    def _get_run(self, rid):
        s = self._store()
        try:
            r = s.runs.get(rid)
            if not r:
                return self._json({"error": "no run"}, 404)
            outputs = []
            for link in s.run_artifacts.list_by_run(rid):
                art = s.artifacts.get(link.artifact_sha256)
                outputs.append({"sha256": link.artifact_sha256, "role": link.role,
                                "kind": art.kind if art else None})
            cachehit = any(e.type == "job.cachehit"
                           for e in s.events.list(run_id=rid, limit=1000))
            from ..db.dao import DynResultDAO
            crashes = DynResultDAO(s.conn).count_crashed_by_run(rid)
            return self._json({**_run(r, crashes=crashes), "outputs": outputs,
                               "from_cache": cachehit})
        finally:
            s.close()

    def _get_target_source(self, tid):
        """The source a target was compiled from, when it came from a source drop.

        A source upload is compiled to an instrumented binary at ingest and analysed as that
        binary; the original source is kept as an artifact keyed to the binary's hash, so the
        code view can show real source instead of disassembly. Returns {source: null} for an
        ordinary binary target.
        """
        s = self._store()
        try:
            t = s.targets.get(tid)
            if not t:
                return self._json({"error": "no target"}, 404)
            for a in s.artifacts.list_by_case(t.case_id):
                if a.kind == "source-code" and (a.meta or {}).get("binary_sha") == t.sha256:
                    try:
                        text = s.content.get_bytes(a.sha256).decode("utf-8", "replace")
                    except Exception:
                        observe.absorbed(_log, "keeping the default")
                        text = None
                    m = a.meta or {}
                    return self._json({"source": text, "filename": m.get("filename"),
                                       "compiler": m.get("compiler"), "sanitizers": m.get("sanitizers")})
            return self._json({"source": None})
        finally:
            s.close()

    def _get_run_output(self, rid):
        """The parsed JSON a stage produced -- what actually happened, for the run log.

        The run row carries status and error but not the stage's own result (how many execs
        the fuzzer ran, how many functions were recovered, what the crash signal was). That
        lives in the run's 'output' artifact; this surfaces it so the UI can say what a stage
        found instead of only that it finished.
        """
        from ..jobs.registry import cached_output_json
        s = self._store()
        try:
            r = s.runs.get(rid)
            if not r:
                return self._json({"error": "no run"}, 404)
            try:
                out = cached_output_json(s, rid)
            except Exception:
                observe.absorbed(_log, "keeping the default")
                out = None
            return self._json({"run_id": rid, "stage": r.stage, "status": r.status,
                               "error": r.error, "output": out})
        finally:
            s.close()

    def _get_artifact(self, sha):
        path = self.server.content.path(sha)
        if not path.exists():
            return self._json({"error": "no artifact"}, 404)
        # Stream from disk in chunks -- an artifact may be a firmware image near the 1 GiB
        # ceiling, and get_bytes() would load the whole blob into memory per concurrent request.
        return self._stream_file(path, "application/octet-stream")

    def _get_attempts(self, sha, qs):
        """One fuzz engine's per-attempt log (fuzz/attempts.py), filtered and paged:
        ?outcome=no_start,crash  ?phase=mutate  ?errors_only=1  ?offset=0&limit=200.
        The summary is judged over the WHOLE log whatever the filter."""
        from ..analyze.fuzz import attempts as _attempts
        path = self.server.content.path(sha)
        if not path.exists():
            return self._json({"error": "no artifact"}, 404)
        # Only parse an artifact the store KNOWS is an attempt log. Any sha reaches this route, and
        # read_log() streams the whole file to judge its summary -- pointed at a target binary or
        # firmware image it would decode up to 1 GiB per request before deciding it was not a log.
        s = self._store()
        try:
            art = s.artifacts.get(sha)
        finally:
            s.close()
        if art is None or art.kind != _attempts.LOG_KIND:
            return self._json({"error": "not a fuzz attempt log"}, 415)

        def _list(name):
            v = (qs.get(name) or [""])[0]
            return [x for x in v.split(",") if x] or None
        from .server import _int_param
        limit = max(1, min(2000, _int_param(qs, "limit", 200)))
        offset = max(0, _int_param(qs, "offset", 0))
        try:
            out = _attempts.read_log(path, outcome=_list("outcome"), phase=_list("phase"),
                                     offset=offset, limit=limit,
                                     errors_only=(qs.get("errors_only") or ["0"])[0] in ("1", "true"))
        except Exception as e:                           # noqa: BLE001 -- not an attempt log
            return self._json({"error": f"not a fuzz attempt log: {e}"}, 415)
        return self._json(out)

    def _get_attempt_logs(self, case_id):
        """Every fuzz attempt log in the case, newest first, with its summary (no rows)."""
        from ..analyze.fuzz.attempts import LOG_KIND
        from ..db.dao import ArtifactDAO
        s = self._store()
        try:
            # an unknown case is a 404, like every other case reader -- not "no logs"
            if not s.cases.get(case_id):
                return self._json({"error": "no case"}, 404)
            arts = [a for a in ArtifactDAO(s.conn).list_by_case(case_id) if a.kind == LOG_KIND]
        finally:
            s.close()
        arts.sort(key=lambda a: a.created_at, reverse=True)
        return self._json([{"sha256": a.sha256, "created_at": a.created_at, "size": a.size,
                            **(a.meta or {})} for a in arts])

    def _get_bundle(self, sha):
        """Open a PoC bundle (.tar.gz) and return its INNER contents for the exploit inspector: the
        meta/primitive, small text files (README, meta.json, PRIMITIVE.txt, runner.sh, exploit.py)
        inlined, and a hexdump preview of the payload (input.bin) -- so the UI can show the exploit,
        not just offer a download. Binary members give size + a note, never their raw bytes here."""
        import json
        import tarfile

        path = self.server.content.path(sha)
        if not path.exists():
            return self._json({"error": "no artifact"}, 404)
        # Open from DISK: any artifact sha reaches this route, and reading the blob into memory
        # first (as this did) loaded a near-1 GiB firmware image per request just to find out it
        # is not a tarball. tarfile streams the gzip and fails fast on the magic.
        try:
            tf = tarfile.open(path, mode="r:gz")            # noqa: SIM115 -- closed in the
                                                             # finally below; a `with` cannot
                                                             # span the 415 return
        except Exception:                                    # noqa: BLE001 -- not a tar.gz bundle
            return self._json({"error": "not a poc bundle"}, 415)
        TEXT = {"README.txt", "meta.json", "PRIMITIVE.txt", "runner.sh", "exploit.py", "recipe.json",
                "stderr.txt"}
        files, meta, run_cmd = [], {}, None
        try:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                base = m.name.split("/")[-1]
                entry = {"name": m.name, "size": m.size}
                blob = tf.extractfile(m)
                data = blob.read(1 << 20) if blob else b""   # cap any single member at 1 MiB
                if base in TEXT and base.endswith((".txt", ".sh", ".py", ".json")):
                    entry["kind"] = "text"
                    entry["text"] = data.decode("utf-8", "replace")
                    if base == "meta.json":
                        try:
                            meta = json.loads(entry["text"])
                        except Exception:                    # noqa: BLE001
                            pass
                    if base == "runner.sh":
                        run_cmd = entry["text"]
                elif base == "input.bin":
                    entry["kind"] = "payload"
                    entry["hexdump"] = _hexdump(data, limit=1024)
                    entry["preview_len"] = min(len(data), 1024)
                else:                                        # target.bin and other binaries
                    entry["kind"] = "binary"
                files.append(entry)
        finally:
            tf.close()
        return self._json({"level": meta.get("level") if isinstance(meta, dict) else None,
                           "exploit": meta.get("exploit") if isinstance(meta, dict) else None,
                           "meta": meta, "run_cmd": run_cmd,
                           "files": files, "download": f"/artifacts/{sha}"})

    def _get_events(self, cid, after, tail=0):
        """Events after a cursor (oldest first, 500 a page) -- or, with `tail=N`, the case's
        NEWEST N events (still oldest first). The GUI needs the tail to seed its live-log cursor
        and to backfill the console on reopen: `after=0` returns the OLDEST 500, so a case with a
        long history seeded the cursor 500 events in and then replayed the rest as if live."""
        s = self._store()
        try:
            if tail > 0:
                from ..db.dao import EventDAO
                rows = s.conn.execute(
                    "SELECT * FROM (SELECT * FROM event WHERE case_id = ? ORDER BY id DESC "
                    "LIMIT ?) ORDER BY id ASC", (cid, min(int(tail), 2000))).fetchall()
                ed = EventDAO(s.conn)
                return self._json([_event(ed._row(r)) for r in rows])
            evs = s.events.list(case_id=cid, after_id=after, limit=500)
            return self._json([_event(e) for e in evs])
        finally:
            s.close()

    def _create_case(self):
        body = self._json_body()
        if body is None:
            return
        name = body.get("name", "case")
        if name is None or name == "":
            name = "case"
        # A non-string name/notes was stored as-is and broke every later reader that formats it
        # (the export filename does `.replace`), so refuse it here instead.
        if not isinstance(name, str) or any(
                body.get(k) is not None and not isinstance(body.get(k), str)
                for k in ("notes", "engagement_ref")):
            return self._json({"error": "name, notes and engagement_ref must be strings"}, 400)
        s = self._store()
        try:
            c = s.cases.create(name[:200], notes=body.get("notes"),
                               engagement_ref=body.get("engagement_ref"))
            return self._json(_case(c), 201)
        finally:
            s.close()

    def _upload_target(self, cid):
        # `..analyze` re-exports `ingest` as a FUNCTION, so importing the module under an
        # alias binds the function and the exception lookup fails at runtime
        from ..analyze.ingest import NotAnalysable, enqueue_triage, ingest
        from ..jobs.registry import reproject_cache_hit
        ctype = self.headers.get("Content-Type", "")
        s = self._store()
        try:
            # TemporaryDirectory, not mkdtemp: the old code unlinked the FILE and left the
            # directory behind, leaking one empty directory per upload for the life of the
            # process. It is also removed on the error paths, which an explicit unlink was not.
            with tempfile.TemporaryDirectory(prefix="lykos-upload-") as td:
                tdp = Path(td)
                raw = tdp / "body.bin"
                if not self._read_body_to_file(raw):   # streamed to disk, never held in memory
                    return self._json({"error": "request body too large or malformed"},
                                      413, close=True)
                try:
                    filename, upload = _extract_upload(ctype, raw, tdp,
                                                       self.headers.get("X-Filename"))
                except ValueError as e:
                    return self._json({"error": str(e)}, 400, close=True)
                # The client-supplied filename must never influence where we write: an absolute
                # path or `../` would escape the temp dir. Reduce it to a bare basename.
                safe_name = Path(filename or "upload.bin").name or "upload.bin"
                # A challenge is often a BUNDLE: binary + its patched loader + libc (+ flag),
                # zipped up. Extract it and ingest the DIRECTORY so ingest() finds the main binary
                # and keeps the loader/libc as deps -- otherwise the binary can't run in analysis.
                try:
                    bundle = _maybe_extract_bundle(upload, tdp, safe_name)
                except BundleRejected as e:
                    return self._json({"error": str(e)}, e.status)
                try:
                    if bundle is not None:
                        target = ingest(s, cid, bundle)     # dir -> main binary + companion deps
                    else:
                        target = ingest(s, cid, upload, filename=safe_name)
                except NotAnalysable as e:
                    # 400, not 500: the upload was understood and refused, and the reason is
                    # for the person who picked the file
                    return self._json({"error": str(e)}, 400)
            run = enqueue_triage(JobQueue(s.conn), target)
            if run.status == "done":   # cache hit: body skipped, re-project its per-target rows
                reproject_cache_hit(s, run.stage, target.id, run.id)
            return self._json({"id": target.id, "sha256": target.sha256,
                               "run_id": run.id}, 201)
        finally:
            s.close()

    def _format_analyze(self):
        """Custom-format builder support: with just a sample, suggest a starting spec
        (detect magic, auto-find the length field); with a spec, show how it carves the
        sample using the real fuzzer parser. No case/target needed."""
        from ..analyze.fuzz import structure
        body = self._json_body()
        if body is None:
            return
        try:
            sample = base64.b64decode(body["sample_b64"]) if body.get("sample_b64") else b""
        except (binascii.Error, ValueError, TypeError):
            return self._json({"error": "invalid sample_b64"}, 400)
        sample = sample[:65536]                          # cap: previews stay fast
        spec = body.get("spec")
        if spec is not None:
            return self._json({"preview": structure.describe(spec, sample)})
        return self._json({"suggestion": structure.suggest_spec(sample)})

    @staticmethod
    def _enqueue_fn(entry):
        from importlib import import_module
        mod, fn = entry
        return getattr(import_module(mod, __package__), fn)

    def _seed_params(self, cid, params):
        """Resolve `seed_shas` (seeds uploaded into THIS case) to their store paths as
        `seed_files` -- the same resolution the server autopilot uses. An unknown hash is
        refused: a run the operator seeded must not quietly run unseeded."""
        if not params or "seed_shas" not in params:
            return params, None
        paths, err = self._resolve_seed_shas(cid, params["seed_shas"])
        if err:
            return params, err
        out = {k: v for k, v in params.items() if k != "seed_shas"}
        if paths:
            out["seed_files"] = paths
        return out, None

    def _create_run(self):
        from ..jobs.registry import reproject_cache_hit
        body = self._json_body()
        if body is None:
            return
        s = self._store()
        try:
            q = JobQueue(s.conn)
            stage = body.get("stage", _INGEST)
            target_id = body.get("target_id")
            params = body.get("params")
            # Shape checks at the edge: a list/number here reached the stage code (or a dict
            # lookup with an unhashable key) and surfaced as a 500.
            if not isinstance(stage, str) or (target_id is not None
                                              and not isinstance(target_id, str)):
                return self._json({"error": "stage and target_id must be strings"}, 400)
            if params is not None and not isinstance(params, dict):
                return self._json({"error": "params must be an object"}, 400)
            # Server-side PATHS and tool binaries are a CLI-only channel. From a browser they let a
            # request copy any file the server can read into the case as a seed, or pick which
            # binary a stage executes. Refused (not dropped), so a caller knows why.
            cli_only = sorted(k for k in (params or {}) if k in _CLI_ONLY_PARAMS)
            if cli_only:
                return self._json({"error": "server-side path parameters are CLI-only; upload "
                                            "seeds to the case and pass seed_shas",
                                   "params": cli_only}, 400)
            if params and "seed_shas" in params and stage not in _SEEDED_STAGES:
                return self._json({"error": f"stage {stage!r} takes no seeds",
                                   "stages": sorted(_SEEDED_STAGES)}, 400)

            if stage in self._CASE_STAGES:            # case-scoped: no target needed
                cid = body.get("case_id")
                if not cid and target_id:             # derive the case from the target
                    _t = s.targets.get(target_id)
                    if _t is None:                    # a bad target_id is a 404, not a 500
                        return self._json({"error": "no target"}, 404)
                    cid = _t.case_id
                # Neither a case nor a target: enqueueing with case_id=None created a run no
                # case owns (or failed in the FK as a 500). Say what is missing instead.
                if not cid or not isinstance(cid, str):
                    return self._json({"error": f"stage {stage!r} requires a case_id"}, 400)
                if not s.cases.get(cid):
                    return self._json({"error": "no case"}, 404)
                params, err = self._seed_params(cid, params)
                if err:
                    return self._json({"error": err}, 400)
                fn = self._enqueue_fn(self._CASE_STAGES[stage])
                run = fn(q, cid) if stage in ("link_case", "ipc_model", "cross_taint") \
                    else fn(q, cid, params=params)
                return self._json({"run_id": run.id, "from_cache": run.status == "done"}, 201)

            if stage in self._TARGET_STAGES and target_id:
                target = s.targets.get(target_id)
                if not target:
                    return self._json({"error": "no target"}, 404)
                params, err = self._seed_params(target.case_id, params)
                if err:
                    return self._json({"error": err}, 400)
                fn = self._enqueue_fn(self._TARGET_STAGES[stage])
                run = fn(q, target) if stage in (_INGEST, "disassemble", "detect_cwe") \
                    else fn(q, target, params=params)
            elif stage in self._TARGET_STAGES:
                return self._json({"error": f"stage {stage!r} requires a target_id"}, 400)
            else:
                # An unregistered name used to fall through to a bare enqueue, creating a run
                # no worker can ever execute; it now fails at the edge with the valid names.
                known = sorted(set(self._CASE_STAGES) | set(self._TARGET_STAGES))
                return self._json({"error": f"unknown stage {stage!r}", "stages": known}, 400)

            if run.status == "done" and target_id:   # cache hit: re-project its per-target rows
                reproject_cache_hit(s, stage, target_id, run.id)
            return self._json({"run_id": run.id, "from_cache": run.status == "done"}, 201)
        finally:
            s.close()
