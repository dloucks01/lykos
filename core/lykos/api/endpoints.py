"""The analyst API endpoint handlers, split out of `server.py` as a mixin.

`server.Handler` mixes this in, so every handler keeps full access to the request/response
helpers (`self._json`, `self._store`, `self._read_body`, `self.server`) and the routing dicts
(`self._CASE_STAGES`, `self._TARGET_STAGES`) via the MRO. Behaviour is unchanged; this only moves
the ~900 lines of endpoint bodies out of the 1600-line server module.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..casestore import CaseStore  # noqa: F401  (some handlers construct it directly)
from ..db.dao import DynResultDAO, FindingDAO, FunctionDAO, PocDAO, StringDAO
from ..jobs import JobQueue
from .multipart import extract_file, extract_file_to
from .serializers import (
    _INGEST,
    _REPORT_FORMATS,
    _case,
    _csv,
    _event,
    _finding,
    _function,  # noqa: F401
    _poc,
    _run,
    _stringref,
    _target,
)

# Bodies at or below this size are extracted in memory (the proven, simple path); larger uploads
# have their file part streamed to disk so a big binary/firmware never sits fully in RAM.
_INMEM_LIMIT = 16 << 20


# Archive formats that ARE themselves an analysable target, not a bundle to unpack: a .jar/.war/
# .ear/.aar is JVM bytecode and a .apk is an Android package -- all zips, but ingest() analyses
# them whole. Unpacking one yields only .class/resource files and no native binary, so a valid
# upload was refused with "no analysable binary found in the bundle". Match on the name, since the
# magic is just "a zip".
_SELF_CONTAINED_ARCHIVES = (".jar", ".war", ".ear", ".aar", ".apk")


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
                for m in z.namelist():
                    mp = Path(m)
                    if m.endswith("/") or mp.is_absolute() or ".." in mp.parts:
                        continue
                    z.extract(m, dest)
            return dest if any(dest.rglob("*")) else None
        if tarfile.is_tarfile(upload):
            with tarfile.open(upload) as tf:
                tf.extractall(dest, filter="data")   # 'data' filter blocks traversal/special files
            return dest if any(dest.rglob("*")) else None
    except Exception:                                # noqa: BLE001 -- a bad archive falls back to
        pass                                         # ingesting the upload as a single file
    return None


def _extract_upload(ctype: str, raw: Path, td: Path, x_filename):
    """(filename, path) of the file to ingest from a body already streamed to `raw`. Small bodies
    use the in-memory multipart parse; large ones stream the file part to disk; a non-multipart
    body is treated as a raw octet-stream upload (the body file itself)."""
    if raw.stat().st_size <= _INMEM_LIMIT:
        filename, data = extract_file(ctype, raw.read_bytes())
        if data is None:                        # raw octet-stream fallback
            return (x_filename or "upload.bin"), raw
        part = td / "part.bin"
        part.write_bytes(data)
        return filename, part
    fn = extract_file_to(ctype, raw, td / "part.bin")
    if fn is None:                              # not the single-file shape -> octet-stream fallback
        return (x_filename or "upload.bin"), raw
    return fn, (td / "part.bin")


class EndpointsMixin:
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
                pass
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
        s = self._store()
        try:
            t = s.targets.get(tid)
            if not t:
                return self._json({"error": "no target"}, 404)
            found = invmod.discover(self._target_strings(s, tid),
                                    usage_hint=body.get("usage_hint"))
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
                sample.write_bytes(base64.b64decode(body["sample_b64"])
                                   if body.get("sample_b64") else b"name=lykos\n")

                def _run(a):
                    return sandbox.run(exe, argv=a, stdin=b"", timeout=float(body.get(
                        "timeout", 15)), arch=t.arch, endianness=t.endianness, bits=t.bits)
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
        times = max(1, min(int((body or {}).get("times", 5)), 10))
        timeout = float((body or {}).get("timeout", 8))
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
                imports = []
        # How to invoke it, read off the binary's own usage line and option string. Static
        # only here: advice must stay fast, and running the target to CHECK the proposal
        # is what POST /targets/<id>/invocation is for.
        try:
            from ..analyze import invocation as invmod
            found = invmod.discover(self._target_strings(s, tid))
            found["proposed_argv"] = invmod.propose_argv(found)
        except Exception:
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
            for f in fd.list_by_case(cid):
                d = _finding(f, site_count=counts.get(f.id, 0),
                             proven=proven.get(f.id, 0))
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
            report = build_report(
                s, cid,
                min_severity=qs.get("min_severity", [None])[0],
                min_state=qs.get("min_state", [DEFAULT_MIN_STATE])[0],
                states=states, finding_ids=finding_ids, embed_pocs=embed,
            )
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
            return self._json({**_run(r), "outputs": outputs, "from_cache": cachehit})
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

    def _get_events(self, cid, after):
        s = self._store()
        try:
            evs = s.events.list(case_id=cid, after_id=after, limit=500)
            return self._json([_event(e) for e in evs])
        finally:
            s.close()

    def _create_case(self):
        body = self._json_body()
        if body is None:
            return
        s = self._store()
        try:
            c = s.cases.create(body.get("name", "case"), notes=body.get("notes"),
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
                filename, upload = _extract_upload(ctype, raw, tdp,
                                                   self.headers.get("X-Filename"))
                # The client-supplied filename must never influence where we write: an absolute
                # path or `../` would escape the temp dir. Reduce it to a bare basename.
                safe_name = Path(filename or "upload.bin").name or "upload.bin"
                # A challenge is often a BUNDLE: binary + its patched loader + libc (+ flag),
                # zipped up. Extract it and ingest the DIRECTORY so ingest() finds the main binary
                # and keeps the loader/libc as deps -- otherwise the binary can't run in analysis.
                bundle = _maybe_extract_bundle(upload, tdp, safe_name)
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
        sample = base64.b64decode(body["sample_b64"]) if body.get("sample_b64") else b""
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

            if stage in self._CASE_STAGES:            # case-scoped: no target needed
                cid = body.get("case_id") or (
                    s.targets.get(target_id).case_id if target_id else None)
                fn = self._enqueue_fn(self._CASE_STAGES[stage])
                run = fn(q, cid) if stage in ("link_case", "ipc_model", "cross_taint") \
                    else fn(q, cid, params=params)
                return self._json({"run_id": run.id, "from_cache": run.status == "done"}, 201)

            if stage in self._TARGET_STAGES and target_id:
                target = s.targets.get(target_id)
                if not target:
                    return self._json({"error": "no target"}, 404)
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
