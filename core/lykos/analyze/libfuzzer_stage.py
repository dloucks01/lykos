"""Stage: coverage-guided libFuzzer fuzzing of a source target.

Builds an LLVMFuzzerTestOneInput harness (in-tree, as OSS projects ship, or synthesized for a
named entry function) with ASan+UBSan, runs libFuzzer for a budget, and files every crash it finds
as a CONFIRMED finding classified from the sanitizer report (bug class + source file:line) -- a real
bug with reproducible evidence and no CTF oracle. This is the coverage-guided complement to the
blind-havoc `fuzz` stage, and the only path that fuzzes LIBRARY source with no `main`.
"""
from __future__ import annotations

import hashlib
import io
import re
import tarfile
from pathlib import Path

from ..db.dao import ArtifactDAO, FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .debug.rootcause import parse_asan_report

TOOL, TOOL_VERSION = "libfuzzer", "libfuzzer-1"


def _materialize_source(ctx, target) -> Path | None:
    """Recover the target's source into a scratch directory: the archived source-project tree, or a
    single source-code file. None when the target was not built from source."""
    arts = ArtifactDAO(ctx.conn).list_by_case(target.case_id)
    d = ctx.scratch() / "src"
    d.mkdir(parents=True, exist_ok=True)
    proj = next((a for a in arts if a.kind == "source-project"
                 and (a.meta or {}).get("binary_sha") == target.sha256), None)
    if proj:
        try:
            with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                              mode="r:gz") as tf:
                for m in tf.getmembers():
                    if m.isfile() and not m.name.startswith("/") and ".." not in m.name:
                        tf.extract(m, d)
            return d
        except Exception:                                # noqa: BLE001
            return None
    single = next((a for a in arts if a.kind == "source-code"
                   and (a.meta or {}).get("binary_sha") == target.sha256), None)
    if single:
        try:
            fn = (single.meta or {}).get("filename") or "a.c"
            (d / Path(fn).name).write_bytes(ctx.content.path(single.sha256).read_bytes())
            return d
        except Exception:                                # noqa: BLE001
            return None
    return None


def libfuzzer_stage(ctx) -> dict:
    from . import libfuzzer as LF

    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("libfuzzer requires a target_id")
    p = ctx.params or {}
    seconds = int(p.get("seconds", 30))

    src = _materialize_source(ctx, target)
    if src is None:
        ctx.emit("libfuzzer.done", payload={"supported": False,
                 "note": "no source for this target (libFuzzer needs C/C++ source to build a harness)"})
        return {"metrics": {"supported": False}}

    ctx.progress(msg="building the libFuzzer harness (ASan+UBSan)")
    out = ctx.scratch() / "lf.bin"
    build = LF.build_libfuzzer(src, out, harness_fn=p.get("harness_fn"),
                               harness_kind=p.get("harness_kind", "cstring"))
    if not build["ok"]:
        note = ("no LLVMFuzzerTestOneInput in the source; pass params.harness_fn to synthesize a "
                "harness for an entry function" if "no LLVMFuzzer" in build["log"]
                else "libFuzzer build failed: " + build["log"][-300:])
        ctx.emit("libfuzzer.done", payload={"supported": False, "note": note})
        ctx.progress(pct=100, msg=note[:90])
        return {"metrics": {"supported": False}}

    ctx.progress(msg=f"fuzzing with libFuzzer ({build['harness']}) for {seconds}s")
    res = LF.run_libfuzzer(build["binary"], ctx.scratch(), seconds=seconds,
                           max_len=int(p.get("max_len", 4096)))
    fd = FindingDAO(ctx.conn)
    found, seen = 0, set()
    for cr in res["crashes"]:
        cls = parse_asan_report(cr.get("report") or "") or {}
        cwe = cls.get("cwe", "CWE-787")
        src_line = cls.get("source")
        key = src_line or hashlib.sha1((cr.get("report") or "")[:256].encode("latin-1", "ignore")).hexdigest()[:12]
        if key in seen:
            continue
        seen.add(key)
        try:
            input_sha = ctx.put_artifact("libfuzzer-crash-input", data=cr["input"])
            title = cls.get("class") or "crash under libFuzzer"
            fd.upsert(target.id, target.case_id, {
                "cwe": cwe, "title": f"{title} (libFuzzer)", "severity": cls.get("severity", "high"),
                "detector": "libfuzzer", "state": "confirmed", "confidence": 0.92,
                "dedup_key": f"{cwe}:libfuzzer:{key}", "function_addr": None, "site_addr": None,
                "site_detail": src_line,
                "evidence": [{"channel": "sanitizer",
                              "detail": f"libFuzzer + {cls.get('sanitizer', 'AddressSanitizer')} "
                                        f"reproduced {title}" + (f" at {src_line}" if src_line else "")
                                        + f" (crashing input {input_sha[:12]})"}]})
            found += 1
        except Exception:                                # noqa: BLE001
            continue
    ctx.emit("libfuzzer.done", payload={"supported": True, "crashes": found,
             "harness": build["harness"]})
    ctx.progress(pct=100, msg=f"libFuzzer: {found} crash finding(s) via {build['harness']}")
    return {"metrics": {"supported": True, "crashes": found}}


def register() -> None:
    register_stage("libfuzzer", libfuzzer_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=600)


def enqueue_libfuzzer(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, "libfuzzer", target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
