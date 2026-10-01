"""Embedded RTOS configuration audit: insecure settings in FreeRTOSConfig.h (and peers).

An RTOS's safety nets are compile-time switches in a config header. If stack-overflow checking
is off, a task overflow silently corrupts a neighbour instead of being caught; if the MPU is
off, every task shares one flat address space; if configASSERT is undefined, the kernel's own
sanity checks compile to nothing. These never show up as a code bug a disassembler can see --
they are the absence of a defence, declared in config -- so they are their own detector.

Pure parsing of the archived source tree, stdlib only. A missing/garbled config is simply no
findings, never fatal.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage

_log = logging.getLogger(__name__)

EMBEDDED_AUDIT_STAGE = "embedded_audit"
TOOL = "embedded-audit"
TOOL_VERSION = "embedded-audit-1"

_MAX_FILES = 6000
_MAX_FILE = 2 << 20
_CONFIG_NAMES = {"freertosconfig.h"}
# A vendored kernel ships EXAMPLE/template configs (kernel/examples/.../FreeRTOSConfig.h) that
# are not the project's build config; auditing them reports settings the real firmware never
# uses. Skip any config under one of these path segments -- the project's own config is not.
_VENDOR_SEGMENTS = {"examples", "example", "demo", "demos", "template", "templates",
                    "test", "tests", "coverity", "docs", "doc"}


def _defines(text: str) -> dict:
    """`#define NAME VALUE` -> {NAME: VALUE}. VALUE is the first token (an int, (int), or name).
    Function-like macros (`#define NAME( x ) ...`) and bare `#define NAME` are recorded as
    defined with an empty value, so "is NAME defined at all" is answerable."""
    out = {}
    for m in re.finditer(r"^\s*#\s*define\s+(\w+)\s+([^\s/(]+)", text, re.M):
        out[m.group(1)] = m.group(2).strip("()")
    for m in re.finditer(r"^\s*#\s*define\s+(\w+)\s*(?:\(|$)", text, re.M):
        out.setdefault(m.group(1), "")              # function-like or value-less macro
    return out


def _is_off(defs: dict, name: str) -> bool:
    """A boolean config knob is OFF when absent or defined to 0."""
    v = defs.get(name)
    return v is None or v == "0"


# (config predicate, cwe, severity, title, detail) -- each a check against the parsed defines.
def _config_findings(defs: dict, where: str) -> list:
    out = []

    def add(cwe, sev, title, detail, key):
        out.append({"cwe": cwe, "severity": sev, "title": title, "detail": detail,
                    "dedup_key": key})

    if _is_off(defs, "configCHECK_FOR_STACK_OVERFLOW"):
        add("CWE-1188", "medium", "FreeRTOS stack-overflow checking disabled",
            "configCHECK_FOR_STACK_OVERFLOW is 0/undefined: a task that overruns its stack "
            "silently corrupts adjacent memory instead of triggering the overflow hook.",
            "frtos-cfg:stackcheck")
    # MPU: off when neither the MPU wrappers nor the ARMv8-M MPU enable are on.
    if _is_off(defs, "portUSING_MPU_WRAPPERS") and _is_off(defs, "configENABLE_MPU"):
        add("CWE-693", "medium", "FreeRTOS MPU memory protection disabled",
            "No MPU wrappers / configENABLE_MPU: all tasks and the kernel share one flat "
            "address space, so a bug in any task can reach kernel or peer-task memory.",
            "frtos-cfg:mpu")
    if "configASSERT" not in defs:
        add("CWE-617", "low", "configASSERT not defined",
            "FreeRTOS's own precondition checks (configASSERT) compile to nothing, so kernel "
            "invariant violations go undetected at runtime.", "frtos-cfg:assert")
    if _is_off(defs, "configUSE_MALLOC_FAILED_HOOK") and not _is_off(
            defs, "configSUPPORT_DYNAMIC_ALLOCATION"):
        add("CWE-252", "low", "FreeRTOS malloc-failure hook disabled",
            "configUSE_MALLOC_FAILED_HOOK is 0 with dynamic allocation enabled: an allocation "
            "failure is not detected, so code proceeds on a NULL handle.", "frtos-cfg:mallocfail")
    for f in out:
        f["evidence"] = [{"channel": "config", "detail": f"{where}: {f.pop('detail')}"}]
    return out


def audit_tree(root: Path) -> list:
    """Insecure RTOS config settings across the source tree: a list of finding dicts ready for
    FindingDAO.upsert (minus target/case ids). Covers the FreeRTOSConfig.h safety knobs.

    (The heap scheme is deliberately NOT inferred from file presence: FreeRTOS ships every
    portable/MemMang/heap_N.c in its tree and only one is compiled, so a presence check would
    false-positive on the unused ones. Which heap is linked is a build-file fact, left to a
    future build-graph check.)"""
    findings: list = []
    n = 0
    for p in sorted(root.rglob("*")):
        if n >= _MAX_FILES:
            break
        if not p.is_file() or p.name.lower() not in _CONFIG_NAMES:
            continue
        if _VENDOR_SEGMENTS & {seg.lower() for seg in p.parts}:
            continue                    # a vendored example/template config, not the project's
        try:
            if p.stat().st_size > _MAX_FILE:
                continue
            text = p.read_text("utf-8", "replace")
        except OSError:
            continue
        n += 1
        findings += _config_findings(_defines(text), p.name)
    uniq, keys = [], set()          # dedupe (the same config may appear in several ports)
    for f in findings:
        if f["dedup_key"] not in keys:
            keys.add(f["dedup_key"])
            uniq.append(f)
    return uniq


def embedded_audit_stage(ctx) -> dict:
    import io
    import tarfile

    from ...db.dao import ArtifactDAO
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("embedded_audit requires a target_id")
    proj = next((a for a in ArtifactDAO(ctx.conn).list_by_case(target.case_id)
                 if a.kind == "source-project"
                 and (a.meta or {}).get("binary_sha") == target.sha256), None)
    if proj is None:
        ctx.emit("embedded_audit.done", payload={"applicable": False,
                 "note": "no archived source tree (RTOS config lives in source)"})
        return {}
    root = ctx.scratch() / "embcfg"
    root.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                          mode="r:gz") as tf:
            for m in tf.getmembers():
                if m.isfile() and not m.name.startswith("/") and ".." not in m.name:
                    tf.extract(m, root)
    except Exception:
        ctx.emit("embedded_audit.done", payload={"applicable": False,
                 "note": "could not unpack the archived source tree"})
        return {}

    ctx.progress(msg="auditing RTOS configuration")
    findings = audit_tree(root)
    fd = FindingDAO(ctx.conn)
    for f in findings:
        fd.upsert(target.id, target.case_id, {
            "cwe": f["cwe"], "severity": f["severity"], "detector": "embedded_config",
            "title": f["title"], "evidence": f["evidence"],
            "function_addr": None, "site_addr": None, "dedup_key": f["dedup_key"],
            "state": "corroborated", "confidence": 0.8})
    ctx.emit("embedded_audit.done", payload={"applicable": True, "findings": len(findings),
             "issues": [f["dedup_key"] for f in findings]})
    ctx.progress(pct=100, msg=f"{len(findings)} insecure RTOS config setting(s)")
    return {}


def register() -> None:
    register_stage(EMBEDDED_AUDIT_STAGE, embedded_audit_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_embedded_audit(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, EMBEDDED_AUDIT_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="quick", force=force)
