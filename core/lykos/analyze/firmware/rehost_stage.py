"""The `firmware_rehost` stage (doc 17.5) — partial single-task rehosting under Unicorn.

For a bare-metal ARM Cortex-M blob, execute it under Unicorn with a Fuzzware-style MMIO model
(peripheral reads = fuzz stream), fuzz the MMIO inputs to maximise coverage, and on an
emulation fault (an access outside flash/SRAM/peripherals) file a Confirmed finding with the
crashing MMIO input as the reproducer. Graceful when Unicorn is absent or the target is not a
recognisable Cortex-M image.
"""
from __future__ import annotations

import base64
import json

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from .headerless import analyze_blob
from .rehost import locate_unicorn_python, run_rehost

REHOST_STAGE = "firmware_rehost"
TOOL = "lykos-rehost"
TOOL_VERSION = "rehost-1"

# emulation fault kind -> (cwe, severity)
_FAULT_CWE = {
    "write": ("CWE-787", "high"), "read": ("CWE-125", "medium"),
    "fetch": ("CWE-119", "high"), "unknown": ("CWE-119", "high"),
}


def firmware_rehost_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("firmware_rehost requires a target_id (the firmware blob)")
    p = ctx.params or {}
    data = ctx.content.path(target.sha256).read_bytes()

    hl = analyze_blob(data)
    # Rehostable arches (the Unicorn driver's supported set). Cortex-M is the strongest case (a
    # reset-vector table gives base/sp/entry); the others run from an assumed base/entry, which
    # an operator can override via params. A target the headerless loader could not classify at
    # all is skipped.
    _REHOST_ARCHES = {"arm", "aarch64", "mips", "mips64", "ppc", "ppc64", "riscv", "riscv64"}
    arch = (hl.get("arch") or "").lower()
    is_cm = arch == "arm" and hl.get("sub") == "cortex-m"
    if not (is_cm or arch in _REHOST_ARCHES):
        ctx.emit("firmware_rehost.done", payload={
            "supported": False, "note": "no rehostable architecture identified in this blob "
            "(no Cortex-M reset vector table and no confident headerless arch)",
            "arch": hl.get("arch")})
        ctx.progress(pct=100, msg="no rehostable arch identified; rehosting unsupported")
        return {"metrics": {"supported": False}}

    python = locate_unicorn_python(p.get("unicorn_python"))
    if python is None:
        ctx.emit("firmware_rehost.done", payload={
            "supported": False, "note": "Unicorn not available (LYKOS_UNICORN_PYTHON / "
            "vendored unicorn-venv / python3 with `import unicorn`)"})
        ctx.progress(pct=100, msg="Unicorn not installed; rehosting unavailable")
        return {"metrics": {"supported": False}}

    blob_path = ctx.scratch() / "firmware.bin"
    blob_path.write_bytes(data)
    spec = {
        "blob": str(blob_path),
        "arch": "cortex-m" if is_cm else arch,
        "sub": hl.get("sub"),
        "endianness": hl.get("endianness") or "little",
        "bits": hl.get("bits") or 32,
        "base": p.get("base", hl.get("base_addr") or (0x08000000 if is_cm else 0)),
        "sp": p.get("sp"), "entry": p.get("entry", hl.get("entry")),
        "mode": p.get("mode", "fuzz"),
        "budget": int(p.get("budget", 20000)),
        "max_iters": int(p.get("max_iters", 300)),
        "seed": int(p.get("seed", 1337)),
        "seeds": p.get("seeds", []),
        "fuzz_b64": p.get("fuzz_b64"),
        # {entry_addr: "skip"|"ret0"|"ret1"} for recognised HAL/libc/delay functions, supplied by
        # an operator or a signature matcher: handled on the host instead of emulated.
        "handlers": p.get("handlers", {}),
    }
    ctx.emit("firmware_rehost.start", payload={"entry": hex(spec["base"]),
             "python": python.name})
    ctx.progress(msg="rehosting Cortex-M image under Unicorn (Fuzzware-style MMIO)")
    res = run_rehost(python, spec, ctx=ctx, timeout=int(p.get("timeout", 120)))

    fz = res.get("fuzz") or {}
    run = res.get("run") or {}
    crash = fz.get("crash") or (run if run.get("fault") else None)
    coverage = fz.get("coverage", run.get("nblocks", 0))

    finding = 0
    if crash and crash.get("fault"):
        fault = crash["fault"]
        kind = fault.get("kind", "unknown")
        cwe, sev = _FAULT_CWE.get(kind, _FAULT_CWE["unknown"])
        mmio_b64 = crash.get("fuzz_b64") or ""
        input_sha = ctx.put_artifact("rehost-mmio-input",
                                     data=base64.b64decode(mmio_b64) if mmio_b64 else b"")
        detail = (f"firmware faulted under emulation: {kind} to {hex(fault['addr'])} "
                  f"(pc {hex(fault['pc'])}) driven by a modelled MMIO input")
        FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
            "cwe": cwe, "title": f"Firmware {kind} fault under rehosting",
            "severity": sev, "state": "confirmed", "confidence": 0.85,
            "detector": "firmware_rehost", "site_addr": hex(fault["pc"]),
            "function_addr": None, "dedup_key": f"rehost:{kind}:{fault['addr']}",
            "evidence": [{"channel": "rehosting", "detail": detail},
                         {"channel": "rehosting",
                          "detail": f"reproducer: MMIO input {input_sha[:16]}… "
                          f"({crash.get('consumed', 0)} bytes consumed)"}]})
        finding = 1

    report = {"arch": res.get("arch", spec["arch"]), "entry": res.get("entry"), "sp": res.get("sp"),
              "unicorn_version": res.get("unicorn_version"), "coverage_blocks": coverage,
              "fuzz": fz, "run": run}
    report_sha = ctx.put_artifact("firmware-rehost",
                                  data=json.dumps(report, indent=2, default=str).encode(),
                                  meta={"coverage": coverage, "crash": bool(crash)})
    ctx.emit("firmware_rehost.done", payload={
        "supported": True, "coverage": coverage, "iters": fz.get("iters"),
        "crash": bool(crash), "cwe": (_FAULT_CWE.get((crash or {}).get("fault", {})
                                      .get("kind", "unknown"))[0] if crash else None),
        "report": report_sha})
    ctx.progress(pct=100, msg=(f"rehosted: {coverage} blocks covered"
                               + (", crash found" if crash else ", no crash")))
    return {"output_shas": [report_sha], "output_kind": "firmware-rehost",
            "metrics": {"coverage": coverage, "crash": bool(crash), "findings": finding}}


def register() -> None:
    register_stage(REHOST_STAGE, firmware_rehost_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=600)


def enqueue_rehost(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, REHOST_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
