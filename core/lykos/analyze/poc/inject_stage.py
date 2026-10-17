"""Phase 6 — the `synthesize_injection` stage: turn static injection candidates into confirmed
PoCs without fuzzing. For each injection class whose sink the binary imports (system/popen ->
command injection, printf-family -> format string, fopen/open -> path traversal), synthesize
marked payloads, deliver them over the input channel, detonate in the sandbox, and confirm by
effect (marker in output / leaked pointers / /etc/passwd content). A confirmed probe yields a
poc-backed finding carrying the exact demonstrating input.
"""
from __future__ import annotations

import json
import logging
import os
import re

from ... import observe
from ...db.dao import CallEdgeDAO, FindingDAO, PocDAO, TargetDAO
from ...jobs.registry import register_stage
from ..detect.catalog import normalize
from ..dynamic import sandbox
from . import bundle, injection

_log = logging.getLogger(__name__)

INJECT_STAGE = "synthesize_injection"
TOOL = "inject"
TOOL_VERSION = "inject-1"


def _marker():
    return "LYK" + os.urandom(5).hex().upper()       # unique per run, avoids stale-output hits


def _channels(call_edges, given):
    if given:
        return [given]
    names = {normalize(e.dst_name) for e in call_edges if e.dst_name}
    order = []
    if names & {"fopen", "fopen64", "open", "open64", "freopen"}:
        order.append("file")
    if names & {"read", "fgets", "gets", "scanf", "__isoc99_scanf", "fread", "getline"}:
        order.append("stdin")
    order.append("arg")
    for m in ("stdin", "arg", "file"):
        if m not in order:
            order.append(m)
    return order


def _deliver(mode, payload, argv_base, ctx, nav=b""):
    if isinstance(payload, str):
        payload = payload.encode()
    if mode == "stdin":
        return list(argv_base), nav + payload
    if mode == "arg":
        return argv_base + [payload.decode("latin-1")], nav
    wf = ctx.scratch() / "input.bin"
    wf.write_bytes(payload)
    return argv_base + [str(wf)], nav


def _nav_preambles(ctx, target, target_bytes):
    """Stdin byte prefixes that NAVIGATE to a sink the entry channel cannot reach.

    A sink behind a menu branch (`printf(user)` under option 2) or an input gate never sees the
    probe: the first read consumes the payload as the menu choice, it fails to parse, and the
    program exits -- which this stage used to report as "no injection confirmed on the entry
    channel". Prepending a menu selection / gate-passing preamble puts the program AT the sink
    before the payload is read. Returns only the non-empty prefixes, in cheapest-first order; the
    bare attempt is made separately so an already-reachable sink costs exactly what it did before.
    """
    from ...db.dao import StringDAO  # local: a sibling-scope import here bites
    from .. import interaction
    try:                                              # detect_menu needs DISASSEMBLER strings --
        strings = [s.value for s in StringDAO(ctx.conn).list_by_target(target.id)]
    except Exception:                                 # noqa: BLE001 -- ElfInfo has no .strings
        strings = []
    try:
        model = interaction.build_model(target_bytes, strings=strings)
    except Exception:                                 # noqa: BLE001
        return []
    out = []
    for opt in (model.menu_opts or [])[:8]:           # select each advertised menu branch FIRST:
        out.append(str(opt).encode() + b"\n")         # highest-signal, and exactly one is the sink
    # Gates are tried after because _gate_preambles is deliberately over-broad -- on a target with
    # no real gate it returns imported symbol names and the interpreter path, so leading with them
    # just buys sandbox runs. Harmless, but they go last.
    for g in (model.gate_preambles or [])[:4]:        # pass an input gate (strstr/banner reply)
        g = g if isinstance(g, bytes) else str(g).encode()
        out.append(g if g.endswith(b"\n") else g + b"\n")
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq[:10]


def synthesize_injection_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("synthesize_injection requires a target_id")
    p = ctx.params or {}
    call_edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    names = {normalize(e.dst_name) for e in call_edges if e.dst_name}
    applicable = {k: v for k, v in injection.PROBES.items() if names & v["sinks"]}
    if not applicable:
        ctx.emit("inject.done", payload={"ok": True, "confirmed": 0,
                 "note": "the binary imports no command/format/file sinks to probe"})
        ctx.progress(pct=100, msg="no injection sinks present")
        return {}

    channels = _channels(call_edges, p.get("input_mode"))
    argv_base = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 8))
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / "target.bin"
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)

    ctx.emit("inject.start", payload={"probes": sorted(applicable), "channels": channels})
    confirmed = []
    navs = None                                      # built lazily: only a failing probe needs it
    for name, spec in applicable.items():
        marker = _marker()
        payloads = spec["payloads"](marker)

        def _attempt(payload, mode, nav=b"", spec=spec, marker=marker):
            run_argv, stdin = _deliver(mode, payload, argv_base, ctx, nav)
            res = sandbox.run(exe, argv=run_argv, stdin=stdin, timeout=timeout,
                              arch=target.arch, endianness=target.endianness, bits=target.bits)
            out = (res.stdout or b"") + b"\n" + (res.stderr or b"")
            if not spec["confirm"](out, payload, marker):
                return None
            return {"payload": payload, "mode": mode, "signal": res.signal_name, "out": out,
                    "marker": marker, "argv_base": list(argv_base), "nav": nav, "stdin": stdin}

        hit = None
        for payload in payloads:                     # 1. the entry channel, exactly as before
            for mode in channels:
                ctx.progress(msg=f"probing {name} ({mode})")
                hit = _attempt(payload, mode)
                if hit:
                    break
            if hit:
                break
        if hit is None:                              # 2. NAVIGATE to a sink behind a menu / gate
            if navs is None:
                navs = _nav_preambles(ctx, target, target_bytes)
            for nav in navs:
                for payload in payloads:
                    ctx.progress(msg=f"probing {name} (stdin after {nav[:8]!r})")
                    hit = _attempt(payload, "stdin", nav)
                    if hit:
                        break
                if hit:
                    break
        if hit:
            confirmed.append({"probe": name, **_finalize(ctx, target, target_bytes, spec, hit)})

    ctx.emit("inject.done", payload={"ok": True, "confirmed": len(confirmed),
             "results": [{"probe": c["probe"], "cwe": c["cwe"], "mode": c["mode"]}
                         for c in confirmed],
             "note": None if confirmed else
                     "no injection confirmed on the entry channel or behind any of the %d "
                     "navigation preamble(s) tried (menu branches / input gates)" % len(navs or [])})
    ctx.progress(pct=100, msg=f"{len(confirmed)} injection PoC(s) confirmed")
    return {}


_HEXWORD = re.compile(rb"0x[0-9a-f]{4,}|\(nil\)|\(null\)")


def _leaked_words(out: bytes, marker: str):
    """The memory words a format-string probe disclosed: the hex pointers / (nil) it printed
    AFTER the marker (so the marker echo itself is not counted). Each hex word is also decoded to
    ASCII where it is printable -- that is how a leaked stack canary / secret string shows up."""
    seg = out.split(marker.encode(), 1)[-1]
    words = [w.decode("latin-1") for w in _HEXWORD.findall(seg)][:16]
    ascii_hits = []
    for w in words:
        if w.startswith("0x"):
            try:
                b = int(w, 16).to_bytes(8, "little")
                s = "".join(chr(c) if 0x20 <= c < 0x7f else "" for c in b)
                if len(s) >= 4:
                    ascii_hits.append(s)
            except Exception:
                observe.absorbed(_log, "continuing")
    return words, ascii_hits


def _fmt_bases(ctx, target, hit):
    """What a format string's leak PROVES, not just that it leaked. `%p` output is pointer-shaped
    text, and a disclosure of stack padding and a disclosure of the image base are both "memory
    leak" until someone resolves them -- the second one hands over the missing half of a chain.
    `leak.disclosed_bases` answers it against the target's OWN symbol layout (a pointer's low 12
    bits are page-invariant), so a base is accepted only where it is anchored, never guessed.

    Classified on the ONE captured run. Pooling runs would be wrong: under ASLR each run's
    pointers belong to a different base, and slots from two bases corroborate nothing."""
    from . import leak as _leak
    out = hit.get("out") or b""
    if not out:
        return {}
    try:
        target_bytes = ctx.content.path(target.sha256).read_bytes()
    except Exception:                                    # noqa: BLE001
        return {}
    from .exploit_stage import _libc_bytes_for
    try:
        return _leak.disclosed_bases(out, target_bytes, _libc_bytes_for(ctx, target) or b"")
    except Exception:                                    # noqa: BLE001
        observe.absorbed(_log, "classifying the format-string leak")
        return {}


def _disclosure_effect(ctx, spec, hit, input_sha, bundle_sha, bases=None):
    """The end effect an injection PoC demonstrates, with the captured output as proof. Returns
    (eff_line, headline_title, effects_evidence_entry). For a format string, the proof is the
    leaked memory itself (persisted), including any secret bytes it exposed."""
    cwe = spec.get("cwe", "")
    out = hit.get("out") or b""
    if cwe == "CWE-134":
        words, ascii_hits = _leaked_words(out, hit.get("marker", ""))
        proof_sha = ctx.put_artifact("disclosure-proof", data=out[:4096])
        note = (f"format string leaked {len(words)} live memory word(s): "
                + " ".join(words[:8])
                + (f" -- decodes to {', '.join(repr(a) for a in ascii_hits[:3])} "
                   "(leaked stack strings / secrets)" if ascii_hits else ""))
        # WHAT the words were. The headline distinction: padding and the image base are both a
        # "memory leak" until one of them is resolved, and only one of them defeats ASLR.
        got = ", ".join(f"{n} {v:#x}" for n, v in
                        (("image base", (bases or {}).get("pie_base")),
                         ("libc base", (bases or {}).get("libc_base")),
                         ("stack canary", (bases or {}).get("canary"))) if isinstance(v, int))
        if got:
            note += (f" -- and those pointers RESOLVE: {got}, corroborated against the target's "
                     f"own symbol layout by the {(bases or {}).get('rule') or 'page-offset'} rule. "
                     "ASLR is defeated from this leak alone (an L2 disclosure primitive).")
        effs = [{"kind": "info-disclosure",
                 "title": ("ASLR defeated by a format string" if got
                           else "Information disclosure (memory leak)"),
                 "status": "demonstrated", "detail": note,
                 "proof": {"type": "artifact", "sha": proof_sha, "input_sha": input_sha,
                           "note": note}},
                {"kind": "memory-corruption",
                 "title": "Memory corruption (arbitrary write)", "status": "potential",
                 "detail": "the same format string can write with %n (write-what-where)"}]
        title = (f"ASLR defeated by a format string (discloses the {got.split(' 0x')[0]}) "
                 "(demonstrated): L2 primitive" if got
                 else "Information disclosure (memory leak) (demonstrated): format string")
    elif cwe in ("CWE-78", "CWE-94"):
        effs = [{"kind": "injection", "title": "Command / code injection", "status": "demonstrated",
                 "detail": "an injected command ran (its marker appeared in output)",
                 "proof": {"type": "bundle", "sha": bundle_sha, "input_sha": input_sha}}]
        title = "Command / code injection (demonstrated)"
    elif cwe == "CWE-89":
        proof_sha = ctx.put_artifact("disclosure-proof", data=out[:4096])
        effs = [{"kind": "injection", "title": "SQL injection", "status": "demonstrated",
                 "detail": "a UNION-injected marker column was returned by the database -- the input "
                           "is concatenated into the query, so an attacker controls its SQL (read "
                           "or, via stacked/2nd-order queries, modify arbitrary data)",
                 "proof": {"type": "bundle", "sha": bundle_sha, "input_sha": input_sha}},
                {"kind": "info-disclosure", "title": "Database disclosure", "status": "demonstrated",
                 "detail": "the query returns attacker-chosen rows",
                 "proof": {"type": "artifact", "sha": proof_sha, "input_sha": input_sha}}]
        title = "SQL injection (demonstrated)"
    elif cwe == "CWE-918":
        proof_sha = ctx.put_artifact("disclosure-proof", data=out[:4096])
        effs = [{"kind": "ssrf", "title": "Server-side request forgery", "status": "demonstrated",
                 "detail": "the server fetched an attacker-controlled URL -- demonstrated with a "
                           "file: URL that returned a local file; the same control reaches internal "
                           "services (http://169.254.169.254/, localhost) in a live environment",
                 "proof": {"type": "artifact", "sha": proof_sha, "input_sha": input_sha}}]
        title = "Server-side request forgery (demonstrated): SSRF"
    elif cwe == "CWE-611":
        proof_sha = ctx.put_artifact("disclosure-proof", data=out[:4096])
        effs = [{"kind": "info-disclosure", "title": "XML external entity (file disclosure)",
                 "status": "demonstrated",
                 "detail": "an external XML entity resolved a local file (/etc/passwd) and its "
                           "content was returned -- the parser substitutes attacker-named SYSTEM "
                           "entities (can also reach internal network services / exfil)",
                 "proof": {"type": "artifact", "sha": proof_sha, "input_sha": input_sha}}]
        title = "Information disclosure (demonstrated): XML external entity (XXE)"
    else:                                              # path traversal etc. -> disclosure
        proof_sha = ctx.put_artifact("disclosure-proof", data=out[:4096])
        effs = [{"kind": "info-disclosure", "title": "Information disclosure",
                 "status": "demonstrated", "detail": "read content outside the intended scope",
                 "proof": {"type": "artifact", "sha": proof_sha, "input_sha": input_sha}}]
        title = "Information disclosure (demonstrated): path traversal"
    return (None, title, {"channel": "effects", "detail": json.dumps(effs)})


def _finalize(ctx, target, target_bytes, spec, hit):
    payload = hit["payload"]
    pb = payload if isinstance(payload, bytes) else payload.encode()
    mode = hit["mode"]
    # The DEMONSTRATING input is whatever actually went down the channel. When the sink sat behind
    # a menu branch that is navigation + payload, and shipping the bare payload would hand the user
    # a bundle that replays to a clean exit.
    nav = hit.get("nav") or b""
    delivered = hit.get("stdin") if mode == "stdin" and hit.get("stdin") else pb
    input_sha = ctx.put_artifact("inject-input", data=delivered)
    # Record the ACTUAL base argv that delivered the payload (the discovered flags / `@@`), not a
    # bare re-derivation: dropping it produced a bundle that a replayer could not reproduce for any
    # target that takes its input behind a flag. The mode + argv_base let the replay place the input.
    run_argv = list(hit.get("argv_base") or [])
    shown = pb.decode("latin-1")[:80]
    detail = (f"{spec['title']} confirmed at runtime via {mode}: payload {shown!r} produced the "
              f"expected effect (no fuzzing)")
    if nav:
        detail += (f" -- reached by navigating first with {nav.decode('latin-1')!r} "
                   "(the sink is behind a menu branch / input gate)")
    # L2 where the leak RESOLVES a base. The injection PoCs are all filed at L1 -- "this defect is
    # real and here is a reproducer" -- and for a format-string READ that was the ceiling, measured:
    # the class demonstrated a leak and could not say the leak was worth anything, so a %p dump that
    # defeats ASLR ranked with one that prints padding. An anchored base is a disclosure PRIMITIVE,
    # the same rung the out-of-bounds read arm claims for the same evidence.
    bases = _fmt_bases(ctx, target, hit) if spec.get("cwe") == "CWE-134" else {}
    level = "L2" if bases.get("proved") else "L1"
    meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
            "argv": run_argv, "level": level, "cwe": spec["cwe"], "injection": spec["title"],
            "tool_version": TOOL_VERSION}
    if nav:
        meta["navigation"] = nav.decode("latin-1")
    data = bundle.build(target_bytes, delivered, meta, b"", mode, run_argv, "none")
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"verified": True, "level": level})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level=level, verified=True,
                                     signal_name=None, input_sha=input_sha, bundle_sha=bundle_sha)
    # The end effect this injection DEMONSTRATES, headlined on the finding, with the captured
    # evidence as proof: a format string leaks live memory (stack words, often secrets), a
    # command injection runs an attacker command, a traversal reads an out-of-scope file.
    eff_line, eff_title, eff_evidence = _disclosure_effect(ctx, spec, hit, input_sha, bundle_sha,
                                                           bases=bases)
    ev = [{"channel": "injection", "detail": detail},
          {"channel": "poc", "detail": f"verified PoC bundle {bundle_sha[:12]}"}]
    if eff_evidence:
        ev.append(eff_evidence)
    fd = FindingDAO(ctx.conn)
    fd.upsert(target.id, target.case_id, {
        "cwe": spec["cwe"], "severity": spec["severity"], "detector": "inject_synth",
        "title": eff_title or f"{spec['title']} (confirmed PoC)",
        "evidence": ev,
        "function_addr": None, "site_addr": None,
        "dedup_key": f"{spec['cwe']}:inject:{mode}", "state": "poc-backed", "confidence": 0.97})
    fid = fd.id_for_dedup(target.id, f"{spec['cwe']}:inject:{mode}")
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    return {"cwe": spec["cwe"], "mode": mode, "bundle": bundle_sha, "input_sha": input_sha,
            "level": level, "bases": {k: v for k, v in bases.items()
                                      if k in ("pie_base", "libc_base", "canary", "rule")}}


def register() -> None:
    register_stage(INJECT_STAGE, synthesize_injection_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=180)


def enqueue_inject(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, INJECT_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
