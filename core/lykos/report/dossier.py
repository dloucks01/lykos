"""The engagement narrative: what a reader of the report needs, in the order they need it.

The report model (`model.build_report`) is an inventory -- every finding, every engine, every
stage's timing -- and both renderers used to print it top to bottom. Measured on jhead 3.06.0.1
(stripped, hardened): the ONE demonstrated vulnerability first appeared on page 5 of 14, titled
"Reproduced crash (SIGSEGV)" at `site=0xa3f0`, with no word that it is a heap over-read, that it
needs `-exifmap -mkexif`, how to reproduce it, what the input looks like, what it means or how to
fix it -- labelled `critical` for what is a 9-byte read crash -- after a page of internal tool ids
and two pages of techniques that ran for 0 s, and before 20 import-pattern notes printed ten lines
each.

This module builds the part a reader acts on, from data the case already holds:

  * executive  -- the bottom line in plain sentences, an overall risk, the actions to take;
  * dossiers   -- one per DEMONSTRATED finding: what it is, where, how it is triggered, exact
                  reproduction, the input, the evidence, the demonstrated impact and the reason
                  escalation stopped, a severity ASSESSED from that impact (with its rationale),
                  and remediation;
  * leads      -- every unproven finding, grouped (one row per kind, not per call site), each with
                  why it is not proven and what would prove it;
  * scope / methodology / limitations -- how the target was run, what was done, and what was not.

Nothing here invents evidence: every field is read from a stage's own record, and a field the
case does not hold is left out rather than guessed.
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

#: Demonstrated = reproduced by execution. Everything else is a lead.
DEMONSTRATED = ("confirmed", "poc-backed")

_LEVEL_RANK = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# --------------------------------------------------------------------------- sanitizer reports
_ASAN_ERR = re.compile(r"ERROR: (AddressSanitizer|MemorySanitizer|ThreadSanitizer|"
                       r"LeakSanitizer|UndefinedBehaviorSanitizer): ([\w-]+)")
_ASAN_ACCESS = re.compile(r"\b(READ|WRITE) of size (\d+)")
_ASAN_FRAME = re.compile(r"#(\d+) 0x[0-9a-f]+ in (\S+) ([^\s:]+):(\d+)")
_ASAN_REGION = re.compile(r"is located (\d+) bytes? (after|before|inside|to the right of|"
                          r"to the left of) (\d+)-byte region")
_UBSAN = re.compile(r"([^\s:]+):(\d+):(\d+): runtime error: (.+)")


def parse_sanitizer(text: str) -> Optional[dict]:
    """The facts a sanitizer report states, or None. Read, never inferred."""
    if not text:
        return None
    m = _ASAN_ERR.search(text)
    u = _UBSAN.search(text)
    if not m and not u:
        return None
    out: dict[str, Any] = {}
    if m:
        out["tool"], out["kind"] = m.group(1), m.group(2)
        a = _ASAN_ACCESS.search(text)
        if a:
            out["access"], out["size"] = a.group(1).lower(), int(a.group(2))
        frames = []
        for f in _ASAN_FRAME.finditer(text[m.start():]):
            frames.append({"fn": f.group(2), "file": f.group(3).rsplit("/", 1)[-1],
                           "line": int(f.group(4)), "path": f.group(3)})
            if len(frames) >= 6 or "allocated by" in text[m.start():f.start() + m.start()]:
                break
        out["frames"] = frames
        r = _ASAN_REGION.search(text)
        if r:
            out["region"] = {"offset": int(r.group(1)), "where": r.group(2),
                             "size": int(r.group(3))}
    elif u:
        out.update(tool="UndefinedBehaviorSanitizer", kind="undefined-behavior",
                   frames=[{"fn": "", "file": u.group(1).rsplit("/", 1)[-1],
                            "line": int(u.group(2)), "path": u.group(1)}],
                   message=u.group(4).strip())
    return out


# --------------------------------------------------------------------------- severity
def assess_severity(f: dict, level: str, *, access: Optional[str], effect: Optional[str],
                    controlled: Optional[bool], kind: str = "") -> tuple[str, str]:
    """(severity, rationale) from what was DEMONSTRATED, not from the detector's prior.

    The crash finding a fuzzer files is `critical` before anyone knows what the crash is; for a
    9-byte read past a buffer that overstates the risk by two grades, and a reader who trusts the
    grade spends their week on the wrong bug. The assessed grade follows the strongest effect a
    replay actually showed, and says which one."""
    cwe = (f.get("cwe") or "").upper()
    k = (kind or "").lower()
    if level == "L3":
        return "critical", ("a working exploit was demonstrated: the attacker's code or command "
                            "ran in the target process")
    if level == "L2" and controlled:
        if effect in ("control-flow-hijack",) or "hijack" in k or "pc" in (effect or ""):
            return "critical", ("control of the instruction pointer was demonstrated; with an "
                                "address leak this is code execution")
        if effect == "arbitrary-write" or access == "write":
            return "critical", "an attacker-chosen memory WRITE was demonstrated"
        return "high", ("an attacker-chosen memory READ was demonstrated (information disclosure "
                        "across the process)")
    if cwe in ("CWE-835", "CWE-400", "CWE-674"):
        return "medium", "a reproducible hang/exhaustion: denial of service"
    if cwe == "CWE-401":
        return "low", "a reproducible memory leak: slow resource exhaustion"
    if access == "write" or "use-after-free" in k or "double-free" in k or cwe in (
            "CWE-416", "CWE-415", "CWE-787", "CWE-121", "CWE-122"):
        return "high", ("memory CORRUPTION reproduced (an out-of-bounds or freed-memory write); "
                        "exploitation was not demonstrated, but this class routinely is")
    if "null" in k or cwe == "CWE-476":
        return "medium", "a reproducible NULL-pointer crash: denial of service"
    if access == "read" or cwe in ("CWE-125", "CWE-126", "CWE-127"):
        return "medium", ("an out-of-bounds READ reproduced: the process crashes (denial of "
                          "service), and on an unguarded heap it reads adjacent memory")
    if level in ("L1", "L2"):
        return "medium", ("a reproducible crash (denial of service); what the faulting access "
                          "can be turned into was not demonstrated")
    return (f.get("severity") or "medium"), "detector's grade (impact not measured)"


# --------------------------------------------------------------------------- per-case lookups
class _Case:
    """Lazy, per-case indexes over the stores the dossiers read."""

    def __init__(self, store, case_id: str):
        self.store, self.case_id = store, case_id
        self.conn = store.conn
        self._runs = None
        self._events: Optional[dict] = None

    def runs(self):
        if self._runs is None:
            from ..db.dao import AnalysisRunDAO
            self._runs = AnalysisRunDAO(self.conn).list_by_case(self.case_id)
        return self._runs

    def runs_for_input(self, stage: str, input_sha: str) -> list:
        return [r for r in self.runs() if r.stage == stage
                and (r.params or {}).get("input_sha") == input_sha]

    def events_of(self, etype: str) -> dict:
        """{run_id: payload} for one event type (the last payload per run)."""
        if self._events is None:
            want = {"primitive.done", "primitive.address", "rootcause.done",
                    "exploit.done", "exploit.declined"}
            ev: dict = {}
            for e in self.store.events.walk(case_id=self.case_id):
                if e.type in want and e.run_id:
                    ev.setdefault(e.type, {})[e.run_id] = e.payload or {}
            self._events = ev
        return self._events.get(etype, {})

    def output_json(self, run, kind: str) -> Optional[dict]:
        rows = self.conn.execute(
            "SELECT a.sha256 FROM run_artifact ra JOIN artifact a ON a.sha256=ra.artifact_sha256 "
            "WHERE ra.run_id=? AND a.kind=?", (run.id, kind)).fetchall()
        for (sha,) in rows:
            try:
                return json.loads(self.store.content.get_bytes(sha))
            except Exception:                            # noqa: BLE001 -- an evicted artifact
                continue
        return None

    def bytes_of(self, sha: Optional[str]) -> Optional[bytes]:
        if not sha:
            return None
        try:
            return self.store.content.get_bytes(sha)
        except Exception:                                # noqa: BLE001
            return None


def _hexdump(data: bytes, n: int = 64) -> list[str]:
    out = []
    for i in range(0, min(len(data), n), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{i:04x}  {hx:<47}  {asc}")
    return out


def _fn_name_at(fns, addr: Optional[int]) -> Optional[str]:
    """The recovered function containing an image-relative address, by nearest start below it."""
    if addr is None or not fns:
        return None
    best = None
    for f in fns:
        a = getattr(f, "addr", None)
        if a is None:
            continue
        try:
            a = int(a, 16) if isinstance(a, str) else int(a)
        except (TypeError, ValueError):
            continue
        if a <= addr and (best is None or a > best[0]):
            best = (a, getattr(f, "name", None))
    return best[1] if best else None


def _place(argv: list, carrier: str) -> list:
    return [carrier if a == "@@" else a for a in argv] if "@@" in argv else argv + [carrier]


# --------------------------------------------------------------------------- one dossier
def _dossier(cx: _Case, t: dict, f: dict, fns) -> dict:
    from ..db.dao import DynResultDAO
    pocs = [p for p in f.get("pocs") or [] if p.get("verified")] or (f.get("pocs") or [])
    pocs.sort(key=lambda p: _LEVEL_RANK.get(p.get("level") or "L0", 0), reverse=True)
    poc = pocs[0] if pocs else None
    level = f.get("level") or (poc or {}).get("level") or ""
    input_sha = (poc or {}).get("input_sha") or next(
        (c.get("input_sha") for c in f.get("crashes") or [] if c.get("input_sha")), None)
    dyns = [d for d in DynResultDAO(cx.conn).list_by_target(t["id"])
            if input_sha and d.input_sha == input_sha]
    dyn = next((d for d in dyns if d.argv), dyns[0] if dyns else None)
    argv = list((dyn.argv if dyn else None) or [])
    mode = (dyn.input_mode if dyn else None) or "file"
    guarded = any("guardpage" in (d.isolation or "") for d in dyns)

    # the stages that measured this input
    rc = None
    for r in cx.runs_for_input("root_cause", input_sha or ""):
        rc = cx.output_json(r, "root-cause") or rc
    prim = None
    for r in cx.runs_for_input("poc_primitive", input_sha or ""):
        p = cx.events_of("primitive.done").get(r.id)
        if p:
            prim = p
    av = (prim or {}).get("address_verdict") or {}
    pv = (prim or {}).get("primitive") or {}
    stderr = ""
    for d in dyns:
        b = cx.bytes_of(d.stderr_sha)
        if b:
            stderr = b.decode("latin-1", "ignore")
            break
    san = parse_sanitizer(stderr)

    # what it is, in words
    access = (san or {}).get("access") or av.get("access") or pv.get("access")
    kind = (san or {}).get("kind") or ((rc or {}).get("classification") or {}).get("class") or ""
    effect = pv.get("effect_kind") or av.get("effect_kind")
    controlled = bool(pv.get("controlled") or av.get("controlled"))
    sev, why_sev = assess_severity(f, level, access=access, effect=effect,
                                   controlled=controlled, kind=kind)
    what = _what_it_is(f, san, av, pv, rc, access)

    # where
    site = f.get("site_addr")
    try:
        site_i = int(site, 16) if isinstance(site, str) else site
    except (TypeError, ValueError):
        site_i = None
    loc: dict[str, Any] = {"site": site}
    fn = (((rc or {}).get("slice") or {}).get("crash_function") or {}).get("name") \
        or _fn_name_at(fns, site_i)
    if fn:
        loc["function"] = fn
    if av.get("disasm") or pv.get("disasm"):
        loc["instruction"] = av.get("disasm") or pv.get("disasm")
    if san and san.get("frames"):
        fr = san["frames"][0]
        loc["source"] = f'{fr["file"]}:{fr["line"]}' + (f' in {fr["fn"]}' if fr["fn"] else "")
        loc["stack"] = [f'{x["fn"]} ({x["file"]}:{x["line"]})' for x in san["frames"]]

    # how it is triggered and reproduced
    exe = t.get("filename") or "target"
    flags = [a for a in argv if a != "@@"]
    trig = []
    if flags:
        trig.append("invoked with " + " ".join(flags) + " (options the fuzzer found; the defect "
                    "is not reached without them)")
    trig.append({"file": "input delivered as a file argument", "stdin": "input on standard input",
                 "arg": "input as a command-line argument",
                 "env": "input in an environment variable"}.get(mode, f"input via {mode}"))
    if guarded:
        trig.append("observed under a guard-page allocator (libdislocator): the access faults "
                    "at the buffer end instead of silently reading the neighbouring heap bytes")
    if mode == "file":
        cmd = " ".join([f"./{exe}"] + _place(argv or ["@@"], "poc-input.bin"))
    elif mode == "stdin":
        cmd = f"./{exe} {' '.join(flags)} < poc-input.bin".replace("  ", " ")
    else:
        cmd = f"./{exe} {' '.join(flags)} <input>".strip()
    if guarded:
        cmd = "LD_PRELOAD=/usr/lib/afl/libdislocator.so " + cmd
    repro = []
    if poc and poc.get("bundle_sha"):
        b = (poc.get("bundle_sha") or "")[:8]
        repro.append({"note": "the self-contained PoC bundle (target, input and runner):",
                      "cmd": f"tar xzf {exe}-{level or 'L1'}-{b}.tar.gz && sh poc/runner.sh"})
    repro.append({"note": "or by hand, with the crash input saved as poc-input.bin "
                          "(run in a sandbox or VM):", "cmd": cmd})
    data = cx.bytes_of(input_sha) or b""

    # impact and where escalation stopped
    stops = []
    note = av.get("note") or pv.get("note")
    if note:
        stops.append(note)
    if (rc or {}).get("exploitability"):
        ex = rc["exploitability"]
        stops.append(f'root-cause exploitability: {ex.get("rating")} ({ex.get("score")}/100)'
                     + (": " + "; ".join(ex.get("reasons") or [])[:300] if ex.get("reasons")
                        else ""))
    for d in ((t.get("execution") or {}).get("declined") or []):
        if isinstance(d, dict) and d.get("stage") == "build_exploit":
            stops.append(f'exploit construction declined: {d.get("reason")}')
    # The exploit mitigations matter to a defect that could become control (a write, a hijack);
    # listing stack canaries under a heap READ crash is noise.
    mit = (((f.get("exploitability") or {}).get("mitigations_in_way") or [])[:4]
           if (access != "read" or controlled) else [])

    from .html import _remediation
    return {
        "id": f.get("id"), "title": what["title"], "summary": what["summary"],
        "cwe": f.get("cwe"), "cwe_name": f.get("cwe_name"), "state": f.get("state"),
        "level": level, "verified": bool((poc or {}).get("verified")),
        "severity": sev, "severity_why": why_sev, "detector_severity": f.get("severity"),
        "location": loc, "trigger": trig, "reproduce": repro,
        "input": {"sha256": input_sha, "size": len(data), "hex": _hexdump(data),
                  "mode": mode} if input_sha else None,
        "evidence": _evidence_lines(f, dyns, san, av),
        "sanitizer": san, "impact": _impact_line(level, sev, controlled, access),
        "escalation": stops, "mitigations": mit,
        # The remediation follows what the defect DOES: CWE-119 is the umbrella a binary crash is
        # filed under, and its write-overflow advice is wrong for a read past the buffer end.
        "remediation": _remediation("CWE-125" if access == "read" and f.get("cwe") in (
            "CWE-119", None) else ("CWE-787" if access == "write" and f.get("cwe") == "CWE-119"
                                   else f.get("cwe"))),
        "found_by": f.get("stage_label") or f.get("detector"),
        "bundle": (poc or {}).get("bundle_sha"),
    }


def _what_it_is(f, san, av, pv, rc, access) -> dict:
    """A title that names the DEFECT, and one sentence that explains it."""
    if san and san.get("kind"):
        k = san["kind"].replace("-", " ")
        acc = f' {san["access"].upper()} of {san["size"]} byte(s)' if san.get("access") else ""
        where = ""
        if san.get("region"):
            r = san["region"]
            where = f' {r["offset"]} byte(s) {r["where"]} a {r["size"]}-byte buffer'
        fn = (san.get("frames") or [{}])[0].get("fn") or ""
        title = f"{k[0].upper()}{k[1:]}" + (f" in {fn}()" if fn else "")
        return {"title": title,
                "summary": f"{san['tool']} reports a {k}:{acc}{where}"
                           + (f", in {fn}()" if fn else "") + "."}
    eff = pv.get("effect_kind") or av.get("effect_kind")
    if av and av.get("access") and not av.get("controlled"):
        acc = av["access"]
        past_end = "page boundary" in (av.get("note") or "")
        return {"title": f"Out-of-bounds {acc}" + (" past the end of a heap buffer" if past_end
                                                    else "") + " (crash)",
                "summary": ((f"The program {'reads' if acc == 'read' else 'writes'} beyond the "
                             f"end of a heap buffer, at the instruction "
                             f"`{av.get('disasm') or '?'}`. ")
                            if past_end else
                            (f"An out-of-bounds memory {acc} faults at "
                             f"`{av.get('disasm') or '?'}`. "))
                           + f"The attacker controls whether it happens, not where it {acc}s."}
    if rc and rc.get("summary"):
        return {"title": f.get("title") or "Reproduced crash", "summary": rc["summary"]}
    if eff == "control-flow-hijack":
        return {"title": "Control-flow hijack", "summary": pv.get("note") or ""}
    return {"title": f.get("title") or "Reproduced crash",
            "summary": f.get("cwe_desc") or ""}


def _impact_line(level, sev, controlled, access) -> str:
    return {
        "L3": "Demonstrated: code execution in the target process.",
        "L2": ("Demonstrated: an exploitation primitive -- "
               + ("the attacker controls the faulting address." if controlled
                  else "see the measurement below.")),
        "L1": ("Demonstrated: a reproducible crash on attacker input (denial of service)"
               + (f"; the faulting access is a {access}" if access else "") + "."),
    }.get(level, "Demonstrated by execution (no PoC bundle level recorded).")


def _evidence_lines(f, dyns, san, av) -> list[str]:
    out = []
    sigs = sorted({d.signal_name for d in dyns if d.signal_name})
    if dyns:
        out.append(f"replayed {len(dyns)} time(s) in the sandbox; every replay faulted "
                   f"({', '.join(sigs) or 'sanitizer abort'})")
    if av.get("observations"):
        out.append(f'{av.get("observations")} detonations measured the faulting address: '
                   f'{av.get("effect_kind")}')
    if san:
        out.append(f'{san.get("tool")}: {san.get("kind")}'
                   + (f' ({san["access"]} of {san["size"]})' if san.get("access") else ""))
    for e in f.get("evidence") or []:
        d = (e.get("detail") or "").strip()
        if e.get("channel") in ("dynamic", "poc", "root-cause", "exploitability") and d:
            out.append(d[:240])
    return out[:8]


# --------------------------------------------------------------------------- leads
_PATTERN_LINE = re.compile(r"call to [\w.]+\(\) at 0x[0-9a-f]+")


def compact_evidence(ev: list) -> list:
    """An evidence trail a person can read: repeated call-site lines folded into one, and the
    machine-readable blobs (`grounding-map` JSON) dropped -- they are for the GUI, not a page."""
    out, sites, first_site = [], [], None
    for e in ev or []:
        ch, d = e.get("channel", ""), (e.get("detail") or "")
        if ch == "grounding-map" or d.lstrip().startswith("{"):
            continue
        if ch == "pattern" and _PATTERN_LINE.search(d):
            sites.append(d.rsplit(" at ", 1)[-1])
            if first_site is None:
                first_site = d.rsplit(" at ", 1)[0]
                out.append(None)                         # placeholder, filled below
            continue
        out.append(e)
    if first_site is not None:
        shown = ", ".join(sites[:4]) + (f" (+{len(sites) - 4} more)" if len(sites) > 4 else "")
        out[out.index(None)] = {"channel": "pattern",
                                "detail": f"{first_site} at {len(sites)} site(s): {shown}"}
    return out


_KIND = {
    "dangerous_api": ("API-use pattern", "the binary calls a risky library function; that "
                      "alone is not a vulnerability"),
    "inject_synth": ("computed payload, not executed", "a payload was computed for the sink "
                     "but never observed to work"),
    "synth_overflow": ("computed payload, not executed", "an overflow layout was computed from "
                       "the stack frame but did not reproduce a crash"),
    "chain_primitive": ("computed payload, not executed", "an exploitation recipe that was not "
                        "detonated"),
    "uc_symbolic": ("symbolic lead", "under-constrained symbolic execution of a function in "
                    "isolation; its inputs are assumed attacker-controlled"),
    "fuzz": ("observed in execution, not verified", "the campaign saw it; the verification replay "
             "did not confirm it"),
    "coverage_fuzz": ("observed in execution, not verified", ""),
    "directed_fuzz": ("observed in execution, not verified", ""),
}


def _why_unproven(f: dict, det: str) -> tuple[str, str]:
    """(why it is not a demonstrated vulnerability, what would prove it), in the reader's terms."""
    ev = {e.get("channel"): (e.get("detail") or "") for e in f.get("evidence") or []}
    ceil = ev.get("recipe-ceiling") or ""
    m = re.search(r"\[needs: (.+?)\]\s*$", ceil)
    needs = m.group(1) if m else ""
    ground = ev.get("grounding") or ""
    unreached = "unreached" in ground or "not reached" in ground
    if det == "dangerous_api":
        return (("the binary calls this function" + (", but no path from attacker input to the "
                 "call was recovered" if unreached else "") + "; a call is a place to look, not a "
                 "defect"),
                "an input that reaches the call with attacker-controlled arguments and shows the "
                "effect (a fault, an executed command, an opened path)")
    if det in ("inject_synth", "synth_overflow", "chain_primitive"):
        why = "a payload was computed but never observed to work"
        if "no runtime marker" in ceil:
            why += ("; the injection probes delivered it on every channel they know and saw no "
                    "effect")
        return why, needs or "a run in which the payload produces its effect on the target"
    if det == "uc_symbolic":
        return ("symbolic execution of the function in isolation, with its arguments assumed "
                "attacker-controlled; no caller was shown to pass attacker data"),\
            "a driver or entry-point input that reaches the function and faults"
    if det in ("fuzz", "coverage_fuzz", "directed_fuzz"):
        return ("the fuzzing campaign observed it, but the differential replay that would prove "
                "it (against a control input) did not confirm it",
                "a replay that reproduces it while a control input does not")
    if f.get("state") == "corroborated":
        return ("two independent analyses agree, but no execution reproduced it",
                "an input that reproduces it under execution")
    return ("one analysis flagged it; nothing else has agreed yet",
            "a second, independent signal, then an input that reproduces it")


def _leads(t: dict) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for f in t.get("findings") or []:
        if f.get("state") in DEMONSTRATED:
            continue
        if (f.get("curation") or {}).get("status") == "false_positive":
            continue
        det = f.get("detector") or ""
        title = re.sub(r"\b(in|at) (fcn\.[0-9a-f]+|0x[0-9a-f]+|\w+_\w+)$", "", f.get("title") or "")
        key = (f.get("cwe"), det, title.strip())
        g = groups.setdefault(key, {
            "cwe": f.get("cwe"), "title": title.strip() or f.get("cwe"), "detector": det,
            "state": f.get("state"), "severity": f.get("severity"), "count": 0, "sites": 0,
            "kind": _KIND.get(det, ("static detection", "found by analysis, not by "
                                    "execution"))[0],
            "kind_note": _KIND.get(det, ("", "found by analysis, not by execution"))[1],
            "why": "", "next": ""})
        g["count"] += 1
        g["sites"] += max(1, sum(1 for e in f.get("evidence") or []
                                 if e.get("channel") == "pattern"))
        if _SEV_RANK.get(f.get("severity") or "info", 0) > _SEV_RANK.get(g["severity"] or "info", 0):
            g["severity"] = f.get("severity")
        if f.get("state") == "corroborated":
            g["state"] = "corroborated"
        if not g["why"]:
            g["why"], g["next"] = _why_unproven(f, det)
    order = {"corroborated": 0, "candidate": 1}
    return sorted(groups.values(), key=lambda g: (
        order.get(g["state"], 2), g["kind"] == "API-use pattern",
        -_SEV_RANK.get(g["severity"] or "info", 0), g["title"]))


# --------------------------------------------------------------------------- the whole narrative
def _engagement_kind(t: dict) -> str:
    declined = {d.get("stage"): d.get("reason") for d in
                ((t.get("execution") or {}).get("declined") or []) if isinstance(d, dict)}
    if "no archived source tree" in (declined.get("cpg_scan") or ""):
        return "binary-only (no source code)"
    return "source code + sanitizer build"


def _scope(cx: _Case, t: dict) -> dict:
    argv, mode, seeds = None, None, []
    for r in cx.runs():
        if r.target_id == t["id"] and r.stage == "fuzz":
            p = r.params or {}
            argv = argv or p.get("argv")
            mode = mode or p.get("input_mode")
            seeds = seeds or [str(s).rsplit("/", 1)[-1] for s in p.get("seed_files") or []]
    mits = t.get("mitigations") or {}
    return {
        "target": t.get("filename"), "sha256": t.get("sha256"), "size": t.get("size"),
        "type": f'{(t.get("file_type") or "?").upper()} {t.get("arch") or ""} '
                f'{t.get("bits") or ""}-bit'.strip(),
        "stripped": t.get("stripped"), "engagement": _engagement_kind(t),
        "invocation": (" ".join(argv) if argv else "inferred from the binary"),
        "input_mode": mode or "inferred", "seeds": seeds,
        "mitigations": ", ".join(f"{k} {'on' if v in (True, 'on', 1, 'full') else v}"
                                 for k, v in mits.items()) or "unknown",
    }


_PHASE = {
    "Recover": ("ingest_triage", "disassemble", "unpack", "firmware_carve", "triage"),
    "Detect": ("detect_cwe", "cpg_scan", "source_sink_scan", "oob_write_scan", "int_overflow_scan",
               "uaf_scan", "assert_guard_scan", "oob_index", "cve_scan", "source_cve_scan",
               "extract_secrets", "grounding", "weggli_scan", "variant_scan", "embedded_audit"),
    "Search": ("fuzz", "coverage_fuzz", "directed_fuzz", "env_fuzz", "net_fuzz", "boundary_fuzz",
               "libfuzzer", "concolic", "uc_symbolic", "dynamic_run", "heap_trace", "mem_oracle",
               "dynamic_taint", "behavior_trace", "harness"),
    "Prove": ("root_cause", "build_poc", "poc_primitive", "confirm", "source_confirm",
              "synth_confirm", "synthesize_poc", "multi_debug", "debug_monitor", "diff_test"),
    "Weaponize": ("build_exploit", "chain_primitive", "synthesize_injection", "cve_poc",
                  "synthesize_secret"),
}


def _methodology(report: dict, t: dict) -> list[dict]:
    techs = (report.get("timing") or {}).get("techniques") or []
    by_stage = {x.get("stage"): x for x in techs}
    eh = (t.get("engine_health") or {}).get("engines") or []
    eng = {e.get("engine"): e for e in eh}
    rows = []
    for phase, stages in _PHASE.items():
        ran = [by_stage[s] for s in stages if s in by_stage and (by_stage[s].get("seconds") or 0) > 0]
        if not ran:
            continue
        secs = sum(x.get("seconds") or 0 for x in ran)
        bits = []
        for x in sorted(ran, key=lambda x: -(x.get("seconds") or 0))[:6]:
            e = eng.get(x.get("stage")) or {}
            extra = []
            if e.get("execs"):
                extra.append(f'{int(e["execs"]):,} executions')
            if e.get("coverage"):
                extra.append(str(e["coverage"]))
            if x.get("findings"):
                extra.append(f'{x["findings"]} findings')
            if x.get("crashes"):
                extra.append(f'{x["crashes"]} crashes')
            bits.append(f'{x.get("label") or x.get("stage")} ({x.get("human")}'
                        + (", " + ", ".join(extra) if extra else "") + ")")
        rows.append({"phase": phase, "seconds": secs, "techniques": bits})
    return rows


def _limitations(t: dict) -> list[str]:
    ex = t.get("execution") or {}
    out = []
    no_src = []
    for d in ex.get("declined") or []:
        if not isinstance(d, dict) or d.get("stage") in ("net_fuzz", "boundary_fuzz"):
            continue
        r = d.get("reason") or ""
        if "source" in r and ("no archived" in r or "no source" in r or "needs C" in r):
            no_src.append(d.get("stage"))
        else:
            out.append(f'{d.get("stage")}: {r}')
    if no_src:
        out.insert(0, f"No source code was provided, so the {len(no_src)} source-code analyses "
                      f"did not apply ({', '.join(no_src)}). Supplying the source tree enables "
                      "them and a sanitizer build.")
    if ex.get("stages_skipped_for_budget"):
        out.append("not reached within the time budget: "
                   + ", ".join(map(str, ex["stages_skipped_for_budget"][:10])))
    if ex.get("failed_stages"):
        out.append("stages that failed: " + ", ".join(ex["failed_stages"]))
    out.append("Absence of a finding is not evidence of absence: only the code the search reached "
               "was tested, and only the defect classes its oracles can observe.")
    return out


def build_narrative(store, case_id: str, report: dict) -> dict:
    """The engagement narrative for a built report model (see the module docstring)."""
    from ..db.dao import FunctionDAO
    cx = _Case(store, case_id)
    targets = []
    all_dossiers = []
    for t in report.get("targets") or []:
        try:
            fns = FunctionDAO(store.conn).list_by_target(t["id"])
        except Exception:                                # noqa: BLE001
            fns = []
        dossiers = []
        for f in t.get("findings") or []:
            if f.get("state") in DEMONSTRATED and \
                    (f.get("curation") or {}).get("status") != "false_positive":
                try:
                    dossiers.append(_dossier(cx, t, f, fns))
                except Exception:                        # noqa: BLE001 -- never sink a report
                    dossiers.append({"id": f.get("id"), "title": f.get("title"),
                                     "summary": "", "severity": f.get("severity"),
                                     "severity_why": "", "level": f.get("level"),
                                     "location": {"site": f.get("site_addr")}, "trigger": [],
                                     "reproduce": [], "input": None, "evidence": [],
                                     "escalation": [], "mitigations": [],
                                     "remediation": "", "impact": "", "cwe": f.get("cwe")})
        dossiers = _merge_attributed(dossiers, t)
        dossiers.sort(key=lambda d: (-_SEV_RANK.get(d.get("severity") or "info", 0),
                                     -_LEVEL_RANK.get(d.get("level") or "L0", 0)))
        all_dossiers += [dict(d, target=t.get("filename")) for d in dossiers]
        targets.append({"id": t["id"], "filename": t.get("filename"),
                        "scope": _scope(cx, t), "dossiers": dossiers, "leads": _leads(t),
                        "methodology": _methodology(report, t),
                        "limitations": _limitations(t)})
    return {"executive": _executive(report, targets, all_dossiers), "targets": targets}


_ATTRIB = re.compile(r"faulting instruction IS this site \((0x[0-9a-f]+)")


def _merge_attributed(dossiers: list, t: dict) -> list:
    """One dossier per DEFECT. A static finding promoted because a reproduced crash faulted at one
    of its sites (root_cause's crash attribution) is the same defect as that crash: on jhead the
    `tainted_deref` detector had listed the faulting load among its 151 sites, and the report showed
    the one bug twice -- once as the crash, once as 'Out-of-bounds read candidate ... (not
    verified)'. It becomes a line of the crash's evidence: the static analysis predicted it."""
    by_id = {f.get("id"): f for f in t.get("findings") or []}
    by_site = {(d.get("location") or {}).get("site"): d for d in dossiers
               if d.get("input") and (d.get("location") or {}).get("site")}
    out = []
    for d in dossiers:
        f = by_id.get(d.get("id")) or {}
        sites = [m.group(1) for e in f.get("evidence") or []
                 if e.get("channel") == "crash-attribution"
                 for m in [_ATTRIB.search(e.get("detail") or "")] if m]
        host = next((by_site[s_] for s_ in sites if s_ in by_site and by_site[s_] is not d), None)
        if host is not None and not d.get("input"):
            host.setdefault("evidence", []).append(
                f'predicted statically: the {f.get("detector")} detector flagged this exact '
                f'instruction ({sites[0]}) before it was reproduced')
            continue
        out.append(d)
    return out


def _executive(report, targets, dossiers) -> dict:
    wall = ((report.get("timing") or {}).get("overall") or {}).get("wall_human")
    names = ", ".join(t["filename"] or "target" for t in targets) or "no target"
    kinds = sorted({t["scope"]["engagement"] for t in targets})
    paras = [f"lykos analysed {names} ({'; '.join(kinds)})"
             + (f" for {wall} of wall-clock time" if wall else "") + "."]
    if dossiers:
        top = dossiers[0]
        lvl = max((_LEVEL_RANK.get(d.get("level") or "L0", 0) for d in dossiers), default=0)
        paras.append(
            f"It demonstrated {len(dossiers)} vulnerabilit{'y' if len(dossiers) == 1 else 'ies'} "
            f"with a reproducer that was replayed and verified: "
            + "; ".join(f'{d["title"]} ({d["severity"]})' for d in dossiers[:5]) + ".")
        paras.append({3: "The strongest result is a working exploit (L3): code execution was shown.",
                      2: "The strongest result is an exploitation primitive (L2); a full exploit "
                         "was not demonstrated.",
                      1: "The strongest result is a reproducible crash (L1): denial of service is "
                         "demonstrated; control of execution was not."}.get(
            lvl, "Each was reproduced by execution."))
        risk = top["severity"]
    else:
        paras.append("No vulnerability was demonstrated by execution in this run.")
        risk = "none demonstrated"
    n_leads = sum(len(t["leads"]) for t in targets)
    n_raw = sum(sum(g["count"] for g in t["leads"]) for t in targets)
    if n_leads:
        paras.append(f"A further {n_raw} detection(s)"
                     + (f" ({n_leads} distinct kinds)" if n_leads != n_raw else "")
                     + " were not proven. They are listed with why each is unproven and what "
                       "would prove it; none of them is a demonstrated vulnerability.")
    actions = [f'{d["title"]}: {d["remediation"]}' for d in dossiers[:5] if d.get("remediation")]
    return {"risk": risk, "paragraphs": paras, "actions": actions,
            "counts": {"demonstrated": len(dossiers), "lead_kinds": n_leads,
                       "lead_findings": n_raw}}
