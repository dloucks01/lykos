"""Differential testing: find bugs by DISAGREEMENT between implementations of one spec.

Sanitizers catch memory corruption; they say nothing about a program that quietly accepts input it
should reject, or parses it differently from another implementation of the same format. Those
*logic* and *validation* bugs -- an authentication bypass, an HTTP request-smuggling desync, a
certificate-validation gap, a decompressor that returns different bytes than its sibling -- are
found by running one input through TWO OR MORE implementations of the same spec and flagging where
they diverge. It is a NON-CRASHING oracle: a discrepancy is a finding with no crash at all, and this
class historically has very high CVE yield (NEZHA, IEEE S&P'17, found 778 discrepancies including
among OpenSSL/LibreSSL/BoringSSL).

This module is lykos's self-contained differential engine (non-AI, offline, reusing the sandbox and
the byte mutator):

  * ``outcome`` -- normalize one run into a comparable verdict: ``accept`` (exited 0), ``reject``
    (non-zero exit), or ``crash`` (a signal). An optional output mode also folds a hash of the
    normalized stdout in, for formats where the OUTPUT must match (decompressors, transcoders).
  * ``discrepancy`` -- pure: given ``{program -> outcome}`` for one input, whether they disagree and
    how they partition. Disagreement is the bug signal.
  * ``delta_key`` -- NEZHA's δ-diversity coverage key: the *combination* of per-program outcomes an
    input produces. A never-seen combination is an interesting input to keep and mutate, which
    drives the search toward the boundary where implementations start to disagree.
  * ``differential_campaign`` -- mutate seeds, run every program, keep δ-novel inputs, and collect
    the inputs on which the implementations disagreed.
"""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass, field
from typing import Optional

from .structure import Mutator


@dataclass
class Program:
    """One implementation under differential test. ``mode`` is how it takes input (stdin/arg/file);
    ``base_argv`` may contain ``@@`` for the input path/value slot (else the input is appended)."""
    name: str
    exe: str
    mode: str = "stdin"
    base_argv: tuple = ()
    arch: Optional[str] = None
    endianness: Optional[str] = None
    bits: Optional[int] = None


def _place(argv, value):
    if "@@" in argv:
        return [value if a == "@@" else a for a in argv]
    return list(argv) + [value]


def run_program(prog: Program, data: bytes, *, timeout: float = 5.0):
    """Run one program on ``data`` via the sandbox and return its RunResult."""
    from ..dynamic import sandbox
    argv, stdin, tmp = list(prog.base_argv), b"", None
    try:
        if prog.mode == "stdin":
            stdin = data
        elif prog.mode == "arg":
            argv = _place(argv, data.split(b"\x00", 1)[0].decode("latin-1"))
        elif prog.mode == "file":
            fd, tmp = tempfile.mkstemp(prefix="lykos-diff-")
            os.write(fd, data); os.close(fd)
            argv = _place(argv, tmp)
        return sandbox.run(prog.exe, argv=argv, stdin=stdin, timeout=timeout,
                           arch=prog.arch, endianness=prog.endianness, bits=prog.bits)
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


_WS = re.compile(rb"\s+")


def outcome(res, *, compare: str = "status") -> str:
    """Normalize a RunResult into a comparable verdict.

    ``status`` (default): ``crash`` / ``accept`` (exit 0) / ``reject`` (nonzero) -- the classic
    accept-vs-reject parser differential. ``output``: also fold a hash of the whitespace-normalized
    stdout in, so two programs that both accept but PRODUCE different bytes still count as diverging
    (decompressors, transcoders, canonicalizers).
    """
    if getattr(res, "crashed", False):
        return "crash:" + (getattr(res, "signal_name", None) or "?")
    code = getattr(res, "exit_code", None)
    verdict = "accept" if code == 0 else "reject"
    if compare == "output":
        out = _WS.sub(b" ", (getattr(res, "stdout", b"") or b"")).strip()
        return f"{verdict}:{hashlib.sha1(out).hexdigest()[:12]}"
    return verdict


def outcomes_for(programs, data: bytes, *, compare: str = "status", timeout: float = 5.0) -> dict:
    """``{program.name -> outcome}`` for one input across all programs."""
    return {p.name: outcome(run_program(p, data, timeout=timeout), compare=compare)
            for p in programs}


def discrepancy(outcomes: dict) -> dict:
    """Pure: do the implementations disagree on this input, and how do they partition?

    Returns ``{disagree, partitions, kind}``. ``disagree`` is True when more than one distinct
    outcome appears. ``kind`` classifies it: ``accept-reject`` (a validation/parsing differential --
    one implementation accepts what another rejects, the highest-value signal), ``crash`` (one
    crashed and another did not), or ``output`` (all accepted but produced different bytes).
    """
    vals = list(outcomes.values())
    distinct = set(vals)
    if len(distinct) <= 1:
        return {"disagree": False, "partitions": {}, "kind": None}
    partitions = {}
    for name, o in outcomes.items():
        partitions.setdefault(o, []).append(name)
    bases = {o.split(":", 1)[0] for o in distinct}
    if "crash" in bases and len(bases) > 1:
        kind = "crash"
    elif "accept" in bases and "reject" in bases:
        kind = "accept-reject"
    else:
        kind = "output"
    return {"disagree": True, "partitions": partitions, "kind": kind}


def delta_key(outcomes: dict) -> tuple:
    """NEZHA δ-diversity key: the canonical combination of per-program outcomes. A never-seen key is
    an input that drove a new joint behaviour -- worth keeping and mutating toward the disagreement
    boundary. Program names are sorted so the key is order-independent."""
    return tuple(sorted(outcomes.items()))


@dataclass
class DiffStats:
    execs: int = 0
    delta_diversity: int = 0
    discrepancies: list = field(default_factory=list)   # {input(hex), kind, partitions}
    corpus: int = 0


def differential_campaign(programs, seeds, *, rng, iterations: int = 2000, timeout: float = 5.0,
                          compare: str = "status", mutator=None,
                          max_findings: int = 64) -> DiffStats:
    """δ-diversity-guided differential fuzzing over ``programs`` (>=2). Mutate ``seeds``, run every
    program, keep inputs that produce a NEW outcome-combination, and record every input on which the
    implementations disagreed. Returns DiffStats. Requires at least two programs."""
    programs = list(programs)
    if len(programs) < 2:
        raise ValueError("differential testing needs >= 2 programs")
    mut = mutator or Mutator(rng, None)
    corpus = [s for s in (seeds or []) if s] or [b"", b"A", b"0\n"]
    seen_delta = set()
    seen_disc = set()
    stats = DiffStats()
    n = max(1, iterations)
    for _ in range(n):
        base = corpus[rng.randrange(len(corpus))]
        data = mut.mutate(base, corpus)
        oc = outcomes_for(programs, data, compare=compare, timeout=timeout)
        stats.execs += 1
        key = delta_key(oc)
        if key not in seen_delta:
            seen_delta.add(key)
            if len(corpus) < 512:
                corpus.append(data)
        d = discrepancy(oc)
        if d["disagree"]:
            sig = (d["kind"], key)
            if sig not in seen_disc and len(stats.discrepancies) < max_findings:
                seen_disc.add(sig)
                stats.discrepancies.append({
                    "input": data.hex()[:512], "kind": d["kind"],
                    "partitions": {o: names for o, names in d["partitions"].items()}})
    stats.delta_diversity = len(seen_delta)
    stats.corpus = len(corpus)
    return stats
