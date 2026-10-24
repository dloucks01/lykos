"""Per-attempt fuzzing log: one line for EVERY execution an engine makes, plus the verdict it adds up to.

The health panel used to judge a campaign from its totals -- execs, blocks, crashes -- and a total
cannot tell "ran 20,000 inputs through the parser" from "tried 20,000 times and the loader refused
every one". The first is a campaign; the second is an error loop that looks like one. So every
attempt is recorded with what was sent and how it ENDED:

  no_start    the input never reached the program: it did not start (missing library, bad interpreter,
              exec format, sandbox refusal) or the delivery failed (connection refused)
  crash       a fault signal (SIGSEGV/SIGABRT/...)
  timeout     hit the per-attempt limit
  error_exit  ran and exited non-zero (usually: rejected the input)
  clean_exit  ran and exited 0

and the stream of outcomes is folded into one verdict -- working / erroring / rejecting / timing_out /
crashing_all -- with the real error text quoted. The same log also measures whether the campaign
EARNED its time: coverage reached by the seeds alone vs. by mutation, and when coverage last grew.

The log is gzipped JSONL in the case's artifact store (kind `fuzz-attempt-log`). Line 1 is a header
{"log": "lykos-fuzz-attempts", "v": 1, engine, unit, ...}; every other line is one attempt:

  i    attempt number (1-based)          t     seconds since the campaign started
  ph   phase: seed | mutate | minimize | reproduce | confirm | afl-seed | afl-queue | afl-crash
  o    outcome (above)                   rc    exit code (null when killed / never started)
  sig  signal name, when killed          ms    duration
  len  input length                      in    first 16 hex of the input's sha256
  head first 24 input bytes, hex         argv  extra flags this attempt ran under (only if any)
  new  coverage units first reached here (only if > 0)      kept  true if it joined the corpus
  err  first non-empty stderr line, <=160 chars (only if any)            note  engine-specific

Pure stdlib; writing a line costs a hash and a json.dumps, which is noise next to a process spawn.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
import time
import zlib
from collections import Counter
from pathlib import Path
from typing import Optional

LOG_KIND = "fuzz-attempt-log"
OUTCOMES = ("no_start", "crash", "timeout", "error_exit", "clean_exit")

# Verdicts, worst-first.
ERRORING = "erroring"          # (almost) no attempt started the program
TIMING_OUT = "timing_out"      # (almost) every attempt hit the limit
REJECTING = "rejecting"        # (almost) every attempt exited with the same error
CRASHING_ALL = "crashing_all"  # every input crashes -- a startup crash, not an input-driven bug
WORKING = "working"
TOO_FEW = "too_few"            # not enough attempts to judge

_MIN_JUDGE = 20                # fewer attempts than this is not a pattern
_DOMINANT = 0.90
#: Seconds between SYNC flushes of the gzip stream. Without one, a campaign killed before
#: `finish()` (a worker timeout, SIGKILL, a crash of the stage itself) left a gzip member with no
#: end marker AND everything since the last 32 KiB deflate block still in the compressor, so the
#: log of the run that most needed explaining was unreadable. A sync flush every few seconds makes
#: every line up to it recoverable, for the cost of a few bytes of compression per flush.
_FLUSH_S = 2.0
#: Phases whose `new` counts are coverage gains -- the same two `AttemptLog.record` credits, so a
#: log read back from disk is judged on the same evidence as the live tally.
_GAIN_PHASES = ("seed", "mutate")

# stderr a loader/launcher prints when the program never got to main(). Matched only on the FIRST
# lines of stderr: a program is free to print "No such file" about its own input.
_LOADER_RE = re.compile(
    r"error while loading shared libraries|cannot open shared object file"
    r"|version `[^']*' not found|GLIBC_[0-9.]+'? not found"
    r"|Exec format error|cannot execute binary file|bad ELF interpreter"
    r"|qemu-[\w.-]+: (?:Could not open|Unable to|unable to|Error)"
    r"|^/?[\w./-]*ld[-.\w]*\.so[.\d]*: ", re.I | re.M)


def _first_line(b) -> str:
    if not b:
        return ""
    s = b.decode("latin-1", "replace") if isinstance(b, (bytes, bytearray)) else str(b)
    for ln in s.splitlines():
        ln = ln.strip()
        if ln:
            return ln[:160]
    return ""


def classify(res) -> str:
    """One RunResult -> one outcome. A never-started program is checked FIRST: a loader that
    cannot find libfoo.so exits 127, and counting that as an ordinary error exit is exactly how an
    error loop passed for a campaign."""
    from ..dynamic import sandbox
    iso = getattr(res, "isolation", None)
    if sandbox.did_not_run(iso):
        return "no_start"
    if getattr(res, "crashed", False):
        return "crash"
    if getattr(res, "timed_out", False):
        return "timeout"
    rc = getattr(res, "exit_code", None)
    err = getattr(res, "stderr", b"") or b""
    head = err[:2048].decode("latin-1", "replace") if isinstance(err, (bytes, bytearray)) else str(err)
    if rc in (126, 127) or (rc not in (0, None) and _LOADER_RE.search(head)):
        return "no_start"
    if rc == 0:
        return "clean_exit"
    return "error_exit"


def classify_rc(rc: Optional[int], *, timed_out: bool = False, spawn_failed: bool = False,
                stderr=b"") -> str:
    """The same classification for an engine that only has a bare return code."""
    if spawn_failed:
        return "no_start"
    if timed_out:
        return "timeout"
    if rc is None:
        return "no_start"
    if rc < 0:
        from ..dynamic import sandbox
        crashed = sandbox.classify_rc(rc)[0]
        return "crash" if crashed else "error_exit"
    head = stderr[:2048].decode("latin-1", "replace") if isinstance(stderr, (bytes, bytearray)) \
        else str(stderr or "")
    if rc in (126, 127) or (rc != 0 and _LOADER_RE.search(head)):
        return "no_start"
    return "clean_exit" if rc == 0 else "error_exit"


class Tally:
    """Running outcome counts + the most common error per outcome. Pure; also used to re-judge a
    log read back from disk."""

    def __init__(self):
        self.counts: Counter = Counter()
        self.total = 0
        self.errors: dict = {o: Counter() for o in OUTCOMES}   # outcome -> Counter[(rc, msg)]

    def add(self, outcome: str, rc=None, err: str = "") -> None:
        if outcome not in OUTCOMES:
            return                                       # logged, but not an execution we judged
        self.total += 1
        self.counts[outcome] += 1
        c = self.errors.setdefault(outcome, Counter())
        key = (rc, err or "")
        if key in c or len(c) < 64:                      # bounded: a novel message per input is noise
            c[key] += 1

    def top(self, outcome: str, n: int = 3) -> list:
        return [{"rc": rc, "msg": msg, "count": k}
                for (rc, msg), k in self.errors.get(outcome, Counter()).most_common(n)]

    def verdict(self, progressed: Optional[bool] = None, did_not_run: bool = False) -> tuple:
        """(verdict, one-line note quoting the real error).

        `progressed` -- did the campaign reach ANY new coverage beyond its first attempt? Most
        mutated inputs are rejected by any parser, so "90% exit 1" is normal for a campaign that is
        also climbing coverage; only a campaign that ALSO reached nothing new is "rejecting" or
        "timing out". A program that never started is an error loop whatever else happened.

        `did_not_run` -- the engine STOPPED because the sandbox said, definitively, that the
        program cannot run (a not-runnable isolation, a loader refusal). That is not a sample too
        small to judge: the engine stops after one such attempt precisely because the answer is
        already known, and calling it "too few" hid the loader message the operator needs."""
        t = self.total
        if did_not_run and t and self.counts["no_start"] >= _DOMINANT * t:
            return ERRORING, self._erroring_note()
        if t < _MIN_JUDGE:
            return TOO_FEW, f"only {t} attempt(s) -- too few to judge"
        c = self.counts

        def pct(k):
            return 100.0 * c[k] / t

        quote = self._quote

        if c["no_start"] >= _DOMINANT * t:
            return ERRORING, self._erroring_note()
        if c["timeout"] >= _DOMINANT * t and not progressed:
            return TIMING_OUT, (f"{c['timeout']:,} of {t:,} attempts ({pct('timeout'):.0f}%) hit the "
                                f"per-attempt time limit -- the target is waiting for something "
                                f"(another input channel, a network peer, an interactive prompt), so "
                                f"the inputs are not reaching it.")
        if c["crash"] >= 0.95 * t:
            return CRASHING_ALL, (f"{c['crash']:,} of {t:,} attempts ({pct('crash'):.0f}%) crashed -- "
                                  f"every input, so this is most likely a crash at startup rather "
                                  f"than one an input causes{quote('crash')}.")
        if c["error_exit"] >= _DOMINANT * t and not progressed:
            top = self.top("error_exit", 1)
            same = top and top[0]["count"] >= _DOMINANT * c["error_exit"]
            if same:
                return REJECTING, (f"{c['error_exit']:,} of {t:,} attempts ({pct('error_exit'):.0f}%) "
                                   f"exited with the same error{quote('error_exit')} -- the target "
                                   f"is refusing every input before it parses it (wrong channel, "
                                   f"missing arguments/config, or a format it does not accept).")
        mix = ", ".join(f"{k.replace('_', ' ')} {pct(k):.0f}%" for k in OUTCOMES if c[k])
        return WORKING, f"{t:,} attempts: {mix}"

    def _quote(self, outcome: str) -> str:
        top = self.top(outcome, 1)
        if not top:
            return ""
        m = top[0]
        bits = []
        if m["rc"] is not None:
            bits.append(f"exit {m['rc']}")
        if m["msg"]:
            bits.append(f"“{m['msg']}”")
        return (" -- " + ", ".join(bits)) if bits else ""

    def _erroring_note(self) -> str:
        t, n = self.total, self.counts["no_start"]
        return (f"{n:,} of {t:,} attempts ({100.0 * n / t:.0f}%) never "
                f"reached the program -- it did not start, or the input could not be "
                f"delivered{self._quote('no_start')}. This is an error loop, not a "
                f"campaign: nothing was tested.")

    def to_dict(self, progressed: Optional[bool] = None, did_not_run: bool = False) -> dict:
        v, note = self.verdict(progressed, did_not_run)
        return {"attempts": self.total, "counts": {o: self.counts[o] for o in OUTCOMES},
                "top_errors": {o: self.top(o) for o in OUTCOMES if self.counts[o] and o != "clean_exit"},
                "verdict": v, "verdict_note": note}


class AttemptLog:
    """Streams one line per attempt to a gzipped JSONL file in scratch, keeps a Tally and the
    coverage-gain measure, and on `finish()` stores the file as an artifact and emits
    `<prefix>.attempts` with the summary. Never raises into the campaign: logging is advisory."""

    def __init__(self, ctx, engine: str, prefix: str, *, unit: str = "behaviours",
                 target_id: Optional[str] = None, path: Optional[Path] = None):
        self.ctx, self.engine, self.prefix, self.unit = ctx, engine, prefix, unit
        self.target_id = target_id
        self.t0 = time.time()
        self.n = 0
        self.tally = Tally()
        self.seed_new = 0             # coverage units reached by the verbatim seeds
        self.mut_new = 0              # coverage units reached only by mutation (the fuzzer's gain)
        self.last_gain_t: Optional[float] = None
        self.first_gain_t: Optional[float] = None
        self.kept = 0
        self.closed = False
        self._fh = None
        self._last_flush = 0.0
        try:
            p = path or (Path(ctx.scratch()) / f"{engine}-attempts.jsonl.gz")
            self.path = p
            self._fh = gzip.open(p, "wt", encoding="utf-8", compresslevel=6)  # noqa: SIM115 -- streamed for the campaign's life
            self._fh.write(json.dumps({"log": "lykos-fuzz-attempts", "v": 1, "engine": engine,
                                       "unit": unit, "target": target_id,
                                       "started": round(self.t0, 3)}) + "\n")
        except Exception:                                # noqa: BLE001 -- the log is advisory
            self._fh = None

    def set_unit(self, unit: str) -> None:
        self.unit = unit

    # -- recording ------------------------------------------------------------------------------
    def record(self, data: bytes, *, outcome: str, phase: str, rc=None, sig=None, ms=None,
               stderr=b"", argv=None, new: int = 0, kept: bool = False, note: Optional[str] = None,
               extra: Optional[dict] = None) -> None:
        self.n += 1
        t = time.time() - self.t0
        err = _first_line(stderr)
        self.tally.add(outcome, rc, err if outcome != "clean_exit" else "")
        if new:
            if phase == "seed":
                self.seed_new += new
            elif phase == "mutate":
                self.mut_new += new
                self.last_gain_t = t
                if self.first_gain_t is None:
                    self.first_gain_t = t
        if kept:
            self.kept += 1
        if self._fh is None:
            return
        d = data if isinstance(data, (bytes, bytearray)) else (str(data or "").encode())
        row = {"i": self.n, "t": round(t, 3), "ph": phase, "o": outcome, "rc": rc}
        if sig:
            row["sig"] = sig
        if ms is not None:
            row["ms"] = int(ms)
        row["len"] = len(d)
        row["in"] = hashlib.sha256(d).hexdigest()[:16]
        row["head"] = bytes(d[:24]).hex()
        if argv:
            row["argv"] = [str(a) for a in argv]
        if new:
            row["new"] = int(new)
        if kept:
            row["kept"] = True
        if err:
            row["err"] = err
        if note:
            row["note"] = str(note)[:200]
        if extra:
            row.update(extra)
        try:
            self._fh.write(json.dumps(row, separators=(",", ":")) + "\n")
            if t - self._last_flush >= _FLUSH_S:
                # SYNC flush: everything written so far becomes decodable even if `finish()` is
                # never reached (see _FLUSH_S); read_log() tolerates the missing end marker.
                self._last_flush = t
                self._fh.flush()
        except Exception:                                # noqa: BLE001 -- disk full etc: stop logging
            self._close_fh()

    def record_result(self, data: bytes, res, *, phase: str, argv=None, new: int = 0,
                      kept: bool = False, note: Optional[str] = None) -> str:
        """Record one sandbox RunResult; returns its outcome."""
        o = classify(res)
        note = note or (getattr(res, "note", None) if o == "no_start" else None)
        self.record(data, outcome=o, phase=phase, rc=getattr(res, "exit_code", None),
                    sig=getattr(res, "signal_name", None) or None,
                    ms=getattr(res, "duration_ms", None), stderr=getattr(res, "stderr", b""),
                    argv=argv, new=new, kept=kept, note=note)
        return o

    # -- summary --------------------------------------------------------------------------------
    def value(self) -> dict:
        """Did the campaign earn its time? Coverage the seeds reached on their own vs. what
        mutation added, and when it last grew."""
        el = time.time() - self.t0
        out = {"unit": self.unit, "seed_coverage": self.seed_new, "gained": self.mut_new,
               "kept": self.kept, "elapsed_s": round(el, 1),
               "last_gain_s": (round(self.last_gain_t, 1) if self.last_gain_t is not None else None)}
        if self.last_gain_t is not None and el > 0:
            # clamped: an engine that sets `last_gain_s` itself (AFL's plot) can report a gain
            # time from its own clock that is past ours, which read as a NEGATIVE idle tail
            out["idle_tail_pct"] = max(0, min(100, round(100.0 * (el - self.last_gain_t) / el)))
        return out

    def set_value(self, *, seed: Optional[int] = None, gained: Optional[int] = None,
                  last_gain_s: Optional[float] = None) -> None:
        """For an engine whose coverage is measured OUTSIDE the per-attempt stream (AFL keeps its
        own edge counts): set the seed/gain numbers directly."""
        if seed is not None:
            self.seed_new = int(seed)
        if gained is not None:
            self.mut_new = int(gained)
        if last_gain_s is not None:
            self.last_gain_t = float(last_gain_s)

    def progressed(self) -> bool:
        """Reached any coverage beyond the very first attempt (which is always 'new')."""
        return (self.seed_new + self.mut_new) > 1

    def snapshot(self) -> dict:
        """Compact live counts for a heartbeat payload."""
        return {o: self.tally.counts[o] for o in OUTCOMES if self.tally.counts[o]}

    def _close_fh(self):
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:                            # noqa: BLE001 -- best effort
                pass
            self._fh = None

    def finish(self, **extra) -> dict:
        """Close, store the log as an artifact, emit `<prefix>.attempts`. Returns the payload."""
        if self.closed:
            return {}
        self.closed = True
        had_file = self._fh is not None
        self._close_fh()
        payload = {"engine": self.engine,
                   **self.tally.to_dict(self.progressed(), bool(extra.get("did_not_run"))),
                   "value": self.value(), **extra}
        if had_file and self.n:
            try:
                payload["log"] = self.ctx.put_artifact(
                    LOG_KIND, src=self.path,
                    meta={"engine": self.engine, "target_id": self.target_id,
                          "run_id": getattr(self.ctx, "run_id", None), "attempts": self.n,
                          "counts": payload["counts"], "verdict": payload["verdict"],
                          "verdict_note": payload["verdict_note"], "value": payload["value"]})
            except Exception:                            # noqa: BLE001 -- summary still goes out
                payload["log"] = None
        try:
            self.ctx.emit(f"{self.prefix}.attempts", payload=payload)
        except Exception:                                # noqa: BLE001 -- advisory
            pass
        return payload


# -- reading a stored log back (API / CLI) -------------------------------------------------------
def _iter_lines(path_or_bytes, state: dict):
    """Lines of a stored log, STREAMED: a long campaign's log decompresses to hundreds of MB, and
    the old reader held all of it (plus a second whole-file read just to sniff the gzip magic) to
    return one page of rows. A gzip stream with no end marker -- the engine was killed before
    `finish()` -- yields every line up to the last sync flush and sets ``state["truncated"]``
    instead of raising and losing the whole log."""
    if isinstance(path_or_bytes, (bytes, bytearray)):
        raw = bytes(path_or_bytes)
        if raw[:2] != b"\x1f\x8b":
            yield from raw.decode("utf-8", "replace").splitlines()
            return
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        tail, pos, step = b"", 0, 1 << 20
        try:
            while pos < len(raw) and not d.eof:
                tail += d.decompress(raw[pos:pos + step])
                pos += step
                *done, tail = tail.split(b"\n")
                for ln in done:
                    yield ln.decode("utf-8", "replace")
            tail += d.flush()
        except zlib.error:
            state["truncated"] = True
        if not d.eof:
            state["truncated"] = True
        for ln in tail.split(b"\n"):
            # a partial final line is dropped by the JSON parse below, never mis-read
            yield ln.decode("utf-8", "replace")
        return
    p = Path(path_or_bytes)
    with open(p, "rb") as fb:
        gz = fb.read(2) == b"\x1f\x8b"
    raw_fh = gzip.open(p, "rb") if gz else open(p, "rb")       # noqa: SIM115 -- closed below
    try:
        f = io.TextIOWrapper(raw_fh, encoding="utf-8", errors="replace")
        try:
            for ln in f:
                yield ln.rstrip("\n")
        except (EOFError, zlib.error, gzip.BadGzipFile):
            state["truncated"] = True
    finally:
        raw_fh.close()


def read_log(path_or_bytes, *, outcome=None, phase=None, offset: int = 0, limit: int = 200,
             errors_only: bool = False) -> dict:
    """Parse a stored attempt log: {header, total, matched, rows[offset:offset+limit], summary}.
    `outcome`/`phase` filter (a str or a collection); `errors_only` keeps every non-clean attempt.
    The summary is re-judged from the full stream, so it is right however the log is filtered.
    Streamed (bounded memory: one page of rows); ``truncated`` is true when the log ended without
    its gzip end marker -- the engine was stopped abruptly -- and the rows are what survived."""
    offset = max(0, int(offset or 0))
    limit = max(0, int(limit or 0))
    want_o = {outcome} if isinstance(outcome, str) else set(outcome or ())
    want_p = {phase} if isinstance(phase, str) else set(phase or ())
    header, rows, total, matched, new_sum = {}, [], 0, 0, 0
    tally = Tally()
    state = {"truncated": False}
    first = True
    for ln in _iter_lines(path_or_bytes, state):
        if not ln.strip():
            continue
        try:
            r = json.loads(ln)
        except ValueError:
            first = False
            continue
        if not isinstance(r, dict):
            first = False
            continue
        if first and r.get("log") == "lykos-fuzz-attempts":
            header = r
            first = False
            continue
        first = False
        total += 1
        if r.get("ph") in _GAIN_PHASES:
            try:
                new_sum += int(r.get("new") or 0)
            except (TypeError, ValueError):
                pass
        tally.add(r.get("o") or "error_exit", r.get("rc"),
                  r.get("err", "") if r.get("o") != "clean_exit" else "")
        if want_o and r.get("o") not in want_o:
            continue
        if want_p and r.get("ph") not in want_p:
            continue
        if errors_only and r.get("o") == "clean_exit":
            continue
        if offset <= matched < offset + limit:
            rows.append(r)
        matched += 1
    return {"header": header, "total": total, "matched": matched, "offset": offset,
            "rows": rows, "truncated": state["truncated"],
            "summary": tally.to_dict(progressed=new_sum > 1)}
