"""The Hypothesis: the unit of work of the find -> solve -> validate loop (doc 52 §3).

A hypothesis names a SITE (an instruction in the program, plus its file:line when the build has
DWARF), a CLASS of violation (stack-write, format-string, ...), and carries the concrete inputs
the solver produced for it. Only a validator VERDICT moves it to `confirmed`: the solver's own
claim is never a finding, because its libc models can be unsound.

Status ladder (each step is evidence, not opinion):
    proposed     a static proposer named the site
    reached      symbolic execution got a state to the site
    solved       the violation was satisfiable there; at least one input was produced
    confirmed    an input, replayed for real, tripped the oracle AT THIS SITE
    unconfirmed  inputs were produced but none replayed at this site
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Optional

STATUSES = ("proposed", "reached", "solved", "confirmed", "unconfirmed")


@dataclass
class Verdict:
    """What replaying one input showed."""
    confirmed: bool
    method: str                      # asan | native-crash | exec-marker | none
    detail: str
    line: Optional[int] = None       # source line the oracle fired at, when known
    runs: int = 1                    # how many replays agreed
    crashes: bool = False            # it crashed on every replay, but not provably at the site

    def to_dict(self) -> dict:
        return {"confirmed": self.confirmed, "method": self.method, "detail": self.detail,
                "line": self.line, "runs": self.runs, "crashes": self.crashes}

    @classmethod
    def from_dict(cls, d: dict) -> "Verdict":
        return cls(bool(d.get("confirmed")), d.get("method", "none"), d.get("detail", ""),
                   d.get("line"), int(d.get("runs", 1)), bool(d.get("crashes")))


@dataclass
class Solution:
    """One concrete input the solver produced for a hypothesis."""
    data: bytes
    detail: str = ""                 # the solver's reason (e.g. "overwrites the saved return ...")
    t: Optional[float] = None        # seconds into the solve when it was found
    verdict: Optional[Verdict] = None

    def to_dict(self) -> dict:
        return {"input_b64": base64.b64encode(self.data).decode(), "detail": self.detail,
                "t": self.t, "verdict": self.verdict.to_dict() if self.verdict else None}

    @classmethod
    def from_dict(cls, d: dict) -> "Solution":
        v = d.get("verdict")
        return cls(base64.b64decode(d.get("input_b64", "")), d.get("detail", ""), d.get("t"),
                   Verdict.from_dict(v) if v else None)


@dataclass
class Hypothesis:
    id: str                          # "<kind>@<site hex>", stable across runs of one binary
    kind: str
    cwe: Optional[str]
    site: Optional[int]              # file (link-time) virtual address of the site instruction
    func: Optional[str] = None
    func_addr: Optional[int] = None  # file vaddr
    func_size: Optional[int] = None
    location: Optional[str] = None   # "src/file.c:42" from DWARF, when available
    status: str = "proposed"
    reached: int = 0
    note: str = ""
    solutions: list = field(default_factory=list)

    @property
    def line(self) -> Optional[int]:
        if self.location and ":" in self.location:
            try:
                return int(self.location.rsplit(":", 1)[1])
            except ValueError:
                return None
        return None

    def confirmed_solution(self) -> Optional[Solution]:
        for s in self.solutions:
            if s.verdict and s.verdict.confirmed:
                return s
        return None

    def crashes_unattributed(self) -> bool:
        return not self.confirmed_solution() and any(
            s.verdict and s.verdict.crashes for s in self.solutions)

    def settle(self) -> None:
        """Set `status` from the evidence held (the verdicts decide, never the solver)."""
        if self.confirmed_solution():
            self.status = "confirmed"
        elif self.solutions and all(s.verdict for s in self.solutions):
            self.status = "unconfirmed"
        elif self.solutions:
            self.status = "solved"
        elif self.reached:
            self.status = "reached"
        else:
            self.status = "proposed"

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "cwe": self.cwe,
                "site": f"{self.site:#x}" if isinstance(self.site, int) else None,
                "func": self.func,
                "func_addr": f"{self.func_addr:#x}" if isinstance(self.func_addr, int) else None,
                "func_size": self.func_size, "location": self.location, "status": self.status,
                "reached": self.reached, "note": self.note,
                "solutions": [s.to_dict() for s in self.solutions]}

    @classmethod
    def from_dict(cls, d: dict) -> "Hypothesis":
        def _hex(v):
            return int(v, 16) if isinstance(v, str) else v
        return cls(d["id"], d["kind"], d.get("cwe"), _hex(d.get("site")), d.get("func"),
                   _hex(d.get("func_addr")), d.get("func_size"), d.get("location"),
                   d.get("status", "proposed"), int(d.get("reached") or 0), d.get("note") or "",
                   [Solution.from_dict(s) for s in d.get("solutions") or []])
