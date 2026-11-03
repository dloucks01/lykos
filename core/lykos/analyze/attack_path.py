"""Attack-path composition -- chain multiple findings into a full attacker path (doc-60 depth).

lykos finds primitives (per-CWE findings) and confirms some to L1/L2/L3, and the weaponize chain now
composes a leak + a write into one detonated exploit. This module is the layer above that: it models
the attacker's progress as a CAPABILITY GRAPH and searches for an ordered path -- each edge backed by
a real finding -- from the attacker's entry to an objective (RCE / command / file / DoS). It
generalizes weaponize's plan_rce from "is RCE reachable" to "what is the deepest path, through which
findings, and what capability does each step buy."

Nodes are attacker capabilities (states). A finding of a given CWE is an EDGE that, given its
precondition capabilities, GAINS others (an OOB read gains a leak; an OOB write gains a write; an
auth bypass gains authentication). TECHNIQUE edges (not findings) model the weaponization steps that
combine capabilities -- a leak + a write give PC control, PC control gives RCE -- which is exactly
what the leak->groom->control chain realizes. Pure + deterministic + testable; a stage and the report
consume the path, and the detonators turn a path's edges into a demonstrated chain.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ---- capability ontology --------------------------------------------------------------------------
REACH = "reach"            # the attacker can drive the vulnerable code (entry point)
AUTH = "auth"              # authenticated / privileged context reached
LEAK = "leak"              # an address disclosed -> ASLR/PIE defeat
READ = "read"             # attacker-controlled read primitive
WRITE = "write"            # attacker-controlled write primitive
PC = "pc"                  # control of the instruction pointer
#: objectives, ranked best-first -- the path search targets the highest reachable one.
RCE = "rce"; CMD = "cmd_exec"; SQL = "sql_exec"; FILE = "file_read"; DOS = "dos"
_OBJECTIVES = [RCE, CMD, SQL, FILE, DOS]
_OBJ_RANK = {o: i for i, o in enumerate(_OBJECTIVES)}      # lower = better


@dataclass(frozen=True)
class Edge:
    requires: frozenset
    gains: frozenset
    label: str
    technique: bool = False    # True = a weaponization step (not a finding), e.g. leak+write -> PC


#: CWE -> the capability transition that class provides (requires -> gains). An attacker who can
#: REACH the sink gains the listed capability. Grounded in cwe_coverage.CEILING but expressed as
#: capability deltas so they COMPOSE.
_CWE_EDGE: dict = {}


def _e(cwes, requires, gains, label):
    for c in cwes:
        _CWE_EDGE[c] = Edge(frozenset(requires), frozenset(gains), label)


_e(["CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-639", "CWE-284"], [REACH], [AUTH], "auth bypass")
_e(["CWE-125", "CWE-126", "CWE-200", "CWE-201", "CWE-209"], [REACH], [LEAK, READ], "info leak / OOB read")
_e(["CWE-134"], [REACH], [LEAK, WRITE], "format string (%n read+write)")
_e(["CWE-787", "CWE-122", "CWE-120", "CWE-121", "CWE-124", "CWE-131", "CWE-787", "CWE-823",
    "CWE-190", "CWE-191", "CWE-680", "CWE-129"], [REACH], [WRITE], "memory write (overflow / bad index)")
_e(["CWE-416", "CWE-415", "CWE-590", "CWE-762", "CWE-761", "CWE-822"], [REACH], [WRITE],
   "use-after-free / bad-free -> reclaim write")
_e(["CWE-78", "CWE-77", "CWE-88"], [REACH], [CMD], "OS command injection")
_e(["CWE-94", "CWE-95", "CWE-502", "CWE-917", "CWE-98"], [REACH], [RCE], "code / deserialization exec")
_e(["CWE-89"], [REACH], [SQL], "SQL injection")
_e(["CWE-22", "CWE-23", "CWE-98"], [REACH], [FILE], "path traversal / file read")
_e(["CWE-369", "CWE-617", "CWE-400", "CWE-401", "CWE-476", "CWE-835"], [REACH], [DOS],
   "crash / resource exhaustion (availability)")

#: TECHNIQUE edges -- weaponization steps that COMBINE capabilities (not themselves findings). These
#: are the composition the chain detonators realize.
_TECH_EDGES = [
    Edge(frozenset([WRITE, LEAK]), frozenset([PC]), "overwrite a code pointer with a leaked address",
         technique=True),
    Edge(frozenset([WRITE, AUTH]), frozenset([PC]), "privileged write -> code-pointer overwrite",
         technique=True),
    Edge(frozenset([PC]), frozenset([RCE]), "PC control -> shell/ROP (RCE)", technique=True),
]


@dataclass
class Step:
    gained: tuple            # capabilities this step added
    label: str
    cwe: "str | None"        # the finding's CWE (None for a technique step)
    finding_id: "str | None"
    function: "str | None"
    level: "str | None"      # best PoC rung backing the finding edge (L0..L3), if any
    technique: bool


@dataclass
class AttackPath:
    objective: "str | None"
    reached: bool
    steps: list = field(default_factory=list)
    gained_caps: frozenset = frozenset()


def _get(f, k, default=None):
    if isinstance(f, dict):
        return f.get(k, default)
    return getattr(f, k, default)


def find_attack_path(findings, *, start=(REACH,), pocs=None) -> AttackPath:
    """Search the capability graph for the deepest attacker path the run's findings support.

    `findings` are dicts/rows with at least `cwe` (and optionally `function`, `id`). `pocs` (dicts/rows
    with `finding_id` + `level`) annotate each finding edge with the rung it is demonstrated at. Starts
    from `start` (default: the attacker can REACH the surface) and greedily applies usable finding and
    technique edges until no new capability appears, then returns the path to the best objective
    reached (ranked rce>cmd>sql>file>dos), or a partial path with reached=False.
    """
    # best demonstrated level per finding id
    best_level = {}
    for p in (pocs or []):
        fid = _get(p, "finding_id")
        lvl = _get(p, "level")
        if fid and lvl:
            if fid not in best_level or _rank(lvl) > _rank(best_level[fid]):
                best_level[fid] = lvl

    # candidate finding edges (dedup by (cwe, function) -- one edge per distinct primitive)
    cand = {}
    for f in findings:
        cwe = _get(f, "cwe")
        edge = _CWE_EDGE.get((cwe or "").strip())
        if edge is None:
            continue
        fn = _get(f, "function") or _get(f, "site_detail") or ""
        key = (cwe, fn)
        if key not in cand:
            cand[key] = (edge, f)

    caps = set(start)
    steps: list = []
    # Fixpoint: apply any usable edge that grants a NEW capability. Finding edges first (they are the
    # evidence), then technique edges (the composition). Deterministic order by (objective-ness, cwe).
    progress = True
    while progress:
        progress = False
        # finding edges
        for (cwe, fn), (edge, f) in sorted(cand.items(), key=lambda kv: kv[0][0] or ""):
            if edge.requires <= caps and not (edge.gains <= caps):
                new = edge.gains - caps
                caps |= edge.gains
                fid = _get(f, "id")
                steps.append(Step(gained=tuple(sorted(new)), label=edge.label, cwe=cwe,
                                  finding_id=fid, function=fn or None,
                                  level=best_level.get(fid), technique=False))
                progress = True
        # technique edges
        for edge in _TECH_EDGES:
            if edge.requires <= caps and not (edge.gains <= caps):
                new = edge.gains - caps
                caps |= edge.gains
                steps.append(Step(gained=tuple(sorted(new)), label=edge.label, cwe=None,
                                  finding_id=None, function=None, level=None, technique=True))
                progress = True

    reached = [o for o in _OBJECTIVES if o in caps]
    objective = min(reached, key=lambda o: _OBJ_RANK[o]) if reached else None
    # trim steps to those on the path to `objective` (keep all when no objective -> show progress)
    path_steps = _steps_for(steps, objective) if objective else steps
    return AttackPath(objective=objective, reached=objective is not None,
                      steps=path_steps, gained_caps=frozenset(caps))


_LEVEL_ORDER = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}


def _rank(lvl):
    return _LEVEL_ORDER.get((lvl or "").upper(), -1)


def _steps_for(steps, objective):
    """Backward slice: keep the steps whose gained capabilities are needed to reach `objective`,
    following technique-edge prerequisites back to the finding edges that supply them."""
    need = {objective}
    keep = []
    for st in reversed(steps):
        if set(st.gained) & need:
            keep.append(st)
            # a technique step needs its prerequisite capabilities; approximate by re-adding all
            # non-objective capabilities it consumed (the fixpoint guarantees they were produced).
            for e in _TECH_EDGES:
                if set(e.gains) & set(st.gained):
                    need |= set(e.requires)
            need |= {c for c in st.gained if c not in _OBJ_RANK}
    return list(reversed(keep))


def format_path(path: AttackPath) -> str:
    """One-line-per-step human rendering, entry -> ... -> objective."""
    if not path.steps:
        return "no attack path: no finding grants a capability from the attacker's entry"
    out = ["entry: attacker can reach the vulnerable surface"]
    for st in path.steps:
        rung = f" [{st.level}]" if st.level else (" [technique]" if st.technique else " [candidate]")
        src = f" ({st.cwe} in {st.function})" if st.cwe else ""
        out.append(f"  -> {'+'.join(st.gained)}: {st.label}{src}{rung}")
    tail = (f"OBJECTIVE REACHED: {path.objective}" if path.reached
            else f"ceiling: reached {sorted(path.gained_caps)} -- no objective")
    out.append(tail)
    return "\n".join(out)
