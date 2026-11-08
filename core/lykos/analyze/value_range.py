"""Value-range / abstract interpretation (static gap 1) — sound-ish interval analysis over a C
function, so "can this operand be 0?" / "can this index exceed N?" is COMPUTED, not inspected.

Every FP/needs-state determination so far answered that question by hand. This gives an intervals
engine: a variable read off the wire gets its type's full range; literals and arithmetic propagate
ranges (interval +,-,*,/,%); a dominating guard that returns/bails on a comparison narrows the range
for the code after it. Then `can_be_zero(expr)` answers the divide-by-zero question and
`max_value(expr)` the index/size-bound question. It caught the DSP divide-by-zero class by range, not
pattern: data_per_block = (nBlockAlign-4*nChannels)*8 has a range including 0 because nBlockAlign is
wire-full-range and unguarded.

Deliberately conservative: unknown => TOP (full range), so a real zero/overflow is never hidden; a
value PROVEN bounded (literal, guarded, masked) is narrowed and reported safe. Pure + testable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_WIDTH = {"8": (0, 255), "16": (0, 65535), "32": (0, 4294967295), "64": (0, 2**64 - 1)}
_INT_MIN, _INT_MAX = -(2**63), 2**63 - 1


@dataclass(frozen=True)
class Interval:
    lo: int
    hi: int

    def includes(self, v: int) -> bool:
        return self.lo <= v <= self.hi

    def __add__(self, o): return Interval(self.lo + o.lo, self.hi + o.hi)
    def __sub__(self, o): return Interval(self.lo - o.hi, self.hi - o.lo)

    def __mul__(self, o):
        c = [self.lo * o.lo, self.lo * o.hi, self.hi * o.lo, self.hi * o.hi]
        return Interval(min(c), max(c))


TOP = Interval(_INT_MIN, _INT_MAX)
_READ = re.compile(r"\bStream_Read_U?INT(8|16|32|64)\s*\(\s*\w+\s*,\s*([A-Za-z_][\w.\->]*)")
_ASSIGN = re.compile(r"\b([A-Za-z_][\w.\->]*)\s*=\s*([^;=][^;]*);")
_NUM = re.compile(r"^(?:0[xX][0-9a-fA-F]+|\d+)(?:ull|ll|ul|u|l)?$", re.I)
_TOK = re.compile(r"0[xX][0-9a-fA-F]+|\d+|[A-Za-z_][\w.\->]*|[-+*/%()]")


def _base(name: str) -> str:
    return name.split(".")[-1].split("->")[-1]


def _lit(tok: str):
    t = tok.rstrip("uUlL")
    try:
        return int(t, 0)
    except ValueError:
        return None


def eval_expr(expr: str, env: dict) -> Interval:
    """Interval of a C expression given var->Interval env. Supports + - * / % and parens; anything
    unrecognised collapses to TOP (conservative)."""
    toks = _TOK.findall(expr)
    if not toks:
        return TOP
    pos = 0

    def parse_expr():
        nonlocal pos
        val = parse_term()
        while pos < len(toks) and toks[pos] in ("+", "-"):
            op = toks[pos]; pos += 1
            rhs = parse_term()
            val = val + rhs if op == "+" else val - rhs
        return val

    def parse_term():
        nonlocal pos
        val = parse_atom()
        while pos < len(toks) and toks[pos] in ("*", "/", "%"):
            op = toks[pos]; pos += 1
            rhs = parse_atom()
            if op == "*":
                val = val * rhs
            else:
                val = TOP                               # div/mod result range: conservative
        return val

    def parse_atom():
        nonlocal pos
        if pos >= len(toks):
            return TOP
        t = toks[pos]
        if t == "(":
            pos += 1
            v = parse_expr()
            if pos < len(toks) and toks[pos] == ")":
                pos += 1
            return v
        pos += 1
        lit = _lit(t)
        if lit is not None:
            return Interval(lit, lit)
        return env.get(_base(t), TOP)

    try:
        return parse_expr()
    except Exception:                                    # noqa: BLE001
        return TOP


def analyze_function(body: str) -> dict:
    """Compute a conservative var->Interval env over the function body (straight-line + return-guards).
    Wire reads => full type range; literal/arith assigns propagate; `if (v REL k) return|goto` narrows
    v for the code after."""
    env: dict = {}
    for line in body.splitlines():
        for m in _READ.finditer(line):
            env[_base(m.group(2))] = Interval(*_WIDTH[m.group(1)])
        gm = re.search(r"if\s*\(\s*([A-Za-z_][\w.\->]*)\s*(<|<=|>|>=|==|!=)\s*(\w+)\s*\)\s*"
                       r"(?:\{\s*)?(?:return|goto|break|continue)", line)
        if gm:
            var, op, k = _base(gm.group(1)), gm.group(2), _lit(gm.group(3))
            if k is not None:
                cur = env.get(var, TOP)
                # the guard BAILS, so after it the surviving range is the complement.
                if op in ("<", "<="):      env[var] = Interval(k if op == "<" else k + 1, cur.hi)
                elif op in (">", ">="):    env[var] = Interval(cur.lo, k if op == ">" else k - 1)
                elif op == "==":          # bailed when ==k, so k is excluded after; narrow if k is an endpoint
                    if k == cur.lo:        env[var] = Interval(cur.lo + 1, cur.hi)
                    elif k == cur.hi:      env[var] = Interval(cur.lo, cur.hi - 1)
                    else:                  env[var] = cur
                elif op == "!=":           env[var] = Interval(k, k)  # survives only when ==k
            continue
        am = _ASSIGN.search(line)
        if am and "==" not in am.group(0):
            lhs, rhs = _base(am.group(1)), am.group(2).strip()
            env[lhs] = eval_expr(rhs, env)
    return env


def can_be_zero(expr: str, body: str) -> bool:
    """Could `expr` evaluate to 0 (divide-by-zero risk) under the function's ranges?"""
    return eval_expr(expr, analyze_function(body)).includes(0)


def max_value(expr: str, body: str) -> int:
    return eval_expr(expr, analyze_function(body)).hi
