"""Grammar-aware, structure-valid fuzzing input generation.

lykos's `StructMutator` keeps a FLAT record valid -- magic, integer fields, a length-prefixed blob.
That reaches a header parser but not the code behind a *recursive* format: nested objects/arrays
(JSON, CBOR), nested type-length-value containers, s-expressions, an expression language. Byte havoc
never builds a balanced `{...[...]...}`; a coverage-guided fuzzer without a grammar random-walks the
outer parser forever. Nautilus (NDSS'19) and Gramatron (ISSTA'21) solve this by generating from a
context-free grammar so every input is structurally valid and the fuzzer explores the *handlers*.

This is a self-contained grammar engine in lykos's own campaign -- no external Gramatron/Nautilus,
no AFL++ custom-mutator glue, no dependency and deterministic given the RNG. It provides:

  * a compact grammar representation (rules of alternative productions of literal / reference
    elements) with a ``%ref%`` string DSL and a JSON-list form for `params.grammar`;
  * ``generate`` -- bounded derivation from the start rule (depth budget + a size cap; near the
    budget it prefers terminal-heavy productions so recursion always terminates);
  * ``GrammarMutator`` -- the standard ``.mutate(data, corpus)`` mutator: mostly emit a fresh valid
    input, sometimes splice corpus/dictionary bytes into a generated skeleton, and occasionally hand
    a valid input to byte havoc so off-grammar edges (the parser's error paths) are still explored;
  * ``from_spec`` -- bridge lykos's inferred flat format spec into a (flat) grammar, plus a handful
    of built-in recursive grammars (``kv``, ``tlv``, ``json``, ``sexpr``) an operator can select.
"""
from __future__ import annotations

import logging
from typing import Optional

from .structure import Mutator

_log = logging.getLogger("lykos.fuzz.grammar")

_MAX_LEN = 4096
_MAX_DEPTH = 24


def _as_bytes(x) -> bytes:
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    return str(x).encode("latin-1", "ignore")


def _compile_production(prod) -> list:
    """One production -> [('lit', bytes) | ('ref', name)]. Accepts a list of elements (tuples
    ('lit',x)/('ref',x) or JSON lists ['lit',x]/['ref',x]) or a compact string where %name% is a
    reference and everything else is a literal (%% is a literal percent)."""
    if isinstance(prod, str):
        out, i, n = [], 0, len(prod)
        buf = []
        while i < n:
            if prod[i] == "%":
                if i + 1 < n and prod[i + 1] == "%":
                    buf.append("%"); i += 2; continue
                j = prod.find("%", i + 1)
                if j == -1:
                    buf.append(prod[i]); i += 1; continue
                if buf:
                    out.append(("lit", _as_bytes("".join(buf)))); buf = []
                out.append(("ref", prod[i + 1:j])); i = j + 1
            else:
                buf.append(prod[i]); i += 1
        if buf:
            out.append(("lit", _as_bytes("".join(buf))))
        return out
    # a bare single element written as ('lit', x) / ('ref', x) is a one-element production
    if isinstance(prod, (tuple, list)) and len(prod) == 2 and prod[0] in ("lit", "ref"):
        prod = [prod]
    elements = []
    for e in prod:
        if isinstance(e, (tuple, list)) and len(e) == 2 and e[0] in ("lit", "ref"):
            elements.append((e[0], _as_bytes(e[1]) if e[0] == "lit" else str(e[1])))
        else:
            elements.append(("lit", _as_bytes(e)))
    return elements


def compile_grammar(spec: dict) -> dict:
    """Normalize a grammar spec into ``{start, rules}`` with productions as element lists.

    ``spec`` = ``{"start": name, "rules": {name: [production, ...]}}``. Raises ValueError on an
    empty/invalid grammar (an undefined start rule, or a rule that references a missing nonterminal)
    so a bad analyst grammar fails loudly at build time rather than silently generating nothing.
    """
    rules_in = spec.get("rules") or {}
    start = spec.get("start") or next(iter(rules_in), None)
    if not start or start not in rules_in:
        raise ValueError("grammar: start rule missing or not defined")
    rules = {}
    for name, prods in rules_in.items():
        if not prods:
            raise ValueError(f"grammar: rule {name!r} has no productions")
        rules[name] = [_compile_production(p) for p in prods]
    # validate references
    for name, prods in rules.items():
        for prod in prods:
            for kind, val in prod:
                if kind == "ref" and val not in rules:
                    raise ValueError(f"grammar: rule {name!r} references undefined {val!r}")
    return {"start": start, "rules": rules, "_minlen": _min_lengths(rules)}


def _min_lengths(rules: dict) -> dict:
    """Fixpoint: the minimum number of REF-expansions a rule needs to terminate. Used near the depth
    budget to choose a production that actually bottoms out (so recursion always terminates)."""
    cost = {n: float("inf") for n in rules}
    changed = True
    while changed:
        changed = False
        for name, prods in rules.items():
            best = min((sum(cost[v] for k, v in p if k == "ref") + 1 for p in prods), default=1)
            if best < cost[name]:
                cost[name] = best; changed = True
    return cost


def generate(grammar: dict, rng, *, max_depth: int = _MAX_DEPTH, max_len: int = _MAX_LEN,
             inject=None) -> bytes:
    """Bounded derivation from the start rule -> a structurally-valid byte string.

    ``inject`` (optional list of byte tokens) lets corpus/dictionary fragments be planted at literal
    slots occasionally, so a grammar can carry real magic/keyword values the target compares.
    """
    rules = grammar["rules"]
    minlen = grammar.get("_minlen") or _min_lengths(rules)
    out = bytearray()

    def expand(name, depth):
        if len(out) >= max_len:
            return
        prods = rules[name]
        if depth <= 0:
            prod = min(prods, key=lambda p: sum(minlen[v] for k, v in p if k == "ref"))
        else:
            prod = rng.choice(prods)
        for kind, val in prod:
            if len(out) >= max_len:
                return
            if kind == "lit":
                if inject and rng.random() < 0.15:
                    out.extend(rng.choice(inject))
                out.extend(val)
            else:
                expand(val, depth - 1)

    expand(grammar["start"], max_depth)
    return bytes(out)


class GrammarMutator:
    """Grammar-aware mutator with the standard ``.mutate(data, corpus)`` interface.

    Strategy: mostly emit a fresh valid derivation; sometimes plant corpus/dictionary bytes into a
    derivation's literal slots (so learned magic/keywords propagate); and, with a small probability,
    hand a valid input to byte havoc so the parser's error paths are exercised too. Never raises --
    any failure degrades to the byte mutator, exactly like StructMutator.
    """
    def __init__(self, rng, grammar: dict, dictionary=None):
        self.rng = rng
        self.grammar = grammar
        self.byte = Mutator(rng, dictionary)
        self.dictionary = list(dictionary or [])

    def mutate(self, data: bytes = b"", corpus=()) -> bytes:
        try:
            r = self.rng.random()
            if r < 0.15 and data:
                # off-grammar exploration: havoc a valid base so error handlers get hit too
                return self.byte.mutate(data, corpus)
            inject = None
            if r < 0.55:
                pool = list(self.dictionary)
                pool += [c for c in list(corpus)[:16] if 0 < len(c) <= 64]
                inject = pool or None
            return generate(self.grammar, self.rng, inject=inject)
        except Exception:
            _log.debug("grammar-mutate failed; byte-havoc fallback", exc_info=True)
            return self.byte.mutate(data, corpus)


# ---------------------------------------------------------------- built-in grammars

_BUILTINS = {
    # key=value config, one per line, repeated (left-recursive via %kv%)
    "kv": {"start": "cfg", "rules": {
        "cfg": ["%pair%\n", "%pair%\n%cfg%"],
        "pair": ["%key%=%val%"],
        "key": ["name", "host", "port", "path", "user", "size", "mode", "timeout"],
        "val": ["%num%", "%word%", "%word%,%val%", "/%word%", "true", "false"],
        "num": ["0", "1", "255", "65535", "%digit%%num%", "%digit%"],
        "digit": ["0", "1", "7", "9"],
        "word": ["a", "admin", "root", "x", "AAAA", "%word%%word%"],
    }},
    # nested type-length-value: a container whose payload is itself a sequence of TLVs
    "tlv": {"start": "tlv", "rules": {
        "tlv": ["%type%%len%%val%"],
        "type": [("lit", b"\x01"), ("lit", b"\x02"), ("lit", b"\x10"), ("lit", b"\xff")],
        "len": [("lit", b"\x00"), ("lit", b"\x04"), ("lit", b"\x08")],
        "val": ["%bytes%", "%tlv%", "%tlv%%tlv%"],
        "bytes": [("lit", b"AAAA"), ("lit", b"\x00\x00\x00\x00"), ("lit", b"\xff\xff")],
    }},
    # JSON-lite: recursive objects/arrays
    "json": {"start": "val", "rules": {
        "val": ["%obj%", "%arr%", "%str%", "%num%", "true", "false", "null"],
        "obj": ["{}", "{%members%}"],
        "members": ["%pair%", "%pair%,%members%"],
        "pair": ["%str%:%val%"],
        "arr": ["[]", "[%elems%]"],
        "elems": ["%val%", "%val%,%elems%"],
        "str": ['"a"', '"key"', '"%chars%"'],
        "chars": ["a", "x", "\\\\", "\\\"", "%chars%%chars%"],
        "num": ["0", "1", "-1", "1e9", "%num%%num%"],
    }},
    # balanced s-expressions / nested parens (stresses recursive-descent stacks)
    "sexpr": {"start": "s", "rules": {
        "s": ["a", "(%list%)"],
        "list": ["%s%", "%s% %list%"],
    }},
}


def builtin(name: str) -> Optional[dict]:
    spec = _BUILTINS.get(name)
    return compile_grammar(spec) if spec else None


def builtin_names() -> list:
    return sorted(_BUILTINS)


def from_spec(format_spec) -> Optional[dict]:
    """Bridge lykos's flat format spec (a list of {type,...} fields) into a flat grammar: the start
    rule is the field sequence, a magic field is a fixed literal, an integer field alternates a few
    boundary values, and a blob/length-prefixed field draws from a small set. This gives the grammar
    path something valid to build even for a non-recursive format; the recursive power lives in the
    built-ins / analyst grammars. Returns None when the spec has no usable fields."""
    if not format_spec:
        return None
    rules = {"S": [[]]}
    seq = []
    for i, fld in enumerate(format_spec):
        t = (fld.get("type") or "").lower()
        rn = f"f{i}"
        if t == "magic":
            v = fld.get("value", b"")
            seq.append(("ref", rn)); rules[rn] = [[("lit", _as_bytes(v))]]
        elif t in ("u8", "u16", "u32", "u64", "int"):
            seq.append(("ref", rn))
            rules[rn] = [[("lit", b"\x00")], [("lit", b"\x01")], [("lit", b"\xff")],
                         [("lit", b"\x00\x00")], [("lit", b"\xff\xff\xff\xff")]]
        else:  # blob / length-prefixed / text: a small varied payload
            seq.append(("ref", rn))
            rules[rn] = [[("lit", b"A")], [("lit", b"AAAAAAAA")], [("lit", b"")],
                         [("lit", b"\x00" * 4)], [("lit", b"%s" % b"\xff" * 8)]]
    if not seq:
        return None
    rules["S"] = [seq]
    return compile_grammar({"start": "S", "rules": rules})
