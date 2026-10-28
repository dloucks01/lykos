"""Source-level exploitation recipes -- the honest FLOOR for a static source finding.

A source scanner finds a dangerous sink (command injection, format string) at file:line whose
dangerous argument is syntactically linked to an UNTRUSTED SOURCE (a function parameter, an input
reader, argv). Unlike the binary recipe synthesizers (fmt_recipe / oob_recipe / chain_primitive)
this cannot compute a stack-exact write plan -- there is no recovered layout -- but it CAN hand the
operator the technique, a concrete candidate payload, and exactly what remains unproven. It is the
non-fuzzing weaponization floor: a finding the confirmation ladder could not turn into a proven PoC
still leaves the engagement with a usable artifact instead of a terminal L0 row.

Honesty contract (inherited from `recipe.file_recipe`, never violated here -- precision is paramount):
  * filed `corroborated`, NEVER `poc-backed` / verified -- nothing ran to confirm it;
  * the source->sink data-flow is reported as a SYNTACTIC link, not proven taint, and the row says
    plainly that attacker-reachability (and, for %n, the stack offset / write target) are unproven
    and need the live or compiled target;
  * it owns its own dedup_key, so it never overwrites or downgrades a stronger (verified) row.
"""
from __future__ import annotations

from typing import Optional

from . import recipe

#: Per class: (candidate payload bytes or None, technique label, target ceiling, how the input is
#: described). None payload = the weaponization is a condition, not fixed bytes (overflow / UAF): the
#: recipe states it in prose and names what the compiled target is needed for.
_WEAPON = {
    "CWE-78": (b"; id #", "shell metacharacter command injection", "L2",
               "the controlled command argument"),
    "CWE-134": (b"%p.%p.%p.%p.%p.%p.%p.%p|%n",
                "format-string %n write-what-where / %s,%p disclosure", "L2",
                "the controlled format argument"),
    "CWE-190": (None, "integer-overflow allocation -> undersized buffer -> heap overflow", "L2",
                "the controlled size input"),
    "CWE-416": (None, "use-after-free with heap grooming -> controlled reclaimed contents", "L2",
                "the controlled free/use path"),
}


def _prose(cwe: str, fn: str, arg_s: str, file: str, line: int, src: str) -> tuple:
    """(summary, why_not_executed, steps) for one class. fn/arg_s are the operation and its subject
    (sink + argument; allocator + size expression; free/use site + pointer)."""
    if cwe == "CWE-78":
        return (
            f"{fn}() at {file}:{line} runs the non-literal command '{arg_s}', which flows from "
            f"{src}; appending shell metacharacters (e.g. `; id #`) injects commands",
            "static source analysis: the source->sink flow is a syntactic link, "
            "attacker-reachability is not dynamically proven and no shell ran here",
            [f"identify the request field / input that reaches {src}",
             "set it to a value with a shell separator, e.g. `legit; id #` or `$(id)`",
             "the shell then runs `id` alongside the intended command",
             "replace `id` with the operator payload (reverse shell, etc.)"])
    if cwe == "CWE-134":
        return (
            f"{fn}() at {file}:{line} uses the non-literal format '{arg_s}', which flows from "
            f"{src}; a controlled format yields %n write-what-where and %s/%p leaks",
            "static source analysis: the source->sink flow is a syntactic link, "
            "attacker-reachability is not proven and the exact arg offset / write target need "
            "the compiled binary",
            [f"control the input that reaches {src}",
             "send `%p.%p.%p...` to leak stack words and locate the format argument's offset",
             "escalate to `%<k>$n` (with short-write chaining) to overwrite a GOT/return slot",
             "the exact offset and write target need the compiled binary -- run fmt_recipe on it"])
    if cwe == "CWE-190":
        return (
            f"{fn}() at {file}:{line} sizes an allocation from overflow-prone arithmetic '{arg_s}', "
            f"which flows from {src}; driving it past the integer width wraps the size, "
            f"under-allocates, and the following copy overflows the heap buffer",
            "static source analysis: the source->size flow is a syntactic link; the exact field "
            "widths and the trailing copy length need the parser/compiled binary, and no "
            "allocation ran here",
            [f"drive {src} so the size arithmetic '{arg_s}' exceeds the integer width and wraps",
             "the allocation then returns a buffer smaller than the data about to be written",
             "the subsequent copy overflows it (heap-buffer-overflow, CWE-122)",
             "widths and the copy length need the compiled binary -- run the memory tools on it"])
    # CWE-416 (use-after-free) / CWE-415 is routed here too
    return (
        f"{fn} at {file}:{line} uses '{arg_s}' after it is freed, and '{arg_s}' flows from {src}; "
        f"reclaiming the freed allocation with controlled contents yields a controlled "
        f"use-after-free",
        "static source analysis: the free->use ordering is matched textually and the pointer's "
        "source is a syntactic link; that both lie on ONE reachable path, and the heap state "
        "between them, are not proven here",
        [f"reach the free of '{arg_s}', then its use at {file}:{line}, on one path",
         "between them, allocate an object of the same size class to reclaim the freed chunk",
         "populate it with controlled bytes -> the use reads/writes attacker-controlled memory",
         "reachability and the heap layout need the compiled binary / a dynamic run"])


def file_source_recipe(ctx, target, *, cwe: str, fn: str, arg: str, file: str, line: int,
                       taint: dict, lead=None) -> Optional[int]:
    """File a corroborated source-level recipe for one tainted finding. `taint` is the data-flow
    link dict ({"via","source"}) the scanner proved syntactically. `fn`/`arg` are the operation and
    its subject (sink+argument, allocator+size, free/use+pointer). Returns the recipe id, or None."""
    spec = _WEAPON.get(cwe if cwe != "CWE-415" else "CWE-416")
    if spec is None:
        return None
    payload, technique, level, mode = spec
    arg_s = " ".join((arg or "").split())[:60]
    src = taint.get("source", "an untrusted source")
    via = taint.get("via", "data flow")
    summary, why, steps = _prose(cwe, fn, arg_s, file, line, src)
    return recipe.file_recipe(
        ctx, target, cwe=cwe, technique=technique, target_level=level, severity="high",
        detector="source_recipe", dedup_key=f"recipe:{cwe}:source:{file}:{line}:{fn}",
        title=f"Exploitation recipe: {technique} at {file}:{line}",
        summary=summary, steps=steps, why_not_executed=why,
        input_bytes=payload, input_mode=mode, lead=lead,
        extra_evidence=[{"channel": "recipe-source",
                         "detail": (f"source finding at {file}:{line}; subject "
                                    f"'{arg_s}' flows from {src} ({via})")}])
