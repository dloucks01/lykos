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

#: Per class: (candidate payload bytes, technique label, target ceiling, how the input is described).
_WEAPON = {
    "CWE-78": (b"; id #", "shell metacharacter command injection", "L2",
               "the controlled command argument"),
    "CWE-134": (b"%p.%p.%p.%p.%p.%p.%p.%p|%n",
                "format-string %n write-what-where / %s,%p disclosure", "L2",
                "the controlled format argument"),
}


def _steps(cwe: str, src: str) -> list:
    if cwe == "CWE-78":
        return [
            f"identify the request field / input that reaches {src}",
            "set it to a value with a shell separator, e.g. `legit; id #` or `$(id)`",
            "the shell then runs `id` alongside the intended command",
            "replace `id` with the operator payload (reverse shell, etc.)"]
    return [
        f"control the input that reaches {src}",
        "send `%p.%p.%p...` to leak stack words and locate the format argument's offset",
        "escalate to `%<k>$n` (with short-write chaining) to overwrite a GOT/return slot",
        "the exact offset and write target need the compiled binary -- run fmt_recipe on it"]


def file_source_recipe(ctx, target, *, cwe: str, fn: str, arg: str, file: str, line: int,
                       taint: dict, lead=None) -> Optional[int]:
    """File a corroborated source-level recipe for one tainted-sink finding. `taint` is the
    data-flow link dict ({"via","source"}) the scanner proved syntactically. Returns the recipe
    finding id, or None."""
    spec = _WEAPON.get(cwe)
    if spec is None:
        return None
    payload, technique, level, mode = spec
    arg_s = " ".join((arg or "").split())[:60]
    src = taint.get("source", "an untrusted source")
    via = taint.get("via", "data flow")
    if cwe == "CWE-78":
        summary = (f"{fn}() at {file}:{line} runs the non-literal command '{arg_s}', which flows "
                   f"from {src}; appending shell metacharacters (e.g. `; id #`) injects commands")
        why = ("static source analysis: the source->sink flow is a syntactic link, "
               "attacker-reachability is not dynamically proven and no shell ran here")
    else:
        summary = (f"{fn}() at {file}:{line} uses the non-literal format '{arg_s}', which flows "
                   f"from {src}; a controlled format yields %n write-what-where and %s/%p leaks")
        why = ("static source analysis: the source->sink flow is a syntactic link, "
               "attacker-reachability is not proven and the exact arg offset / write target "
               "need the compiled binary")
    return recipe.file_recipe(
        ctx, target, cwe=cwe, technique=technique, target_level=level, severity="high",
        detector="source_recipe", dedup_key=f"recipe:{cwe}:source:{file}:{line}:{fn}",
        title=f"Exploitation recipe: {technique} at {file}:{line}",
        summary=summary, steps=_steps(cwe, src), why_not_executed=why,
        input_bytes=payload, input_mode=mode, lead=lead,
        extra_evidence=[{"channel": "recipe-source",
                         "detail": (f"source finding at {file}:{line}; dangerous argument "
                                    f"'{arg_s}' flows from {src} ({via})")}])
