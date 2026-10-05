"""Tainted-argument sink detector (CWE-78 command injection, CWE-134 format string), source-level.

Two of the highest-impact C/C++ bugs have the SAME tell in source: a dangerous sink is called with
a NON-LITERAL argument where a literal belongs.

  * `system(cmd)` / `popen(cmd, ...)` with a non-literal command -> the shell interprets whatever
    reached `cmd` (CWE-78). `system("ls")` with a string literal is intentional and is NOT flagged.
  * `printf(fmt)` / `fprintf(f, fmt)` / `sprintf(b, fmt, ...)` / `syslog(pri, fmt)` / the scanf
    family with a non-literal FORMAT argument -> an attacker who controls the format gets `%n`
    write-what-where and `%s`/`%p` leaks (CWE-134). `printf("%s", s)` is safe.

Like the int_overflow / uaf source detectors this is a HEURISTIC (findings are `candidate`): it
proves the argument is not a literal, not that it is attacker-controlled. To cut the most common
false positive it tracks locals assigned a string literal in the same file (`const char *fmt =
"..."; printf(fmt);` is safe) and treats an i18n wrapper around a literal (`_( "..." )`,
`gettext("...")`) as a literal. Pure parsing, stdlib based; an unreadable file is skipped.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ...db.dao import ArtifactDAO, FindingDAO, TargetDAO
from ...jobs.registry import register_stage

_log = logging.getLogger(__name__)

SOURCE_SINK_STAGE = "source_sink_scan"
TOOL = "source-sinks"
TOOL_VERSION = "source-sinks-1"

_MAX_FILES = 6000
_MAX_FILE = 4 << 20
_SRC_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")
_SKIP_SEGMENTS = {"examples", "example", "demo", "demos", "test", "tests", "third_party",
                  "3rdparty", "vendor", "node_modules"}

_IDENT = r"[A-Za-z_]\w*"
# command sinks -> the command argument position (0-based) whose non-literal value is CWE-78.
_CMDI = {"system": 0, "popen": 0}
# format sinks -> the FORMAT argument position whose non-literal value is CWE-134.
_FMT = {"printf": 0, "vprintf": 0, "fprintf": 1, "vfprintf": 1, "dprintf": 1, "vdprintf": 1,
        "sprintf": 1, "vsprintf": 1, "snprintf": 2, "vsnprintf": 2, "asprintf": 1, "vasprintf": 1,
        "syslog": 1, "vsyslog": 1, "scanf": 0, "fscanf": 1, "sscanf": 1}
_SINKS = set(_CMDI) | set(_FMT)
_CALL = re.compile(rf"\b({'|'.join(sorted(_SINKS, key=len, reverse=True))})\s*\(")
# an i18n wrapper whose single argument is the real (literal) format: _("..."), gettext("..."), N_(...)
_I18N = re.compile(r'^\s*(?:_|N_|gettext|dgettext|dcgettext|ngettext)\s*\(\s*(.*)$', re.S)
# a local assigned a string literal: `[type] name = "..."` -> name is a safe literal format
_LIT_ASSIGN = re.compile(rf'(?:^|[;{{]|\bconst\b|\bstatic\b|\bchar\b|\*)\s*({_IDENT})\s*=\s*(?:L|u8|u|U)?"')


def _balanced_arg(text: str, open_paren: int) -> str:
    depth, i, n = 0, open_paren, len(text)
    while i < n:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:i]
        i += 1
    return text[open_paren + 1:min(n, open_paren + 800)]


def _split_args(arglist: str) -> list:
    """Top-level comma split of a call's argument text (commas inside (), [], "" or '' do not
    separate). Good enough for picking the Nth argument of a flat call."""
    out, depth, i, start, n = [], 0, 0, 0, len(arglist)
    instr = None
    while i < n:
        c = arglist[i]
        if instr:
            if c == "\\":
                i += 2
                continue
            if c == instr:
                instr = None
        elif c in "\"'":
            instr = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(arglist[start:i].strip())
            start = i + 1
        i += 1
    out.append(arglist[start:n].strip())
    return out


_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def _strip_comments(text: str) -> str:
    """Blank out C/C++ comments while preserving line structure (so reported line numbers stay
    correct). A sink mentioned in PROSE -- `builds on top of the system (like for instance ...)` --
    is not a call; scanning the comment-stripped text removes that whole false-positive class."""
    return _COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def _is_literal(arg: str) -> bool:
    """True if the argument is (or wraps, via i18n) a string literal -- the safe case."""
    a = arg.strip()
    m = _I18N.match(a)
    if m:
        a = m.group(1).strip()
    return bool(re.match(r'^(?:L|u8|u|U)?"', a))


def scan_source(root: Path) -> list:
    findings: list = []
    n = 0
    for p in sorted(root.rglob("*")):
        if n >= _MAX_FILES:
            break
        if not p.is_file() or p.suffix.lower() not in _SRC_SUFFIXES:
            continue
        if _SKIP_SEGMENTS & {seg.lower() for seg in p.parts}:
            continue
        try:
            if p.stat().st_size > _MAX_FILE:
                continue
            text = p.read_text("utf-8", "replace")
        except OSError:
            continue
        n += 1
        text = _strip_comments(text)                       # a sink named in a comment is not a call
        lines = text.splitlines()
        lit_vars = set(_LIT_ASSIGN.findall(text))          # locals assigned a string literal
        for i, ln in enumerate(lines):
            for m in _CALL.finditer(ln):
                fn = m.group(1)
                args = _split_args(_balanced_arg(ln, ln.index("(", m.end() - 1)))
                pos = _CMDI.get(fn, _FMT.get(fn))
                if pos is None or pos >= len(args):
                    continue
                arg = args[pos]
                if _is_literal(arg) or arg in lit_vars:
                    continue
                # a bare numeric / sizeof / NULL is not a tainted string either
                if re.fullmatch(r"(?:NULL|0|nullptr)", arg):
                    continue
                if fn in _CMDI:
                    findings.append(_mk(p.name, i, fn, arg, "CWE-78",
                                        f"{fn}() runs a non-literal command ('{arg}')",
                                        "OS command injection"))
                else:
                    findings.append(_mk(p.name, i, fn, arg, "CWE-134",
                                        f"{fn}() uses a non-literal format string ('{arg}')",
                                        "format string"))
    return findings


def _mk(name, line, fn, arg, cwe, detail_tail, label) -> dict:
    return {
        "cwe": cwe, "severity": "high",
        "title": f"{label} via {fn}() ({cwe})",
        "dedup_key": f"srcsink:{cwe}:{name}:{line + 1}:{fn}",
        "evidence": [{"channel": "source", "detail": f"{name}:{line + 1}: {detail_tail}"}]}


def source_sink_stage(ctx) -> dict:
    import io
    import tarfile

    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("source_sink_scan requires a target_id")
    proj = next((a for a in ArtifactDAO(ctx.conn).list_by_case(target.case_id)
                 if a.kind == "source-project"
                 and (a.meta or {}).get("binary_sha") == target.sha256), None)
    if proj is None:
        ctx.emit("source_sink.done", payload={"applicable": False,
                 "note": "no archived source tree (this detector reads C/C++ source)"})
        return {}
    root = ctx.scratch() / "srcsink"
    root.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                          mode="r:gz") as tf:
            for mem in tf.getmembers():
                if mem.isfile() and not mem.name.startswith("/") and ".." not in mem.name:
                    tf.extract(mem, root)
    except Exception:
        ctx.emit("source_sink.done", payload={"applicable": False,
                 "note": "could not unpack the archived source tree"})
        return {}

    ctx.progress(msg="scanning for tainted command / format-string sinks")
    findings = scan_source(root)
    fd = FindingDAO(ctx.conn)
    for f in findings:
        fd.upsert(target.id, target.case_id, {
            "cwe": f["cwe"], "severity": f["severity"], "detector": "source_sink",
            "title": f["title"], "evidence": f["evidence"],
            "function_addr": None, "site_addr": None, "dedup_key": f["dedup_key"],
            "state": "candidate", "confidence": 0.4})
    ctx.emit("source_sink.done", payload={"applicable": True, "findings": len(findings)})
    ctx.progress(pct=100, msg=f"{len(findings)} tainted-sink candidate(s)")
    return {}


def register() -> None:
    register_stage(SOURCE_SINK_STAGE, source_sink_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_source_sink_scan(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, SOURCE_SINK_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="quick", force=force)
