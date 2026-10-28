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

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..source_lookup import source_project_for
from .srcwalk import source_files

_log = logging.getLogger(__name__)

SOURCE_SINK_STAGE = "source_sink_scan"
TOOL = "source-sinks"
TOOL_VERSION = "source-sinks-1"
#: cap on corroborated recipes filed per scan, so a huge tree cannot flood the finding table.
_MAX_SOURCE_RECIPES = 64


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


# keywords that can directly precede a CALL (`return printf(f)`, `else system(c)`); any other
# identifier (or a `*`) right before the sink name makes it a declaration / definition
# (`int printf(const char *fmt, ...)`, `static void syslog(int pri, const char *f)`), not a call.
_CALL_PREFIX_KW = {"return", "else", "do", "case", "goto", "sizeof", "typeof", "__typeof__"}


def _is_declaration(prefix: str) -> bool:
    p = prefix.rstrip()
    if not p:
        return False
    if p.endswith("*"):
        return True
    m = re.search(rf"({_IDENT})$", p)
    return bool(m) and m.group(1) not in _CALL_PREFIX_KW


def _is_literal(arg: str) -> bool:
    """True if the argument is (or wraps, via i18n) a string literal -- the safe case."""
    a = arg.strip()
    m = _I18N.match(a)
    if m:
        a = m.group(1).strip()
    return bool(re.match(r'^(?:L|u8|u|U)?"', a))


# ---- taint-lite: link the dangerous argument to an UNTRUSTED SOURCE (sound, intraprocedural) -----
# The sink finding on its own only proves the argument is non-literal. A corroborated exploitation
# recipe is warranted only when that value is syntactically derived from input, so these report a
# CHECKABLE SYNTACTIC FACT (the base identifier is a function parameter, or is filled by a known
# input reader in the same function) -- never an inferred guess. They under-report by design (a
# multi-line signature or a transitive copy yields no link -> the finding stays a candidate with no
# recipe) so a recipe is never filed on a fabricated flow.
# a column-0 function-definition header: `<type> name(params)` ending at the body's `{` (which may
# be on this line, with the body after it, or on the next line -> end-of-line). The two-identifier
# `<type> <name>` shape (return type THEN name) is what separates a definition from a bare call.
_SIG = re.compile(r'^[A-Za-z_][\w \t\*]*\b[A-Za-z_]\w*\s*\(([^;{]*)\)\s*(?:\{|$)')


def _base_ident(arg: str):
    """The leading identifier of the sink argument (`msg->fmt` -> `msg`, `&buf[0]` -> `buf`). A
    call or a literal has no simple base and yields None (-> no taint link)."""
    a = arg.strip().lstrip("&").lstrip("*").strip()
    m = re.match(r"([A-Za-z_]\w*)", a)
    if not m:
        return None
    ident = m.group(1)
    rest = a[m.end():].lstrip()
    if rest.startswith("("):                                # a function call, not a variable
        return None
    return ident


def _param_idents(params: str) -> set:
    """Identifier names of a (single-line) function signature's parameter list."""
    out = set()
    for part in params.split(","):
        toks = re.findall(r"[A-Za-z_]\w*", part)
        if toks and part.strip() not in ("void", ""):
            out.add(toks[-1])                              # the declared name is the last token
    return out


def _enclosing(lines: list, idx: int):
    """Conservative enclosing-function bounds: start just after the previous function's column-0
    closing brace (normal multi-line C), but not earlier than the NEAREST column-0 signature above
    the sink (so a one-line definition, whose `}` is not at column 0, is handled too). Returns
    (signature_or_start_index, param_name_set); an empty set means the params could not be parsed
    (e.g. a multi-line signature) -> no parameter link is claimed."""
    start = 0
    for s in range(idx - 1, -1, -1):
        if lines[s][:1] == "}":                            # column-0 '}' = end of the prior function
            start = s + 1
            break
    for s in range(idx, start - 1, -1):                    # nearest column-0 signature above the sink
        m = _SIG.match(lines[s])
        if m:
            return s, _param_idents(m.group(1))
    return start, set()


def _reader_source(body: str, base: str):
    """If `base` is filled by a known input reader in `body`, name that reader; else None. Readers
    are matched at the exact destination/return position so a count or fd argument is not mistaken
    for the data buffer."""
    b = re.escape(base)
    if re.search(rf"\b{b}\s*=\s*argv\s*\[", body):
        return "argv[]"
    for fn in ("getenv", "secure_getenv", "fgetln"):       # data-returning readers (assigned-from)
        if re.search(rf"\b{b}\s*=\s*{fn}\s*\(", body):
            return f"{fn}()"
    for fn in ("read", "recv", "recvfrom"):                # destination = 2nd argument
        if re.search(rf"\b{fn}\s*\(\s*[^,;()]+,\s*(?:&)?{b}\b", body):
            return f"{fn}()"
    for fn in ("fgets", "gets", "fread"):                  # destination = 1st argument
        if re.search(rf"\b{fn}\s*\(\s*(?:&)?{b}\b", body):
            return f"{fn}()"
    return None


def _taint_link(lines: list, idx: int, arg: str):
    """Syntactic link from the sink argument to an untrusted source, or None. {"via","source"}."""
    base = _base_ident(arg)
    if not base:
        return None
    start, params = _enclosing(lines, idx)
    if base in params:
        return {"via": "parameter", "source": f"function parameter '{base}'"}
    rdr = _reader_source("\n".join(lines[start:idx + 1]), base)
    if rdr:
        return {"via": "input-reader", "source": f"{rdr} into '{base}'"}
    return None


def scan_source(root: Path) -> list:
    findings: list = []
    for label, _p, text in source_files(root):
        text = _strip_comments(text)                       # a sink named in a comment is not a call
        lines = text.splitlines()
        lit_vars = set(_LIT_ASSIGN.findall(text))          # locals assigned a string literal
        for i, ln in enumerate(lines):
            if ln.lstrip().startswith("#"):
                continue                # a macro body forwards its PARAMETER; the call site decides
            for m in _CALL.finditer(ln):
                fn = m.group(1)
                if _is_declaration(ln[:m.start()]) or ln[:m.start()].rstrip().endswith((".", "->")):
                    continue            # a prototype/definition, or a same-named member function
                args = _split_args(_balanced_arg(ln, ln.index("(", m.end() - 1)))
                pos = _CMDI.get(fn, _FMT.get(fn))
                if pos is None or pos >= len(args):
                    continue
                arg = args[pos]
                if _is_literal(arg) or arg in lit_vars:
                    continue
                # the v* family takes a va_list: `vfprintf(stderr, fmt, ap)` is the body of a
                # printf-style WRAPPER forwarding its own format parameter -- the correct pattern,
                # whose callers decide the format (the binary format_string detector excludes the
                # v* family for the same reason)
                if fn.startswith("v") and re.fullmatch(_IDENT, arg):
                    continue
                # a bare numeric / sizeof / NULL is not a tainted string either
                if re.fullmatch(r"(?:NULL|0|nullptr)", arg):
                    continue
                taint = _taint_link(lines, i, arg)
                if fn in _CMDI:
                    findings.append(_mk(label, i, fn, arg, "CWE-78",
                                        f"{fn}() runs a non-literal command ('{arg}')",
                                        "OS command injection", taint))
                else:
                    findings.append(_mk(label, i, fn, arg, "CWE-134",
                                        f"{fn}() uses a non-literal format string ('{arg}')",
                                        "format string", taint))
    return findings


def _mk(name, line, fn, arg, cwe, detail_tail, label, taint=None) -> dict:
    ev = [{"channel": "source", "detail": f"{name}:{line + 1}: {detail_tail}"}]
    if taint:                                              # a proven source->sink link raises the row
        ev.append({"channel": "source-flow",
                   "detail": f"the sink argument flows from {taint['source']} ({taint['via']})"})
    return {
        "cwe": cwe, "severity": "high",
        "title": f"{label} via {fn}() ({cwe})",
        "dedup_key": f"srcsink:{cwe}:{name}:{line + 1}:{fn}",
        "fn": fn, "arg": arg, "file": name, "line": line + 1, "taint": taint,
        "evidence": ev}


def source_sink_stage(ctx) -> dict:
    import io
    import tarfile

    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("source_sink_scan requires a target_id")
    proj = source_project_for(ctx.conn, target)
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
    recipes = _file_findings(ctx, target, findings)
    ctx.emit("source_sink.done", payload={"applicable": True, "findings": len(findings),
             "recipes": recipes})
    ctx.progress(pct=100, msg=f"{len(findings)} tainted-sink candidate(s), {recipes} recipe(s)")
    return {"metrics": {"findings": len(findings), "recipes": recipes}}


def _file_findings(ctx, target, findings) -> int:
    """File each sink as a `candidate`, and for every one with a proven source->sink link also file
    the corroborated exploitation recipe (the non-fuzzing weaponization floor). Returns the number
    of recipes filed. A linked finding carries more confidence than a flat pattern match."""
    from ..poc.source_recipe import file_source_recipe
    fd = FindingDAO(ctx.conn)
    recipes = 0
    for f in findings:
        linked = bool(f.get("taint"))
        fd.upsert(target.id, target.case_id, {
            "cwe": f["cwe"], "severity": f["severity"], "detector": "source_sink",
            "title": f["title"], "evidence": f["evidence"], "site_detail": f"{f['file']}:{f['line']}",
            "function_addr": None, "site_addr": None, "dedup_key": f["dedup_key"],
            "state": "candidate", "confidence": 0.6 if linked else 0.4})
        if linked and recipes < _MAX_SOURCE_RECIPES:
            if file_source_recipe(ctx, target, cwe=f["cwe"], fn=f["fn"], arg=f["arg"],
                                  file=f["file"], line=f["line"], taint=f["taint"]) is not None:
                recipes += 1
    return recipes


def register() -> None:
    register_stage(SOURCE_SINK_STAGE, source_sink_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_source_sink_scan(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, SOURCE_SINK_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="quick", force=force)
