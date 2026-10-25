"""Runtime-environment discovery: what a target needs AROUND its argv before it runs at all.

The commonest reason a real engagement binary came back static-only was not a wrong argv: the
target needed a config file WITH content at a fixed path, a data/runtime directory, or an
environment variable, and exited at that gate on every execution -- so every dynamic stage
measured the gate (doc 47 R2.d / P5). `invocation.materialize` already writes a file behind a
value flag; this covers what no flag names:

  * env vars the target reads -- `getenv`/`secure_getenv` call sites with a string-literal
    argument (x86-64 call-site recovery), else env-shaped strings of a getenv importer;
  * absolute (and cwd-relative) paths it opens/stats/opendir/chdir/mkdir's with a literal;
  * the config FORMAT: keys, `[section]` headers and the separator the binary itself names.

Then it CONFIRMS before supplying anything, because supplying is a claim about the target:

  1. a baseline run (traced with strace -- or qemu `-strace` for an emulated target -- when
     available) records how the target exits and which paths it tried and did not find;
  2. the candidates are synthesised -- a plausible config with content (`textconf`), the
     directories, the env values -- and the target is run again with them;
  3. it is applied ONLY if that run got further than the baseline (not the same early exit),
     and every item is then removed one at a time: an item whose removal changes nothing was not
     needed and is dropped. What remains is exactly what the target needed, with the evidence.

Containment. Nothing is written to the host's real paths. Files and dirs are staged under the
caller's scratch and exposed INSIDE the bubblewrap sandbox: a file is `--ro-bind`-mounted at the
path the target opens, a directory is created fresh per run (`--dir`), and a system directory that
has to gain an entry (/etc, /var/lib, ...) gets a throwaway `--tmp-overlay`, so the sandbox's view
changes and the host's does not. A cwd-relative path lands in the sandbox cwd. Where bwrap (or its
overlay support) is missing, an absolute path cannot be supplied without touching the host, so it
is NOT supplied and the result says so (`degraded`) -- never silently.

Additive / never-degrade: a target whose baseline already runs (exit 0 with no missing-resource
complaint, or stays up) gets nothing; a set that does not change the outcome is not applied.
Pure stdlib.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)

# --- what counts as a runtime need ---------------------------------------------------------------

#: callee -> (argument index holding the path/name, what kind of need it is)
#:   env   : the argument is an environment-variable NAME
#:   file  : a file the target reads (supplied as a synthesized file)
#:   dir   : a directory it lists / enters (supplied as a directory)
#:   parent: it CREATES the path (mkdir / O_CREAT) -- what it needs is the parent directory
#:   exists: an existence probe (access/stat) -- a file if the name has an extension, else a dir
_NEED_CALLS = {
    "getenv": (0, "env"), "secure_getenv": (0, "env"), "__secure_getenv": (0, "env"),
    "fopen": (0, "file"), "fopen64": (0, "file"), "freopen": (0, "file"),
    "open": (0, "file"), "open64": (0, "file"), "__open_2": (0, "file"),
    "__open64_2": (0, "file"), "openat": (1, "file"), "openat64": (1, "file"),
    "__openat_2": (1, "file"), "creat": (0, "parent"),
    "access": (0, "exists"), "euidaccess": (0, "exists"), "eaccess": (0, "exists"),
    "faccessat": (1, "exists"), "stat": (0, "exists"), "stat64": (0, "exists"),
    "lstat": (0, "exists"), "lstat64": (0, "exists"), "__xstat": (1, "exists"),
    "__xstat64": (1, "exists"), "__lxstat": (1, "exists"), "__lxstat64": (1, "exists"),
    "statx": (1, "exists"), "realpath": (0, "exists"),
    "opendir": (0, "dir"), "chdir": (0, "dir"), "scandir": (0, "dir"),
    "mkdir": (0, "parent"),
}
#: Variables never supplied: the loader's and libc's own knobs (setting one changes how EVERY
#: program behaves, which is not this target's need) and the standard session variables.
_ENV_NEVER = re.compile(
    r"^(?:LD_\w+|MALLOC_\w+|GLIBC_TUNABLES|GCONV_PATH|LOCPATH|NLSPATH|HOSTALIASES|RES_OPTIONS|"
    r"LOCALDOMAIN|TZ|TZDIR|LANG|LANGUAGE|LC_\w+|PATH|HOME|USER|LOGNAME|SHELL|TERM|PWD|OLDPWD|"
    r"TMPDIR|TMP|TEMP|IFS|DISPLAY|POSIXLY_CORRECT|ASAN_OPTIONS|\w*SAN_OPTIONS|QEMU_\w+|"
    r"LYKOS_\w+|PYTHON\w*|COLUMNS|LINES|SHLVL|MAIL|HOSTNAME|XDG_\w+|DBUS_\w+|SSH_\w+)$")
#: A path the target's loader/libc touches on its own (not the program's need), or that the
#: sandbox owns. ENOENTs on these are noise, never a requirement.
_SYSTEM_PATH = re.compile(
    r"^(?:/proc/|/sys/|/dev/|/etc/ld\.so|/etc/(?:localtime|nsswitch\.conf|host\.conf|hosts|"
    r"resolv\.conf|gai\.conf|passwd|group|shadow|services|protocols|mtab|selinux|"
    r"malloc\.conf)|/usr/lib/locale|/usr/share/locale|/usr/lib\w*/gconv|/usr/share/zoneinfo|"
    r"/usr/share/X11/locale|/usr/lib/debug|/(?:usr/)?lib(?:32|64|x32)?/[^/]+$)|"
    r"\.so(?:\.[\d.]+)?$|/glibc-hwcaps/|/tls/|/haswell/|/x86_64/|-linux-gnu\w*/|-linux-musl\w*/|"
    # an EXECUTABLE it looks for (sendmail, a helper): a placeholder file there is not a program
    r"^/(?:usr/)?(?:local/)?s?bin/|^/usr/libexec/")
#: Candidate absolute paths from strings: rooted in a conventional config/data location.
_ABS_PATH = re.compile(r"^/(?:etc|var|usr/local|opt|srv|run|data|home/[\w.-]+|usr/share)"
                       r"(?:/[A-Za-z0-9_.+@-]+)+/?$")
#: Candidate relative paths: `conf/app.conf`, `./data/`, `app.ini`.
_REL_PATH = re.compile(r"^(?:\./)?(?:[A-Za-z0-9_.+-]+/)*[A-Za-z0-9_+-][A-Za-z0-9_.+-]*"
                       r"(?:\.(?:conf|cfg|ini|json|ya?ml|xml|toml|rc|db|dat|key|pem)|/)$")
_ENV_SHAPE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
_CONF_EXT = re.compile(r"(?i)\.(?:conf|cfg|ini|json|ya?ml|xml|toml|rc|config|properties)$")
#: An output line that says the run stopped on a missing resource (vs. running normally).
_MISSING = re.compile(
    r"(?i)cannot (?:open|find|read|access|stat|load|chdir)|could not (?:open|find|read|load)|"
    r"can't (?:open|find|read|load)|no such file|not found|does not exist|missing|not set|"
    r"is required|must be set|unable to (?:open|read|load|find)|failed to (?:open|read|load|"
    r"stat|access|find)|no config|not configured|empty config")
_DIRISH_ENV = re.compile(r"(?i)(?:^|_)(?:DIR|DIRECTORY|ROOT|HOME|PREFIX|PATH|SPOOL|CACHE|DATA|"
                         r"STATE|LIB|RUN|RUNDIR|BASE|WORKDIR)$")
#: More env candidates than this and only the ones the baseline output names are tried.
_ENV_CAP = 8
_ENV_KNOB = re.compile(r"(?i)DEBUG|TRACE|VERBOSE|TEST|PROFIL|DUMP|COLOU?R|LOG|LISTEN_(?:PID|FDS)|"
                       r"NOTIFY_SOCKET|INVOCATION_ID|JOURNAL|WATCHDOG|SESSION|PAGER|EDITOR")
#: A parser naming the LINE of its config it rejected.
_LINE_ERR = re.compile(r"(?i)\bline\s+(\d{1,4})\b|:(\d{1,4}):")
_FILEISH_ENV = re.compile(r"(?i)(?:^|_)(?:CONF|CFG|CONFIG|FILE|INI|RC|CONFFILE|CONFIGFILE)$")


# --- static discovery ------------------------------------------------------------------------------

def _elf64_x86(data) -> bool:
    return (len(data) > 0x40 and bytes(data[:4]) == b"\x7fELF" and data[4] == 2 and data[5] == 1
            and struct.unpack_from("<H", data, 0x12)[0] == 62)


def _sections(data):
    from . import elf as _elf
    try:
        return _elf._raw_sections(data, True, "<")
    except Exception:                                    # noqa: BLE001 -- malformed: no sites
        return []


def _cstr_at(data, secs, va: int, cap: int = 256) -> Optional[str]:
    """The NUL-terminated printable string at virtual address `va`, or None."""
    for s in secs:
        if s["type"] in (0, 8) or not s["addr"]:             # NULL / NOBITS: nothing on disk
            continue
        if s["addr"] <= va < s["addr"] + s["size"]:
            off = s["offset"] + (va - s["addr"])
            raw = bytes(data[off:off + cap])
            end = raw.find(b"\x00")
            if end <= 0:
                return None
            raw = raw[:end]
            if all(0x20 <= c < 0x7F for c in raw):
                return raw.decode("ascii")
            return None
    return None


def _got_names(data, secs) -> dict:
    """{GOT slot VA: imported symbol} from the JUMP_SLOT / GLOB_DAT dynamic relocations."""
    out: dict = {}
    for rs in secs:
        if rs["type"] != 4 or rs["entsize"] < 24 or rs["link"] >= len(secs):  # SHT_RELA
            continue
        symtab = secs[rs["link"]]
        if symtab["type"] != 11 or symtab["link"] >= len(secs):            # SHT_DYNSYM
            continue
        strtab = secs[symtab["link"]]
        n = rs["size"] // rs["entsize"]
        for k in range(min(n, 200000)):
            o = rs["offset"] + k * rs["entsize"]
            if o + 24 > len(data):
                break
            r_off, r_info, _add = struct.unpack_from("<QQq", data, o)
            if (r_info & 0xFFFFFFFF) not in (6, 7):                       # GLOB_DAT, JUMP_SLOT
                continue
            so = symtab["offset"] + (r_info >> 32) * 24
            if so + 24 > len(data):
                continue
            st_name = struct.unpack_from("<I", data, so)[0]
            no = strtab["offset"] + st_name
            end = data.find(b"\x00", no)
            if end < 0:
                continue
            nm = bytes(data[no:end]).decode("ascii", "replace").split("@")[0]
            if nm in _NEED_CALLS:
                out[r_off] = nm
    return out


_ARG_REG = {0: 7, 1: 6, 2: 2}            # SysV: rdi, rsi, rdx


def _reg_value(code: bytes, base_va: int, end: int, reg: int, hops: int = 1):
    """The constant ADDRESS register `reg` holds just before code offset `end` -- the closest
    `lea reg,[rip+d]`, `mov reg32,imm32`, `mov reg64,imm32` setter, following one `mov reg,reg`
    hop (the -O0 `lea rax,str; mov rdi,rax`). Any other recognised write to `reg` in between
    (a load from memory, xor) makes it unknown. None when not recoverable."""
    lo = max(0, end - 96)
    best = None                                   # (insn_end, kind, value)
    for i in range(lo, end):
        b0 = code[i]
        # lea r64,[rip+disp32]: REX.W(+R) 8D modrm(mod=00,rm=101)
        if b0 in (0x48, 0x4C) and i + 7 <= end and code[i + 1] == 0x8D \
                and (code[i + 2] & 0xC7) == 0x05:
            r = ((code[i + 2] >> 3) & 7) | (8 if b0 == 0x4C else 0)
            if r == reg:
                d = struct.unpack_from("<i", code, i + 3)[0]
                cand = (i + 7, "addr", base_va + i + 7 + d)
                if best is None or cand[0] >= best[0]:
                    best = cand
        # mov r32, imm32 (B8+r) -- the non-PIE `mov edi, 0x402004`
        if reg < 8 and b0 == 0xB8 + reg and i + 5 <= end:
            cand = (i + 5, "addr", struct.unpack_from("<I", code, i + 1)[0])
            if best is None or cand[0] >= best[0]:
                best = cand
        # mov r/m64, imm32: 48 C7 C0+r
        if reg < 8 and b0 == 0x48 and i + 7 <= end and code[i + 1] == 0xC7 \
                and code[i + 2] == 0xC0 + reg:
            cand = (i + 7, "addr", struct.unpack_from("<I", code, i + 3)[0])
            if best is None or cand[0] >= best[0]:
                best = cand
        # mov r64, r64 / load: 48 89 /r (dst = rm) or 48 8B /r (dst = reg)
        if b0 in (0x48, 0x49, 0x4C, 0x4D) and i + 3 <= end and code[i + 1] in (0x89, 0x8B):
            m = code[i + 2]
            rex_r, rex_b = bool(b0 & 4), bool(b0 & 1)
            mreg = ((m >> 3) & 7) | (8 if rex_r else 0)
            mrm = (m & 7) | (8 if rex_b else 0)
            if (m >> 6) == 3:
                dst, src = (mrm, mreg) if code[i + 1] == 0x89 else (mreg, mrm)
                if dst == reg:
                    cand = (i + 3, "reg", src)
                    if best is None or cand[0] >= best[0]:
                        best = cand
            elif code[i + 1] == 0x8B and mreg == reg:
                cand = (i + 3, "unknown", None)           # a load from memory: not a literal
                if best is None or cand[0] >= best[0]:
                    best = cand
    if best is None or best[1] == "unknown":
        return None
    if best[1] == "reg":
        if hops <= 0:
            return None
        return _reg_value(code, base_va, best[0] - 3, best[2], hops - 1)
    return best[2]


_CALL_OP = re.compile(rb"\xe8|\xff\x15")


def callsite_args(data, *, budget_s: float = 30.0) -> list:
    """[{func, kind, value, site}] for every call to a `_NEED_CALLS` import whose path/name
    argument is a string literal. x86-64 ELF only (PLT stubs, `.plt.sec`, and `-fno-plt`
    `call [rip+GOT]`); [] for anything else, which then falls back to strings."""
    if not _elf64_x86(data):
        return []
    secs = _sections(data)
    if not secs:
        return []
    got = _got_names(data, secs)
    if not got:
        return []
    execs = [s for s in secs if s["type"] == 1 and (s["flags"] & 0x4) and s["size"]]
    stubs: dict = {}
    for s in execs:
        seg = bytes(data[s["offset"]:s["offset"] + s["size"]])
        k = seg.find(b"\xff\x25")
        while k >= 0:
            if k + 6 <= len(seg):
                tgt = s["addr"] + k + 6 + struct.unpack_from("<i", seg, k + 2)[0]
                nm = got.get(tgt)
                if nm:
                    stubs[s["addr"] + k] = nm
                    j = k
                    if j >= 1 and seg[j - 1] == 0xF2:                 # bnd prefix
                        j -= 1
                        stubs[s["addr"] + j] = nm
                    if j >= 4 and seg[j - 4:j] == b"\xf3\x0f\x1e\xfa":  # endbr64
                        stubs[s["addr"] + j - 4] = nm
            k = seg.find(b"\xff\x25", k + 1)
    out, seen = [], set()
    deadline = time.monotonic() + budget_s
    for s in execs:
        if s["name"] in (".plt", ".plt.sec", ".plt.got"):
            continue
        seg = bytes(data[s["offset"]:s["offset"] + s["size"]])
        lim = len(seg) - 5
        # candidate call opcodes found at C speed; a 100 MB .text has ~1/256 of its bytes as E8
        for mt in _CALL_OP.finditer(seg):
            i = mt.start()
            if i >= lim or time.monotonic() > deadline:
                break
            nm = None
            if seg[i] == 0xE8:
                tgt = s["addr"] + i + 5 + struct.unpack_from("<i", seg, i + 1)[0]
                nm = stubs.get(tgt)
                end = i
            elif seg[i] == 0xFF and seg[i + 1] == 0x15 and i + 6 <= len(seg):
                tgt = s["addr"] + i + 6 + struct.unpack_from("<i", seg, i + 2)[0]
                nm = got.get(tgt)
                end = i
            if not nm:
                continue
            argi, kind = _NEED_CALLS[nm]
            va = _reg_value(seg, s["addr"], end, _ARG_REG[argi])
            if va is None:
                continue
            v = _cstr_at(data, secs, va)
            if not v:
                continue
            mode = None
            if nm in ("fopen", "fopen64", "freopen"):
                mva = _reg_value(seg, s["addr"], end, 6)
                mode = _cstr_at(data, secs, mva) if mva is not None else None
                if mode and mode[:1] in ("w", "a"):
                    kind = "parent"                    # it creates the file: needs the dir
            key = (nm, v)
            if key in seen:
                continue
            seen.add(key)
            out.append({"func": nm, "kind": kind, "value": v, "site": hex(s["addr"] + i),
                        "mode": mode})
    return out


def symbol_names(data) -> set:
    """Every name in the ELF's .dynstr/.strtab -- function and object names, which a raw string
    scan also returns and which are never config keys (`getenv`, `deregister_tm_clones`)."""
    if not (len(data) > 0x40 and bytes(data[:4]) == b"\x7fELF"):
        return set()
    try:
        from . import elf as _elf
        is64 = data[4] == 2
        endc = "<" if data[5] == 1 else ">"
        secs = _elf._raw_sections(data, is64, endc)
    except Exception:                                    # noqa: BLE001
        return set()
    out: set = set()
    for s in secs:
        if s["type"] == 3 and s["name"] in (".dynstr", ".strtab") and s["size"] < (64 << 20):
            blob = bytes(data[s["offset"]:s["offset"] + s["size"]])
            out.update(x.decode("ascii", "replace").split("@")[0]
                       for x in blob.split(b"\x00") if x)
    return out


_PATH_SHAPE = re.compile(r"^(?:/|\./)?[A-Za-z0-9_.+@~-]+(?:/[A-Za-z0-9_.+@~-]+)*/?$")
_SOURCE_FILE = re.compile(r"(?i)\.(?:c|h|cc|cpp|cxx|hpp|hh|rs|go|py|s|asm|m|java)$")


def _pathish(v: str) -> bool:
    """A literal that is plausibly a filesystem path the program needs: path characters only,
    not the root/dot, not a source-file name (`__FILE__` strings reach assert/log calls), and not
    escaping the working directory."""
    return bool(len(v) >= 2 and v not in ("/", ".", "..") and _PATH_SHAPE.match(v)
                and not _SOURCE_FILE.search(v) and not v.startswith("..")
                and not _SYSTEM_PATH.search(v))


def _good_key(k: str, syms=()) -> bool:
    """A config key worth writing: not a symbol name, not a source/library file name, and
    shaped like an identifier (`listen`, `max_conn`) rather than a code-byte run (`TIB`)."""
    return bool(k not in syms and not re.search(r"\.(?:c|h|so|o|a|cc|cpp)(?:\.|$)", k)
                and (re.match(r"^[a-z][a-z0-9_.-]{2,30}$", k) or "_" in k))


def _imports_getenv(data) -> bool:
    return any(data.find(n) >= 0 for n in (b"getenv\x00", b"secure_getenv\x00"))


def _string_values(strings) -> list:
    return [getattr(s, "value", s) for s in (strings or ()) if getattr(s, "value", s)]


def discover(data, strings=None) -> dict:
    """Static runtime needs: {"env": [...], "paths": [...], "config": {keys, sections, sep},
    "sources": [...]}. Each env/path entry carries its `source` (call-site / strings) and the
    calling function, so the operator can see why it was considered."""
    from . import invocation as invmod
    from .fuzz import textconf
    vals = _string_values(strings) if strings is not None else \
        [x.value for x in invmod.string_rows(invmod.raw_strings(bytes(data[:64 << 20])))]
    sites = callsite_args(data)
    syms = symbol_names(data)
    env: list = []
    paths: list = []
    sources: list = []
    seen_env, seen_path = set(), set()
    for c in sites:
        v = c["value"]
        if c["kind"] == "env":
            if v not in seen_env and not _ENV_NEVER.match(v) and re.match(r"^[A-Za-z_]\w{0,63}$", v):
                seen_env.add(v)
                env.append({"name": v, "source": "call-site", "via": c["func"], "site": c["site"]})
        elif v not in seen_path and _pathish(v):
            seen_path.add(v)
            paths.append({"path": v, "kind": c["kind"], "source": "call-site", "via": c["func"],
                          "site": c["site"], "mode": c.get("mode")})
    if sites:
        sources.append("call-site")
    # Strings fallback: only where call-site recovery could not speak (not x86-64, a static
    # binary with no PLT). Weaker evidence, so every one of these still has to survive the
    # dynamic confirmation before it is supplied.
    if not sites:
        if _imports_getenv(data):
            for v in vals:
                t = (v or "").strip()
                if _ENV_SHAPE.match(t) and not _ENV_NEVER.match(t) and t not in seen_env \
                        and len(seen_env) < 16:
                    seen_env.add(t)
                    env.append({"name": t, "source": "strings", "via": "getenv"})
        for v in vals:
            t = (v or "").strip()
            if len(seen_path) >= 24:
                break
            if t in seen_path or not _pathish(t):
                continue
            if _ABS_PATH.match(t) or (_REL_PATH.match(t) and "/" in t.rstrip("/")) \
                    or (_REL_PATH.match(t) and _CONF_EXT.search(t)):
                seen_path.add(t)
                kind = "dir" if t.endswith("/") or not re.search(r"\.[A-Za-z0-9]{1,8}$", t) \
                    else "file"
                paths.append({"path": t, "kind": kind, "source": "strings", "via": None})
        if env or paths:
            sources.append("strings")
    return {"env": env, "paths": paths, "sources": sources,
            "config": {"keys": [k for k in textconf.keys_from(
                           [v for v in vals if v not in syms], limit=48)
                           if _good_key(k, syms)][:24],
                       "sections": textconf.sections_from(vals),
                       "sep": textconf.separator_from(vals)},
            "strings": vals, "symbols": syms}


# --- the dynamic tracer ----------------------------------------------------------------------------

#: strace / qemu -strace line: `openat(AT_FDCWD, "/etc/x", O_RDONLY) = -1 ENOENT (...)`
#: (qemu: `123 openat(AT_FDCWD,"/etc/x",O_RDONLY) = -1 errno=2 (No such file or directory)`)
_TRACE_LINE = re.compile(
    r"\b(open|openat|openat2|open64|creat|access|faccessat|faccessat2|stat|stat64|lstat|"
    r"lstat64|newfstatat|fstatat64|statx|chdir|mkdir|mkdirat|readlink|readlinkat|execve)\("
    r"(?:AT_FDCWD|-?\d+|0x[0-9a-f]+)?,?\s*\"([^\"]*)\"(.*)$")
_ENOENT = re.compile(r"=\s*-1\s+(?:ENOENT|errno=2\b)")
_DENIED = re.compile(r"=\s*-1\s+(?:EROFS|EACCES|EPERM|errno=(?:30|13|1)\b)")
_CREATING = re.compile(r"O_CREAT|O_WRONLY|O_RDWR")


class _Resolved:
    """A trace match whose path group is replaced by its chdir-resolved absolute form."""

    def __init__(self, m, path):
        self._m, self._p = m, path

    def group(self, i):
        return self._p if i == 2 else self._m.group(i)


def parse_trace(text: str) -> dict:
    """{"enoent": [(syscall, path, flags)], "calls": n} from strace/qemu -strace output. Only
    syscalls that NAME a path; the count is every traced line (a coarse "how far it got")."""
    enoent, denied, n = [], [], 0
    cwd = None                     # where a RELATIVE path resolves, once the target chdir()s
    for line in (text or "").splitlines():
        m = _TRACE_LINE.search(line)
        if not m:
            continue
        n += 1
        if m.group(1) == "execve":
            continue
        if m.group(1) == "chdir" and re.search(r"=\s*0\s*$", m.group(3)):
            d = m.group(2)
            cwd = d if d.startswith("/") else (os.path.normpath(os.path.join(cwd, d))
                                               if cwd else None)
            continue
        if cwd and not m.group(2).startswith("/"):
            # a relative path after a chdir is relative to THAT dir, not to the sandbox cwd
            m = _Resolved(m, os.path.normpath(os.path.join(cwd, m.group(2))))
        if _ENOENT.search(m.group(3)):
            enoent.append((m.group(1), m.group(2), m.group(3)))
        elif _DENIED.search(m.group(3)) and (m.group(1) in ("mkdir", "mkdirat", "creat")
                                             or _CREATING.search(m.group(3))):
            # it tried to CREATE/WRITE here and the sandbox's read-only root refused: what it
            # needs is a writable directory (a pid/lock/socket/log/spool dir)
            denied.append((m.group(1), m.group(2), m.group(3)))
    return {"enoent": enoent, "denied": denied, "calls": n}


def _strace() -> Optional[str]:
    return shutil.which("strace")


# --- the staged environment ------------------------------------------------------------------------

@dataclass
class RuntimeEnv:
    """What is supplied to the target: env vars, files (staged src -> in-sandbox dst), dirs, and
    the overlays that make a read-only system dir able to gain them. `supplied` is the
    operator-facing record (what, where, why); `degraded` what could not be supplied and why."""
    root: str = ""
    env: dict = field(default_factory=dict)
    files: list = field(default_factory=list)          # [(host src, sandbox dst)]
    dirs: list = field(default_factory=list)           # [sandbox dst]
    overlays: list = field(default_factory=list)       # [system dir to tmp-overlay]
    tmpfs: list = field(default_factory=list)          # [runtime dir replaced by a fresh tmpfs]
    rel_files: list = field(default_factory=list)      # [(host src, cwd-relative path)]
    rel_dirs: list = field(default_factory=list)       # [cwd-relative path]
    supplied: list = field(default_factory=list)
    degraded: list = field(default_factory=list)
    applied: bool = False
    note: str = ""
    baseline: dict = field(default_factory=dict)
    result: dict = field(default_factory=dict)
    runs: int = 0
    traced: bool = False
    #: the baseline stopped at a missing-resource gate (whether or not it could be opened)
    gated: bool = False

    def bwrap_args(self, *, cwd: str = "/tmp") -> list:
        """bwrap arguments that expose this environment inside the sandbox. Goes AFTER the
        base `--ro-bind / /` / `--tmpfs /tmp` and the exedir bind, BEFORE the `--`. `cwd` is
        the sandbox's working directory (the base args chdir to /tmp) -- relative paths land
        there."""
        if not self.applied:
            return []
        a: list = []
        for t in self.tmpfs:
            a += ["--tmpfs", t]
        for o in self.overlays:
            a += ["--overlay-src", o, "--tmp-overlay", o]
        for d in self.dirs:
            a += ["--dir", d]
        for src, dst in self.files:
            a += ["--ro-bind", src, dst]
        for rel in self.rel_dirs:
            a += ["--dir", os.path.join(cwd, rel)]
        for src, rel in self.rel_files:
            a += ["--ro-bind", src, os.path.join(cwd, rel)]
        return a

    def populate_cwd(self, d) -> None:
        """Copy the cwd-relative part into `d` -- for an UNWRAPPED (rlimits-only) run, whose cwd
        is a throwaway dir. Absolute paths are never written to the host (see `degraded`)."""
        if not self.applied:
            return
        for rel in self.rel_dirs:
            os.makedirs(os.path.join(d, rel), exist_ok=True)
        for src, rel in self.rel_files:
            dst = os.path.join(d, rel)
            os.makedirs(os.path.dirname(dst) or d, exist_ok=True)
            shutil.copyfile(src, dst)

    def summary(self) -> dict:
        """The operator-facing record: exactly what was supplied and what could not be."""
        return {"applied": self.applied, "note": self.note, "supplied": list(self.supplied),
                "degraded": list(self.degraded), "env": dict(self.env) if self.applied else {},
                "runs": self.runs, "traced": self.traced, "baseline": dict(self.baseline),
                "result": dict(self.result), "gated": bool(self.gated or self.applied)}


# --- sandbox capability probes ---------------------------------------------------------------------

_overlay_cache: Optional[bool] = None


def overlay_usable() -> bool:
    """Can bwrap put a throwaway writable overlay on a system dir here? (bwrap >= 0.8 and a
    kernel that allows overlayfs in a user namespace.) Probed once."""
    global _overlay_cache
    if _overlay_cache is not None:
        return _overlay_cache
    from .dynamic import sandbox
    ok = False
    if sandbox._bwrap_usable():
        try:
            r = subprocess.run(["bwrap", "--ro-bind", "/", "/", "--unshare-net", "--dev", "/dev",
                                "--overlay-src", "/etc", "--tmp-overlay", "/etc",
                                "--dir", "/etc/.lykos-overlay-probe", "--", "true"],
                               capture_output=True, timeout=10)
            ok = r.returncode == 0
        except Exception:                                # noqa: BLE001
            ok = False
    _overlay_cache = ok
    return ok


_root_cache: dict = {}


def overlay_ok(root: str) -> bool:
    """Can THIS directory be tmp-overlaid? (/run on many hosts cannot: overlayfs refuses a
    lower that is itself a tmpfs with submounts.) Probed once per directory."""
    if root in _root_cache:
        return _root_cache[root]
    ok = False
    if overlay_usable():
        try:
            r = subprocess.run(["bwrap", "--ro-bind", "/", "/", "--unshare-net", "--dev", "/dev",
                                "--overlay-src", root, "--tmp-overlay", root, "--", "true"],
                               capture_output=True, timeout=10)
            ok = r.returncode == 0
        except Exception:                                # noqa: BLE001
            ok = False
    _root_cache[root] = ok
    return ok


_FORBIDDEN_ROOTS = ("/", "/proc", "/dev", "/sys", "/tmp", "/home", "/root", "/run/user", "/boot")


def _canon(path: str) -> str:
    """`path` with its existing part resolved through symlinks (/var/run/x -> /run/x): bwrap
    creates mount points by walking the NEW root, where an absolute symlink is not the host's,
    so every staged destination is given in canonical form."""
    path = os.path.normpath(path)
    head, tail = path, []
    while head and head != "/" and not os.path.lexists(head):
        head, t = os.path.split(head)
        tail.insert(0, t)
    try:
        head = os.path.realpath(head)
    except OSError:
        return path
    return os.path.join(head, *tail) if tail else head


def _overlay_root(dst: str, protected, *, itself: bool = False) -> tuple:
    """(overlay dir or None, reason). The nearest EXISTING ancestor of `dst` -- the read-only dir
    that has to gain an entry. Refused when it is the root, a kernel/sandbox-owned mount, or an
    ancestor of something the sandbox masks (an overlay would re-expose the host's copy) or of
    the staged executable."""
    p = os.path.normpath(dst) if itself else os.path.dirname(os.path.normpath(dst))
    while p and p != "/" and not os.path.isdir(p):
        p = os.path.dirname(p)
    if p == "/tmp" or p.startswith("/tmp/"):
        return None, "tmpfs"                             # writable already: no overlay needed
    if not p or p in _FORBIDDEN_ROOTS or p.startswith(("/home/", "/root/", "/proc/", "/sys/",
                                                       "/dev/", "/run/user/")):
        return None, f"would need an overlay on {p or '/'}, which the sandbox does not allow"
    for q in protected:
        q = os.path.normpath(str(q))
        if q == p or q.startswith(p.rstrip("/") + "/"):
            return None, f"an overlay on {p} would re-expose the protected {q}"
    return p, ""


# --- probe runs ------------------------------------------------------------------------------------

@dataclass
class _Probe:
    rc: Optional[int] = None
    crashed: bool = False
    timed_out: bool = False
    out: str = ""
    trace: Optional[dict] = None
    ms: int = 0
    failed: bool = False                                 # could not run at all

    def sig(self) -> tuple:
        first = next((ln.strip() for ln in self.out.splitlines() if ln.strip()), "")
        first = re.sub(r"\d+", "#", first)[:160]
        return (self.crashed, self.timed_out, None if self.timed_out else self.rc, first)

    def view(self) -> dict:
        return {"rc": self.rc, "crashed": self.crashed, "timed_out": self.timed_out,
                "says": next((ln.strip() for ln in self.out.splitlines() if ln.strip()),
                             "")[:200],
                "traced_calls": (self.trace or {}).get("calls")}


def _run_probe(exe: str, argv: list, renv: Optional[RuntimeEnv], *, timeout: float, arch=None,
               endianness=None, bits=None, trace: bool = True,
               sample_dir: Optional[str] = None) -> _Probe:
    """One contained run of `exe` with `renv` supplied (None = baseline), optionally traced."""
    from .dynamic import sandbox
    exe = str(Path(exe).resolve())
    exedir = os.path.dirname(exe)
    host = sandbox.host_arch()
    emu = None
    if arch and host and arch != host:
        emu = sandbox._qemu_for(arch, endianness, bits)
        if not emu:
            return _Probe(failed=True, out=f"no qemu-user for {arch}")
    logdir = tempfile.mkdtemp(prefix="lykos-renv-log-")
    log = os.path.join(logdir, "trace.log")
    env = {k: v for k, v in os.environ.items()}
    traced = False
    if emu:
        inner = [emu] + (["-strace", "-D", log] if trace else []) + [exe] + list(argv)
        traced = trace
        sr = sandbox.qemu_ld_prefix(arch, endianness, bits, exedir=exedir)
        if sr:
            env.setdefault("QEMU_LD_PREFIX", sr)
    elif trace and _strace():
        inner = [_strace(), "-f", "-qq", "-o", log, "-e", "trace=%file,chdir", exe] + list(argv)
        traced = True
    else:
        inner = [exe] + list(argv)
    if renv is not None and renv.applied:
        env.update(renv.env)
    rel = sandbox._relative_interp(exe)
    ro = [renv.root] if (renv is not None and renv.root and os.path.isdir(renv.root)
                         and not renv.root.startswith(exedir + "/")) else []
    if sample_dir and os.path.isdir(sample_dir) and not sample_dir.startswith(exedir + "/"):
        ro.append(sample_dir)
    prefix = sandbox.isolate_prefix(exedir, net=False, ro_binds=ro,
                                    rw_binds=[logdir] + ([exedir] if rel else []),
                                    chdir=(exedir if rel else ""))
    cwd = None
    tmp_cwd = None
    if prefix:
        cut = prefix.index("--")
        extra = renv.bwrap_args(cwd=(exedir if rel else "/tmp")) if renv is not None else []
        cmd = prefix[:cut] + extra + prefix[cut:] + inner
    else:
        cmd = inner
        tmp_cwd = cwd = exedir if rel else tempfile.mkdtemp(prefix="lykos-renv-cwd-")
        if renv is not None:
            renv.populate_cwd(cwd)
    san = emu is None and sandbox._is_sanitizer_exe(exe)
    preexec = sandbox._rlimits(1024, int(timeout) + 2, set_as=(emu is None and not san
                                                                 and not traced),
                               nproc=sandbox._nproc_cap(emu is not None or san))
    t0 = time.time()
    p = _Probe()
    try:
        try:
            r = sandbox.run_reaped(cmd, timeout=timeout, capture_output=True, env=env,
                                   preexec_fn=preexec, **({"cwd": cwd} if cwd else {}))
            rc, out, err = r.returncode, r.stdout or b"", r.stderr or b""
        except subprocess.TimeoutExpired as e:
            p.timed_out = True
            rc, out, err = None, e.output or b"", e.stderr or b""
        except Exception as e:                           # noqa: BLE001
            return _Probe(failed=True, out=f"probe could not run: {e}")
        p.ms = int((time.time() - t0) * 1000)
        if rc is not None:
            crashed, _sig, _name, code = sandbox.classify_rc(rc)
            p.crashed, p.rc = bool(crashed), code
            if not crashed and sandbox._exec_failed(rc, err):
                p.failed = True
        p.out = (out + err).decode("utf-8", "replace")[:8192]
        if prefix and err.startswith(b"bwrap:"):
            p.failed = True                              # the SANDBOX refused (e.g. an overlay)
        if traced:
            try:
                p.trace = parse_trace(Path(log).read_text("utf-8", "replace"))
            except OSError:
                p.trace = None
        return p
    finally:
        shutil.rmtree(logdir, ignore_errors=True)
        if tmp_cwd and not rel:
            shutil.rmtree(tmp_cwd, ignore_errors=True)


def _complaint(out: str) -> Optional[str]:
    """The first output line that says a resource is missing, digits normalised."""
    lines = [ln for ln in (out or "").splitlines() if ln.strip()][:6]
    for ln in lines:
        # a help/usage table row ("   backfill   Download missing objects") is documentation,
        # not the program complaining -- only a flush-left line is a diagnostic
        if ln[:1].isspace() or re.match(r"(?i)\s*usage\b", ln):
            continue
        if _MISSING.search(ln):
            return re.sub(r"\d+", "#", ln.strip())[:200]
    return None


def _gated(b: _Probe, *, enoent=(), absent=(), env_names=()) -> bool:
    """Is the baseline an early exit ON A MISSING RESOURCE -- the gate this module can open?

    A clean exit, a run that stays up or crashes, is a target that already runs. A non-zero
    exit alone is not enough: a target refusing its ARGV (a usage line) is not missing anything
    from its environment, and feeding it twenty env vars until its output changes would be
    "progress" of the wrong kind. So the baseline must also show the gate: a missing-resource
    complaint, a traced ENOENT on a path the binary names, a complaint naming one of the env
    vars it reads, or -- untraced -- a silent non-zero exit with a literal path it opens that
    does not exist."""
    if b.failed or b.crashed or b.timed_out or (b.rc or 0) == 0:
        # it ran -- a clean exit is a target that works today, even one that WARNED it fell
        # back to defaults; supplying it a config would change a run that already succeeds
        return False
    if _complaint(b.out) or enoent:
        return True
    if any(n in b.out for n in env_names):
        return True
    return b.trace is None and bool(absent) and not b.out.strip()


def _progressed(b: _Probe, c: _Probe) -> bool:
    """Did run `c` get further than baseline `b`? Not merely different: a usage refusal, a run
    that could not start, or the same early exit is not progress."""
    if c.failed:
        return False
    if c.sig() == b.sig():
        return False
    if c.crashed or c.timed_out:
        return True
    if (b.rc or 0) != 0 and (c.rc or 0) == 0:
        return True
    bc = _complaint(b.out)
    if bc is not None:
        # a different early exit counts only if the baseline's own complaint is gone
        return bc not in {_complaint(ln) for ln in c.out.splitlines()}
    # a silent gate: progress is the target doing MORE (traced) or saying something new
    if b.trace and c.trace:
        return c.trace["calls"] > b.trace["calls"]
    return bool(c.out.strip()) and not b.out.strip()


# --- synthesis -------------------------------------------------------------------------------------

def _evidence_ok(path: str, vals_set: set, basenames: set) -> bool:
    """A traced ENOENT is a need of THIS program (not the loader's/libc's) only when the binary
    names the path, its file name, or its directory."""
    if _SYSTEM_PATH.search(path):
        return False
    if path in vals_set:
        return True
    base = os.path.basename(path.rstrip("/"))
    parent = os.path.dirname(path.rstrip("/"))
    return bool((base and base in basenames) or (parent and len(parent) > 5 and parent in vals_set))


#: A runtime artefact the program creates itself -- never synthesized with content.
_RUNTIME_FILE = re.compile(r"(?i)\.(?:pid|lock|lck|sock|socket|ctl)$")


def _trace_kind(sc: str, flags: str, path: str = "") -> str:
    """What a traced ENOENT asks for: a dir (chdir / O_DIRECTORY), the parent of a path it
    creates (mkdir / creat / O_CREAT), a file it reads, or an existence probe."""
    if sc == "chdir" or "O_DIRECTORY" in flags:
        return "dir"
    if sc in ("mkdir", "mkdirat", "creat") or "O_CREAT" in flags:
        return "parent"
    if _RUNTIME_FILE.search(path):
        return "parent"              # probing its own pid/lock/socket: it will CREATE it next
    return "file" if sc in ("open", "openat", "openat2", "open64") else "exists"


def _item_key(it: dict) -> str:
    return it.get("name") or it.get("path")


class _Stager:
    """Builds a RuntimeEnv for a chosen item set, under `root`."""

    def __init__(self, root: Path, needs: dict, exe: str):
        from .dynamic import sandbox
        self.root = root
        self.needs = needs
        self.exe = exe
        self.bwrap = sandbox._bwrap_usable()
        self.overlay = self.bwrap and overlay_usable()
        self.protected = ([str(Path(exe).resolve().parent), os.path.expanduser("~"), "/root"]
                          + list(getattr(sandbox, "_EXTRA_PROTECTED", ())))
        self.conf_dir = root / "files"
        self.conf_dir.mkdir(parents=True, exist_ok=True)
        self.bodies: dict = {}                           # path -> the content it is given
        self.syms = needs.get("symbols") or set()

    def _stage_file(self, path: str) -> str:
        from .fuzz import textconf
        h = hashlib.sha1(path.encode()).hexdigest()[:10]
        src = self.conf_dir / f"{h}-{os.path.basename(path.rstrip('/')) or 'file'}"
        if path in self.bodies:
            src.write_bytes(self.bodies[path])
            return str(src)
        cfg = self.needs.get("config") or {}
        vals = self.needs.get("strings") or []
        if _CONF_EXT.search(path) or not re.search(r"\.[A-Za-z0-9]{1,8}$", path):
            # keys NEAR the path first: a parser's key literals sit beside its file name in
            # .rodata, while the whole-binary list is diluted by every other subsystem's words
            keys = None
            for i, v in enumerate(vals):
                if v == path or (os.path.basename(path) and v.endswith(os.path.basename(path))):
                    near = [k for k in textconf.keys_from(vals[max(0, i - 60):i + 60], limit=24)
                            if _good_key(k, self.syms)][:12]
                    if len(near) >= 2:
                        keys = near
                    break
            body = textconf.plausible_config(path, vals,
                                             keys=keys if keys is not None else cfg.get("keys"),
                                             dir_value="/tmp", file_value="/dev/null")
        else:
            body = b"lykos\n"
        self.bodies[path] = body
        src.write_bytes(body)
        return str(src)

    def repair(self, out: str) -> bool:
        """The target rejected a LINE of a synthesized config ("bad option at line 3 of
        /etc/app.conf"): drop that line, so the next run gets past it. False when the complaint
        does not point at exactly one of our files and one of its key lines."""
        m = _LINE_ERR.search(out or "")
        if not m:
            return False
        named = [p for p in self.bodies if p in out] or \
            [p for p in self.bodies if os.path.basename(p) and os.path.basename(p) in out]
        if len(named) != 1:
            return False
        lines = self.bodies[named[0]].split(b"\n")
        n = int(m.group(1) or m.group(2))
        if not (1 <= n <= len(lines)) or lines[n - 1].startswith(b"#") or not lines[n - 1].strip():
            return False
        # keep the line count (so later line numbers still match): blank it, comment it out
        lines[n - 1] = b"# " + lines[n - 1]
        self.bodies[named[0]] = b"\n".join(lines)
        return True

    def build(self, items: list) -> RuntimeEnv:
        renv = RuntimeEnv(root=str(self.root), applied=True)
        overlays: list = []
        for it in items:
            if "name" in it:                                         # env var
                val = it["value"]
                for extra in it.get("stage", ()):                    # a path the value names
                    if self.bwrap:
                        self._place(renv, extra, overlays, record=False)
                    else:
                        # unwrapped: the target sees the host fs, so point the variable at a
                        # real path under the scratch root instead of a sandbox-only one
                        hp = self.root / "envstage" / os.path.basename(extra["path"])
                        hp.parent.mkdir(parents=True, exist_ok=True)
                        if extra["kind"] == "dir":
                            hp.mkdir(exist_ok=True)
                        else:
                            hp.write_bytes(Path(self._stage_file(extra["path"])).read_bytes())
                        val = str(hp)
                renv.env[it["name"]] = val
                renv.supplied.append({"kind": "env", "name": it["name"], "value": val,
                                      "source": it.get("source"), "why": it.get("why", "")})
                continue
            self._place(renv, it, overlays)
        # outermost overlays only (an overlay nested in another is already writable)
        ov = sorted({o for o in overlays
                     if not any(o == t or o.startswith(t + "/") for t in renv.tmpfs)}, key=len)
        renv.overlays = [o for o in ov if not any(o != p and o.startswith(p.rstrip("/") + "/")
                                                  for p in ov)]
        return renv

    def _place(self, renv: RuntimeEnv, it: dict, overlays: list, record: bool = True) -> None:
        path, kind = it["path"], it["kind"]
        want_dir = kind in ("dir", "parent", "writable")
        target = os.path.dirname(path.rstrip("/")) if kind == "parent" else path.rstrip("/")
        if not target:
            return
        label = "writable-dir" if kind == "writable" else "dir" if want_dir else "file"
        if not target.startswith("/"):                               # cwd-relative
            rel = os.path.normpath(target)
            if rel.startswith(".."):
                renv.degraded.append({"path": path, "why": "relative path escapes the cwd"})
                return
            if want_dir:
                renv.rel_dirs.append(rel)
            else:
                src = it.get("src") or self._stage_file(path)
                renv.rel_files.append((src, rel))
            if record:
                renv.supplied.append({"kind": label, "path": path,
                                      "at": f"<cwd>/{rel}", "source": it.get("source"),
                                      "why": it.get("why", ""),
                                      **({"content": _peek(renv.rel_files[-1][0])}
                                         if not want_dir else {})})
            return
        if not self.bwrap:
            renv.degraded.append({"path": path, "why": (
                "no bubblewrap here: an absolute path can only be supplied inside the sandbox, "
                "and writing the host's real path is not allowed")})
            return
        target = _canon(target)
        exists = kind == "writable" and os.path.isdir(target)
        root, why = _overlay_root(target, self.protected, itself=exists)
        if root is None and why != "tmpfs":
            renv.degraded.append({"path": path, "why": why})
            return
        if root is not None and not overlay_ok(root):
            if root == "/run" or root.startswith("/run/"):
                # /run holds only RUNTIME state (it is an empty tmpfs at every boot) and on many
                # hosts cannot be overlaid; a daemon's runtime dir goes in a fresh /run instead.
                # It also hides the host's live sockets from the target, which costs it nothing.
                if "/run" not in renv.tmpfs:
                    renv.tmpfs.append("/run")
                root, exists = None, False
            else:
                renv.degraded.append({"path": path, "why": (
                    f"{root} is read-only in the sandbox and this bwrap/kernel cannot overlay it")})
                return
        if root is not None:
            overlays.append(root)
        elif exists:
            return                                       # under /tmp: writable already
        if want_dir:
            if not exists:
                renv.dirs.append(target)
            at = target
        else:
            src = it.get("src") or self._stage_file(path)
            renv.files.append((src, target))
            at = target
        if record:
            rec = {"kind": label, "path": path if kind in ("dir", "file") else target,
                   "at": at, **({"for": path} if kind == "parent" else {}),
                   "source": it.get("source"), "why": it.get("why", "")}
            if not want_dir:
                rec["content"] = _peek(renv.files[-1][0])
            renv.supplied.append(rec)


def _peek(src: str, cap: int = 240) -> str:
    try:
        return Path(src).read_bytes()[:cap].decode("utf-8", "replace")
    except OSError:
        return ""


def _env_item(e: dict, root: Path) -> dict:
    """An env var with a value shaped by its name: a directory var gets a (sandbox-created)
    directory, a config var a synthesized config file, a port a port..."""
    from .fuzz import textconf
    name = e["name"]
    it = dict(e)
    if _FILEISH_ENV.search(name):
        dst = f"/tmp/lykos-env/{name.lower()}.conf"
        it["value"] = dst
        it["stage"] = [{"path": dst, "kind": "file", "source": "env-value"}]
    elif _DIRISH_ENV.search(name):
        dst = f"/tmp/lykos-env/{name.lower()}"
        it["value"] = dst
        it["stage"] = [{"path": dst, "kind": "dir", "source": "env-value"}]
    else:
        it["value"] = textconf.value_for(name, dir_value="/tmp", file_value="/dev/null")
    return it


def _path_item(p: dict) -> dict:
    it = dict(p)
    if it["kind"] in ("file", "exists") and _RUNTIME_FILE.search(it["path"]):
        it["kind"] = "parent"
    if it["kind"] == "exists":
        it["kind"] = "file" if re.search(r"\.[A-Za-z0-9]{1,8}$", it["path"].rstrip("/")) \
            and not it["path"].endswith("/") else "dir"
    if it["kind"] == "file" and it["path"].endswith("/"):
        it["kind"] = "dir"
    return it


# --- the entry point -------------------------------------------------------------------------------

def prepare(exe, *, argv=(), data=None, strings=None, scratch, arch=None, endianness=None,
            bits=None, timeout: float = 3.0, max_runs: int = 24, trace: bool = True,
            needs: Optional[dict] = None, budget_s: float = 90.0) -> RuntimeEnv:
    """Discover, confirm and stage what `exe` needs around `argv` to run past its startup gate.

    `argv` must be concrete (no `@@`: give it a real sample path). `scratch` is a directory this
    call may write (the staged files live there and must outlive the runs that use them).
    Returns a RuntimeEnv; `applied` is False -- with `note` saying why -- whenever nothing was
    needed, nothing helped, or nothing could be supplied. Never raises.
    """
    exe = str(Path(exe).resolve())
    # An environment already registered for this staged dir would be applied by the sandbox hook
    # to the BASELINE too and every comparison below would be against the supplied run. Lift it
    # for the duration of the probes.
    with _REG_LOCK:
        lifted = _REG.pop(_key(exe), None)
    try:
        return _prepare(exe, argv=argv, data=data, strings=strings, scratch=scratch, arch=arch,
                        endianness=endianness, bits=bits, timeout=timeout, max_runs=max_runs,
                        trace=trace, needs=needs, budget_s=budget_s)
    finally:
        if lifted is not None:
            with _REG_LOCK:
                _REG.setdefault(_key(exe), lifted)


def _prepare(exe, *, argv, data, strings, scratch, arch, endianness, bits, timeout, max_runs,
             trace, needs, budget_s) -> RuntimeEnv:
    root = Path(scratch) / "runtime_env"
    renv0 = RuntimeEnv(root=str(root))
    try:
        if data is None:
            data = Path(exe).read_bytes()
        needs = needs if needs is not None else discover(data, strings)
        root.mkdir(parents=True, exist_ok=True)
        runs = 0
        # `@@` is where the campaign's input goes; the probe needs a real file there. It gets a
        # plausible config (the commonest input behind a value flag) so the probe measures the
        # environment gate, not an empty-input refusal.
        from . import invocation as invmod
        from .fuzz import textconf
        cargv: list = []
        for a in argv:
            if a == invmod.INPUT_PLACEHOLDER:
                smp = root / "sample.conf"
                smp.write_bytes(textconf.plausible_config("sample.conf", needs.get("strings") or (),
                                                          keys=(needs.get("config") or {}).get("keys")))
                cargv.append(str(smp))
            elif a == invmod.OUTPUT_PLACEHOLDER:
                cargv.append(invmod.OUTPUT_SCRATCH)
            else:
                cargv.append(str(a))

        deadline = time.monotonic() + budget_s

        def go(r):
            nonlocal runs, max_runs
            runs += 1
            if time.monotonic() + timeout > deadline:
                max_runs = min(max_runs, runs)          # the wall-clock budget is spent
            return _run_probe(exe, cargv, r, timeout=timeout, arch=arch,
                              endianness=endianness, bits=bits, trace=trace,
                              sample_dir=str(root))

        base = go(None)
        renv0.baseline = base.view()
        renv0.traced = base.trace is not None
        if base.failed:
            renv0.note = f"baseline did not run ({base.out.strip()[:160]}); nothing supplied"
            return _done(renv0, runs)
        vals = needs.get("strings") or []
        vals_set = set(vals)
        basenames = {os.path.basename(v.rstrip("/")) for v in vals if "/" in v or "." in v}
        base_enoent = [(sc, path, fl) for sc, path, fl in (base.trace or {}).get("enoent", [])
                       if _evidence_ok(path, vals_set, basenames)]
        absent = [p["path"] for p in needs.get("paths") or []
                  if p["source"] == "call-site" and p["path"].startswith("/")
                  and not os.path.lexists(p["path"])]
        base_denied = [(sc, path, fl) for sc, path, fl in (base.trace or {}).get("denied", [])
                       if _evidence_ok(path, vals_set, basenames)]
        if not _gated(base, enoent=base_enoent + base_denied, absent=absent,
                      env_names=[e["name"] for e in needs.get("env") or []]):
            renv0.note = ("the target runs without a supplied environment (it "
                          + ("stays up" if base.timed_out else "crashed" if base.crashed
                             else f"exits {base.rc} with no missing-resource complaint")
                          + "); nothing supplied")
            return _done(renv0, runs)
        items: list = []
        keys = set()

        def add(it):
            k = _item_key(it)
            if "path" in it:
                tp = it["path"].rstrip("/")
                tp = os.path.dirname(tp) if it["kind"] == "parent" else tp
                if it["kind"] in ("parent", "writable") and tp.startswith("/") \
                        and os.path.isdir(tp):
                    # the directory is there but the sandbox's root is read-only: the need is to
                    # WRITE in it (a pid/lock/log/spool dir) -- a throwaway overlay, no content
                    if tp == "/tmp" or tp.startswith("/tmp/"):
                        return
                    it = dict(it, path=tp, kind="writable")
                    k = tp
                # never shadow what the host already has: the sandbox's read-only root shows it
                # to the target, and replacing a real file would change a target that works
                elif tp.startswith("/") and os.path.lexists(tp):
                    return
            if k and k in keys:
                for prev in items:                       # same need, a second witness
                    if _item_key(prev) == k and it.get("source") not in (prev.get("source") or ""):
                        prev["source"] = f"{prev.get('source')}+{it.get('source')}"
                return
            if k:
                keys.add(k)
                items.append(it)

        # traced ENOENTs the program itself asked for -- the strongest evidence there is
        for sc, path, flags in base_enoent:
            add(_path_item({"path": path, "kind": _trace_kind(sc, flags, path), "source": "trace",
                            "why": f"the target's {sc}() of it failed ENOENT"}))
        # it tried to create/write and the read-only root refused: a writable directory
        for sc, path, flags in (base.trace or {}).get("denied", []):
            if _evidence_ok(path, vals_set, basenames):
                d = path.rstrip("/") if sc in ("mkdir", "mkdirat") else path
                add({"path": d, "kind": "parent", "source": "trace",
                     "why": f"the target's {sc}() here was refused by the read-only root"})
        for p in needs.get("paths") or []:
            if base.trace is not None and p["source"] == "strings":
                # traced, and the target never asked for it: a string is not a need
                if not any(path == p["path"] for _s, path, _f in base.trace["enoent"]):
                    continue
            add(_path_item(dict(p, why=p.get("why") or (
                f"{p.get('via') or 'referenced'}() of a literal path"
                if p["source"] == "call-site" else "named in the binary's strings"))))
        # Env vars. A program that reads a handful is plausibly gated on one; one that reads a
        # hundred (git) is configured BY them, and setting them all to placeholder values changes
        # its behaviour in ways that are not "getting further". There, only a variable the
        # baseline's own output names is a candidate.
        def _named(e):
            return re.search(r"(?<![A-Za-z0-9_])" + re.escape(e["name"]) + r"(?![A-Za-z0-9_])",
                             base.out)
        # a debug/trace/log knob changes HOW it runs, never WHETHER: only when the output asks
        envs = [e for e in needs.get("env") or [] if e["name"] not in os.environ
                and (not _ENV_KNOB.search(e["name"]) or _named(e))]
        cap = _ENV_CAP if all(e["source"] == "call-site" for e in envs) else _ENV_CAP // 2
        if len(envs) > cap:
            envs = [e for e in envs if _named(e)]
        for e in envs:
            add(_env_item(dict(e, why=(f"{e.get('via', 'getenv')}(\"{e['name']}\")"
                                       if e["source"] == "call-site"
                                       else "env-shaped string in a getenv importer")), root))
        renv0.gated = True
        if not items:
            renv0.note = ("the target exits early (" + (base.view()["says"] or f"rc {base.rc}")
                          + ") but no env var, path or directory it needs was recovered")
            return _done(renv0, runs)

        stager = _Stager(root, needs, exe)
        full = stager.build(items)
        cur = go(full)
        # chase what the supplied environment unlocked next (config -> data dir -> ...)
        for _round in range(3):
            if cur.trace is None or runs >= max_runs:
                break
            new = []
            for sc, path, flags in cur.trace["enoent"]:
                if _evidence_ok(path, vals_set, basenames) and path not in keys:
                    new.append(_path_item({"path": path, "kind": _trace_kind(sc, flags, path),
                                           "source": "trace",
                                           "why": f"after the first supply, its {sc}() of it "
                                                  "failed ENOENT"}))
            for sc, path, flags in cur.trace.get("denied", []):
                if _evidence_ok(path, vals_set, basenames):
                    d = path.rstrip("/") if sc in ("mkdir", "mkdirat") else path
                    if os.path.dirname(d) not in keys:
                        new.append({"path": d, "kind": "parent", "source": "trace",
                                    "why": f"after the first supply, its {sc}() here was "
                                           "refused by the read-only root"})
            n_before = len(items)
            for it in new:
                add(it)
            if len(items) == n_before:
                break
            full = stager.build(items)
            cur = go(full)
        # a synthesized config the parser rejects line by line: comment the offending line out
        # and try again (bounded) -- a daemon that exits on its first unknown option otherwise
        # reads as "the config did not help", when it was only the placeholder keys
        if _LINE_ERR.search(cur.out) and stager.bodies and runs < max_runs:
            # first the cheapest answer: many parsers accept a config that sets nothing
            saved = dict(stager.bodies)
            for pth in stager.bodies:
                if _CONF_EXT.search(pth) or not re.search(r"\.[A-Za-z0-9]{1,8}$", pth):
                    stager.bodies[pth] = b"# lykos: synthesized\n"
            trial_env = stager.build(items)
            trial = go(trial_env)
            if _progressed(base, trial):
                full, cur = trial_env, trial
            else:
                stager.bodies = saved
                for _round in range(16):
                    if runs >= max_runs or not stager.repair(cur.out):
                        break
                    full = stager.build(items)
                    cur = go(full)
        if not _progressed(base, cur):
            renv0.degraded = full.degraded
            renv0.result = cur.view()
            renv0.note = ("supplied " + ", ".join(_item_key(i) for i in items)[:300]
                          + " but the target's early exit did not change ("
                          + (cur.view()["says"] or f"rc {cur.rc}") + "); not applied")
            return _done(renv0, runs)
        # minimise: drop every item whose removal does not change the outcome
        keep = list(items)
        target_sig = cur.sig()
        tested_all = True
        for it in list(items):
            if runs >= max_runs:
                tested_all = False
                break
            trial = [x for x in keep if x is not it]
            if not trial:
                break
            t = go(stager.build(trial))
            if not t.failed and t.sig() == target_sig:
                keep = trial
        final = stager.build(keep)
        # what could NOT be supplied stays visible even when the run got past its gate without it
        final.degraded += [d for d in full.degraded if d not in final.degraded]
        final.baseline = renv0.baseline
        final.result = cur.view()
        final.traced = renv0.traced
        minimal = tested_all or len(keep) == 1
        for rec in final.supplied:
            rec["confirmed"] = ("removing it reverts the run" if minimal
                                else "part of a set that gets the target past its gate "
                                     "(run budget spent before each item was tested alone)")
        final.note = (f"the target exited early ({renv0.baseline.get('says') or 'rc ' + str(base.rc)})"
                      f"; with {len(final.supplied)} supplied item(s) it "
                      + ("stays up" if cur.timed_out else "crashes" if cur.crashed
                         else f"exits {cur.rc}" + (f" ({cur.view()['says']})"
                                                   if cur.view()["says"] else "")))
        return _done(final, runs)
    except Exception as e:                               # noqa: BLE001 -- an optimisation, never a blocker
        _log.debug("runtime_env.prepare failed", exc_info=True)
        renv0.note = f"runtime-environment discovery failed: {e}"
        renv0.applied = False
        return _done(renv0, 0)


def _done(r: RuntimeEnv, runs: int) -> RuntimeEnv:
    r.runs = runs
    return r


# --- the registry the sandbox consults --------------------------------------------------------------
# Every runner (sandbox.run, run_batch, isolate_prefix callers) execs a target from the directory
# the caller staged it in, so the environment is registered against that directory: one lookup
# in the sandbox serves every stage that runs this staged copy.

_REG: dict = {}
_REG_LOCK = threading.Lock()


def _key(p) -> str:
    p = Path(p)
    try:
        p = p.resolve()
    except OSError:
        pass
    return str(p if p.is_dir() else p.parent)


def register(renv: RuntimeEnv, *where) -> None:
    """Supply `renv` to every sandboxed run of an exe staged in any of `where` (exe paths or
    their directories). A not-applied env is not registered."""
    if not renv or not renv.applied:
        return
    with _REG_LOCK:
        for w in where:
            _REG[_key(w)] = renv


def unregister(*where) -> None:
    with _REG_LOCK:
        for w in where:
            _REG.pop(_key(w), None)


def for_exe(exe_or_dir) -> Optional[RuntimeEnv]:
    """The registered environment for an exe (or its staged dir), or None. Cheap (no I/O beyond a
    resolve) so the sandbox can ask on every run."""
    if not _REG:
        return None
    with _REG_LOCK:
        return _REG.get(_key(exe_or_dir))


def bwrap_args_for(exe_or_dir, *, cwd: str = "/tmp") -> list:
    """The bwrap arguments for a registered environment ([] when none) -- the one call the
    sandbox's command builders make, placed before their `--`."""
    r = for_exe(exe_or_dir)
    return r.bwrap_args(cwd=cwd) if r is not None else []


def setenv_args(renv: Optional[RuntimeEnv], skip=()) -> list:
    """`--setenv NAME VALUE` bwrap arguments for an applied environment's variables, for a runner
    whose own process environment the sandbox does not control (`isolate_prefix` callers).
    `skip` names variables the caller sets itself (an env-channel input): theirs must win."""
    if renv is None or not renv.applied:
        return []
    skip = set(skip or ())
    a: list = []
    for k, v in renv.env.items():
        if k not in skip:
            a += ["--setenv", str(k), str(v)]
    return a


# --- persistence: one confirmed environment per target, shared by every stage ----------------------
# Discovery costs up to `max_runs` executions, so it runs ONCE per target (the first stage that
# executes it) and the result is recorded in the case dir. Every later `stage_target` -- in this
# process or a worker -- adopts that record for the directory it staged into, so the campaign, the
# PoC builders, the debuggers and the exploit ladder all run the target with the same environment
# without probing again. The record carries the synthesized file CONTENTS (they are small text
# configs), and each process restages them under its own temp root: the case store itself is never
# a bind source, and a removed stage scratch cannot leave a dangling bind behind.

_RECORD_DIR = "runtime_env"
_RECORD_VERSION = 1
_MAX_RECORD_FILE = 1 << 20                               # a synthesized config is a few hundred bytes
_BY_SHA: dict = {}                                       # target sha256 -> applied RuntimeEnv
_LOADED: dict = {}                                       # record path -> (mtime_ns, RuntimeEnv|None)
_ENSURE_LOCKS: dict = {}
_PROC_ROOT: Optional[str] = None


def to_record(renv: RuntimeEnv, *, argv=()) -> dict:
    """A JSON-safe record of `renv`, file contents included, from which `from_record` rebuilds an
    equivalent environment anywhere."""
    import base64

    def _blob(src):
        try:
            with open(src, "rb") as fh:
                data = fh.read(_MAX_RECORD_FILE + 1)
        except OSError:
            return None
        return base64.b64encode(data[:_MAX_RECORD_FILE]).decode("ascii")

    return {"version": _RECORD_VERSION, "argv": [str(a) for a in argv],
            "applied": bool(renv.applied), "note": renv.note, "env": dict(renv.env),
            "files": [{"dst": dst, "b64": _blob(src)} for src, dst in renv.files],
            "rel_files": [{"dst": rel, "b64": _blob(src)} for src, rel in renv.rel_files],
            "dirs": list(renv.dirs), "rel_dirs": list(renv.rel_dirs),
            "overlays": list(renv.overlays), "tmpfs": list(renv.tmpfs),
            "supplied": list(renv.supplied), "degraded": list(renv.degraded),
            "baseline": dict(renv.baseline), "result": dict(renv.result),
            "runs": int(renv.runs), "traced": bool(renv.traced), "gated": bool(renv.gated)}


def from_record(rec: dict, root) -> RuntimeEnv:
    """Rebuild a RuntimeEnv from `to_record` output, writing its files under `root`. A file whose
    content did not survive makes the environment NOT applied (and says why): binding a missing
    source would make bwrap refuse every run, which reads as a sandbox failure."""
    import base64
    root = Path(root)
    r = RuntimeEnv(root=str(root), env=dict(rec.get("env") or {}),
                   dirs=list(rec.get("dirs") or []), rel_dirs=list(rec.get("rel_dirs") or []),
                   overlays=list(rec.get("overlays") or []), tmpfs=list(rec.get("tmpfs") or []),
                   supplied=list(rec.get("supplied") or []),
                   degraded=list(rec.get("degraded") or []), applied=bool(rec.get("applied")),
                   note=str(rec.get("note") or ""), baseline=dict(rec.get("baseline") or {}),
                   result=dict(rec.get("result") or {}), runs=int(rec.get("runs") or 0),
                   traced=bool(rec.get("traced")), gated=bool(rec.get("gated")))
    if not r.applied:
        return r
    fdir = root / "files"
    for key, out in (("files", r.files), ("rel_files", r.rel_files)):
        for i, f in enumerate(rec.get(key) or []):
            if not isinstance(f, dict) or f.get("b64") is None or not f.get("dst"):
                r.applied = False
                r.note = f"recorded environment is incomplete (no content for {f!r:.80})"
                return r
            fdir.mkdir(parents=True, exist_ok=True)
            src = fdir / f"{key}-{i}-{os.path.basename(str(f['dst']).rstrip('/')) or 'file'}"
            src.write_bytes(base64.b64decode(f["b64"]))
            out.append((str(src), str(f["dst"])))
    return r


def record_path(case_root, sha256: str) -> Path:
    return Path(case_root) / _RECORD_DIR / f"{sha256}.json"


def _proc_root() -> str:
    """This process's restaging root (removed at exit)."""
    global _PROC_ROOT
    if _PROC_ROOT is None or not os.path.isdir(_PROC_ROOT):
        import atexit
        _PROC_ROOT = tempfile.mkdtemp(prefix="lykos-renv-")
        atexit.register(shutil.rmtree, _PROC_ROOT, True)
    return _PROC_ROOT


def save(case_root, sha256: str, renv: RuntimeEnv, *, argv=()) -> None:
    """Record `renv` for target `sha256` in the case dir (atomic). Never raises."""
    import json
    try:
        p = record_path(case_root, sha256)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps(to_record(renv, argv=argv), sort_keys=True))
        os.replace(tmp, p)
        with _REG_LOCK:
            _LOADED.pop(str(p), None)
    except Exception:                                    # noqa: BLE001 -- recording is best-effort
        _log.debug("runtime_env record not saved", exc_info=True)


def load(case_root, sha256: str) -> Optional[tuple]:
    """(record dict, RuntimeEnv restaged in this process) for target `sha256`, or None when no
    record exists. Cached on the record's mtime, so asking on every staging costs one stat."""
    import json
    p = record_path(case_root, sha256)
    try:
        mt = p.stat().st_mtime_ns
    except OSError:
        return None
    key = str(p)
    with _REG_LOCK:
        hit = _LOADED.get(key)
    if hit is not None and hit[0] == mt:
        return hit[1]
    try:
        rec = json.loads(p.read_text())
        if not isinstance(rec, dict) or rec.get("version") != _RECORD_VERSION:
            return None
        root = Path(_proc_root()) / hashlib.sha1(f"{key}:{mt}".encode()).hexdigest()[:16]
        out = (rec, from_record(rec, root))
    except Exception:                                    # noqa: BLE001 -- a bad record is no record
        _log.debug("runtime_env record unreadable: %s", p, exc_info=True)
        return None
    with _REG_LOCK:
        _LOADED[key] = (mt, out)
    return out


def for_sha(sha256: Optional[str]) -> Optional[RuntimeEnv]:
    """The applied environment known in this process for target `sha256`, or None."""
    if not sha256 or not _BY_SHA:
        return None
    with _REG_LOCK:
        return _BY_SHA.get(sha256)


def adopt(case_root, sha256: str, *where) -> Optional[RuntimeEnv]:
    """Register the recorded environment of target `sha256` (if any, and applied) for every dir in
    `where`. Called by `ContentStore.stage_target`, so every staged copy of a target that needed
    an environment gets it. Cheap when there is no record (one failed stat). Never raises."""
    try:
        got = load(case_root, sha256)
        if got is None or not got[1].applied:
            return None
        renv = got[1]
        register(renv, *where)
        with _REG_LOCK:
            _BY_SHA[sha256] = renv
        return renv
    except Exception:                                    # noqa: BLE001
        _log.debug("runtime_env adopt failed", exc_info=True)
        return None


def ensure(ctx, target, argv=(), *, strings=None, exec_timeout: float = 2.0,
           also=(), budget_s: float = 90.0) -> Optional[RuntimeEnv]:
    """Discover the target's runtime environment once per case and supply it to every stage.

    The first call for a target (per argv) probes it (`prepare`), records the result in the case
    dir and emits a `runtime_env` event; later calls -- from any stage, in any process -- reuse the
    record. An applied environment is registered for this stage's scratch and every dir in `also`
    (and, via `stage_target`, for every later staged copy). An applied record is reused under any
    argv (a startup gate is the program's, not the invocation's); a record that applied nothing
    is re-probed only when the argv differs. Returns the environment in effect, or None. Never
    raises."""
    try:
        case_root = getattr(ctx.content, "root", None)
        sha = target.sha256
        argv = [str(a) for a in argv]
        if case_root is None:
            return None
        key = str(record_path(case_root, sha))
        with _REG_LOCK:
            lock = _ENSURE_LOCKS.setdefault(key, threading.Lock())
        with lock:
            got = load(case_root, sha)
            if got is not None and (got[0].get("argv") == argv or got[1].applied):
                renv = got[1]
                if renv.applied:
                    register(renv, ctx.scratch(), *also)
                    with _REG_LOCK:
                        _BY_SHA[sha] = renv
                    try:
                        ctx.emit("runtime_env", payload=dict(renv.summary(), reused=True))
                    except Exception:                    # noqa: BLE001
                        pass
                return renv if renv.applied else None
            from . import invocation as invmod
            d = Path(ctx.scratch()) / "renvprobe"
            d.mkdir(parents=True, exist_ok=True)
            data = ctx.content.path(sha).read_bytes()
            if data[:4] != b"\x7fELF":
                return None                              # discovery reads ELF call sites only
            exe = ctx.content.stage_target(target, d, invmod.exec_name_for(data) or "target.bin")
            renv = prepare(exe, argv=argv, data=data, strings=strings, scratch=d,
                           arch=getattr(target, "arch", None),
                           endianness=getattr(target, "endianness", None),
                           bits=getattr(target, "bits", None),
                           timeout=max(2.0, 2.0 * float(exec_timeout or 0)), budget_s=budget_s)
            try:
                ctx.emit("runtime_env", payload=renv.summary())
            except Exception:                            # noqa: BLE001
                _log.debug("runtime_env event not emitted", exc_info=True)
            save(case_root, sha, renv, argv=argv)        # (any prior record applied nothing)
            # Re-adopt from the record: the probe's staged files live in this stage's scratch,
            # which is removed when the stage ends; the restaged copy outlives it.
            if renv.applied:
                return adopt(case_root, sha, ctx.scratch(), *also) or renv
            return None
    except Exception:                                    # noqa: BLE001 -- discovery never blocks a stage
        _log.debug("runtime_env ensure failed", exc_info=True)
        return None


# --- the stage-side entry point -----------------------------------------------------------------------

def stage_hook(ctx, target, exe, argv=(), *, strings=None, exec_timeout: float = 2.0,
               also=(), budget_s: float = 90.0) -> RuntimeEnv:
    """Prepare, REPORT and register the runtime environment for a target the stage staged at
    `exe`. Emits a `runtime_env` event carrying exactly what was supplied / could not be (the
    operator sees it whether or not it applied), and registers an applied environment for the
    exe's directory, the stage scratch and every dir in `also` -- so the campaign, the argv
    probe and every later sandboxed run of a copy staged there get it. Never raises."""
    renv = prepare(exe, argv=[str(a) for a in argv], strings=strings, scratch=ctx.scratch(),
                   arch=getattr(target, "arch", None),
                   endianness=getattr(target, "endianness", None),
                   bits=getattr(target, "bits", None),
                   timeout=max(2.0, 2.0 * float(exec_timeout or 0)), budget_s=budget_s)
    try:
        ctx.emit("runtime_env", payload=renv.summary())
    except Exception:                                    # noqa: BLE001 -- reporting is best-effort
        _log.debug("runtime_env event not emitted", exc_info=True)
    if renv.applied:
        register(renv, exe, ctx.scratch(), *also)
        if getattr(target, "sha256", None):
            with _REG_LOCK:
                _BY_SHA[target.sha256] = renv
    return renv


def release(ctx, exe=None, also=()) -> None:
    """Undo `stage_hook`'s registration (call in the stage's `finally`)."""
    unregister(*([exe] if exe else []), ctx.scratch(), *also)
