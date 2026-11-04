"""QASan: an AddressSanitizer-grade memory oracle for a binary we have no source for.

A heap over-read, a small heap over-write, a use-after-free and a double-free usually do NOT crash a
native binary: the access lands in mapped memory and the program carries on. On a source target
lykos rebuilds with ASan and sees them; on a binary-only target every executed input that hits one
of these looked clean, which is why 25k-57k fuzz executions per binary in the 2026-11-02 recall
bench produced no crash at all. AFL++'s QASan closes that: afl-qemu-trace instruments every guest
load/store against a shadow map that libqasan.so maintains by hooking the guest's allocator, and
reports the first invalid access ASan-style (class, READ/WRITE, size, the faulting frame inside the
target image, the allocation site).

This module is that oracle as a function: run ONE input under QASan, inside the sandbox, with a hard
deadline, and return a parsed, forgery-checked report or None.

Soundness (the report must come from the instrumentation, not from the target):
  * the target is staged under a random NONCE filename, and a report is accepted only when one of
    its frames names that file (`(<.../nonce>+0x...)`) -- a target that echoes its input, or
    prints a canned sanitizer banner, does not know the nonce. The guest's argv[0] is set to a
    neutral name (qemu `-0`), so printing argv[0] does not reveal it either. (A target written to
    defeat the oracle could readlink /proc/self/exe; that is out of scope -- the threat model is an
    echoing or chatty target, not one engineered against lykos.);
  * the report text must not occur in the input bytes (echo);
  * the run must END abnormally: death by a fatal signal, or a hang AFTER the report (QASan's SEGV
    path can spin after reporting a second error -- measured -- so a deadline kill that follows a
    report still counts). A report followed by a clean exit 0 is rejected.

Limits, stated: libqasan is built for x86-64 guests only, and it hooks the DYNAMIC allocator -- a
statically linked binary keeps its own malloc, which QASan cannot shadow (`applicable` says so).
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

#: QASan-supported guest architectures (the bundled libqasan.so is an x86-64 object).
_ARCHES = ("x86-64",)

_ERR = re.compile(rb"ERROR: QEMU-AddressSanitizer: ([\w-]+) on (?:unknown )?address (0x[0-9a-f]+)"
                  rb"(?: at pc (0x[0-9a-f]+)| \(pc (0x[0-9a-f]+))")
_ACCESS = re.compile(rb"(READ|WRITE) of size (\d+) at")
_REGION = re.compile(rb"is located (\d+) bytes to the (left|right) of (\d+)-byte region")
_FRAME = re.compile(rb"#(\d+) 0x[0-9a-f]+ (?:in (\S+) )?\(([^()+]+)\+(0x[0-9a-f]+)\)")
_ANSI = re.compile(rb"\x1b\[[0-9;]*m")

#: QASan bug class -> CWE. Reads and writes split heap-buffer-overflow (the class names the same
#: report either way; the access line decides).
_CWE = {"heap-use-after-free": "CWE-416", "double-free": "CWE-415", "invalid-free": "CWE-763",
        "stack-buffer-overflow": "CWE-121", "global-buffer-overflow": "CWE-787",
        "SEGV": "CWE-476"}


@dataclass
class QasanReport:
    kind: str                       # heap-buffer-overflow, heap-use-after-free, double-free, ...
    access: Optional[str]           # READ / WRITE / None (free-class reports have no access line)
    size: Optional[int]
    site_off: Optional[int]         # offset of the first in-target frame within the target image
    frames: list = field(default_factory=list)          # [(fn|None, module_basename, off)]
    alloc_off: Optional[int] = None  # first in-target frame of the "allocated by" stack
    region: Optional[str] = None     # "0 bytes to the right of 16-byte region"
    ended: str = ""                  # "signal:11" / "timeout-after-report"
    raw: str = ""

    @property
    def cwe(self) -> str:
        if self.kind == "heap-buffer-overflow":
            return "CWE-125" if self.access == "READ" else "CWE-787"
        return _CWE.get(self.kind, "CWE-119")

    def summary(self) -> str:
        acc = f"{self.access} of size {self.size}" if self.access else "no access line"
        site = f"+{self.site_off:#x}" if self.site_off is not None else "?"
        reg = f", {self.region}" if self.region else ""
        return f"QASan {self.kind} ({acc}) at target{site}{reg} [{self.ended}]"


def _locate():
    """(afl-qemu-trace for x86-64, directory holding libqasan.so) or (None, None)."""
    lib = None
    env = os.environ.get("LYKOS_QASAN")
    if env and Path(env).is_file():
        lib = Path(env)
    if lib is None:
        try:
            from . import memoracle
            lib = memoracle.libqasan_lib()
        except Exception:                                    # noqa: BLE001
            lib = None
    if lib is None:
        try:
            from ... import vendorenv
            v = vendorenv.vendor_dir()
            cand = v / "tools" / "aflpp" / "libqasan.so" if v else None
            lib = cand if cand and cand.is_file() else None
        except Exception:                                    # noqa: BLE001
            lib = None
    if lib is None:
        return None, None
    trace = None
    try:
        from ..fuzz import aflpp
        afl = aflpp.locate_afl()
        trace = aflpp.locate_qemu_trace_for(afl, "x86-64")
    except Exception:                                        # noqa: BLE001
        trace = None
    if trace is None:
        for name in ("afl-qemu-trace-x86-64", "afl-qemu-trace-x86_64"):
            w = shutil.which(name)
            if w:
                trace = Path(w)
                break
    return (Path(trace), lib.parent) if trace else (None, None)


def available() -> bool:
    t, d = _locate()
    return bool(t and d)


def _is_static_elf(data: bytes) -> bool:
    """No PT_INTERP -> statically linked (its own malloc: QASan cannot shadow it)."""
    import struct
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        return False
    (phoff,) = struct.unpack_from("<Q", data, 32)
    (phentsize,) = struct.unpack_from("<H", data, 54)
    (phnum,) = struct.unpack_from("<H", data, 56)
    for i in range(min(phnum, 256)):
        b = phoff + i * phentsize
        if b + 4 > len(data):
            break
        if struct.unpack_from("<I", data, b)[0] == 3:        # PT_INTERP
            return False
    return True


def applicable(exe_bytes: bytes, arch: Optional[str]) -> tuple:
    """(ok, reason). QASan needs an x86-64, dynamically linked ELF and the bundled tooling."""
    if (arch or "").lower().replace("_", "-") not in _ARCHES:
        return False, f"QASan's libqasan is built for x86-64 guests only (target is {arch})"
    if exe_bytes[:4] != b"\x7fELF":
        return False, "QASan runs ELF executables only"
    if _is_static_elf(exe_bytes):
        return False, ("statically linked: the target carries its own malloc, which libqasan "
                       "cannot hook, so heap errors stay invisible (a dislocator/valgrind lane "
                       "or a source ASan build covers it)")
    if not available():
        return False, "afl-qemu-trace (x86-64) or libqasan.so is not available"
    return True, ""


def parse(stderr: bytes, *, module: str) -> Optional[QasanReport]:
    """Parse the FIRST QASan report in `stderr`. `module` is the staged target's file name; frames
    in it give the in-target site. Returns None when there is no report or none of its frames is in
    the target (the nonce check)."""
    text = _ANSI.sub(b"", stderr or b"")
    m = _ERR.search(text)
    if not m:
        return None
    body = text[m.start():]
    # cut at a second report, if any: we classify the first error only
    nxt = _ERR.search(body, 1)
    first = body[:nxt.start()] if nxt else body
    acc = _ACCESS.search(first)
    reg = _REGION.search(first)
    alloc_at = first.find(b"allocated by")
    frames, alloc_off, site_off = [], None, None
    mod = module.encode()
    for fm in _FRAME.finditer(first):
        path = fm.group(3)
        off = int(fm.group(4), 16)
        fn = fm.group(2).decode("latin-1") if fm.group(2) else None
        base = os.path.basename(path).decode("latin-1", "replace")
        in_target = os.path.basename(path) == mod
        if alloc_at != -1 and fm.start() > alloc_at:
            if in_target and alloc_off is None:
                alloc_off = off
            continue
        frames.append((fn, base, off))
        if in_target and site_off is None:
            site_off = off
    if site_off is None and alloc_off is None:
        return None                                          # no frame names the nonce'd target
    region = None
    if reg:
        region = (f"{int(reg.group(1))} bytes to the {reg.group(2).decode()} of "
                  f"{int(reg.group(3))}-byte region")
    return QasanReport(kind=m.group(1).decode(), access=acc.group(1).decode() if acc else None,
                       size=int(acc.group(2)) if acc else None, site_off=site_off, frames=frames,
                       alloc_off=alloc_off, region=region,
                       raw=first[:4000].decode("latin-1", "replace"))


def run(exe, data: bytes, *, argv=(), mode: str = "stdin", timeout: float = 10.0,
        input_suffix: str = "") -> Optional[QasanReport]:
    """Run `exe` once under QASan with `data` as its input and return the accepted report, or None.

    `mode`: "stdin" feeds `data` on stdin; "file" writes it to a file and substitutes the path for
    '@@' in `argv` (appended when there is no '@@'). Sandboxed (bwrap, no network, fresh /tmp);
    bounded by `timeout`. Never raises."""
    trace, libdir = _locate()
    if not trace:
        return None
    work = Path(tempfile.mkdtemp(prefix="lykos-qasan-"))
    try:
        nonce = "t_" + secrets.token_hex(6)
        staged = work / nonce
        shutil.copyfile(str(exe), str(staged))
        os.chmod(staged, 0o755)
        tail = [str(a) for a in argv]
        stdin_data = data
        if mode == "file":
            inp = work / ("input" + (input_suffix or ""))
            inp.write_bytes(data)
            tail = [str(inp) if a == "@@" else a for a in tail] if "@@" in tail else tail + [str(inp)]
            stdin_data = b""
        env = {k: v for k, v in os.environ.items() if k not in ("LD_PRELOAD", "AFL_PRELOAD")}
        env.update({"AFL_PATH": str(libdir), "AFL_USE_QASAN": "1"})
        # `-0 target`: the guest's argv[0] is a neutral name, NOT the nonce path -- a target that
        # prints its own argv[0] into a canned report must not learn the nonce (measured: it did).
        cmd = [str(trace), "-0", "target", str(staged)] + tail
        try:
            from . import sandbox
            pre = sandbox.isolate_prefix(str(work), net=False, ro_binds=[str(libdir)],
                                         rw_binds=[str(work)], chdir=str(work))
        except Exception:                                    # noqa: BLE001 -- containment best-effort
            pre = []
        if pre and "--" in pre:
            i = pre.index("--")
            pre = pre[:i] + ["--setenv", "AFL_PATH", str(libdir), "--setenv", "AFL_USE_QASAN", "1"] + pre[i:]
        err_path = work / "stderr"
        ended = ""
        with open(err_path, "wb") as errf:
            try:
                p = subprocess.Popen(pre + cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                     stderr=errf, env=env, start_new_session=True)
            except OSError:
                return None
            ended = _wait(p, stdin_data, err_path, timeout)
        rep = parse(err_path.read_bytes(), module=nonce)
        if rep is None:
            return None
        if ended.startswith("exit:"):
            return None                                      # a report then a clean exit: not ours
        if rep.raw[:60].encode("latin-1", "replace") in (data or b""):
            return None                                      # the input carries the report text
        rep.ended = "hung-after-report" if ended in ("timeout", "killed-after-report") else ended
        return rep
    finally:
        shutil.rmtree(work, ignore_errors=True)


#: after a complete report appears, how long the process gets to die on its own before we stop it.
#: QASan's SEGV path can spin forever after a second error (measured), so without this every
#: detection costs the full deadline.
_GRACE = 1.0


def _wait(p, stdin_data: bytes, err_path: Path, timeout: float) -> str:
    """Feed stdin, then wait for exit / deadline, polling the stderr file. Returns 'signal:N',
    'exit:N', 'killed-after-report' (a report appeared and the process was still alive _GRACE s
    later) or 'timeout'."""
    import time
    try:
        if p.stdin:
            try:
                p.stdin.write(stdin_data or b"")
            except (BrokenPipeError, OSError):
                pass
            try:
                p.stdin.close()
            except OSError:
                pass
        t_end = time.monotonic() + timeout
        seen_report_at = None
        while True:
            rc = p.poll()
            if rc is not None:
                if rc < 0:
                    return f"signal:{-rc}"
                if rc >= 129:
                    return f"signal:{rc - 128}"           # bwrap/shell relays a signal as 128+n
                return f"exit:{rc}"
            now = time.monotonic()
            if seen_report_at is None:
                try:
                    blob = err_path.read_bytes()
                except OSError:
                    blob = b""
                if _ERR.search(_ANSI.sub(b"", blob)) and (b"allocated by" in blob or b"SUMMARY" in blob
                                                           or b"#1 " in blob):
                    seen_report_at = now
            elif now - seen_report_at >= _GRACE:
                _kill(p)
                return "killed-after-report"
            if now >= t_end:
                _kill(p)
                return "timeout"
            time.sleep(0.02)
    except Exception:                                        # noqa: BLE001
        _kill(p)
        return "timeout"


def _kill(p) -> None:
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        p.wait(timeout=5)
    except Exception:                                        # noqa: BLE001
        pass


def site_va(rep: QasanReport, exe_bytes: bytes) -> Optional[int]:
    """The link-time VA of the report's in-target site. QASan prints frames as module+offset, where
    the module base is the image's lowest PT_LOAD -- so VA = offset + lowest p_vaddr (0 on a PIE,
    0x400000 on a classic non-PIE x86-64 build)."""
    import struct
    if rep.site_off is None or exe_bytes[:4] != b"\x7fELF" or exe_bytes[4] != 2:
        return None
    (phoff,) = struct.unpack_from("<Q", exe_bytes, 32)
    (phentsize,) = struct.unpack_from("<H", exe_bytes, 54)
    (phnum,) = struct.unpack_from("<H", exe_bytes, 56)
    lows = []
    for i in range(min(phnum, 256)):
        b = phoff + i * phentsize
        if b + 24 > len(exe_bytes):
            break
        if struct.unpack_from("<I", exe_bytes, b)[0] == 1:
            lows.append(struct.unpack_from("<Q", exe_bytes, b + 16)[0])
    if not lows:
        return None
    return rep.site_off + (min(lows) & ~0xFFF)
