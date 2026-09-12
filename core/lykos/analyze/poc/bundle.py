"""Self-contained PoC bundle builder (a .tar.gz an analyst can run offline)."""
from __future__ import annotations

import io
import json
import shlex
import tarfile
import time


def _add(tar, name, data: bytes, mode=0o644):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(data))


INPUT_PLACEHOLDER = "@@"


def _argv_text(argv, *, carrier=None) -> str:
    """The recorded flag prefix as shell text, with `@@` replaced by the input.

    `@@` is the contract the fuzzer and the runner already share -- it marks where the input
    belongs when it is not simply the last argument. The bundle did not honour it, and file
    mode ignored argv ENTIRELY, so a target that needs `-c <config>` got a reproducer reading
    `./target.bin ./input.bin`: it prints its usage, exits 2, and the bundle that was supposed
    to prove the crash proves nothing.
    """
    out = []
    for a in argv or []:
        a = str(a)
        out.append("./input.bin" if (a == INPUT_PLACEHOLDER and carrier) else shlex.quote(a))
    return " ".join(out)


def _runner(mode: str, argv, signal_name: str, run_cmd=None, runtime: str = "native",
            main_class: str | None = None) -> bytes:
    argv = list(argv or [])
    placed = INPUT_PLACEHOLDER in [str(a) for a in argv]
    # A jar is not executable and the JVM is not the target: `./target.bin` is a zip file, and
    # the reproducer has to name the runtime that reads it.
    exe, setup = "./target.bin", "chmod +x ./target.bin\n"
    if runtime == "jar":
        exe, setup = "java -jar ./target.bin", ""
    elif runtime == "class":
        # The JVM resolves a class by FILE NAME, so `target.bin` cannot be run as-is: it has
        # to be put back under the name the class declares.
        cls = (main_class or "Main").replace("/", ".")
        exe = f"java -cp . {shlex.quote(cls)}"
        setup = f"cp ./target.bin ./{cls.rsplit('.', 1)[-1]}.class\n"
    pre = _argv_text(argv, carrier="./input.bin")
    if run_cmd:                                          # script-based reproducer (e.g. PIE)
        invoke = run_cmd
    elif mode == "stdin":
        invoke = f'{exe}{" " + pre if pre else ""} < ./input.bin'
    elif mode == "file":
        invoke = f'{exe} {pre}' if placed else f'{exe}{" " + pre if pre else ""} ./input.bin'
    elif mode == "arg":
        # The INPUT is the argument. This used to emit the stage's BASE argv -- normally
        # empty -- so the reproducer ran `./target.bin ''` and demonstrated nothing, which
        # made every argv-mode bundle useless as a deliverable.
        # Command substitution is byte-transparent apart from NUL, which it drops, and
        # execve truncates an argument at the first NUL regardless: the shell therefore
        # delivers exactly the bytes the kernel would.
        if placed:
            invoke = (exe + " " + " ".join(
                '"$(cat ./input.bin)"' if str(a) == INPUT_PLACEHOLDER else shlex.quote(str(a))
                for a in argv))
        else:
            invoke = f'{exe}{" " + pre if pre else ""} "$(cat ./input.bin)"'
    else:
        invoke = f'{exe}{" " + pre if pre else ""}'
    if runtime in ("jar", "class"):
        # A JVM fault is an uncaught exception on stderr and an exit code of 1, not a signal.
        # Telling the reader to look for 128+signum would have them conclude the reproducer
        # failed when it worked.
        hint = (f'echo "exit status: $rc -- {signal_name} appears on stderr above as an '
                'uncaught exception; the JVM exits 1 (or 3 on OutOfMemoryError)"')
    else:
        hint = (f'echo "exit status: $rc (a crash by {signal_name} shows as 128+signum, '
                'e.g. 139=SIGSEGV)"')
    return ("#!/bin/sh\n"
            f"# PoC reproducer. Expected result: {signal_name}. RUN IN A SANDBOX/VM --\n"
            "# this executes an untrusted binary. Authorized use only.\n"
            'cd "$(dirname "$0")"\n'
            f"{setup}"
            f"{invoke}\n"
            'rc=$?\n'
            + hint + "\n").encode()


def _primitive_txt(prim: dict) -> bytes:
    lines = [
        "L2 exploitation primitive",
        "=========================",
        f"Primitive: {prim.get('type')}",
        f"Control offset: {prim.get('offset')} bytes",
        f"Sentinel: 0x{prim.get('marker', 0):x}",
        f"Observed program counter at fault: 0x{prim.get('observed_pc', 0):x}",
        f"Confirmed: {prim.get('confirmed')}",
        "",
        "input.bin places the sentinel address at the control offset. Under native execution",
        "the program counter is loaded with the sentinel, demonstrating full instruction-",
        "pointer control (not merely a crash). Register control (if any):",
    ]
    for reg, off in (prim.get("registers") or {}).items():
        lines.append(f"  {reg}: input offset {off}")
    lines.append("")
    return ("\n".join(lines)).encode()


# what each level proves and what a successful run looks like
_LEVEL_MEANING = {
    "L0": "a crash reproducer -- the input makes the target fault",
    "L1": "a verified crash reproducer -- the crash is real and repeatable",
    "L2": "an exploitation PRIMITIVE -- attacker control of the instruction pointer or a "
          "memory read/write (not merely a crash); see PRIMITIVE.txt",
    "L3": "a working EXPLOIT -- control flow is hijacked to attacker-chosen code",
}


def build(target_bytes: bytes, input_bytes: bytes, meta: dict, stderr: bytes,
          mode: str, argv, signal_name: str, primitive: dict | None = None,
          extra_files: dict | None = None, run_cmd: str | None = None,
          runtime: str = "native", main_class: str | None = None) -> bytes:
    level = meta.get("level", "L1")
    script = extra_files and "exploit.py" in extra_files
    prim_line = ""
    if primitive:
        prim_line = (f"\nPrimitive: {primitive.get('type')} at control offset "
                     f"{primitive.get('offset')} (confirmed={primitive.get('confirmed')}). "
                     "See PRIMITIVE.txt.\n")
    files = ["target.bin  - the exact analyzed binary (self-contained; runs anywhere)"
             if runtime == "native" else
             "target.bin  - the exact analyzed " + ("jar" if runtime == "jar" else "class")
             + " (needs a JVM on the machine that replays it)"]
    if script:
        files += ["exploit.py  - the reproducer: leaks a runtime address, defeats ASLR, and "
                  "delivers the exploit live (the payload is base-specific so it cannot be "
                  "a static file)"]
    else:
        files += ["input.bin   - the crafted input that triggers it"]
    files += ["runner.sh   - runs the reproducer for you",
              "meta.json   - machine-readable details (target hash, arch, offset, tool)",
              "PRIMITIVE.txt / stderr.txt - the primitive description and captured diagnostics"]
    what_success = ("the process is hijacked to the attacker-chosen code (you'll see its "
                    "marker output)" if level == "L3"
                    else f"the process dies with {signal_name} (a shell shows exit 128+signum)")
    readme = (
        "LYKOS PROOF-OF-CONCEPT BUNDLE\n"
        "=============================\n"
        f"Level {level}: {_LEVEL_MEANING.get(level, 'a demonstrated finding')}.\n"
        f"Target sha256: {meta.get('target_sha256')}    arch: {meta.get('arch')}\n"
        f"{prim_line}\n"
        "WHAT THIS IS\n"
        "  A self-contained, reproducible proof that this vulnerability is real. It carries the\n"
        "  exact binary and everything needed to demonstrate it, so anyone can verify it\n"
        "  offline, on any machine -- it is the evidence behind the finding.\n\n"
        "HOW TO RUN  (do this inside a VM or disposable sandbox -- it executes untrusted code)\n"
        "  $ tar -xzf <bundle>.tar.gz && cd poc && "
        + ("python3 ./exploit.py" if script else "sh ./runner.sh") + "\n"
        f"  Success = {what_success}.\n\n"
        "WHAT TO DO WITH IT\n"
        "  - Independently confirm the finding by running the reproducer above.\n"
        "  - Attach the whole poc/ folder to your report or ticket as the evidence.\n"
        "  - Hand it to a colleague; it needs nothing from this tool to reproduce.\n\n"
        "FILES\n  " + "\n  ".join(files) + "\n\n"
        "Authorized use only. Do not run against systems you are not authorized to test.\n"
    ).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        _add(tar, "poc/target.bin", target_bytes, mode=0o755)
        _add(tar, "poc/input.bin", input_bytes)
        for name, data in (extra_files or {}).items():
            _add(tar, f"poc/{name}", data, mode=0o755 if name.endswith(".py") else 0o644)
        _add(tar, "poc/runner.sh",
             _runner(mode, argv, signal_name, run_cmd, runtime, main_class), mode=0o755)
        _add(tar, "poc/meta.json", json.dumps(meta, indent=2, sort_keys=True).encode())
        _add(tar, "poc/stderr.txt", stderr or b"")
        if primitive:
            _add(tar, "poc/PRIMITIVE.txt", _primitive_txt(primitive))
        _add(tar, "poc/README.txt", readme)
    return buf.getvalue()


# ------------------------------------------------------------------ secret-extraction PoC
# The offline re-extractor shipped in the bundle: it re-derives each secret from the binary
# alone (seek the recorded file offset, read the C-string; fall back to a printable-run scan),
# proving the credential is really embedded -- deterministically, with NO execution of the
# target. Pure stdlib so it runs on any air-gapped box.
_EXTRACT_PY = r'''#!/usr/bin/env python3
"""Re-extract the hard-coded secret(s) from the target binary -- offline, no execution."""
import json, os, sys, re

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "target.bin")
SECRETS = json.load(open(os.path.join(HERE, "secrets.json")))
blob = open(TARGET, "rb").read()

def cstr_at(off):
    end = blob.find(b"\x00", off)
    return blob[off:(end if end >= 0 else len(blob))]

ok = 0
for s in SECRETS:
    want = s["value"].encode("latin-1", "replace")
    got, how = None, None
    off = s.get("file_offset")
    if off is not None and 0 <= off <= len(blob):
        cand = cstr_at(off)
        if cand.startswith(want) or want in cand:
            got, how = cand.split(b"\x00", 1)[0], "offset 0x%x" % off
    if got is None:                                    # content scan fallback
        i = blob.find(want)
        if i >= 0:
            got, how = cstr_at(i).split(b"\x00", 1)[0], "found at 0x%x" % i
    label = "%s [%s]" % (s.get("title") or "secret", s.get("cwe") or "")
    if got is not None and want in got:
        ok += 1
        print("[+] %s (%s):\n      %s" % (label, how, got.decode("latin-1", "replace")))
    else:
        print("[-] %s: NOT found in this binary" % label)
print("\n%d/%d secret(s) re-extracted from the binary." % (ok, len(SECRETS)))
sys.exit(0 if ok else 2)
'''


def _secret_readme(meta: dict, secrets: list) -> bytes:
    lines = [
        "LYKOS PROOF-OF-CONCEPT BUNDLE  (hard-coded secret extraction)",
        "============================================================",
        "Level L0-secret: a demonstrated finding -- the credential is embedded in the binary",
        "and is recoverable offline, deterministically, WITHOUT running the target.",
        "",
        f"Target sha256: {meta.get('target_sha256')}    arch: {meta.get('arch')}",
        "",
        "WHAT THIS IS",
        "  Proof that a secret (credential / key / token) is baked into the binary. Anyone can",
        "  independently recover it from target.bin alone -- no execution, no fuzzing, no this",
        "  tool. That extractability IS the vulnerability (CWE-798 / CWE-321): the secret ships",
        "  to every holder of the binary and cannot be rotated without a rebuild.",
        "",
        "HOW TO RUN  (safe -- it only reads the file; it does NOT execute the target)",
        "  $ tar -xzf <bundle>.tar.gz && cd poc && sh ./runner.sh",
        "  Success = the secret(s) below are printed back, re-derived from the binary.",
        "",
        "EXTRACTED SECRET(S)",
    ]
    for s in secrets:
        loc = ("file offset 0x%x" % s["file_offset"]) if s.get("file_offset") is not None \
            else "by content scan"
        lines += [f"  - {s.get('title')} [{s.get('cwe')}] @ {loc}",
                  f"      {s.get('value')}"]
    lines += [
        "",
        "FILES",
        "  target.bin   - the exact analyzed binary (self-contained)",
        "  secret.txt   - the extracted secret(s), human-readable",
        "  secrets.json - machine-readable: value, cwe, file offset",
        "  extract.py   - re-derives the secret(s) from target.bin (the reproducer)",
        "  runner.sh    - runs extract.py for you",
        "  meta.json    - target hash, arch, tool version",
        "",
        "REMEDIATION",
        "  Remove the secret from the source; load it at runtime from a secrets manager or",
        "  an operator-supplied config/env; rotate the exposed credential immediately.",
        "",
        "Authorized use only.",
    ]
    return ("\n".join(lines) + "\n").encode()


def build_secret(target_bytes: bytes, secrets: list, meta: dict) -> bytes:
    """Bundle a hard-coded-secret PoC: the binary, the extracted secret(s), and a pure-stdlib
    offline re-extractor that proves the credential is embedded (no target execution).

    `secrets` = [{value, cwe, title, severity, file_offset|None}] (verified re-extractable).
    """
    txt = ["Hard-coded secrets extracted from the target binary", "=" * 51, ""]
    for s in secrets:
        loc = ("file offset 0x%x" % s["file_offset"]) if s.get("file_offset") is not None \
            else "content scan"
        txt += [f"{s.get('title')} [{s.get('cwe')} / {s.get('severity')}]  ({loc}):",
                f"    {s.get('value')}", ""]
    secrets_json = [{"value": s["value"], "cwe": s.get("cwe"), "title": s.get("title"),
                     "severity": s.get("severity"), "file_offset": s.get("file_offset")}
                    for s in secrets]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        _add(tar, "poc/target.bin", target_bytes, mode=0o755)
        _add(tar, "poc/secret.txt", ("\n".join(txt)).encode())
        _add(tar, "poc/secrets.json", json.dumps(secrets_json, indent=2).encode())
        _add(tar, "poc/extract.py", _EXTRACT_PY.encode(), mode=0o755)
        _add(tar, "poc/runner.sh",
             (b'#!/bin/sh\n# Re-extract the embedded secret(s). Reads the file only; does not '
              b'execute it.\ncd "$(dirname "$0")"\npython3 ./extract.py ./target.bin\n'),
             mode=0o755)
        _add(tar, "poc/meta.json", json.dumps(meta, indent=2, sort_keys=True).encode())
        _add(tar, "poc/README.txt", _secret_readme(meta, secrets))
    return buf.getvalue()
