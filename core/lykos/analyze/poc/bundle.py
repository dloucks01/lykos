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
            main_class: str | None = None, sanitizer: str = "", retries: int = 0,
            marker: str = "") -> bytes:
    argv = list(argv or [])
    placed = INPUT_PLACEHOLDER in [str(a) for a in argv]
    # A jar is not executable and the JVM is not the target: `./target.bin` is a zip file, and
    # the reproducer has to name the runtime that reads it.
    exe, setup = "./target.bin", "chmod +x ./target.bin\n"
    if sanitizer:
        # A sanitizer build does not die on a signal by DEFAULT: ASan prints its report and calls
        # _exit(1). The capture and the fuzzers set `abort_on_error=1` so the fault is a SIGABRT,
        # and the bundle has to set it too -- otherwise the operator who unpacks this runs the
        # reproducer, gets exit 1 where the README says 134, and concludes the PoC is broken.
        # `detect_leaks=0` keeps LeakSanitizer's at-exit report from standing in for the defect.
        setup += 'ASAN_OPTIONS="abort_on_error=1:detect_leaks=0"; export ASAN_OPTIONS\n'
    if runtime == "jar":
        exe, setup = "java -jar ./target.bin", ""
    elif runtime == "class":
        # The JVM resolves a class by FILE NAME, so `target.bin` cannot be run as-is: it has
        # to be put back under the name the class declares.
        cls = (main_class or "Main").replace("/", ".")
        exe = f"java -cp . {shlex.quote(cls)}"
        setup = f"cp ./target.bin ./{shlex.quote(cls.rsplit('.', 1)[-1] + '.class')}\n"
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
    elif mode == "prompt":
        # One field per prompt, paced by the shipped script. `< input.bin` is wrong here for the
        # reason in `_PROMPT_REPLAY`: `read` takes whatever is available, so a bulk feed puts
        # field two's bytes inside field one and the target rejects them at its first gate.
        invoke = f'python3 ./replay_prompt.py {exe}' + (" " + pre if pre else "")
    elif mode == "socket":
        # A socket PoC cannot be a one-liner: the input only exists after the server is listening,
        # so the reproducer has to spawn the target, find its port and connect. Without this an
        # env/socket bundle ran the target with no input and demonstrated nothing.
        invoke = f'python3 ./replay_socket.py {exe}' + (" " + pre if pre else "")
    elif mode == "env":
        # The input is an ENVIRONMENT VARIABLE's value, and the variable's name rides along as a
        # "NAME=@@" argv prefix element (how env_fuzz records it). Export it from the file and drop
        # the placeholder from the command line -- without this an env-mode bundle ran the target
        # with no input at all and demonstrated nothing.
        from .capture import env_var_from_argv
        var, rest = env_var_from_argv(argv)
        pre = _argv_text(rest, carrier="./input.bin")
        if var:
            invoke = (f'{var}="$(cat ./input.bin)" {exe}' + (" " + pre if pre else ""))
        else:
            invoke = f'{exe}{" " + pre if pre else ""}'
    else:
        invoke = f'{exe}{" " + pre if pre else ""}'
    if runtime in ("jar", "class"):
        # A JVM fault is an uncaught exception on stderr and an exit code of 1, not a signal.
        # Telling the reader to look for 128+signum would have them conclude the reproducer
        # failed when it worked.
        hint = (f'echo "exit status: $rc -- {signal_name} appears on stderr above as an '
                'uncaught exception; the JVM exits 1 (or 3 on OutOfMemoryError)"')
    elif sanitizer:
        hint = (f'echo "exit status: $rc -- the {sanitizer} report is on stderr above; with '
                'abort_on_error=1 (exported by this script) the process dies on SIGABRT, '
                'so 134 is the expected status"')
    elif run_cmd:
        # A script reproducer (a shell-spawning exploit / a live leak) reports its OWN outcome;
        # "a crash shows as 128+signum" is wrong for it and made an L3 bundle read as a crash.
        hint = ('echo "exit status: $rc -- the reproducer above prints whether it succeeded '
                '(a spawned shell / hijacked control), not a crash code"')
    else:
        hint = (f'echo "exit status: $rc (a crash by {signal_name} shows as 128+signum, '
                'e.g. 139=SIGSEGV)"')
    if retries > 1 and marker:
        # A CONCURRENCY defect does not reproduce on demand: the detector reports what the
        # scheduler happened to show it. A one-shot script therefore demonstrates nothing on the
        # runs where the interleaving does not happen, and the operator -- who runs it once --
        # concludes the finding is false. So loop, stop at the first run that REPORTS (the
        # marker is the detector's own line, not an exit code: a sanitizer's exit status is the
        # detector's, and other things exit non-zero too), and say what the rate was.
        return ("#!/bin/sh\n"
                f"# PoC reproducer for a CONCURRENCY defect. Expected result: {signal_name}.\n"
                f"# It is NON-DETERMINISTIC: this script makes up to {retries} attempts and stops\n"
                "# at the first one that reports. RUN IN A SANDBOX/VM -- this executes an\n"
                "# untrusted binary. Authorized use only.\n"
                'cd "$(dirname "$0")"\n'
                f"{setup}"
                f"attempts={retries}\n"
                "i=1\n"
                "rc=1\n"
                "while [ $i -le $attempts ]; do\n"
                f"  {invoke} > ./run.out 2> ./run.err\n"
                "  rc=$?\n"
                f"  if grep -q {shlex.quote(marker)} ./run.err 2>/dev/null; then\n"
                '    echo "reproduced on attempt $i of $attempts"\n'
                "    cat ./run.err\n"
                "    exit $rc\n"
                "  fi\n"
                "  i=$((i+1))\n"
                "done\n"
                'cat ./run.err\n'
                f'echo "did NOT reproduce in $attempts attempts -- a concurrency defect depends '
                f'on the scheduler, so try more attempts, a loaded machine, or a different core '
                f'count before concluding anything"\n'
                "exit 1\n").encode()
    return ("#!/bin/sh\n"
            f"# PoC reproducer. Expected result: {signal_name}. RUN IN A SANDBOX/VM --\n"
            "# this executes an untrusted binary. Authorized use only.\n"
            'cd "$(dirname "$0")"\n'
            f"{setup}"
            f"{invoke}\n"
            'rc=$?\n'
            # A target's last write often has no trailing newline, which ran the verdict onto the
            # end of the program's own output ("...\xa6h\xe0 Uexit status: 139").
            'printf "\\n"\n'
            + hint + "\n"
            # Propagate the reproducer's status. Ending on `echo` made runner.sh exit 0 ALWAYS, so
            # the one machine-readable thing a bundle has said "clean" for a reproducer that had
            # just segfaulted: measured on `replaceme`, where the script printed "exit status: 139"
            # and `sh ./runner.sh; echo $?` printed 0. Anything gating on the reproducer -- an
            # operator's CI, a triage script, our own end-to-end check -- read the wrong answer.
            'exit $rc\n').encode()


def _race_marker(prim: dict) -> str:
    """The detector's own report line for this class, which is what the looping reproducer greps
    for. Not an exit code: a sanitizer's status belongs to the detector, and plenty of other
    things exit non-zero."""
    cls = str((prim or {}).get("sanitizer_class") or "").replace("-", " ")
    return f"ThreadSanitizer: {cls}"


def _primitive_txt(prim: dict) -> bytes:
    # An L2 IP-control primitive carries a sentinel address and the observed faulting PC; an L3
    # WORKING-EXPLOIT primitive (ret2win, ret2csu, execve, srop, a partial overwrite) carries
    # neither. Forcing the L2 template onto an L3 printed "Sentinel: 0x0 / Observed PC: 0x0" for a
    # confirmed exploit -- meaningless and misleading -- so each is described as what it is.
    # An out-of-bounds ACCESS primitive has no control offset and no sentinel: nothing about it
    # is a jump. Printing "Control offset: None / Sentinel: 0x0" under an L2 heading would be the
    # same defect the comment above describes, one class further on, so it gets its own template
    # stating the magnitude the sanitizer measured and the experiment that bounded it.
    if prim.get("race"):
        lines = [
            "L1 reproducer for a NON-DETERMINISTIC defect",
            "=" * 43,
            f"Primitive: {prim.get('type')}",
            f"Sanitizer class: {prim.get('sanitizer_class')}",
            f"Reproduction rate: {prim.get('hits')} of {prim.get('runs')} runs of the SAME "
            f"input ({prim.get('rate')})",
            f"Reproducer attempts: {prim.get('retries')} (runner.sh loops; it stops at the "
            f"first run that reports)",
            "",
        ]
        w = prim.get("widening")
        if w:
            lines += [
                "WINDOW WIDENING: the rate is the attacker's to raise.",
                f"  input variant     {w['variant']}",
                f"  widened rate      {w['hits']}/{w['runs']} ({w['rate']}) against a baseline "
                f"of {w['baseline_rate']}",
                f"  chance under the baseline rate   {w['p_value']} (exact one-sided binomial)",
                "  input.bin in this bundle IS that variant, not the baseline input.",
                "  The baseline rate is an 8-sample estimate, so this is a directional result.",
                "",
            ]
        elif prim.get("widening_trials"):
            lines += [
                "WINDOW WIDENING: attempted and NOT shown. No input variant reported often",
                "enough to be surprising at the baseline rate, so the rate is not shown to be",
                "the attacker's to raise -- the defect still needs retries. Variants tried:",
            ]
            for t in prim["widening_trials"][:6]:
                lines.append(f"  {str(t.get('variant'))[:28]:28s} -> {t.get('hits')}/"
                             f"{t.get('runs')}")
            lines.append("")
        lines += [
            f"Accesses: {', '.join(prim.get('accesses') or []) or '(not stated)'}",
            f"Object: {prim.get('location') or '(not stated)'}",
            "Sites (a race has more than one -- naming one describes half the defect):",
        ]
        for site in (prim.get("race_sites") or []) or ["(not symbolized)"]:
            lines.append(f"  {site}")
        lines += [
            "",
            "What this does NOT claim: what the race CAUSES. That depends on what the",
            "unsynchronised value is used for, and this stage does not determine it. Nothing",
            "here is an exploitation primitive, which is why this is an L1 and not an L2.",
            "",
            "Per-run outcome (the evidence for the rate above):",
        ]
        for o in (prim.get("observations") or [])[:12]:
            lines.append(f"  {str(o.get('variant'))[:10]:10s} -> "
                         f"{'reported' if o.get('reported') else 'silent'}")
        lines.append("")
        return ("\n".join(lines)).encode()
    if prim.get("quantity"):
        # A QUANTITY defect: no access, no dead object, and deliberately no L2 heading. What the
        # experiment bounded is a number, and the template says which number and what it means.
        controlled = bool(prim.get("confirmed"))
        lim = (f"  ({prim.get('quantity_limit_name')}: {prim.get('quantity_limit')})"
               if prim.get("quantity_limit") is not None else "")
        lines = [
            "L1 reproducer with a measured magnitude",
            "=" * 39,
            f"Primitive: {prim.get('type')}",
            f"Sanitizer class: {prim.get('sanitizer_class')}",
            f"{str(prim.get('quantity_name') or 'value').capitalize()}: "
            f"{prim.get('quantity_min')}..{prim.get('quantity_max')}{lim}",
            f"Attacker-controlled magnitude: {controlled}",
            f"Effect: {prim.get('effect_kind')} ({prim.get('effect_status')})",
            "",
            f"What this is: {prim.get('meaning')}.",
            "",
            "This is NOT an L2 exploitation primitive and does not claim to be: nothing here",
            "controls the instruction pointer or writes to a chosen address. The claim is the",
            "magnitude and who picks it.",
            "",
        ]
        if prim.get("effect_status") != "demonstrated":
            lines += ["The sanitizer PREVENTED the consequence (it intercepted the call, or the",
                      "access is undefined rather than performed), so the effect is recorded as",
                      "potential: what a build without the sanitizer would do is an inference.",
                      ""]
        if prim.get("observations"):
            lines.append("Input variants detonated (the evidence for the line above):")
            for o in prim["observations"][:10]:
                lines.append(f"  {str(o.get('variant'))[:28]:28s} -> {o.get('quantity')}")
            if not controlled:
                lines += ["",
                          "Every variant produced the same number, so it is not shown to be the",
                          "attacker's to pick. The defect reproduces; the degree of control over",
                          "it is unproven, and is reported so."]
            lines.append("")
        return ("\n".join(lines)).encode()
    if prim.get("lifetime"):
        # A LIFETIME defect: the object is dead, so there is no distance past its end and, for a
        # double free, no access at all. Printing the out-of-bounds template here would state a
        # magnitude about the wrong thing -- the same defect this file's comments describe twice
        # already, one bug class further on.
        controlled = bool(prim.get("confirmed"))
        cls = prim.get("sanitizer_class")
        lines = [
            ("L2 exploitation primitive" if controlled else "L1 lifetime defect"),
            "=" * (25 if controlled else 18),
            f"Primitive: {prim.get('type')}",
            f"Sanitizer class: {cls}",
        ]
        if prim.get("access"):
            lines.append(f"Access: {str(prim.get('access')).upper()} of size "
                         f"{prim.get('access_size')}")
        lines += [
            f"Freed chunk: {prim.get('region_size_min')}..{prim.get('region_size_max')} bytes "
            f"(attacker-controlled size: {bool(prim.get('size_controlled'))})",
            f"Offset inside the chunk: {prim.get('region_offset_min')}.."
            f"{prim.get('region_offset_max')} "
            f"(attacker-controlled offset: {bool(prim.get('offset_controlled'))})",
            "",
            "The three places this defect lives:",
            f"  used at      {prim.get('used_at') or '(not symbolized)'}",
            f"  freed at     {prim.get('freed_at') or '(not symbolized)'}",
            f"  allocated at {prim.get('allocated_at') or '(not symbolized)'}",
            "",
            "What this does NOT claim: ASan holds a freed chunk in quarantine, which is how the",
            "use is caught at all -- so nothing reclaimed the chunk during these runs and no",
            "overwrite of a live object was demonstrated. What the variants below show is that",
            "the defect is attacker-PARAMETERISED: the offset, or the size class, follows the",
            "input. On a build without the sanitizer the same chunk is reusable.",
            "",
        ]
        if prim.get("observations"):
            lines.append("Input variants detonated (this is the evidence for the lines above):")
            for o in prim["observations"][:10]:
                lines.append(f"  {str(o.get('variant'))[:28]:28s} -> offset "
                             f"{o.get('region_offset')} in {o.get('region_size')} bytes")
            if not controlled:
                lines += ["",
                          "Every variant touched the same offset in a chunk of the same size, so",
                          "neither is shown to be the attacker's to pick. The defect reproduces;",
                          "the degree of control over it is unproven, and is reported so."]
            lines.append("")
        return ("\n".join(lines)).encode()
    if prim.get("sanitizer_class"):
        controlled = bool(prim.get("confirmed"))
        lines = [
            ("L2 exploitation primitive" if controlled else "L1 out-of-bounds access"),
            "=" * (25 if controlled else 23),
            f"Primitive: {prim.get('type')}",
            f"Sanitizer class: {prim.get('sanitizer_class')}",
            f"Access: {str(prim.get('access')).upper()} of size {prim.get('access_size')}",
            f"Object: {prim.get('region_size')}-byte region",
            f"Distance {prim.get('side') or 'past'} the object: "
            f"{prim.get('distance_min')}..{prim.get('distance_max')} bytes",
            f"Attacker-controlled distance: {controlled}",
            "",
            "The fault is reported BY THE SANITIZER, so the process exits with a code rather than",
            "dying on a signal -- runner.sh reports that exit status, and the report itself is on",
            "stderr. Nothing here claims instruction-pointer control: this primitive is the",
            "access, and its effect is what the access does.",
            "",
        ]
        if prim.get("observations"):
            lines.append("Input variants detonated (this is the evidence for the line above):")
            for o in prim["observations"][:10]:
                lines.append(f"  {str(o.get('variant'))[:28]:28s} -> distance "
                             f"{o.get('distance')} bytes")
            if not controlled:
                lines += ["",
                          "Every variant read the same distance past the end, so the reach",
                          "was not shown to be the attacker's to pick. The defect reproduces;",
                          "the degree of control over it is unproven, and is reported so."]
            lines.append("")
        return ("\n".join(lines)).encode()
    if "marker" in prim or "observed_pc" in prim:
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
    lines = [
        "L3 working-exploit primitive",
        "============================",
        f"Technique: {prim.get('type')}",
        f"Control offset: {prim.get('offset')} bytes",
        f"Confirmed: {prim.get('confirmed')}",
        "",
    ]
    if prim.get("note"):
        lines += [str(prim["note"]), ""]
    lines += [
        "input.bin drives control flow to attacker-chosen code -- this is a working exploit, not",
        "merely a crash. meta.json records the technique and offset; runner.sh reproduces it and",
        "prints the outcome (a spawned shell / the hijack's marker output).",
        "",
    ]
    return ("\n".join(lines)).encode()


# what each level proves and what a successful run looks like
_LEVEL_MEANING = {
    "L0": "a crash reproducer -- the input makes the target fault",
    "L1": "a verified crash reproducer -- the crash is real and repeatable",
    "L2": "an exploitation PRIMITIVE -- attacker control of the instruction pointer or a "
          "memory read/write (not merely a crash); see PRIMITIVE.txt",
    "L3": "a working EXPLOIT -- control flow is hijacked to attacker-chosen code",
}


_PROMPT_REPLAY = br'''#!/usr/bin/env python3
"""Replay a crash against a PROMPT-DRIVEN target: one field per prompt.

The target reads each field with its own `read(0, buf, N)`. `read` returns whatever is
AVAILABLE, so `./target.bin < input.bin` hands the whole file to field one and field two gets
EOF -- the program then rejects the input at its first gate and the crash does not reproduce.
input.bin holds one LINE per field; this writes them one at a time and waits for the target to
consume each, which is how the campaign delivered it.

    python3 replay_prompt.py ./target.bin [args...]
"""
import subprocess
import sys
import time

exe = sys.argv[1] if len(sys.argv) > 1 else "./target.bin"
args = sys.argv[2:]
data = open("input.bin", "rb").read()
lines = data.split(b"\n")
if lines and lines[-1] == b"":
    lines.pop()

p = subprocess.Popen([exe] + args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT)
try:
    for line in lines:
        time.sleep(0.25)                 # let the target print its prompt and block on read()
        try:
            p.stdin.write(line + b"\n")
            p.stdin.flush()
        except (BrokenPipeError, OSError):
            break                        # the target is gone: that is the result we wanted
    try:
        p.stdin.close()
    except OSError:
        pass
    out, _ = p.communicate(timeout=30)
except subprocess.TimeoutExpired:
    p.kill()
    out, _ = p.communicate()
sys.stdout.write((out or b"").decode("latin-1", "replace"))
rc = p.returncode if p.returncode is not None else 0
# Exit the way a SHELL reports it, so runner.sh's "a crash shows as 128+signum" is true of this
# reproducer too -- a script with its own exit convention would make that advice wrong.
sys.exit(128 + (-rc) if rc < 0 else rc)
'''


_SOCKET_REPLAY = br'''#!/usr/bin/env python3
"""Replay a SOCKET-delivered crash: spawn the server, find the port it opens, send ./input.bin.

A socket input has no exec-time carrier -- it exists only once the server is listening -- so this
cannot be a shell one-liner the way a stdin/argv/file/env PoC can. The port is discovered by
diffing the listening set around the spawn, so no port has to be hard-coded. Authorized-use only.
"""
import socket, subprocess, sys, time

EXE = sys.argv[1] if len(sys.argv) > 1 else "./target.bin"
ARGS = sys.argv[2:]
PAYLOAD = open("./input.bin", "rb").read()


def listening():
    out = set()
    for proto, path in (("tcp", "/proc/net/tcp"), ("tcp", "/proc/net/tcp6"),
                        ("udp", "/proc/net/udp"), ("udp", "/proc/net/udp6")):
        try:
            for line in open(path).read().splitlines()[1:]:
                f = line.split()
                if len(f) > 3 and (proto == "udp" or f[3] == "0A"):   # 0A == TCP LISTEN
                    out.add((proto, int(f[1].split(":")[1], 16)))
        except OSError:
            pass
    return out


before = listening()
proc = subprocess.Popen([EXE] + ARGS, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
found = None
for _ in range(50):
    time.sleep(0.1)
    new = listening() - before
    if new:
        found = sorted(new)[0]
        break
if not found:
    proc.kill(); sys.stderr.write("server never listened\n"); sys.exit(2)
proto, port = found
print("server listening: %s port %d" % (proto.upper(), port))
try:
    if proto == "tcp":
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        s.sendall(PAYLOAD); s.close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(PAYLOAD, ("127.0.0.1", port)); s.close()
except OSError as e:
    print("send failed (%s) -- the server may already be gone" % e)
time.sleep(0.6)
rc = proc.poll()
if rc is None:
    proc.kill(); sys.stderr.write("server survived: crash did not reproduce\n"); sys.exit(1)
if rc < 0:
    print("CRASHED: killed by signal %d" % -rc); sys.exit(0)
sys.stderr.write("server exited %d without a fatal signal\n" % rc); sys.exit(1)
'''


def build(target_bytes: bytes, input_bytes: bytes, meta: dict, stderr: bytes,
          mode: str, argv, signal_name: str, primitive: dict | None = None,
          extra_files: dict | None = None, run_cmd: str | None = None,
          runtime: str = "native", main_class: str | None = None) -> bytes:
    # A sanitizer-reported fault needs a different reproducer and a different success criterion
    # from a signal; the primitive is the only thing that knows which this is.
    sanitizer = str((primitive or {}).get("sanitizer_class") or "")
    level = meta.get("level", "L1")
    if mode == "socket":                                 # the runner invokes this; ship it
        extra_files = dict(extra_files or {})
        extra_files.setdefault("replay_socket.py", _SOCKET_REPLAY)
    if mode == "prompt":
        # A prompt-protocol crash cannot be a `< input.bin` one-liner: delivered in bulk the
        # whole file lands in field one and field two reaches EOF, so the reproducer the operator
        # runs would NOT reproduce -- a verified PoC whose bundle proves nothing.
        extra_files = dict(extra_files or {})
        extra_files.setdefault("replay_prompt.py", _PROMPT_REPLAY)
    script = extra_files and "exploit.py" in extra_files
    prim_line = ""
    if sanitizer and (primitive or {}).get("race"):
        _w = (primitive or {}).get("widening")
        prim_line = (f"\nPrimitive: {primitive.get('type')} -- reported on "
                     f"{primitive.get('hits')}/{primitive.get('runs')} runs of the same input; "
                     f"runner.sh makes {primitive.get('retries')} attempts because a concurrency "
                     f"defect does not reproduce on demand."
                     + (f" The window WIDENS with the input: this bundle's input.bin is the "
                        f"variant that reported {_w['hits']}/{_w['runs']}, not the baseline one."
                        if _w else "")
                     + " See PRIMITIVE.txt.\n")
    elif sanitizer and (primitive or {}).get("quantity"):
        prim_line = (f"\nPrimitive: {primitive.get('type')} -- "
                     f"{primitive.get('quantity_name')} "
                     f"{primitive.get('quantity_min')}..{primitive.get('quantity_max')} "
                     f"(attacker-controlled={primitive.get('confirmed')}; "
                     f"{primitive.get('effect_kind')}, {primitive.get('effect_status')}). "
                     f"See PRIMITIVE.txt.\n")
    elif sanitizer and (primitive or {}).get("lifetime"):
        # A dead object has no "distance past the end": what the experiment bounded is WHERE in
        # the freed chunk the access landed and HOW BIG the chunk was.
        prim_line = (f"\nPrimitive: {primitive.get('type')} -- offset "
                     f"{primitive.get('region_offset_min')}..{primitive.get('region_offset_max')}"
                     f" inside a {primitive.get('region_size_min')}.."
                     f"{primitive.get('region_size_max')}-byte freed chunk "
                     f"(attacker-controlled offset={primitive.get('offset_controlled')}, "
                     f"size={primitive.get('size_controlled')}). See PRIMITIVE.txt.\n")
    elif sanitizer:
        prim_line = (f"\nPrimitive: {primitive.get('type')} -- "
                     f"{primitive.get('distance_min')}..{primitive.get('distance_max')} bytes "
                     f"{primitive.get('side') or 'past'} a {primitive.get('region_size')}-byte "
                     f"object (attacker-controlled distance="
                     f"{primitive.get('confirmed')}). See PRIMITIVE.txt.\n")
    elif primitive:
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
        files += ["input.bin   - the crafted input that triggers it"
                  + (" (one LINE per prompted field)" if mode == "prompt" else "")]
    if mode == "prompt":
        files += ["replay_prompt.py - delivers input.bin one field per prompt, which is how the "
                  "crash was found: fed in bulk, field one swallows the whole file"]
    files += ["runner.sh   - runs the reproducer for you",
              "meta.json   - machine-readable details (target hash, arch, offset, tool)",
              "PRIMITIVE.txt / stderr.txt - the primitive description and captured diagnostics"]
    what_success = ("the process is hijacked to the attacker-chosen code (you'll see its "
                    "marker output)" if level == "L3"
                    else f"the {sanitizer} report appears on stderr and the process aborts "
                         f"(exit 134)" if sanitizer
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
        # A concurrency verdict asks for a LOOPING reproducer, and says how many attempts its
        # own measured rate justifies. The marker is the detector's own report line, because a
        # sanitizer's exit code belongs to the detector and other things exit non-zero too.
        _race = (primitive or {}).get("race")
        _add(tar, "poc/runner.sh",
             _runner(mode, argv, signal_name, run_cmd, runtime, main_class,
                     sanitizer=sanitizer,
                     retries=int((primitive or {}).get("retries") or 0) if _race else 0,
                     marker=_race_marker(primitive) if _race else ""), mode=0o755)
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
# target. Pure stdlib so it runs on any offline box.
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
