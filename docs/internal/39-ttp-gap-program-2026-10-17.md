# The TTP gaps doc 38 did not cover (2026-10-17)

Doc 38 closed an ordered list of heap and FSOP techniques. This one starts from a different
question -- *what is missing across the whole platform, not just the heap catalogue* -- and was
built from a survey of what is actually in the tree (`exploit_stage`'s strategy dispatch, `rop.py`,
`heap.py`, the `aaheg` catalogue, `injection.PROBES`, the conformance cases), not from a textbook
list. The survey's first result was that the tree is broader than doc 38 claimed: SROP, BROP
partial-overwrite, ret2csu, ret2dlresolve, one-gadget, ORW/seccomp, House of Apple 2, House of Cat,
setcontext, mprotect-shellcode and cross-arch ret2libc are all real and gated.

What follows is what was not.

## The cheap ones: primitives we already produce, bridged to effects we already demonstrate

### 1. `environ` -> a stack address -- DONE

**The gap.** Arbitrary read existed in three forms and `environ` was already in
`rop._LEAK_ANCHOR_SYMS`, but only as a *corroborating anchor* for a libc base. Nothing read
`libc_base + environ` to obtain a STACK address, so an arbitrary read whose process had no
reachable heap target had nowhere to go.

**Built.** `rop.exec_range`/`is_return_site`/`libc_symbol_ranges`/`saved_return_slots`/
`main_return_images`/`build_stack_ret2libc`/`environ_stack_targets`, and a `stack` plan in
`leak.indexed_write_fsop` -- tried LAST, so every existing plan's measured behaviour is byte for
byte unchanged.

**Measured, not read:**

* A saved return address is told from a code pointer that merely lives in a local by **the bytes
  BEFORE it decoding as a `call`**. Nothing about register allocation or frame layout changes that.
  8/8 positives and 6/6 negatives against objdump on a real build.
* Main's saved return address points into `__libc_start_call_main`, which **no libc exports**. It
  is identified NEGATIVELY: the first libc code pointer below `environ` that is not inside
  `__libc_start_main` (exported, with its size). The two libc return addresses above main's both
  belong to frames that are never returned from -- `__libc_start_main` calls
  `__libc_start_call_main`, which is noreturn. Measured at -0x130 below `environ`'s value.
* The walk stops at 0x400 bytes. Deeper slots are the frames of whatever is reading our input, and
  a chain written there is scribbled over by the next `printf` before that frame ever returns --
  seen as a write that did not read back and a process dead at the trigger.
* The chain must be written at **both rsp parities**: `system`'s prologue has a `movaps`, and one
  parity segfaults (-11) while the other spawns a shell.

**Gate.** `environ_saved_return` -- the same unbounded index, on a program that has closed stderr
(so `_IO_un_link` took the FILE the other plans forge off `_IO_list_all`) with a 512-byte table
(under House of Cat's 0x390). On that fixture the setcontext plan's 9 cells all land and the
trigger does nothing, the system plan's 5 do the same, House of Cat is excluded for room -- and the
stack plan spawns a shell. **PASS L3 in 36s**; the generated bundle reproducer re-derives the slot
and pops a shell standalone under full ASLR.

### 2. The SSP / `argv[0]` read oracle -- a MEASURED REFUSAL, not a build

**The gap as stated.** Overwrite `argv[0]` with a pointer and let `__stack_chk_fail` print
`*** stack smashing detected ***: <argv[0]> terminated` -- an arbitrary-read oracle that exists
precisely on canary-on targets, which is where leaks are hardest.

**It is dead.** glibc dropped `__libc_argv[0]` from that message. Measured two ways rather than
asserted from a version: the message printed by a live overflow is
`*** stack smashing detected ***: terminated` on **both** the host's glibc 2.43 and the cached
glibc 2.35, and the format string in each libc's bytes is `*** %s ***: terminated\n` -- **one**
conversion, where the trick needs two (the reason, then the program name).

**Built instead.** `rop.ssp_leak_feasible(libc_data)`, which decides it from the libc's own bytes
by counting the conversions in `__fortify_fail`'s format string, and says UNKNOWN when handed no
libc rather than defaulting to the historical answer. Same philosophy as `heap.guard_sites`: never
assert a libc capability from a version number.

### 3. The canary, brute-forced against a forking server -- DONE

**The gap.** `brop.py` bruted the randomised PIE nibble but had no canary brute, so a forking
server with `canary=on` capped below the BROP machinery sitting next to it. The dispatch said so in
a comment: *"PIE + CANARY: the leak-free partial-overwrite / BROP paths below cannot work -- the
canary must be leaked and written back."* For a one-shot process that is true. For a forking server
it is exactly backwards.

**Why it is backwards.** The canary is generated once, at the PARENT's TLS setup, and every forked
child inherits it -- exactly as every child inherits the parent's ASLR layout. So the same
crash-vs-survived oracle BROP uses to read a saved return address reads the CANARY a byte at a
time: a wrong byte aborts in `__stack_chk_fail` and the handler's post-return reply never arrives.
7 x 256 connections at worst, and glibc's own NUL low byte gives one of the eight away.

**Built.** `brop.brute_canary`, `brop.brute_frame`, `brop.canary_pad`,
`brop.calibrate_survive_token`, a `pad` parameter on `candidate_overwrites`/`brute_ret2win`, and a
canary branch in `_pie_brop_server_exploit` -- which now runs BEFORE the stdin-driven canary
weaponizer, because that one would spend its whole budget timing out against a process blocked in
`accept()`.

**Measured, not read:**

* **The saved return address's slot cannot be probed for.** "The first word past the canary whose
  corruption crashes the child" is the saved RBP, not the return address: a wild rbp makes `leave`
  set rsp from garbage and the child dies too. Measured at 80 when the real answer was 88, and the
  partial overwrite silently missed. It has to be found by READING past the canary and telling the
  two apart by CONTENT -- a stack pointer vs a main-image code pointer -- which the byte-at-a-time
  read gives for free, because it writes the canary back as it accumulates.
* **The survival oracle cannot key on a literal.** `make_survive_oracle`'s `b"OK"` default was the
  test fixture's own reply. `calibrate_survive_token` reads whatever the server answers to a
  harmless probe, and the path declines when the server answers nothing -- otherwise every
  connection looks like a crash and the brute reports the first byte it tried.
* **A canary cannot be baked into a reproducer**: a re-spawned server has a different one. The
  reproducer re-runs the byte-at-a-time read, which is the exploit anyway.
* The control that matters is flipping one byte of the canary we wrote back. It spawns no shell,
  which is what proves the recovered canary was load-bearing.

**Timings on the fixture:** canary recovered in 1.4s; the full frame read (canary + rbp + return
address, 32 bytes) in 97s; the leak-free 1-byte partial overwrite to `win()` in 1.2s.

**Gate.** `forking_server_canary_brute` -- **PASS L3 in 252s, `pie=on can=on`,
`build_exploit/CWE-121`** -- and it is the FIRST gate case to drive the forking-server BROP path at
all, canary or not. Those paths had only ever had unit tests. One thing the run surfaced on the
way: `synthesize_injection` wedges on a forking-server target and has its lease reclaimed, which
costs the run time but not the verdict.

## 4. Shellcode craft -- DONE

`shellcode.py` was 45 bytes of `execve` plus a bad-char encoder. Two real failure modes had no
answer at all, and the encoder turned out not to work for the commonest constraint there is.

**`egg_hunter` / `egg` (48 bytes).** For a target whose EXECUTABLE buffer is too small but which
holds a larger copy of our input somewhere else -- an environment variable, argv, a heap copy of a
file. The hunter goes in the small one and the payload in whatever has room, with no address known
to either side. Measured finding a payload at 0x100, 0x4000 and 0x100000 bytes, and declining when
the tag is broken. Two details were measured rather than read:

* the walk starts at `lea rdx, [rip]`, not at 0. From the bottom of the address space it is one
  `access()` syscall per page across 47 bits and it never arrives -- the first version hung.
* the probe is `access(rdx + 8, 0)`, not `access(rdx, 0)`. The comparison reads EIGHT bytes
  (`scasd` twice), so a window whose first byte is on a mapped page and whose last is not faults
  even though the probe passed. Seen as a SIGSEGV at exactly the distance where the scan crossed
  into unmapped memory. Probing the window's END covers both pages in one syscall, because the walk
  only ever enters pages it has already validated.

`access` is the probe rather than a SIGSEGV handler because its -EFAULT return reports an unmapped
page WITHOUT taking a signal, so the hunter leaves the target's own handlers alone.

**`find_socket_execve_binsh` (82 bytes) / `dup2_execve_binsh` (40).** `execve_binsh` alone is
useless on a network target: the shell inherits the service's stdio, which goes to a log or
/dev/null, and nothing reaches the attacker. The usual alternative is a reverse shell, which needs
outbound egress -- and could not be verified by this repo's own standard, since the sandbox runs
with `net=False`. `getpeername(fd)` returning 0 is the test, and it is the right one: it succeeds
only on a socket that HAS a peer, so a LISTENING socket fails it (ENOTCONN) and so does every file,
pipe and tty (ENOTSOCK). Measured walking 0, 1, 2 (ENOTSOCK), 3 (EBADF -- the listening socket the
child closed) and finding 4; shell over the connection; int3 control at the same length fails.

**`encode_avoiding` rewritten.** Three choices, each forced by a banned set defeating the obvious
one:

* the `jmp`/`call`/`pop` get-PC replaces `lea rsi, [rip+N]`. A forward RIP-relative reference has
  only a disp32, so it wrote three NUL bytes into the decoder's own displacement -- and
  `exploit_stage` asks for exactly `{0x00, 0x0a}` ("a line reader stops at NUL / newline") at a
  call site that could therefore **never** succeed. A backward `call` is a small negative disp32,
  which is 0xff bytes and no NULs, and its pushed return address IS the payload's address.
* `dec dl; jnz` replaces `loop`. `loop` needs the whole of rcx zeroed first, and every short way to
  zero it (`xor ecx,ecx`, `sub ecx,ecx`) encodes ModRM 0xc9 -- which HTB execute's banned set, the
  one real set this module was built against, bans.
* the loop body takes 0-3 filler bytes, searched alongside the keys, because even then the `jnz`'s
  own displacement came out 0xf6, also banned. **A stub with fixed bytes is only ever LUCKY with
  respect to a banned set; searching a small variant space is what makes it robust.**

Plus a 4-byte rolling key as a fallback, and the `push imm8` length load is gone: it SIGN-EXTENDS,
so a payload of 128 bytes or more set rcx to ~2^64 and the decode loop ran over the address space.

Measured: all four stubs now encode against `{NUL,LF}`, a line-reader set, HTB and HTB+NUL+LF;
`{NUL,LF}` was previously impossible for every payload. Both decoders and the hunter are proved by
EXECUTION. The honest remaining limit is the stub's own fixed alphabet -- against a random 40-byte
banned set the dominant outcome is still "no encoding", and no key or padding can move those bytes.

**Not built, with reasons.** A reverse shell: unverifiable under `net=False`, so it could only be
claimed, not demonstrated. An alphanumeric/printable-only encoder: not reachable as an extension of
this design, since the XOR stub's own bytes are non-printable -- it needs a sub-encoder, which is
its own piece of work.

## 5. Kernel -- what is possible here, measured

Two facts bound this item, both measured on the host rather than assumed:

* **there is no kernel build tree** (`/lib/modules/$(uname -r)/build` does not exist), so a
  planted-bug module cannot be compiled -- which means no conformance fixture, by the same logic
  that makes every other case in the gate possible;
* **`qemu-system-*` is not installed**, so no kernel can be booted. Every dynamic rung is therefore
  out of reach: no ret2usr, no kROP, no `modprobe_path`, no heap spray, because none of them can be
  *run*, and this platform's standard is a demonstrated effect.

So the honest scope is static, and the finding was that lykos could not see a kernel module at all.
Measured on two real modules from this host (`binfmt_misc.ko`, `test_bpf.ko`):

| | before | after |
|---|---|---|
| imports reported | **0** | 65 / 51 |
| exports reported | **0** | 4 / 6 |
| call sites recovered | **0 named** | 163 / 902, exact |
| `relro` / `bind_now` | `off` (fabricated) | `unknown` |

Three things were wrong, and each is plumbing rather than analysis -- the usual shape:

1. **Imports came only from `.dynsym`.** An ET_REL object has none; its external references are
   UNDEFINED entries in `.symtab`. Every import-gated detector and every injection probe keys on
   `imported_symbols`, so a `.ko` was silently invisible to all of them.
2. **`relro` and `bind_now` were reported as `off`.** They are properties of a LINK, and a
   relocatable object has not been linked -- it has no program headers, so there is no
   `PT_GNU_RELRO` to find and no `DT_FLAGS` to read. Reporting `off` states a fact about the file
   that is not in the file.
3. **The call graph is in the relocations, not the instructions.** In an unlinked object every
   external call is `call <self+5>` with a placeholder displacement; the callee's name appears only
   in `.rela.text`. Measured on `binfmt_misc.ko`: `call <scanarg+0x5>` with
   `R_X86_64_PLT32 __check_object_size-0x4` beside it. A disassembler that does not apply
   relocations loses every callee name, so each call-edge detector saw edges pointing back into
   their own function.

`elf.rel_call_sites` reads them directly -- exact, not heuristic, and needing no backend: the
relocation names the symbol, the section header names the section, `r_offset` is the byte. Verified
against `readelf` to the entry: 163/163 and 902/902. It then surfaced `_copy_from_user` at
`.text+0x13b` and `.text+0x4f9` in `binfmt_misc.ko` -- that module's actual user-input surface.

The kernel sinks added to the `DANGEROUS` catalogue are advisory severities on purpose, on the same
footing as `memcpy`: the sink is certain, the defect needs the data flow. What is different about
them is the boundary -- the argument comes from an unprivileged process, so an unvalidated length is
a privilege-boundary violation rather than a crash in the caller's own program.

## 6. App-layer injection -- three classes added, the rest refused

`injection.PROBES` had six classes. The constraint that decides what can be added is this
platform's own standard: a probe needs a NATIVE sink symbol and an OFFLINE, forgery-proof oracle.
Three classes clear it.

* **XInclude (CWE-611)** -- and it is NOT an XXE variant, which is the point. The accepted XXE fix
  is to parse without `XML_PARSE_NOENT` so a SYSTEM entity is never substituted. Measured on one
  binary built exactly that way: the entity payload came back with the entity UNEXPANDED, and
  `<xi:include href="file:///etc/passwd" parse="text"/>` returned the file. `parse="text"` is
  load-bearing -- the default `parse="xml"` tries to parse /etc/passwd AS XML and fails.
* **`wordexp` command substitution (CWE-78)** -- command execution in a binary with no `system`,
  no `popen` and no `exec*` anywhere in it, so the existing `command-injection` probe does not even
  apply. Its payload set has to be its own: measured, `$(echo MARK)` and the backtick form run,
  while the cmdi set's `; echo MARK` is REJECTED by `wordexp` as a syntax error.
* **XPath (CWE-643)** -- deliberately a CAPABILITY verdict (L2), not an effect one. The union
  payload really does disclose: on the fixture, a lookup restricted to `public` returned every
  `secret` in the document. But a probe does not know what the document holds, and XPath 1.0 gives
  an injected expression no way to make the engine emit a marker of OUR choosing -- `|` unions node
  sets and cannot introduce a literal, and there is no `document()` outside XSLT. So the oracle is
  the evaluator's own error on an unbalanced quote, which proves the string reaches the expression
  parser and which a target that binds or escapes its value never produces. Same rung, same
  reasoning, as error-based SQL injection's branch in `sqli_confirm`.

**Refused, with the reason.** SSTI, JNDI/log4shell and prototype pollution have no native sink in
this platform (Java and JavaScript territory; the JVM front-end reaches L1 and cannot execute an
attacker class). LDAP and NoSQL injection have real C sinks but no offline oracle -- both need a
live server, so a probe could only report that the sink exists, which `dangerous_api` already does.
Zip-slip has a real sink and a real oracle, but the oracle is "a file appeared outside the
destination directory", which the probe framework cannot see: it grades OUTPUT. That one is a
framework change, not a probe.

## Found on the way

**`socket_overflow` fails its bundle check, and has nothing to do with this round.** Measured
twice with this round's changes and once on a CLEAN tree at `065dc30`: identical verdict, identical
740s -- `L1 verified but the BUNDLE does not reproduce: bundle ran but exited 0 (want >=128, a
signal)`. So it is pre-existing and deterministic, not a flake and not a regression. The shape of
it: `_bundle_reproduces` reads `$?` and wants 128+signum, and this target's `main` loops forever on
`accept()`, so a `runner.sh` that returns 0 promptly means the payload never reached the handler on
replay. That is a socket-channel BUNDLE problem -- the detection half works, `net_fuzz` files
CWE-119 at L1 -- and it belongs to the bundle/replay seam, not to this programme. Diagnosing it
needs a `--keep-failed` run to open the shipped `runner.sh`.

`synthesize_injection` **wedges on a TCP-server target** and has its lease reclaimed by the
supervisor (`worker-N wedged in stage synthesize_injection ... the stuck thread is abandoned`).
Observed on two different server cases, including one run before any of this round's probes
existed, so it is pre-existing. It costs roughly 90 seconds per server case and does not change the
verdict.

## 7. The prompt-paced capture channel -- DONE

Not an exploitation technique but a DELIVERY shape, and it was capping a whole class of defect at
L1 regardless of how good the technique catalogue was. A prompt-driven target reads each field with
its own `read(0, ...)`, so a bulk feed desyncs it. The campaign paced
(`fuzz.runner.run_input_prompted`) and the bundle paced (`replay_prompt.py`), but the ptrace
capture that the L2 primitive and the root-cause stage both drive had no `prompt` branch and no
`else` -- an input recorded as prompted left stdin unset, the child ran with no input, and the
helper reported "no fatal signal". A real crash, a wrong setup, nothing saying so.

Fixed in `ptrace_capture.py` (paced stdin over a pipe, the child's own output as the clock),
`capture.py` (one shared `paced_chunks` split, `sweep_modes` adding `prompt` only when the input
has more than one field, `how_to_feed` reading the prompted isolation tag), with the sweep sites in
the L2 and root-cause stages wired through it. The silence is closed structurally too: an
unrecognised delivery mode is now an explicit refusal rather than a child run with no input.

`prompt_protocol_overflow` raised **L1 -> L2**, strict; measured L2 with `--ceiling`
(`primitive/CWE-119` + `chain_primitive/CWE-787`, 137s). L3 is a different seam: the exploit
recipes frame their chain through `_measured_frame` as one blob, so weaponizing a prompt protocol
needs that framing to pace too, which this case does not yet assert.

## 8. The exit-handler route -- identification and verdict built; the live L3 scoped

`exit()` walks a registered list of handlers and calls each -- the one control-flow endpoint the
engine did not model, since every other route it has lands through stdio (FSOP) or a saved return
address. A write-what-where that reaches the handler list is a fourth way to turn a write into a
call, and the one left when the FILE structs are unreachable.

Built this round, as the location + verdict layer (the same shape as the large-bin and
tcache-stash verdicts -- read from the libc's bytes, UNKNOWN without them):

* `rop.exit_handlers_targets(libc_data)` -- locates `__exit_funcs` from `exit`'s own RIP-relative
  `lea` (anchored on the exported `exit` symbol, no backend), and reports the `exit_function`
  struct layout. Cross-libc differential: `libc+0x1e7680` on 2.43, `libc+0x21a838` on 2.35, read
  from each rather than hardcoded.
* `rop.guard_demangle_sites(libc_data)` -- counts the `ror 0x11; xor fs:0x30` demangle, so the
  pointer-guard precondition is measured (37 sites on 2.43, 31 on 2.35), not assumed from a
  version.
* `aaheg.exit_handlers_verdict(env)` -- the conditional verdict: located, guarded, the precondition
  (an arbitrary read to recover the guard, which these write-what-where primitives arrive with),
  and the emitted shape. Surfaced in `plan_exploit` as a write->CALL consumer for the control-flow
  goal, a peer of the FSOP helpers. UNKNOWN without libc bytes.

Why it stops at a verdict rather than a push-button L3: every handler flavor stores its function
pointer under glibc's pointer guard, so the route is not an overwrite-with-an-address. It needs the
guard recovered first, and a working chain is therefore its own design with its own negative
controls -- worth doing deliberately against a planted-bug fixture where `exit()` is the only
reachable endpoint, rather than bolted onto an existing case. That is the remaining piece; the
identification and the honest verdict are what landed.

Tested in `tests/test_exit_handlers.py` (8), the same way `test_largebin.py` tests the other
measured verdicts: located-from-bytes, the cross-libc differential, the guard count, and
UNKNOWN-without-bytes.

## Still to do in this programme
9. **Zip-slip / archive extraction traversal.** It has a real native sink (libarchive) and a real
   oracle, but the oracle is a FILESYSTEM effect and the probe framework grades output. Closing it
   means giving a probe a filesystem oracle, which is a framework change worth doing on its own.
10. **An alphanumeric / printable-only encoder.** Not reachable by extending `encode_avoiding`: the
   XOR stub's own bytes are non-printable, so it needs a sub-encoder.

## Noted but deliberately not built

* **House of Apple 1/3** -- only needed when the FSOP route we have is blocked, and House of Apple
  2 + House of Cat + setcontext already cover the reachable shapes.
* **`tcache_perthread_struct`** -- an amplifier on tcache poisoning, not a way in.
* **ret2vdso** -- `_execve_rop_exploit` already handles the static-binary case it would serve.
* **JOP/COP** -- matters against CFI / no-`ret` binaries, and nothing in the corpus produces those.
* **Windows is structurally capped, not merely unimplemented.** `substrate.py` is explicit: PE
  dispatches to wine, which AFL cannot instrument and whose `wineserver` our ptrace supervision
  cannot follow (`batchable=False`). SEH overwrite and DLL search-order hijack need that
  supervision problem solved first, not the techniques written.
* **ARM hardening** -- PAC is nop'd in the fixtures rather than defeated; BTI and MTE unmodelled.

## The ROP catalogue, driven to L3 (and two measured ceilings)

The gate proved the core ROP/exploitation techniques at L3 but had no dedicated L3 case for five
named variants that existed only as autopilot strategies + unit tests. Research
(ir0nstone, HackTricks, the SROP paper, the glibc 2.34 CSU hardening, one_gadget docs) pinned down
the canonical shape of each; the result:

**Gate-proven at L3 this round** (fixtures that force each as the only route):
* `srop_execve_plant` -- SROP, L3. read() delivery (not scanf, which can't carry a binary
  sigreturn frame), static + no system + no "/bin/sh" + NX, so the auto dispatch falls through to
  SROP's forge-frame / plant-"/bin/sh" / execve path.
* `orw_seccomp_disclose` -- ORW, L3. A seccomp filter kills execve, so a shell finisher SIGSYSes
  and the only L3 route is an open/read/write disclosure of a planted-marker file.
* `ret2dlresolve_nolibc` -- ret2dlresolve, L3. No system PLT, no "/bin/sh", no leak; forge
  Rela/Sym/string in a >=0x100 .bss and resolve system() through the loader. Needs the pop gadgets
  in-image (glibc 2.34 removed the CSU gadgets a minimal binary used to supply), so the fixture
  carries an explicit gadget block.

**Two measured ceilings** -- correctly implemented, version/architecture-sensitive, and honestly
not gate-forceable on this host:
* **one-gadget is dead on glibc 2.43.** `rop.find_one_gadgets` matches the classic
  `lea rdi,[rip->"/bin/sh"]` -> execve single-jump pattern; measured, it finds **1** on the cached
  glibc 2.35 and **0** on the host's 2.43. A genuine glibc evolution (the pattern matches on 2.35,
  so it is not a stale finder), the same shape as "no fastbins on 2.43". The finisher is wired into
  the libc-leak path and tried opportunistically; on 2.43 it yields nothing, so system("/bin/sh")
  is the finisher that fires. Not a gap -- a fact about the libc.
* **ret2csu is structurally subsumed on x86-64.** The technique needs the CSU_POP gadget
  (`5b 5d 41 5c 41 5d 41 5e 41 5f c3`) to load r12-r15 before the CSU_CALL. That byte string ends
  in `41 5f c3`, whose `5f c3` tail IS a `pop rdi; ret` -- so every binary carrying the ret2csu
  gadgets also carries a pop-rdi gadget, and ret2csu additionally requires the same `system` + 
  "/bin/sh" that plain ret2system does. The autopilot therefore always prefers ret2system, and
  ret2csu can never be the minimal route a fixture forces. This is the concrete mechanism behind
  the write-ups' verdict that ret2csu is "irrelevant in the real world", and glibc 2.34 removed the
  CSU gadgets outright. It stays as an explicit-strategy last resort; it is not auto-gate-forceable.

**Not a regression, cleared by a controlled test:** the full 108-case run showed `stack_pivot_shell`
and `addr_leak_pie_ret2win` at L2, but both reach L3 in isolation (stack_pivot at 104s vs 172s
under full-gate load). The drop was budget pressure under whole-run load, not broken code -- and
`sweep_modes` was hardened (prompt capture is now a recorded-mode channel, not guessed from a 0x0a
byte in the payload) to cut the avoidable per-detonation cost that aggravated it.

## 2026-10-18 -- `addr_leak_pie_ret2win` WAS broken, not budget pressure (correction)

The line above was wrong about `addr_leak_pie_ret2win`. Driven in isolation and sampled 3x (not
once), the case was a DETERMINISTIC L2 at HEAD, not a load artefact -- and the cause was three
independent defects on the binary out-of-bounds-READ path, each of which alone caps the case.
Measured end to end: with all three fixed the autopilot reaches L3 unaided from the stripped PIE
3/3 (182s/184s/183s); with any one reverted it falls back to L2.

1. **`_distinct_crashes` collapsed two distinct defects.** A fuzzer's batch runner stores a crash
   with the signal but **no fault PC**, so the `dump=<N>` over-read (which faults inside the
   program's own `memcpy`) and the `name=` stack smash (a write) both keyed as `(SIGSEGV, None)`
   and only ONE survived dedup -- non-deterministically, and usually the write. The read that
   carries the ASLR defeat never reached the primitive stage. Fix: `orchestrate._recover_missing_
   fault_pcs` re-captures an **in-image** fault PC (relativised to the load base from `maps`) for
   the stdin crashes in a genuinely colliding bucket, so the two defects split. Hijack/libc PCs
   are left None on purpose, so a single stack smash still collapses instead of fanning out.

2. **`address_primitive` discarded the verdict on a poisoning sibling.** `_address_verdict` folds
   sibling crashes in as free observations; a `name=` hijack sibling faults a page away, and the
   `len({pc>>12}) != 1` guard then threw the whole read verdict away (`faulted: 8, verdict: null`).
   Fix: anchor to the BASE crash's own fault page and judge those observations; off-page siblings
   are a different defect answering a different question.

3. **The disclosure never steered the index to zero.** The `dump=<N>` lever is a DECIMAL field,
   which cannot isolate as a single-byte lever (a flipped digit re-parses to a different number),
   so `offset` is None and `_address_disclosure` tried only the crashing input -- `dump=99`, far
   out of bounds, which faults again and discloses nothing. Fix: steer each numeric field toward
   zero (`_DISCLOSE_DECIMALS`); `dump=0` reads just off the 64-byte object into the neighbour
   chunk, `leak.disclosed_bases` resolves the PIE and libc bases with ASLR on, and `build_exploit`
   relocates `win` and pops the shell.

Regression-checked across the dedup-sensitive cases (double_free, heap_uaf_read, argv_overflow,
indexed_read_l2, prompt_protocol_overflow, stripped_opt_overflow, heap_fnptr_system,
multicall_dispatch): all still pass at their levels, no hijack fan-out. The lesson for the record:
"reaches L3 in isolation" was asserted from single runs; 3x sampling showed it was deterministic
L2, and the budget-pressure story masked three real bugs. Gate conclusions are now 3x-sampled.
