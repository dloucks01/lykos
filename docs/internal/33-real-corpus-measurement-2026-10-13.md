# 33 — What a real corpus says, and the four defects it found (2026-10-13)

Doc 32 asked for two things first: **re-measure the breadth sample** after the budget fix, and
**synthesise a seed per detected format**. Both are done. The re-measure confirms the budget fix
on the whole sample; the seed work turned into something larger, because pointing the pipeline at
*real* software — CVE-bearing library tools built from source, not gate fixtures — found that the
seed was never the binding constraint on those targets.

Corpus (all on this host, all black-box unless stated):

| class | targets |
|---|---|
| stock utilities | `cat`, `xxd`, `readelf`, `jpegtran` — doc 32's four-binary sample |
| real CVE-bearing libraries, built here | zlib 1.2.11 (`minigzip`), bzip2 1.0.6, libtiff 4.0.3 (`tiffinfo`/`tiffcp`/`tiffcrop`), expat 2.1.0 (`xmlwf`), mupdf 1.12.0 (`mutool`) |
| black-box exploitation | 20 HTB pwn ELFs (17 distinct; x86-64 + one ARM32) |

## 1. Doc 32 item 1: the budget fix holds on the whole sample

420 s per binary, serial, same probe:

| binary | pre-fix (doc 32) | post-fix |
|---|---|---|
| `/usr/bin/cat` | 1,511 | **16,792** (86/s) |
| `/usr/bin/xxd` | 2,756 | **25,673** (126/s) |
| `readelf` | 1,473 | **12,962** (81/s) |
| `jpegtran` | **0** | **19,018** (116/s) |

The zero-execution case is fixed, not just the one binary doc 32 re-ran.

## 2. The headline: on real libraries we IDENTIFY, we do not DEMONSTRATE

Nine targets, ~170,000 executions, **zero crash-derived findings**. Every finding filed on a real
library came from `cve_fingerprint` (N-day version matching — 108 of them on libtiff 4.0.3, which
is a real capability and should not be confused with a demonstrated bug), `dangerous_api`,
`oob_index`, `tainted_deref`, `stack_frame` or `chain_primitive`. `mutool` and the `xmlwf` wrapper
filed nothing at all.

That is the gap, stated precisely: **we can say "this binary is libtiff 4.0.3 and these 108 CVEs
apply to it", and we cannot yet make any one of them happen.**

## 3. Four defects found, three fixed

### (a) FIXED — the format detector was wrong, not merely incomplete

`structure._BUILTINS` had ten formats and none of TIFF, PDF, XML, gzip, bzip2 or ELF, and
`detect_format` voted on the executable's own strings only. Measured, before:

| target | parses | detected as | seed it got |
|---|---|---|---|
| `tiffinfo`/`tiffcp` | TIFF | **jpeg** (they link libjpeg) | 215 B JPEG, rejected at the magic |
| `mutool` | PDF | **zip** (it reads EPUB/XPS) | 137 B ZIP |
| `readelf` | ELF | **h264** (three-letter coincidence) | 37 B of video |
| `bzip2`, `minigzip`, `xmlwf` | bz2/gz/XML | nothing | `""`, `"AAAA"`, a path |
| `jpegtran` | JPEG | jpeg | correct |

One of eight. Now: six new models, each emitting a seed **verified accepted by a real parser**
(`tiffinfo`, `tiffcp`, `mutool`, `xmlwf`, `xmllint`, `minigzip`, GNU `gzip -t`, `bzip2 -t`,
`readelf`, `objdump`, `nm`), and detection reads **imports as well as strings** and returns a
**ranked list** rather than a winner. **20/20 top-1 correct** on the corpus, `cat`/`xxd` still
correctly detecting nothing.

Two sub-findings worth keeping:

* `xmlwf` carries not one XML string — they all live in the libexpat it links — so a
  strings-only detector was blind to it *in principle*. Its import table says
  `XML_ParserCreate`. Import evidence is now part of the vote.
* The first weighting scaled an import by its symbol-name length, which ranked `unzip` as a
  **bzip2** reader: it imports four long `BZ2_bzDecompress*` symbols to decompress members
  inside a zip. A linkage fact is one flat capped weight; separately, a parser repeats its own
  format's vocabulary, so token frequency counts (bounded at 3).

`xmlgrammar.XmlMutator` already existed but could only be selected when the corpus *already*
looked like XML — never true on an unseeded target. Detection now selects it and seeds a
well-formed document, which makes an existing capability reachable.

### (b) FIXED — the string scan stopped at 1.6 MB, so every consumer went blind on big binaries

`invocation.raw_strings` scanned `data[:limit * 8]`, conflating "at most 200,000 strings" with
"at most 1.6 MB of bytes". Plain `tiffinfo` is 1.24 MB and yielded 5,815 strings with every TIFF
marker; the ASan-instrumented `tiffcrop` is 5.47 MB, so its `.rodata` sat past the cap and the
scan returned **784 strings of mostly code**. Invocation discovery, the fuzzing dictionary, the
format detector and the credential detector all go through this function, and all of them failed
at once on that target: discovery proposed a flag soup the target refused, detection found
nothing, and the campaign fell through to mutating **text commands** mined from three-letter
fragments (`exp`, `log`, `pow`, `taf`, `uaf`, …) against a TIFF reader.

Now the whole file is scanned with a C-speed regex: 784 → **9,445** strings on that binary, and
**faster than the old prefix loop** (60 ms for 5.5 MB; 156 ms for mutool's 36.7 MB). A byte
prefix is the wrong bound for this question — a large binary is exactly the case where the
strings matter most.

### (c) FIXED — a dispatch tool's input slot was stolen by an optional read flag

`propose_argv` placed the input at the first read-ish optional flag before falling back to the
positional, so `mutool` was invoked as `draw -r @@` — `-r` is a *resolution*, so the document was
fed to that flag and the tool had no input left. When a subcommand is present the positional now
wins (`mutool draw @@`); the optional-read-flag branch still serves the case it was written for
(`tcpdump -r <pcap>`, which has no subcommand to anchor).

### (d) OPEN — a source project builds a target that cannot run, and the budget funds it anyway

`_ingest_built_project` (ingest.py:321) stores only `built["primary"]` — "the biggest produced
executable" — and records the rest as `other_binaries` metadata. For libtiff that is
`tools/.libs/tiffcrop`, a libtool binary needing `libtiff.so.5`, which nothing stages. The
scorecard said so exactly:

```
baseline: {"ran": false, "isolation": "bwrap+netns/not-runnable",
           "note": "the image never executed (the loader refused it);
                    nothing was run, which is not the same as nothing found"}
executions: {"total": 34059, ...}
```

The report layer was right and the orchestrator ignored it: **34,059 executions of a binary that
cannot load.** Two fixes, independent: stage the libraries the build produced as deps (the
bundle path already does this for a CTF layout), and let a `ran: false` baseline stop the
dynamic phases instead of funding them. Also: a source *library* is ~20 entry points
(`tiffcp`, `tiffinfo`, `tiff2pdf`, `fax2tiff`, …) and only the largest is analysed.

## 4. OPEN — the instrumented build is the one the budget starves

With (a)–(c) fixed, the pipeline does the right thing on a static ASan `tiffcrop` unaided:

```
fuzz.invocation  {"argv": ["@@","lykos.out"], "discovered": "...verified by running it"}
fuzz.format      {"model": "tiff", "auto": true}
```

Correct invocation, correct model, 1,715 distinct behaviours — and zero crashes. The full pass
says why that is not yet an answer about libtiff:

| | plain `tiffinfo` | ASan `tiffcrop` |
|---|---|---|
| rate | 105/s | **20.5/s** |
| executions in 420 s | 27,458 | **2,761** |
| stages reached | 24 done / 13 skipped | **11 done / 25 skipped** |
| AFL++ (`coverage_fuzz`) | ran | **never ran** (`by_engine`: `fuzz` only) |

An instrumented target costs ~5× per execution and gets the same wall clock, so the only
configuration whose oracle can see a heap OOB read is the one reduced to a smoke test. The
budget divides *time*; it should divide *executions* against a measured per-target rate, which
`budget.py` already carries a table for.

And one limit of the new seeds themselves: a minimal TIFF sets `Compression=1` (none), so no
codec path is exercised — while most of libtiff 4.0.3's CVEs live in OJPEG/LZW/PixarLog/NeXT/
thunder. The models should emit one seed per codec, which is cheap now that the model exists.

## 5. FIXED — the channel ranking had no evidence unless `disassemble` had run

The HTB half of the corpus found a second chain of the same shape, and this one had regressed a
capability an earlier session had demonstrated. `quack_quack` -- whose verified L1 (SIGABRT,
CWE-787) is on record -- came back **L0 at 240 s and again at 600 s with 90,872 executions**.

It is a two-link chain, and neither link is the fuzzer:

1. **`modes_for` read only call edges.** Those come from `disassemble`, which returned in 0.6 s
   under the per-target budget, so the edge set was empty, *no channel had any evidence*, and
   the no-evidence fallback was taken -- `arg`, which is correct for a binary that genuinely
   reads nothing and wrong here. The concolic stage therefore solved against **argv** for a
   program whose input is `read(0, ...)`. Triage had parsed that import table at ingest.
   Fixed: a native target's recorded symbol names are unioned into the same C vocabulary the
   call edges use, so `read` is evidence whether it arrives as an edge or an import. Scoped to
   native targets by file type -- Python's `open`/`read` are a file object's METHODS, and
   feeding them to the C vocabulary turned a Python file reader into an interactive stdin
   target. Two false starts worth remembering: making `arg` non-leading broke the designed and
   tested "imports no input function at all" case, and gating on "the managed vocabulary found
   nothing" suppressed the C reading for quack_quack itself, which imports `open` for its own
   `flag.txt`.

2. **`concolic` sizes its symbolic input from the frames `disassemble` recovered.** Run as
   `disassemble` then `concolic` with the channel fix in place, it reaches the defect in 19.8 s
   and files `confirmed: 2` with `signal=SIGABRT mode=stdin` -- the known L1 crash, reproduced.
   Without the frames it deadends in 2.07 s of a 180 s slice and reports nothing about why, so
   the stage degrades silently to a no-op. It should say "symbolic input sized blindly, no
   frames recovered" instead.

The channel fix is confirmed at the stage level: across the three attempts the chosen mode went
`arg` -> `file` -> `stdin`, and on `stdin` the SIGABRT returns.

### The autopilot is STILL L0 on this target, and the reason is now identified

The channel fix does hold end to end -- captured from inside the autopilot,
`concolic.start {'targets': ['0x4012ff','0x4013ae'], 'seeds': 0, 'mode': 'stdin'}`, and
`fuzz.channels {'channels': ['stdin'], 'execs': 59081}`. The stage is aimed correctly now.

What it comes back with is this:

```
concolic.explored  {'generated': 0, 'incomplete': True,
                    'note': 'StageCancelled: subprocess .../angr-venv/bin/python cancelled'}
```

**The solver is killed at the instant it would have returned, and everything it found is
discarded.** `spec["max_seconds"]` (angr's own exploration budget) and the subprocess kill
timeout are the SAME number, and finding an input is not the deliverable -- `_validate` still has
to run each generated input to turn it into a crash. Driven alone with the SAME 19 s slice, the
stage explores for 19.13 s, validates, and files `confirmed: 2` with `signal=SIGABRT mode=stdin`.
Inside the autopilot it is cancelled at 19.2 s with `generated: 0`.

This is exactly the defect doc 32's process note records -- "handing one number to both the stage,
as its campaign length, and the worker, as its kill deadline, killed every campaign at the instant
it would have returned; the work was done and the summary discarded" -- which was fixed for the
fuzz campaigns and never applied to `concolic`.

**The obvious fix is measured and WRONG, so do not re-apply it.** Reserving part of the slice for
validation (`explore_seconds = max_seconds * 0.6`) was tried here and reverted: at a 19 s slice it
cuts exploration to 11 s, and the solver then returns `generated: 1, unconstrained: 0` and finds
nothing, because this target needs the full ~19 s of exploration to reach the gate. Shrinking the
solver's budget trades a silent cancel for a silent miss.

The fix is upstream, and it is the same theme as §4: `concolic` asked for `want=120.0` and was
handed **19.2 s** -- 16% of its request -- while `fuzz` took 211.4 s and `directed_fuzz` 185.0 s
to produce 91,896 executions and nothing.

### FIXED, and re-measured: L1 is back

Two changes, both in the allocation rather than in any analysis:

* `budget.SOLVER_RESERVE` (0.20 of the case clock) and `SAMPLER_STAGES`: a sampler may not spend
  what the solver is owed. This is the phase-reserve principle applied WITHIN the search phase --
  a blind campaign cannot construct the input behind a `strstr(input, "Quack Quack")` gate at any
  budget, and the solver does it in seconds, so the solver's share is not the samplers' to spend.
  The reserve is RELEASED once a non-sampler search stage has been served, or the campaign that
  closes the coverage loop afterwards would be permanently denied the time to do it.
* `fuzz` and `coverage_fuzz` now declare `want=_CAMPAIGN_WANT` (180 s). They were the only stages
  that declared nothing, which in `budget.slice` means "give me half of whatever this phase has
  left".

Re-measured, same target, same 600 s budget, nothing else changed:

| | before | after |
|---|---|---|
| `concolic` slice | 19.2 s, **cancelled**, `generated: 0` | 21.0 s, **completed**, `found: 1` |
| PoC | none | **L1, verified**, `signal=SIGABRT` |
| finding | 2 candidates | **poc-backed CWE-787** "Reproduced crash (SIGABRT) under dynamic execution" |
| executions | 91,896 | 87,416 |

**The margin is thin and this is not finished.** The solver still gets 21 s of the 120 s it asks
for, and it succeeded by about five seconds: `concolic` explored 18.52 s and then had to validate
inside a deadline of roughly 26 s. Two reasons the reserve delivered less than the 97 s a
straight simulation predicts: `directed_fuzz` is invoked three times, and every stage OVERSPENDS
its slice by the worker margin plus the orchestrator grace (`fuzz` spent 180.8 s on a 150 s
slice). The durable fix is the one doc 32 applied to the fuzz campaigns and never to the solver:
let the stage's own budget be strictly smaller than the deadline that reaps it, so exploring and
validating both fit. Do NOT do that by shrinking the exploration budget -- that was measured and
reverted (see above).

## 6. Where the capability actually stands

* **Identify, black-box, real software:** yes — N-day fingerprinting (108 CVEs on libtiff
  4.0.3, 54 on expat 2.1.0), static sink/API/frame detectors, symbolic `tainted_deref`/
  `oob_index`. Reported with provenance, and the scorecard now says when nothing ran.
* **Demonstrate (crash/PoC) on real library software:** not yet, on this corpus. Every
  obstacle found so far was mechanical — detection, string truncation, invocation, loadability,
  budget — rather than a limit of the fuzzer, and four of six are now closed.
* **Weaponize:** `quack_quack` is **L1 verified** (poc-backed CWE-787) and `el_pipo` is **L1
  verified** (CWE-119) after the allocation fix; both were L0 before it. Of the rest:

  * `replaceme` -- **still L0 after both fixes**, and the reason is neither of them. Its defect
    is real and hand-reproducible (SIGSEGV: `'a'*128 + 's/a/' + 'B'*100 + '/'` overflows a
    192-byte stack buffer in `do_replacement`, no canary; delivered as ONE bulk write, because
    `read(0, buf, 0x80)` takes the first 128 bytes as the text and the remainder as the sed
    expression). The pipeline files the class and a technique -- `oob_index` CWE-129,
    `chain_primitive` recipe "oob_write -> oob-index-write" -- without demonstrating it.

    What blocks it, measured:

    1. **`concolic` cannot explore this binary.** It returns after **66 steps in 0.29 s** with
       one state deadended, nothing active, nothing generated. NOT a budget problem: read
       `by_stage` carefully, those numbers are ELAPSED time, so the "concolic 3.0 s" in both
       runs is the stage FINISHING early, not being starved. (The same reading error is easy to
       make on quack_quack, where 19.2 s elapsed WAS a deadline cancel -- the difference is the
       `StageCancelled` note, not the number.) `no_gadgets` shows the same collapse, harder: 5
       steps in 0.01 s.
    2. **The campaign has the right token now but not at the right offset.** `example_seeds`
       mines the specimen out of the binary's own prompt -- "in SED format (e.g. s/old/new/)" --
       and emits `s/old/new/` plus a long-field variant `s/old/AAAA.../`, which is the crash
       shape. But delivered as one blob the seed sits at offset 0, so `read` #1 swallows it as
       the TEXT and the expression never reaches field two. The crash needs 128 bytes of text
       (containing the needle) and THEN the expression.

    **FIXED -- linear prompt protocol delivery.** A linear protocol is a numbered menu minus
    the dispatch, and the delivery the menu path already uses is the one it needed:

    * `menu.crawl_linear` learns the field template by driving the live target one prompt at a
      time (reusing `_drain`, which detects "stalled waiting on input" = a prompt). Gated: only
      when `detect_menu` finds nothing, and only at two or more fields.
    * `runner.run_input_prompted` / `prompted_runner` deliver the blob's LINES one per prompt
      with a drain between, and drop into `fuzz_campaign` as its `run_fn` (which already
      disables batching for any runner that is not `run_input` -- correct, these cannot batch).
    * `menu.linear_seeds` + `_grow_to` emit protocol-shaped seeds: one line per field, the
      documented example tried in each position at each of four plausible line sizes.

    Three constraints that were measured rather than reasoned, all of which cost a wrong answer
    first:

    1. a line LONGER than the field's `read(0, buf, N)` spills its tail into the next read and
       desyncs every field after it -- a 160-byte filler ahead of this target's 0x80 reader
       swallowed field two's expression and all 16 seeds were rejected at the first gate;
    2. a line far SHORTER than N cannot reach a defect that needs the buffer nearly full -- a
       48-byte filler left the result at 165 bytes against a 192-byte buffer, just short;
    3. clipping an example into a slot breaks its grammar at the far end -- `s/old/new/` cut at
       128 bytes loses its closing delimiter and the target answers "Missing '/' after the
       replacement" -- so `_grow_to` expands the example's LAST field instead.

    Measured, same target, same 600 s budget:

    | | before | after |
    |---|---|---|
    | crashes | 0 in 63,234 executions | **1 reproducible in 1,015** |
    | findings | 3 corroborated + 1 candidate, no crash | **confirmed CWE-119** (SIGSEGV) + **corroborated CWE-121** from `monitor` ("Stack overflow observed: read() copied 128 bytes into ask_input") |
    | rate | 105/s bulk | 6-30/s prompted (a drain per field) |

    A guard bug in the first version is worth remembering, because it is this document's own
    theme: the path was gated on `not p.get("input_mode")`, and the autopilot ALWAYS passes
    `input_mode` -- that parameter carries the orchestrator's channel decision, not an operator
    override. So the feature worked when the stage was driven directly and did nothing at all in
    the pipeline that needs it. Key such a gate on the CHANNEL, never on how the channel was
    chosen.

    **STILL OPEN, one layer up: the PoC ladder cannot verify a prompt-protocol crash.** The PoC
    row is L0 `verified: false` even though the crash is confirmed and reproducible, because
    `poc/stage.py` replays by sweeping `[mode] + MODES` through `sandbox.run` -- bulk delivery
    only. The recorded isolation tag is `bwrap+netns/prompted`, which is the signal a fix keys
    on. Do NOT fix only the replay: the bundled reproducer SCRIPT also delivers in bulk, and
    this input (two 112-byte lines) desyncs that way, so a replay-only patch would file a
    "verified L1" whose bundle does not reproduce for the operator -- the exact failure this
    stage already warns about for a mismatched signal.
  * `no_gadgets` -- L0, and NOT a budget failure: `concolic` returns after **5 steps in 0.01 s**
    with nothing active or deadended, i.e. angr never explored the binary (it ships a bundled
    `ld-2.35.so`). The recorded L1 for this challenge came from its ASan SOURCE build
    (`a.lykos.bin`), not the prebuilt binary, so L0 here is consistent with that history.
  * `tictactoe` -- **zero executions** at 240 s and again at 600 s, so more budget is not the
    answer. DEFERRED by the operator on 2026-10-13: open and unexplained, not dismissed. At
    600 s the clock went `disassemble` 121.4 s, `coverage_fuzz` 118.1 s dying on "lease
    expired", `mem_oracle` 90.5 s, and then `fuzz` 35.5 s that recorded NO executions at all
    (`by_engine: {}`) -- most likely the live menu crawl consuming the whole campaign slice
    before any input was delivered. Two stages also died on lease expiry, burning 148 s.

  The exploitation machinery is intact; what was broken is what the autopilot hands it.

## Process note

Three of the four defects here were invisible to both the conformance gate and the breadth probe,
and became visible only by asking *why a change that should have helped did not*. The gate's
fixtures are 2–8 KB, so the 1.6 MB string cap could never fire; the probe records work, not
which model or invocation the campaign chose. The diagnostic that found them prints
`fuzz.format`, `fuzz.invocation` and `fuzz.done` per campaign — that belongs in the probe.
