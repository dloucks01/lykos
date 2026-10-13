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

**But the full autopilot is still L0 on this target, and the reason is NOT yet identified.**
91,896 executions at 600 s, `concolic` 19.2 s -- within a second of the 19.76 s the isolated run
needed -- and no crash. So "disassemble was starved" is NOT a sufficient explanation: that stage
costs well under a second on this 20 KB binary in the isolated run too. The most likely remaining
link, unverified, is `how_to_feed`'s first branch: it returns the mode recorded by whichever
`DynResult` matches `input_sha`, and the blind campaign runs before `concolic` and records plenty
of them -- which would override the ranking this round just fixed. **Whoever picks this up: run
the autopilot with the fuzz stages disabled and see whether concolic reaches SIGABRT; that
isolates it in one run.** Do not assume the channel fix is sufficient end to end, because it
measurably is not.

## 6. Where the capability actually stands

* **Identify, black-box, real software:** yes — N-day fingerprinting (108 CVEs on libtiff
  4.0.3, 54 on expat 2.1.0), static sink/API/frame detectors, symbolic `tainted_deref`/
  `oob_index`. Reported with provenance, and the scorecard now says when nothing ran.
* **Demonstrate (crash/PoC) on real library software:** not yet, on this corpus. Every
  obstacle found so far was mechanical — detection, string truncation, invocation, loadability,
  budget — rather than a limit of the fuzzer, and four of six are now closed.
* **Weaponize:** the recorded ceiling (L1 on a canaried stack overflow, L2 demonstrated libc
  leak on `deathnote`, L3 on the no-PIE / leak-bearing-PIE / win()-bearing classes, doc 32 §7)
  did NOT reproduce through the autopilot this round: five HTB targets at 240 s and
  `quack_quack` twice at 600 s all returned **L0**, while the same crash is reachable in 19.8 s
  from the concolic stage driven directly. `tictactoe` managed **zero executions** in 240 s --
  `mem_oracle` 76.9 s and `disassemble` 46.9 s ate the clock, `coverage_fuzz` aborted
  ("Fork server handshake failed"), and every search stage was then skipped for want of budget.
  The exploitation machinery is intact; what is broken is what the autopilot hands it.

## Process note

Three of the four defects here were invisible to both the conformance gate and the breadth probe,
and became visible only by asking *why a change that should have helped did not*. The gate's
fixtures are 2–8 KB, so the 1.6 MB string cap could never fire; the probe records work, not
which model or invocation the campaign chose. The diagnostic that found them prints
`fuzz.format`, `fuzz.invocation` and `fuzz.done` per campaign — that belongs in the probe.
