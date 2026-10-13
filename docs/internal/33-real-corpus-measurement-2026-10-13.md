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

## 5. Where the capability actually stands

* **Identify, black-box, real software:** yes — N-day fingerprinting (108 CVEs on libtiff
  4.0.3, 54 on expat 2.1.0), static sink/API/frame detectors, symbolic `tainted_deref`/
  `oob_index`. Reported with provenance, and the scorecard now says when nothing ran.
* **Demonstrate (crash/PoC) on real library software:** not yet, on this corpus. Every
  obstacle found so far was mechanical — detection, string truncation, invocation, loadability,
  budget — rather than a limit of the fuzzer, and four of six are now closed.
* **Weaponize:** unchanged by this round; the HTB ceiling (L1 on canaried stack overflow, L2
  demonstrated libc leak on `deathnote`, L3 on the no-PIE / leak-bearing-PIE / win()-bearing
  classes) is documented in doc 32 §7 and the memory notes.

## Process note

Three of the four defects here were invisible to both the conformance gate and the breadth probe,
and became visible only by asking *why a change that should have helped did not*. The gate's
fixtures are 2–8 KB, so the 1.6 MB string cap could never fire; the probe records work, not
which model or invocation the campaign chose. The diagnostic that found them prints
`fuzz.format`, `fuzz.invocation` and `fuzz.done` per campaign — that belongs in the probe.
