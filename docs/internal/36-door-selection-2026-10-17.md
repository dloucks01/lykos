# The door, not the library — 2026-10-17

In-process fuzzing reaches a library through one function at a time, so the answer to "did we
fuzz libsndfile?" is never *yes* or *no*. It is the name of a function. This round measured four
real trees and found that for three of them the name was wrong — and that nothing in any
instrument could see it, because a door that is not a door produces a clean row: no error, no
decline, a plausible execution count, and zero findings.

## What was measured

| tree | door the planner chose, before | after |
|---|---|---|
| libsndfile 1.0.28 | `psf_allocate()` → `psf_fopen()`, from `src/common.h` | `sf_open_virtual` → `sf_readf_short` → `sf_close` |
| openjpeg 2.3.0 | `known zlib`, `TIFFOpen()`, `gzopen()`, `cmsOpenProfileFromFile()`, then `tests/fuzzers/fuzzingengine.c` | its own `tests/fuzzers/opj_decompress_fuzzer.cpp` |
| mupdf 1.12.0 | five harnesses from `thirdparty/harfbuzz` and `thirdparty/freetype` | `pdf_decode_cmap()` and five more of mupdf's own |
| libsndfile (ranked functions) | `db_open()` — a sqlite wrapper from `regtest/` | `double64_be_read()` … (library code) |

libsndfile's row in `tools/real_corpus_gate.py`, same tarball, same 600 s budget:

| | before | after |
|---|---|---|
| doors built | 0/6 | **1/6** |
| executions | 4,677 at **34.4/s** | **11,545 at 57.7/s** |
| stages errored | 1 (`detect_cwe`, "lease expired") | **0** |
| findings | none | **UBSan `integer-overflow` at `common.c:174`, confirmed, verified L1** |
| verdict | FAIL (two plumbing defects) | PASS |

## The four mistakes, and the rule each one needed

1. **An internal header is not an API.** Being declared in *some* header was the whole test, and
   `src/common.h` — the structs libsndfile keeps to itself — passed it. The strongest triple in
   the tree was therefore a door no application has, on a handle a harness cannot honestly build;
   it did not even compile (*use of undeclared identifier `psf_allocate`*), and the first failed
   compile consumed the slice the other five doors were waiting for.

   A project states which headers are its API, in its own build files. `installed_headers` reads
   the statement: `include_HEADERS` under any automake prefix, `install(FILES …)` with its
   `set(…)` variables expanded (zlib's rule names no header at all), `install_headers(…)`.
   Commented-out rules do not count. A bundled project's rules are not this library's — reading
   `contrib/minizip` would have made zlib's own `zlib.h` private and lost `gzopen`, the door that
   works. A tree that states nothing (bzip2 installs with a shell script) keeps every candidate
   it had: **an unknown answer is not "nothing is public"**, and neither is a rule naming a
   header that is not on disk yet, which is the state of every generated public header —
   libsndfile's `sndfile.h` comes from `sndfile.h.in`. For the same reason the stage now
   configures the tree *before* planning; the build had always configured it, one step too late.

2. **A bundled library is not the library under analysis.** openjpeg vendors zlib, libtiff and
   lcms2; mupdf vendors harfbuzz and freetype, each of which *ships a libFuzzer harness* shallower
   than anything mupdf writes. Every finding in them would have been filed against the wrapper.
   A vendored tree is now excluded the way a platform port already was — from the source scan,
   the header scan (which is what `known_harness` gates on), the install rules and the in-tree
   harness search. The bundled code is still compiled and still reachable *through this
   project's own entry points*, which is the only way a bug in it is honestly openjpeg's.

3. **A driver is not a harness.** openjpeg's `tests/fuzzers/fuzzingengine.c` declares
   `LLVMFuzzerTestOneInput` and defines `main`: it is OSS-Fuzz's standalone driver, the file you
   link *instead of* libFuzzer. Mentioning the symbol was the test, so that driver was openjpeg's
   top-ranked door — a build with two `main`s and no entry point. A harness has to DEFINE the
   entry point.

4. **A tool directory is not the library, whatever it is called.** `_NOT_LIBRARY` is a list of
   names and the names keep being different: libsndfile's regression program lives in `regtest/`,
   openjpeg's command line tools in `src/bin/`. `program_dirs` reads the project's own build file
   — a directory that builds PROGRAMS and no library is not the library. A directory that builds
   both still is (libsndfile's `src/` builds the library and its unit tests), and the root never
   counts, or a project that builds one program at its top level would have nothing left to fuzz.

## Two reporting defects the same run exposed

* **A budget stop is not an error.** A lease lapses for two opposite reasons and both recorded as
  `error: lease expired`. The heartbeat stops renewing *on purpose* at a run's budget deadline,
  so for every oversized target the row said the stage had wedged — and the gate failed the
  target on its own invariant, that an error is never an acceptable outcome while a decline is.
  Measured on libsndfile's 8 MB ASan `sndfile-info`: 801 functions, 271,495 instructions, which
  `detect_cwe` cannot finish inside its slice on an idle machine. The heartbeat now flags the run
  cancelled on its way out; an unmarked lapse is still the wedge case the reaper was written for.
* **A stage cut short is an outcome, and it was invisible.** The scorecard had two outcomes for a
  stage — it worked, or it declined — so a cancelled run was neither and fell out of the card:
  the reader saw 0 findings from a detector that was never allowed to finish.
  `capability.cancelled` now names them, the CLI prints "cut short … (out of budget)", and the
  gate records it as a note rather than a failure. For the same reason a libFuzzer *pass* whose
  doors were all starved no longer reports `supported: false`: out of time is not a refusal, and
  it offers the doors it never attempted again.

## What this round did not close

* **Depth per door.** 1/6 doors at 600 s is the budget's decision and the floor in
  `tools/corpus_regression.py` is 1 for exactly that reason. The first door compiles 188
  translation units under ASan+UBSan; the five behind it cost almost no build time and all of
  their fuzzing time. A reach floor above 1 needs a bigger slice, not a planner change.
* ~~A callback is still a candidate.~~ Closed in the same round: a name that says the LIBRARY
  calls it (`*_callback`, `*_cb`, `*_handler`, `on_*`) is penalised, not excluded — the name is a
  convention, not a contract, so a tree whose only candidates are callbacks still offers them,
  last. openjpeg's tail is now `jpwl_markcomp()` and `gene_cache()` instead of
  `error_callback()` and `info_callback()`.
* **The honesty rule for a known harness is unchanged and still hand-written.** The libsndfile
  entry supplies the four virtual-IO callbacks and sizes the read buffer the way libsndfile
  documents it (`frames * channels` shorts), with the seek callback CLAMPED — an out-of-range
  seek we honoured would be our out-of-bounds read, filed against the library.
