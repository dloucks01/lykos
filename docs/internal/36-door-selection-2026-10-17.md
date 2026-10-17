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

---

# The heap overflow nobody could demonstrate — same day, weaponization

`tools/coverage_matrix.py` asks what each MECHANISM reaches, and the answer for **heap-overflow**
was L0 on both axes it appears on — while the lifetime classes beside it (UAF, double-free) reach
L3 through the FSOP chain. Every heap case in the conformance gate was a lifetime case; the class
with the most real-world CVEs behind it had no case at all, and the machinery to finish it
(`chain_primitive`: "overwrite an adjacent CODE pointer with the win address, trigger the use, and
CONFIRM control reached it") had been written and was never exercised on one.

The new case, `heap_fnptr_hijack`, is the common shape and not a contrived one: a notebook menu
over `struct note { char text[32]; void (*show)(struct note *); }`, an edit that takes its own
length, and a separate option that INVOKES the callback. Two properties make it a test of the
chain rather than of a crash finder — the corrupting write and the detonation are DIFFERENT menu
operations, and the pointer is overwritten in place, so what faults is a call through our bytes.

Five defects stood between "crash found" and "shell", and each was invisible until the one before
it was fixed. Every one is a measurement, in order:

1. **The case passed at L1 while its source said `want_level=3`.** `_scored` is
   `lvl_ok or bool(demod)`, so any poc-backed finding carrying a listed CWE passes the case
   whatever level it reached. `want_cwe=()` now, for the same reason `oob_leak_pie_ret2win`
   carries none: the LEVEL is the claim.
2. **The fixture's own accidental use-after-free was the easier bug.** `free` did not NULL its
   slot, so every crash the campaign found was `add(i); free(i); show(i)` — three tokens long —
   and the overflow the case exists for was never driven. It NULLs now; the lifetime classes are
   gated by the `heap_fsop` cases.
3. **The menu model had no buffer in it.** An edit reads its data only when the slot holds an
   object (`printf("data: "); if (db[i]) read(...)`), and an isolated crawl never primes one, so
   the option printed `data: `, skipped the read and looped back: the model said
   `2 -> [idx, num]`. No generated sequence could overflow anything and the campaign ran 6,064
   executions with zero crashes. A prompt that is printed and not read is still a field — the
   prompt is the evidence it exists, the guard is why it was not read — and it only counts when
   the line is UNFINISHED (`data: ` yes, `ok\n` no, which is output).
4. **Three primers, and the named one was trusted.** A size-then-buffer flow is exactly an
   EDIT's shape too, so `2` was named as the allocator and every sequence began by editing an
   object that had never been created. `new(slot)` for a fixed-size record asks for no size at
   all, so it was not a candidate in the first place. Every candidate is primed with in turn now,
   interleaved under the cap, with the payload-bearing options first — and a stray newline after
   a length-governed data field is dropped when another operation follows it, because it was
   being read as menu choice 0 and turned "write, then call" into "write, then exit".
   6 of 48 generated sequences now fault, one of them through the hijacked callback.
5. **The cyclic pattern could not reproduce the crash it was handed.** Structure-preserving
   framing keeps the bytes around the filler, and for a menu-driven write those bytes include
   the LENGTH the target is about to read: `2\n0\n512\n` in front of a 1,064-byte cyclic leaves
   552 bytes of pattern in the pipe, the next operation reads garbage instead of the option that
   detonates the write, and the stage reported "cyclic pattern did not fault". The field follows
   the payload now, rewritten only when it is at least as large as the filler it precedes (an
   index is smaller), offered as one more framing in the sweep, and recorded with the prefix and
   suffix so L3 inherits the same framing the offset was measured in.
6. **A hijacked function pointer does not put the attacker's bytes in the program counter.** On
   x86-64 a call through a register holding a non-canonical address raises #GP and the kernel
   reports SIGSEGV with the pc AT THE CALL:

   ```
   pc  = 0x401489           -> cyclic_find = -1   (the call site, inside the program)
   rdx = 0x6161616261616161 -> cyclic_find = 32   (the pattern, at the pointer's offset)
   disasm = `call   rdx`
   ```

   `controlled_registers` already saw `{rdx: 32}`; nothing connected it to the branch. The
   faulting INSTRUCTION names the register (register-direct forms only — `call [rax+0x30]` reads
   its target from memory, a weaker claim the sentinel would refuse anyway), and the sentinel
   settles it: MARKER is a canonical address, so a confirming run really does arrive there.
   Measured: `recover_ip_offset -> (32, 'reg:rdx')`, and the confirming detonation lands with
   `pc = 0x1337c0de1337`.

7. **The guard-page oracle HID the bug.** Every execution of the campaign preloads
   libdislocator, and a write the KERNEL performs cannot fault the process: `read(fd, buf, n)`
   into a buffer at the end of a guarded page copies only as far as the page boundary, the rest
   of the sequence is then read as data, and the operation that would call the overwritten
   pointer is never selected. The crashing seed is SIGSEGV plain and **exit 0 guarded** — 5,810
   executions, zero crashes, on a target that crashes on its own seed. The two oracles catch
   different overflows and each hides the other's (busybox's lzma read faults ONLY under the
   guard page), so every calibration seed now runs under BOTH; the mutation phase keeps the
   stage's chosen oracle, and the isolation tag still records which one found a crash, so the
   PoC replays the way it was found.

**Result, measured 2026-10-17:** `heap_fnptr_hijack` **PASSES at L3 in 126 s**, through the real
autopilot, with `want_cwe=()` so only the level can satisfy it — `exploit/CWE-119`,
`primitive/CWE-787`, `root_cause/CWE-787`. The heap-overflow row of the coverage matrix is no
longer L0.

## ...and then without a win function at all

`find_win` is strict on purpose — a suggestive name, or a local function that calls a
shell-spawner — and that strictness is the stated reason L3 was unreachable on real binaries:
*"ncompress has a reachable stack overflow and confirmed instruction-pointer control but imports
nothing that spawns a shell and has no function called `win`."* An indirect call makes it worse:
one jump, no return address, so every stack recipe (pop-rdi + system, SROP, ret2csu,
ret2dlresolve) is unavailable too.

What is available is the convention. The dominant C callback shape passes the object ITSELF as
the callback's first argument — `obj->run(obj)` — so when the overwritten pointer is `system`,
the argument is already the object, and the object's first bytes are the start of our payload.
`"/bin/sh\0"` at offset 0 and `system@plt` at the control offset is the entire exploit.

It is filed **only on a spawned shell** (`require_shell`), and that is not caution for its own
sake: arrival at `system` proves the pointer was overwritten, while the ARGUMENT — the half this
recipe is about — is proved by the shell coming up. It is also what keeps the recipe honest on a
shape it does not fit, since a smashed return address reaches `system` just as well with rdi
holding whatever the program left there. The recipe is offered only where L2 recovered control
from a branch REGISTER, which is why the L2 record now carries its `source`.

`heap_fnptr_system` — the same notebook with no `win` anywhere and `system` imported for an
ordinary reason (a `4.date` option) — **PASSES at L3 in 104 s**, autonomous.

## ...and on a PIE binary, with no leak at all

The two cases above are no-PIE, so `win` and `system@plt` are link-time constants. `heap_fnptr_pie_leak`
is the same notebook built `-fPIE -pie`, where nothing is known until the process runs, plus a
`4.dump` that prints the object raw — so the callback, a CODE pointer, reaches stdout.

Two routes were open and the cheaper one is the one that fired. The leak route works: measured by
hand, the dump leaks `plain()` and `leak.disclosed_bases` resolves the image base from it alone
(*"one leaked slot whose page offset matches exactly one symbol, so it is unambiguous. ASLR is
defeated from the leak alone"*). But PIE randomises the page base and not the low 12 bits, and
`plain` and `win` differ only in their LOW BYTE — so overwriting ONE byte of the callback turns one
into the other, deterministically, with no information leak whatsoever. That recipe
(`_pie_partial_overwrite_exploit`) already existed; what it could not do was DELIVER the byte,
because it builds and detonates its own payload instead of going through the generic path, and so
never saw the framing. One byte as a program's whole input drives no menu at all.

`build_exploit` now derives the measured framing once, before the ladder, from the record L2 left,
and the partial-overwrite path takes it. Measured:

```
primitive.done  offset 32, source "reg:rdx", confirmed, level L2,
                frame_prefix "1\n0\n1\n1\n2\n1\n512\n", frame_suffix "3\n1\n", frame_relength true
exploit.done    exploit "ret2win-partial", offset 32, confirmed
```

**`heap_fnptr_pie_leak` PASSES at L3 in 100 s**, autonomous, on a PIE target with ASLR on and no
leak used. All three forms of the heap-callback hijack now reach a demonstrated effect: with a
win (126 s), with no win at all (104 s), and PIE (100 s).
