# How far does a mechanism get? — 2026-10-17

The coverage matrix had twenty mechanism rows and twelve of them read below L3 — nine at L0, one
at L1, three at L2 — while the rows beside them read L3. The obvious reading, "those classes are
not weaponized", was not available,
because every cell showed the level a case **DEMANDS**, not the level the ladder **REACHES**. A
case that asserts only "the defect is identified" reads L0 forever, however far the autopilot
could have gone on it; a case that stops the moment its criterion is met never finds out what came
next. Nothing in the repo could answer "how far does this mechanism get", which is the only
question worth asking before deepening one.

## The instrument first

`tools/pipeline_conformance.py --ceiling` runs each case to the END of its budget instead of
stopping at its criterion, so the level in the PROFILE column is the ceiling rather than the exit.
Measured, before any of the work below:

| case | mechanism | ceiling | and then |
|---|---|---|---|
| `oob_index_write` | bad-index | **L2** | L3 — a shell, with nothing to point the write at |
| `int_overflow_alloc` | integer-overflow | **L1** | a new case reaches L3 |
| `uninit_stack_read` | uninitialised | **L0** | a new case reaches L2 |
| `format_read_leak` | format-string | **L1** | **L2** |
| `cpp_uaf_vtable` | type-confusion | **L2** | honest ceiling; the capability gated by a new case |
| `double_free` | lifetime | **L1** | honest ceiling, now demanded |
| `off_by_one` | oob-write | **L0, FAIL** | pre-existing red; see below |

## 1. An arbitrary write with nothing to point it at

`table[i] = v` with an unchecked index is a write-what-where, and `_oob_write_hijack` finishes it
by aiming a GOT slot at a win function — when one exists. In the gate's fixture none does: no win,
no `system` in the PLT, and no call site whose first argument we control (every `printf` in the
loop passes a .rodata format string). So the class fell back to an L2 recipe whose own text said a
leak-based chain was analyst work.

The two halves of the same bug finish it. The unchecked index **reads** a GOT slot — a resolved
libc address — and `resolve_libc_base` keeps the result only if it is page aligned, so the libc
base is recovered in-band under live ASLR; the same read then fetches the forged FILE's own
`_wide_data` rather than guessing it. The index then **writes** five House-of-Apple-2 cells, and
`exit()` turns the flush into `system(" /bin/sh")`.

Three things had to be right for a cell-at-a-time delivery:

* **The FILE is `_IO_2_1_stderr_`, not stdout.** The target's own code runs between every write —
  its next prompt — so a FILE it uses would be executed half-built. Nothing reads a forged FILE
  until `exit()` walks `_IO_list_all`.
* **The 0x300 blob cannot be delivered one word at a time at all**: it lands over the FILE *and*
  the `stdout`/`stderr`/`stdin` pointer variables that follow it. `heap.house_of_apple2_cells`
  reduces it to five writes and orders them — `_flags` last, because the command's leading space
  is `_IO_ERR_SEEN` and writing it earlier stops that FILE being usable.
* **The fake wide jump table goes inside the target's own global array**, so the forgery stays in
  memory the bug already reaches.

Every cell is read back before the trigger, so a cell that did not land is a stated failure rather
than a crash at the trigger, and the shell is confirmed by a marker it echoes. **17s** through the
real autopilot.

The bundle's reproducer was run by hand against the fixture as well, because a PoC that only the
engine can fire is not a deliverable: it resolves the libc base itself (`nm -D` on the libc the
target links, page-alignment as the accept test — no address is baked in), writes the five cells,
exits, and `id` comes back from the shell it spawned.

## 2. An integer overflow with something to aim

`int_overflow_alloc` proves its wrap and then memsets 'A's over its own heap: nothing adjacent is
worth reaching, the verdict family is magnitude, and L1 is the end. The weaponizable shape is the
other one — the wrap **under-allocates** and a separate option recomputes the copy length from the
saved count in 64-bit, so the fill runs off the chunk with content we chose, into the next record's
callback. Four defects, each measured on the new fixture and each general:

* **`add(slot, count)` was not an allocator.** `_is_alloc` wanted a size followed by the buffer it
  fills, or nothing but sizes, so a size into a SLOT TABLE named no allocator at all — and with
  none named, every op sequence drove objects that had never been created.
* **A prompt's NUMBER is a vocabulary, and the vocabulary had no object nouns.** `records: ` was
  typed as a string, the crawl answered it `"lykos"`, `strtol` returned 0, and the creator
  allocated nothing. The plural is the signal: "entries" asks how many, "entry" asks which one.
* **Two primers were built from one wrong idea, in two files.** `one + one` drove the option's
  DEFAULT id twice, so a slot table ended up with one live object and a leaked chunk — and an
  overflow needs a neighbour. Both copies carried a comment claiming two objects; neither made
  two. They are now one definition, `menu.alloc_primers`, which also offers the counts whose
  product with a common element size wraps a 32-bit size computation. Those thresholds are the
  only values that under-allocate: byte mutation effectively never emits the decimal text of a
  nine-digit number, and the "large" values every other shape drives (999, 0x7FFFFFFF) make malloc
  REFUSE instead. Offered only for a count-WITHOUT-buffer creator, where a wrap does not
  under-copy by the same amount — which also leaves every size-then-data notebook's budget alone.
* **Only the WRITTEN object was ever detonated.** An overflow runs forward, so the code pointer it
  reaches belongs to the NEXT object; where the callback sits at the start of the record, this
  object's own pointer is behind the write and unreachable. That layout was invisible — the write
  landed, nothing called it, and the sequence faulted nowhere.

**32s** through the real autopilot, and the finding names the wrap as well as the overwrite.

## 3. A read that never faults, and what its bytes are worth

Two classes, one missing question. memcheck proves undefined bytes reached a write syscall and the
injection probe proves a format string interpreted its directives — both are effects, and neither
said what the bytes WERE. Stack residue full of pointers defeats ASLR and residue full of padding
does not, and the out-of-bounds read arm has drawn that line since it was written
(`leak.disclosed_bases`).

* The whole L2 disclosure ladder hangs off a FAULT — an MSan build aborts inside the read, which is
  how the `src_uninit_*` cases reach L2 — so on a plain binary the uninitialised class had no path
  to a primitive however good the leaked bytes were. The disclosure arm now runs the
  UNINSTRUMENTED target under live ASLR and classifies what came out, **each run on its own**:
  under ASLR two runs' pointers belong to two different bases, and slots from two bases corroborate
  nothing.
* `disclosed_bases` harvested only the RAW-WORD rendering. Its docstring claimed hex text too and
  the implementation parsed none of it, so a PRINTED pointer was invisible to the one function that
  can resolve it: 30 `%p` disclosed a PIE code pointer, two libc pointers and a stack address, and
  it reported `distinct: 0`.
* The format-string recon payload asked for eight `%p`, which confirms the bug and resolves
  nothing, because the pointers that anchor a base sit deeper than the eighth varargs slot. Four
  runs each: 8 and 12 directives proved a base 0/4, 24 proved it 4/4, PIE and non-PIE alike.

`uninit_pointer_leak` (PIE, ASLR on, nothing faults) reaches **L2 in 12s**; `format_read_leak`
reaches **L2**. There is no L3 in either, and that is a property of the targets: a disclosure is
half a chain, and the format-string fixture has one `printf` and no second call site to redirect.

## 4. What a confirmation PROVES

Every injection PoC was filed at L1 — "the defect is real, here is a reproducer" — because the
ladder was built around crashes, where L1 is a verified crash and the effect is two rungs further
on. An injection has no crash and its oracle IS the effect: the marker appears only because the
shell RAN our `echo`, the database returned our row, or /etc/passwd came back. Filing demonstrated
command execution one rung above "identified" understates every injection this platform finds, so
each probe now declares what its confirmation proves and the PoC is levelled by it.

Two deliberate exceptions, both reasoned rather than assumed: a memory leak is chain material and
not an end effect, so the format string stays levelled by what its leak RESOLVES; and error-based
SQL injection proves the string reaches the parser and nothing more — control of the query, a
primitive — while the UNION branch, where the database hands back the attacker's row, is the
effect.

Measured with `--ceiling`, before and after:

| case | ceiling before | after | oracle |
|---|---|---|---|
| `cmd_injection` | L1 | **L3** | the marker appears and `echo <marker>` does not: the shell ran it |
| `path_traversal` | L1 | **L3** | /etc/passwd's own content came back |
| `xxe_injection` | L1 | **L3** | the same content, through a SYSTEM entity |
| `sql_injection` | SKIP | — | no sqlite3 headers on this host; the rule applies, unmeasured |
| `ssrf_injection` | SKIP | — | no libcurl headers on this host; same |

The two skipped cases keep the demand that was measured. A rule that has not been run is not a
result.

## 5. Honest ceilings, recorded rather than worked around

Three of the measured gaps are the fixtures' interfaces and not the engine's reach, and the cases
now DEMAND what they reach so that losing it is a regression:

* `double_free` (L1): `1.alloc` takes no size and no data, and there is no view and no edit. The
  program offers no way to write a forged chunk and no way to read one back, and every route past a
  double free needs one or both — so glibc's abort is the whole observable effect. The notebooks
  that do have those options (`heap_fsop_*`) carry this class's L3 claim.
* `cpp_uaf_vtable` (L2): g++ builds PIE and the fixture has no win, so there is no address to aim a
  forged vtable at. `_cpp_vtable_uaf` could always finish this chain and NOTHING gated it, because
  the only C++ case in the table is the PIE win-less one — `cpp_uaf_vtable_win` is the same defect
  non-PIE with a win reachable.
* `hppa` and `sparcv9` stay at L1 for architectural reasons already recorded in `archgate`: both
  keep the return address off the stack, so a bounded forward overflow never reaches control flow.

And one pre-existing red: the binary `off_by_one` case demands a demonstrated CWE that nothing can
produce. Two bytes past a 64-byte stack buffer land in padding or the saved frame pointer and do
not fault; the guard page is a heap allocator, memcheck does not track stack bounds, and ASan needs
source — which `src_off_by_one` has and this case deliberately does not. It is a detection gap, not
a weaponization one, and it was failing before this round.

## What the matrix says now

One ISA, one column: the conformance cases name a substrate by their cross-compiler prefix and the
ISA ladder names it by the engine's arch label, so the grid had grown `q:riscv64` beside `q:riscv`,
`q:s390x` beside `q:s390` and `q:powerpc64` beside `q:ppc64`. Both halves then read as
half-covered — the conformance case for an ISA demands L1 because it is there to prove the pipeline
REACHES the architecture, while the ladder case measures L3 on the same toolchain. Four cells read
L1 that are L3.

## 6. Mechanisms with no case at all

`coverage_matrix.MECHANISM` named twenty-one mechanisms and the matrix printed the rows that some
case happened to carry a CWE for. Four of the named ones — null-deref, div-by-zero, race,
resource-exhaustion — had NO fixture, so their rows did not exist, and the grid read as if the
taxonomy stopped where the case list stopped. Twelve new fixtures, each landing with
`want_level=0 / want_cwe=()` so it cannot fail, measured with `--ceiling`, and only then demanding
what it reached:

| case | mechanism | why it is its own mechanism |
|---|---|---|
| `null_deref` | null-deref | the cheapest crash there is, and `printf("%s", NULL)` is NOT it — glibc prints `(null)` and the program survives |
| `div_by_zero` | div-by-zero | a different SIGNAL (SIGFPE); the fault classification is signal-driven and nothing asserted a non-SEGV fault |
| `stack_exhaustion` | stack-exhaustion | the fault address is the stack guard, not anything the attacker chose — a DoS, and the verdict should say so |
| `alloc_size_dos` | resource-exhaustion | the magnitude family: the attacker chooses how much memory is asked for, and there is nothing to hijack |
| `memory_leak` | resource-exhaustion | never crashes; valgrind's leak summary is the only oracle |
| `invalid_free` | lifetime | the family's third member after UAF and double free, and the one with no case |
| `int_underflow_alloc` | integer-overflow | a wrap in a LENGTH gives a count near SIZE_MAX: it faults at once, so there is nothing to place |
| `int_truncation_fnptr` | integer-truncation | correct in 64 bits, stored into 16 — under-allocates at 4096 records where the overflow twin needs 268435456 |
| `unchecked_malloc` | unchecked-return | an allocation the attacker makes FAIL turns the next copy into a write through NULL |
| `hardcoded_secret` | hardcoded-secret | no memory is corrupted and nothing crashes; the defect is the string, and the effect is the authentication it passes |
| `race_counter` | race | TSan is the only oracle; the concurrency family is capped at L1 because a race is a scheduling fact, not an attacker-chosen write |
| `cpp_uaf_vtable_win` | type-confusion | the non-PIE, win-bearing half of the C++ UAF, which nothing gated |

And the table gained the mechanisms it never named: integer-truncation, unchecked-return,
stack-exhaustion, hardcoded-secret, deserialization, symlink-follow, temp-file, weak-crypto,
search-path, decompression-bomb, redos, privilege. The test for belonging is that the mechanism
changes what can be DONE with the defect — a truncation under-allocates where an overflow
over-allocates, so one is weaponizable and the other is a refused malloc.

## 7. What the new cases measured, including three holes

| case | ceiling | what it says |
|---|---|---|
| `int_truncation_fnptr` | **L3** | the truncation family's thresholds work; a new mechanism row at the top rung |
| `null_deref` | L1 | `root_cause/CWE-476`, the right class |
| `div_by_zero` | L1 | `root_cause/CWE-369` — the first case on a non-SEGV signal |
| `invalid_free` | L1 | `root_cause/CWE-590`, the lifetime family's third member |
| `int_underflow_alloc` | L1 | a wrap in a LENGTH faults at once; nothing to place, as predicted |
| `unchecked_malloc` | L1 | the dereference is reported; naming the missing CHECK is a labelling gap |
| `alloc_size_dos` | L1 | the magnitude family's honest ceiling |
| `race_counter` | L1 | `tsan/CWE-362` — the concurrency family's ceiling by construction |
| `stack_exhaustion` | L1 | **and it was mislabelled**: see below |
| `memory_leak` | GAP | no CWE-401 at all |
| `hardcoded_secret` | GAP | `hardcoded_secrets` files nothing |

Three things came out of this that are worth more than the rows:

**A stack-guard fault was an "invalid write".** A write immediately below the `[stack]` mapping is
the guard page, and what walks into it is a stack that grew as far as the rlimit allows. It came
back `root_cause/CWE-787`, severity high — an out-of-bounds-write lead for an address the input
never chose, with no primitive to chain. `classify` now recognises the guard page as CWE-674 and
`exploitability` offers it no write primitive, the same way it offers none for a null dereference.

**A mechanism whose evidence can only be STATIC could not be asserted at all.** "Detected is not
demonstrated" is right for memory corruption, and for a credential in `.rodata`, a predictable
PRNG seed or an insecure temp-file name there is nothing to run: the static fact IS the finding.
`_verdict` drops every static detector, so `want_cwe` can never match and `want_level=0` claims
nothing — such a case came back FAIL with the detector that found it printed in its own reason
column. `want_static_cwe` is the assertion they can keep, deliberately separate from the
demonstrated ones.

**Two fixtures measured a hole, and a hole has no honest verdict.** `clean` claims the opposite,
a want_* demand makes the case permanently red, and deleting the case loses the fixture and the
measurement together. `known_gap` reports GAP, is counted apart from the pass rate and excluded
from the exit status, and the note says what is missing:

* `memory_leak` — the leak is real and `memoracle` already maps a leak-only run to CWE-401. What
  is missing is in between: `mem_oracle`'s probe list is recorded crash inputs plus the empty one,
  a target that never crashes contributes none, and on empty input this program's first `fgets`
  returns NULL and it leaks nothing.
* `hardcoded_secret` — `hardcoded_secrets` looks for a secret-SHAPED value (an assignment to a
  password-ish name, high-entropy base64/hex). A plaintext credential compared with `strcmp`
  against a literal has neither shape: the evidence is the COMPARISON, not the string.

The binary `off_by_one` case moves here too. It was failing before this round for a reason its own
note already stated — two bytes past a 64-byte stack buffer land in padding, the guard page is a
heap allocator, memcheck does not track stack bounds, and ASan needs source, which
`src_off_by_one` has and this case deliberately does not.

### The verification pass

All eighteen new cases, normal mode, one serial run:

```
CONFORMANCE: 12/12 bug-classes demonstrated end-to-end through the real autopilot (1954s)
MEASURED HOLES (reported, not graded): off_by_one, memory_leak, hardcoded_secret,
                                       toctou_access, search_path_hijack, redos_regex
```

`int_truncation_fnptr` L3 in 31s, `untrusted_pointer` L2, `race_counter` L1 on `tsan/CWE-362`,
`temp_file` and `weak_prng_token` green on their static assertions in 2s each. Both labelling
fixes show up where they should: `stack_exhaustion` now reports `root_cause/CWE-674` instead of
CWE-787, and `unchecked_malloc` reports `root_cause/CWE-476` now that its copy is bounded and the
fuzzer can no longer find a different bug in the same fixture.

The mechanism axis, before this round and after:

| | before | after |
|---|---|---|
| mechanisms NAMED in the taxonomy | 21 | **34** |
| mechanism ROWS in the matrix | 20 | **33** |
| conformance cases | 71 | **92** |
| (mechanism, case) pairs | 145 | **168** |
| rows demanding L3 | 8 | **15** |
