# The technique catalogue: what is driven, what is only described, what is absent — 2026-10-17

An exploitation technique is in one of three states here, and the difference is the whole point:

* **driven** — the engine builds the chain, detonates it and confirms the effect, so a finding
  carries a PoC;
* **knowledge-base** — `aaheg` names the technique, its preconditions and the primitive it
  yields, and stops. The finding is L2 analyst guidance;
* **absent** — nothing in the tree knows it exists.

## Where it stands

**Driven (confirmed end to end):** ret2win, ret2libc (puts-leak and analyst-supplied libc),
ret2system, ret2csu, ret2dlresolve, ret2plt, SROP, BROP (blind, forking server), one_gadget, ORW
and seccomp-aware ORW, mprotect→shellcode, format-string `%n` → GOT / ret2win /
write-what-where, magic-value overwrite, PIE one-byte partial overwrite, tcache poisoning, House
of Apple 2 (one-piece, split, and the cell form for a one-word-at-a-time writer — with either
`system` or `setcontext` as the fake `__doallocate`), the heap and C++ hijacks (adjacent code
pointer, vtable, indexed-write GOT), and — new — the WASM indirect-call redirect, the stack pivot,
`setcontext` register control, House of Cat (`_IO_list_all` → a FILE that is entirely ours), and
the self-executing input.

**Knowledge-base, now with measured verdicts** — every entry's primitive, preconditions and
emitted chain are decided against the libc in hand (`Env(libc_data=...)`), and each says UNKNOWN
rather than guessing when handed no libc: fastbin_dup, House of Spirit, House of Force, safe
unlink, unsorted-bin attack, tcache stashing, large-bin attack.

**Absent:** `__exit_funcs`/`atexit` and TLS `dtor_list`; House of Apple 1/3;
`tcache_perthread_struct`; ret2vdso; JOP/COP; canary byte-brute against a forking server;
`_rtld_global` lock gadgets.

## The order, and why

Each item below is one unit of work: the technique, a fixture where it is the ONLY route, a
conformance case demanding the rung, and a measured run. The order is value × feasibility on the
glibc actually installed here, not textbook order.

1. ~~**Stack pivot**~~ — **DONE.** `rop.find_pivots`/`pivot_placement`/`build_pivot_chain`/
   `pivot_fits` and a `pivot` strategy in `exploit_stage`. `stack_pivot_shell` PASSes L3 through
   the autopilot in 133s. The thing that had to be measured rather than read: the pivoted stack is
   not a place the chain reads words from, it *is* the stack, so what the placement needs is
   **writable memory below the chain**, not room inside the buffer. With the chain at the buffer's
   start the pivot fired and the process died in `_dl_runtime_resolve_xsavec`; with the PLT slot
   pre-resolved, `system()` itself still segfaulted on 192, 448 and 960 bytes of slack and spawned
   a shell on 1984. A 256-byte buffer with 8 KiB of unrelated globals underneath works.
2. ~~**`setcontext` register control**~~ — **DONE.** `rop.find_setcontext` locates the
   register-loading entry by decoding `mov reg,[rdx+disp]` out of the byte stream (it must skip
   the prologue's `fldenv [rcx]`/`ldmxcsr [rdx+0x1c0]`, or the forged context would need a valid
   fpregs *pointer* too — the usable entry is **+0x35** here, not the +61 the write-ups quote),
   and `heap.setcontext_fsop_cells` is the FSOP plan `leak.indexed_write_fsop` now tries first.

   It works on one instruction in the caller: `_IO_wdoallocbuf` does `mov rdx,rdi` before
   `call [rax+0x68]`, so at the controlled call RDX holds the FILE pointer — **the forged FILE is
   its own `ucontext`**. The gregs offsets land on fields that are dead by then (`_chain` = RDI,
   `_fileno` = RSI, `_freeres_list` = RIP) or that we are setting anyway (`_wide_data` = RSP, so
   the pivoted stack is the forged wide_data by construction, not a free parameter).

   Two `_flags` bits carry it, and neither was obvious:
   * `_IO_UNBUFFERED` must be **cleared** — `_IO_wdoallocbuf` opens `test BYTE PTR [rdi],0x2` and
     the unbuffered path never reaches the vtable call. The `system` plan only gets away with
     leaving it alone because `" /bin/sh"`'s leading space clears it by accident.
   * `_IO_USER_LOCK` must be **set** — `_IO_flockfile` is
     `if ((fp->_flags & _IO_USER_LOCK) == 0) _IO_lock_lock (*fp->_lock)`, so setting it stops
     `_lock` being dereferenced. That is the only reason fp+0x88 is free to be `gregs[RDX] = 0`,
     and a NULL rdx is what lets RIP go **straight to `execve("/bin/sh", NULL, NULL)` with no
     chain and no gadget at all** — which matters, because this glibc has no `pop rdx; ret` in an
     executable segment (a raw `blob.find(b"\x5a\xc3")` finds one in `.rodata` and the jump
     faults on *execute*, with `si_addr == rip`).

   Nine cells, measured live on the `oob_index_write` fixture and through the generated bundle
   reproducer. `system` stays as the fallback plan and keeps its own test.
3. ~~**Large-bin attack → `_IO_list_all` / House of Cat**~~ — **DONE, and it split in two.**

   **House of Cat is driven.** `heap.build_house_of_cat` builds the FILE, its `_IO_wide_data` and
   its fake `_wide_vtable` as one blob, and `leak.indexed_write_fsop` gained it as a third plan
   (`cat`) after `setcontext` and `system`. The caller writes the blob and then ONE pointer,
   `_IO_list_all := &blob`. It needs the fewest leaks of the three plans — no `_wide_data`
   read-back, no `_flags` read — and it takes the setcontext finish, so the effect is
   `execve("/bin/sh", NULL, NULL)`.

   What makes a self-built FILE work is `_mode`. `_IO_flush_all` fires on
   `(_mode <= 0 && _IO_write_ptr > _IO_write_base) || (_mode > 0 && wide write_ptr > wide
   write_base)`, and a blob delivered at a heap CHUNK address cannot choose the narrow pair at
   0x20/0x28 — in a chunk sitting in a large bin those are `fd_nextsize` and `bk_nextsize`,
   pointers glibc wrote. So `_mode` is 1 and the wide pair, inside the blob, carries the test.

   The conformance case is the shape that forces it: `house_of_cat_list_all` is the same unbounded
   index as `oob_index_write` but the target **prompts on stderr**, so the program reads
   `_IO_2_1_stderr_` between our cells and both plans that forge a FILE glibc owns execute a
   half-built one. Measured: setcontext fails, system fails, cat wins. PASS L3 in 23s.

   **The large-bin attack itself is version-gated, and the gate is read from the bytes.** The
   insertion ends in `victim->bk_nextsize->fd_nextsize = victim`, so corrupting the resident
   chunk's `bk_nextsize` to `TARGET-0x20` writes the new chunk's address to TARGET. Whether that
   is an *arbitrary* write depends on whether the branch is preceded by
   `if (fwd->bk_nextsize->fd_nextsize != fwd) malloc_printerr(...)` — and that compare reads
   `*(bk_nextsize + 0x20)`, **the very slot the write then overwrites**, so a guarded branch only
   writes where TARGET already holds the resident chunk's address.

   `heap.large_bin_guard` counts the guard sites by counting the jumps that reach the error
   string's loader — no version table, no reliance on the compiler's register choices. Measured
   on this host: **glibc 2.35 → one site** (the short branch writes unchecked: a real arbitrary
   write), **glibc 2.43 → two sites** (both guarded). Confirmed live both ways on 2.43: with
   TARGET untouched the process dies with glibc's own
   `malloc(): largebin double linked list corrupted (nextsize)`; with TARGET pre-seeded to the
   resident chunk's address the write lands. So on 2.43 the technique is a **pointer swap**, not
   an arbitrary write, and `_IO_list_all` — which holds a libc pointer — is out of reach by that
   route. `aaheg`'s entry now says exactly that, differently per libc, and says "UNKNOWN" rather
   than guessing when it was handed no libc bytes.
4. ~~**tcache stashing**~~ — **DONE as a measured chain, and three things the recipes say are
   wrong on current glibc.**

   The primitive is real and still unguarded here. `_int_malloc`'s smallbin path hands out
   `last(bin)` through a *checked* unlink and then stashes the bin's remaining same-size chunks
   into the tcache through an unchecked one:

   ```
   bck = tc_victim->bk;  bin->bk = bck;  bck->fd = bin;  tcache_put (tc_victim, tc_idx);
   ```

   `heap.smallbin_stash_guard` counts the jumps reaching `malloc(): smallbin double linked list
   corrupted` — **one site on 2.35 and on 2.43**, so only the first unlink is checked. Corrupt the
   to-be-stashed chunk's `bk` to `TARGET-0x10` and the next allocation of that size **returns
   TARGET**. Nothing in a smallbin is safe-linked, so unlike tcache poisoning this needs no heap
   leak to mangle a pointer with. Proved live: `*TARGET` reads back `"STASHED!"`.

   What the write-ups get wrong, all three measured here:

   * **The tcache holds 16 chunks per bin, not 7.** `heap.tcache_capacity()` measures it with a
     probe that calibrates on the first freed chunk's `tcache_key` rather than guessing what a
     pointer looks like — necessary, because `tcache_key` is a full-width random word and passes
     any `> 0x7f0000000000` test, which is exactly how a tcache entry gets mistaken for a chunk
     sitting in a bin. A recipe that frees seven and expects the eighth to reach a bin does
     nothing at all.
   * **`calloc` no longer bypasses the tcache.** Every published version of this attack triggers
     the smallbin path with `calloc` while the tcache still has room. On 2.43 `calloc` takes the
     tcache head like `malloc`. `heap.tcache_bypass_allocators()` measures who still does bypass
     it: **`memalign` with an alignment above 0x10, and a growing `realloc`**.
   * **"Write a libc address AND get an allocation" is not both at once.** Reaching the smallbin
     path with a plain `malloc` requires that tcache bin to be *empty*, so the stash loop starts
     at count 0, always has room for the fake chunk, and stashes it on the next iteration — and
     `tcache_put` writes the fake's `next` at `fake+0x10`, which is TARGET, over the `&bin` the
     unlink just put there. With a plain trigger the write is **transient** and the deliverable is
     the arbitrary allocation. Keeping the write needs a tcache-bypassing trigger plus a tcache
     filled to capacity−1, so the loop stops after the first stash.

   One more trap, stated in the emitted chain: after stashing the fake the loop reads `fake->bk`
   as the next `last(bin)`, and a NULL there **hangs** rather than crashes — glibc's
   `if (tc_victim != 0)` skips the body without advancing the loop. So `*(TARGET+0x8)` must be set
   to the bin head, which terminates it cleanly.

   `tcache_perthread_struct` stays absent: it is an amplifier on top of tcache poisoning (which is
   already driven), not a way in, so it waits for a target that needs it.
5. ~~**fastbin_dup**~~ — **DEAD ON 2.43, and not because of a check: THERE ARE NO FASTBINS.**

   One probe binary, run against two libcs, settles it:

   | | glibc 2.35 | glibc 2.43 |
   |---|---|---|
   | tcache capacity (chunk 0x20) | 7 | **16** |
   | where the next free lands | **FASTBIN** (mangled `fd`, `bk` untouched) | **a BIN** (`fd` *and* `bk` are arena pointers) |
   | `double free or corruption (fasttop)` | present | **absent** |
   | `mallopt mxfast` (sets `global_max_fast`) | present | **absent** |

   `heap.fastbins_present()` reads that verdict out of the bytes and
   `heap.post_tcache_destination()` confirms it live; a test asserts the two agree, in opposite
   directions, on both libcs. The entry stays listed where the size fits — an omitted technique
   reads as "not considered" — and carries the refusal plus a pointer at tcache_poisoning (already
   driven) and tcache_stashing.

6. ~~**House of Spirit**~~ — **DONE: it did not die with the fastbins, it MOVED.**

   The classic framing ("forge a fastbin-size chunk") is void on 2.43, but the technique is not:
   the entry now follows the forged chunk to wherever this libc actually puts it and names the
   checks it has to survive there. A tcache-range chunk lands in the **tcache**, where the
   constraints are 16-byte alignment (`free(): unaligned chunk detected in tcache 2`), a size
   field whose tcache index matches the bin, and a `key` word that must not already equal
   `tcache_key` (`free(): double free detected in tcache 2`) — and, notably, **no next-size
   check**, which makes it *easier* than the fastbin form, not harder. Anything above the ceiling
   lands in a bin and faces the full set.

7. ~~**Safe unlink**~~ — **DONE as a constrained write, with the constraint named.**
   `heap.guard_sites` reports `corrupted double-linked list` at **two sites on both 2.35 and
   2.43**, so the forged `fd`/`bk` must satisfy `fd->bk == P && bk->fd == P`. That is what makes
   this a write of `&P-0x18` *into P*, not an arbitrary value at an arbitrary address — plus
   `corrupted size vs. prev_size`, so the forged `prev_size` has to match the fake size exactly.
   The entry says so instead of calling it "near-arbitrary".

8. ~~**Unsorted-bin attack**~~ — **DONE as a refusal with a redirect.**
   `malloc(): unsorted double linked list corrupted` is at **two sites on both libcs**: the scan
   verifies `bck->fd == victim`, so TARGET must already hold `&victim` and the write is not free.
   The entry says BLOCKED, and points at tcache_stashing, whose stashing unlink is the one glibc
   still does not check. It also drops the classic worked example where it does not apply:
   `global_max_fast` is the usual thing to overwrite with "an unchosen large value", and on a libc
   with no fastbins that variable does not exist.

## One the gate found rather than the catalogue: the self-executing input

Not on the list above, because it is not a technique so much as the absence of one. A plugin or
JIT loader copies its input into a page, makes it executable and **calls it** — so there is no
saved return address to overwrite and no instruction pointer to hijack; the program hands control
over on purpose.

Every strategy in `exploit_stage` was wrong for that shape. `_mprotect_shellcode` *builds* this
situation with a ROP chain and therefore needs gadgets, an overflow offset and an analyst-supplied
page symbol, none of which exist when the program already did the work; everything else needs an
offset. Measured before the fix, `jit_page_executed` reached **L2**: the pipeline found the input
being executed (it crashes on whatever the fuzzer sent), classified the fault as a memory error
and stopped, because nothing asked whether bytes *we* choose would do something instead of
crashing.

The answer is 25 bytes. `_self_exec_exploit` runs before every strategy that needs an offset,
gated on an `mprotect`/`mmap` import, and sends position-independent `execve("/bin/sh")` on the
input channel — no offset, no gadget, no leak. It confirms with an **int3 negative control at the
same length on the same channel**, which is what makes the marker mean anything: `_spawn_and_mark`
proves a shell by writing `echo <marker>` and reading it back, so a target that merely echoed its
stdin would otherwise pass without executing a thing.

## The allocator facts this round measured

Worth separating from the techniques, because they invalidate recipes across the board and none of
them is what the literature says:

* **the tcache holds 16 chunks per bin on glibc 2.43**, not 7 (`heap.tcache_capacity()`);
* **there are no fastbins on 2.43** (`heap.fastbins_present()`, `post_tcache_destination()`);
* **`calloc` no longer bypasses the tcache**; `memalign` above 0x10 alignment and a growing
  `realloc` still do (`heap.tcache_bypass_allocators()`);
* **the large-bin insertion's short branch is now guarded** (two sites on 2.43, one on 2.35), so
  that attack is a pointer swap rather than an arbitrary write (`heap.large_bin_guard()`);
* **the tcache-stashing unlink is still unguarded** on both (`heap.smallbin_stash_guard()`).

Every one of these is answered by `heap.guard_sites()` (count the jumps reaching a check's error
string) or by a compiled probe, never by a version table — and the probes calibrate rather than
threshold, because `tcache_key` is a full-width random word that passes any "looks like a libc
pointer" test and will otherwise make a tcache entry look like a binned chunk.

## Two that end in a verdict rather than a chain

Building these would mean fabricating a capability the allocator or the libc denies, so the
deliverable is an explicit, version-gated refusal with the check that kills it:

* **House of Force** — glibc ≥ 2.29 validates the top chunk's size against the arena, so the
  technique is dead on anything current. `aaheg` already gates by version; the work is to make
  the refusal say which check forbids it rather than omitting the technique silently.
* **`__exit_funcs` / TLS `dtor_list`** — the entries are PTR_MANGLE'd (rotated and XORed with the
  thread's pointer guard), so a write without the guard produces an unusable pointer. Feasible
  only with a TLS or stack leak that discloses the guard; absent one, the honest output is "this
  route needs the pointer guard, which this leak does not disclose".
