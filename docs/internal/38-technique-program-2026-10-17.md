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
`setcontext` register control, and House of Cat (`_IO_list_all` → a FILE that is entirely ours).

**Knowledge-base only:** fastbin_dup, House of Spirit, House of Force, unlink, unsorted-bin
attack. The large-bin attack is now knowledge-base *with a measured verdict* (below).

**Absent:** `__exit_funcs`/`atexit` and TLS `dtor_list`; House of Apple 1/3; tcache stashing and
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
4. **tcache stashing / `tcache_perthread_struct`.** Arbitrary allocation by corrupting the
   per-thread cache's own bookkeeping; works where a single free is all the program offers.
5. **fastbin_dup.** The pre-tcache double-free, still reachable by filling the tcache bin first;
   the fallback when the chunk size is above the tcache ceiling.
6. **House of Spirit.** Free a fake chunk inside a buffer we control, and malloc hands it back —
   the route when the program frees a pointer we can influence but never allocates for us.
7. **Safe unlink.** Narrow on modern glibc (`P->fd->bk == P` must hold), but the shape it needs —
   a global array of object pointers — is exactly what every notebook fixture has.
8. **Unsorted-bin attack.** Writes `main_arena+96` to a chosen address: not arbitrary data, so
   the deliverable is a counter/size overwrite (e.g. `global_max_fast`), stated as such.

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
