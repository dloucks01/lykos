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
pointer, vtable, indexed-write GOT), and — new — the WASM indirect-call redirect, the stack pivot
and `setcontext` register control.

**Knowledge-base only:** fastbin_dup, House of Spirit, House of Force, unlink, unsorted-bin
attack, large-bin attack.

**Absent:** `__exit_funcs`/`atexit` and TLS `dtor_list`; House of Apple 1/3, House of Cat and
`_IO_list_all` corruption; tcache stashing and `tcache_perthread_struct`; ret2vdso; JOP/COP;
canary byte-brute against a forking server; `_rtld_global` lock gadgets.

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
3. **Large-bin attack → `_IO_list_all` / House of Cat.** The modern no-hook chain: a large-bin
   attack writes a HEAP pointer to a chosen address, which is exactly what corrupting
   `_IO_list_all` needs. Covers the case where `_IO_2_1_stderr_` is unusable.
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
