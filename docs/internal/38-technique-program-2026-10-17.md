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
of Apple 2 (one-piece, split, and the five-cell form for a one-word-at-a-time writer), the heap
and C++ hijacks (adjacent code pointer, vtable, indexed-write GOT), and — new — the WASM
indirect-call redirect.

**Knowledge-base only:** fastbin_dup, House of Spirit, House of Force, unlink, unsorted-bin
attack, large-bin attack.

**Absent:** stack pivot; `setcontext` register control; `__exit_funcs`/`atexit` and TLS
`dtor_list`; House of Apple 1/3, House of Cat and `_IO_list_all` corruption; tcache stashing and
`tcache_perthread_struct`; ret2vdso; JOP/COP; canary byte-brute against a forking server;
`_rtld_global` lock gadgets.

## The order, and why

Each item below is one unit of work: the technique, a fixture where it is the ONLY route, a
conformance case demanding the rung, and a measured run. The order is value × feasibility on the
glibc actually installed here, not textbook order.

1. **Stack pivot** (`leave; ret`, `pop rsp`, `add rsp, N`). No allocator dependence, pure gadget
   work, and it unlocks a class the engine currently abandons: an overflow with only a few words
   past the saved return address cannot hold a ret2libc chain, so today it stops at L2 with the
   offset proved. A pivot moves `rsp` into a buffer that CAN hold the chain.
2. **`setcontext` register control.** One controlled write plus a pointer to a fake `ucontext`
   gives every register, which is the standard modern finish for a write-what-where when the
   FILE route is blocked. Pairs directly with the five-cell writer already built.
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
