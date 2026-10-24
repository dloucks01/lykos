"""Corpus distillation (minset): reduce a fuzzing corpus to a coverage-preserving minimum.

"Seed Selection for Successful Fuzzing" (ISSTA'21) found that the *quality of the seed minset*
dominates the choice of fuzzer -- a smaller corpus that preserves total coverage makes every later
campaign spend its budget on new behaviour instead of re-running near-duplicate inputs. afl-cmin is
the classic tool; lykos does the same thing self-contained, using the **block-coverage tracer it
already has** (so it works on a stripped, cross-architecture binary with no instrumented build), and
adds no dependency: pure greedy set-cover over per-input block sets and deterministic.

Two pieces:
  * ``greedy_minset`` -- the pure algorithm: given each input's set of reached blocks, greedily keep
    the input that adds the most *new* blocks (ties broken toward the smaller input, as afl-cmin
    keeps the smallest input covering each feature) until the whole corpus's coverage is preserved.
    Inputs that add nothing a kept seed already covers are dropped.
  * ``block_coverage`` / ``distill`` -- run each corpus input once under the block tracer to get its
    coverage, then minset. Known crashers are always kept (a reproducer is never redundant), and a
    hard cap bounds the up-front tracing cost on a large corpus.

The result is a small, high-coverage seed set that seeds the directed/blind campaign; the campaign's
own coverage ratchet grows it from there.
"""
from __future__ import annotations

import heapq
import time
from typing import Callable, Iterable, Optional

#: How many inputs may come back with EMPTY coverage before we conclude the tracer is reporting
#: nothing at all on this target and stop asking. Measured on zlib's ASan `example` binary:
#: 12,584 blocks were recovered and armed, every one of 169 traces returned no coverage
#: ("the runner reported no coverage for any input; the campaign ran blind"), and the stage spent
#: 150 seconds of a 12-34 second slice finding that out 169 times over.
_SILENT_TRACER_PROBES = 8


def greedy_minset(coverage: dict, sizes: Optional[dict] = None) -> list:
    """Greedy weighted set-cover over ``{key -> set(block_addrs)}``.

    Returns the selected keys, in selection order, whose block-sets union to the SAME total the
    whole corpus covers. ``sizes`` (``{key -> weight}``, e.g. input length) breaks ties toward the
    smaller/cheaper input. Keys with empty coverage are dropped. Deterministic: on a full tie the
    lower key wins -- by the keys' own order, whatever their type (see `_ranks`).

    LAZY greedy (Minoux): a key's marginal gain only ever shrinks as coverage grows, so a stale
    gain is an upper bound and only the heap's top needs re-measuring. Same selection as the eager
    form, which rebuilt ``remaining[k] - covered`` for EVERY key on EVERY pick -- O(n^2 * |set|),
    measured 6.0 s against 0.64 s here on a 2,000-input corpus of 300-block traces.
    """
    sizes = sizes or {}
    keys = [k for k, v in coverage.items() if v]
    rank = _ranks(keys)
    universe = set()
    for k in keys:
        universe |= coverage[k]
    # (-gain, size, rank) ascending == the old max over (gain, -size, -rank)
    heap = [(-len(coverage[k]), sizes.get(k, 0), rank[k], i) for i, k in enumerate(keys)]
    heapq.heapify(heap)
    covered: set = set()
    selected: list = []
    while heap and len(covered) < len(universe):
        _neg, sz, rk, i = heapq.heappop(heap)
        k = keys[i]
        gain = len(coverage[k] - covered)
        if not gain:
            continue                                   # nothing left to add: never selectable
        fresh = (-gain, sz, rk, i)
        if heap and fresh > heap[0]:
            heapq.heappush(heap, fresh)                # someone may now beat it: re-queue
            continue
        selected.append(k)
        covered |= coverage[k]
    return selected


def _ranks(keys) -> dict:
    """key -> its position in a deterministic total order of the keys.

    The tie-break used to be ``hash(k)`` for a non-numeric key, and str/bytes hashing is salted
    per process (PYTHONHASHSEED): two runs over the same corpus kept DIFFERENT seeds on a tie,
    which is exactly what "deterministic" promised not to do. Natural order when the keys are
    mutually comparable (ints, strs), else (type name, repr)."""
    try:
        order = sorted(keys)
    except TypeError:
        order = sorted(keys, key=lambda k: (type(k).__name__, repr(k)))
    return {k: i for i, k in enumerate(order)}


def block_coverage(exe, inputs, blocks, *, mode: str = "stdin", base_argv=(),
                   timeout: float = 2.0, arch=None, endianness=None, bits=None,
                   host=None, cap: int = 256, deadline: Optional[float] = None) -> list:
    """Per-input reached-block sets via the sandbox block tracer.

    Each input is traced in ITS OWN batch: the tracer's breakpoints are one-shot *within* a batch,
    so a shared batch would report only each input's marginal (order-dependent) blocks, not its full
    coverage -- and the minset needs each input's independent coverage. Returns a list aligned with
    ``inputs`` (a set of block addresses per input; empty when tracing declined, e.g. a cross-arch
    or PE target). At most ``cap`` inputs are traced; the rest come back empty (kept upstream).
    """
    return [c for c, _ in _trace(exe, inputs, blocks, mode=mode, base_argv=base_argv,
                                 timeout=timeout, arch=arch, endianness=endianness, bits=bits,
                                 host=host, cap=cap, deadline=deadline)]


def _trace(exe, inputs, blocks, *, mode="stdin", base_argv=(), timeout=2.0, arch=None,
           endianness=None, bits=None, host=None, cap=256, deadline=None) -> list:
    """[(reached_block_set, crashed_bool)] per input, each traced in its own batch (see
    block_coverage). A crashed input is a reproducer the caller must keep regardless of coverage.

    Bounded two ways, because `cap` bounds the NUMBER of traces and the cost of one is a property
    of the target, not of this module. On zlib's ASan `example` binary each trace of a 12,584-block
    arming cost about a second, so a 169-input corpus under the default cap spent 150 seconds --
    five to twelve times the whole campaign slice the caller had -- and the campaign that
    distillation exists to speed up then got ZERO executions.

      * `deadline` (wall clock): stop tracing and let the rest come back unmeasured. `distill`
        keeps an unmeasured input ("absence of evidence is not redundancy"), so stopping early
        costs minset quality and never correctness.
      * a SILENT TRACER: if the first `_SILENT_TRACER_PROBES` traces all report no coverage, the
        mechanism is not working on this target (no ptrace in the sandbox, a cross-arch image)
        and the remaining traces cannot tell us anything either.
    """
    from ..dynamic import sandbox
    blocks = tuple(blocks or ())
    out, traced, silent = [], 0, 0
    for i, data in enumerate(inputs):
        if i >= cap or not blocks:
            out.append((set(), False))
            continue
        if deadline is not None and time.time() >= deadline:
            out.append((set(), False))
            continue
        if silent >= _SILENT_TRACER_PROBES and traced == silent:
            out.append((set(), False))
            continue
        res = sandbox.run_batch(exe, [data], mode=mode, base_argv=base_argv, timeout=timeout,
                                arch=arch, endianness=endianness, bits=bits, host=host,
                                blocks=blocks)
        traced += 1
        if res:
            hit = set(res[0].blocks_hit or ())
            out.append((hit, bool(res[0].crashed)))
            if not hit:
                silent += 1
        else:
            out.append((set(), False))
            silent += 1
    return out


def distill(inputs: list, cover_sets: list, *, keep_idx: Iterable[int] = ()) -> dict:
    """Minset a corpus given each input's coverage set. Returns ``{kept, dropped, order, stats}``.

    ``inputs`` and ``cover_sets`` are aligned lists. ``keep_idx`` are indices that must be kept
    regardless of coverage (crash reproducers). The kept list preserves the corpus's total block
    coverage; ``dropped`` are the redundant inputs. Inputs whose coverage could not be measured
    (empty set) are kept when they are not shown redundant -- we never discard on missing evidence.
    """
    keep = set(keep_idx)
    coverage = {i: cover_sets[i] for i in range(len(inputs)) if cover_sets[i]}
    sizes = {i: len(inputs[i]) for i in range(len(inputs))}
    order = greedy_minset(coverage, sizes)             # once: it was computed twice
    picked = set(order)
    # Anything with no measured coverage is kept (absence of evidence is not redundancy); so are the
    # forced-keep crashers. Only inputs that HAD coverage and were not picked are dropped.
    kept_idx = [i for i in range(len(inputs))
                if i in picked or i in keep or not cover_sets[i]]
    kept = [inputs[i] for i in kept_idx]
    dropped = len(inputs) - len(kept)
    total_blocks = set()
    for c in cover_sets:
        total_blocks |= c
    return {
        "kept": kept, "kept_idx": kept_idx, "dropped": dropped,
        "order": order,
        "stats": {"in": len(inputs), "out": len(kept), "dropped": dropped,
                  "blocks_preserved": len(total_blocks),
                  "measured": sum(1 for c in cover_sets if c)},
    }


def distill_corpus(exe, inputs: list, blocks, *, keep_idx: Iterable[int] = (),
                   mode: str = "stdin", base_argv=(), timeout: float = 2.0,
                   arch=None, endianness=None, bits=None, host=None,
                   cover_fn: Optional[Callable] = None, cap: int = 256,
                   deadline: Optional[float] = None) -> dict:
    """Convenience: trace ``inputs`` for block coverage, then ``distill``. ``cover_fn`` replaces the
    tracer (for tests). Returns ``distill``'s dict."""
    keep = set(keep_idx)
    if cover_fn is not None:
        cover = [set(cover_fn(d)) for d in inputs]
    else:
        traced = _trace(exe, inputs, blocks, mode=mode, base_argv=base_argv, timeout=timeout,
                        arch=arch, endianness=endianness, bits=bits, host=host, cap=cap,
                        deadline=deadline)
        cover = [c for c, _ in traced]
        # a traced input that crashed is a reproducer -- keep it whatever its coverage.
        keep |= {i for i, (_, crashed) in enumerate(traced) if crashed}
    return distill(inputs, cover, keep_idx=keep)
