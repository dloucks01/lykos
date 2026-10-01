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

from typing import Callable, Iterable, Optional


def greedy_minset(coverage: dict, sizes: Optional[dict] = None) -> list:
    """Greedy weighted set-cover over ``{key -> set(block_addrs)}``.

    Returns the selected keys, in selection order, whose block-sets union to the SAME total the
    whole corpus covers. ``sizes`` (``{key -> weight}``, e.g. input length) breaks ties toward the
    smaller/cheaper input. Keys with empty coverage are dropped. Deterministic: on a full tie the
    lower key wins.
    """
    sizes = sizes or {}
    universe = set()
    for v in coverage.values():
        universe |= v
    remaining = {k: set(v) for k, v in coverage.items() if v}
    covered: set = set()
    selected: list = []
    while covered != universe and remaining:
        # most new blocks; tie-break smaller size, then lower key (for stable output)
        best = max(remaining,
                   key=lambda k: (len(remaining[k] - covered), -sizes.get(k, 0), -_ordkey(k)))
        gain = remaining[best] - covered
        if not gain:
            break
        selected.append(best)
        covered |= remaining[best]
        del remaining[best]
    return selected


def _ordkey(k):
    """A numeric ordering for the tie-break, whatever the key type."""
    if isinstance(k, (int, float)):
        return k
    try:
        return hash(k) & 0xFFFFFFFF
    except TypeError:
        return 0


def block_coverage(exe, inputs, blocks, *, mode: str = "stdin", base_argv=(),
                   timeout: float = 2.0, arch=None, endianness=None, bits=None,
                   host=None, cap: int = 256) -> list:
    """Per-input reached-block sets via the sandbox block tracer.

    Each input is traced in ITS OWN batch: the tracer's breakpoints are one-shot *within* a batch,
    so a shared batch would report only each input's marginal (order-dependent) blocks, not its full
    coverage -- and the minset needs each input's independent coverage. Returns a list aligned with
    ``inputs`` (a set of block addresses per input; empty when tracing declined, e.g. a cross-arch
    or PE target). At most ``cap`` inputs are traced; the rest come back empty (kept upstream).
    """
    return [c for c, _ in _trace(exe, inputs, blocks, mode=mode, base_argv=base_argv,
                                 timeout=timeout, arch=arch, endianness=endianness, bits=bits,
                                 host=host, cap=cap)]


def _trace(exe, inputs, blocks, *, mode="stdin", base_argv=(), timeout=2.0, arch=None,
           endianness=None, bits=None, host=None, cap=256) -> list:
    """[(reached_block_set, crashed_bool)] per input, each traced in its own batch (see
    block_coverage). A crashed input is a reproducer the caller must keep regardless of coverage."""
    from ..dynamic import sandbox
    blocks = tuple(blocks or ())
    out = []
    for i, data in enumerate(inputs):
        if i >= cap or not blocks:
            out.append((set(), False))
            continue
        res = sandbox.run_batch(exe, [data], mode=mode, base_argv=base_argv, timeout=timeout,
                                arch=arch, endianness=endianness, bits=bits, host=host,
                                blocks=blocks)
        if res:
            out.append((set(res[0].blocks_hit or ()), bool(res[0].crashed)))
        else:
            out.append((set(), False))
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
    picked = set(greedy_minset(coverage, sizes))
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
        "order": greedy_minset(coverage, sizes),
        "stats": {"in": len(inputs), "out": len(kept), "dropped": dropped,
                  "blocks_preserved": len(total_blocks),
                  "measured": sum(1 for c in cover_sets if c)},
    }


def distill_corpus(exe, inputs: list, blocks, *, keep_idx: Iterable[int] = (),
                   mode: str = "stdin", base_argv=(), timeout: float = 2.0,
                   arch=None, endianness=None, bits=None, host=None,
                   cover_fn: Optional[Callable] = None, cap: int = 256) -> dict:
    """Convenience: trace ``inputs`` for block coverage, then ``distill``. ``cover_fn`` replaces the
    tracer (for tests). Returns ``distill``'s dict."""
    keep = set(keep_idx)
    if cover_fn is not None:
        cover = [set(cover_fn(d)) for d in inputs]
    else:
        traced = _trace(exe, inputs, blocks, mode=mode, base_argv=base_argv, timeout=timeout,
                        arch=arch, endianness=endianness, bits=bits, host=host, cap=cap)
        cover = [c for c, _ in traced]
        # a traced input that crashed is a reproducer -- keep it whatever its coverage.
        keep |= {i for i, (_, crashed) in enumerate(traced) if crashed}
    return distill(inputs, cover, keep_idx=keep)
