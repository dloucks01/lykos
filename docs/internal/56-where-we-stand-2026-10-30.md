# 56 — What we decided, what's different, where we keep going wrong, how forward (2026-10-30)

A consolidation of the doc-52 rethink and everything learned building it (docs 53/54/55). Written
because the one failure mode that keeps recurring is drifting off the plan; this is the anchor.

## 1. The decision (doc 52)

**The one task:** point lykos at a binary or a source tree, find the vulnerabilities (statically
first), and produce a **validated PoC** for each. LLM-free, air-gapped.

**The core object is the Hypothesis, not the "finding".** A hypothesis carries a machine-checkable
*predicate* (the violation at a site: `len > cap`, `idx >= n`, `cnt*sz` wraps, format bytes contain
`%`, divisor can be 0, path escapes its base, …) and a path to a PoC — not prose.

**The one loop:**
```
propose    static, high-recall, predicate-emitting (precision is NOT its job)
  -> trigger   directed symbolic reach + SOLVE THE VIOLATION, cheapest engine first
  -> validate  replay a concrete input under a class-correct oracle -- the ONLY path to "confirmed"
  -> weaponize feed the validated PoC (with its framing) to the exploit ladder
```

**North-star metric (replaces stage/feature counts):** *validated PoCs at the correct site ÷ known
bugs, with **false confirmations = 0***, measured on a fixed corpus every change:
Tier-0 (planted) → Tier-1 (CGC cb-multios, binary ground truth) → Tier-2 (Magma/ARVO, source).

**Why (the research, LLM-free lens):** static proposes targets, *execution decides*; pattern SAST
alone is a dead end (misses 47–80% of real CVEs — do not add more detectors); *reaching is not
triggering* — solve the violation, not reachability; static output is target locations, not path
guidance; directed and undirected engines run together, never directed alone; function-level /
under-constrained crashes are only *potential* until a real caller reproduces them; robustness beats
cleverness (N-run replay, the right sanitizer per class).

## 2. What we're doing differently, and why

- **Validation is the only gate.** Nothing is "confirmed" without a real replay whose oracle fires
  AT the hypothesis site. *Why:* the solver's own models are unsound (angr's snprintf let it "solve"
  len=0 and not crash); `false confirmations = 0` is inviolable and the solver's claim is never the
  finding.
- **Solve the violation, not reachability.** The trigger engine adds the predicate as a constraint
  and concretises the input. *Why:* on Magma a sink was *reached* in 10 s and *triggered* after ~20 h.
- **One engine for source and binary.** Compile source with `-g`, run the SAME binary engine on it,
  map to file:line via DWARF; a separate ASan/UBSan (or MSan/LSan/vptr) build is the oracle. *Why:*
  it kills the old separate "source track" where findings and PoCs never met.
- **Directed first; fuzzing is a demoted, SEEDED, GATED fallback.** AFL++/CmpLog runs only when the
  directed engine confirmed nothing, seeded with the inputs the directed engine already reached the
  sinks with, and every crash is validated + attributed through the SAME hypothesis validator.
  *Why:* directed is precise but stalls on structure; fuzzing is robust but was the old disconnected
  discovery crutch. Together, never alone — and the fuzzer only *proposes inputs*, it can never
  *confirm*. (This is the distinction that makes the fallback NOT a reversion to the old tool.)
- **Freeze breadth until the metric moves** — no new architectures, detectors, GUI, stages.

## 3. Where we keep going wrong (the honest part)

1. **We drift toward breadth instead of the metric.** The original tool grew to 58 stages / ~117k
   lines *around* the gap without closing it. The same pull is still here: this build added 19 CWEs,
   7 oracle types, two weaponizers, a tool inventory — each defensible — yet we have **not produced a
   single Tier-1 (real CGC) validated number**. Activity is not the metric.
2. **The gate looks sound until something adversarially tests it.** The audit (doc 55) found REAL
   defects hiding behind a green Tier-0: a resource-exhaustion false confirmation (an always-slow
   program), a cmd-injection false-positive path, and — worst — the native-crash oracle was **dead**
   (fault_pc always None), so no binary-only target could EVER have validated. "0 false confirmations"
   is only true where we actually tried to break it.
3. **We over-trust the planted Tier-0 corpus.** 73% at 0 false confirmations is on *our own* planted
   bugs — designed to be findable. It measures the loop against itself. Tier-1/Tier-2 (real ground
   truth) is still unmeasured, and we keep polishing Tier-0 instead of facing it.
4. **Scale/cost keeps biting, and we keep being surprised by it.** angr OOMed at 6 GB (o02); a static
   CGC binary flooded the proposer with 3,145 libc hypotheses; there are still no per-hypothesis
   budgets. Symbolic execution not scaling is a *known* property of the field, not a surprise to
   discover each time.
5. **The directed engine stalls on structured input, and we reach for fuzzing** — the exact instinct
   the rethink warned about. It is a legitimate fallback (§2 above), but every time we lean on it we
   are admitting the directed path (CCBSE, value-set proposers) is not yet strong enough to carry its
   own weight. The fix is to strengthen directed, not to widen the fallback's job.

## 4. How we go forward

1. **Measure Tier-1/Tier-2 FIRST, then improve against the number.** Stop polishing Tier-0. Get the
   real CGC/Magma baseline even if it is embarrassingly low — that number is the north star and it
   tells us what actually breaks on real code.
2. **Gate every change on the metric:** Tier-X validated must go up (or hold) AND false confirmations
   must stay 0. If a change doesn't move the number on real targets, it doesn't ship.
3. **Adversarially test the gate on every new oracle** — try to construct a program that gets a false
   confirmation — before trusting it. This is the invariant, re-earned each time.
4. **Strengthen the DIRECTED engine so fuzzing stays a true last resort:** CCBSE backward climb
   (potentials, then climb to a reachable input), value-set/interval proposers emitting predicates,
   per-hypothesis budgets. The fuzz fallback stays gated and seeded; its job does not grow.
5. **Treat scale as a first-class constraint:** memory bounds, per-hypothesis budgets, function
   summaries, CB scoping — not afterthoughts discovered at OOM time.
6. **Keep breadth frozen** until the metric moves on real targets.

**Immediate next:** CCBSE (strengthen directed reach on deep functions) → the Tier-1 CGC sweep for
the first real number. Then let that number — not a feature list — drive what comes next.
