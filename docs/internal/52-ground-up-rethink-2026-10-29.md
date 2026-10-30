# 52 — Ground-up rethink: static vuln → validated PoC (2026-10-29)

**Operator ask, verbatim intent:** look at a binary or source tree, find the vulnerabilities
(statically first), and produce a PoC/exploit for each one found. LLM-free, fully air-gapped.

**Bottom line:** lykos has strong parts: ingest, sandboxing, emulation, and the exploit ladder for a
crash it already has. What it lacks is the one loop the task needs:
**finding → solve for an input that reaches it and triggers it → run that input to validate it →
weaponize.**

Today a static finding never produces an input. Every working PoC comes from a fuzzer that knows
nothing about the findings, so findings and PoCs live on two disconnected tracks. Fifty-eight stages
and about 117k lines grew around that gap without closing it. The fix is a new core, not more stages.

---

## 1. Evidence: a 4-bug test program, run the way an operator would

The test target is `rec.c`, a 60-line record parser. Its input file is a 2-byte `"RC"` magic, then
records of [type u8][len u16][payload]. It has four planted bugs:

| # | Bug | Site |
|---|---|---|
| B1 | `memcpy(tmp[64], p, len)`, with `len` up to 65535 taken from the file → stack overflow and RIP control | `handle_name` |
| B2 | count byte up to 255 used to index `items[16]` → stack out-of-bounds write | `handle_items` |
| B3 | `printf(msg)` where `msg` comes from the file → format string | `handle_log` |
| B4 | `malloc(cnt*sz)`, a 32-bit wrap → heap overflow | `handle_blob` |

Results (300 s budget for each lykos run):

| | lykos (binary) | lykos (source dir) | CodeQL security-extended | cppcheck / clang SA | **Prototype: finding → angr solve → run it** |
|---|---|---|---|---|---|
| B1 stack overflow | **missed**. Only a "memcpy (verify length is bounded)" low lint; `build_exploit`: "cyclic pattern did not fault" | PoC, but from the fuzzer | missed | missed | **PoC in 71 s.** ASan `stack-buffer-overflow rec.c:11`; RIP=0 on the real binary |
| B2 OOB index | PoC from the fuzzer (5 duplicate bundles of the same bug) | missed | missed | missed | not attempted |
| B3 format string | "recipe" whose payload omits the `RC\x03<len>` framing, so it can never reach `printf`; blamed on "air-gap" | same recipe; static check rated it **low/hygiene** | found | missed | **PoC in 3 s.** SIGSEGV inside `printf` on `%n%n` |
| B4 int-overflow alloc | crash from the fuzzer | missed (low candidate) | found | missed | not attempted |
| False/noise items | 13 "detected only" lints | 18 "detected only"; `fopen(argv[1])` rated **HIGH** (the operator picks that file) | 1 (argv path) | 5 noise (clang) | — |

What this shows:

1. **No PoC came from static analysis.** Every demonstrated bug came from a fuzzer that happened to
   crash, and each run caught a different subset (binary run: B2+B4; source run: B1).
2. **Detection is lexical.** The binary detectors are regexes over disassembly text
   (`detectors.py`, 5.6k lines; `_x86_aliases`, mnemonic matching). The source detectors are regexes
   over lines (`source_sinks.py`, `srcwalk.py`).
   - Neither models buffer sizes, value ranges, or where an input value flows.
   - So the most canonical bug, a memcpy whose length comes from input into a fixed stack buffer, is
     a "verify length" lint.
   - The precision pass from earlier today then ranks the real format string *low* and an argv path
     *high*.
3. **Recipes ignore the path condition.** The format-string payload is a bare `%p` string. It never
   reaches the sink because nothing computed that the file must start with `RC`, carry type 3, and
   have a consistent length.
   - "Could not confirm (air-gap / unreachable)" is a misdiagnosis: the binary ran fine locally.
4. **Ordering starves the right engine.** `concolic` is scheduled last and was "skipped — no budget
   left" in both runs. Fuzzing ate 51–80% of the budget.
5. **The per-finding mitigation text is boilerplate.** The B3 finding says "PIE, canary, full RELRO"
   on a `-no-pie -fno-stack-protector` partial-RELRO binary. The target-level mitigations are right;
   the finding copies a generic list.
6. The CLI `analyze` refuses a source directory ("not a file"), although `ingest()` supports one.
   Only the GUI path works.

**What closed B1 and B3 here:** one solver call per finding. Explore from the program entry to the
sink address, then add the violation as a constraint (`len > 64+8+8`, or format bytes `== "%n%n"`),
then concretize the symbolic file.
- The magic, type byte and length field fall out of the path condition automatically. Nobody wrote
  a parser model.
- The first B3 solve was **wrong**: angr's `snprintf` model let it choose len=0. Running the input
  caught it, and adding a constraint fixed it. This is exactly why the validator is mandatory.
- The prototypes are in Appendix A.

---

## 2. What the field says (LLM-free lens; sources in Appendix B)

- **"Static proposes targets, execution decides."** Every high-precision system gates "confirmed"
  on running a concrete input under a sanitizer or oracle. This holds for both LLM and non-LLM
  systems (AIxCC, FuzzSlice, Naptime).
- **Pattern SAST alone is a dead end for this task.**
  - On real CVEs, each tool misses 47–80% (Lipp et al., ISSTA'22).
  - At least 76% of warnings in vulnerable functions are irrelevant (Charoenwet, ISSTA'24).
  - No classic tool exceeds 35% recall even on micro-benchmarks (CASTLE'25).
  - **Do not try to win by adding more detectors.** Our own numbers agree: FreeRDP recall was 6/180
    with 932 raw findings.
- **Reaching is not triggering.** In Magma, a sink was reached in 10 s and triggered after about
  20 h. Atlantis reached 73.8% of sinks but triggered 35.7%. The engine has to solve for the
  *violation*, not just for reachability. These are security predicates in the style of Sydr and
  SAVIOR: solve `len > cap`, `idx >= n`, or "the multiplication overflows" at the sink.
- **Static output should be used as target locations, not as path guidance.** Feeding analyzer
  traces into symbolic execution added about 0× (Busse et al., ISSTA'22), while targeting gave
  about 4×.
- **Directed and undirected engines run together, never directed alone.** On Magma, AFLGo triggered
  41 bugs against 49 for AFL++ with CmpLog.
- **Function-level / under-constrained crashes are only "potential" until a real caller reproduces
  them.** This is the main source of false crashes: Hopper had 26 of 51 spurious; UC-KLEE had heavy
  false positives. The fix is to climb through callers (CCBSE, SnipTest levels).
- **Robustness beat cleverness in AIxCC.**
  - Plain parallel fuzzing with the given harnesses triggered 75% of the C bugs.
  - Most misses were pipeline failures: no N-run replay, the wrong sanitizer for the class,
    over-coarse dedup, disk exhaustion.
  - Shellphish's "reproduces 5× in a row" rule gave the best PoV accuracy (94.8%).
- **Classic AEG starts from a crash** (Mayhem, Revery, MAZE). lykos's exploit ladder is already that
  piece. What it has been missing is a reliable feed of validated, correctly framed inputs.
- **Honest expectations on real code:**
  - Symbolic validation leaves about 30–40% of candidates undecided (timeouts).
  - Binary-only static finders reach about 40–60% true alerts.
  - Report "undecided" as undecided, never as a bug.

---

## 3. Target architecture: one loop, six parts

The central new object is the **Hypothesis**. It replaces "finding" as the unit of work, and it is
what links a static result to its PoC.

```
Hypothesis = {
  site:        function + address (binary) / file:line (source, plus DWARF address)
  class:       CWE + primitive kind (stack-write, heap-write, oob-index, fmt, int-wrap->alloc, cmd)
  predicate:   machine-checkable violation at the site, over program state
               e.g. rdx > frame_cap(tmp); idx >= 16; fmt_bytes contain '%'; cnt*sz wraps
  source:      which input channel feeds it (file / stdin / argv / env / socket) + taint evidence
  status:      proposed -> reached -> TRIGGERED(validated) | potential(UC only) | undecided | refuted
  poc:         concrete input bytes + how they are delivered (argv/@@/stdin)
  evidence:    sanitizer/oracle report whose crash frame MATCHES site; N-run replay count
  exploit:     the ladder's L2/L3 result, built on top of poc
}
```

The six parts:

1. **Program model, built once per target.**
   - Binary: angr CFG + VEX, with Ghidra/rizin for recovery (which exist today).
   - Source: compile it, then run the **same binary engine on the `-g` build**, mapping to file:line
     through DWARF. A separate ASan/UBSan build is the validator.
   - One trigger engine then serves both input kinds, which removes the separate "source track".
   - Optional source enrichment: Joern CPG (Apache-2.0). CodeQL is installed, but **its licence does
     not cover analysing closed-source code without a GHAS licence**, so it is a dev and benchmark aid
     only, not a bundle dependency.
2. **Proposers (static, high recall).** These are per-class checkers that emit Hypotheses *with
   predicates*, not prose. They use value-set / interval analysis on the lifted IR for buffer
   capacities and ranges, plus taint from the input channel. The dangerous-API, bounds and
   srctaint logic is reused, but its output becomes predicates.
   - **Precision is not their job.** Abstract interpretation is used only to prune sites proved safe.
   - Ranking orders the queue; it is not a verdict.
3. **Trigger engine (per hypothesis, cheapest first).**
   - **a. Directed symbolic reach + violate** from the real entry. Exploration is ordered by CFG
     distance to the site, then the predicate is added and the input solved (the Appendix A
     prototype).
   - **b. Backward climb (CCBSE).** If (a) stalls, start symbolic execution at the site's function
     and climb callers toward main. A function-only solve is `potential`.
   - **c. Hybrid fallback.** If symbolic times out, seed directed fuzzing with (a)'s partial prefix,
     and keep undirected AFL++/CmpLog running in parallel. Fuzzing becomes the fallback engine of a
     hypothesis, not the discovery engine.
   - Budget is per hypothesis, with a plateau bail-out (the reach-gate policy already decided).
4. **Validator, the only path to "confirmed".**
   - Run the concrete input under ASan/UBSan (source), or under qemu/gdb with a site-specific oracle
     (binary). Examples of a site-specific oracle:
     - a watch on the write past the frame;
     - PC equals the pattern at `ret`;
     - a `%n` write observed.
   - **The crash frame must match the hypothesis site.**
   - Replay N≥3 times.
   - A mismatch or no-trigger result feeds a counterexample back to (3a) and the input is re-solved.
5. **Weaponize.** Hand the validated input to the existing exploit ladder. It now carries the
   correct framing prefix and the solved field layout, which is what the recipes were missing.
   Static recipes stay only as an annotation on a validated PoC, never as a standalone "finding".
6. **Report: one entry per validated root cause.** Each entry gives the site, the violation, the
   PoC bytes (hex plus a delivery line), the validator output, and the exploit level.
   - Undecided and potential hypotheses go in a separate, clearly labelled list.
   - Lint-style "check X is not tainted" items are not findings.

**North-star metric (replaces stage counts and feature lists):** *validated PoCs at the correct site
÷ known bugs*, together with *false confirmations = 0*. It is measured on a fixed corpus every
change:

- **Tier 0:** about 30 small planted-bug programs, `rec.c`-style, covering ~8 classes and
  x86-64/aarch64, each with a known site. Runs in CI in minutes.
- **Tier 1 (binary-only ground truth):** the DARPA CGC challenge binaries (Linux port,
  `cb-multios`). Each ships a known vulnerability and a reference PoV.
- **Tier 2 (source ground truth):** a Magma or ARVO subset. Each has a reproducible crashing input
  and its fix.

---

## 4. Keep / replace / freeze

- **Keep (they work, and they feed the new loop):**
  - ingest/triage/ELF/PE parsing;
  - sandbox (bwrap) and qemu-user;
  - the gdbstub capture;
  - the exploit ladder (`exploit_stage`, `rop*`, `archmodel`, `leak`, `fmt`, `heap`);
  - PoC bundles and replay scripts;
  - case store and reports;
  - the angr and symqemu venvs;
  - the fuzzers, demoted to fallback.
- **Replace:**
  - **Detection:** regex-over-text becomes predicate-emitting proposers on lifted IR.
  - **Orchestration:** the 58-stage plan becomes the Hypothesis loop (propose → trigger → validate
    → weaponize). The other stages become optional tools around it.
  - **Recipes as findings:** they become annotations on validated PoCs only.
- **Freeze until the metric moves:** new architectures, firmware, PE depth, new GUI figures, new
  detectors, new stages.

## 5. Build order (each step has an exit test on the corpus)

| Step | Work | Exit criterion |
|---|---|---|
| 0 | Tier-0 corpus + scorer (`lykos bench`); score today's lykos as the baseline | baseline number recorded |
| 1 | `Hypothesis` object + store; CLI accepts source dirs | — |
| 2 | Trigger engine (3a) + validator (4) for the 5 core classes: stack/heap copy overflow, OOB index write, format string, int-wrap→alloc, command injection | Tier-0 ≥ 80% validated, 0 false confirmations |
| 3 | Proposers on lifted IR (value-set capacities + input taint) emitting predicates | Tier-0 recall without hand-given sites |
| 4 | Ladder consumes validated hypotheses (framing-aware) | B1-style → L3 shell; B3 → `%n` write-what-where |
| 5 | CCBSE climb + hybrid fallback + per-hypothesis budgets | Tier-1 CGC: measured, then improved |
| 6 | Scale: function summaries, libc models checked against execution, loop bounding | Tier-2 subset measured |

---

## Appendix A — prototypes (angr venv; `python -I`)

`rec` built `-O0 -g -no-pie -fno-stack-protector`. Same 4-bug source as above.

```python
# B1: reach memcpy@0x401302 in handle_name, require len past saved RIP, solve the file
p = angr.Project(BIN, auto_load_libs=False); N = 260
content = claripy.BVS("file", N * 8)
st = p.factory.full_init_state(args=[BIN, "in.rc"], fs={"in.rc": angr.SimFile("in.rc", content=content, size=N)},
     add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
sm = p.factory.simulation_manager(st); sm.explore(find=0x401302, num_find=1)
s = sm.found[0]; s.solver.add(s.regs.rdx > 64 + 8 + 8, s.regs.rdx < N - 5)
poc = s.solver.eval(content, cast_to=bytes)       # -> 52 43 01 fb 00 ... (RC, type 1, len 251)
# B3: reach printf@0x401410, require the format bytes == "%n%n" AND 4 <= len <= 8
#     (without the len bound angr's snprintf model "solved" len=0 -> no crash; validator caught it)
```

Measured: B1 solved in 71 s (unguided `explore`; distance-ordered search should cut this), ASan
`stack-buffer-overflow rec.c:11`, RIP=0 on the real binary. B3 solved in 3 s, SIGSEGV in
`__printf_buffer` on the format `"%n%n"`.

## Appendix B — key sources

- SoK: DARPA AIxCC (2026) — https://arxiv.org/abs/2602.07666
- ATLANTIS report — https://arxiv.org/abs/2509.14589
- Lipp et al., ISSTA'22, SAST on real C CVEs — https://mediatum.ub.tum.de/doc/1659728/1659728.pdf
- Charoenwet et al., ISSTA'24 — https://arxiv.org/abs/2407.12241
- CASTLE benchmark — https://arxiv.org/html/2503.09433v2
- Busse et al., ISSTA'22, static analysis → directed symbolic execution — https://srg.doc.ic.ac.uk/files/papers/sa-dse-issta-22.pdf
- Ma et al., SAS'11, directed symbolic execution / CCBSE — https://www.cs.umd.edu/~mwh/papers/ma11directed.html
- SAVIOR — https://arxiv.org/pdf/1906.07327
- Sydr security predicates — https://arxiv.org/pdf/2211.11595v2.pdf
- FuzzSlice, ICSE'24 — https://arxiv.org/html/2402.01923v1
- DAFL, USENIX Security'23 — https://www.usenix.org/conference/usenixsecurity23/presentation/kim-tae-eun
- Magma — https://arxiv.org/abs/2009.01120
- ARVO — https://arxiv.org/abs/2408.02153
- UC-KLEE — https://www.usenix.net/system/files/conference/usenixsecurity15/sec15-paper-ramos.pdf
- Pulse-X / Incorrectness Separation Logic — https://discovery.ucl.ac.uk/id/eprint/10146384/1/3527325.pdf
- Operation Mango — https://www.usenix.org/conference/usenixsecurity24/presentation/gibbs
- Arbiter — https://www.usenix.org/conference/usenixsecurity22/presentation/vadayath
- Revery — https://nisl.github.io/files/papers/ccs18-revery.pdf
- MAZE — https://www.usenix.org/conference/usenixsecurity21/presentation/wang-yan
