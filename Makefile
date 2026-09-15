# Lykos — offline dev + CI targets (P0.11). Runtime is stdlib-only.
PY ?= python3
export PYTHONPATH := core

.PHONY: doctor toolchain-bundle test coverage lint typecheck gui ci bundle verify run eval eval-gate arch-gate real-gate dashboard release clean help

help:
	@echo "targets: doctor toolchain-bundle test coverage lint typecheck gui ci bundle verify run eval eval-gate arch-gate dashboard release clean"

# What this host can and cannot do, and the install line for anything missing. On an
# air-gapped workstation there is no package manager to ask, and "the stage declined" is a
# poor way to discover an engine was never installed.
doctor:
	@$(PY) -m lykos doctor

# Build the air-gap toolchain bundle (run on a CONNECTED machine). See docs/23.
toolchain-bundle:
	bash packaging/collect-toolchain.sh

test:
	$(PY) -m pytest tests/ -q

# Line/branch coverage INCLUDING the capabilities that only exist as subprocesses. Without
# the sitecustomize shim below, the ptrace helper, the AFL++ batch runner and the angr and
# unicorn drivers all report 0% -- not because nothing drives them, but because a subprocess
# started by a test is not measured by the test's own interpreter. That reads as "five
# untested modules" when the truth is "five unobservable ones", and the two call for opposite
# work. COVERAGE_PROCESS_START plus a sitecustomize on PYTHONPATH makes every child write its
# own data file, which `coverage combine` then merges.
COV_DIR := .coverage-shim
coverage:
	@command -v coverage >/dev/null 2>&1 || $(PY) -c "import coverage" 2>/dev/null || { \
	  echo "coverage not installed. pip install coverage" >&2; exit 1; }
	@mkdir -p $(COV_DIR)
	@printf 'import coverage\ncoverage.process_startup()\n' > $(COV_DIR)/sitecustomize.py
	@rm -f .coverage .coverage.*
	COVERAGE_PROCESS_START=$(CURDIR)/.coveragerc \
	PYTHONPATH=$(CURDIR)/$(COV_DIR):$(CURDIR)/core \
	  $(PY) -m coverage run -m pytest tests/ -q
	$(PY) -m coverage combine
	$(PY) -m coverage report --skip-covered --sort=miss
	@echo "(full report: coverage report; annotated: coverage html)"

# lint/typecheck are gates, not suggestions: a missing tool FAILS rather than passing
# quietly, so `make ci` can never go green without actually having run them.
lint:
	@command -v ruff >/dev/null 2>&1 || { \
	  echo "ruff not installed -- gate cannot run. pip install ruff" >&2; exit 1; }
	ruff check core tests

# Two-tier gate (see mypy.ini): strict over the infra core (db/jobs/hashing/casestore),
# errors not reported for the dict-passing analysis/API/report/eval layers.
typecheck:
	@command -v mypy >/dev/null 2>&1 || { \
	  echo "mypy not installed -- gate cannot run. pip install mypy" >&2; exit 1; }
	mypy core/lykos

# The GUI harnesses render the page's own script against a stubbed DOM and assert what comes
# out. They run under pytest too, but there they SKIP when node is absent -- and a skip is
# invisible in a green run, which is the same "decorative gate" failure this file already
# warns about for lint/typecheck and for the FP budget. So node missing FAILS here.
#
# They exist because every other GUI assertion in the suite checks that source text EXISTS --
# a function is named, a label appears -- and none of them would notice a board that renders
# zero rows. One such bug got as far as a commit: `t.open || ... || BOARD_OPEN[k]`
# short-circuits, so the chevron on a default-open tier did nothing at all.
GUI_PAGE ?= core/lykos/api/static/index.html

gui:
	@command -v node >/dev/null 2>&1 || { \
	  echo "node not installed -- GUI gate cannot run. Install node (or run the harnesses" >&2; \
	  echo "via 'make test', where they skip rather than fail)." >&2; exit 1; }
	@for h in tests/js/*.js; do \
	  echo "== $$h"; node "$$h" "$(GUI_PAGE)" || exit 1; \
	done

ci: lint typecheck gui test
	@echo "CI complete"

bundle:
	bash packaging/build.sh

verify: bundle
	bash packaging/verify.sh

run:
	$(PY) -m lykos serve --http 127.0.0.1:8787 --case-store .cases --workers 2

eval:
	$(PY) -m lykos eval --out eval-report.json

# Release gate: benchmark detection quality (doc 14) and fail on regression.
# The dynamic (confirmed-stage) gate needs only gcc; the static gates need Ghidra and SKIP
# cleanly when it is absent (see `lykos eval` gate logic).
#
# On the static FP budget: the corpus carries DISCRIMINATION negatives -- good cases that
# call the dangerous sink correctly (guarded strcpy, clamped memcpy, literal-format printf,
# constant-command system). A rule-only detector flags those at `candidate`, which is honest
# behaviour for a pattern rule, so the candidate-stage budget is a RATCHET at the currently
# measured rate rather than 0: it cannot pass a detector that fires more broadly than today's
# does. Tighten the number whenever the real rate drops. (Before those negatives existed the
# corpus had no false-positive surface at all, so `--max-fp-rate 0.0` could not fail under
# any code change -- the gate was decorative.)
STATIC_FP_BUDGET ?= 0.60

# Corroborated stage: the data-flow channel, and the reason the confidence lifecycle exists.
# It trades a little recall for a large precision gain over the rule channel -- measured
# x86-64 / Ghidra 12.1: recall 1.00 -> 0.83, fp_rate 0.571 -> 0.214, precision 0.43 -> 0.62.
# Both thresholds are ratchets at the measured values, so this fails in EITHER direction: a
# regression in argv seeding or frame-slot tracking drops recall, and a detector that fires
# more broadly raises fp_rate.
#
# Recall WAS capped at 0.83 (5/6) by the CWE-798 hard-coded-secret case: hardcoded_secrets is
# a string detector with no call site, so neither the reachability nor the data-flow channel
# could corroborate it, and the threshold sat at 0.80 to leave room for that. String-xref
# corroboration removed the cap -- a secret the code demonstrably READS is corroborated by the
# xref itself -- and the measured rate has been 1.00 on every run since (eval-history.jsonl:
# 0.833, 0.833, then 1.00, 1.00, 1.00).
#
# So the threshold moves to the measured value, because that is what a ratchet is. Left at
# 0.80 it carried 0.20 of slack: a regression losing a case outright would have dropped recall
# to 0.83 and passed silently, which is precisely the decorative-gate failure described above
# for the FP budget. At 1.0 any lost case fails the gate, which is the point -- if a case
# legitimately stops being corroborable, that is a deliberate decision to record here with the
# reason, not something to absorb into unused headroom.
CORROB_MIN_RECALL ?= 1.0
CORROB_FP_BUDGET  ?= 0.25

eval-gate:
	@echo "== release gate: confirmed-stage recall (dynamic; gcc only) =="
	$(PY) -m lykos eval --stage dynamic --record
	@echo "== release gate: candidate-stage detection + FP ratchet (static; needs Ghidra) =="
	$(PY) -m lykos eval --stage static --min-state candidate --record \
	      --min-recall 1.0 --max-fp-rate $(STATIC_FP_BUDGET)
	@echo "== release gate: corroborated-stage discrimination (static; needs Ghidra) =="
	$(PY) -m lykos eval --stage static --min-state corroborated --record \
	      --min-recall $(CORROB_MIN_RECALL) --max-fp-rate $(CORROB_FP_BUDGET)

# Architecture coverage gate: every supported ISA still reaches its expected PoC level.
# Builds a vulnerable program per architecture with the cross toolchain, detonates it through
# the real sandbox and drives the real PoC stages. Skips (does not fail) an architecture whose
# cross-compiler is absent. Does NOT need Ghidra -- decompilation is the slow part and nearly
# every arch regression lives in the dynamic path, which keeps this cheap enough to gate on.
arch-gate:
	$(PY) -m lykos archgate

# The full chain on a program that behaves like real software: detect -> PoC ladder ->
# crash attribution, with NO stage told how to feed the target and the produced bundle
# actually run. The other gates each cover a slice and leave the join uncovered.
real-gate:
	$(PY) -m lykos realgate

# Render the detection-quality regression dashboard from the recorded history.
dashboard:
	$(PY) -m lykos dashboard --html eval-dashboard.html

# Full release bar: code checks + packaged-artifact verify + detection-quality gate.
release: ci verify eval-gate arch-gate real-gate
	@echo "release gate complete"

clean:
	rm -rf dist .cases
	find core -type d -name __pycache__ -exec rm -rf {} +
