# Lykos — offline dev + CI targets (P0.11). Runtime is stdlib-only.
PY ?= python3
export PYTHONPATH := core

.PHONY: test lint typecheck ci bundle verify run eval eval-gate dashboard release clean help

help:
	@echo "targets: test lint typecheck ci bundle verify run eval eval-gate dashboard release clean"

test:
	$(PY) -m pytest tests/ -q

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

ci: lint typecheck test
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
# Recall is capped at 0.83 (5/6) by the CWE-798 hard-coded-secret case, and that is
# structural rather than a gap: hardcoded_secrets is a string detector with no call site, so
# neither the reachability nor the data-flow channel can corroborate it. Secrets are promoted
# by the `synthesize_secret` stage instead (straight to poc-backed), which this static-only
# benchmark does not run. Raise this only if that changes.
CORROB_MIN_RECALL ?= 0.80
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

# Render the detection-quality regression dashboard from the recorded history.
dashboard:
	$(PY) -m lykos dashboard --html eval-dashboard.html

# Full release bar: code checks + packaged-artifact verify + detection-quality gate.
release: ci verify eval-gate
	@echo "release gate complete"

clean:
	rm -rf dist .cases core/lykos/**/__pycache__ core/lykos/__pycache__
