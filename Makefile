# Lykos — offline dev + CI targets (P0.11). Runtime is stdlib-only.
PY ?= python3
export PYTHONPATH := core

.PHONY: test lint typecheck ci bundle verify run eval eval-gate release clean help

help:
	@echo "targets: test lint typecheck ci bundle verify run eval eval-gate release clean"

test:
	$(PY) -m pytest tests/ -q

lint:
	@if command -v ruff >/dev/null 2>&1; then ruff check core tests; else echo "ruff not installed; skipping lint"; fi

typecheck:
	@if command -v mypy >/dev/null 2>&1; then mypy --ignore-missing-imports core/lykos; else echo "mypy not installed; skipping typecheck"; fi

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
# The dynamic (confirmed-stage) gate needs only gcc; the static (candidate-stage)
# gate needs Ghidra and SKIPs cleanly when it is absent (see `lykos eval` gate logic).
eval-gate:
	@echo "== release gate: confirmed-stage recall (dynamic; gcc only) =="
	$(PY) -m lykos eval --stage dynamic
	@echo "== release gate: candidate-stage detection (static; Ghidra, skipped if absent) =="
	$(PY) -m lykos eval --stage static

# Full release bar: code checks + packaged-artifact verify + detection-quality gate.
release: ci verify eval-gate
	@echo "release gate complete"

clean:
	rm -rf dist .cases core/lykos/**/__pycache__ core/lykos/__pycache__
