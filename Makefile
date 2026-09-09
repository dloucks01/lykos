# Lykos — offline dev + CI targets (P0.11). Runtime is stdlib-only.
PY ?= python3
export PYTHONPATH := core

.PHONY: test lint typecheck ci bundle verify run clean help

help:
	@echo "targets: test lint typecheck ci bundle verify run clean"

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

clean:
	rm -rf dist .cases core/lykos/**/__pycache__ core/lykos/__pycache__
