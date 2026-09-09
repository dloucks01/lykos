#!/usr/bin/env bash
# P0.10 — build a self-contained, offline, single-file zipapp (.pyz).
# The runtime is stdlib-only, so no dependencies are fetched: this builds with no network.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"; mkdir -p "$DIST"
STAGE="$(mktemp -d)"
cp -r "$ROOT/core/lykos" "$STAGE/lykos"
find "$STAGE" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
python3 -m zipapp "$STAGE" -m "lykos.cli:main" -p "/usr/bin/env python3" \
        -o "$DIST/lykos.pyz"
rm -rf "$STAGE"
echo "built $DIST/lykos.pyz ($(du -h "$DIST/lykos.pyz" | cut -f1)) — run: python3 dist/lykos.pyz --help"
