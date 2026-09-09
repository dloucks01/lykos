#!/usr/bin/env bash
# Phase 0 exit demo — clean-VM, network-off runner.
# Boots a throwaway service on a temp case-store and runs the acceptance harness.
# Usage: tests/phase0_exit_demo.sh [SAMPLE_BINARY]
set -euo pipefail

SAMPLE="${1:-tests/corpus/httpd-aarch64}"   # stripped AArch64 ELF from the golden corpus (IT-21)

echo "== Phase 0 exit demo =="

# Soft air-gap check: warn (do not fail) if an interface looks network-connected.
if command -v ip >/dev/null 2>&1; then
  if ip route get 1.1.1.1 >/dev/null 2>&1; then
    echo "WARNING: a default route exists — the true air-gap test runs with networking OFF." >&2
  else
    echo "[ok] no default route (air-gapped)."
  fi
fi

[ -f "$SAMPLE" ] || { echo "FATAL: sample '$SAMPLE' missing — build the golden corpus (ticket IT-21)."; exit 2; }

# The harness boots the service itself (--start) on a temp case-store, runs all checks, tears down.
python tests/phase0_exit_demo.py --start --sample "$SAMPLE"
