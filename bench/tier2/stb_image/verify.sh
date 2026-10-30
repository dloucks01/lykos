#!/usr/bin/env bash
# Self-verify the committed real-bug PoCs: each crashes the vulnerable stb_image and is SURVIVED
# by the fixed one (the differential that makes it a real bug, not an incidental defect).
set -euo pipefail
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; T="$(mktemp -d)"
ln -sf "$D/vuln.h"  "$T/target.h"; gcc -O0 -g -w -fsanitize=address,undefined -I"$T" -o "$T/vuln"  "$D/harness.c" -lm
ln -sf "$D/fixed.h" "$T/target.h"; gcc -O0 -g -w -fsanitize=address,undefined -I"$T" -o "$T/fixed" "$D/harness.c" -lm
ok=0; tot=0
for p in "$D"/crashes/*.bin; do
  tot=$((tot+1))
  v=0; ASAN_OPTIONS=detect_leaks=0 "$T/vuln"  "$p" >/dev/null 2>&1 || v=1
  f=0; ASAN_OPTIONS=detect_leaks=0 "$T/fixed" "$p" >/dev/null 2>&1 || f=1
  if [ "$v" = 1 ] && [ "$f" = 0 ]; then echo "PASS $(basename "$p") (vuln crashes, fixed survives)"; ok=$((ok+1));
  else echo "FAIL $(basename "$p") (vuln_crash=$v fixed_crash=$f)"; fi
done
rm -rf "$T"; echo "$ok/$tot PoCs verified as real (vuln-only) bugs"; [ "$ok" = "$tot" ]
