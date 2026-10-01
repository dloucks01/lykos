#!/usr/bin/env bash
# P0.10 — offline smoke: run the packaged .pyz end-to-end with no dependencies.
# The app makes no network calls; for a strict offline check run this under: unshare -rn packaging/verify.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYZ="$ROOT/dist/lykos.pyz"
[ -f "$PYZ" ] || bash "$ROOT/packaging/build.sh"
T="$(mktemp -d)"; SOCK="$T/s.sock"
SAMPLE="${1:-/bin/ls}"

# `${SRV:-0}` would expand to `0` before SRV is assigned (an early `db init` failure), and
# `kill 0` signals the whole process group -- including make and the parent shell. Only kill a
# server we actually started.
fail(){ echo "VERIFY FAIL: $1"; [ -f "$T/log" ] && cat "$T/log"; [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null; rm -rf "$T"; exit 1; }

python3 "$PYZ" db init --case-store "$T/cs" >/dev/null || fail "db init"
python3 "$PYZ" serve --socket "$SOCK" --case-store "$T/cs" --workers 2 >"$T/log" 2>&1 &
SRV=$!
for i in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.05; done
[ -S "$SOCK" ] || fail "socket never appeared"

curl -sf --unix-socket "$SOCK" http://localhost/health >/dev/null || fail "health"
# capture-then-grep (not `curl | grep -q`): grep -q exits on first match and SIGPIPEs curl
# mid-body, which under `set -o pipefail` would fail the pipeline on a large page.
UI="$(curl -s --unix-socket "$SOCK" http://localhost/)"
case "$UI" in *"<title>Lykos"*) ;; *) fail "UI not served from pyz";; esac
CID=$(curl -s --unix-socket "$SOCK" -H 'Content-Type: application/json' -d '{"name":"verify"}' \
      http://localhost/cases | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
RUN=$(curl -s --unix-socket "$SOCK" -F "file=@$SAMPLE" http://localhost/cases/$CID/targets \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["run_id"])')
ST=""
for i in $(seq 1 100); do
  ST=$(curl -s --unix-socket "$SOCK" http://localhost/runs/$RUN \
       | python3 -c 'import sys,json;print(json.load(sys.stdin)["status"])')
  [ "$ST" = done ] && break; sleep 0.1
done
kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null || true
[ "$ST" = done ] || fail "run status=$ST"
echo "VERIFY OK: packaged .pyz served the UI and triaged $SAMPLE offline (run done)"
rm -rf "$T"
