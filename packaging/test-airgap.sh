#!/usr/bin/env bash
# Faithfully test an air-gap PACKAGE the way the laptop will see it -- offline, non-root, with NO
# build tools and NONE of the analysis tools installed system-wide -- so the "works on my build
# machine, breaks on the laptop" class of bug (a Python lib the bundle forgot to vendor, a tool that
# silently resolved to a host binary, an env var the launcher didn't set) is caught HERE, not after
# the DVD is carried in. This is the test the build-host import smoke-check cannot be: the build host
# has every system library, so it always passes while the bundle may be incomplete.
#
#   packaging/test-airgap.sh folder [dist/lykos-airgapped-*.zip]   # test the unzip-and-run folder
#   packaging/test-airgap.sh container [dist/lykos-container-*.tar.zst]  # test the container image
#
# Env: BASE=<image> overrides the simulated-laptop base (default: a recent glibc so the folder's
# vendored binaries load; the folder is glibc-coupled -- see docs/23). RT=podman|docker.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KIND="${1:-folder}"
ART="${2:-}"
RT="${RT:-$(command -v podman || command -v docker)}"
BASE="${BASE:-docker.io/kalilinux/kali-rolling:latest}"   # glibc >= build host; no analysis tools
say(){ printf '\n== %s\n' "$*"; }
die(){ echo "FAIL: $*" >&2; exit 1; }
[ -n "$RT" ] || die "need podman or docker"

# The REQUIRED tools doctor must find running purely from the package on a bare laptop.
REQ='Python 3|rizin|pypcode|qemu-user|GDB|C compiler|AFL\+\+|afl-qemu-trace'

if [ "$KIND" = folder ]; then
  ART="${ART:-$(ls -1t "$ROOT"/dist/lykos-airgapped-*.zip 2>/dev/null | head -1)}"
  [ -n "$ART" ] && [ -f "$ART" ] || die "no folder zip (build with ./package)"
  say "cold-laptop test of $(basename "$ART")  base=$BASE  (offline, non-root, no tools)"
  # Extract HERE (the build host has unzip) and mount the tree read-only -- the minimal laptop base
  # deliberately has no tools, unzip included, so extracting inside it would give a false NO_UNZIP.
  command -v unzip >/dev/null 2>&1 || die "need unzip on the build host to test the folder package"
  EXD="$(mktemp -d)"; trap 'rm -rf "$EXD"' EXIT
  unzip -oq "$ART" -d "$EXD" || die "could not extract $ART"
  ROOTDIR="$(dirname "$(find "$EXD" -maxdepth 2 -name DOCTOR.sh | head -1)")"
  [ -n "$ROOTDIR" ] && [ -d "$ROOTDIR" ] || { echo "NO_DOCTOR (package has no DOCTOR.sh)"; exit 1; }
  # --network none: air-gapped. --user 1000: not root. The package tree is the ONLY thing present.
  out="$("$RT" run --rm --network none --user 1000:1000 \
        -v "$ROOTDIR":/lykos:ro -e HOME=/tmp \
        "$BASE" sh -c 'cd /tmp && sh /lykos/DOCTOR.sh 2>&1' 2>&1 || true)"
else
  die "usage: test-airgap.sh folder [artifact]"
fi

echo "$out" | grep -iE '\[ok|\[MISS|present|REQUIRED missing|cannot open|not found|NO_DOCTOR|NO_UNZIP' || true
# Guard against a false pass: if doctor never ran (no DOCTOR.sh, no unzip, or no [ok]/[MISS] lines at
# all) there is nothing to judge, so the package is NOT proven -- fail.
if echo "$out" | grep -qiE 'NO_DOCTOR|NO_UNZIP' || ! echo "$out" | grep -qiE '\[ok|\[MISS'; then
  say "AIR-GAP TEST FAILED -- doctor did not run inside the package (no DOCTOR.sh / unzip / output):"
  echo "$out" | tail -5
  exit 1
fi
# Verdict: every REQUIRED tool must read [ok]. A required MISS, or a loader error, fails the build.
missing="$(echo "$out" | grep -iE "\[MISS\].*(${REQ})" || true)"
loaderr="$(echo "$out" | grep -iE 'error while loading shared libraries|cannot open shared object' || true)"
if [ -n "$missing" ] || [ -n "$loaderr" ]; then
  say "AIR-GAP TEST FAILED -- the package is not self-contained on a bare laptop:"
  [ -n "$missing" ] && echo "$missing"
  [ -n "$loaderr" ] && echo "$loaderr"
  echo "(folder: usually a shared library the bundle did not vendor -- the closure pass in"
  echo " make-runnable.sh should copy it; container: rebuild. See docs/23-airgap-install.md.)"
  exit 1
fi
say "AIR-GAP TEST PASSED -- every required tool resolves from the package alone."
