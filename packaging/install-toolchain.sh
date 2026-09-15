#!/usr/bin/env bash
# Install the air-gap toolchain bundle. Run this ON the air-gapped workstation, from the
# directory the bundle was extracted into. Needs no network.
#
# Verifies first, installs second, and finishes by running `lykos doctor` so the outcome is a
# capability report rather than a claim that it worked.
#
# INTEGRITY SCOPE: SHA256SUMS is an UNSIGNED manifest, so verification proves the bundle is
# not CORRUPTED (bit-rot, a truncated transfer) and that no file it lists was altered or added.
# It does NOT prove authenticity: an attacker who can rewrite the whole bundle can rewrite
# SHA256SUMS to match. Treat the checksum as corruption-resistance, and carry the bundle over a
# trusted channel. (Future step: sign SHA256SUMS and verify the signature here.)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LYKOS_ROOT="${LYKOS_ROOT:-}"

say(){ printf '\n== %s\n' "$*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }

say "verifying the bundle"
[ -f "$HERE/SHA256SUMS" ] || die "no SHA256SUMS -- this is not a lykos toolchain bundle"
( cd "$HERE" && sha256sum --quiet -c SHA256SUMS ) \
  || die "checksum mismatch: the bundle is corrupt (a listed file was altered or truncated)"
# `sha256sum -c` only checks the files it LISTS; a file added to the bundle passes silently and
# would then be swept up by the debs/*.deb glob below. Require the set of files actually present
# to equal the set the manifest names, so an unlisted deb cannot ride along.
extra="$(cd "$HERE" && comm -13 \
  <(sed 's/^[0-9a-f]\{64\} [ *]//' SHA256SUMS | sort) \
  <(find . -type f ! -name SHA256SUMS | sort))"
[ -z "$extra" ] || die "bundle contains files not named in SHA256SUMS -- refusing (corruption \
or tampering):
$(printf '%s\n' "$extra" | sed 's/^/    /')"
echo "  ok -- $(grep -c . "$HERE/SHA256SUMS") files, no extras"
[ -f "$HERE/manifest/BUNDLE.txt" ] && sed 's/^/  /' "$HERE/manifest/BUNDLE.txt"

if [ "${1:-}" = "--verify-only" ]; then
  echo; echo "verify-only: nothing installed."; exit 0
fi

say "installing packages"
if [ -n "$(find "$HERE/debs" -name '*.deb' 2>/dev/null | head -1)" ]; then
  # dpkg over the whole set at once so inter-dependencies resolve in any order; apt-get -f
  # afterwards settles anything dpkg alone could not. The glob is safe: the set-equality check
  # above guarantees every debs/*.deb is a manifest-listed, checksum-verified file.
  sudo dpkg -i "$HERE"/debs/*.deb 2>&1 | grep -vE '^\(Reading|^Preparing|^Unpacking' || true
  sudo apt-get -f install -y --no-download --fix-missing 2>/dev/null || true
else
  echo "  no debs in this bundle -- skipping"
fi

say "installing python engine venvs"
DEST="${LYKOS_ROOT:+$LYKOS_ROOT/vendor}"
if [ -z "$DEST" ]; then
  # default beside the repo if we can find it, else /opt
  if [ -d "$HERE/../core/lykos" ]; then DEST="$(cd "$HERE/.." && pwd)/vendor"
  else DEST="/opt/lykos/vendor"; fi
fi
mkdir -p "$DEST"
for v in "$HERE"/venvs/*-venv; do
  [ -d "$v" ] || continue
  name="$(basename "$v")"
  rm -rf "${DEST:?}/$name"
  cp -a "$v" "$DEST/$name"
  # a venv records the interpreter it was built against; repoint it at this host's python3
  if [ -f "$DEST/$name/pyvenv.cfg" ]; then
    sed -i "s|^home = .*|home = $(dirname "$(command -v python3)")|" "$DEST/$name/pyvenv.cfg"
  fi
  if "$DEST/$name/bin/python" -c "import sys" 2>/dev/null; then
    echo "  $name -> $DEST/$name"
  else
    echo "  WARNING: $name does not run here (built for a different Python); that engine"
    echo "           will be unavailable. Rebuild it on a matching host."
  fi
done
echo "  set LYKOS_ANGR_PYTHON / LYKOS_UNICORN_PYTHON to override these paths"

say "installing bundled engines (extras)"
# The collector (_bundle_extras.py) stages the non-apt engines under extras/ -- Ghidra above
# all, which is a REQUIRED engine and only an apt package on Kali. Without this step a native
# bundle would arrive with Ghidra and drop it silently, exactly the failure the bundling
# machinery exists to prevent. Destinations match the locators: locate_ghidra() finds
# <vendor>/ghidra/support/analyzeHeadless, locate_symqemu() finds <vendor>/symqemu/symqemu-<arch>.
if [ -d "$HERE/extras" ] && [ -n "$(ls -A "$HERE/extras" 2>/dev/null)" ]; then
  for g in "$HERE"/extras/ghidra/*/; do
    [ -d "$g" ] || continue
    rm -rf "${DEST:?}/ghidra"
    cp -a "$g" "$DEST/ghidra"
    echo "  ghidra -> $DEST/ghidra"
    [ -d "$DEST/ghidra/support" ] || echo "  WARNING: $DEST/ghidra has no support/ dir -- locator may not find it"
  done
  if [ -d "$HERE/extras/symqemu" ] && [ -n "$(ls -A "$HERE/extras/symqemu" 2>/dev/null)" ]; then
    mkdir -p "$DEST/symqemu"
    cp -a "$HERE"/extras/symqemu/* "$DEST/symqemu/"
    echo "  symqemu -> $DEST/symqemu"
  fi
  # Any future engine staged under extras/<key> lands at <vendor>/<key> verbatim.
  for d in "$HERE"/extras/*/; do
    [ -d "$d" ] || continue
    key="$(basename "$d")"
    case "$key" in ghidra|symqemu) continue ;; esac
    rm -rf "$DEST/$key"; cp -a "$d" "$DEST/$key"; echo "  $key -> $DEST/$key"
  done
  # $DEST is the repo's vendor/ only when installed from a checkout (the documented
  # LYKOS_ROOT=$PWD flow). Installed detached under /opt, the Ghidra locator searches
  # /opt/ghidra* rather than /opt/lykos/vendor -- point it with LYKOS_GHIDRA if so.
  case "$DEST" in /opt/*) echo "  note: run lykos from a checkout, or set LYKOS_GHIDRA=$DEST/ghidra" ;; esac
else
  echo "  none in this bundle"
  # Ghidra is REQUIRED. If it is neither bundled nor an installed deb, do not stay silent.
  if [ -z "$(find "$HERE/debs" -iname 'ghidra*.deb' 2>/dev/null | head -1)" ]; then
    echo "  WARNING: Ghidra (a REQUIRED engine) is neither in extras/ nor among the debs."
    echo "           Disassembly and detection will be unavailable until it is installed:"
    echo "           unpack a Ghidra release into /opt and set LYKOS_GHIDRA, or rebuild the"
    echo "           bundle on an image/host that provides it."
  fi
fi

say "installing per-guest afl-qemu-trace"
if [ -n "$(ls -A "$HERE/afl-qemu" 2>/dev/null)" ]; then
  for f in "$HERE"/afl-qemu/*; do
    sudo install -m 0755 "$f" /usr/local/bin/ && echo "  $(basename "$f")"
  done
else
  echo "  none in this bundle"
fi

say "capability report"
if [ -n "$LYKOS_ROOT" ] && [ -d "$LYKOS_ROOT/core" ]; then
  PYTHONPATH="$LYKOS_ROOT/core" python3 -m lykos doctor || true
elif [ -d "$HERE/../core/lykos" ]; then
  PYTHONPATH="$(cd "$HERE/.." && pwd)/core" python3 -m lykos doctor || true
else
  echo "  run this from your lykos checkout to see it:"
  echo "    PYTHONPATH=core python3 -m lykos doctor"
fi

cat <<'EOF'

Done. Anything still marked MISS names its own install line.

Next:
  cd <your lykos checkout>
  make test        # the suite; stages whose tool is absent skip, and say so
  make run         # serve the UI on 127.0.0.1:8787
EOF
