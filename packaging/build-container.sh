#!/usr/bin/env bash
# Build the self-contained lykos container image and save it as an air-gap transfer tarball.
# Run this on a CONNECTED machine with podman (or docker) + network. The result is ONE file you
# carry to the air-gapped laptop; nothing about the laptop's distro/glibc/Python matters there.
#
#   packaging/build-container.sh            # build + save dist/lykos-container-*.tar.zst
#   packaging/build-container.sh --no-save  # just build the image locally
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"; mkdir -p "$DIST"
IMG="lykos:latest"
say(){ printf '\n== %s\n' "$*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }

RT="$(command -v podman || command -v docker || true)"
[ -n "$RT" ] || die "need podman or docker on this build host"
command -v zstd >/dev/null 2>&1 || die "need zstd (apt-get install zstd)"

say "building $IMG with $RT (this pulls the base + installs the toolchain; give it time)"
"$RT" build -t "$IMG" -f "$ROOT/packaging/Containerfile" "$ROOT"

if [ "${1:-}" = "--no-save" ]; then
  say "done (image built, not saved)"; "$RT" images "$IMG"; exit 0
fi

STAMP="$(date +%Y%m%d)"; ARCH="$(uname -m)"
OUT="$DIST/lykos-container-$STAMP-$ARCH.tar.zst"
say "saving image -> $OUT (zstd)"
# save the OCI image and compress in one stream; -T0 = all cores, -19 = strong ratio
"$RT" save "$IMG" | zstd -T0 -19 -o "$OUT"
( cd "$DIST" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )

say "done"
printf '  %s (%s)\n' "$OUT" "$(du -h "$OUT" | cut -f1)"
cat "$OUT.sha256" | sed 's/^/  /'
cat <<EOF

On the air-gapped laptop (podman shown; docker is identical):
  sha256sum -c $(basename "$OUT").sha256
  zstd -dc $(basename "$OUT") | podman load
  mkdir -p cases
  podman run --rm -p 127.0.0.1:8787:8787 -v "\$PWD/cases:/cases" lykos:latest
  # then open http://127.0.0.1:8787
Nothing is installed on the laptop; the image is self-contained. See docs/23-airgap-install.md.
EOF
