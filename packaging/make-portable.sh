#!/usr/bin/env bash
# Build the PORTABLE lykos package: the container's fully self-contained rootfs (its OWN glibc + every
# tool) plus a chroot/unshare launcher -- so it runs on ANY Linux, at ANY glibc, with NO podman and
# NO docker. It only needs util-linux (chroot / unshare), which is on every Kali. This is the package
# for an air-gapped laptop whose glibc is old and whose container runtime is unknown: the folder is
# glibc-coupled (needs laptop glibc >= build host) and the container needs podman -- this needs
# neither. Validated running the full server + doctor on glibc 2.27.
#
#   packaging/make-portable.sh          # build image if needed, emit dist/lykos-portable-*.tar.zst
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"; mkdir -p "$DIST"
IMG="localhost/lykos:latest"
RT="${RT:-$(command -v podman || command -v docker)}"
say(){ printf '\n== %s\n' "$*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }
[ -n "$RT" ] || die "need podman or docker to export the appliance rootfs (build host only)"
command -v zstd >/dev/null 2>&1 || die "need zstd"

"$RT" image exists "$IMG" 2>/dev/null || die "image $IMG not found -- run packaging/build-container.sh first"

STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
APP="$STAGE/lykos-portable"; mkdir -p "$APP/rootfs" "$APP/cases"

say "exporting the appliance rootfs (its own glibc + every tool)"
cid="$("$RT" create "$IMG")"; "$RT" export "$cid" | tar -x -C "$APP/rootfs"; "$RT" rm "$cid" >/dev/null
# the mount points the launcher binds into
mkdir -p "$APP/rootfs/cases" "$APP/rootfs/proc" "$APP/rootfs/dev" "$APP/rootfs/sys"

say "writing the chroot/unshare launcher"
cat > "$APP/RUN.sh" <<'EOF'
#!/bin/sh
# Portable lykos -- no podman/docker, any glibc. The rootfs/ tree carries its OWN glibc and every
# tool, so the laptop's age does not matter; we just enter it with chroot (root) or an unprivileged
# user namespace (unshare). Only util-linux is required, and it is always present.
set -e
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT="$here/rootfs"
[ -d "$ROOT/opt/lykos" ] || { echo "rootfs/ is missing or incomplete -- did the archive fully extract?"; exit 1; }
CASES="$here/cases"; mkdir -p "$CASES" "$ROOT/cases" "$ROOT/proc" "$ROOT/dev" "$ROOT/sys"
HTTP="${LYKOS_HTTP:-127.0.0.1:8787}"
CMD='PYTHONPATH=/opt/lykos/core LYKOS_VENDOR=/opt/lykos/vendor PATH=/usr/local/bin:/usr/bin:/bin PYTHONUNBUFFERED=1 python3 -m lykos '"${LYKOS_CMD:-serve --http $HTTP --case-store /cases --workers 2}"

# __inner: we have just re-entered inside the user namespace (or we were root) and can now mount +
# chroot. Kept as a self-re-invocation so the namespace setup stays a single clean exec, no heredoc.
if [ "${1:-}" = __inner ]; then
  mount --bind "$CASES" "$ROOT/cases" 2>/dev/null || true
  mount -t proc proc "$ROOT/proc" 2>/dev/null || mount --bind /proc "$ROOT/proc" 2>/dev/null || true
  mount --bind /dev "$ROOT/dev" 2>/dev/null || true
  exec chroot "$ROOT" /usr/bin/env sh -c "$CMD" </dev/null
fi
export ROOT CASES CMD HTTP
if [ "$(id -u)" = 0 ]; then
  exec "$0" __inner                                    # already root: mount + chroot directly
elif unshare --user --map-root-user true 2>/dev/null; then
  exec unshare --user --map-root-user --mount --pid --fork "$0" __inner   # unprivileged userns
else
  echo "This laptop has unprivileged user namespaces disabled and you are not root."
  echo "Run with sudo:   sudo ./RUN.sh        (or enable: sysctl -w kernel.unprivileged_userns_clone=1)"
  exit 1
fi
EOF
# doctor variant: same entry, but run `doctor` instead of the server
cat > "$APP/DOCTOR.sh" <<'EOF'
#!/bin/sh
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LYKOS_CMD="doctor $*" exec "$here/RUN.sh"
EOF
chmod +x "$APP/RUN.sh" "$APP/DOCTOR.sh"

cat > "$APP/READ-ME-FIRST.txt" <<'EOF'
lykos -- PORTABLE build. No install, no podman/docker, works on any Linux at any glibc.

  1. Extract this archive anywhere on the laptop (you already have).
  2. Check it:   ./DOCTOR.sh
  3. Run it:     ./RUN.sh          (or: sudo ./RUN.sh  if user namespaces are disabled)
  4. Open:       http://127.0.0.1:8787

Everything runs from ./rootfs (its own glibc + every tool). Results are written to ./cases on the
laptop. Nothing else on the machine is touched. To move the port: LYKOS_HTTP=127.0.0.1:9000 ./RUN.sh
EOF

STAMP="$(date +%Y%m%d)"; ARCH="$(uname -m)"
OUT="$DIST/lykos-portable-$STAMP-$ARCH.tar.zst"
say "packaging -> $OUT"
tar -C "$STAGE" -c lykos-portable | zstd -f -T0 -19 -o "$OUT"
( cd "$DIST" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )
say "done"
printf '  %s (%s)\n' "$OUT" "$(du -h "$OUT" | cut -f1)"
cat <<EOF

On the air-gapped laptop (no podman needed):
  sha256sum -c $(basename "$OUT").sha256
  tar --zstd -xf $(basename "$OUT")
  cd lykos-portable && ./RUN.sh
  # open http://127.0.0.1:8787
EOF
