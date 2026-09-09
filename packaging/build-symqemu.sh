#!/usr/bin/env bash
# Build the SymQEMU concolic engine in an Ubuntu 22.04 container (the authors' known-good
# toolchain: LLVM 14 + Z3), then vendor the emulator and its SymCC runtime into
# vendor/symqemu/ where Lykos's locator finds it. Requires docker with host networking.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMG="lykos-symqemu:22.04"
DEST="$ROOT/vendor/symqemu"
echo "[*] building $IMG (this compiles Z3 + SymCC + QEMU; takes a while)…"
docker build --network=host -t "$IMG" -f "$ROOT/packaging/symqemu.Dockerfile" "$ROOT/packaging"
mkdir -p "$DEST"
CID="$(docker create "$IMG")"
trap 'docker rm "$CID" >/dev/null 2>&1 || true' EXIT
echo "[*] extracting emulator + SymCC runtime → $DEST"
docker cp "$CID:/symqemu/build/qemu-x86_64" "$DEST/symqemu-x86_64"
docker cp "$CID:/symqemu/build/subprojects/symcc-rt/libSymCCRtShared.so" "$DEST/libSymCCRtShared.so"
chmod +x "$DEST/symqemu-x86_64"
echo "[*] done. verify:"
echo "    LD_LIBRARY_PATH=$DEST $DEST/symqemu-x86_64 --version"
