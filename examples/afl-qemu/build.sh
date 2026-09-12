#!/usr/bin/env bash
# Build an afl-qemu-trace for ONE guest architecture, and install it where lykos looks.
#
# afl-qemu-trace is an emulator: it is always built for the host, and the guest it can run is
# fixed at build time by CPU_TARGET. Covering ARM and AArch64 and x86-64 therefore means three
# binaries, and AFL++ installs them all under the same name -- so lykos looks for arch-suffixed
# neighbours (afl-qemu-trace-arm) or an explicit LYKOS_AFL_QEMU_<ARCH>, and verifies the guest
# from qemu's own version banner before using one.
#
# Why bother: measured on jhead, 32-bit ARM
#     black-box qemu path   ~39-55 exec/s
#     AFL++ fork server   ~1,965 exec/s      (and it found the crash in 60s)
#
#   usage:  ./build.sh arm [/usr/local/bin]
#           ./build.sh x86_64
#           ./build.sh aarch64
set -euo pipefail
CPU="${1:?usage: build.sh <cpu-target> [install-dir]}"
DEST="${2:-/usr/local/bin}"
SRC="${AFL_SRC:-/tmp/aflsrc}"
VER="${AFL_VERSION:-v4.33c}"          # match the installed afl-fuzz (afl-fuzz --version)

# prerequisites beyond a normal build host: qemu needs these and they are easy to miss
for t in ninja meson bison flex; do
  command -v "$t" >/dev/null || { echo "missing build tool: $t" >&2; exit 1; }
done

[ -d "$SRC" ] || git clone --depth 1 --branch "$VER" \
  https://github.com/AFLplusplus/AFLplusplus "$SRC"
cd "$SRC"
[ -x ./afl-showmap ] || make -j"$(nproc)"     # qemu_mode's sanity check needs this

# qemuafl is based on qemu 5.x and its coverage macro does not compile for a 32-bit guest on a
# modern toolchain: it feeds a target_ulong straight into an x86 addressing mode, so a 32-bit
# guest yields `(%rdx,%edi,1)` -- base and index must be the same width. 64-bit guests are
# unaffected, which is why aarch64 builds and arm does not. Widen the index to pointer size.
COMMON="$SRC/qemu_mode/qemuafl/qemuafl/common.h"
if [ -f "$COMMON" ] && grep -q '"r"(afl_area_ptr), "r"(loc)' "$COMMON"; then
  sed -i 's/"r"(afl_area_ptr), "r"(loc)/"r"(afl_area_ptr), "r"((uintptr_t)(loc))/' "$COMMON"
  echo "[*] patched INC_AFL_AREA for 32-bit guests"
fi

cd "$SRC/qemu_mode"
PYTHON=/usr/bin/python3 CPU_TARGET="$CPU" ./build_qemu_support.sh

BUILT="$SRC/qemu_mode/qemuafl/build/qemu-$CPU"
[ -x "$BUILT" ] || { echo "build produced no qemu-$CPU" >&2; exit 1; }

# lykos spells a few architectures differently from qemu; install under ITS name so the
# arch-suffixed lookup finds it (x86_64 -> x86-64, i386 -> x86).
case "$CPU" in
  x86_64) NAME=x86-64 ;;
  i386)   NAME=x86 ;;
  *)      NAME="$CPU" ;;
esac
install -m 0755 "$BUILT" "$DEST/afl-qemu-trace-$NAME"
echo "[+] installed $DEST/afl-qemu-trace-$NAME"
"$DEST/afl-qemu-trace-$NAME" --version | head -1
