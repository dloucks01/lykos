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
for t in ninja meson bison flex pkg-config; do
  command -v "$t" >/dev/null || { echo "missing build tool: $t" >&2; exit 1; }
done
# qemu's configure also needs the glib + pixman dev headers (found via pkg-config); without them
# build_qemu_support.sh fails deep in configure with a bare "pkg-config not found"-style error.
for pc in glib-2.0 pixman-1; do
  pkg-config --exists "$pc" 2>/dev/null || {
    echo "missing dev headers: $pc (apt-get install libglib2.0-dev libpixman-1-dev)" >&2; exit 1; }
done

[ -d "$SRC" ] || git clone --depth 1 --branch "$VER" \
  https://github.com/AFLplusplus/AFLplusplus "$SRC"
cd "$SRC"
[ -x ./afl-showmap ] || make -j"$(nproc)"     # qemu_mode's sanity check needs this

cd "$SRC/qemu_mode"

# qemuafl (the pinned QEMU fork) must be CHECKED OUT before its coverage macro can be patched.
# build_qemu_support.sh clones it only on its first run, so the previous ordering -- patch, THEN run
# the script -- edited a path that did not exist yet and silently no-op'd. That is the real reason
# 32-bit guests never built: the fix below was correct but never applied. Do the same checkout the
# script does, patch, then build with NO_CHECKOUT so the build keeps the patched tree.
if [ ! -f qemuafl/qemuafl/common.h ]; then
  ( git submodule init && git submodule update ./qemuafl ) >/dev/null 2>&1 \
    || git clone --depth 1 https://github.com/AFLplusplus/qemuafl
fi
QV="$(cat ./QEMUAFL_VERSION 2>/dev/null || true)"
if [ -n "$QV" ] && [ -d qemuafl/.git ]; then
  ( cd qemuafl && { git fetch --depth 1 origin "$QV" >/dev/null 2>&1 || true; \
                    git checkout "$QV" >/dev/null 2>&1 || true; } )
fi

# qemuafl is based on qemu 5.x. Its per-edge coverage macro INC_AFL_AREA has an x86-HOST inline-asm
# fast path (`addb $1,(%0,%1,1)`) selected purely by the *host* arch, so it is compiled for every
# guest -- and expanded in accel/tcg/translate-all.c. Its index operand is the guest `loc` (a
# target_ulong): for a 32-bit guest that is a 32-bit register, so the assembler sees `(%rdx,%edi,1)`
# -- base 64-bit, index 32-bit, illegal -- and arm/i386 fail to assemble. 64-bit guests (aarch64,
# x86_64) are unaffected, which is why they build and arm does not. Gate the asm fast path on a
# 64-bit guest (TARGET_LONG_BITS) so a 32-bit guest uses the portable `afl_area_ptr[loc]++` branch;
# also widen the operand wherever the asm survives. Idempotent; format-tolerant across AFL++ releases.
COMMON="$SRC/qemu_mode/qemuafl/qemuafl/common.h"
if [ -f "$COMMON" ] && ! grep -q 'lykos:' "$COMMON"; then
  # NOTE: sed delimiter is @ -- the pattern contains `||` and the replacement contains `/`, so the
  # usual | or / delimiters would both break the expression.
  sed -i 's@#if (defined(__x86_64__) || defined(__i386__))@#if (defined(__x86_64__) || defined(__i386__)) \&\& TARGET_LONG_BITS == 64 /* lykos: 32-bit guest -> portable C path */@' "$COMMON"
  sed -i 's@"r"(afl_area_ptr), "r"(loc)@"r"(afl_area_ptr), "r"((uintptr_t)(loc))@' "$COMMON"
  echo "[*] patched INC_AFL_AREA for 32-bit guests (guard + operand width)"
fi

NO_CHECKOUT=1 PYTHON=/usr/bin/python3 CPU_TARGET="$CPU" ./build_qemu_support.sh

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
