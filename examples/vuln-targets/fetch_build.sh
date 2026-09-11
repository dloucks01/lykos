#!/usr/bin/env bash
# Real third-party targets for the vulnerability chain: detect -> fuzz -> crash -> root cause
# -> PoC. The RE corpus next door (../re-corpus) is for triage and decompilation and contains
# nothing vulnerable; these are programs with real bugs, which is what the chain needs.
#
# jhead is built for every cross toolchain present, because an architecture regression in the
# dynamic path (endianness, qemu mapping, register layout) is invisible on x86-64 alone -- and
# unlike the arch gate's synthetic program, this is real third-party code with a real bug.
#
# Binaries are NOT committed (large, reproducible). Sources are pinned by sha256.
set -u
cd "$(dirname "$0")"; mkdir -p bin src; W=$PWD

fetch() { # name url sha256
  local out="src/$1" url="$2" want="$3"
  if [ -s "$out" ] && [ "$(sha256sum "$out" | cut -d' ' -f1)" = "$want" ]; then return 0; fi
  timeout 180 curl -fsSL "$url" -o "$out" || { echo "  x download failed: $1"; return 1; }
  local got; got=$(sha256sum "$out" | cut -d' ' -f1)
  [ "$got" = "$want" ] || { echo "  x sha256 mismatch for $1"; echo "     want $want"; \
                            echo "     got  $got"; rm -f "$out"; return 1; }
}

# ---------------------------------------------------------------- jhead 3.04 (EXIF/JPEG)
# CWE-125 out-of-bounds read in ProcessGpsInfo. The bounds check adds a GPS entry's value
# offset to its byte count in 32 bits, so a pair that WRAPS passes the check while the offset
# still points far outside the segment. inputs/jhead-crash.jpg is that pair; it is generated
# by lykos's own JPEG model, not captured from a fuzzer.
JH_SHA=ef89bbcf4f6c25ed88088cf242a47a6aedfff4f08cc7dc205bf3e2c0f10a03c9
if fetch jhead.tar.gz https://deb.debian.org/debian/pool/main/j/jhead/jhead_3.04.orig.tar.gz $JH_SHA; then
  rm -rf src/jhead-3.04; tar xzf src/jhead.tar.gz -C src
  # myglob.c is the Win32 path (#include <io.h>); jhead's own makefile leaves it out
  SRC="exif.c iptc.c gpsinfo.c jpgfile.c jpgqguess.c paths.c makernote.c jhead.c"
  echo "== jhead 3.04, every toolchain present =="
  for spec in x86-64:gcc: x86:gcc:-m32 aarch64:aarch64-linux-gnu-gcc: \
              arm:arm-linux-gnueabihf-gcc: ppc:powerpc-linux-gnu-gcc: \
              ppc64:powerpc64-linux-gnu-gcc: ppc64le:powerpc64le-linux-gnu-gcc: \
              riscv64:riscv64-linux-gnu-gcc: s390x:s390x-linux-gnu-gcc: \
              m68k:m68k-linux-gnu-gcc: sh4:sh4-linux-gnu-gcc: \
              sparc64:sparc64-linux-gnu-gcc: loongarch64:loongarch64-linux-gnu-gcc:; do
    a=${spec%%:*}; rest=${spec#*:}; cc=${rest%%:*}; fl=${rest#*:}
    command -v "$cc" >/dev/null || { echo "  - $a (no $cc)"; continue; }
    # static so qemu-user needs no sysroot; -O0 keeps the frames recoverable
    if (cd src/jhead-3.04 && $cc -O0 -static -w $fl -o "$W/bin/jhead_$a" $SRC -lm) 2>/dev/null
    then echo "  + jhead_$a"; else echo "  x jhead_$a (toolchain present, build failed)"; fi
  done
fi

# ---------------------------------------------------------------- giflib 5.1.4 (GIF)
# NOT known-vulnerable: 5.1.4 already carries the "not confined to screen dimension" check
# that CVE-2016-3977 defeated. It is here as the negative case -- a real parser the chain
# should run clean on -- and because it exercises the GIF model end to end.
GL_SHA=df27ec3ff24671f80b29e6ab1c4971059c14ac3db95406884fc26574631ba8d5
if fetch giflib.tar.bz2 http://archive.ubuntu.com/ubuntu/pool/main/g/giflib/giflib_5.1.4.orig.tar.bz2 $GL_SHA; then
  rm -rf src/giflib-5.1.4; tar xf src/giflib.tar.bz2 -C src
  echo "== giflib 5.1.4 gif2rgb =="
  (cd src/giflib-5.1.4 && gcc -O0 -w -Ilib -Iutil -o "$W/bin/gif2rgb_x86-64" \
     lib/dgif_lib.c lib/egif_lib.c lib/gifalloc.c lib/gif_err.c lib/gif_font.c \
     lib/gif_hash.c lib/openbsd-reallocarray.c lib/quantize.c \
     util/gif2rgb.c util/getarg.c util/qprintf.c) 2>/dev/null \
    && echo "  + gif2rgb_x86-64" || echo "  x gif2rgb_x86-64"
fi

# ---------------------------------------------------------------- unzip 6.0 (ZIP)
# Info-ZIP 6.0, the last release (2009), with a long CVE history. K&R declarations need
# -std=gnu89 on a modern gcc, and linux_noasm avoids the hand-written CRC assembler.
UZ_SHA=036d96991646d0449ed0aa952e4fbe21b476ce994abc276e49d30e686708bd37
if fetch unzip.tar.gz https://deb.debian.org/debian/pool/main/u/unzip/unzip_6.0.orig.tar.gz $UZ_SHA; then
  rm -rf src/unzip60; tar xzf src/unzip.tar.gz -C src
  echo "== unzip 6.0 =="
  (cd src/unzip60 && make -f unix/Makefile linux_noasm CC=gcc CFLAGS="-O0" \
      CF_NOOPT="-I. -DUNIX -std=gnu89 -w -DNO_LCHMOD" >/dev/null 2>&1 \
   && cp unzip "$W/bin/unzip_x86-64") && echo "  + unzip_x86-64" || echo "  x unzip_x86-64"
fi

echo
echo "== self-check: the crasher must fault, the seed must parse =="
for f in bin/jhead_*; do
  a=${f#bin/jhead_}
  case $a in x86-64) q="";; x86) q="";; s390x) q=qemu-s390x;; powerpc) q=qemu-ppc;;
             ppc) q=qemu-ppc;; riscv64) q=qemu-riscv64;; *) q=qemu-$a;; esac
  [ -z "$q" ] || command -v "$q" >/dev/null || { echo "  ? $a (no $q)"; continue; }
  # the subshell keeps bash from printing its own "Segmentation fault" line for each one
  ( $q ./$f inputs/jhead-crash.jpg >/dev/null 2>&1 ); bad=$?
  ( $q ./$f inputs/jhead-ok.jpg    >/dev/null 2>&1 ); ok=$?
  [ $bad -gt 128 ] && [ $ok -eq 0 ] && echo "  + $a  crash=$bad clean=$ok" \
                                    || echo "  x $a  crash=$bad clean=$ok (expected >128 and 0)"
done
echo; echo "binaries in bin/ -- see README.md"
