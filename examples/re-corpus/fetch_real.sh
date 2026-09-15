#!/usr/bin/env bash
# Fetch real-world, stripped, statically-linked binaries across many architectures
# (busybox) plus a hard Rust binary (ripgrep). Complements build_corpus.sh, which
# compiles the local x86-64 / PE / C++ variants. Requires network.
set -u
cd "$(dirname "$0")"; mkdir -p bin; cd bin

# These downloads are not reproducible: nothing here is pinned by sha256 (contrast
# ../vuln-targets/fetch_build.sh). record() computes and logs the hash of each fetched binary to
# DOWNLOADED.sha256 and flags it UNVERIFIED, so provenance is at least captured and an operator
# can pin it. The ripgrep step below additionally selects the "latest" .deb, so its bytes drift.
: > DOWNLOADED.sha256
record(){ # file url
  [ -s "$1" ] || return 0
  local got; got="$(sha256sum "$1" | cut -d' ' -f1)"
  echo "$got  $2" >> DOWNLOADED.sha256
  echo "    UNVERIFIED sha256 $got"
}

echo "== busybox 1.26.2 defconfig-multiarch (arm/mips/ppc/sparc/x86) =="
B=https://busybox.net/downloads/binaries/1.26.2-defconfig-multiarch
for a in armv4l armv5l armv6l i686 mips mipsel powerpc sparc x86_64; do
  out="busybox_${a/x86_64/x86-64}"
  if timeout 40 curl -fsSL "$B/busybox-$a" -o "$out" 2>/dev/null && [ -s "$out" ]; then
    chmod -x "$out"; echo "  + $out"; record "$out" "$B/busybox-$a"
  else echo "  x $out"; rm -f "$out"; fi
done

echo "== busybox-static from Debian (modern 64-bit arches) =="
POOL=https://ftp.debian.org/debian/pool/main/b/busybox
V=1.37.0-6+b9
deb64(){ darch="$1"; out="$2"; T=$(mktemp -d)
  if timeout 60 curl -fsSL "$POOL/busybox-static_${V}_${darch}.deb" -o "$T/p.deb" 2>/dev/null; then
    ( cd "$T" && ar x p.deb && tar xf data.tar.* )
    bb="$T/usr/bin/busybox"
    if [ -f "$bb" ] && file -b "$bb"|grep -q ELF; then
      cp "$bb" "$out"; chmod -x "$out"; echo "  + $out"
      record "$out" "$POOL/busybox-static_${V}_${darch}.deb"
    else echo "  x $out"; fi
  fi; rm -rf "$T"; }
deb64 arm64   busybox_aarch64
deb64 riscv64 busybox_riscv64
deb64 ppc64el busybox_ppc64le
deb64 s390x   busybox_s390x

echo "== ripgrep (real-world Rust, PIE) =="
# NOTE: this picks the LATEST ripgrep .deb in the pool (sort -u | tail -1), so the version -- and
# therefore the bytes -- change over time. Pin RGURL to a specific .deb for a reproducible corpus.
T=$(mktemp -d)
RGBASE=https://ftp.debian.org/debian/pool/main/r/rust-ripgrep
RG=$(timeout 20 curl -fsSL "$RGBASE/" 2>/dev/null | grep -oE 'ripgrep_[^"]+_amd64\.deb' | sort -u | tail -1)
if [ -n "$RG" ] && timeout 90 curl -fsSL "$RGBASE/$RG" -o "$T/p.deb" 2>/dev/null; then
  ( cd "$T" && ar x p.deb && tar xf data.tar.* )
  rg=$(find "$T" -type f -path "*bin/rg" | head -1)
  if [ -n "$rg" ]; then
    cp "$rg" hello_rust_ripgrep; chmod -x hello_rust_ripgrep; echo "  + hello_rust_ripgrep ($RG)"
    record hello_rust_ripgrep "$RGBASE/$RG"
  fi
fi; rm -rf "$T"
echo "done. Run ./build_corpus.sh for the locally-compiled variants, then regen manifest."
