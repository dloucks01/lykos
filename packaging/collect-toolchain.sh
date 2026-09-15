#!/usr/bin/env bash
# Build the air-gap TOOLCHAIN bundle. Run on a machine WITH network; carry the result to the
# air-gapped workstation and run install.sh from the extracted bundle.
#
# The lykos repo itself needs no bundle -- clone it and the stdlib-only core runs. This carries
# the optional engines (Ghidra, qemu-user, GDB, AFL++, Wine, cross compilers, the angr/Unicorn
# venvs), which are too large for git and turn a working platform into a complete one.
#
# THE BUNDLE IS DISTRIBUTION-SPECIFIC. A .deb, a compiled emulator and a Python venv all bind
# to the C library and interpreter they were built against, so a bundle collected on one distro
# is not installable on another -- and the failure is not graceful: dpkg leaves a half-configured
# system, and a venv raises ImportError at first use rather than at install. So by default this
# collects INSIDE A CONTAINER MATCHING THE TARGET, not from this host.
#
#   ./packaging/collect-toolchain.sh                      # Kali rolling (default)
#   ./packaging/collect-toolchain.sh --image kalilinux/kali-rolling:2025.3
#   ./packaging/collect-toolchain.sh --target native      # a host identical to this one
#
# The package list is NOT written here: it comes from lykos.toolchain, the same table
# `lykos doctor` reports and doc 23 documents, so a tool cannot be added in one place and
# forgotten in the others.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="kali"; IMAGE="kalilinux/kali-rolling:latest"; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --image)  IMAGE="$2"; shift 2 ;;
    --out)    OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
    *) OUT="$1"; shift ;;
  esac
done

say(){ printf '\n== %s\n' "$*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }

PKGS="$(PYTHONPATH="$ROOT/core" python3 -c \
  'from lykos import toolchain; print(" ".join(toolchain.apt_packages()))')"
[ -n "$PKGS" ] || die "could not read the package list from lykos.toolchain"
STAMP="$(date +%Y%m%d)"; ARCH="$(uname -m)"

if [ "$TARGET" = "native" ]; then
  . /etc/os-release 2>/dev/null || true
  OUT="${OUT:-$ROOT/dist/lykos-toolchain-${ID:-host}-$STAMP-$ARCH.tar.zst}"
  say "collecting NATIVELY from ${PRETTY_NAME:-this host}"
  echo "  Installable ONLY on ${PRETTY_NAME:-this host} (or something ABI-identical)."
  exec bash "$ROOT/packaging/_collect-here.sh" "$OUT" "$PKGS" "$ROOT"
fi

RUNTIME="$(command -v podman || command -v docker || true)"
[ -n "$RUNTIME" ] || die "need podman or docker for a container bundle (or --target native)"
TAG="$(echo "$IMAGE" | sed 's|.*/||; s|:|-|g')"
OUT="${OUT:-$ROOT/dist/lykos-toolchain-$TAG-$STAMP-$ARCH.tar.zst}"
mkdir -p "$(dirname "$OUT")"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK" 2>/dev/null || true' EXIT

say "collecting inside $IMAGE"
[ "$IMAGE" = "kalilinux/kali-rolling:latest" ] && \
  echo "  note: ':latest' is a MOVING tag -- two bundles built days apart differ. For a" && \
  echo "        reproducible bundle pass --image kalilinux/kali-rolling:<YYYY.N>"
echo "  target:   $IMAGE"
echo "  host:     $(. /etc/os-release; echo "$PRETTY_NAME") -- drives the container only"
echo "  packages: $(echo "$PKGS" | wc -w)"

cp "$ROOT/packaging/install-toolchain.sh" "$WORK/install.sh"

# ONE finished archive comes back out. Loose files cannot work across both runtimes: rootless
# podman maps container-root to the invoking user, so chowning to the real uid INSIDE pushes
# files onto a subuid the host cannot read -- while under rootful docker, not chowning leaves
# them root-owned. In an archive, ownership is metadata rather than filesystem permission, so
# neither case arises and the host only ever touches a single file.
"$RUNTIME" run --rm -v "$WORK:/out:z" -e PKGS="$PKGS" "$IMAGE" \
  bash -euo pipefail -c '
say(){ printf "\n-- %s\n" "$*"; }
export DEBIAN_FRONTEND=noninteractive

say "apt update"
apt-get -qq update 2>/dev/null

say "collector prerequisites (container only)"
apt-get -qq install -y --no-install-recommends \
        python3 python3-venv python3-pip ca-certificates zstd >/dev/null 2>&1

mkdir -p /stage/debs /stage/venvs /stage/manifest /stage/extras /stage/afl-qemu
cp /out/install.sh /stage/install.sh && chmod +x /stage/install.sh

say "resolving availability"
HAVE=""; GONE=""
for p in $PKGS; do
  if apt-cache show "$p" >/dev/null 2>&1; then HAVE="$HAVE $p"; else GONE="$GONE $p"; fi
done
[ -n "$GONE" ] && { echo "  NOT IN THIS DISTRO (skipped):"
                    echo "$GONE" | tr " " "\n" | sed "/^$/d;s/^/    /"; }

say "downloading debs (with dependencies)"
# --reinstall so packages already in the image are still fetched; without it a fatter base
# image silently yields a thinner bundle.
apt-get -o Dir::Cache::archives=/stage/debs install --reinstall --download-only -y $HAVE \
  >/dev/null 2>&1
rm -rf /stage/debs/partial /stage/debs/lock
printf "  %s debs, %s\n" "$(find /stage/debs -name "*.deb" | wc -l)" \
                         "$(du -sh /stage/debs | cut -f1)"

# Ghidra is a REQUIRED engine. In the container path extras/ is not populated (the repo is not
# mounted in), so if this image also does not package Ghidra the bundle ships without it -- warn
# loudly rather than let the air-gapped install discover it at first disassemble.
if [ -z "$(find /stage/debs -iname "ghidra*.deb" 2>/dev/null | head -1)" ] && \
   [ -z "$(ls -A /stage/extras 2>/dev/null)" ]; then
  echo "  WARNING: Ghidra (REQUIRED) is not an apt package in this image and no extras/ was"
  echo "           staged -- this bundle will install WITHOUT Ghidra. Collect on an image that"
  echo "           packages it (Kali), or add Ghidra to the extras/ dir before packing."
fi

say "python venvs (this distro s interpreter)"
for spec in "angr:angr" "unicorn:unicorn keystone-engine"; do
  name="${spec%%:*}"; want="${spec#*:}"
  python3 -m venv "/stage/venvs/$name-venv" >/dev/null 2>&1 || continue
  "/stage/venvs/$name-venv/bin/pip" install -q --upgrade pip >/dev/null 2>&1 || true
  if "/stage/venvs/$name-venv/bin/pip" install -q $want >/dev/null 2>&1; then
    echo "  $name ok ($(python3 -V 2>&1))"
  else
    echo "  WARNING: $name unavailable here -- that engine will be missing"
    rm -rf "/stage/venvs/$name-venv"
  fi
done

say "manifest"
{
  . /etc/os-release
  echo "target-distro:  $PRETTY_NAME"
  echo "target-glibc:   $(ldd --version | head -1 | awk "{print \$NF}")"
  echo "target-python:  $(python3 -V 2>&1)"
  echo "arch:           $(uname -m)"
  echo "built:          $(date -Is)"
  echo
  echo "Installable on the distribution above. A .deb, a compiled emulator and a"
  echo "Python venv each bind to the C library and interpreter they were built"
  echo "against; installing this elsewhere fails, and not gracefully."
  echo
  echo "NOT included, deliberately:"
  echo "  afl-qemu-trace  compiled emulators, guest fixed at build time --"
  echo "                  build on the target: examples/afl-qemu/build.sh <arch>"
  echo "  symqemu         built from source: packaging/build-symqemu.sh"
  echo
  echo "packages requested:"; echo "$PKGS" | tr " " "\n" | sed "/^$/d;s/^/  /"
} > /stage/manifest/BUNDLE.txt
sed "s/^/  /" /stage/manifest/BUNDLE.txt

say "hashing and packing"
cd /stage
find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
printf "  %s files\n" "$(wc -l < SHA256SUMS)"
tar -cf - . | zstd -19 -T0 -q -o /out/bundle.tar.zst
printf "  %s\n" "$(du -h /out/bundle.tar.zst | cut -f1)"
'

[ -f "$WORK/bundle.tar.zst" ] || die "the container produced no bundle"
mv "$WORK/bundle.tar.zst" "$OUT"
sha256sum "$OUT" > "$OUT.sha256"

cat <<EOF

BUNDLE: $OUT ($(du -h "$OUT" | cut -f1))
$(cat "$OUT.sha256")

The .sha256 and the bundle's SHA256SUMS are UNSIGNED: they prove the bundle arrived
un-corrupted and un-added-to, not that it is authentic. Carry it over a trusted channel.
(Future: sign SHA256SUMS and verify the signature at install time.)

On the air-gapped host -- carry the repo, this file and its .sha256, and verify on ARRIVAL:
  sha256sum -c $(basename "$OUT").sha256
  mkdir -p /tmp/lt && tar xf $(basename "$OUT") -C /tmp/lt
  /tmp/lt/install.sh --verify-only            # checksums only, installs nothing
  cd <lykos checkout> && LYKOS_ROOT=\$PWD /tmp/lt/install.sh
EOF
