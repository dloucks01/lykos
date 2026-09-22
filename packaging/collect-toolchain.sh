#!/usr/bin/env bash
# Build the air-gap TOOLCHAIN bundle. Run on a machine WITH network; carry the result to the
# air-gapped workstation and run setup.sh from the extracted bundle (nothing is installed).
#
# The lykos repo itself needs no bundle -- clone it and the stdlib-only core runs. This carries
# the optional engines (Ghidra, qemu-user, GDB, AFL++, Wine, cross compilers, the angr/Unicorn
# venvs), which are too large for git and turn a working platform into a complete one.
#
# THE BUNDLE IS DISTRIBUTION-SPECIFIC. An extracted glibc-linked binary, a compiled emulator
# and a Python venv all bind to the C library and interpreter they were built against, so a
# bundle collected on one distro does not run on another -- and the failure is not graceful: a
# binary aborts on a symbol its host libc lacks, and a venv raises ImportError at first use. So
# by default this collects INSIDE A CONTAINER MATCHING THE TARGET, not from this host.
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

# ONE build with every capability. The list comes from lykos.toolchain; rizin/rz-ghidra +
# pypcode is the RE backend (Ghidra is replaced and carries no apt), everything else is pulled.
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

cp "$ROOT/packaging/setup-toolchain.sh" "$WORK/setup.sh"

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

# The bundle installs NOTHING on the air-gapped side: it ships a relocatable toolchain/ tree
# the engines run out of in place. So here we DOWNLOAD the debs and then EXTRACT them into that
# tree (dpkg-deb -x, data only, no maintainer scripts, no dpkg database) rather than shipping
# the .deb files for a dpkg install.
mkdir -p /tmp/debs /stage/toolchain /stage/venvs /stage/manifest /stage/extras /stage/afl-qemu
cp /out/setup.sh /stage/setup.sh && chmod +x /stage/setup.sh

say "resolving availability"
HAVE=""; GONE=""
for p in $PKGS; do
  if apt-cache show "$p" >/dev/null 2>&1; then HAVE="$HAVE $p"; else GONE="$GONE $p"; fi
done
[ -n "$GONE" ] && { echo "  NOT IN THIS DISTRO (skipped):"
                    echo "$GONE" | tr " " "\n" | sed "/^$/d;s/^/    /"; }

say "downloading debs (with dependencies)"
# --reinstall so packages already in the image are still fetched; without it a fatter base
# image silently yields a thinner bundle. kali-rolling is a MOVING target: over a long, slow
# download the mirror can sync mid-flight, so a .deb no longer matches the Packages index that
# apt update just read -- apt aborts with a hash-sum mismatch (exit 100). Retry, refreshing the
# index each time so apt re-reads the mirror current state, and let apt own stderr through (the
# old 2>redirect hid exactly this error). Acquire::Retries also rides out a transient per-URL
# fetch drop. NOTE: this whole block runs inside a single-quoted -c string -- no apostrophes.
mkdir -p /tmp/debs/partial
tries=0
until apt-get -o Dir::Cache::archives=/tmp/debs -o Acquire::Retries=5 \
        install --reinstall --download-only -y $HAVE >/dev/null; do
  tries=$((tries + 1))
  [ "$tries" -ge 4 ] && { echo "  ERROR: deb download still failing after $tries attempts" >&2; exit 1; }
  echo "  download failed (attempt $tries) -- refreshing the index and retrying" >&2
  apt-get -qq update 2>/dev/null || true
  sleep 5
done
rm -rf /tmp/debs/partial /tmp/debs/lock
printf "  %s debs, %s\n" "$(find /tmp/debs -name "*.deb" | wc -l)" \
                         "$(du -sh /tmp/debs | cut -f1)"

say "extracting debs into a relocatable toolchain/ tree (no install)"
for d in /tmp/debs/*.deb; do dpkg-deb -x "$d" /stage/toolchain; done
rm -rf /tmp/debs
printf "  toolchain/ is %s\n" "$(du -sh /stage/toolchain | cut -f1)"

# Ghidra is a REQUIRED engine. In the container path extras/ is not populated (the repo is not
# mounted in), so if this image also does not package Ghidra the bundle ships without it -- warn
# loudly rather than let the air-gapped setup discover it at first disassemble.
# The RE backend is rizin/rz-ghidra + pypcode (Ghidra is replaced, no JVM). What must not be
# missing is the native backend itself -- warn if rizin did not land in the tree.
if [ -z "$(find /stage/toolchain -iname "rizin" -o -iname "rz-ghidra*" 2>/dev/null | head -1)" ]; then
  echo "  WARNING: rizin (the RE backend) is not in this bundle -- disassembly will have no"
  echo "           default engine. Collect on an image that packages rizin + rz-ghidra (Kali)."
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

say "vendored python site (pypcode = Ghidra P-Code IR, no JVM)"
mkdir -p /stage/pysite
if python3 -m pip install --target /stage/pysite pypcode >/dev/null 2>&1; then
  echo "  pypcode -> pysite ($(python3 -V 2>&1))"
else
  echo "  WARNING: pypcode unavailable -- the native RE backend will decompile but P-Code-based"
  echo "           memory-safety detection (taint/bounds/int-overflow) will degrade"
  rm -rf /stage/pysite; mkdir -p /stage/pysite
fi

say "manifest"
{
  . /etc/os-release
  echo "target-distro:  $PRETTY_NAME"
  echo "target-glibc:   $(ldd --version | head -1 | awk "{print \$NF}")"
  echo "target-python:  $(python3 -V 2>&1)"
  echo "arch:           $(uname -m)"
  echo "built:          $(date -Is)"
  echo
  echo "Runs IN PLACE on the distribution above -- nothing is installed. The debs are"
  echo "extracted into toolchain/ and lykos puts that tree on its own PATH. A compiled"
  echo "emulator, an extracted glibc-linked binary and a Python venv each bind to the C"
  echo "library and interpreter they were built against; running this on another distro"
  echo "fails, and not gracefully."
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
(Future: sign SHA256SUMS and verify the signature at setup time.)

On the air-gapped host -- carry the repo, this file and its .sha256, and verify on ARRIVAL.
Nothing is installed: the toolchain is placed under the repo's vendor/ and run in place.
  sha256sum -c $(basename "$OUT").sha256
  mkdir -p /tmp/lt && tar xf $(basename "$OUT") -C /tmp/lt
  /tmp/lt/setup.sh --verify-only              # checksums only, places nothing
  cd <lykos checkout> && LYKOS_ROOT=\$PWD /tmp/lt/setup.sh
EOF
