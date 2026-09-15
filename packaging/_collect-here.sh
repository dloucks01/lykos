#!/usr/bin/env bash
# Native collection: build a bundle from THIS host, for a host identical to it.
# Driven by collect-toolchain.sh --target native; not meant to be run directly.
set -euo pipefail
OUT="$1"; PKGS="$2"; ROOT="$3"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
say(){ printf '\n== %s\n' "$*"; }

mkdir -p "$WORK"/{debs,venvs,extras,afl-qemu,manifest}
cp "$ROOT/packaging/install-toolchain.sh" "$WORK/install.sh"; chmod +x "$WORK/install.sh"

say "resolving availability"
HAVE=""; GONE=""
for p in $PKGS; do
  if apt-cache show "$p" >/dev/null 2>&1; then HAVE="$HAVE $p"; else GONE="$GONE $p"; fi
done
[ -n "$GONE" ] && { echo "  NOT IN THIS DISTRO (skipped):"; \
                    echo "$GONE" | tr ' ' '\n' | sed '/^$/d;s/^/    /'; }

say "downloading debs"
apt-get -o Dir::Cache::archives="$WORK/debs" -o Debug::NoLocking=1 \
        install --reinstall --download-only -y $HAVE >/dev/null
find "$WORK/debs" -name '*.deb' | wc -l | xargs printf '  %s debs\n'

say "non-apt tools"
PYTHONPATH="$ROOT/core" python3 "$ROOT/packaging/_bundle_extras.py" "$WORK/extras"

say "python venvs"
for spec in "angr:angr" "unicorn:unicorn keystone-engine"; do
  name="${spec%%:*}"; want="${spec#*:}"
  python3 -m venv "$WORK/venvs/$name-venv" 2>/dev/null || continue
  if "$WORK/venvs/$name-venv/bin/pip" install --quiet $want >/dev/null 2>&1; then
    echo "  $name ok"
  else
    echo "  WARNING: $name unavailable"; rm -rf "$WORK/venvs/$name-venv"
  fi
done

say "per-guest afl-qemu-trace"
for a in arm aarch64 x86-64; do
  src="$(command -v "afl-qemu-trace-$a" || true)"
  [ -n "$src" ] && cp "$src" "$WORK/afl-qemu/" && echo "  bundled afl-qemu-trace-$a"
done

say "manifest"
{
  . /etc/os-release
  echo "target-distro:  $PRETTY_NAME"
  echo "target-glibc:   $(ldd --version | head -1 | awk '{print $NF}')"
  echo "target-python:  $(python3 -V 2>&1)"
  echo "arch:           $(uname -m)"
  echo "built:          $(date -Is)"
  echo "NOTE: collected NATIVELY -- installable only on this distribution."
  echo
  echo "packages requested:"; echo "$PKGS" | tr ' ' '\n' | sed '/^$/d;s/^/  /'
} > "$WORK/manifest/BUNDLE.txt"

say "hashing"
( cd "$WORK" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
  | xargs -0 sha256sum > SHA256SUMS )

mkdir -p "$(dirname "$OUT")"
say "writing $OUT"
if command -v zstd >/dev/null; then tar -C "$WORK" -cf - . | zstd -19 -T0 -q -o "$OUT"
else OUT="${OUT%.zst}.gz"; tar -C "$WORK" -czf "$OUT" .; fi
echo; echo "BUNDLE: $OUT ($(du -h "$OUT" | cut -f1))"
sha256sum "$OUT" | tee "$OUT.sha256"
