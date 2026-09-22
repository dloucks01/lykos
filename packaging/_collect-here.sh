#!/usr/bin/env bash
# Native collection: build a bundle from THIS host, for a host identical to it.
# Driven by collect-toolchain.sh --target native; not meant to be run directly.
set -euo pipefail
OUT="$1"; PKGS="$2"; ROOT="$3"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
say(){ printf '\n== %s\n' "$*"; }

mkdir -p "$WORK"/{toolchain,venvs,extras,afl-qemu,manifest}
DEBS="$(mktemp -d)"; trap 'rm -rf "$WORK" "$DEBS"' EXIT
cp "$ROOT/packaging/setup-toolchain.sh" "$WORK/setup.sh"; chmod +x "$WORK/setup.sh"

say "resolving availability"
HAVE=""; GONE=""
for p in $PKGS; do
  if apt-cache show "$p" >/dev/null 2>&1; then HAVE="$HAVE $p"; else GONE="$GONE $p"; fi
done
[ -n "$GONE" ] && { echo "  NOT IN THIS DISTRO (skipped):"; \
                    echo "$GONE" | tr ' ' '\n' | sed '/^$/d;s/^/    /'; }

say "downloading debs"
# Retry on a mirror that drifts mid-download (hash-sum mismatch) or a transient fetch drop,
# refreshing the index between attempts; apt's stderr is left visible on failure.
mkdir -p "$DEBS/partial"
tries=0
until apt-get -o Dir::Cache::archives="$DEBS" -o Debug::NoLocking=1 -o Acquire::Retries=5 \
        install --reinstall --download-only -y $HAVE >/dev/null; do
  tries=$((tries + 1))
  [ "$tries" -ge 4 ] && { echo "  ERROR: deb download still failing after $tries attempts" >&2; exit 1; }
  echo "  download failed (attempt $tries) -- refreshing the index and retrying" >&2
  apt-get -qq update 2>/dev/null || true
  sleep 5
done
find "$DEBS" -name '*.deb' | wc -l | xargs printf '  %s debs\n'

say "extracting debs into a relocatable toolchain/ tree (no install)"
for d in "$DEBS"/*.deb; do dpkg-deb -x "$d" "$WORK/toolchain"; done
du -sh "$WORK/toolchain" | awk '{print "  toolchain/ is " $1}'

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

say "vendored python site (pypcode = Ghidra P-Code IR, no JVM)"
mkdir -p "$WORK/pysite"
if python3 -m pip install --target "$WORK/pysite" pypcode >/dev/null 2>&1; then
  echo "  pypcode ok"
else
  echo "  WARNING: pypcode unavailable -- P-Code-based memory-safety detection will degrade"
  rm -rf "$WORK/pysite"; mkdir -p "$WORK/pysite"
fi

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
  echo "NOTE: collected NATIVELY -- runs in place (no install) only on this distribution."
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
