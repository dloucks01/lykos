#!/usr/bin/env bash
# Build the dynamic engines that the DEFAULT `make toolchain-bundle` does NOT carry, and stage
# them where `make-runnable.sh`/`./package` will inject them. Run this on a CONNECTED build host
# BETWEEN `make toolchain-bundle` and `./package` (see docs/offline-packaging.md).
#
# These engines are built separately because each needs a toolchain the base collector does not:
#   * afl-qemu-trace (per guest)  -- AFL++ qemu_mode: ninja/meson/bison/flex + glib/pixman headers.
#                                    Without it a cross-arch target gets NO coverage-guided fuzzing
#                                    (the "no coverage fuzzing" engagement symptom); the black-box
#                                    fuzzer still runs, just blind.
#   * libqasan.so                 -- AFL++ qemu_mode/libqasan: the QEMU-mode heap/ASan oracle.
#   * weggli                      -- a Rust/cargo release binary (source variant analysis).
#   * symqemu                     -- a concolic emulator built in a container (needs docker).
#
# EACH engine is BEST-EFFORT: a host missing one engine's prerequisites still builds the others,
# and the run ends with a summary of what built and what did not (and why) -- nothing is silently
# "written off". The result is staged under dist/engines/, and dist/engines/engines.env holds the
# LYKOS_* exports to source before `make-runnable.sh`/`./package` so the bundle carries them.
#
#   usage:  ./packaging/build-engines.sh
#           ENGINES_GUESTS="aarch64 arm x86_64 mips" ./packaging/build-engines.sh
#           ENGINES_SKIP="symqemu" ./packaging/build-engines.sh      # skip the docker one
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ENGINES_OUT:-$ROOT/dist/engines}"
GUESTS="${ENGINES_GUESTS:-aarch64 arm x86_64}"     # the guests most firmware/cross-arch work needs
SKIP=" ${ENGINES_SKIP:-} "                         # space-padded for word-match
AFL_SRC="${AFL_SRC:-/tmp/aflsrc}"                  # examples/afl-qemu/build.sh clones here
export AFL_SRC

mkdir -p "$OUT"
declare -a OK=() FAIL=()
_have() { command -v "$1" >/dev/null 2>&1; }
_skip() { case "$SKIP" in *" $1 "*) return 0;; *) return 1;; esac; }
say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# ---- afl-qemu-trace, one binary per guest -------------------------------------------------
AFLQEMU_DIR="$OUT/afl-qemu"
if _skip afl-qemu; then
  echo "[skip] afl-qemu (ENGINES_SKIP)"
else
  say "afl-qemu-trace for: $GUESTS"
  mkdir -p "$AFLQEMU_DIR"
  built_any=0
  for g in $GUESTS; do
    if bash "$ROOT/examples/afl-qemu/build.sh" "$g" "$AFLQEMU_DIR"; then
      built_any=1
    else
      echo "[warn] afl-qemu-trace for $g did not build (see the error above)" >&2
    fi
  done
  if [ "$built_any" = 1 ]; then OK+=("afl-qemu-trace -> $AFLQEMU_DIR"); else
    FAIL+=("afl-qemu-trace (no guest built -- need ninja/meson/bison/flex + libglib2.0-dev/libpixman-1-dev)")
  fi

  # ---- libqasan.so (reuses the AFL++ tree the afl-qemu build already cloned) --------------
  if [ -d "$AFL_SRC/qemu_mode/libqasan" ]; then
    say "libqasan.so"
    if make -C "$AFL_SRC/qemu_mode/libqasan" >/dev/null 2>&1 && \
       [ -f "$AFL_SRC/qemu_mode/libqasan/libqasan.so" ]; then
      install -m0755 "$AFL_SRC/qemu_mode/libqasan/libqasan.so" "$AFLQEMU_DIR/../libqasan.so"
      OK+=("libqasan.so -> $OUT/libqasan.so")
    else
      FAIL+=("libqasan.so (build failed in $AFL_SRC/qemu_mode/libqasan)")
    fi
  else
    FAIL+=("libqasan.so (no AFL++ source at $AFL_SRC -- afl-qemu must build first)")
  fi
fi

# ---- weggli (cargo release binary) --------------------------------------------------------
if _skip weggli; then
  echo "[skip] weggli (ENGINES_SKIP)"
elif ! _have cargo; then
  FAIL+=("weggli (cargo not installed -- https://rustup.rs, then rerun)")
else
  say "weggli (cargo install)"
  if cargo install weggli --root "$OUT/weggli-root" --quiet 2>/dev/null && \
     [ -x "$OUT/weggli-root/bin/weggli" ]; then
    install -m0755 "$OUT/weggli-root/bin/weggli" "$OUT/weggli"
    OK+=("weggli -> $OUT/weggli")
  else
    FAIL+=("weggli (cargo install failed -- a connected host with the crates.io index is needed)")
  fi
fi

# ---- symqemu (container build into vendor/symqemu) ----------------------------------------
if _skip symqemu; then
  echo "[skip] symqemu (ENGINES_SKIP)"
elif ! _have docker; then
  FAIL+=("symqemu (docker not installed -- needed for the authors' LLVM14/Z3 toolchain)")
else
  say "symqemu (docker build)"
  if bash "$ROOT/packaging/build-symqemu.sh"; then
    OK+=("symqemu -> $ROOT/vendor/symqemu")
  else
    FAIL+=("symqemu (build-symqemu.sh failed -- see the docker output above)")
  fi
fi

# ---- emit the env file the packager sources ----------------------------------------------
ENVF="$OUT/engines.env"
{
  echo "# Source this before packaging/make-runnable.sh (or ./package) so the bundle carries the"
  echo "# engines built by build-engines.sh. Generated $(date -u +%Y-%m-%dT%H:%M:%SZ)."
  [ -d "$AFLQEMU_DIR" ] && [ -n "$(ls -A "$AFLQEMU_DIR" 2>/dev/null)" ] && \
    echo "export LYKOS_AFLQEMU_DIR=\"$AFLQEMU_DIR\""
  [ -f "$OUT/libqasan.so" ] && echo "export LYKOS_QASAN=\"$OUT/libqasan.so\""
  [ -x "$OUT/weggli" ]      && echo "export LYKOS_WEGGLI_BIN=\"$OUT/weggli\""
  [ -d "$ROOT/vendor/symqemu" ] && [ -n "$(ls -A "$ROOT/vendor/symqemu" 2>/dev/null)" ] && \
    echo "export LYKOS_SYMQEMU_DIR=\"$ROOT/vendor/symqemu\""
} > "$ENVF"

say "engines summary"
for o in "${OK[@]:-}";   do [ -n "$o" ] && echo "  [built] $o"; done
for f in "${FAIL[@]:-}"; do [ -n "$f" ] && echo "  [MISSING] $f"; done
echo
echo "env written: $ENVF"
echo "next: source \"$ENVF\" && bash packaging/make-runnable.sh   (then ./package)"
# Non-fatal overall: a partial engine set is still worth packaging. Exit non-zero ONLY if
# nothing at all built, so CI can tell "no engines" from "some engines".
[ "${#OK[@]}" -gt 0 ] || { echo "nothing built" >&2; exit 1; }
